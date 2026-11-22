#!/usr/bin/env python3
"""Build all twelve P4 production images from one exact source commit."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROLES = ("runner", "custody", "anchor", "signer", "worker", "verifier")
VARIANTS = ("a", "b")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
KEY_ID_RE = re.compile(r"^ed25519:[0-9a-f]{32}$")


def run(command: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def inspect_image(reference: str, *, cwd: Path) -> dict[str, Any]:
    result = run(["docker", "image", "inspect", reference], cwd=cwd)
    document = json.loads(result.stdout)
    if not isinstance(document, list) or len(document) != 1:
        raise RuntimeError(f"unexpected image inspection result: {reference}")
    return document[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag-prefix", required=True)
    parser.add_argument("--public-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--roles", nargs="*", choices=ROLES, default=list(ROLES))
    args = parser.parse_args()

    source_root = args.source_root.resolve(strict=True)
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise SystemExit("source commit must be an exact 40-character Git SHA")
    metadata = json.loads(args.public_metadata.read_text(encoding="utf-8"))
    key_id = str(metadata.get("key_id") or "")
    if not KEY_ID_RE.fullmatch(key_id):
        raise SystemExit("public metadata contains no valid Ed25519 key ID")
    if not args.tag_prefix.startswith("p4-"):
        raise SystemExit("tag prefix must begin with p4-")

    records: list[dict[str, Any]] = []
    for role in args.roles:
        dockerfile = source_root / "images" / role / "Dockerfile"
        if not dockerfile.is_file():
            raise RuntimeError(f"Dockerfile missing: {dockerfile}")
        policy_id = f"p4.{role}.production.v1"
        for variant in VARIANTS:
            reference = f"echo-certforge-{role}:{args.tag_prefix}-{variant}"
            command = [
                "docker",
                "build",
                "--no-cache",
                "--pull=false",
                "--build-arg",
                f"SOURCE_REVISION={args.source_commit}",
                "--build-arg",
                f"IMAGE_VARIANT={variant}",
                "--build-arg",
                f"ADMISSION_POLICY_ID={policy_id}",
                "--build-arg",
                f"ATTESTATION_KEY_ID={key_id}",
                "-f",
                str(dockerfile.relative_to(source_root)),
                "-t",
                reference,
                ".",
            ]
            started = datetime.now(UTC)
            completed = run(command, cwd=source_root, check=False)
            log_path = args.output.parent / "build-logs" / role / f"{variant}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
            if completed.returncode != 0:
                raise RuntimeError(f"image build failed: {reference}; log={log_path}")
            image = inspect_image(reference, cwd=source_root)
            labels = ((image.get("Config") or {}).get("Labels") or {})
            expected_labels = {
                "echo.certforge.image.role": role,
                "echo.certforge.image.variant": variant,
                "echo.certforge.admission.policy": policy_id,
                "echo.certforge.attestation.key_id": key_id,
                "org.opencontainers.image.revision": args.source_commit,
            }
            for name, expected in expected_labels.items():
                if labels.get(name) != expected:
                    raise RuntimeError(f"built image label mismatch: {reference}:{name}")
            if (image.get("Config") or {}).get("User") != "65532:65532":
                raise RuntimeError(f"built image user mismatch: {reference}")
            if not ((image.get("Config") or {}).get("Healthcheck") or {}).get("Test"):
                raise RuntimeError(f"built image health command missing: {reference}")
            records.append(
                {
                    "role": role,
                    "variant": variant,
                    "reference": reference,
                    "image_id": image.get("Id"),
                    "repo_digests": image.get("RepoDigests") or [],
                    "created": image.get("Created"),
                    "started_at_utc": started.isoformat().replace("+00:00", "Z"),
                    "completed_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "build_log": str(log_path),
                    "labels": expected_labels,
                }
            )

    output = {
        "schema_version": "1.0.0",
        "source_commit": args.source_commit,
        "tag_prefix": args.tag_prefix,
        "attestation_key_id": key_id,
        "record_count": len(records),
        "records": records,
        "passed": len(records) == len(args.roles) * len(VARIANTS),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "record_count": len(records), "passed": output["passed"]}, indent=2))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
