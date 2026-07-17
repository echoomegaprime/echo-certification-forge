#!/usr/bin/env python3
"""Build the deterministic P4 evidence index from exact repository files."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "artifacts/p4_forge_acceptance.json"
DEFAULT_MANIFEST = ROOT / "artifacts/p4_images/manifest.json"
DEFAULT_OUTPUT = ROOT / "artifacts/p4_evidence_index.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_relative(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if ROOT not in resolved.parents:
        raise ValueError(f"evidence file is outside repository: {resolved}")
    return resolved.relative_to(ROOT).as_posix()


def validate_source_commit(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("source commit must be a lowercase 40-character Git SHA-1")
    return normalized


def build_index(
    *,
    source_commit: str,
    report_path: Path,
    manifest_path: Path,
    extra_paths: list[Path],
) -> dict[str, Any]:
    source_commit = validate_source_commit(source_commit)
    report = json.loads(report_path.resolve(strict=True).read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.resolve(strict=True).read_text(encoding="utf-8"))
    if report.get("passed") is not True or report.get("run_outcome") != "COMPLETE":
        raise ValueError("P4 acceptance report is not a complete passing run")
    if report.get("release_verdict") != "NOT_READY":
        raise ValueError("P4 phase completion must preserve release_verdict NOT_READY")
    if report.get("source_commit") != source_commit:
        raise ValueError("acceptance report source commit mismatch")
    if manifest.get("source_commit") != source_commit:
        raise ValueError("image manifest source commit mismatch")

    unique_paths: dict[str, Path] = {}
    for path in [report_path, manifest_path, *extra_paths]:
        relative = repository_relative(path)
        unique_paths[relative] = path.resolve(strict=True)
    files = [
        {
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for relative, path in sorted(unique_paths.items())
    ]
    report_relative = repository_relative(report_path)
    manifest_relative = repository_relative(manifest_path)
    return {
        "schema_version": "1.0.0",
        "phase": "P4",
        "source_commit": source_commit,
        "completed_phase_gate": "P4",
        "run_outcome": "COMPLETE",
        "release_verdict": "NOT_READY",
        "acceptance_report": {
            "path": report_relative,
            "sha256": sha256_file(report_path),
        },
        "image_manifest": {
            "path": manifest_relative,
            "sha256": sha256_file(manifest_path),
        },
        "files": files,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--extra", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        index = build_index(
            source_commit=args.source_commit,
            report_path=args.report,
            manifest_path=args.manifest,
            extra_paths=list(args.extra),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "passed": True,
                "output": str(args.output.resolve()),
                "bytes": args.output.stat().st_size,
                "sha256": sha256_file(args.output),
                "file_count": len(index["files"]),
                "release_verdict": index["release_verdict"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
