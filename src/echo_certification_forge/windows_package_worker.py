"""CLI for the pinned Echo Desktop P8C Windows package observer."""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .operational_telemetry import SignedOperationalReport
from .runner import SignedRunCredential
from .windows_package import (
    file_sha256,
    inspect_windows_installer,
    load_runner_private_key,
    sign_package_result,
)


def _lock_private_key(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        username = os.environ.get("USERNAME")
        if not username:
            raise RuntimeError("USERNAME is required to ACL the runner key")
        import subprocess

        process = subprocess.run(
            ["icacls.exe", str(path), "/inheritance:r", "/grant:r", f"{username}:F"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        if process.returncode != 0:
            raise RuntimeError("failed to restrict runner private-key ACL")


def initialize_identity(private_key_path: Path, public_key_path: Path) -> dict[str, str]:
    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("runner identity path already exists")
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    _lock_private_key(private_key_path)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path.write_bytes(public_pem)
    return {"initialized": "true", "public_key_path": str(public_key_path)}


def run_once(
    *,
    endpoint: str,
    artifact_path: Path,
    source_root: Path,
    credential_path: Path,
    private_key_path: Path,
    expected_artifact_sha256: str,
    expected_source_commit: str,
    expected_reference: str,
) -> dict[str, object]:
    if not endpoint.startswith("https://") and not endpoint.startswith("http://127.0.0.1"):
        raise ValueError("runner endpoint must use HTTPS (or loopback HTTP for tests)")
    credential = SignedRunCredential.model_validate_json(
        credential_path.read_text(encoding="utf-8")
    )
    worker_image_sha256 = file_sha256(Path(__file__).with_name("windows_package.py"))
    body = inspect_windows_installer(
        artifact_path,
        source_root,
        worker_image_sha256=worker_image_sha256,
        expected_artifact_sha256=expected_artifact_sha256,
        expected_source_commit=expected_source_commit,
        expected_reference=expected_reference,
    )
    response = sign_package_result(
        body,
        credential,
        load_runner_private_key(private_key_path),
    )
    report = SignedOperationalReport(credential=credential, response=response)
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/v1/internal/windows-package-results",
        data=report.model_dump_json().encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as result:
            payload = json.loads(result.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"control plane rejected Windows result with HTTP {exc.code}") from exc
    if not isinstance(payload, dict) or payload.get("accepted") is not True:
        raise RuntimeError("control plane did not authenticate the Windows result")
    return {
        "accepted": True,
        "run_id": credential.claims.run_id,
        "artifact_sha256": body.artifact_sha256,
        "source_commit": body.source_commit,
        "authenticode_status": body.authenticode_status,
        "ready_candidate": body.ready_candidate,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--private-key", type=Path, required=True)
    init_parser.add_argument("--public-key", type=Path, required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--endpoint", required=True)
    run_parser.add_argument("--artifact", type=Path, required=True)
    run_parser.add_argument("--source-root", type=Path, required=True)
    run_parser.add_argument("--credential", type=Path, required=True)
    run_parser.add_argument("--private-key", type=Path, required=True)
    run_parser.add_argument("--artifact-sha256", required=True)
    run_parser.add_argument("--source-commit", required=True)
    run_parser.add_argument("--reference", required=True)
    args = parser.parse_args(argv)
    if args.command == "init":
        result = initialize_identity(args.private_key, args.public_key)
    else:
        result = run_once(
            endpoint=args.endpoint,
            artifact_path=args.artifact,
            source_root=args.source_root,
            credential_path=args.credential,
            private_key_path=args.private_key,
            expected_artifact_sha256=args.artifact_sha256,
            expected_source_commit=args.source_commit,
            expected_reference=args.reference,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
