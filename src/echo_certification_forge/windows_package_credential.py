"""Control-plane CLI for short-lived Windows package runner credentials."""
from __future__ import annotations

import argparse
import json
import os
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import sha256_bytes, utc_now
from .runner import ControlPlaneTransportAuthority, RunnerCommand


def _secure(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def initialize_authority(private_key_path: Path, public_key_path: Path) -> dict[str, str]:
    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("transport authority path already exists")
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
    _secure(private_key_path)
    authority = ControlPlaneTransportAuthority(key)
    public_key_path.write_text(authority.public_key_pem, encoding="ascii")
    return {"initialized": "true", "key_id": authority.key_id}


def issue_credential(
    *,
    authority_key_path: Path,
    runner_public_key_path: Path,
    run_id: str,
    tenant_id: str,
    runner_id: str,
    output_path: Path,
    ttl_seconds: int,
) -> dict[str, str]:
    if ttl_seconds < 30 or ttl_seconds > 900:
        raise ValueError("credential TTL must be between 30 and 900 seconds")
    key = serialization.load_pem_private_key(authority_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("transport authority key must be Ed25519")
    authority = ControlPlaneTransportAuthority(key)
    runner_public_pem = runner_public_key_path.read_text(encoding="ascii")
    issued_at = utc_now()
    credential = authority.issue(
        credential_id=(
            "winpkg-"
            + sha256_bytes(
                f"{run_id}:{tenant_id}:{runner_id}:{issued_at.isoformat()}".encode("utf-8")
            )[:24]
        ),
        run_id=run_id,
        tenant_id=tenant_id,
        runner_id=runner_id,
        runner_public_key_pem=runner_public_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=issued_at,
        ttl=timedelta(seconds=ttl_seconds),
    )
    if output_path.exists():
        raise FileExistsError("credential output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(credential.model_dump_json(indent=2) + "\n", encoding="utf-8")
    _secure(output_path)
    return {
        "issued": "true",
        "credential_id": credential.claims.credential_id,
        "run_id": run_id,
        "runner_id": runner_id,
        "expires_at": credential.claims.expires_at.isoformat(),
        "output_path": str(output_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--private-key", type=Path, required=True)
    init_parser.add_argument("--public-key", type=Path, required=True)
    issue_parser = subparsers.add_parser("issue")
    issue_parser.add_argument("--authority-key", type=Path, required=True)
    issue_parser.add_argument("--runner-public-key", type=Path, required=True)
    issue_parser.add_argument("--run-id", required=True)
    issue_parser.add_argument("--tenant", required=True)
    issue_parser.add_argument("--runner-id", required=True)
    issue_parser.add_argument("--out", type=Path, required=True)
    issue_parser.add_argument("--ttl-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    if args.command == "init":
        result = initialize_authority(args.private_key, args.public_key)
    else:
        result = issue_credential(
            authority_key_path=args.authority_key,
            runner_public_key_path=args.runner_public_key,
            run_id=args.run_id,
            tenant_id=args.tenant,
            runner_id=args.runner_id,
            output_path=args.out,
            ttl_seconds=args.ttl_seconds,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
