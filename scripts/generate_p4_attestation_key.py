#!/usr/bin/env python3
"""Generate a short-lived P4 image-attestation key pair outside image build contexts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.private_key, args.public_key, args.metadata):
        path.parent.mkdir(parents=True, exist_ok=True)
    if args.private_key.exists() or args.public_key.exists() or args.metadata.exists():
        raise SystemExit("refusing to overwrite an existing P4 attestation key artifact")

    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = f"ed25519:{hashlib.sha256(raw_public).hexdigest()[:32]}"
    args.private_key.write_bytes(private_bytes)
    os.chmod(args.private_key, 0o600)
    args.public_key.write_bytes(public_bytes)
    os.chmod(args.public_key, 0o644)
    metadata = {
        "schema_version": "1.0.0",
        "algorithm": "Ed25519",
        "key_id": key_id,
        "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "private_key_persisted_for_sealing_only": True,
    }
    args.metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
