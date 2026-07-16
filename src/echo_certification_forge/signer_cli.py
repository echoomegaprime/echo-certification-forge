"""One-request isolated signer entry point for a hardened container."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .anchor import AnchorVerificationBundle
from .canonical import canonical_json
from .signing_service import (
    IsolatedVerdictSigningService,
    ProductionSigningRequest,
    PublicKeyRecord,
    SigningRunContext,
    SigningStore,
    TrustedSigningAuthorizationRegistry,
)


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--key-record", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--authorization-public-key", type=Path, required=True)
    parser.add_argument("--trusted-anchor-public-key", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-bundle", type=Path, required=True)
    args = parser.parse_args()

    try:
        key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("signing key must be Ed25519")
        request = ProductionSigningRequest.model_validate(_read_json(args.request))
        context = SigningRunContext.model_validate(_read_json(args.context))
        key_record = PublicKeyRecord.model_validate(_read_json(args.key_record))
        auth_registry = TrustedSigningAuthorizationRegistry()
        auth_registry.add_pem(args.authorization_public_key.read_text(encoding="ascii"))
        anchor_pem = args.trusted_anchor_public_key.read_text(encoding="ascii")
        anchor_key_id = request.anchor_bundle.receipt.provider_key_id
        store = SigningStore(args.db)
        store.register_context(context)
        store.publish_key(key_record)
        service = IsolatedVerdictSigningService(
            store,
            {key_record.key_id: key},
            auth_registry,
            {anchor_key_id: anchor_pem},
        )
        envelope = service.sign(request, now=request.issued_at)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.public_bundle.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            canonical_json(envelope.model_dump(mode="json")) + "\n",
            encoding="utf-8",
        )
        args.public_bundle.write_text(
            canonical_json(store.public_bundle()) + "\n",
            encoding="utf-8",
        )
        print(
            canonical_json(
                {
                    "ok": True,
                    "request_id": request.request_id,
                    "run_id": request.run_id,
                    "key_id": envelope.key_id,
                    "payload_sha256": envelope.payload_sha256,
                    "anchor_receipt_id": envelope.payload.anchor_receipt_id,
                }
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        print(
            canonical_json(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "reason": str(exc),
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
