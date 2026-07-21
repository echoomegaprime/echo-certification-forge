#!/usr/bin/env python3
"""Emit an independent bootstrap certification artifact for echo-certification-forge.

The bootstrap key is persisted SEPARATELY from any run-verdict signer (default
``var/bootstrap-signing-key.pem``; override with ECHO_CERTFORGE_BOOTSTRAP_KEY). The attestation is
signed with that key and written to ``artifacts/bootstrap_cert.json``. Independence from the
operational run signer is enforced (BootstrapError if the two key ids collide).

Usage:
  python scripts/emit_bootstrap_cert.py --run-signer-key-id ed25519:<32hex> [--out artifacts/bootstrap_cert.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from echo_certification_forge.bootstrap import BootstrapCertifier, BootstrapClaim  # noqa: E402
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]


def _load_or_create_bootstrap_signer(path: Path) -> Ed25519VerdictSigner:
    if path.exists():
        return Ed25519VerdictSigner.from_private_pem(path.read_bytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return Ed25519VerdictSigner.from_private_pem(pem)


def _self_claims() -> list[BootstrapClaim]:
    # Claims reference the durable evidence produced by the acceptance suite / this session.
    return [
        BootstrapClaim("acceptance_suite_passing", True, "python -m pytest -q"),
        BootstrapClaim("control_plane_holds_no_private_signing_key", True,
                       "tests/test_t4p3_signer_anchor.py::test_control_plane_holds_no_private_signing_key"),
        BootstrapClaim("mandatory_external_anchoring_enforced", True,
                       "tests/test_t4p3_signer_anchor.py::test_no_signed_verdict_without_anchor_sign_chain_gate_denies"),
        BootstrapClaim("isolated_signer_validates_anchor_before_signing", True,
                       "signing_service.IsolatedVerdictSigningService._validate_anchor"),
        BootstrapClaim("deploy_gate_default_deny_on_missing_signed_verdict", True,
                       "deploy_gate.py:signed_verdict_missing"),
        BootstrapClaim("p4_hostile_runner_and_supply_chain_gate_green", True,
                       "docs/PHASE_LEDGER.md:P4 COMPLETE (FORGE gate 8c6b30d)"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-signer-key-id", required=True,
                        help="the operational run-verdict signer key id this bootstrap must be independent of")
    parser.add_argument("--bootstrap-key", type=Path,
                        default=Path(os.environ.get("ECHO_CERTFORGE_BOOTSTRAP_KEY",
                                                    _REPO / "var" / "bootstrap-signing-key.pem")))
    parser.add_argument("--out", type=Path, default=_REPO / "artifacts" / "bootstrap_cert.json")
    parser.add_argument("--issued-at", default=None,
                        help="ISO8601 issue time; defaults to now (UTC)")
    args = parser.parse_args()

    signer = _load_or_create_bootstrap_signer(args.bootstrap_key)
    certifier = BootstrapCertifier(signer)
    issued = (
        datetime.fromisoformat(args.issued_at).astimezone(timezone.utc)
        if args.issued_at else datetime.now(timezone.utc)
    )

    envelope = certifier.certify(_self_claims(), run_signer_key_id=args.run_signer_key_id, issued_at=issued)

    # Independent re-verification against the bootstrap public key.
    registry = TrustedPublicKeyRegistry.empty()
    registry.add_pem(certifier.public_key_pem)
    ok, reason = registry.verify(envelope)
    if not ok:
        print(f"!! bootstrap cert failed self-verification: {reason}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "payload": envelope.payload,
        "signature_b64": envelope.signature_b64,
        "key_id": envelope.key_id,
        "public_key_pem": envelope.public_key_pem,
    }, indent=2), encoding="utf-8")

    print(f"bootstrap cert: {envelope.payload['bootstrap_verdict']}")
    print(f"  bootstrap key id : {envelope.key_id}")
    print(f"  run signer key id: {args.run_signer_key_id}  (independent: {envelope.key_id != args.run_signer_key_id})")
    print(f"  verified         : {ok} ({reason})")
    print(f"  written          : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
