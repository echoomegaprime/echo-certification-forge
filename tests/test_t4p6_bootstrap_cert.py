"""T4.P6 acceptance — independent bootstrap certification.

The bootstrap attestation must be signed by a key distinct from the run-verdict signer, verify
under its own key, and NOT verify under the run-signer key (that separation is the whole point).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from echo_certification_forge.bootstrap import BootstrapCertifier, BootstrapClaim, BootstrapError
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

_ISSUED = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)

_CLAIMS = [
    BootstrapClaim("acceptance_suite_passing", True, "pytest:205-passed"),
    BootstrapClaim("control_plane_holds_no_private_key", True, "test_t4p3_signer_anchor"),
    BootstrapClaim("deploy_gate_requires_signed_verdict", True, "deploy_gate.py:signed_verdict_missing"),
]


def test_bootstrap_verdict_signed_by_key_independent_of_run_signer():
    run_signer = Ed25519VerdictSigner.generate()
    boot = BootstrapCertifier.generate()

    envelope = boot.certify(_CLAIMS, run_signer_key_id=run_signer.key_id, issued_at=_ISSUED)

    # SPEC T4.P6 #3: bootstrap self-verdict's signing key id differs from the run-signer key id.
    assert envelope.key_id != run_signer.key_id
    assert envelope.payload["signing_key_id"] == boot.key_id
    assert envelope.payload["bootstrap_verdict"] == "CERTIFIED"
    assert envelope.payload["subject"] == "echo-certification-forge"


def test_bootstrap_envelope_verifies_under_bootstrap_key_only():
    run_signer = Ed25519VerdictSigner.generate()
    boot = BootstrapCertifier.generate()
    envelope = boot.certify(_CLAIMS, run_signer_key_id=run_signer.key_id, issued_at=_ISSUED)

    trusts_bootstrap = TrustedPublicKeyRegistry.empty()
    trusts_bootstrap.add_pem(boot.public_key_pem)
    ok, reason = trusts_bootstrap.verify(envelope)
    assert ok, reason

    # A registry that trusts ONLY the run signer must NOT accept the bootstrap attestation —
    # this is the independence guarantee.
    trusts_run_only = TrustedPublicKeyRegistry.empty()
    trusts_run_only.add_pem(run_signer.public_key_pem)
    ok2, reason2 = trusts_run_only.verify(envelope)
    assert ok2 is False
    assert reason2 == "untrusted_signing_key"


def test_certify_rejects_non_independent_signer():
    boot = BootstrapCertifier.generate()
    with pytest.raises(BootstrapError, match="independent"):
        boot.certify(_CLAIMS, run_signer_key_id=boot.key_id, issued_at=_ISSUED)


def test_verdict_is_default_deny():
    run_signer = Ed25519VerdictSigner.generate()
    boot = BootstrapCertifier.generate()

    # no claims -> NOT_CERTIFIED
    empty = boot.certify([], run_signer_key_id=run_signer.key_id, issued_at=_ISSUED)
    assert empty.payload["bootstrap_verdict"] == "NOT_CERTIFIED"

    # one unsatisfied claim -> NOT_CERTIFIED, and it is named
    mixed = boot.certify(
        [BootstrapClaim("ok_one", True, "e1"), BootstrapClaim("failing_one", False, "e2")],
        run_signer_key_id=run_signer.key_id, issued_at=_ISSUED,
    )
    assert mixed.payload["bootstrap_verdict"] == "NOT_CERTIFIED"
    assert mixed.payload["unsatisfied_claims"] == ["failing_one"]


def test_tampered_bootstrap_attestation_fails_verification():
    run_signer = Ed25519VerdictSigner.generate()
    boot = BootstrapCertifier.generate()
    envelope = boot.certify(_CLAIMS, run_signer_key_id=run_signer.key_id, issued_at=_ISSUED)

    trusts_bootstrap = TrustedPublicKeyRegistry.empty()
    trusts_bootstrap.add_pem(boot.public_key_pem)

    # flip the verdict in the payload without re-signing
    tampered = envelope.payload | {"bootstrap_verdict": "CERTIFIED_TAMPERED"}
    from echo_certification_forge.models import SignedVerdictEnvelope
    forged = SignedVerdictEnvelope(
        payload=tampered, signature_b64=envelope.signature_b64,
        key_id=envelope.key_id, public_key_pem=envelope.public_key_pem,
    )
    ok, reason = trusts_bootstrap.verify(forged)
    assert ok is False
    assert reason == "invalid_signature"
