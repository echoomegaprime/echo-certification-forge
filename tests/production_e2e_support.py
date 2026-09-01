"""Trusted production-E2E attestations used by tests that exercise ready paths."""

from __future__ import annotations

from datetime import timedelta

from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.production_e2e import (
    BASE_CHECKS,
    GENERIC_PROFILE,
    SCHEMA_VERSION,
    VerifiedProductionE2E,
    verify_signed_attestation,
)
from echo_certification_forge.signing import (
    Ed25519VerdictSigner,
    TrustedPublicKeyRegistry,
)


def trusted_generic_production_e2e(
    target: TargetIdentity,
    environment: EnvironmentIdentity,
) -> VerifiedProductionE2E:
    """Create a fresh signed generic attestation through the real trust verifier."""

    observed_at = utc_now()
    signer = Ed25519VerdictSigner.generate()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "attestation_id": f"test-e2e-{target.identity_digest[:16]}",
        "profile": GENERIC_PROFILE,
        "target_identity_digest": target.identity_digest,
        "environment_identity_digest": environment.identity_digest,
        "source_commit": target.source_commit,
        "deployment_sha": target.source_commit,
        "canonical_target": f"https://api.github.com/certforge/{target.identity_digest}",
        "required_checks": sorted(BASE_CHECKS),
        "checks": {name: True for name in sorted(BASE_CHECKS)},
        "stability_probe_count": 3,
        "observed_at": to_utc_iso(observed_at),
        "expires_at": to_utc_iso(observed_at + timedelta(minutes=30)),
        "signing_key_id": signer.key_id,
    }
    envelope = signer.sign_payload(payload)
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    return verify_signed_attestation(envelope, trusted)
