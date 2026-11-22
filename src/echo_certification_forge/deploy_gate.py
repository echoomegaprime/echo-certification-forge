"""Exact-identity, signature, evidence, and lifecycle deployment gate."""
from __future__ import annotations

import json
from datetime import datetime

from .canonical import parse_utc_iso, sha256_json, utc_now
from .evidence import EvidenceStore
from .models import DeployGateDecision, ReleaseVerdict, SignedVerdictEnvelope
from .signing import TrustedPublicKeyRegistry


class DeployGate:
    def __init__(self, store: EvidenceStore, trusted_keys: TrustedPublicKeyRegistry) -> None:
        self.store = store
        self.trusted_keys = trusted_keys

    def evaluate(
        self,
        tenant_id: str,
        run_id: str,
        target_identity_digest: str,
        environment_identity_digest: str,
        rule_manifest_digest: str,
        evidence_merkle_root: str | None = None,
        signing_key_id: str | None = None,
        at: datetime | None = None,
    ) -> DeployGateDecision:
        reasons: list[str] = []
        row = self.store.latest_signed_verdict(run_id, tenant_id)
        if row is None:
            return DeployGateDecision(False, ReleaseVerdict.NOT_READY, run_id, ("signed_verdict_missing",))
        payload = json.loads(row["payload_json"])
        envelope = SignedVerdictEnvelope(
            payload=payload,
            signature_b64=row["signature_b64"],
            key_id=row["key_id"],
            public_key_pem=row["public_key_pem"],
        )
        if sha256_json(payload) != row["payload_sha256"]:
            reasons.append("stored_payload_hash_mismatch")
        signature_ok, signature_reason = self.trusted_keys.verify(envelope)
        if not signature_ok:
            reasons.append(signature_reason)
        if payload.get("release_verdict") != ReleaseVerdict.PRODUCTION_READY.value:
            reasons.append("verdict_not_production_ready")
        if payload.get("run_outcome") != "COMPLETE":
            reasons.append("run_not_complete")
        if payload.get("target_identity_digest") != target_identity_digest:
            reasons.append("target_identity_mismatch")
        if payload.get("environment_identity_digest") != environment_identity_digest:
            reasons.append("environment_identity_mismatch")
        if payload.get("rule_manifest_digest") != rule_manifest_digest:
            reasons.append("rule_manifest_mismatch")
        if (
            evidence_merkle_root is not None
            and payload.get("evidence_merkle_root") != evidence_merkle_root
        ):
            reasons.append("requested_evidence_root_mismatch")
        if signing_key_id is not None and payload.get("signing_key_id") != signing_key_id:
            reasons.append("requested_signing_key_mismatch")
        now = at or utc_now()
        if parse_utc_iso(str(payload["expires_at"])) <= now:
            reasons.append("verdict_expired")
        lifecycle = self.store.lifecycle_events(run_id, tenant_id)
        if lifecycle:
            reasons.extend(f"verdict_{event['event_type'].lower()}" for event in lifecycle)
        evidence = self.store.verify_evidence(run_id, tenant_id)
        if not evidence.valid:
            reasons.append("current_evidence_invalid")
        if payload.get("evidence_merkle_root") != evidence.merkle_root:
            reasons.append("evidence_root_mismatch")
        allowed = not reasons
        return DeployGateDecision(
            allowed=allowed,
            release_verdict=ReleaseVerdict.PRODUCTION_READY if allowed else ReleaseVerdict.NOT_READY,
            run_id=run_id,
            reasons=tuple(sorted(set(reasons))) if reasons else ("exact_certification_valid",),
        )
