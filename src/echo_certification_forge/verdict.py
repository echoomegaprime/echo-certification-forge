"""Deterministic verdict calculation; no model output can override these rules."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from .canonical import sha256_json, utc_now
from .evidence import EvidenceStore
from .models import EnvironmentIdentity, ReleaseVerdict, RunOutcome, TargetIdentity, VerdictDecision
from .policy import RuleManifest
from .production_e2e import RULE_ID as PRODUCTION_E2E_RULE_ID
from .production_e2e import validate_attestation_trust_metadata
from .production_e2e import validate_production_e2e


class DeterministicVerdictEngine:
    def evaluate(
        self,
        store: EvidenceStore,
        run_id: str,
        tenant_id: str,
        manifest: RuleManifest,
        signing_key_id: str,
    ) -> VerdictDecision:
        run = store.get_run(run_id, tenant_id)
        reasons: list[str] = []
        outcome = RunOutcome(run["run_outcome"])
        if outcome is not RunOutcome.COMPLETE:
            reasons.append(f"run_outcome_{outcome.value.lower()}")
        if run["rule_manifest_id"] != manifest.manifest_id or run["rule_manifest_digest"] != manifest.digest:
            reasons.append("rule_manifest_identity_mismatch")

        target_data: dict[str, Any] = json.loads(run["target_identity_json"])
        environment_data: dict[str, Any] = json.loads(run["environment_identity_json"])
        # A run created via the intake `submit` path carries only a DECLARED target commitment
        # ({tenant_id, target_type, declared_identity_digest, reference}), not the full canonical
        # TargetIdentity. Such a run has not been reconciled to an acquired artifact, so it cannot be
        # certified: fail-closed with an explicit reason instead of crashing on TargetIdentity(**...).
        target: TargetIdentity | None = None
        environment: EnvironmentIdentity | None = None
        if "declared_identity_digest" in target_data or "artifact_sha256" not in target_data:
            reasons.append("target_identity_not_reconciled")
        else:
            target = TargetIdentity(**target_data)
            environment = EnvironmentIdentity(**environment_data)
            if target.identity_digest != run["target_identity_digest"]:
                reasons.append("target_identity_integrity_failed")
            if environment.identity_digest != run["environment_identity_digest"]:
                reasons.append("environment_identity_integrity_failed")
            if sha256_json(target_data) != run["target_identity_digest"]:
                reasons.append("target_identity_serialization_mismatch")
            if sha256_json(environment_data) != run["environment_identity_digest"]:
                reasons.append("environment_identity_serialization_mismatch")

        verification = store.verify_evidence(run_id, tenant_id)
        if not verification.valid:
            reasons.append("evidence_integrity_failed")
        results = store.list_rule_results(run_id, tenant_id)
        conditional_failures: list[str] = []
        for rule in manifest.rules:
            result = results.get(rule.id)
            if result is None:
                if rule.mandatory:
                    reasons.append(f"mandatory_rule_missing:{rule.id}")
                else:
                    conditional_failures.append(rule.id)
                continue
            if not result.passed:
                if rule.mandatory or not rule.conditional_allowed:
                    reasons.append(f"mandatory_rule_failed:{rule.id}")
                else:
                    conditional_failures.append(rule.id)
            if len(set(result.evidence_ids)) < rule.minimum_evidence:
                reasons.append(f"insufficient_rule_evidence:{rule.id}")
            invalid_references = set(result.evidence_ids) - verification.valid_artifact_ids
            if invalid_references:
                reasons.append(f"invalid_rule_evidence:{rule.id}")

        # PRODUCTION_READY is impossible without a current, signed, exact-identity E2E
        # attestation. This is an engine invariant, not an optional policy convention;
        # legacy/custom manifests that omit the rule fail closed as well.
        if not any(rule.id == PRODUCTION_E2E_RULE_ID for rule in manifest.rules):
            reasons.append("production_e2e_rule_missing_from_policy")
        e2e_result = results.get(PRODUCTION_E2E_RULE_ID)
        verified_e2e: dict[str, Any] | None = None
        if target is None or environment is None:
            reasons.append("production_e2e_identity_unavailable")
        elif e2e_result is None:
            reasons.append("production_e2e_attestation_missing")
        elif (
            not e2e_result.passed
            and e2e_result.details.get("validation")
            == "production_e2e_attestation_missing"
        ):
            # The executor records a fail-closed rule row even when no attestation was supplied.
            # Preserve that explicit cause instead of re-validating the diagnostic placeholder as
            # though it were a malformed attestation payload.
            reasons.append("production_e2e_attestation_missing")
        else:
            e2e_valid, e2e_reason = validate_production_e2e(
                e2e_result.details,
                target,
                environment,
                now=utc_now(),
            )
            if not e2e_valid:
                reasons.append(e2e_reason)
            else:
                trust_valid, trust_reason = validate_attestation_trust_metadata(
                    e2e_result.details
                )
                if not trust_valid:
                    reasons.append(trust_reason)
                else:
                    verified_e2e = e2e_result.details

        if store.blocking_findings(run_id, tenant_id):
            reasons.append("blocking_findings_present")

        if reasons:
            release_verdict = ReleaseVerdict.NOT_READY
        elif conditional_failures:
            release_verdict = ReleaseVerdict.CONDITIONALLY_READY
            reasons.extend(f"conditional_rule_failed:{item}" for item in conditional_failures)
        else:
            release_verdict = ReleaseVerdict.PRODUCTION_READY
            reasons.append("all_mandatory_rules_verified")

        issued_at = utc_now()
        return VerdictDecision(
            schema_version="1.0.0",
            run_id=run_id,
            tenant_id=tenant_id,
            run_outcome=outcome,
            release_verdict=release_verdict,
            reasons=tuple(sorted(set(reasons))),
            target_identity_digest=run["target_identity_digest"],
            environment_identity_digest=run["environment_identity_digest"],
            rule_manifest_id=manifest.manifest_id,
            rule_manifest_digest=manifest.digest,
            evidence_merkle_root=verification.merkle_root,
            production_e2e_attestation_id=(
                str(verified_e2e["attestation_id"]) if verified_e2e is not None else None
            ),
            production_e2e_profile=(
                str(verified_e2e["profile"]) if verified_e2e is not None else None
            ),
            production_e2e_envelope_sha256=(
                str(verified_e2e["attestation_envelope_sha256"])
                if verified_e2e is not None
                else None
            ),
            signing_key_id=signing_key_id,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=manifest.verdict_ttl_seconds),
        )
