"""Deterministic verdict calculation; no model output can override these rules."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from .canonical import sha256_json, utc_now
from .evidence import EvidenceStore
from .models import EnvironmentIdentity, ReleaseVerdict, RunOutcome, TargetIdentity, VerdictDecision
from .policy import RuleManifest


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
            signing_key_id=signing_key_id,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=manifest.verdict_ttl_seconds),
        )
