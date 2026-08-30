from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest

from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.models import (
    RedactionStatus,
    ReleaseVerdict,
    RuleResult,
    RunOutcome,
    EnvironmentIdentity,
    TargetIdentity,
    VerdictLifecycleEvent,
)
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.production_e2e import BASE_CHECKS, GENERIC_PROFILE, SCHEMA_VERSION
from echo_certification_forge.verdict import DeterministicVerdictEngine


def register(store, manifest, target, environment, run_id="cert-001"):
    store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    return run_id


def satisfy_all_rules(store, manifest, run_id, tenant_id, *, include_production_e2e=True):
    run = store.get_run(run_id, tenant_id)
    target = TargetIdentity(**json.loads(run["target_identity_json"]))
    environment = EnvironmentIdentity(**json.loads(run["environment_identity_json"]))
    observed_at = utc_now()
    production_e2e = {
        "schema_version": SCHEMA_VERSION,
        "attestation_id": f"e2e-{run_id}",
        "profile": GENERIC_PROFILE,
        "target_identity_digest": target.identity_digest,
        "environment_identity_digest": environment.identity_digest,
        "source_commit": target.source_commit,
        "deployment_sha": target.source_commit,
        "canonical_target": "https://example.test/runtime",
        "required_checks": sorted(BASE_CHECKS),
        "checks": {name: True for name in sorted(BASE_CHECKS)},
        "stability_probe_count": 3,
        "observed_at": to_utc_iso(observed_at),
        "expires_at": to_utc_iso(observed_at + timedelta(minutes=30)),
        "signing_key_id": "ed25519:" + "a" * 32,
        "signature_verified": True,
        "collector_key_id": "ed25519:" + "a" * 32,
        "attestation_envelope_sha256": "f" * 64,
    }
    for index, rule in enumerate(manifest.rules, start=1):
        if rule.id == "production_e2e" and not include_production_e2e:
            continue
        artifact_id = f"evidence-{index:02d}"
        store.append_artifact(
            run_id,
            tenant_id,
            artifact_id,
            json.dumps({"rule": rule.id, "passed": True}, sort_keys=True).encode(),
            "application/json",
            "deterministic-test-harness",
            RedactionStatus.COMPLETE,
        )
        store.record_rule_result(
            run_id,
            tenant_id,
            RuleResult(
                rule.id,
                True,
                (artifact_id,),
                production_e2e if rule.id == "production_e2e" else {"source": "acceptance"},
            ),
        )


def test_run_defaults_to_not_ready(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.run_outcome is RunOutcome.INCONCLUSIVE
    assert decision.release_verdict is ReleaseVerdict.NOT_READY
    assert "evidence_integrity_failed" in decision.reasons
    assert any(reason.startswith("mandatory_rule_missing:") for reason in decision.reasons)


def test_complete_run_with_verified_evidence_gets_signed_ready(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict is ReleaseVerdict.PRODUCTION_READY
    envelope = signer.sign(decision)
    store.save_signed_verdict(run_id, target.tenant_id, envelope)
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    verified, reason = trusted.verify(envelope)
    assert verified, reason
    gate = DeployGate(store, trusted).evaluate(
        target.tenant_id,
        run_id,
        target.identity_digest,
        environment.identity_digest,
        manifest.digest,
    )
    assert gate.allowed


def test_source_and_rule_rows_without_production_e2e_never_get_ready(
    store, manifest, target, environment
):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(
        store,
        manifest,
        run_id,
        target.tenant_id,
        include_production_e2e=False,
    )
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict is ReleaseVerdict.NOT_READY
    assert "production_e2e_attestation_missing" in decision.reasons


def test_bare_database_rows_cannot_manufacture_ready(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    now = "2026-07-16T00:00:00Z"
    with closing(sqlite3.connect(store.db_path)) as connection:
        with connection:
            for index, rule in enumerate(manifest.rules, start=1):
                artifact_id = f"bare-{index:02d}"
                descriptor = {
                    "artifact_id": artifact_id,
                    "run_id": run_id,
                    "tenant_id": target.tenant_id,
                    "relative_path": f"{target.tenant_id}/{run_id}/artifacts/{artifact_id}.bin",
                    "sha256": "0" * 64,
                    "size_bytes": 1,
                    "media_type": "application/json",
                    "source_component": "forged-row",
                    "redaction_status": "COMPLETE",
                    "ordinal": index,
                    "created_at": now,
                }
                from echo_certification_forge.canonical import sha256_json
                from echo_certification_forge.evidence import _ZERO_HASH
                record_hash = sha256_json(descriptor)
                previous = _ZERO_HASH if index == 1 else "1" * 64
                chain_hash = "1" * 64
                connection.execute(
                    "INSERT INTO evidence_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        artifact_id, run_id, target.tenant_id, descriptor["relative_path"], "0" * 64, 1,
                        "application/json", "forged-row", "COMPLETE", index, now,
                        record_hash, previous, chain_hash,
                    ),
                )
                connection.execute(
                    "INSERT INTO rule_results(run_id, tenant_id, rule_id, passed, evidence_ids_json, details_json, created_at) VALUES (?, ?, ?, 1, ?, '{}', ?)",
                    (run_id, target.tenant_id, rule.id, json.dumps([artifact_id]), now),
                )
            connection.execute(
                "UPDATE runs SET run_outcome = 'COMPLETE' WHERE run_id = ?", (run_id,)
            )
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict is ReleaseVerdict.NOT_READY
    assert "evidence_integrity_failed" in decision.reasons
    assert any(reason.startswith("invalid_rule_evidence:") for reason in decision.reasons)


def test_altered_artifact_forces_not_ready(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    row = store.verify_evidence(run_id, target.tenant_id)
    assert row.valid
    artifact = store.evidence_root / target.tenant_id / run_id / "artifacts" / "evidence-01.bin"
    artifact.write_bytes(b"tampered")
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict is ReleaseVerdict.NOT_READY
    assert "evidence_integrity_failed" in decision.reasons


def test_missing_artifact_forces_not_ready(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    artifact = store.evidence_root / target.tenant_id / run_id / "artifacts" / "evidence-02.bin"
    artifact.unlink()
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict is ReleaseVerdict.NOT_READY


def test_digest_mismatch_blocks_deployment(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(store, run_id, target.tenant_id, manifest, signer.key_id)
    envelope = signer.sign(decision)
    store.save_signed_verdict(run_id, target.tenant_id, envelope)
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    gate = DeployGate(store, trusted).evaluate(
        target.tenant_id, run_id, "f" * 64, environment.identity_digest, manifest.digest
    )
    assert not gate.allowed
    assert "target_identity_mismatch" in gate.reasons


def test_untrusted_self_signed_verdict_is_rejected(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    attacker = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(store, run_id, target.tenant_id, manifest, attacker.key_id)
    store.save_signed_verdict(run_id, target.tenant_id, attacker.sign(decision))
    gate = DeployGate(store, TrustedPublicKeyRegistry.empty()).evaluate(
        target.tenant_id, run_id, target.identity_digest, environment.identity_digest, manifest.digest
    )
    assert not gate.allowed
    assert "untrusted_signing_key" in gate.reasons


def test_revocation_blocks_previously_valid_verdict(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(store, run_id, target.tenant_id, manifest, signer.key_id)
    store.save_signed_verdict(run_id, target.tenant_id, signer.sign(decision))
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    store.append_lifecycle_event(
        run_id, target.tenant_id, VerdictLifecycleEvent.REVOKED, "release-authority", "security advisory"
    )
    gate = DeployGate(store, trusted).evaluate(
        target.tenant_id, run_id, target.identity_digest, environment.identity_digest, manifest.digest
    )
    assert not gate.allowed
    assert "verdict_revoked" in gate.reasons


def test_evidence_rows_are_append_only(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    store.append_artifact(
        run_id, target.tenant_id, "immutable-evidence", b"proof", "text/plain", "unit-test"
    )
    with closing(sqlite3.connect(store.db_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE evidence_artifacts SET sha256 = ? WHERE artifact_id = ?",
                ("f" * 64, "immutable-evidence"),
            )


def test_cross_tenant_read_is_not_disclosed(store, manifest, target, environment):
    run_id = register(store, manifest, target, environment)
    with pytest.raises(KeyError):
        store.get_run(run_id, "tenant-other")
