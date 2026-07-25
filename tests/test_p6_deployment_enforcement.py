"""P6 acceptance — deployment enforcement: certification is mandatory to deploy.

SPEC section 37 acceptance, executed against the REAL stack (real EvidenceStore, real
Ed25519 signing, real RunExecutor with a real subprocess journey, real DeployGate):

  1. A production deployment using an uncertified artifact must fail.
  2. A deployment using a different digest from the certified artifact must fail.
  3. A valid, unexpired READY artifact under the required policy must pass.

Plus the P6 enforcement contract: fail-closed on missing/stale/untrusted certification,
staging-first acceptance, revocation, rollback evidence, tenant isolation, and an
append-only tamper-evident audit chain.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import threading
from datetime import timedelta
from pathlib import Path

import pytest

from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.deployment import (
    AdmissionRequest,
    BindingError,
    DeploymentAdmissionController,
    DeploymentLedger,
    DeploymentOutcomeStatus,
    DeploymentRecordType,
    OutcomeError,
    normalize_artifact_digest,
)
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import (
    EnvironmentIdentity,
    TargetIdentity,
    VerdictLifecycleEvent,
)
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

TENANT = "tenant-alpha"
OTHER_TENANT = "tenant-beta"
ACTOR = "certforge.test"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _target(artifact_label: str, tenant_id: str = TENANT) -> TargetIdentity:
    return TargetIdentity(
        tenant_id=tenant_id,
        target_type="container",
        canonical_ref=f"registry.echo/app@{artifact_label}",
        artifact_sha256=_digest(artifact_label),
        source_commit="abc123def456",
        dependency_sha256=_digest("dependencies"),
        configuration_sha256=_digest("configuration"),
    )


@pytest.fixture
def ledger(tmp_path: Path) -> DeploymentLedger:
    return DeploymentLedger(tmp_path / "deployments.sqlite3")


@pytest.fixture
def signer() -> Ed25519VerdictSigner:
    return Ed25519VerdictSigner.generate()


@pytest.fixture
def trusted(signer: Ed25519VerdictSigner) -> TrustedPublicKeyRegistry:
    registry = TrustedPublicKeyRegistry.empty()
    registry.add_pem(signer.public_key_pem)
    return registry


@pytest.fixture
def controller(store, trusted, ledger, manifest) -> DeploymentAdmissionController:
    return DeploymentAdmissionController(store, trusted, ledger, manifest.digest)


def _certify(
    store,
    manifest,
    signer: Ed25519VerdictSigner,
    environment: EnvironmentIdentity,
    tmp_path: Path,
    run_id: str,
    target: TargetIdentity,
) -> None:
    """Drive a REAL certification run to a signed PRODUCTION_READY verdict."""
    store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    workdir = tmp_path / f"src-{run_id}"
    workdir.mkdir()
    (workdir / "hello.py").write_text("print('service ok')\n", encoding="utf-8")
    executor = RunExecutor(store, manifest, signer)
    result = executor.execute(
        run_id,
        target.tenant_id,
        workdir,
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "hello.py"],
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
    )
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings


def _admission(
    artifact: str,
    env: str,
    environment: EnvironmentIdentity,
    manifest,
    deployment_id: str = "deploy-001",
    tenant_id: str = TENANT,
) -> AdmissionRequest:
    return AdmissionRequest(
        tenant_id=tenant_id,
        artifact_sha256=artifact,
        deployment_environment=env,
        environment_identity_digest=environment.identity_digest,
        rule_manifest_digest=manifest.digest,
        deployment_id=deployment_id,
        requested_by="ci.pipeline",
    )


# --------------------------------------------------------------------------------------
# SPEC section 37 acceptance
# --------------------------------------------------------------------------------------


def test_spec_p6_uncertified_artifact_production_deployment_fails(
    controller, environment, manifest
):
    decision = controller.admit(
        _admission(_digest("never-certified"), "production", environment, manifest), ACTOR
    )
    assert decision.allowed is False
    assert "artifact_not_certified" in decision.reasons
    assert decision.run_id is None


def test_spec_p6_different_digest_from_certified_artifact_fails(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-v1")
    _certify(store, manifest, signer, environment, tmp_path, "cert-p6-v1", target)
    controller.bind_certification("cert-p6-v1", TENANT, ACTOR)
    decision = controller.admit(
        _admission(_digest("app-v2-DIFFERENT"), "staging", environment, manifest), ACTOR
    )
    assert decision.allowed is False
    assert "artifact_not_certified" in decision.reasons


def test_spec_p6_valid_unexpired_ready_artifact_under_required_policy_passes(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-v1")
    _certify(store, manifest, signer, environment, tmp_path, "cert-p6-v1", target)
    binding = controller.bind_certification("cert-p6-v1", TENANT, ACTOR)
    assert binding["created"] is True
    assert binding["artifact_sha256"] == target.artifact_sha256

    staging = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-stg-1"),
        ACTOR,
    )
    assert staging.allowed is True, staging.reasons
    assert staging.reasons == ("exact_certification_valid",)
    controller.report_outcome(
        staging.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "staging green", ACTOR
    )

    production = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-prd-1"),
        ACTOR,
    )
    assert production.allowed is True, production.reasons
    assert production.run_id == "cert-p6-v1"


# --------------------------------------------------------------------------------------
# Fail-closed: missing / stale / untrusted / revoked / policy-mismatched certification
# --------------------------------------------------------------------------------------


def _resigned_payload(store, run_id: str, signer: Ed25519VerdictSigner, **overrides):
    row = store.latest_signed_verdict(run_id, TENANT)
    payload = json.loads(row["payload_json"])
    payload.update(overrides)
    envelope = signer.sign_payload(payload)
    store.save_signed_verdict(run_id, TENANT, envelope)


def test_missing_signed_verdict_cannot_bind(controller, store, manifest, environment):
    target = _target("app-unsigned")
    store.register_run("cert-unsigned", target, environment, manifest.manifest_id, manifest.digest)
    with pytest.raises(BindingError) as excinfo:
        controller.bind_certification("cert-unsigned", TENANT, ACTOR)
    assert excinfo.value.code == "signed_verdict_missing"


def test_stale_expired_certification_is_denied(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-stale")
    _certify(store, manifest, signer, environment, tmp_path, "cert-stale", target)
    controller.bind_certification("cert-stale", TENANT, ACTOR)
    _resigned_payload(
        store, "cert-stale", signer, expires_at=to_utc_iso(utc_now() - timedelta(seconds=1))
    )
    decision = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest), ACTOR
    )
    assert decision.allowed is False
    assert "verdict_expired" in decision.reasons


def test_untrusted_signing_key_is_denied(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-untrusted")
    _certify(store, manifest, signer, environment, tmp_path, "cert-untrusted", target)
    controller.bind_certification("cert-untrusted", TENANT, ACTOR)
    rogue = Ed25519VerdictSigner.generate()  # never added to the trusted registry
    _resigned_payload(store, "cert-untrusted", rogue, signing_key_id=rogue.key_id)
    decision = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest), ACTOR
    )
    assert decision.allowed is False
    assert "untrusted_signing_key" in decision.reasons


def test_revoked_certification_is_denied(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-revoked")
    _certify(store, manifest, signer, environment, tmp_path, "cert-revoked", target)
    controller.bind_certification("cert-revoked", TENANT, ACTOR)
    store.append_lifecycle_event(
        "cert-revoked", TENANT, VerdictLifecycleEvent.REVOKED, ACTOR, "critical vulnerability"
    )
    decision = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest), ACTOR
    )
    assert decision.allowed is False
    assert "verdict_revoked" in decision.reasons


def test_wrong_release_policy_or_environment_is_denied(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-policy")
    _certify(store, manifest, signer, environment, tmp_path, "cert-policy", target)
    controller.bind_certification("cert-policy", TENANT, ACTOR)

    wrong_policy = AdmissionRequest(
        tenant_id=TENANT,
        artifact_sha256=target.artifact_sha256,
        deployment_environment="staging",
        environment_identity_digest=environment.identity_digest,
        rule_manifest_digest=_digest("some-other-policy"),
        deployment_id="deploy-wp",
        requested_by="ci.pipeline",
    )
    decision = controller.admit(wrong_policy, ACTOR)
    assert decision.allowed is False
    assert "rule_manifest_not_active" in decision.reasons

    wrong_environment = AdmissionRequest(
        tenant_id=TENANT,
        artifact_sha256=target.artifact_sha256,
        deployment_environment="staging",
        environment_identity_digest=_digest("some-other-environment"),
        rule_manifest_digest=manifest.digest,
        deployment_id="deploy-we",
        requested_by="ci.pipeline",
    )
    decision = controller.admit(wrong_environment, ACTOR)
    assert decision.allowed is False
    assert "environment_identity_mismatch" in decision.reasons


# --------------------------------------------------------------------------------------
# Staging-first acceptance
# --------------------------------------------------------------------------------------


def test_production_requires_prior_successful_staging(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-sf")
    _certify(store, manifest, signer, environment, tmp_path, "cert-sf", target)
    controller.bind_certification("cert-sf", TENANT, ACTOR)

    # no staging at all -> denied
    decision = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-p0"),
        ACTOR,
    )
    assert decision.allowed is False
    assert decision.reasons == ("staging_acceptance_missing",)

    # staging admitted but FAILED -> still denied
    staging = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-s1"), ACTOR
    )
    assert staging.allowed is True
    controller.report_outcome(
        staging.admission_id, TENANT, DeploymentOutcomeStatus.FAILED, "smoke red", ACTOR
    )
    decision = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-p1"),
        ACTOR,
    )
    assert decision.allowed is False
    assert "staging_acceptance_missing" in decision.reasons

    # a NEW staging admission that SUCCEEDED unlocks production
    staging2 = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-s2"), ACTOR
    )
    controller.report_outcome(
        staging2.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "smoke green", ACTOR
    )
    decision = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-p2"),
        ACTOR,
    )
    assert decision.allowed is True, decision.reasons


# --------------------------------------------------------------------------------------
# Rollback evidence and outcomes
# --------------------------------------------------------------------------------------


def _deploy_to_production(controller, manifest, environment, artifact: str, tag: str) -> str:
    staging = controller.admit(
        _admission(artifact, "staging", environment, manifest, f"deploy-stg-{tag}"), ACTOR
    )
    assert staging.allowed, staging.reasons
    controller.report_outcome(
        staging.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "staging green", ACTOR
    )
    production = controller.admit(
        _admission(artifact, "production", environment, manifest, f"deploy-prd-{tag}"), ACTOR
    )
    assert production.allowed, production.reasons
    return production.admission_id


def test_failed_production_deployment_produces_rollback_evidence(
    controller, store, manifest, environment, signer, tmp_path
):
    v1 = _target("app-v1")
    v2 = _target("app-v2")
    _certify(store, manifest, signer, environment, tmp_path, "cert-v1", v1)
    _certify(store, manifest, signer, environment, tmp_path, "cert-v2", v2)
    controller.bind_certification("cert-v1", TENANT, ACTOR)
    controller.bind_certification("cert-v2", TENANT, ACTOR)

    # v1 ships clean; it becomes the last known good
    v1_admission = _deploy_to_production(controller, manifest, environment, v1.artifact_sha256, "v1")
    controller.report_outcome(
        v1_admission, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )

    # v2 ships and fails in production
    v2_admission = _deploy_to_production(controller, manifest, environment, v2.artifact_sha256, "v2")
    failure = controller.report_outcome(
        v2_admission, TENANT, DeploymentOutcomeStatus.FAILED, "prod smoke red", ACTOR
    )
    # the failure record itself carries the last-known-good rollback candidate
    assert failure["payload"]["rollback_candidate"]["artifact_sha256"] == v1.artifact_sha256

    # the live rollback target is v1
    target = controller.rollback_target(TENANT)
    assert target is not None
    assert target["artifact_sha256"] == v1.artifact_sha256
    assert target["run_id"] == "cert-v1"

    # rollback evidence MUST name the restored digest — refuse otherwise
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            v2_admission, TENANT, DeploymentOutcomeStatus.ROLLED_BACK, "rolled back", ACTOR
        )
    assert excinfo.value.code == "rollback_target_required"
    rollback = controller.report_outcome(
        v2_admission,
        TENANT,
        DeploymentOutcomeStatus.ROLLED_BACK,
        "restored v1",
        ACTOR,
        rollback_to=v1.artifact_sha256,
    )
    assert rollback["payload"]["rollback_to"] == v1.artifact_sha256

    # a since-revoked certification is never offered as a rollback target (fail-closed)
    store.append_lifecycle_event(
        "cert-v1", TENANT, VerdictLifecycleEvent.REVOKED, ACTOR, "cve found in v1"
    )
    assert controller.rollback_target(TENANT) is None


def test_outcome_on_denied_admission_is_refused(controller, environment, manifest):
    denied = controller.admit(
        _admission(_digest("uncertified"), "staging", environment, manifest), ACTOR
    )
    assert denied.allowed is False
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            denied.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "impossible", ACTOR
        )
    assert excinfo.value.code == "outcome_on_denied_admission"


# --------------------------------------------------------------------------------------
# Tenant isolation
# --------------------------------------------------------------------------------------


def test_tenant_isolation_on_binding_admission_and_audit(
    controller, store, manifest, environment, signer, tmp_path
):
    target = _target("app-iso")
    _certify(store, manifest, signer, environment, tmp_path, "cert-iso", target)
    controller.bind_certification("cert-iso", TENANT, ACTOR)

    # another tenant cannot bind this run
    with pytest.raises(KeyError):
        controller.bind_certification("cert-iso", OTHER_TENANT, ACTOR)

    # another tenant presenting the same digest is uncertified in THEIR scope
    decision = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-x",
                   tenant_id=OTHER_TENANT),
        ACTOR,
    )
    assert decision.allowed is False
    assert "artifact_not_certified" in decision.reasons

    # audit trails are tenant-scoped
    alpha_trail = controller.ledger.trail(TENANT)
    beta_trail = controller.ledger.trail(OTHER_TENANT)
    assert all(row["tenant_id"] == TENANT for row in alpha_trail)
    assert all(row["tenant_id"] == OTHER_TENANT for row in beta_trail)
    assert any(row["record_type"] == "BINDING" for row in alpha_trail)
    assert not any(row["record_type"] == "BINDING" for row in beta_trail)


# --------------------------------------------------------------------------------------
# Auditability: append-only, hash-chained, tamper-evident
# --------------------------------------------------------------------------------------


def test_audit_chain_is_append_only_and_tamper_evident(
    controller, store, manifest, environment, signer, tmp_path, ledger
):
    target = _target("app-audit")
    _certify(store, manifest, signer, environment, tmp_path, "cert-audit", target)
    controller.bind_certification("cert-audit", TENANT, ACTOR)
    controller.admit(_admission(target.artifact_sha256, "staging", environment, manifest), ACTOR)

    valid, broken = ledger.verify_chain()
    assert valid is True and broken is None

    # UPDATE is refused outright (append-only triggers)
    connection = sqlite3.connect(ledger.db_path)
    with pytest.raises(sqlite3.DatabaseError):
        with connection:
            connection.execute("UPDATE deployment_records SET actor = 'attacker' WHERE ordinal = 1")

    # even an attacker who strips the triggers cannot rewrite history undetected
    with connection:
        connection.execute("DROP TRIGGER no_update_deployment_records")
        connection.execute(
            "UPDATE deployment_records SET payload_json = ? WHERE ordinal = 1",
            (json.dumps({"forged": True}),),
        )
    connection.close()
    valid, broken = ledger.verify_chain()
    assert valid is False
    assert broken == 1


def test_normalize_artifact_digest_accepts_registry_form():
    bare = _digest("image")
    assert normalize_artifact_digest(f"sha256:{bare}") == bare
    assert normalize_artifact_digest(bare.upper()) == bare
    with pytest.raises(ValueError):
        normalize_artifact_digest("sha256:not-a-digest")


def test_concurrent_ledger_appends_yield_one_linear_valid_chain(ledger):
    """Chain-tip reads happen under BEGIN IMMEDIATE — parallel writers cannot fork the chain."""
    workers = 8
    appends_per_worker = 5
    errors: list[Exception] = []
    barrier = threading.Barrier(workers)

    def writer(worker: int) -> None:
        try:
            barrier.wait(timeout=30)
            for i in range(appends_per_worker):
                ledger.append(
                    DeploymentRecordType.ADMISSION,
                    TENANT,
                    {"worker": worker, "attempt": i},
                    ACTOR,
                    deployment_environment="staging",
                    allowed=False,
                )
        except Exception as exc:  # pragma: no cover — failure evidence
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert errors == []

    rows = ledger.trail(TENANT)
    assert len(rows) == workers * appends_per_worker
    valid, broken = ledger.verify_chain()
    assert valid is True and broken is None
    # exactly one linear chain: hashes unique, each prev links the previous record
    chain_hashes = [row["chain_hash"] for row in rows]
    assert len(set(chain_hashes)) == len(chain_hashes)
    prev = "0" * 64
    for row in rows:
        assert row["prev_chain_hash"] == prev
        prev = row["chain_hash"]


def test_policy_rollover_rejects_stale_caller_supplied_manifest_digest(
    store, trusted, ledger, manifest, environment, signer, tmp_path
):
    """The controller is bound to the ACTIVE manifest digest — a caller cannot resurrect an
    old policy by supplying its digest after rollover."""
    target = _target("app-rollover")
    _certify(store, manifest, signer, environment, tmp_path, "cert-rollover", target)

    # Bind while the certified manifest is still ACTIVE, then roll the policy over.
    original = DeploymentAdmissionController(store, trusted, ledger, manifest.digest)
    original.bind_certification("cert-rollover", TENANT, ACTOR)
    rolled = DeploymentAdmissionController(
        store, trusted, ledger, _digest("rolled-over-manifest")
    )

    # binding a run certified under the superseded policy AFTER rollover is refused
    with pytest.raises(BindingError, match="rule_manifest_not_active"):
        rolled.bind_certification("cert-rollover", TENANT, ACTOR)

    # presenting the OLD (certified) digest after rollover is refused outright
    stale = rolled.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-ro-1"),
        ACTOR,
    )
    assert stale.allowed is False
    assert "rule_manifest_not_active" in stale.reasons

    # presenting the ACTIVE digest still fails closed: the verdict is bound to the old policy
    active = AdmissionRequest(
        tenant_id=TENANT,
        artifact_sha256=target.artifact_sha256,
        deployment_environment="staging",
        environment_identity_digest=environment.identity_digest,
        rule_manifest_digest=_digest("rolled-over-manifest"),
        deployment_id="deploy-ro-2",
        requested_by="ci.pipeline",
    )
    decision = rolled.admit(active, ACTOR)
    assert decision.allowed is False
    assert "rule_manifest_mismatch" in decision.reasons


def test_nonce_consumption_is_atomic_and_persistent_across_instances(tmp_path):
    """Replay protection survives worker restarts: a nonce consumed by one ledger
    instance is rejected by ANOTHER instance over the same database, and concurrent
    consumers agree on exactly one winner."""
    path = tmp_path / "deployments.sqlite3"
    first = DeploymentLedger(path)
    assert first.consume_nonce(TENANT, "nonce-persistence-0001", ttl_seconds=600) is True
    # same instance replay
    assert first.consume_nonce(TENANT, "nonce-persistence-0001", ttl_seconds=600) is False
    # a NEW instance (simulated restart / second worker) still sees it consumed
    second = DeploymentLedger(path)
    assert second.consume_nonce(TENANT, "nonce-persistence-0001", ttl_seconds=600) is False
    # nonces are tenant-scoped: another tenant may use the same nonce value
    assert second.consume_nonce("tenant-beta", "nonce-persistence-0001", ttl_seconds=600) is True

    # concurrent consumption of ONE fresh nonce across instances -> exactly one winner
    ledgers = [DeploymentLedger(path) for _ in range(4)]
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(len(ledgers))

    def consume(ledger: DeploymentLedger) -> None:
        barrier.wait()
        outcome = ledger.consume_nonce(TENANT, "nonce-concurrent-0001", ttl_seconds=600)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=consume, args=(ledger,)) for ledger in ledgers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(results) == [False, False, False, True]

    # an EXPIRED nonce can be pruned and reused (TTL window bounds the replay cache)
    assert first.consume_nonce(TENANT, "nonce-expiring-0001", ttl_seconds=-1) is True
    assert first.consume_nonce(TENANT, "nonce-expiring-0001", ttl_seconds=-1) is True


# --------------------------------------------------------------------------------------
# Terminal outcome transitions — atomic, immutable, admission-bound rollback evidence
# --------------------------------------------------------------------------------------


def test_terminal_outcome_transitions_are_immutable(
    controller, store, manifest, environment, signer, tmp_path, ledger
):
    """Once ANY terminal outcome exists for an admission, contradictory or repeated
    transitions are rejected — especially the forgery FAILED -> SUCCEEDED — and a
    ROLLED_BACK is only accepted against the candidate BOUND into the FAILED record."""
    v1 = _target("term-v1")
    v2 = _target("term-v2")
    _certify(store, manifest, signer, environment, tmp_path, "cert-term-v1", v1)
    _certify(store, manifest, signer, environment, tmp_path, "cert-term-v2", v2)
    controller.bind_certification("cert-term-v1", TENANT, ACTOR)
    controller.bind_certification("cert-term-v2", TENANT, ACTOR)

    # -- staging: the one successful outcome is immutable ------------------------------
    staging = controller.admit(
        _admission(v1.artifact_sha256, "staging", environment, manifest, "deploy-term-s1"), ACTOR
    )
    assert staging.allowed, staging.reasons
    controller.report_outcome(
        staging.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "staging green", ACTOR
    )
    for repeat in (DeploymentOutcomeStatus.SUCCEEDED, DeploymentOutcomeStatus.FAILED):
        with pytest.raises(OutcomeError) as excinfo:
            controller.report_outcome(staging.admission_id, TENANT, repeat, "again", ACTOR)
        assert excinfo.value.code == "outcome_already_terminal"
    # a staging admission can never carry rollback evidence
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            staging.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "impossible", ACTOR, rollback_to=v1.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_requires_failed_production"

    # -- production: ROLLED_BACK needs a preceding FAILED on the SAME admission --------
    prod1 = controller.admit(
        _admission(v1.artifact_sha256, "production", environment, manifest, "deploy-term-p1"),
        ACTOR,
    )
    assert prod1.allowed, prod1.reasons
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            prod1.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "no failure yet", ACTOR, rollback_to=v1.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_requires_failed_production"

    # first production failure has NO prior good production -> no bound candidate
    failure = controller.report_outcome(
        prod1.admission_id, TENANT, DeploymentOutcomeStatus.FAILED, "prod red", ACTOR
    )
    assert failure["payload"]["rollback_candidate"] is None
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            prod1.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "nothing to restore", ACTOR, rollback_to=v1.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_candidate_missing"
    # the forgery: FAILED can never be rewritten to SUCCEEDED
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            prod1.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "forged", ACTOR
        )
    assert excinfo.value.code == "outcome_already_terminal"

    # -- v1 ships clean on a NEW admission; SUCCEEDED is terminal too -------------------
    prod2 = controller.admit(
        _admission(v1.artifact_sha256, "production", environment, manifest, "deploy-term-p2"),
        ACTOR,
    )
    assert prod2.allowed, prod2.reasons
    controller.report_outcome(
        prod2.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            prod2.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "cannot roll back a success", ACTOR, rollback_to=v1.artifact_sha256,
        )
    assert excinfo.value.code == "outcome_already_terminal"

    # -- v2 fails in production; rollback accepted ONLY for the bound candidate ---------
    v2_admission = _deploy_to_production(controller, manifest, environment, v2.artifact_sha256, "term-v2")
    failure = controller.report_outcome(
        v2_admission, TENANT, DeploymentOutcomeStatus.FAILED, "prod smoke red", ACTOR
    )
    assert failure["payload"]["rollback_candidate"]["artifact_sha256"] == v1.artifact_sha256
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            v2_admission, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "wrong digest", ACTOR, rollback_to=v2.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_target_mismatch"
    controller.report_outcome(
        v2_admission, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
        "restored v1", ACTOR, rollback_to=v1.artifact_sha256,
    )
    for status in (
        DeploymentOutcomeStatus.ROLLED_BACK,
        DeploymentOutcomeStatus.FAILED,
        DeploymentOutcomeStatus.SUCCEEDED,
    ):
        with pytest.raises(OutcomeError) as excinfo:
            controller.report_outcome(
                v2_admission, TENANT, status, "post-rollback", ACTOR,
                rollback_to=v1.artifact_sha256,
            )
        assert excinfo.value.code == "outcome_already_terminal"

    assert ledger.verify_chain()[0] is True


def test_staging_acceptance_requires_the_one_immutable_successful_outcome(
    controller, store, manifest, environment, signer, tmp_path
):
    """A failed staging outcome can never be rewritten into the success that unlocks
    production — promotion requires a staging admission whose FIRST (and only terminal)
    outcome is SUCCEEDED."""
    target = _target("stg-immutable")
    _certify(store, manifest, signer, environment, tmp_path, "cert-stg-imm", target)
    controller.bind_certification("cert-stg-imm", TENANT, ACTOR)

    staging = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-imm-s1"),
        ACTOR,
    )
    assert staging.allowed, staging.reasons
    controller.report_outcome(
        staging.admission_id, TENANT, DeploymentOutcomeStatus.FAILED, "staging red", ACTOR
    )

    # the failed staging cannot be overwritten with a success
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            staging.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "forged", ACTOR
        )
    assert excinfo.value.code == "outcome_already_terminal"

    # production stays locked
    denied = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-imm-p1"),
        ACTOR,
    )
    assert denied.allowed is False
    assert "staging_acceptance_missing" in denied.reasons

    # a NEW staging deployment that genuinely succeeds is what unlocks production
    staging2 = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-imm-s2"),
        ACTOR,
    )
    assert staging2.allowed, staging2.reasons
    controller.report_outcome(
        staging2.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "staging green", ACTOR
    )
    allowed = controller.admit(
        _admission(target.artifact_sha256, "production", environment, manifest, "deploy-imm-p2"),
        ACTOR,
    )
    assert allowed.allowed is True, allowed.reasons


def test_rollback_evidence_bound_at_failure_ignores_target_drift(
    controller, store, manifest, environment, signer, tmp_path
):
    """The accepted rollback digest is the candidate FROZEN into the FAILED record.
    Concurrent deployment activity that moves the LIVE rollback target afterwards must
    not change what the failed admission may report as its rollback."""
    a1 = _target("drift-v1")
    a2 = _target("drift-v2")
    a3 = _target("drift-v3")
    for run_id, target in (("cert-drift-v1", a1), ("cert-drift-v2", a2), ("cert-drift-v3", a3)):
        _certify(store, manifest, signer, environment, tmp_path, run_id, target)
        controller.bind_certification(run_id, TENANT, ACTOR)

    # v1 becomes last known good
    v1_admission = _deploy_to_production(controller, manifest, environment, a1.artifact_sha256, "drift-v1")
    controller.report_outcome(
        v1_admission, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )

    # v2 fails in production — the rollback candidate v1 is bound into the FAILED record
    v2_admission = _deploy_to_production(controller, manifest, environment, a2.artifact_sha256, "drift-v2")
    failure = controller.report_outcome(
        v2_admission, TENANT, DeploymentOutcomeStatus.FAILED, "prod red", ACTOR
    )
    assert failure["payload"]["rollback_candidate"]["artifact_sha256"] == a1.artifact_sha256

    # CONCURRENT drift: v3 ships clean, the LIVE rollback target moves to v3
    v3_admission = _deploy_to_production(controller, manifest, environment, a3.artifact_sha256, "drift-v3")
    controller.report_outcome(
        v3_admission, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )
    live = controller.rollback_target(TENANT)
    assert live is not None and live["artifact_sha256"] == a3.artifact_sha256

    # reporting the drifted live target as the v2 rollback is REJECTED
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            v2_admission, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "drifted target", ACTOR, rollback_to=a3.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_target_mismatch"

    # only the digest bound at failure time is accepted
    rollback = controller.report_outcome(
        v2_admission, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
        "restored bound candidate", ACTOR, rollback_to=a1.artifact_sha256,
    )
    assert rollback["payload"]["rollback_to"] == a1.artifact_sha256


def test_concurrent_outcome_reports_have_exactly_one_winner(
    controller, store, manifest, environment, signer, tmp_path, ledger
):
    """Racing outcome writers for one admission: exactly ONE terminal outcome lands, all
    other attempts fail with outcome_already_terminal, and the hash chain stays linear."""
    target = _target("race-outcome")
    _certify(store, manifest, signer, environment, tmp_path, "cert-race", target)
    controller.bind_certification("cert-race", TENANT, ACTOR)
    staging = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-race-s1"),
        ACTOR,
    )
    assert staging.allowed, staging.reasons

    workers = 8
    barrier = threading.Barrier(workers)
    results: list[tuple[str, str]] = []
    lock = threading.Lock()

    def report(index: int) -> None:
        status = (
            DeploymentOutcomeStatus.SUCCEEDED if index % 2 == 0 else DeploymentOutcomeStatus.FAILED
        )
        barrier.wait(timeout=30)
        try:
            controller.report_outcome(
                staging.admission_id, TENANT, status, f"attempt-{index}", ACTOR
            )
            outcome = ("ok", status.value)
        except OutcomeError as exc:
            outcome = ("error", exc.code)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=report, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert len(results) == workers
    winners = [entry for entry in results if entry[0] == "ok"]
    losers = [entry for entry in results if entry[0] == "error"]
    assert len(winners) == 1
    assert len(losers) == workers - 1
    assert all(code == "outcome_already_terminal" for _, code in losers)

    recorded = ledger.outcomes(staging.admission_id, TENANT)
    assert len(recorded) == 1
    assert json.loads(str(recorded[0]["payload_json"]))["status"] == winners[0][1]
    assert ledger.verify_chain()[0] is True

def test_outcome_operation_id_idempotent_replay_and_conflict(
    controller, store, manifest, environment, signer, tmp_path
):
    """A stable client operation id makes outcome submission recoverable across
    commit-then-response-loss: the EXACT retry returns the committed record
    (replayed) instead of tripping the terminal-transition guard, while a reused
    id with a different payload is rejected as a conflict."""
    target = _target("op-idem-v1")
    _certify(store, manifest, signer, environment, tmp_path, "cert-op-idem", target)
    controller.bind_certification("cert-op-idem", TENANT, ACTOR)
    staging = controller.admit(
        _admission(target.artifact_sha256, "staging", environment, manifest, "deploy-op-idem"),
        ACTOR,
    )
    assert staging.allowed, staging.reasons

    first = controller.report_outcome(
        staging.admission_id,
        TENANT,
        DeploymentOutcomeStatus.SUCCEEDED,
        "staging green",
        ACTOR,
        operation_id="op-stable-0001",
    )
    assert first["replayed"] is False
    assert first["payload"]["operation_id"] == "op-stable-0001"

    # EXACT retry of the same operation (same id + same status/detail/rollback_to)
    # returns the COMMITTED record instead of outcome_already_terminal.
    replay = controller.report_outcome(
        staging.admission_id,
        TENANT,
        DeploymentOutcomeStatus.SUCCEEDED,
        "staging green",
        ACTOR,
        operation_id="op-stable-0001",
    )
    assert replay["replayed"] is True
    assert replay["record_id"] == first["record_id"]
    assert replay["payload"] == first["payload"]

    # Same operation id but a DIFFERENT payload is a conflict, never a silent dedupe.
    with pytest.raises(OutcomeError) as conflict_detail:
        controller.report_outcome(
            staging.admission_id,
            TENANT,
            DeploymentOutcomeStatus.SUCCEEDED,
            "different detail text",
            ACTOR,
            operation_id="op-stable-0001",
        )
    assert conflict_detail.value.code == "outcome_operation_conflict"
    with pytest.raises(OutcomeError) as conflict_status:
        controller.report_outcome(
            staging.admission_id,
            TENANT,
            DeploymentOutcomeStatus.FAILED,
            "staging green",
            ACTOR,
            operation_id="op-stable-0001",
        )
    assert conflict_status.value.code == "outcome_operation_conflict"

    # A NEW operation id against the already-terminal admission keeps the strict
    # terminal guard (idempotency never weakens immutability).
    with pytest.raises(OutcomeError) as terminal:
        controller.report_outcome(
            staging.admission_id,
            TENANT,
            DeploymentOutcomeStatus.SUCCEEDED,
            "staging green",
            ACTOR,
            operation_id="op-stable-9999",
        )
    assert terminal.value.code == "outcome_already_terminal"

    # And submissions WITHOUT an operation id keep prior strict behavior.
    with pytest.raises(OutcomeError) as legacy:
        controller.report_outcome(
            staging.admission_id,
            TENANT,
            DeploymentOutcomeStatus.SUCCEEDED,
            "staging green",
            ACTOR,
        )
    assert legacy.value.code == "outcome_already_terminal"

    # The chain stays linear and valid with exactly one committed outcome.
    outcomes = controller.ledger.outcomes(staging.admission_id, TENANT)
    assert len(outcomes) == 1
    assert controller.ledger.verify_chain()[0] is True

def test_rollback_target_frozen_at_admission_survives_concurrent_drift(
    controller, store, manifest, environment, signer, tmp_path
):
    """Concurrent production deployments cannot drift each other's rollback target: the
    exact last-known-good is FROZEN into each admission record BEFORE the deployment
    begins, surfaced on the decision, and ROLLED_BACK must name that frozen digest."""
    a = _target("freeze-A")
    b = _target("freeze-B")
    c = _target("freeze-C")
    for run_id, target in (("cert-freeze-A", a), ("cert-freeze-B", b), ("cert-freeze-C", c)):
        _certify(store, manifest, signer, environment, tmp_path, run_id, target)
        controller.bind_certification(run_id, TENANT, ACTOR)

    def _prod_admit(target, tag):
        staging = controller.admit(
            _admission(target.artifact_sha256, "staging", environment, manifest, f"deploy-stg-{tag}"),
            ACTOR,
        )
        assert staging.allowed, staging.reasons
        # staging admissions freeze NO rollback target
        assert staging.rollback_candidate is None
        controller.report_outcome(
            staging.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "staging green", ACTOR
        )
        decision = controller.admit(
            _admission(target.artifact_sha256, "production", environment, manifest, f"deploy-prd-{tag}"),
            ACTOR,
        )
        assert decision.allowed, decision.reasons
        return decision

    # A ships clean and becomes the last known good
    a_decision = _prod_admit(a, "freeze-A")
    assert a_decision.rollback_candidate is None  # no prior good production existed
    controller.report_outcome(
        a_decision.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )

    # B and C are admitted CONCURRENTLY — BOTH freeze A as their rollback target, and the
    # frozen target is returned on the decision (what enforce_admission.sh consumes)
    b_decision = _prod_admit(b, "freeze-B")
    c_decision = _prod_admit(c, "freeze-C")
    assert b_decision.rollback_candidate is not None
    assert b_decision.rollback_candidate["artifact_sha256"] == a.artifact_sha256
    assert c_decision.rollback_candidate is not None
    assert c_decision.rollback_candidate["artifact_sha256"] == a.artifact_sha256
    assert c_decision.to_dict()["rollback_candidate"]["artifact_sha256"] == a.artifact_sha256

    # B ships clean — the LIVE last-known-good drifts to B ...
    controller.report_outcome(
        b_decision.admission_id, TENANT, DeploymentOutcomeStatus.SUCCEEDED, "prod green", ACTOR
    )
    live = controller.rollback_target(TENANT)
    assert live is not None and live["artifact_sha256"] == b.artifact_sha256

    # ... but C's failure evidence still carries the ADMISSION-FROZEN candidate A
    failure = controller.report_outcome(
        c_decision.admission_id, TENANT, DeploymentOutcomeStatus.FAILED, "prod red", ACTOR
    )
    assert failure["payload"]["rollback_candidate"]["artifact_sha256"] == a.artifact_sha256

    # ROLLED_BACK naming the drifted live target B is REJECTED ...
    with pytest.raises(OutcomeError) as excinfo:
        controller.report_outcome(
            c_decision.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
            "rolled to drifted live target", ACTOR, rollback_to=b.artifact_sha256,
        )
    assert excinfo.value.code == "rollback_target_mismatch"

    # ... and only the exact admission-bound target A is accepted
    rollback = controller.report_outcome(
        c_decision.admission_id, TENANT, DeploymentOutcomeStatus.ROLLED_BACK,
        "restored admission-bound target", ACTOR, rollback_to=a.artifact_sha256,
    )
    assert rollback["payload"]["rollback_to"] == a.artifact_sha256


def test_delayed_stale_binding_cannot_shadow_active_certification(
    store, trusted, ledger, manifest, environment, signer, tmp_path
):
    """Stale-binding shadowing is closed on BOTH ends: bind_certification refuses to
    bind a run certified under a superseded manifest, and admission selects the
    currently VALID active-manifest certification even when a stale legacy binding
    lands LATER (higher ledger ordinal) than the valid one."""
    import dataclasses

    target = _target("shadow-app")
    _certify(store, manifest, signer, environment, tmp_path, "cert-shadow-old", target)

    # bound under the ORIGINAL manifest while it was active
    original = DeploymentAdmissionController(store, trusted, ledger, manifest.digest)
    original.bind_certification("cert-shadow-old", TENANT, ACTOR)

    # the mandatory rules roll over: same manifest_id, NEW content digest
    rolled_manifest = dataclasses.replace(manifest, digest=_digest("shadow-rolled-manifest"))
    rolled = DeploymentAdmissionController(store, trusted, ledger, rolled_manifest.digest)

    # DELAYED re-binding of the stale-manifest run is refused outright — a stale run is
    # recertified, never rebound
    with pytest.raises(BindingError, match="rule_manifest_not_active"):
        rolled.bind_certification("cert-shadow-old", TENANT, ACTOR)

    # recertify the SAME artifact under the ACTIVE manifest and bind it
    _certify(store, rolled_manifest, signer, environment, tmp_path, "cert-shadow-new", target)
    rolled.bind_certification("cert-shadow-new", TENANT, ACTOR)

    # a LEGACY stale binding row lands AFTER the valid one (delayed writer running the
    # pre-rollover code path appended directly to the shared ledger)
    ledger.append(
        DeploymentRecordType.BINDING,
        TENANT,
        {
            "artifact_sha256": target.artifact_sha256,
            "source_commit": target.source_commit,
            "rule_manifest_digest": manifest.digest,
        },
        ACTOR,
        run_id="cert-shadow-old",
        artifact_sha256=target.artifact_sha256,
    )
    bindings = ledger.find_bindings(TENANT, target.artifact_sha256)
    assert str(bindings[0]["run_id"]) == "cert-shadow-old"  # the stale one IS newest

    # admission must select the currently VALID active-manifest certification, never the
    # newest binding ordinal blindly
    decision = rolled.admit(
        _admission(target.artifact_sha256, "staging", environment, rolled_manifest, "deploy-shadow-s1"),
        ACTOR,
    )
    assert decision.allowed is True, decision.reasons
    assert decision.run_id == "cert-shadow-new"

    # and under the ORIGINAL controller the stale run would fail the gate anyway: the
    # active digest there no longer matches the recertification — fail-closed both ways
    stale_decision = rolled.admit(
        _admission(target.artifact_sha256, "staging", environment, rolled_manifest, "deploy-shadow-s2"),
        ACTOR,
    )
    assert stale_decision.run_id == "cert-shadow-new"