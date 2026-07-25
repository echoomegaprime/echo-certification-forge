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

    rolled = DeploymentAdmissionController(
        store, trusted, ledger, _digest("rolled-over-manifest")
    )
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
