"""Heartbeat lifecycle regression tests; no customer code or real signing is executed."""
from __future__ import annotations

import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import echo_certification_forge.run_worker as worker
from echo_certification_forge.canonical import sha256_json
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.models import RunState
from echo_certification_forge.runner import RunnerResponse
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import SubscriberError, SubscriberGovernance
from test_p7_subscriber_governance import PEPPER, _policy, _provision, _submit_local_run


def _context(tmp_path, manifest, monkeypatch):
    now = [datetime.now(UTC)]
    policy = _policy().model_copy(update={
        "worker_claim_lease_seconds": 4,
        "worker_heartbeat_interval_seconds": 1,
    })
    store = EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")
    governance = SubscriberGovernance(
        store.db_path, policy, PEPPER, clock=lambda: now[0],
    )
    client = TestClient(create_app(ServiceContext(
        store, manifest, TrustedPublicKeyRegistry.empty(), governance,
    )))
    org = _provision(governance, "heartbeat-cleanup")
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("Synthetic non-executable target.", encoding="utf-8")
    run_id, _ = _submit_local_run(
        client, manifest, org.organization_id, org.bootstrap_api_key,
        source, key="heartbeat-cleanup-0001",
    )
    heartbeats = []
    original_heartbeat = worker._ClaimHeartbeat

    class RecordedHeartbeat(original_heartbeat):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            heartbeats.append(self)

    monkeypatch.setattr(worker, "_ClaimHeartbeat", RecordedHeartbeat)
    return now, store, governance, org, source, run_id, heartbeats


@pytest.mark.parametrize("failure", [sqlite3.OperationalError, OSError, RuntimeError])
def test_executor_exception_stops_renewal_and_preserves_expired_claim_fencing(
    tmp_path, manifest, monkeypatch, failure,
):
    now, store, governance, org, source, run_id, heartbeats = _context(
        tmp_path, manifest, monkeypatch,
    )

    def fail_executor(*args, **kwargs):
        raise failure("synthetic executor failure")

    monkeypatch.setattr(worker.RunExecutor, "execute", fail_executor)
    try:
        # Infrastructure and unexpected failures still propagate to their caller.
        with pytest.raises(failure, match="synthetic executor failure"):
            worker.run(
                run_id, org.organization_id, {"type": "local", "path": str(source)},
                store=store, manifest=manifest,
                signer=Ed25519VerdictSigner.generate(), subscribers=governance,
            )
        assert len(heartbeats) == 1
        heartbeat = heartbeats[0]
        assert heartbeat._stop.is_set()
        assert not heartbeat._thread.is_alive()
        assert not list((store.evidence_root / ".worker").iterdir())
        assert source.exists()
        assert store.latest_signed_verdict(run_id, org.organization_id) is None
        assert store.get_run(run_id, org.organization_id)["state"] == "ACQUIRING_TARGET"

        # Stopping renewal lets the existing expiry recovery release concurrency.
        now[0] += timedelta(seconds=governance.policy.worker_claim_lease_seconds + 1)
        assert governance.recover_expired_claims(org.organization_id) == 1
        assert governance.recover_expired_claims(org.organization_id) == 0
        run = store.get_run(run_id, org.organization_id)
        assert run["state"] == RunState.INFRASTRUCTURE_FAILURE.value
        assert run["run_outcome"] == "INFRA_FAILED"
        assert governance.dispatch_status(run_id, org.organization_id)["state"] == "FAILED"
        assert store.latest_signed_verdict(run_id, org.organization_id) is None
        with pytest.raises(SubscriberError, match="worker_run_claim_inactive"):
            governance.heartbeat_worker_claim(heartbeat._claim)
        with pytest.raises(SubscriberError, match="worker_run_claim_inactive"):
            governance.assert_worker_claim_active(heartbeat._claim)
        with sqlite3.connect(store.db_path) as connection:
            state = connection.execute(
                "SELECT state FROM subscriber_run_reservations WHERE run_id = ?", (run_id,),
            ).fetchone()[0]
            compensation = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(quantity), 0) FROM subscriber_usage_events "
                "WHERE organization_id = ? AND idempotency_key = ?",
                (org.organization_id, f"claim-crash:heartbeat-cleanup-0001@{manifest.digest[:16]}"),
            ).fetchone()
        assert state == "RELEASED"
        assert compensation == (1, -1)
    finally:
        # The negative baseline must not itself strand a live renewal thread.
        for heartbeat in heartbeats:
            heartbeat.stop()


def test_normal_executor_return_stops_renewal_and_cleans_owned_workspace(
    tmp_path, manifest, monkeypatch,
):
    _, store, governance, org, source, run_id, heartbeats = _context(
        tmp_path, manifest, monkeypatch,
    )
    # This lifecycle-only test substitutes the executor, not a release verdict.
    # It neither executes customer code nor stores/signs a certification.
    monkeypatch.setattr(worker.RunExecutor, "execute", lambda *args, **kwargs: SimpleNamespace(
        run_id=run_id, final_state="COMPLETED", run_outcome="COMPLETE",
        release_verdict="NOT_READY", signed=False, blocking_findings=(),
    ))
    try:
        result = worker.run(
            run_id, org.organization_id, {"type": "local", "path": str(source)},
            store=store, manifest=manifest,
            signer=Ed25519VerdictSigner.generate(), subscribers=governance,
        )
        assert result["signed"] is False and result["release_verdict"] == "NOT_READY"
        assert len(heartbeats) == 1
        assert heartbeats[0]._stop.is_set()
        assert not heartbeats[0]._thread.is_alive()
        assert not list((store.evidence_root / ".worker").iterdir())
        assert source.exists()
        assert store.latest_signed_verdict(run_id, org.organization_id) is None
    finally:
        for heartbeat in heartbeats:
            heartbeat.stop()

@pytest.mark.parametrize("stage", ["run_lookup", "adapter_append"])
def test_pre_executor_storage_failure_stops_renewal_and_allows_safe_requeue(
    tmp_path, manifest, monkeypatch, stage,
):
    now, store, governance, org, source, run_id, heartbeats = _context(
        tmp_path, manifest, monkeypatch,
    )
    executor_calls = []

    def unexpected_executor(*args, **kwargs):
        executor_calls.append(args)
        raise AssertionError("pre-executor failure must not enter customer execution")

    monkeypatch.setattr(worker.RunExecutor, "execute", unexpected_executor)
    message = f"synthetic {stage} storage failure"
    options = {}

    def failed_connection():
        raise sqlite3.OperationalError(message)

    if stage == "adapter_append":
        # A schema-valid synthetic transport envelope only reaches persistence;
        # no adapter/customer execution or attestation verification is substituted.
        body = {"fixture": "pre-executor storage regression"}
        options["adapter_bundle_response"] = RunnerResponse(
            response_id="cleanup-response", request_id="cleanup-request",
            run_id=run_id, tenant_id=org.organization_id, runner_id="cleanup-runner",
            sequence=1, issued_at=datetime.now(UTC), status="COMPLETED",
            body=body, body_sha256=sha256_json(body),
            runner_key_id="synthetic-fixture", signature_b64="synthetic-fixture",
        )

        class FailedArtifactInsert(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if "INSERT INTO evidence_artifacts" in sql:
                    raise sqlite3.OperationalError(message)
                return super().execute(sql, *args, **kwargs)

        def failed_connection():
            connection = sqlite3.connect(
                store.db_path, timeout=10, factory=FailedArtifactInsert,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            return connection

    try:
        with monkeypatch.context() as storage_fault:
            storage_fault.setattr(store, "_connect", failed_connection)
            with pytest.raises(sqlite3.OperationalError, match=message):
                worker.run(
                    run_id, org.organization_id,
                    {"type": "local", "path": str(source)},
                    store=store, manifest=manifest,
                    signer=Ed25519VerdictSigner.generate(), subscribers=governance,
                    **options,
                )
        assert executor_calls == []
        assert len(heartbeats) == 1
        heartbeat = heartbeats[0]
        assert heartbeat._stop.is_set()
        assert not heartbeat._thread.is_alive()
        assert not list((store.evidence_root / ".worker").iterdir())
        assert source.exists()
        assert store.get_run(run_id, org.organization_id)["state"] == "QUEUED"
        assert store.latest_signed_verdict(run_id, org.organization_id) is None

        # Pre-start work is requeued by the existing lease policy, never promoted
        # to execution or compensated as if customer code had already started.
        now[0] += timedelta(seconds=governance.policy.worker_claim_lease_seconds + 1)
        assert governance.recover_expired_claims(org.organization_id) == 1
        assert governance.recover_expired_claims(org.organization_id) == 0
        assert store.get_run(run_id, org.organization_id)["state"] == "QUEUED"
        with sqlite3.connect(store.db_path) as connection:
            state = connection.execute(
                "SELECT state FROM subscriber_run_reservations WHERE run_id = ?", (run_id,),
            ).fetchone()[0]
            compensations = connection.execute(
                "SELECT COUNT(*) FROM subscriber_usage_events "
                "WHERE organization_id = ? AND quantity < 0", (org.organization_id,),
            ).fetchone()[0]
        assert state == "BOUND"
        assert compensations == 0
        with pytest.raises(SubscriberError, match="worker_run_claim_inactive"):
            governance.heartbeat_worker_claim(heartbeat._claim)
        assert store.latest_signed_verdict(run_id, org.organization_id) is None
    finally:
        for heartbeat in heartbeats:
            heartbeat.stop()
        # Keep the intentionally red baseline isolated to its own fixture tree.
        shutil.rmtree(store.evidence_root / ".worker", ignore_errors=True)
