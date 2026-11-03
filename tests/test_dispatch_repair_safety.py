"""Release integration checks for dispatch compensation and recovery boundaries."""
from __future__ import annotations

import sqlite3
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from echo_certification_forge.subscriber import SubscriberError
from test_dispatch_orphaned_runs import _orphan_the_old_way, _run
from test_p7_subscriber_governance import _headers, _policy, _provision, _stack, _submit_local_run


def _snapshot(governance, run_id):
    with sqlite3.connect(governance.db_path) as db:
        return {
            "run": db.execute("SELECT state, run_outcome FROM runs WHERE run_id = ?", (run_id,)).fetchone(),
            "reservation": db.execute("SELECT state FROM subscriber_run_reservations WHERE run_id = ?", (run_id,)).fetchone(),
            "dispatch": db.execute("SELECT state, claim_token, attempts FROM subscriber_run_dispatches WHERE run_id = ?", (run_id,)).fetchone(),
            "usage": db.execute("SELECT quantity, idempotency_key, occurred_at FROM subscriber_usage_events ORDER BY rowid").fetchall(),
            "events": db.execute("SELECT COUNT(*) FROM state_events WHERE run_id = ?", (run_id,)).fetchone(),
        }


@pytest.mark.parametrize("recovery", [False, True])
def test_compensation_failure_rolls_back_entire_repair(tmp_path, manifest, recovery):
    _, governance, org, run_id = _run(tmp_path, manifest, "atomic-repair", max_attempts=1)
    if recovery:
        _orphan_the_old_way(governance, org, run_id)
    else:
        dispatch = governance.claim_dispatch("dispatcher-a", run_id=run_id, organization_id=org.organization_id)
    before = _snapshot(governance, run_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("""CREATE TRIGGER reject_refund BEFORE INSERT ON subscriber_usage_events
                      WHEN NEW.quantity < 0 BEGIN SELECT RAISE(ABORT, 'refund write failed'); END""")
    repair = (lambda: governance.claim_dispatch("recovery", organization_id=org.organization_id)) if recovery else (
        lambda: governance.finish_dispatch(dispatch, error="worker denied")
    )
    with pytest.raises(sqlite3.IntegrityError, match="refund write failed"):
        repair()
    assert _snapshot(governance, run_id) == before
    with sqlite3.connect(governance.db_path) as db:
        db.execute("DROP TRIGGER reject_refund")
    repair()
    after = _snapshot(governance, run_id)
    assert after["run"] == ("INFRASTRUCTURE_FAILURE", "INFRA_FAILED")
    assert after["reservation"] == ("RELEASED",)
    assert sum(row[0] for row in after["usage"]) == 0


@pytest.mark.parametrize("recovery", [False, True])
def test_dispatch_refund_stays_in_original_meter_period(tmp_path, manifest, recovery):
    _, governance, org, run_id = _run(tmp_path, manifest, "original-period", max_attempts=1)
    original = _snapshot(governance, run_id)["usage"][0][2]
    later = governance._now() + timedelta(days=40)
    governance._clock = lambda: later
    if recovery:
        _orphan_the_old_way(governance, org, run_id)
        governance.claim_dispatch("recovery", organization_id=org.organization_id)
    else:
        dispatch = governance.claim_dispatch("dispatcher", run_id=run_id, organization_id=org.organization_id)
        governance.finish_dispatch(dispatch, error="worker denied")
    refunds = [row for row in _snapshot(governance, run_id)["usage"] if row[0] < 0]
    assert len(refunds) == 1 and refunds[0][0] == -1 and refunds[0][2] == original


@pytest.mark.parametrize("reservation,run_state", [
    ("EXECUTING", "QUEUED"), ("STARTED", "ACQUIRING_TARGET"),
    ("RELEASED", "CANCELLED"), ("RELEASED", "COMPLETED"),
    ("RELEASED", "INFRASTRUCTURE_FAILURE"),
])
def test_orphan_sweep_preserves_noneligible_runs(tmp_path, manifest, reservation, run_state):
    _, governance, org, run_id = _run(tmp_path, manifest, "preserve-ineligible", max_attempts=1)
    _orphan_the_old_way(governance, org, run_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("UPDATE subscriber_run_reservations SET state = ? WHERE run_id = ?", (reservation, run_id))
        db.execute("UPDATE runs SET state = ? WHERE run_id = ?", (run_state, run_id))
    before = _snapshot(governance, run_id)
    assert governance.claim_dispatch("recovery", organization_id=org.organization_id) is None
    assert _snapshot(governance, run_id) == before


def test_concurrent_recovery_and_stale_finish_compensate_once(tmp_path, manifest):
    _, governance, org, run_id = _run(tmp_path, manifest, "concurrent-repair", max_attempts=1)
    dispatch = governance.claim_dispatch("old-dispatcher", run_id=run_id, organization_id=org.organization_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("UPDATE subscriber_run_dispatches SET lease_expires_at = '2000-01-01T00:00:00Z' WHERE run_id = ?", (run_id,))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda worker: governance.claim_dispatch(worker, organization_id=org.organization_id), ["recover-a", "recover-b"]))
    assert results == [None, None]
    with pytest.raises(SubscriberError, match="dispatch_claim_inactive"):
        governance.finish_dispatch(dispatch, error="late worker exit")
    after = _snapshot(governance, run_id)
    assert after["run"] == ("INFRASTRUCTURE_FAILURE", "INFRA_FAILED")
    assert [row[0] for row in after["usage"]] == [1, -1]
    assert after["events"] == (2,)


@pytest.mark.parametrize("prefix", ["dispatch-crash", "claim-crash", "dispatch-worker-error"])
def test_existing_dispatch_credit_is_not_inserted_again(tmp_path, manifest, prefix):
    _, governance, org, run_id = _run(tmp_path, manifest, "existing-credit", max_attempts=1)
    _orphan_the_old_way(governance, org, run_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("""INSERT INTO subscriber_usage_events
            (organization_id, meter, quantity, idempotency_key, metadata_json, occurred_at)
            SELECT organization_id, meter, -1, ? || ':' || idempotency_key,
                   json_object('run_id', ?), occurred_at
            FROM subscriber_usage_events WHERE quantity = 1""", (prefix, run_id))
    governance.claim_dispatch("recovery", organization_id=org.organization_id)
    after = _snapshot(governance, run_id)
    assert after["run"] == ("INFRASTRUCTURE_FAILURE", "INFRA_FAILED")
    assert [row[0] for row in after["usage"]] == [1, -1]


@pytest.mark.parametrize("recovery", [False, True])
@pytest.mark.parametrize("second_before_refund", [False, True])
def test_customer_keys_cannot_collide_with_dispatch_refunds(tmp_path, manifest, recovery, second_before_refund):
    policy = _policy().model_copy(update={"max_dispatch_attempts": 1})
    store, governance, client = _stack(tmp_path, manifest, policy=policy)
    org = _provision(governance, "collision-refund", plan_code="professional")
    source = tmp_path / "source"
    source.mkdir()
    (source / "hello.py").write_text("print('hello')\n")
    first, _ = _submit_local_run(client, manifest, org.organization_id, org.bootstrap_api_key, source, key="run-key-0001")
    with sqlite3.connect(governance.db_path) as db:
        payload = json.loads(db.execute("SELECT submit_request_json FROM subscriber_run_reservations WHERE run_id = ?", (first,)).fetchone()[0])
    def submit_second():
        response = client.post("/v1/certifications", headers=_headers(org.organization_id, org.bootstrap_api_key), json={**payload, "idempotency_key": "dispatch-crash:run-key-0001"})
        assert response.status_code == 201
        return response.json()["run_id"]
    if second_before_refund:
        second = submit_second()
    if recovery:
        _orphan_the_old_way(governance, org, first)
        governance.claim_dispatch("recovery", run_id=first, organization_id=org.organization_id)
    else:
        dispatch = governance.claim_dispatch("dispatcher", run_id=first, organization_id=org.organization_id)
        governance.finish_dispatch(dispatch, error="worker denied")
    if not second_before_refund:
        second = submit_second()
    assert store.get_run(first, org.organization_id)["state"] == "INFRASTRUCTURE_FAILURE"
    assert store.get_run(second, org.organization_id)["state"] == "QUEUED"
    ledger = _snapshot(governance, first)["usage"]
    assert sorted(row[0] for row in ledger) == [-1, 1, 1]
    governance.claim_dispatch("repeat", run_id=first, organization_id=org.organization_id)
    assert _snapshot(governance, first)["usage"] == ledger


def test_unexpected_internal_credit_key_collision_rolls_back(tmp_path, manifest):
    _, governance, org, run_id = _run(tmp_path, manifest, "internal-collision", max_attempts=1)
    _orphan_the_old_way(governance, org, run_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("""INSERT INTO subscriber_usage_events
            (organization_id, meter, quantity, idempotency_key, metadata_json, occurred_at)
            VALUES (?, 'certification_runs', 1, ?, '{}', '2026-01-01T00:00:00Z')""",
            (org.organization_id, f"run-compensation:{run_id}"))
    before = _snapshot(governance, run_id)
    with pytest.raises(sqlite3.IntegrityError):
        governance.claim_dispatch("recovery", organization_id=org.organization_id)
    assert _snapshot(governance, run_id) == before


def test_audit_failure_rolls_back_credit_and_terminalization(tmp_path, manifest):
    _, governance, org, run_id = _run(tmp_path, manifest, "audit-rollback", max_attempts=1)
    _orphan_the_old_way(governance, org, run_id)
    before = _snapshot(governance, run_id)
    with sqlite3.connect(governance.db_path) as db:
        db.execute("""CREATE TRIGGER reject_repair_audit BEFORE INSERT ON subscriber_audit_events
            WHEN NEW.action = 'certification.dispatch_orphan_reconciled'
            BEGIN SELECT RAISE(ABORT, 'audit write failed'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="audit write failed"):
        governance.claim_dispatch("recovery", organization_id=org.organization_id)
    assert _snapshot(governance, run_id) == before
