"""Terminal claim repair stays scoped, authorized, audited and non-executing."""
from datetime import UTC, datetime, timedelta
import json
import sqlite3

import pytest

from echo_certification_forge.subscriber import Permission, SubscriberError
from test_p7_subscriber_governance import (
    _headers, _owner, _project, _provision, _stack, _submit_body,
)

NOW = datetime(2026, 11, 2, 15, 0, tzinfo=UTC)
STALE_CLAIM = "synthetic-expired-test-claim"


def _subject(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    governance._clock = lambda: NOW
    organization = _provision(governance, "claim-repair", plan_code="enterprise")
    headers = _headers(organization.organization_id, organization.bootstrap_api_key)
    project = _project(client, organization.organization_id, organization.bootstrap_api_key).json()
    request = _submit_body(manifest, organization.organization_id, project["project_id"], "released-repair-0001")
    submitted = client.post("/v1/certifications", headers=headers, json=request)
    assert submitted.status_code == 201
    run_id = submitted.json()["run_id"]
    cancelled = client.post(f"/v1/certifications/{run_id}/cancel", headers=headers)
    assert cancelled.status_code == 200
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE subscriber_run_reservations SET state='RELEASED',claim_token=?,"
                           "lease_expires_at=?,updated_at=? WHERE run_id=?",
                           (STALE_CLAIM, (NOW - timedelta(days=1)).isoformat(),
                            (NOW - timedelta(days=1, seconds=5)).isoformat(), run_id))
        connection.execute("UPDATE subscriber_run_dispatches SET state='FAILED' WHERE run_id=?", (run_id,))
        # A prior terminal credit is closed history, not another compensation
        # opportunity for the metadata repair.
        connection.execute("INSERT INTO subscriber_usage_events(organization_id,meter,quantity,idempotency_key,metadata_json,occurred_at) "
                           "SELECT u.organization_id,u.meter,-1,'prior-terminal-credit:'||u.idempotency_key,?,u.occurred_at "
                           "FROM subscriber_usage_events u JOIN subscriber_run_reservations r "
                           "ON r.organization_id=u.organization_id AND r.idempotency_key=u.idempotency_key "
                           "WHERE r.run_id=? AND u.quantity=1 LIMIT 1",
                           (json.dumps({"reason": "previous_terminal_credit"}), run_id))
    principal = _owner(governance, organization.organization_id, organization.bootstrap_api_key,
                       Permission.GOVERNANCE_MANAGE)
    return store, governance, client, organization, headers, principal, run_id, project


def _snapshot(store):
    with sqlite3.connect(store.db_path) as connection:
        return {table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                for table in ("runs", "subscriber_run_reservations", "subscriber_run_dispatches",
                              "subscriber_usage_events")}


def _repair(governance, principal, run_id):
    return governance.reconcile_released_reservation(principal, run_id=run_id,
                                                       reason="expired_terminal_claim_owner_repair")


def test_owner_api_repairs_only_expired_terminal_residual_and_is_idempotent(tmp_path, manifest):
    store, governance, client, org, headers, principal, run_id, project = _subject(tmp_path, manifest)
    for index in range(13):
        body = _submit_body(manifest, org.organization_id, project["project_id"], f"pending-preserved-{index:02}")
        assert client.post("/v1/certifications", headers=headers, json=body).status_code == 201
    # Normal intake already terminalizes old rows but historically leaves the
    # RELEASED residual unchanged. Preserve exactly what the owner sees now.
    before = _snapshot(store)
    with sqlite3.connect(store.db_path) as connection:
        connection.row_factory = sqlite3.Row
        reservations_before = {row["run_id"]: dict(row) for row in connection.execute("SELECT * FROM subscriber_run_reservations")}
    route = f"/v1/subscriber/certifications/{run_id}/reconcile-reservation"
    response = client.post(route, headers=headers, json={"command": "reconcile", "reason": "expired_terminal_claim_owner_repair"})
    assert response.status_code == 200
    result = response.json()
    assert result["reconciled"] is True and result["run_state"] == "CANCELLED"
    assert result["reservation_state"] == "RELEASED" and result["meter_compensated"] is False
    assert result["residual_claim_present"] is False and result["lease_present"] is False
    assert STALE_CLAIM not in response.text and "idempotency_key" not in response.text
    after = _snapshot(store)
    for table in ("runs", "subscriber_run_dispatches", "subscriber_usage_events"):
        assert before[table] == after[table]
    with sqlite3.connect(store.db_path) as connection:
        connection.row_factory = sqlite3.Row
        reservation = dict(connection.execute("SELECT * FROM subscriber_run_reservations WHERE run_id=?", (run_id,)).fetchone())
        reservations_after = {row["run_id"]: dict(row) for row in connection.execute("SELECT * FROM subscriber_run_reservations")}
        assert reservation["claim_token"] is None and reservation["lease_expires_at"] is None
        assert connection.execute("SELECT COUNT(*) FROM subscriber_run_dispatches WHERE state='PENDING'").fetchone()[0] == 13
        audits = connection.execute("SELECT details_json FROM subscriber_audit_events WHERE action='certification.released_claim_reconcile'").fetchall()
    assert len(audits) == 1
    reservations_before[run_id].update(claim_token=None, lease_expires_at=None,
                                       updated_at=result["reservation_updated_at"])
    assert reservations_after == reservations_before
    assert json.loads(audits[0][0])["meter_compensated"] is False
    assert STALE_CLAIM not in audits[0][0]
    second = client.post(route, headers=headers, json={"reason": "expired_terminal_claim_owner_repair"})
    assert second.status_code == 200 and second.json()["reconciled"] is False
    assert _snapshot(store) == after
    assert governance.verify_audit(principal)["valid"] is True
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM subscriber_audit_events WHERE action='certification.released_claim_reconcile'").fetchone()[0] == 1


def test_normal_terminal_reconciliation_clears_claim_when_it_releases_reservation(tmp_path, manifest):
    store, _, client, org, headers, _, run_id, project = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE subscriber_run_reservations SET state='EXECUTING' WHERE run_id=?", (run_id,))
    body = _submit_body(manifest, org.organization_id, project["project_id"], "normal-reconcile-0002")
    assert client.post("/v1/certifications", headers=headers, json=body).status_code == 201
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute("SELECT state,claim_token,lease_expires_at FROM subscriber_run_reservations WHERE run_id=?", (run_id,)).fetchone() == ("RELEASED", None, None)


@pytest.mark.parametrize("field,value,error", [
    ("state", "BOUND", "reservation_not_released"),
    ("state", "EXECUTING", "reservation_not_released"),
    ("state", "STARTED", "reservation_not_released"),
    ("lease_expires_at", (NOW + timedelta(seconds=1)).isoformat(), "released_claim_not_expired"),
    ("lease_expires_at", None, "released_claim_expiry_unproven"),
    ("lease_expires_at", "not-a-timestamp", "released_claim_expiry_invalid"),
    ("lease_expires_at", "2026-11-01T10:00:00", "released_claim_expiry_invalid"),
])
def test_unsafe_or_unproven_residual_is_unchanged(tmp_path, manifest, field, value, error):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(f"UPDATE subscriber_run_reservations SET {field}=? WHERE run_id=?", (value, run_id))
    before = _snapshot(store)
    with pytest.raises(SubscriberError, match=error):
        _repair(governance, principal, run_id)
    assert _snapshot(store) == before


@pytest.mark.parametrize("state", ["QUEUED", "EXECUTING_TESTS"])
def test_nonterminal_run_is_not_reconciled(tmp_path, manifest, state):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE runs SET state=? WHERE run_id=?", (state, run_id))
    before = _snapshot(store)
    with pytest.raises(SubscriberError, match="run_not_terminal"):
        _repair(governance, principal, run_id)
    assert _snapshot(store) == before


def test_other_tenant_cannot_discover_or_reconcile_target(tmp_path, manifest):
    store, governance, client, _, _, _, run_id, _ = _subject(tmp_path, manifest)
    other = _provision(governance, "claim-other-owner")
    before = _snapshot(store)
    response = client.post(f"/v1/subscriber/certifications/{run_id}/reconcile-reservation",
                           headers=_headers(other.organization_id, other.bootstrap_api_key),
                           json={"reason": "expired_terminal_claim_owner_repair"})
    assert response.status_code == 404
    assert response.json()["detail"] == "run_reservation_not_found"
    assert _snapshot(store) == before


def test_live_permission_is_rechecked_inside_same_write_transaction(tmp_path, manifest):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE subscriber_api_keys SET scopes_json=? WHERE key_id=?",
                           (json.dumps([Permission.RUN_READ.value]), principal.key_id))
    before = _snapshot(store)
    with pytest.raises(SubscriberError, match="permission_denied"):
        _repair(governance, principal, run_id)
    assert _snapshot(store) == before


def test_active_dispatch_is_not_reconciled(tmp_path, manifest):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE subscriber_run_dispatches SET state='CLAIMED',claim_token=?,lease_owner='test-owner',lease_expires_at=? WHERE run_id=?",
                           ("synthetic-dispatch-token", (NOW + timedelta(seconds=30)).isoformat(), run_id))
    before = _snapshot(store)
    with pytest.raises(SubscriberError, match="dispatch_not_terminal_and_unclaimed"):
        _repair(governance, principal, run_id)
    assert _snapshot(store) == before


@pytest.mark.parametrize("terminal", ["CANCELLED", "COMPLETED", "INFRASTRUCTURE_FAILURE"])
def test_all_existing_terminal_states_support_expired_lease_only_cleanup(tmp_path, manifest, terminal):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE runs SET state=? WHERE run_id=?", (terminal, run_id))
        connection.execute("UPDATE subscriber_run_reservations SET claim_token=NULL,lease_expires_at=? WHERE run_id=?",
                           (NOW.isoformat(), run_id))
    result = _repair(governance, principal, run_id)
    assert result["reconciled"] is True and result["run_state"] == terminal


def test_audit_failure_rolls_back_ownership_cleanup(tmp_path, manifest, monkeypatch):
    store, governance, _, _, _, principal, run_id, _ = _subject(tmp_path, manifest)
    before = _snapshot(store)
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic_audit_storage_failure")
    monkeypatch.setattr(governance, "_append_audit", fail)
    with pytest.raises(RuntimeError, match="synthetic_audit_storage_failure"):
        _repair(governance, principal, run_id)
    assert _snapshot(store) == before


def test_api_requires_existing_governance_scope_and_valid_fixed_body(tmp_path, manifest):
    store, _, client, _, headers, principal, run_id, _ = _subject(tmp_path, manifest)
    route = f"/v1/subscriber/certifications/{run_id}/reconcile-reservation"
    before = _snapshot(store)
    with sqlite3.connect(store.db_path) as connection:
        connection.execute("UPDATE subscriber_api_keys SET scopes_json=? WHERE key_id=?",
                           (json.dumps([Permission.RUN_READ.value]), principal.key_id))
    denied = client.post(route, headers=headers, json={"reason": "owner_repair"})
    assert denied.status_code == 403
    assert _snapshot(store) == before
    invalid = client.post(route, headers=headers, json={"reason": "owner repair", "claim_token": "forbidden"})
    assert invalid.status_code == 422
    assert _snapshot(store) == before
