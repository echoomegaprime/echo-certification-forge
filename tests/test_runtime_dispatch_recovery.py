"""Runtime operator failures may defer only a wholly unstarted owned dispatch."""
from __future__ import annotations

import sqlite3

import pytest

from echo_certification_forge.subscriber import SubscriberError
from test_dispatch_orphaned_runs import _run, _usage


def _rows(governance, run_id):
    with sqlite3.connect(governance.db_path) as connection:
        return {
            table: connection.execute(
                f"SELECT * FROM {table} WHERE run_id = ?", (run_id,)
            ).fetchall()
            for table in ("runs", "subscriber_run_dispatches", "subscriber_run_reservations")
        }


@pytest.mark.parametrize(("column", "value"), [
    ("execution_started_at", "2026-11-12T12:00:00Z"),
    ("consumed_at", "2026-11-12T12:01:00Z"),
    ("worker_id", "synthetic-owned-worker"),
    ("worker_attestation_sha256", "1" * 64),
    ("execution_location", "synthetic-worker"),
    ("signing_authority", "customer"),
    ("signing_key_id", "synthetic-key"),
    ("claim_token", "synthetic-reservation-claim"),
    ("lease_expires_at", "2026-11-15T12:00:00Z"),
    ("last_heartbeat_at", "2026-11-12T12:00:00Z"),
])
def test_runtime_deferral_preserves_every_reservation_ownership(
    tmp_path, manifest, column, value
):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "runtime-owned", max_attempts=1
    )
    dispatch = governance.claim_dispatch(
        "dispatcher", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    # Only synthetic contradictory evidence in the disposable fixture database.
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            f"UPDATE subscriber_run_reservations SET {column} = ? WHERE run_id = ?",
            (value, run_id),
        )
    before_rows, before_usage = _rows(governance, run_id), _usage(governance, org)
    with pytest.raises(SubscriberError) as caught:
        governance.defer_dispatch_runtime_failure(
            dispatch, error="runtime_operator_profile_mismatch"
        )
    assert caught.value.status_code == 409
    assert caught.value.code == "dispatch_claim_inactive"
    assert _rows(governance, run_id) == before_rows
    assert _usage(governance, org) == before_usage
    assert store.get_run(run_id, org.organization_id)["state"] == "QUEUED"


def test_runtime_deferral_rejects_expired_dispatch_without_spending_retry(
    tmp_path, manifest
):
    _store, governance, org, run_id = _run(
        tmp_path, manifest, "runtime-expired", max_attempts=1
    )
    dispatch = governance.claim_dispatch(
        "dispatcher", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            "UPDATE subscriber_run_dispatches SET lease_expires_at = ? WHERE run_id = ?",
            ("2000-01-01T00:00:00Z", run_id),
        )
    before_rows, before_usage = _rows(governance, run_id), _usage(governance, org)
    with pytest.raises(SubscriberError) as caught:
        governance.defer_dispatch_runtime_failure(dispatch, error="runtime_identity_unavailable")
    assert caught.value.status_code == 409
    assert caught.value.code == "dispatch_claim_inactive"
    assert _rows(governance, run_id) == before_rows
    assert _usage(governance, org) == before_usage


@pytest.mark.parametrize("error", [
    "runtime_operator_profile_mismatch", "runtime_identity_unavailable",
])
def test_valid_runtime_deferral_returns_pending_without_spending_attempt_or_meter(
    tmp_path, manifest, error
):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "runtime-unstarted", max_attempts=1
    )
    dispatch = governance.claim_dispatch(
        "dispatcher", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    before_usage = _usage(governance, org)
    governance.defer_dispatch_runtime_failure(dispatch, error=error)
    status = governance.dispatch_status(run_id, org.organization_id)
    assert status["state"] == "PENDING"
    assert status["attempts"] == 0
    assert status["last_error"] == error
    assert _usage(governance, org) == before_usage
    assert store.get_run(run_id, org.organization_id)["state"] == "QUEUED"
    with sqlite3.connect(governance.db_path) as connection:
        assert connection.execute(
            "SELECT claim_token, lease_owner, lease_expires_at FROM subscriber_run_dispatches "
            "WHERE run_id = ?", (run_id,)
        ).fetchone() == (None, None, None)
    after = _rows(governance, run_id)
    with pytest.raises(SubscriberError):
        governance.defer_dispatch_runtime_failure(dispatch, error=error)
    assert _rows(governance, run_id) == after
    assert _usage(governance, org) == before_usage
    reclaimed = governance.claim_dispatch(
        "dispatcher-next", run_id=run_id, organization_id=org.organization_id
    )
    assert reclaimed is not None
    assert governance.dispatch_status(run_id, org.organization_id)["attempts"] == 1


def test_runtime_deferral_never_stores_arbitrary_worker_error(tmp_path, manifest):
    _store, governance, org, run_id = _run(
        tmp_path, manifest, "runtime-error", max_attempts=1
    )
    dispatch = governance.claim_dispatch(
        "dispatcher", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    before_rows, before_usage = _rows(governance, run_id), _usage(governance, org)
    with pytest.raises(ValueError, match="runtime deferral"):
        governance.defer_dispatch_runtime_failure(
            dispatch, error="synthetic untrusted worker detail"
        )
    assert _rows(governance, run_id) == before_rows
    assert _usage(governance, org) == before_usage


@pytest.mark.parametrize("max_attempts", [1, 3])
@pytest.mark.parametrize(("column", "value"), [
    ("worker_id", "synthetic-active-worker"),
    ("claim_token", "synthetic-active-claim"),
    ("last_heartbeat_at", "2026-11-14T07:00:00Z"),
])
def test_guarded_deferral_reports_spent_attempt_and_preserves_live_ownership(
    tmp_path, manifest, max_attempts, column, value
):
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.signing import Ed25519VerdictSigner

    store, governance, org, run_id = _run(
        tmp_path, manifest, "runtime-postclaim", max_attempts=max_attempts
    )
    before_usage = _usage(governance, org)
    owned_reservation = []
    def claimed_worker(*_args, **_kwargs):
        # Reproduce execution ownership being acquired before measurement fails.
        with sqlite3.connect(governance.db_path) as connection:
            connection.execute(
                f"UPDATE subscriber_run_reservations SET {column} = ? WHERE run_id = ?",
                (value, run_id),
            )
            owned_reservation[:] = connection.execute(
                "SELECT * FROM subscriber_run_reservations WHERE run_id = ?", (run_id,)
            ).fetchall()
        return {"run_id": run_id, "error": "runtime_identity_unavailable"}

    dispatch, result = dispatch_once(
        governance, claimed_worker, dispatcher_id="dispatcher",
        run_id=run_id, organization_id=org.organization_id,
        worker_options={"store": store, "manifest": manifest,
                        "signer": Ed25519VerdictSigner.generate(), "subscribers": governance},
    )
    assert dispatch is not None
    assert result["dispatcher_halted"] is True
    assert result["retry_budget_consumed"] is True
    assert governance.dispatch_status(run_id, org.organization_id)["attempts"] == 1
    with sqlite3.connect(governance.db_path) as connection:
        assert connection.execute(
            "SELECT * FROM subscriber_run_reservations WHERE run_id = ?", (run_id,)
        ).fetchall() == owned_reservation
    assert store.get_run(run_id, org.organization_id)["state"] == "QUEUED"
    assert _usage(governance, org) == before_usage
    # Neither ordinary retry nor orphan reconciliation may acquire this owned run.
    assert governance.claim_dispatch(
        "other-dispatcher", run_id=run_id, organization_id=org.organization_id
    ) is None
    assert _usage(governance, org) == before_usage
