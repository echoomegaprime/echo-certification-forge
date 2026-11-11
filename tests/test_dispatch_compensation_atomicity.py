"""Failure-injection acceptance for dispatch compensation transaction atomicity.

Test-only follow-up to combined recovery PR #49 and concurrency PR #53.
All writes are confined to pytest's temporary SQLite fixture.
"""
from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _orphan_the_old_way, _run, _usage


def _database_snapshot(governance, org, run_id):
    with sqlite3.connect(governance.db_path) as conn:
        reservation = conn.execute(
            "SELECT state FROM subscriber_run_reservations "
            "WHERE run_id = ? AND organization_id = ?",
            (run_id, org.organization_id),
        ).fetchone()
        dispatch = conn.execute(
            "SELECT state FROM subscriber_run_dispatches "
            "WHERE run_id = ? AND organization_id = ?",
            (run_id, org.organization_id),
        ).fetchone()
        compensations = conn.execute(
            "SELECT COUNT(*) FROM subscriber_usage_events "
            "WHERE organization_id = ? AND meter = 'certification_runs' "
            "AND quantity = -1 AND idempotency_key LIKE 'dispatch-crash:%'",
            (org.organization_id,),
        ).fetchone()[0]
    assert reservation is not None and dispatch is not None
    return reservation[0], dispatch[0], compensations


def _compensation_unavailable(*_args, **_kwargs):
    raise RuntimeError("injected compensation failure")


def test_orphan_recovery_compensation_exception_rolls_back(tmp_path, manifest):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "orphan-compensation-rollback", max_attempts=3
    )
    _orphan_the_old_way(governance, org, run_id)

    with patch.object(
        type(governance), "_compensate_crash_meter",
        side_effect=_compensation_unavailable,
    ):
        with pytest.raises(RuntimeError, match="injected compensation failure"):
            governance.claim_dispatch("failure-injection", organization_id=org.organization_id)

    # A crash between state transition and metering must not leave a half-finished run.
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert _database_snapshot(governance, org, run_id) == ("BOUND", "FAILED", 0)
    assert _usage(governance, org)["meters"]["certification_runs"] == 1

    # Retrying after restoring the real compensator must complete the entire transaction once.
    assert governance.claim_dispatch("recovery-retry", organization_id=org.organization_id) is None
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert _database_snapshot(governance, org, run_id) == ("RELEASED", "FAILED", 1)
    assert _usage(governance, org)["meters"]["certification_runs"] == 0
    assert governance.claim_dispatch("recovery-repeat", organization_id=org.organization_id) is None
    assert _database_snapshot(governance, org, run_id)[2] == 1


def test_last_attempt_compensation_exception_preserves_claim(tmp_path, manifest):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "finish-compensation-rollback", max_attempts=1
    )
    dispatch = governance.claim_dispatch("failure-injection", organization_id=org.organization_id)
    assert dispatch is not None

    with patch.object(
        type(governance), "_compensate_crash_meter",
        side_effect=_compensation_unavailable,
    ):
        with pytest.raises(RuntimeError, match="injected compensation failure"):
            governance.finish_dispatch(dispatch, error="subscriber_worker_claim_denied")

    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert _database_snapshot(governance, org, run_id) == ("BOUND", "CLAIMED", 0)
    assert _usage(governance, org)["meters"]["certification_runs"] == 1

    assert governance.finish_dispatch(dispatch, error="subscriber_worker_claim_denied") == "FAILED"
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert _database_snapshot(governance, org, run_id) == ("RELEASED", "FAILED", 1)
    assert _usage(governance, org)["meters"]["certification_runs"] == 0
