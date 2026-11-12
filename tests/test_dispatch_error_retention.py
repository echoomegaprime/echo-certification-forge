"""Untrusted dispatch worker exceptions must not persist or leak on readback."""
from __future__ import annotations

import sqlite3

import pytest

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _orphan_the_old_way, _run, _usage


@pytest.mark.parametrize(
    ("incoming", "expected"),
    [
        ("subscriber_worker_claim_denied", "subscriber_worker_claim_denied"),
        ("Authorization: Bearer synthetic-do-not-retain-000", "redacted"),
        ("arbitrary remote stack trace", "redacted"),
    ],
)
def test_new_worker_error_storage_and_status_redacted(
    tmp_path, manifest, incoming, expected
):
    store, gov, org, run_id = _run(tmp_path, manifest, "error-retention", max_attempts=1)
    dispatch = gov.claim_dispatch(
        "dispatcher", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    assert gov.finish_dispatch(dispatch, error=incoming) == "FAILED"
    assert store.get_run(run_id, org.organization_id)["state"] == (
        RunState.INFRASTRUCTURE_FAILURE.value
    )
    usage = _usage(gov, org)
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0
    assert gov.dispatch_status(run_id, org.organization_id)["last_error"] == expected
    with sqlite3.connect(gov.db_path) as conn:
        stored = conn.execute(
            "SELECT last_error FROM subscriber_run_dispatches WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
    assert stored == expected
    assert "synthetic-do-not-retain-000" not in (stored or "")


def test_legacy_error_read_redacted_without_mutating_db(tmp_path, manifest):
    store, gov, org, run_id = _run(tmp_path, manifest, "legacy-error", max_attempts=3)
    _orphan_the_old_way(gov, org, run_id)
    raw = "Authorization: Bearer synthetic-legacy-no-display-000"
    with sqlite3.connect(gov.db_path) as conn:
        conn.execute(
            "UPDATE subscriber_run_dispatches SET last_error = ? WHERE run_id = ?",
            (raw, run_id),
        )
        conn.commit()
    assert gov.dispatch_status(run_id, org.organization_id)["last_error"] == "redacted"
    with sqlite3.connect(gov.db_path) as conn:
        assert conn.execute(
            "SELECT last_error FROM subscriber_run_dispatches WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0] == raw
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
