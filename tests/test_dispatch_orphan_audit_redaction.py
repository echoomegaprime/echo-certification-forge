"""Historical orphan reconciliation must fail closed for untrusted error text.

All state changes use a private pytest SQLite fixture; this test never
modifies production data or sends a synthetic heartbeat.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _orphan_the_old_way, _run, _usage


@pytest.mark.parametrize(
    ("incoming_error", "eligible_for_recovery"),
    [
        ("subscriber_worker_claim_denied", True),
        ("Authorization: Bearer synthetic-do-not-store-000", False),
        (None, False),
    ],
)
def test_orphan_recovery_audit_redacts_untrusted_last_error(
    tmp_path, manifest, incoming_error, eligible_for_recovery
):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "audit-redaction", max_attempts=3
    )
    _orphan_the_old_way(governance, org, run_id)
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            "UPDATE subscriber_run_dispatches SET last_error = ? "
            "WHERE run_id = ? AND organization_id = ?",
            (incoming_error, run_id, org.organization_id),
        )

    assert governance.claim_dispatch(
        "audit-recovery", organization_id=org.organization_id
    ) is None
    expected_state = (
        RunState.INFRASTRUCTURE_FAILURE.value
        if eligible_for_recovery else RunState.QUEUED.value
    )
    assert store.get_run(run_id, org.organization_id)["state"] == expected_state

    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == (
        0 if eligible_for_recovery else 1
    )
    assert usage["active_run_reservations"] == (
        0 if eligible_for_recovery else 1
    )

    with sqlite3.connect(governance.db_path) as connection:
        audit_rows = connection.execute(
            "SELECT details_json FROM subscriber_audit_events "
            "WHERE organization_id = ? AND resource_id = ? "
            "AND action = 'certification.dispatch_orphan_reconciled'",
            (org.organization_id, run_id),
        ).fetchall()

    assert len(audit_rows) == (1 if eligible_for_recovery else 0)
    if eligible_for_recovery:
        assert json.loads(audit_rows[0][0])["last_error"] == (
            "subscriber_worker_claim_denied"
        )
    # Neither recognized nor rejected paths may persist a raw sensitive error.
    assert "synthetic-do-not-store-000" not in "\n".join(row[0] for row in audit_rows)
