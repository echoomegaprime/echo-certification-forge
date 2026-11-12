"""The immutable orphan-reconciliation audit must not persist untrusted error text.

All state changes use pytest's private temporary SQLite database.
This test covers the recovery path only, without a production dispatcher.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _orphan_the_old_way, _run, _usage


@pytest.mark.parametrize(
    ("incoming_error", "audited_error"),
    [
        ("subscriber_worker_claim_denied", "subscriber_worker_claim_denied"),
        ("Authorization: Bearer synthetic-do-not-store-000", "redacted"),
        (None, None),
    ],
)
def test_orphan_recovery_audit_redacts_untrusted_last_error(
    tmp_path, manifest, incoming_error, audited_error
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
        connection.commit()

    assert governance.claim_dispatch(
        "audit-recovery", organization_id=org.organization_id
    ) is None
    assert store.get_run(run_id, org.organization_id)["state"] == (
        RunState.INFRASTRUCTURE_FAILURE.value
    )
    assert _usage(governance, org)["meters"]["certification_runs"] == 0

    with sqlite3.connect(governance.db_path) as connection:
        audit_rows = connection.execute(
            "SELECT details_json FROM subscriber_audit_events "
            "WHERE organization_id = ? AND resource_id = ? "
            "AND action = 'certification.dispatch_orphan_reconciled'",
            (org.organization_id, run_id),
        ).fetchall()
    assert len(audit_rows) == 1
    recorded = audit_rows[0][0]
    assert json.loads(recorded)["last_error"] == audited_error
    assert "synthetic-do-not-store-000" not in recorded
