"""Reconcile multiple legacy dispatch orphans across tenants exactly once.

All runs, principals, and accounting events use disposable local fixtures.
"""
from __future__ import annotations

import sqlite3

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _usage
from test_p7_subscriber_governance import _policy, _provision, _stack, _submit_local_run


def test_multiple_tenant_orphans_reconciled_once(tmp_path, manifest):
    policy = _policy().model_copy(update={"max_dispatch_attempts": 3})
    store, governance, client = _stack(tmp_path, manifest, policy=policy)
    pairs = []
    for index in range(5):
        org = _provision(governance, f"batch-orphan-org-{index}")
        source = tmp_path / f"orphan-source-{index}"
        source.mkdir()
        (source / "hello.py").write_text("print('ok')\n", encoding="utf-8")
        run_id, _ = _submit_local_run(
            client, manifest, org.organization_id, org.bootstrap_api_key,
            source, key=f"batch-orphan-{index:04d}",
        )
        pairs.append((org, run_id))

    # Recreate the legacy state without invoking claim_dispatch while staging;
    # that call would run the new reconciler before the whole batch exists.
    with sqlite3.connect(governance.db_path) as db:
        for org, run_id in pairs:
            db.execute(
                "UPDATE subscriber_run_dispatches "
                "SET state='FAILED', attempts=3, claim_token=NULL, "
                "lease_owner=NULL, lease_expires_at=NULL, "
                "last_error='subscriber_worker_claim_denied' "
                "WHERE run_id=? AND organization_id=?",
                (run_id, org.organization_id),
            )
        db.commit()

    assert all(_usage(governance, org)["meters"]["certification_runs"] == 1 for org, _ in pairs)
    assert governance.claim_dispatch("batch-recovery") is None
    for org, run_id in pairs:
        assert store.get_run(run_id, org.organization_id)["state"] == RunState.INFRASTRUCTURE_FAILURE.value
        usage = _usage(governance, org)
        assert usage["meters"]["certification_runs"] == 0
        assert usage["active_run_reservations"] == 0

    def readback():
        with sqlite3.connect(governance.db_path) as db:
            audits = db.execute(
                "SELECT COUNT(*) FROM subscriber_audit_events "
                "WHERE action='certification.dispatch_orphan_reconciled'"
            ).fetchone()[0]
            refunds = dict(db.execute(
                "SELECT organization_id, COUNT(*) FROM subscriber_usage_events "
                "WHERE meter='certification_runs' AND quantity=-1 "
                "GROUP BY organization_id"
            ).fetchall())
        return audits, refunds

    expected_refunds = {org.organization_id: 1 for org, _ in pairs}
    assert readback() == (len(pairs), expected_refunds)
    assert governance.claim_dispatch("batch-recovery-repeat") is None
    assert readback() == (len(pairs), expected_refunds)
