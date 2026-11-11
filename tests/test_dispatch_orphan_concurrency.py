"""A concurrent orphan sweep must compensate a metered run exactly once.

This regression supplements the sequential orphan recovery coverage from PR #49.
It uses an isolated SQLite fixture; no production service or Telegram/OAuth integration.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import sqlite3

from echo_certification_forge.models import RunState
from test_dispatch_orphaned_runs import _run, _orphan_the_old_way, _usage


def test_two_simultaneous_recoverers_compensate_once(tmp_path, manifest):
    store, governance, org, run_id = _run(
        tmp_path, manifest, "probe-concurrent-recovery", max_attempts=3
    )
    _orphan_the_old_way(governance, org, run_id)
    barrier = Barrier(3)

    def recover(label):
        barrier.wait(timeout=8)
        return governance.claim_dispatch(label, organization_id=org.organization_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(recover, "probe-recoverer-a")
        two = pool.submit(recover, "probe-recoverer-b")
        barrier.wait(timeout=8)
        results = [one.result(timeout=20), two.result(timeout=20)]

    assert results == [None, None]
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0
    with sqlite3.connect(governance.db_path) as connection:
        compensations = connection.execute(
            "SELECT count(*) FROM subscriber_usage_events "
            "WHERE organization_id = ? AND meter = 'certification_runs' "
            "AND quantity = -1 AND idempotency_key LIKE 'dispatch-crash:%'",
            (org.organization_id,),
        ).fetchone()[0]
    assert compensations == 1, f"expected one compensation, got {compensations}"
