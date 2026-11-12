"""A dispatch that gives up must not leave its run QUEUED forever (Echo fleet #49604).

On FORGE (2026-11-03) seven runs from 2026-10-09..10-30 were QUEUED while their dispatch rows were
FAILED after 3 attempts with `subscriber_worker_claim_denied`, their reservations still BOUND and
execution never started. finish_dispatch() marked only the dispatch FAILED, so the runs never
reached a terminal state, the customer was never compensated for the metered run, and every
"is the queue idle?" check (for example the swarm re-certification) stayed blocked.

The lease-expiry path already does the right thing (INFRASTRUCTURE_FAILURE, run_outcome INFRA_FAILED,
reservation RELEASED, meter compensated). These tests pin the same outcome for finish_dispatch, and
for runs already orphaned by the old code.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from echo_certification_forge.models import RunState  # noqa: E402
from echo_certification_forge.subscriber import Permission  # noqa: E402
from test_p7_subscriber_governance import (  # noqa: E402
    _owner,
    _policy,
    _provision,
    _stack,
    _submit_local_run,
)


def _run(tmp_path, manifest, name, *, max_attempts):
    policy = _policy().model_copy(update={"max_dispatch_attempts": max_attempts})
    store, governance, client = _stack(tmp_path, manifest, policy=policy)
    org = _provision(governance, name)
    source = tmp_path / f"{name}-source"
    source.mkdir()
    (source / "hello.py").write_text("print('dispatch')\n", encoding="utf-8")
    run_id, _ = _submit_local_run(client, manifest, org.organization_id, org.bootstrap_api_key, source,
                                  key=f"{name}-0001")
    return store, governance, org, run_id


def _usage(governance, org):
    return governance.usage_summary(_owner(governance, org.organization_id, org.bootstrap_api_key,
                                           Permission.USAGE_READ))


def test_worker_error_on_the_last_attempt_terminalizes_and_compensates(tmp_path, manifest) -> None:
    store, governance, org, run_id = _run(tmp_path, manifest, "exhausted-claim-denied", max_attempts=1)
    dispatch = governance.claim_dispatch("dispatcher-a", run_id=run_id, organization_id=org.organization_id)
    assert dispatch is not None

    assert governance.finish_dispatch(dispatch, error="subscriber_worker_claim_denied") == "FAILED"

    run = store.get_run(run_id, org.organization_id)
    assert run["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert run["run_outcome"] == "INFRA_FAILED"
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "FAILED"
    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0


def test_worker_error_with_attempts_left_still_retries(tmp_path, manifest) -> None:
    store, governance, org, run_id = _run(tmp_path, manifest, "retry-left", max_attempts=3)
    dispatch = governance.claim_dispatch("dispatcher-a", run_id=run_id, organization_id=org.organization_id)

    assert governance.finish_dispatch(dispatch, error="subscriber_worker_claim_denied") == "PENDING"

    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert _usage(governance, org)["meters"]["certification_runs"] == 1


def _orphan_the_old_way(governance, org, run_id) -> None:
    """Reproduce what the old finish_dispatch left behind: dispatch FAILED, run QUEUED, reservation BOUND."""
    dispatch = governance.claim_dispatch("dispatcher-a", run_id=run_id, organization_id=org.organization_id)
    assert dispatch is not None
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET state = 'FAILED', attempts = 3, claim_token = NULL, lease_owner = NULL,
                lease_expires_at = NULL, last_error = 'subscriber_worker_claim_denied'
            WHERE run_id = ? AND organization_id = ?
            """,
            (run_id, org.organization_id),
        )
        connection.commit()


def test_runs_orphaned_by_the_old_code_are_reconciled_once(tmp_path, manifest) -> None:
    store, governance, org, run_id = _run(tmp_path, manifest, "orphan-reconcile", max_attempts=3)
    _orphan_the_old_way(governance, org, run_id)
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert _usage(governance, org)["meters"]["certification_runs"] == 1

    assert governance.claim_dispatch("dispatcher-b", organization_id=org.organization_id) is None

    run = store.get_run(run_id, org.organization_id)
    assert run["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert run["run_outcome"] == "INFRA_FAILED"
    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0
    # Idempotent: a later pass neither re-transitions nor compensates twice.
    assert governance.claim_dispatch("dispatcher-c", organization_id=org.organization_id) is None
    assert _usage(governance, org)["meters"]["certification_runs"] == 0


def test_a_failed_dispatch_whose_run_already_finished_is_left_alone(tmp_path, manifest) -> None:
    store, governance, org, run_id = _run(tmp_path, manifest, "orphan-terminal", max_attempts=1)
    dispatch = governance.claim_dispatch("dispatcher-a", run_id=run_id, organization_id=org.organization_id)
    governance.finish_dispatch(dispatch, error="subscriber_worker_claim_denied")
    before = _usage(governance, org)["meters"]["certification_runs"]
    assert governance.claim_dispatch("dispatcher-b", organization_id=org.organization_id) is None
    assert _usage(governance, org)["meters"]["certification_runs"] == before == 0


# Synthetic contradictory records must not lose live execution ownership,
# immutable evidence or metered reservations during historical recovery.
import pytest


@pytest.mark.parametrize(
    ("table", "column", "value"),
    [
        ("subscriber_run_reservations", "execution_started_at", "2026-11-12T12:00:00Z"),
        ("subscriber_run_reservations", "consumed_at", "2026-11-12T12:01:00Z"),
        ("subscriber_run_reservations", "worker_id", "synthetic-test-worker"),
        ("subscriber_run_reservations", "worker_attestation_sha256", "1" * 64),
        ("subscriber_run_reservations", "execution_location", "synthetic-test-location"),
        ("subscriber_run_reservations", "signing_authority", "synthetic-test-authority"),
        ("subscriber_run_reservations", "signing_key_id", "synthetic-test-key"),
        ("subscriber_run_reservations", "claim_token", "synthetic-test-claim"),
        ("subscriber_run_reservations", "lease_expires_at", "2026-11-12T13:00:00Z"),
        ("subscriber_run_reservations", "last_heartbeat_at", "2026-11-12T12:00:00Z"),
        ("subscriber_run_dispatches", "claim_token", "synthetic-test-dispatch-claim"),
        ("subscriber_run_dispatches", "lease_owner", "synthetic-test-dispatch-owner"),
        ("subscriber_run_dispatches", "lease_expires_at", "2026-11-12T13:00:00Z"),
    ],
)
def test_orphan_recovery_preserves_conflicting_ownership(
    tmp_path, manifest, table, column, value
) -> None:
    store, governance, org, run_id = _run(
        tmp_path, manifest, "contradictory-owner", max_attempts=3
    )
    _orphan_the_old_way(governance, org, run_id)
    # Only disposable test SQLite, never production. Parameters are test constants.
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE run_id = ? AND organization_id = ?",
            (value, run_id, org.organization_id),
        )
    assert governance.claim_dispatch(
        "dispatcher-reconciler", organization_id=org.organization_id
    ) is None
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == 1
    assert usage["active_run_reservations"] == 1
    with sqlite3.connect(governance.db_path) as connection:
        state = connection.execute(
            "SELECT state FROM subscriber_run_reservations "
            "WHERE run_id = ? AND organization_id = ?",
            (run_id, org.organization_id),
        ).fetchone()[0]
        assert state == "BOUND"


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("consumed_at", "2026-11-12T14:00:00Z"),
        ("execution_started_at", "2026-11-12T14:00:00Z"),
        ("worker_id", "synthetic-live-worker"),
    ],
)
def test_final_dispatch_error_preserves_conflicting_execution_evidence(
    tmp_path, manifest, column, value
) -> None:
    """An exhausted claimed dispatch cannot erase contradictory ownership."""
    store, governance, org, run_id = _run(
        tmp_path, manifest, "final-attempt-owner", max_attempts=1
    )
    dispatch = governance.claim_dispatch(
        "dispatcher-a", run_id=run_id, organization_id=org.organization_id
    )
    assert dispatch is not None
    # Synthetic state mutation is confined to the disposable test fixture DB.
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            f"UPDATE subscriber_run_reservations SET {column} = ? "
            "WHERE run_id = ? AND organization_id = ?",
            (value, run_id, org.organization_id),
        )
    assert governance.finish_dispatch(
        dispatch, error="subscriber_worker_claim_denied"
    ) == "FAILED"
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "FAILED"
    usage = _usage(governance, org)
    assert usage["meters"]["certification_runs"] == 1
    assert usage["active_run_reservations"] == 1
    # No historical reconcile may reinterpret the contradictory record as unstarted.
    assert governance.claim_dispatch("dispatcher-b", organization_id=org.organization_id) is None
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
