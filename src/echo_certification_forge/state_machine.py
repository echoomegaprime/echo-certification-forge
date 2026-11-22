"""Fail-closed CertificationRun state transition contract."""
from __future__ import annotations

from .models import RunState

_ALLOWED: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset({RunState.QUEUED, RunState.CANCELLED}),
    RunState.QUEUED: frozenset({RunState.ACQUIRING_TARGET, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.ACQUIRING_TARGET: frozenset({RunState.DISCOVERING, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.DISCOVERING: frozenset({RunState.PLANNING, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.PLANNING: frozenset({RunState.PROVISIONING, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.PROVISIONING: frozenset({RunState.BUILDING, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.BUILDING: frozenset({RunState.STARTING_APPLICATION, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.STARTING_APPLICATION: frozenset({RunState.VERIFYING_READINESS, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.VERIFYING_READINESS: frozenset({RunState.EXECUTING_TESTS, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.EXECUTING_TESTS: frozenset({RunState.COLLECTING_EVIDENCE, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.COLLECTING_EVIDENCE: frozenset({RunState.CLASSIFYING_FINDINGS, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.CLASSIFYING_FINDINGS: frozenset({RunState.CALCULATING_VERDICT, RunState.CANCELLED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.CALCULATING_VERDICT: frozenset({RunState.FINALIZING_REPORT, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.FINALIZING_REPORT: frozenset({RunState.REGISTERING_RESULT, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.REGISTERING_RESULT: frozenset({RunState.COMPLETED, RunState.INFRASTRUCTURE_FAILURE}),
    RunState.COMPLETED: frozenset(),
    RunState.CANCELLED: frozenset(),
    RunState.INFRASTRUCTURE_FAILURE: frozenset(),
}


def validate_transition(current: RunState, requested: RunState) -> None:
    if requested not in _ALLOWED[current]:
        raise ValueError(f"illegal run-state transition: {current.value} -> {requested.value}")
