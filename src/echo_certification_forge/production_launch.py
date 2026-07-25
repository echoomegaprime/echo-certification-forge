"""Pure production run-worker argument construction."""
from __future__ import annotations

import json
from pathlib import Path


def production_worker_args(
    *,
    run_id: str,
    tenant: str,
    target: dict,
    journey: list[str] | None,
    policy_id: str,
    adapter_response: Path,
    adapter_policy: Path,
    adapter_registry: Path,
    adapter_runner_signing_key: Path,
) -> list[str]:
    args = [
        "--run-id",
        run_id,
        "--tenant",
        tenant,
        "--target-json",
        json.dumps(target),
        "--sandbox",
        "--policy-version",
        policy_id,
        "--adapter-response",
        str(adapter_response),
        "--adapter-policy",
        str(adapter_policy),
        "--adapter-registry",
        str(adapter_registry),
        "--adapter-runner-signing-key",
        str(adapter_runner_signing_key),
    ]
    if journey:
        args.extend(["--journey-json", json.dumps(journey)])
    return args
