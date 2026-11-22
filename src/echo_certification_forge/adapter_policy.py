"""Strict loading of versioned P5 adapter acceptance policy files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .adapters import AdapterAcceptancePolicy, AdapterMaturity


class AdapterPolicyError(ValueError):
    """The adapter acceptance policy is malformed or unsupported."""


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AdapterPolicyError(
            f"{field} schema mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def parse_adapter_acceptance_policy(raw: Any) -> AdapterAcceptancePolicy:
    if not isinstance(raw, dict):
        raise AdapterPolicyError("adapter policy must be an object")
    _exact_keys(
        raw,
        {
            "schema_version",
            "required_adapters",
            "minimum_score",
            "minimum_cases",
            "required_maturity",
            "required_execution_nodes",
        },
        "adapter policy",
    )
    if raw["schema_version"] != "1.0.0":
        raise AdapterPolicyError("unsupported adapter policy schema_version")

    required = raw["required_adapters"]
    nodes = raw["required_execution_nodes"]
    if not isinstance(required, list) or not required:
        raise AdapterPolicyError("required_adapters must be a non-empty array")
    if not isinstance(nodes, list) or not all(isinstance(node, str) for node in nodes):
        raise AdapterPolicyError("required_execution_nodes must be a string array")

    required_pairs: list[tuple[str, str]] = []
    for index, item in enumerate(required):
        if not isinstance(item, dict):
            raise AdapterPolicyError(f"required_adapters[{index}] must be an object")
        _exact_keys(item, {"adapter_id", "identity_digest"}, f"required_adapters[{index}]")
        required_pairs.append((str(item["adapter_id"]), str(item["identity_digest"])))

    try:
        return AdapterAcceptancePolicy(
            required_adapter_digests=tuple(required_pairs),
            minimum_score=float(raw["minimum_score"]),
            minimum_cases=int(raw["minimum_cases"]),
            required_maturity=AdapterMaturity(str(raw["required_maturity"])),
            required_execution_nodes=tuple(nodes),
        )
    except (TypeError, ValueError) as exc:
        raise AdapterPolicyError(f"adapter policy invalid: {exc}") from exc


def load_adapter_acceptance_policy(path: Path) -> AdapterAcceptancePolicy:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterPolicyError(f"adapter policy unreadable: {type(exc).__name__}") from exc
    return parse_adapter_acceptance_policy(raw)
