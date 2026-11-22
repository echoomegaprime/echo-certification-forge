from __future__ import annotations

import json

import pytest

from echo_certification_forge.adapter_policy import (
    AdapterPolicyError,
    load_adapter_acceptance_policy,
    parse_adapter_acceptance_policy,
)
from echo_certification_forge.adapters import AdapterMaturity


def digest(ch: str) -> str:
    return ch * 64


def valid_policy() -> dict:
    return {
        "schema_version": "1.0.0",
        "required_adapters": [
            {"adapter_id": "gs343", "identity_digest": digest("a")},
            {"adapter_id": "r2d2", "identity_digest": digest("b")},
        ],
        "minimum_score": 0.95,
        "minimum_cases": 20,
        "required_maturity": "STABLE",
        "required_execution_nodes": ["ANVIL"],
    }


def test_valid_policy_is_normalized() -> None:
    policy = parse_adapter_acceptance_policy(valid_policy())

    assert policy.required == {"gs343": digest("a"), "r2d2": digest("b")}
    assert policy.minimum_score == 0.95
    assert policy.minimum_cases == 20
    assert policy.required_maturity is AdapterMaturity.STABLE
    assert policy.required_execution_nodes == ("ANVIL",)


def test_unknown_fields_are_rejected() -> None:
    raw = valid_policy()
    raw["allow_unverified"] = True

    with pytest.raises(AdapterPolicyError, match="schema mismatch"):
        parse_adapter_acceptance_policy(raw)


def test_duplicate_required_adapter_is_rejected() -> None:
    raw = valid_policy()
    raw["required_adapters"].append(
        {"adapter_id": "gs343", "identity_digest": digest("c")}
    )

    with pytest.raises(AdapterPolicyError, match="duplicate required adapter_id"):
        parse_adapter_acceptance_policy(raw)


def test_empty_execution_nodes_are_rejected() -> None:
    raw = valid_policy()
    raw["required_execution_nodes"] = []

    with pytest.raises(AdapterPolicyError, match="required execution node"):
        parse_adapter_acceptance_policy(raw)


def test_policy_file_loader_rejects_invalid_json(tmp_path) -> None:
    path = tmp_path / "adapter-policy.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(AdapterPolicyError, match="unreadable"):
        load_adapter_acceptance_policy(path)


def test_policy_file_loader_round_trips(tmp_path) -> None:
    path = tmp_path / "adapter-policy.json"
    path.write_text(json.dumps(valid_policy()), encoding="utf-8")

    policy = load_adapter_acceptance_policy(path)

    assert policy.required_execution_nodes == ("ANVIL",)
    assert tuple(policy.required) == ("gs343", "r2d2")
