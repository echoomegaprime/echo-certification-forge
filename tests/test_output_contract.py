from __future__ import annotations

import json

from echo_certification_forge.output_contract import normalize_adapter_output


def test_gs_policy_owns_mutation_permission_and_minimum_release_risk() -> None:
    raw = json.dumps(
        {
            "classification": "dependency-defect",
            "confidence": 0.92,
            "abstain": False,
            "root_causes": ["dependency unavailable"],
            "repair_actions": ["restore the pinned dependency"],
            "release_risk": "conditional",
        }
    )
    result = normalize_adapter_output("gs343", raw)
    answer = json.loads(result.content)
    assert answer["target_mutation_allowed"] is False
    assert answer["release_risk"] == "block"
    assert result.applied_rules == (
        "gs343.force_target_mutation_prohibited",
        "gs343.enforce_minimum_release_risk",
    )


def test_gs_policy_never_weakens_an_existing_block() -> None:
    raw = json.dumps(
        {
            "classification": "harness-defect",
            "target_mutation_allowed": False,
            "release_risk": "block",
        }
    )
    result = normalize_adapter_output("gs343", raw)
    assert json.loads(result.content)["release_risk"] == "block"
    assert result.applied_rules == ()


def test_r2_compound_marker_expansion_does_not_change_verdict() -> None:
    raw = json.dumps(
        {
            "reported_verdict": "NOT_READY",
            "persona_markers": ["R2-diagnostic-beep", "presentation-only"],
            "changes_verdict": False,
        }
    )
    result = normalize_adapter_output("r2d2", raw)
    answer = json.loads(result.content)
    assert answer["reported_verdict"] == "NOT_READY"
    assert {"R2-D2", "diagnostic-beep", "presentation-only"}.issubset(
        answer["persona_markers"]
    )
    assert result.applied_rules == ("r2d2.expand_compound_persona_markers",)


def test_malformed_json_is_not_repaired_or_reinterpreted() -> None:
    raw = '{"reported_verdict":"NOT_READY"} trailing'
    result = normalize_adapter_output("r2d2", raw)
    assert result.content == raw
    assert result.applied_rules == ()
