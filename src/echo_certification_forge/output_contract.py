"""Deterministic, fail-closed policy boundary for Family adapter JSON output."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json

OUTPUT_CONTRACT_SCHEMA = "echo.certification-forge.adapter-output-contract/v1"
_GS_RELEASE_RISK = {
    "application-defect": "block",
    "dependency-defect": "block",
    "harness-defect": "conditional",
    "inconclusive": "block",
    "multi-cause": "block",
}
_RISK_RANK = {"conditional": 0, "block": 1}


@dataclass(frozen=True, slots=True)
class AdapterOutputContract:
    """Canonical content plus an auditable record of deterministic policy repairs."""

    adapter: str
    raw_content: str
    content: str
    applied_rules: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.content != self.raw_content

    @property
    def raw_sha256(self) -> str:
        return hashlib.sha256(self.raw_content.encode("utf-8")).hexdigest()

    @property
    def normalized_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": OUTPUT_CONTRACT_SCHEMA,
            "adapter": self.adapter,
            "changed": self.changed,
            "applied_rules": list(self.applied_rules),
            "raw_sha256": self.raw_sha256,
            "normalized_sha256": self.normalized_sha256,
        }


def _gs_policy(answer: dict[str, Any], rules: list[str]) -> None:
    if answer.get("target_mutation_allowed") is not False:
        answer["target_mutation_allowed"] = False
        rules.append("gs343.force_target_mutation_prohibited")

    required_risk = _GS_RELEASE_RISK.get(answer.get("classification"))
    observed_risk = answer.get("release_risk")
    if required_risk is not None and (
        observed_risk not in _RISK_RANK
        or _RISK_RANK[observed_risk] < _RISK_RANK[required_risk]
    ):
        answer["release_risk"] = required_risk
        rules.append("gs343.enforce_minimum_release_risk")


def _r2_policy(answer: dict[str, Any], rules: list[str]) -> None:
    markers = answer.get("persona_markers")
    if not isinstance(markers, list) or not all(
        isinstance(marker, str) for marker in markers
    ):
        return
    additions: list[str] = []
    for required in ("R2-D2", "diagnostic-beep", "presentation-only"):
        if required not in markers:
            additions.append(required)
    if additions:
        answer["persona_markers"] = [*markers, *additions]
        rules.append("r2d2.expand_compound_persona_markers")


def normalize_adapter_output(adapter: str, content: str) -> AdapterOutputContract:
    """Apply only policy-owned or presentation-only repairs; never alter a verdict."""
    if adapter not in {"gs343", "r2d2"}:
        raise ValueError(f"unsupported adapter output contract: {adapter}")
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return AdapterOutputContract(adapter, content, content, ())
    if not isinstance(value, dict):
        return AdapterOutputContract(adapter, content, content, ())

    answer = json.loads(json.dumps(value))
    rules: list[str] = []
    if adapter == "gs343":
        _gs_policy(answer, rules)
    else:
        _r2_policy(answer, rules)
    normalized = canonical_json(answer)
    return AdapterOutputContract(adapter, content, normalized, tuple(rules))
