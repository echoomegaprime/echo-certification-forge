"""Deterministic adapter identity, quality, and maturity acceptance.

P5 requires model/persona adapters to become first-class certification inputs rather
than an opaque ``adapter_set_sha256`` commitment. This module defines the immutable
records emitted by adapter execution and the fail-closed policy used to decide whether
that exact set is eligible for a production verdict.

No model output can override this evaluator. Missing, duplicate, unexpected,
non-STABLE, low-quality, critically failing, unapproved-node, or identity-mismatched
adapters are rejected deterministically.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum

from .canonical import require_identifier, require_sha256, sha256_json


class AdapterMaturity(StrEnum):
    EXPERIMENTAL = "EXPERIMENTAL"
    STABLE = "STABLE"
    DEGRADED = "DEGRADED"
    RETIRED = "RETIRED"


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    adapter_id: str
    version: str
    artifact_sha256: str
    configuration_sha256: str
    runtime_sha256: str
    maturity: AdapterMaturity
    provenance: str

    def __post_init__(self) -> None:
        require_identifier(self.adapter_id, "adapter_id")
        require_identifier(self.version, "version")
        object.__setattr__(
            self,
            "artifact_sha256",
            require_sha256(self.artifact_sha256, "artifact_sha256"),
        )
        object.__setattr__(
            self,
            "configuration_sha256",
            require_sha256(self.configuration_sha256, "configuration_sha256"),
        )
        object.__setattr__(
            self,
            "runtime_sha256",
            require_sha256(self.runtime_sha256, "runtime_sha256"),
        )
        object.__setattr__(self, "maturity", AdapterMaturity(self.maturity))
        provenance = self.provenance.strip()
        if not provenance:
            raise ValueError("provenance is required")
        if len(provenance) > 2048:
            raise ValueError("provenance exceeds 2048 characters")
        object.__setattr__(self, "provenance", provenance)

    def to_dict(self) -> dict[str, str]:
        return {
            "adapter_id": self.adapter_id,
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "configuration_sha256": self.configuration_sha256,
            "runtime_sha256": self.runtime_sha256,
            "maturity": self.maturity.value,
            "provenance": self.provenance,
        }

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class AdapterQualityReport:
    adapter_id: str
    passed_cases: int
    total_cases: int
    critical_failures: tuple[str, ...]
    suite_sha256: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.adapter_id, "adapter_id")
        if self.total_cases <= 0:
            raise ValueError("total_cases must be positive")
        if self.passed_cases < 0 or self.passed_cases > self.total_cases:
            raise ValueError("passed_cases must be between zero and total_cases")
        object.__setattr__(
            self,
            "suite_sha256",
            require_sha256(self.suite_sha256, "suite_sha256"),
        )
        failures = tuple(item.strip() for item in self.critical_failures)
        if any(not item for item in failures):
            raise ValueError("critical_failures may not contain blank values")
        for item in failures:
            require_identifier(item, "critical failure code")
        evidence = tuple(item.strip() for item in self.evidence_ids)
        if any(not item for item in evidence):
            raise ValueError("evidence_ids may not contain blank values")
        for item in evidence:
            require_identifier(item, "evidence_id")
        if len(set(evidence)) != len(evidence):
            raise ValueError("evidence_ids must be unique")
        object.__setattr__(self, "critical_failures", failures)
        object.__setattr__(self, "evidence_ids", evidence)

    @property
    def score(self) -> float:
        return self.passed_cases / self.total_cases

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "passed_cases": self.passed_cases,
            "total_cases": self.total_cases,
            "critical_failures": list(self.critical_failures),
            "suite_sha256": self.suite_sha256,
            "evidence_ids": list(self.evidence_ids),
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class AdapterExecutionRecord:
    identity: AdapterIdentity
    observed_identity_digest: str
    quality: AdapterQualityReport
    execution_node: str
    result_sha256: str

    def __post_init__(self) -> None:
        if self.identity.adapter_id != self.quality.adapter_id:
            raise ValueError("identity and quality adapter_id must match")
        object.__setattr__(
            self,
            "observed_identity_digest",
            require_sha256(self.observed_identity_digest, "observed_identity_digest"),
        )
        require_identifier(self.execution_node, "execution_node")
        object.__setattr__(
            self,
            "result_sha256",
            require_sha256(self.result_sha256, "result_sha256"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity.to_dict(),
            "observed_identity_digest": self.observed_identity_digest,
            "quality": self.quality.to_dict(),
            "execution_node": self.execution_node,
            "result_sha256": self.result_sha256,
        }


@dataclass(frozen=True, slots=True)
class AdapterAcceptancePolicy:
    required_adapter_digests: tuple[tuple[str, str], ...]
    minimum_score: float = 0.95
    minimum_cases: int = 20
    required_maturity: AdapterMaturity = AdapterMaturity.STABLE
    required_execution_nodes: tuple[str, ...] = ("ANVIL",)

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_score <= 1.0:
            raise ValueError("minimum_score must be between 0 and 1")
        if self.minimum_cases <= 0:
            raise ValueError("minimum_cases must be positive")
        object.__setattr__(self, "required_maturity", AdapterMaturity(self.required_maturity))

        normalized: list[tuple[str, str]] = []
        seen: set[str] = set()
        for adapter_id, digest in self.required_adapter_digests:
            require_identifier(adapter_id, "required adapter_id")
            if adapter_id in seen:
                raise ValueError(f"duplicate required adapter_id: {adapter_id}")
            seen.add(adapter_id)
            normalized.append((adapter_id, require_sha256(digest, f"{adapter_id} identity digest")))
        if not normalized:
            raise ValueError("at least one required adapter is required")
        object.__setattr__(self, "required_adapter_digests", tuple(sorted(normalized)))

        nodes = tuple(node.strip() for node in self.required_execution_nodes)
        if not nodes or any(not node for node in nodes):
            raise ValueError("at least one required execution node is required")
        for node in nodes:
            require_identifier(node, "required execution node")
        if len(set(nodes)) != len(nodes):
            raise ValueError("required_execution_nodes must be unique")
        object.__setattr__(self, "required_execution_nodes", tuple(sorted(nodes)))

    @property
    def required(self) -> dict[str, str]:
        return dict(self.required_adapter_digests)


@dataclass(frozen=True, slots=True)
class AdapterAcceptance:
    eligible: bool
    reasons: tuple[str, ...]
    adapter_set_sha256: str
    accepted_adapters: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def adapter_set_digest(records: tuple[AdapterExecutionRecord, ...]) -> str:
    """Hash the exact adapter identities independent of record ordering."""
    identities = [record.identity.to_dict() for record in records]
    identities.sort(key=lambda item: str(item["adapter_id"]))
    return sha256_json(identities)


def evaluate_adapter_acceptance(
    records: tuple[AdapterExecutionRecord, ...],
    policy: AdapterAcceptancePolicy,
    expected_adapter_set_sha256: str,
) -> AdapterAcceptance:
    """Evaluate an exact adapter set with deterministic, fail-closed reasons."""
    expected_set = require_sha256(expected_adapter_set_sha256, "expected_adapter_set_sha256")
    reasons: set[str] = set()
    by_id: dict[str, AdapterExecutionRecord] = {}

    for record in records:
        adapter_id = record.identity.adapter_id
        if adapter_id in by_id:
            reasons.add(f"duplicate_adapter:{adapter_id}")
            continue
        by_id[adapter_id] = record

    required = policy.required
    for adapter_id in sorted(set(required) - set(by_id)):
        reasons.add(f"missing_adapter:{adapter_id}")
    for adapter_id in sorted(set(by_id) - set(required)):
        reasons.add(f"unexpected_adapter:{adapter_id}")

    accepted: list[str] = []
    for adapter_id in sorted(set(required) & set(by_id)):
        record = by_id[adapter_id]
        local_reasons: list[str] = []

        if record.observed_identity_digest != record.identity.identity_digest:
            local_reasons.append(f"observed_identity_mismatch:{adapter_id}")
        if record.identity.identity_digest != required[adapter_id]:
            local_reasons.append(f"unapproved_identity:{adapter_id}")
        if record.identity.maturity is not policy.required_maturity:
            local_reasons.append(
                f"maturity_not_{policy.required_maturity.value.lower()}:{adapter_id}"
            )
        if record.execution_node not in policy.required_execution_nodes:
            local_reasons.append(f"unapproved_execution_node:{adapter_id}")
        if record.quality.total_cases < policy.minimum_cases:
            local_reasons.append(f"insufficient_quality_cases:{adapter_id}")
        if record.quality.score < policy.minimum_score:
            local_reasons.append(f"quality_below_threshold:{adapter_id}")
        if record.quality.critical_failures:
            local_reasons.append(f"critical_quality_failure:{adapter_id}")
        if not record.quality.evidence_ids:
            local_reasons.append(f"quality_evidence_missing:{adapter_id}")

        reasons.update(local_reasons)
        if not local_reasons:
            accepted.append(adapter_id)

    actual_set = adapter_set_digest(records)
    if actual_set != expected_set:
        reasons.add("adapter_set_identity_mismatch")

    ordered_reasons = tuple(sorted(reasons))
    return AdapterAcceptance(
        eligible=not ordered_reasons,
        reasons=ordered_reasons,
        adapter_set_sha256=actual_set,
        accepted_adapters=tuple(accepted),
    )
