"""Immutable domain models and public verdict vocabulary."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .canonical import require_identifier, require_sha256, sha256_json, to_utc_iso


class RunOutcome(StrEnum):
    COMPLETE = "COMPLETE"
    INCONCLUSIVE = "INCONCLUSIVE"
    CANCELLED = "CANCELLED"
    INFRA_FAILED = "INFRA_FAILED"


class ReleaseVerdict(StrEnum):
    NOT_READY = "NOT_READY"
    CONDITIONALLY_READY = "CONDITIONALLY_READY"
    PRODUCTION_READY = "PRODUCTION_READY"


class RunState(StrEnum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    ACQUIRING_TARGET = "ACQUIRING_TARGET"
    DISCOVERING = "DISCOVERING"
    PLANNING = "PLANNING"
    PROVISIONING = "PROVISIONING"
    BUILDING = "BUILDING"
    STARTING_APPLICATION = "STARTING_APPLICATION"
    VERIFYING_READINESS = "VERIFYING_READINESS"
    EXECUTING_TESTS = "EXECUTING_TESTS"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    CLASSIFYING_FINDINGS = "CLASSIFYING_FINDINGS"
    CALCULATING_VERDICT = "CALCULATING_VERDICT"
    FINALIZING_REPORT = "FINALIZING_REPORT"
    REGISTERING_RESULT = "REGISTERING_RESULT"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"


class RedactionStatus(StrEnum):
    COMPLETE = "COMPLETE"
    NOT_REQUIRED = "NOT_REQUIRED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class FindingSeverity(StrEnum):
    BLOCKER = "BLOCKER"
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VerdictLifecycleEvent(StrEnum):
    REVOKED = "REVOKED"
    INVALIDATED = "INVALIDATED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class TargetIdentity:
    tenant_id: str
    target_type: str
    canonical_ref: str
    artifact_sha256: str
    source_commit: str | None = None
    dependency_sha256: str | None = None
    configuration_sha256: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, "tenant_id")
        require_identifier(self.target_type, "target_type")
        if not self.canonical_ref.strip():
            raise ValueError("canonical_ref is required")
        require_sha256(self.artifact_sha256, "artifact_sha256")
        if self.dependency_sha256 is not None:
            require_sha256(self.dependency_sha256, "dependency_sha256")
        if self.configuration_sha256 is not None:
            require_sha256(self.configuration_sha256, "configuration_sha256")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class EnvironmentIdentity:
    runner_image_sha256: str
    adapter_set_sha256: str
    test_plan_sha256: str
    policy_sha256: str
    harness_sha256: str
    prompt_set_sha256: str
    model_route_sha256: str
    os_runtime_sha256: str
    egress_policy_sha256: str

    def __post_init__(self) -> None:
        for field_name, value in asdict(self).items():
            require_sha256(value, field_name)

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.to_dict())


def declared_target_identity_digest(
    tenant_id: str,
    target_type: str,
    artifact_sha256: str | None,
    source_commit: str | None,
    reference: str,
) -> str:
    """Canonical digest of a DECLARED (pre-acquisition) target commitment.

    Shared by webhook intake (which computes the commitment), submit-time verification,
    and reconciliation (which re-verifies the commitment before binding a declared run
    to its acquired exact ``TargetIdentity``)."""
    return sha256_json(
        {
            "tenant_id": tenant_id,
            "target_type": target_type,
            "artifact_sha256": artifact_sha256,
            "source_commit": source_commit,
            "reference": reference,
        }
    )


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule_id: str
    passed: bool
    evidence_ids: tuple[str, ...]
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    run_id: str
    tenant_id: str
    valid: bool
    artifact_count: int
    valid_artifact_ids: frozenset[str]
    invalid_artifacts: tuple[dict[str, str], ...]
    merkle_root: str
    chain_tip: str


@dataclass(frozen=True, slots=True)
class VerdictDecision:
    schema_version: str
    run_id: str
    tenant_id: str
    run_outcome: RunOutcome
    release_verdict: ReleaseVerdict
    reasons: tuple[str, ...]
    target_identity_digest: str
    environment_identity_digest: str
    rule_manifest_id: str
    rule_manifest_digest: str
    evidence_merkle_root: str
    signing_key_id: str
    issued_at: datetime
    expires_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "run_outcome": self.run_outcome.value,
            "release_verdict": self.release_verdict.value,
            "reasons": list(self.reasons),
            "target_identity_digest": self.target_identity_digest,
            "environment_identity_digest": self.environment_identity_digest,
            "rule_manifest_id": self.rule_manifest_id,
            "rule_manifest_digest": self.rule_manifest_digest,
            "evidence_merkle_root": self.evidence_merkle_root,
            "signing_key_id": self.signing_key_id,
            "issued_at": to_utc_iso(self.issued_at),
            "expires_at": to_utc_iso(self.expires_at),
        }


@dataclass(frozen=True, slots=True)
class SignedVerdictEnvelope:
    payload: dict[str, Any]
    signature_b64: str
    key_id: str
    public_key_pem: str

    @property
    def payload_sha256(self) -> str:
        return sha256_json(self.payload)


@dataclass(frozen=True, slots=True)
class DeployGateDecision:
    allowed: bool
    release_verdict: ReleaseVerdict
    run_id: str | None
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "release_verdict": self.release_verdict.value,
            "run_id": self.run_id,
            "reasons": list(self.reasons),
        }
