"""Build signed P5 adapter execution bundles from verified ANVIL evidence.

This module bridges Family 14B routing proof and local quality qualification into
the strict ``adapter_execution_bundle`` shape consumed by the certification
executor. It never trusts requested model labels alone: each adapter record must
come from a signed routing receipt that says which adapter was selected, whether
fallback was used, and which server/registry/base identities were active.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapter_transport import parse_verified_adapter_bundle
from .adapters import (
    AdapterAcceptancePolicy,
    AdapterExecutionRecord,
    AdapterIdentity,
    AdapterMaturity,
    AdapterQualityReport,
    adapter_set_digest,
    evaluate_adapter_acceptance,
)
from .canonical import (
    require_identifier,
    require_sha256,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from .p5_qualification import (
    QualificationEvidenceTrustPins,
    QualificationError,
    TrustedRoutingKey,
    verify_qualification_evidence,
)
from .family_r5 import R5Error, verify_full_r5_evidence
from .runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerResponse,
    create_transport_request,
)


class AdapterExecutionError(RuntimeError):
    """P5 adapter evidence is missing, malformed, or not eligible."""


@dataclass(frozen=True, slots=True)
class AdapterEvidenceSource:
    """One adapter's signed routing evidence and quality mode."""

    adapter_id: str
    target_model: str
    r5_evidence_directory: Path
    quality_mode: str
    trusted_routing_key: TrustedRoutingKey
    r5_run_id: str
    r5_run_nonce: str

    def __post_init__(self) -> None:
        require_identifier(self.adapter_id, "adapter_id")
        require_identifier(self.target_model, "target_model")
        require_identifier(self.quality_mode, "quality_mode")
        require_identifier(self.r5_run_id, "r5_run_id")
        if len(self.r5_run_nonce) < 16:
            raise ValueError("r5_run_nonce must contain at least 16 characters")


@dataclass(frozen=True, slots=True)
class AdapterBundleTrustBinding:
    registry_id: str
    runner_key_id: str
    policy_id: str
    policy_sha256: str
    qualification_trust_pins_sha256: str
    r5_trust_pins_sha256: str
    external_trust_pins_sha256: str

    def __post_init__(self) -> None:
        for field in ("registry_id", "policy_id"):
            require_identifier(str(getattr(self, field)), field)
        if not self.runner_key_id.startswith("ed25519:"):
            raise ValueError("runner_key_id must identify an Ed25519 key")
        for field in (
            "policy_sha256",
            "qualification_trust_pins_sha256",
            "r5_trust_pins_sha256",
            "external_trust_pins_sha256",
        ):
            object.__setattr__(
                self,
                field,
                require_sha256(str(getattr(self, field)), field),
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "registry_id": self.registry_id,
            "runner_key_id": self.runner_key_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "qualification_trust_pins_sha256": self.qualification_trust_pins_sha256,
            "r5_trust_pins_sha256": self.r5_trust_pins_sha256,
            "external_trust_pins_sha256": self.external_trust_pins_sha256,
        }


@dataclass(frozen=True, slots=True)
class SignedAdapterBundle:
    response: RunnerResponse
    runner_public_key_pem: str
    adapter_set_sha256: str
    trust_binding: AdapterBundleTrustBinding


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterExecutionError(f"unreadable JSON evidence: {path}") from exc
    if not isinstance(value, dict):
        raise AdapterExecutionError(f"JSON evidence must be an object: {path}")
    return value


def adapter_record_bundle_dict(record: AdapterExecutionRecord) -> dict[str, Any]:
    """Return the exact strict transport shape for one record."""
    quality = {
        "adapter_id": record.quality.adapter_id,
        "passed_cases": record.quality.passed_cases,
        "total_cases": record.quality.total_cases,
        "critical_failures": list(record.quality.critical_failures),
        "suite_sha256": record.quality.suite_sha256,
        "evidence_ids": list(record.quality.evidence_ids),
    }
    return {
        "identity": record.identity.to_dict(),
        "observed_identity_digest": record.observed_identity_digest,
        "quality": quality,
        "execution_node": record.execution_node,
        "result_sha256": record.result_sha256,
    }


def adapter_bundle_body(
    records: tuple[AdapterExecutionRecord, ...],
    trust_binding: AdapterBundleTrustBinding,
) -> dict[str, Any]:
    if not records:
        raise AdapterExecutionError("adapter bundle requires at least one record")
    return {
        "schema_version": "1.0.0",
        "kind": "adapter_execution_bundle",
        "trust_roots": trust_binding.to_dict(),
        "records": [adapter_record_bundle_dict(record) for record in records],
    }


def sign_adapter_bundle(
    records: tuple[AdapterExecutionRecord, ...],
    *,
    run_id: str,
    tenant_id: str,
    trust_binding: AdapterBundleTrustBinding,
    runner_identity: RunnerEphemeralIdentity | None = None,
    runner_id: str = "anvil-adapter-runner",
    issued_at: datetime | None = None,
) -> SignedAdapterBundle:
    """Sign records with a run-scoped runner key and return public verification material."""
    require_identifier(run_id, "run_id")
    require_identifier(tenant_id, "tenant_id")
    require_identifier(runner_id, "runner_id")
    issued_at = issued_at or utc_now()
    authority = ControlPlaneTransportAuthority.generate()
    runner = runner_identity or RunnerEphemeralIdentity.generate()
    if trust_binding.runner_key_id != runner.key_id:
        raise AdapterExecutionError(
            "bundle trust binding runner key does not match signing identity"
        )
    credential = authority.issue(
        credential_id=f"{run_id}-adapter-credential",
        run_id=run_id,
        tenant_id=tenant_id,
        runner_id=runner_id,
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=issued_at,
        ttl=timedelta(minutes=5),
    )
    request = create_transport_request(
        request_id=f"{run_id}-adapter-request",
        credential=credential,
        nonce=f"{run_id}-adapter-nonce-0000000000000000",
        command=RunnerCommand.TRANSITION,
        sequence=1,
        issued_at=issued_at,
        body={"action": "execute_adapters", "adapter_set_sha256": adapter_set_digest(records)},
    )
    response = runner.sign_response(
        response_id=f"{run_id}-adapter-response",
        request=request,
        status="COMPLETED",
        body=adapter_bundle_body(records, trust_binding),
        issued_at=issued_at,
    )
    return SignedAdapterBundle(
        response=response,
        runner_public_key_pem=runner.public_key_pem,
        adapter_set_sha256=adapter_set_digest(records),
        trust_binding=trust_binding,
    )


def load_adapter_runner_identity(path: Path) -> RunnerEphemeralIdentity:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise AdapterExecutionError(
            f"adapter runner signing key is unreadable: {type(exc).__name__}"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AdapterExecutionError("adapter runner signing key is not Ed25519")
    return RunnerEphemeralIdentity(key)


def default_p5_policy(records: tuple[AdapterExecutionRecord, ...]) -> AdapterAcceptancePolicy:
    if not records:
        raise AdapterExecutionError("cannot build adapter policy without records")
    return AdapterAcceptancePolicy(
        required_adapter_digests=tuple((record.identity.adapter_id, record.identity.identity_digest) for record in records),
        minimum_score=1.0,
        minimum_cases=min(record.quality.total_cases for record in records),
        required_maturity=AdapterMaturity.STABLE,
        required_execution_nodes=("ANVIL",),
    )


def r5_trust_pins_digest(
    sources: tuple[AdapterEvidenceSource, ...],
    deployment_identity: Mapping[str, Any],
) -> str:
    by_adapter = {
        source.adapter_id: {
            "routing_key": source.trusted_routing_key.to_dict(),
            "run_id": source.r5_run_id,
            "run_nonce_sha256": sha256_json(source.r5_run_nonce),
        }
        for source in sources
    }
    if set(by_adapter) != {"gs343", "r2d2"}:
        raise AdapterExecutionError(
            "external R5 trust pins must cover exactly gs343 and r2d2"
        )
    return sha256_json(
        {
            "routing_sources": dict(sorted(by_adapter.items())),
            "deployment_identity": dict(deployment_identity),
        }
    )


def external_trust_pins_digest(
    qualification_trust_pins: QualificationEvidenceTrustPins,
    sources: tuple[AdapterEvidenceSource, ...],
) -> str:
    return sha256_json(
        {
            "qualification_trust_pins_sha256": qualification_trust_pins.digest,
            "r5_trust_pins_sha256": r5_trust_pins_digest(
                sources,
                qualification_trust_pins.deployment_identity.to_dict(),
            ),
        }
    )


def build_acceptance_report(
    response: RunnerResponse,
    runner_public_key_pem: str,
    *,
    run_id: str,
    tenant_id: str,
    policy: AdapterAcceptancePolicy,
    expected_adapter_set_sha256: str,
    trust_binding: AdapterBundleTrustBinding,
) -> dict[str, Any]:
    records = parse_verified_adapter_bundle(
        response,
        runner_public_key_pem,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_trust_roots=trust_binding.to_dict(),
    )
    acceptance = evaluate_adapter_acceptance(records, policy, expected_adapter_set_sha256)
    return {
        "schema_version": "1.0.0",
        "generated_at_utc": to_utc_iso(utc_now()),
        "run_id": run_id,
        "tenant_id": tenant_id,
        "adapter_gate_eligible": acceptance.eligible,
        "adapter_gate": "GO" if acceptance.eligible else "BLOCK",
        "release_verdict": "NOT_READY",
        "not_ready_reason": "P5 adapter gate proof only; P6/P7 and hosted CI remain release blockers",
        "accepted_adapters": list(acceptance.accepted_adapters),
        "adapter_set_sha256": acceptance.adapter_set_sha256,
        "external_trust_pins_sha256": trust_binding.external_trust_pins_sha256,
        "trust_roots": trust_binding.to_dict(),
        "reasons": list(acceptance.reasons),
        "records": [adapter_record_bundle_dict(record) for record in records],
        "policy": policy_to_json(policy),
    }


def policy_to_json(policy: AdapterAcceptancePolicy) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "required_adapters": [
            {"adapter_id": adapter_id, "identity_digest": digest}
            for adapter_id, digest in policy.required_adapter_digests
        ],
        "minimum_score": policy.minimum_score,
        "minimum_cases": policy.minimum_cases,
        "required_maturity": policy.required_maturity.value,
        "required_execution_nodes": list(policy.required_execution_nodes),
    }


def build_records_from_evidence(
    sources: tuple[AdapterEvidenceSource, ...],
    *,
    qualification_report: Mapping[str, Any],
    qualification_trust_pins: QualificationEvidenceTrustPins,
    execution_node: str = "ANVIL",
) -> tuple[AdapterExecutionRecord, ...]:
    if not sources:
        raise AdapterExecutionError("at least one adapter evidence source is required")
    if (
        qualification_report.get("schema")
        != "echo.certification-forge.p5-qualification/v1"
    ):
        raise AdapterExecutionError(
            "legacy qualification reports are not eligible for bundle construction"
        )
    try:
        verified_qualification = verify_qualification_evidence(
            qualification_report,
            qualification_trust_pins,
        )
    except QualificationError as exc:
        raise AdapterExecutionError(
            f"candidate qualification evidence is invalid: {exc}"
        ) from exc
    require_identifier(execution_node, "execution_node")
    seen: set[str] = set()
    records: list[AdapterExecutionRecord] = []
    for source in sources:
        if source.adapter_id in seen:
            raise AdapterExecutionError(f"duplicate adapter source: {source.adapter_id}")
        seen.add(source.adapter_id)
        records.append(
            _record_from_source(
                source,
                qualification_report,
                qualification_trust_pins=qualification_trust_pins,
                verified_qualification=verified_qualification,
                execution_node=execution_node,
            )
        )
    return tuple(records)


def _record_from_source(
    source: AdapterEvidenceSource,
    qualification_report: Mapping[str, Any],
    *,
    qualification_trust_pins: QualificationEvidenceTrustPins,
    verified_qualification: Mapping[str, Any],
    execution_node: str,
) -> AdapterExecutionRecord:
    models = _object(qualification_report.get("models"), "models")
    other_adapter = "r2d2" if source.adapter_id == "gs343" else "gs343"
    other_models = _object(models.get(other_adapter), f"models.{other_adapter}")
    wrong_model = other_models.get("candidate")
    if not isinstance(wrong_model, str):
        raise AdapterExecutionError(
            f"qualification report lacks {other_adapter} candidate model"
        )
    target_digest = qualification_trust_pins.artifact_digests.by_adapter(
        source.adapter_id
    )["candidate"]
    wrong_digest = qualification_trust_pins.artifact_digests.by_adapter(
        other_adapter
    )["candidate"]
    try:
        full_r5 = verify_full_r5_evidence(
            source.r5_evidence_directory,
            trusted_public_key_pem=source.trusted_routing_key.public_key_pem,
            trusted_key_id=source.trusted_routing_key.key_id,
            target_model=source.target_model,
            target_adapter_digest=target_digest,
            wrong_model=wrong_model,
            wrong_adapter_digest=wrong_digest,
            deployment_identity=qualification_trust_pins.deployment_identity.to_dict(),
            evidence_run_id=source.r5_run_id,
            evidence_run_nonce=source.r5_run_nonce,
        )
    except (R5Error, ValueError) as exc:
        raise AdapterExecutionError(
            f"R5 full evidence rejected for {source.adapter_id}: {exc}"
        ) from exc
    receipt = _object(full_r5.get("target_receipt"), "target routing receipt")
    payload = _object(receipt.get("payload"), "routing receipt payload")

    selected_digest = require_sha256(str(payload.get("selected_adapter_digest")), "selected_adapter_digest")
    if selected_digest != target_digest:
        raise AdapterExecutionError(
            f"R5 artifact digest differs from external pin for {source.adapter_id}"
        )
    identity = AdapterIdentity(
        adapter_id=source.adapter_id,
        version=_identifier_or_default(payload.get("adapter_version"), "adapter_version", default="unknown"),
        artifact_sha256=selected_digest,
        configuration_sha256=sha256_json(
            {
                "registry_snapshot_digest": payload.get("registry_snapshot_digest"),
                "registry_revision": payload.get("registry_revision"),
                "registry_adapter_id": payload.get("registry_adapter_id"),
                "routing_mode": payload.get("routing_mode"),
            }
        ),
        runtime_sha256=sha256_json(
            {
                "server_build_digest": payload.get("server_build_digest"),
                "base_model_digest": payload.get("base_model_digest"),
                "base_model_revision": payload.get("base_model_revision"),
                "signature_key_id": payload.get("signature_key_id"),
            }
        ),
        maturity=_maturity(payload.get("maturity_state")),
        provenance=(
            f"anvil-family-r5:{source.target_model}:"
            f"{payload.get('registry_revision')}:{payload.get('signature_key_id')}"
        ),
    )
    quality = _quality_report(
        source.adapter_id,
        source.quality_mode,
        qualification_report,
        target_model=source.target_model,
        artifact_sha256=selected_digest,
        verified_qualification=verified_qualification,
        manifest_sha256=sha256_json(full_r5["manifest"]),
    )
    result_payload = {
        "identity": identity.to_dict(),
        "observed_identity_digest": identity.identity_digest,
        "quality": {
            "adapter_id": quality.adapter_id,
            "passed_cases": quality.passed_cases,
            "total_cases": quality.total_cases,
            "critical_failures": list(quality.critical_failures),
            "suite_sha256": quality.suite_sha256,
            "evidence_ids": list(quality.evidence_ids),
        },
        "execution_node": execution_node,
    }
    return AdapterExecutionRecord(
        identity=identity,
        observed_identity_digest=identity.identity_digest,
        quality=quality,
        execution_node=execution_node,
        result_sha256=sha256_json(result_payload),
    )


def _quality_report(
    adapter_id: str,
    mode_name: str,
    qualification_report: Mapping[str, Any],
    *,
    target_model: str,
    artifact_sha256: str,
    verified_qualification: Mapping[str, Any],
    manifest_sha256: str,
) -> AdapterQualityReport:
    del mode_name
    verified_evidence = verified_qualification
    models = _object(qualification_report.get("models"), "models")
    adapter_models = _object(models.get(adapter_id), f"models.{adapter_id}")
    if adapter_models.get("candidate") != target_model:
        raise AdapterExecutionError(
            f"candidate qualification model mismatch for {adapter_id}"
        )
    artifact_digests = _object(
        qualification_report.get("artifact_digests"), "artifact_digests"
    )
    adapter_digests = _object(
        artifact_digests.get(adapter_id), f"artifact_digests.{adapter_id}"
    )
    expected_artifact = require_sha256(
        str(adapter_digests.get("candidate")),
        f"{adapter_id} candidate artifact digest",
    )
    if expected_artifact != artifact_sha256:
        raise AdapterExecutionError(
            f"candidate qualification artifact digest mismatch for {adapter_id}"
        )
    qualifications = _object(verified_evidence.get("qualification"), "qualification")
    qualification = _object(
        qualifications.get(adapter_id), f"qualification.{adapter_id}"
    )
    candidate = _object(
        qualification.get("candidate"), f"qualification.{adapter_id}.candidate"
    )
    routing_identity = _object(
        qualification.get("routing_identity"),
        f"qualification.{adapter_id}.routing_identity",
    )
    promotion_threshold = _object(
        qualification.get("promotion_threshold"),
        f"qualification.{adapter_id}.promotion_threshold",
    )
    if routing_identity.get("candidate_digests") != [artifact_sha256]:
        raise AdapterExecutionError(
            f"candidate qualification routing digest mismatch for {adapter_id}"
        )
    if routing_identity.get("expected_candidate_digest") != [artifact_sha256]:
        raise AdapterExecutionError(
            f"candidate qualification expected digest mismatch for {adapter_id}"
        )
    if routing_identity.get("passed") is not True:
        raise AdapterExecutionError(
            f"candidate qualification routing identity failed for {adapter_id}"
        )
    if not isinstance(candidate.get("row_count"), int) or candidate["row_count"] <= 0:
        raise AdapterExecutionError(
            f"candidate qualification row count is invalid for {adapter_id}"
        )
    for field in ("hard_gates_passed",):
        if not isinstance(candidate.get(field), bool):
            raise AdapterExecutionError(
                f"candidate qualification {field} must be boolean for {adapter_id}"
            )
    if not isinstance(promotion_threshold.get("passed"), bool):
        raise AdapterExecutionError(
            f"candidate qualification threshold result must be boolean for {adapter_id}"
        )
    adapter_decision = qualification.get("promotion_decision")
    if adapter_decision not in {"PROMOTE", "BLOCK"}:
        raise AdapterExecutionError(
            f"candidate qualification adapter decision is invalid for {adapter_id}"
        )
    blockers = qualification.get("blockers")
    if not isinstance(blockers, list) or any(not isinstance(item, str) for item in blockers):
        raise AdapterExecutionError(
            f"candidate qualification blockers are invalid for {adapter_id}"
        )
    promoted = (
        adapter_decision == "PROMOTE"
        and candidate["hard_gates_passed"] is True
        and promotion_threshold["passed"] is True
        and not blockers
    )
    total = candidate["row_count"]
    return AdapterQualityReport(
        adapter_id=adapter_id,
        passed_cases=total if promoted else 0,
        total_cases=total,
        critical_failures=() if promoted else ("qualification_blocked",),
        suite_sha256=sha256_json(
            {
                "schema": qualification_report["schema"],
                "qualification_run_id": verified_evidence["qualification_run_id"],
                "evidence_manifest_sha256": verified_evidence["manifest_sha256"],
                "external_qualification_trust_pins_sha256": verified_evidence[
                    "external_trust_pins_sha256"
                ],
                "adapter": adapter_id,
                "target_model": target_model,
                "artifact_sha256": artifact_sha256,
                "candidate": candidate,
                "promotion_threshold": promotion_threshold,
                "routing_identity": routing_identity,
                "blockers": blockers,
                "eval": qualification_report.get("eval", {}).get(adapter_id),
                "score_ledger": qualification_report.get("score_ledger"),
                "response_receipts": qualification_report.get(
                    "response_receipts", {}
                ).get("by_adapter_and_role", {}).get(adapter_id),
                "r5_evidence_manifest_sha256": manifest_sha256,
            }
        ),
        evidence_ids=(
            f"{adapter_id}-r5-evidence",
            f"{adapter_id}-candidate-qualification",
        ),
    )


def write_adapter_execution_artifacts(
    output_directory: Path,
    *,
    signed_bundle: SignedAdapterBundle,
    acceptance_report: Mapping[str, Any],
    policy: AdapterAcceptancePolicy,
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "adapter-bundle-response.json").write_text(
        signed_bundle.response.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output_directory / "adapter-runner-public-key.pem").write_text(
        signed_bundle.runner_public_key_pem,
        encoding="ascii",
        newline="\n",
    )
    (output_directory / "adapter-policy.json").write_text(
        json.dumps(policy_to_json(policy), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output_directory / "adapter-acceptance-report.json").write_text(
        json.dumps(dict(acceptance_report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterExecutionError(f"{field} must be an object")
    return value


def _identifier_or_default(value: Any, field: str, *, default: str) -> str:
    raw = default if value in (None, "") else str(value)
    return require_identifier(raw, field)


def _maturity(value: Any) -> AdapterMaturity:
    raw = str(value or "").strip().upper()
    aliases = {
        "QUALIFIED": AdapterMaturity.STABLE,
        "PRODUCTION_READY": AdapterMaturity.STABLE,
        "CONFORMANCE_PASSED": AdapterMaturity.STABLE,
        "CONFORMANCE_PENDING": AdapterMaturity.EXPERIMENTAL,
        "BETA": AdapterMaturity.EXPERIMENTAL,
        "DISABLED": AdapterMaturity.DEGRADED,
    }
    if raw in aliases:
        return aliases[raw]
    try:
        return AdapterMaturity(raw)
    except ValueError:
        return AdapterMaturity.EXPERIMENTAL
