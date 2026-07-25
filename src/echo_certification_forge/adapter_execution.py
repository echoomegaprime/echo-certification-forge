"""Build signed P5 adapter execution bundles from verified ANVIL evidence.

This module bridges Family 14B routing proof and local quality qualification into
the strict ``adapter_execution_bundle`` shape consumed by the certification
executor. It never trusts requested model labels alone: each adapter record must
come from a signed routing receipt that says which adapter was selected, whether
fallback was used, and which server/registry/base identities were active.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    canonical_json,
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from .runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerResponse,
    SignedRunCredential,
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

    def __post_init__(self) -> None:
        require_identifier(self.adapter_id, "adapter_id")
        require_identifier(self.target_model, "target_model")
        require_identifier(self.quality_mode, "quality_mode")


@dataclass(frozen=True, slots=True)
class SignedAdapterBundle:
    credential: SignedRunCredential
    response: RunnerResponse
    control_plane_public_key_pem: str
    runner_public_key_pem: str
    adapter_set_sha256: str


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


def adapter_bundle_body(records: tuple[AdapterExecutionRecord, ...]) -> dict[str, Any]:
    if not records:
        raise AdapterExecutionError("adapter bundle requires at least one record")
    return {
        "schema_version": "1.0.0",
        "kind": "adapter_execution_bundle",
        "records": [adapter_record_bundle_dict(record) for record in records],
    }


def sign_adapter_bundle(
    records: tuple[AdapterExecutionRecord, ...],
    *,
    run_id: str,
    tenant_id: str,
    runner_id: str = "anvil-adapter-runner",
) -> SignedAdapterBundle:
    """Sign records with a run-scoped runner key and return public verification material."""
    require_identifier(run_id, "run_id")
    require_identifier(tenant_id, "tenant_id")
    require_identifier(runner_id, "runner_id")
    issued_at = utc_now()
    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
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
        body=adapter_bundle_body(records),
        issued_at=issued_at,
    )
    return SignedAdapterBundle(
        credential=credential,
        response=response,
        control_plane_public_key_pem=authority.public_key_pem,
        runner_public_key_pem=runner.public_key_pem,
        adapter_set_sha256=adapter_set_digest(records),
    )


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


def build_acceptance_report(
    response: RunnerResponse,
    runner_public_key_pem: str,
    *,
    run_id: str,
    tenant_id: str,
    policy: AdapterAcceptancePolicy,
    expected_adapter_set_sha256: str,
) -> dict[str, Any]:
    records = parse_verified_adapter_bundle(
        response,
        runner_public_key_pem,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
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
    execution_node: str = "ANVIL",
) -> tuple[AdapterExecutionRecord, ...]:
    if not sources:
        raise AdapterExecutionError("at least one adapter evidence source is required")
    require_identifier(execution_node, "execution_node")
    seen: set[str] = set()
    records: list[AdapterExecutionRecord] = []
    for source in sources:
        if source.adapter_id in seen:
            raise AdapterExecutionError(f"duplicate adapter source: {source.adapter_id}")
        seen.add(source.adapter_id)
        records.append(_record_from_source(source, qualification_report, execution_node=execution_node))
    return tuple(records)


def _record_from_source(
    source: AdapterEvidenceSource,
    qualification_report: Mapping[str, Any],
    *,
    execution_node: str,
) -> AdapterExecutionRecord:
    r5_report = load_json(source.r5_evidence_directory / "r5-report.json")
    positive = load_json(source.r5_evidence_directory / "positive-target.json")
    manifest = load_json(source.r5_evidence_directory / "evidence-manifest.json")
    if r5_report.get("r5_gate") != "PASS" or r5_report.get("run_outcome") != "COMPLETE":
        raise AdapterExecutionError(f"R5 gate is not PASS for {source.adapter_id}")
    expected = _object(r5_report.get("expected_identity"), "expected_identity")
    if expected.get("target_model") != source.target_model:
        raise AdapterExecutionError(f"R5 target model mismatch for {source.adapter_id}")
    receipt = _verified_receipt(r5_report, positive, source.target_model)
    payload = _object(receipt.get("payload"), "routing receipt payload")

    selected_digest = require_sha256(str(payload.get("selected_adapter_digest")), "selected_adapter_digest")
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
        manifest_sha256=sha256_json(manifest),
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


def _verified_receipt(
    r5_report: Mapping[str, Any],
    positive_target: Mapping[str, Any],
    target_model: str,
) -> dict[str, Any]:
    bundle = _object(r5_report.get("forge_verification_bundle"), "forge_verification_bundle")
    public_key_pem = bundle.get("public_key_pem")
    if not isinstance(public_key_pem, str):
        raise AdapterExecutionError("R5 report lacks attested public key")
    body = _object(positive_target.get("body"), "positive-target body")
    receipt = _object(body.get("routing_receipt"), "routing_receipt")
    payload = _object(receipt.get("payload"), "routing receipt payload")
    signature_b64 = receipt.get("signature_b64")
    if not isinstance(signature_b64, str):
        raise AdapterExecutionError("routing receipt lacks signature_b64")
    key = _public_key(public_key_pem)
    expected_key_id = f"ed25519:{sha256_bytes(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))[:32]}"
    if receipt.get("key_id") != expected_key_id or bundle.get("attested_key_id") != expected_key_id:
        raise AdapterExecutionError("routing receipt key does not match attestation")
    try:
        key.verify(base64.b64decode(signature_b64, validate=True), canonical_json(payload).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AdapterExecutionError("routing receipt signature is invalid") from exc
    required = {
        "selected_adapter_id": target_model,
        "registry_adapter_id": target_model,
        "requested_model": target_model,
        "adapter_applied": True,
        "persona_applied": True,
        "fallback_used": False,
    }
    for field, expected in required.items():
        if payload.get(field) != expected:
            raise AdapterExecutionError(f"routing receipt {field} mismatch for {target_model}")
    require_sha256(str(payload.get("selected_adapter_digest")), "selected_adapter_digest")
    return receipt


def _quality_report(
    adapter_id: str,
    mode_name: str,
    qualification_report: Mapping[str, Any],
    *,
    manifest_sha256: str,
) -> AdapterQualityReport:
    qualifications = _object(qualification_report.get("qualification"), "qualification")
    mode_scores = _object(qualification_report.get("mode_scores"), "mode_scores")
    qualification = _object(qualifications.get(mode_name), f"qualification.{mode_name}")
    integration_verdict = qualification.get("integration_verdict")
    if integration_verdict not in {"GO", "NEEDS_RETRAIN_OR_ROUTING_PROOF"}:
        raise AdapterExecutionError(f"invalid integration verdict: {mode_name}")
    for gate_name in ("content_gate_passed", "routing_gate_passed"):
        if not isinstance(qualification.get(gate_name), bool):
            raise AdapterExecutionError(f"qualification.{mode_name}.{gate_name} must be boolean")
    score = _object(mode_scores.get(mode_name), f"mode_scores.{mode_name}")
    probes = score.get("probe_results")
    if not isinstance(probes, list) or not probes:
        raise AdapterExecutionError(f"mode_scores.{mode_name}.probe_results must be non-empty")
    passed = sum(1 for item in probes if isinstance(item, dict) and item.get("passed") is True)
    total = len(probes)
    critical_failures = tuple(
        f"probe_failed:{index}"
        for index, item in enumerate(probes)
        if not (isinstance(item, dict) and item.get("passed") is True)
    )
    return AdapterQualityReport(
        adapter_id=adapter_id,
        passed_cases=passed,
        total_cases=total,
        critical_failures=critical_failures,
        suite_sha256=sha256_json(
            {
                "mode": mode_name,
                "probes": probes,
                "qualification": qualification,
                "r5_evidence_manifest_sha256": manifest_sha256,
            }
        ),
        evidence_ids=(f"{adapter_id}-r5-evidence", f"{adapter_id}-{mode_name}-quality"),
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


def _public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise AdapterExecutionError("attested public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AdapterExecutionError("attested public key is not Ed25519")
    return key


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
