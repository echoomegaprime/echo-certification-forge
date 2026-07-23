"""Verified transport boundary for P5 adapter execution bundles.

Adapter quality claims are accepted only after the existing runner response signature
has verified. The signed body is strict-schema, run/tenant/runner bound, and each
record carries a deterministic result hash over its identity, quality, and execution
node. This keeps adapter execution on the established narrow runner protocol.
"""
from __future__ import annotations

from typing import Any, Collection

from .adapters import (
    AdapterExecutionRecord,
    AdapterIdentity,
    AdapterMaturity,
    AdapterQualityReport,
)
from .canonical import require_identifier, require_sha256, sha256_json
from .runner import RunnerResponse, verify_runner_response


class AdapterBundleError(ValueError):
    """The signed adapter bundle is invalid or not bound to this certification run."""


def _record(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterBundleError(f"{field} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise AdapterBundleError(f"{field} schema mismatch: missing={missing}, extra={extra}")


def _parse_execution_record(raw_value: Any, index: int) -> AdapterExecutionRecord:
    field = f"records[{index}]"
    raw = _record(raw_value, field)
    _exact_keys(
        raw,
        {"identity", "observed_identity_digest", "quality", "execution_node", "result_sha256"},
        field,
    )

    identity_raw = _record(raw["identity"], f"{field}.identity")
    _exact_keys(
        identity_raw,
        {
            "adapter_id",
            "version",
            "artifact_sha256",
            "configuration_sha256",
            "runtime_sha256",
            "maturity",
            "provenance",
        },
        f"{field}.identity",
    )
    quality_raw = _record(raw["quality"], f"{field}.quality")
    _exact_keys(
        quality_raw,
        {
            "adapter_id",
            "passed_cases",
            "total_cases",
            "critical_failures",
            "suite_sha256",
            "evidence_ids",
        },
        f"{field}.quality",
    )

    critical_failures = quality_raw["critical_failures"]
    evidence_ids = quality_raw["evidence_ids"]
    if not isinstance(critical_failures, list) or not all(isinstance(item, str) for item in critical_failures):
        raise AdapterBundleError(f"{field}.quality.critical_failures must be a string array")
    if not isinstance(evidence_ids, list) or not all(isinstance(item, str) for item in evidence_ids):
        raise AdapterBundleError(f"{field}.quality.evidence_ids must be a string array")

    try:
        identity = AdapterIdentity(
            adapter_id=str(identity_raw["adapter_id"]),
            version=str(identity_raw["version"]),
            artifact_sha256=str(identity_raw["artifact_sha256"]),
            configuration_sha256=str(identity_raw["configuration_sha256"]),
            runtime_sha256=str(identity_raw["runtime_sha256"]),
            maturity=AdapterMaturity(str(identity_raw["maturity"])),
            provenance=str(identity_raw["provenance"]),
        )
        quality = AdapterQualityReport(
            adapter_id=str(quality_raw["adapter_id"]),
            passed_cases=int(quality_raw["passed_cases"]),
            total_cases=int(quality_raw["total_cases"]),
            critical_failures=tuple(critical_failures),
            suite_sha256=str(quality_raw["suite_sha256"]),
            evidence_ids=tuple(evidence_ids),
        )
        execution_node = str(raw["execution_node"])
        require_identifier(execution_node, "execution_node")
        observed_digest = require_sha256(str(raw["observed_identity_digest"]), "observed_identity_digest")
        result_digest = require_sha256(str(raw["result_sha256"]), "result_sha256")
    except (TypeError, ValueError) as exc:
        raise AdapterBundleError(f"{field} invalid: {exc}") from exc

    result_payload = {
        "identity": identity.to_dict(),
        "observed_identity_digest": observed_digest,
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
    if result_digest != sha256_json(result_payload):
        raise AdapterBundleError(f"{field}.result_sha256 mismatch")

    return AdapterExecutionRecord(
        identity=identity,
        observed_identity_digest=observed_digest,
        quality=quality,
        execution_node=execution_node,
        result_sha256=result_digest,
    )


def parse_verified_adapter_bundle(
    response: RunnerResponse,
    runner_public_key_pem: str,
    *,
    expected_run_id: str,
    expected_tenant_id: str,
    allowed_runner_ids: Collection[str] = ("anvil-adapter-runner",),
    max_records: int = 64,
) -> tuple[AdapterExecutionRecord, ...]:
    """Verify and parse a signed ANVIL adapter execution response.

    Every mismatch is a hard failure. No partially parsed records are returned.
    """
    require_identifier(expected_run_id, "expected_run_id")
    require_identifier(expected_tenant_id, "expected_tenant_id")
    allowed = frozenset(allowed_runner_ids)
    if not allowed:
        raise AdapterBundleError("allowed_runner_ids may not be empty")
    for runner_id in allowed:
        require_identifier(runner_id, "allowed runner_id")
    if max_records < 1 or max_records > 1024:
        raise AdapterBundleError("max_records must be between 1 and 1024")

    valid, reason = verify_runner_response(response, runner_public_key_pem)
    if not valid:
        raise AdapterBundleError(f"runner response rejected: {reason}")
    if response.status != "COMPLETED":
        raise AdapterBundleError(f"runner response is not complete: {response.status}")
    if response.run_id != expected_run_id or response.tenant_id != expected_tenant_id:
        raise AdapterBundleError("runner response run or tenant mismatch")
    if response.runner_id not in allowed:
        raise AdapterBundleError(f"runner is not approved: {response.runner_id}")

    body = _record(response.body, "body")
    _exact_keys(body, {"schema_version", "kind", "records"}, "body")
    if body["schema_version"] != "1.0.0":
        raise AdapterBundleError("unsupported adapter bundle schema_version")
    if body["kind"] != "adapter_execution_bundle":
        raise AdapterBundleError("unsupported adapter bundle kind")
    records_raw = body["records"]
    if not isinstance(records_raw, list):
        raise AdapterBundleError("body.records must be an array")
    if not records_raw:
        raise AdapterBundleError("body.records may not be empty")
    if len(records_raw) > max_records:
        raise AdapterBundleError("body.records exceeds max_records")

    return tuple(_parse_execution_record(item, index) for index, item in enumerate(records_raw))
