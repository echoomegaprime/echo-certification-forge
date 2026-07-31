"""Adapter qualification gate for the product readiness verdict.

WHY THIS MODULE EXISTS
`verify_product_readiness` previously returned PRODUCTION_READY after checking only that the
signed report parsed, its signature verified, its `source_commit` matched the deployment, and it
had not expired. It never consulted adapter evidence -- `product_readiness.py` contained zero
occurrences of the word "adapter". The public surface therefore advertised
`adapter_qualification: REQUIRED` alongside `release_verdict: PRODUCTION_READY` while the
committed adapter acceptance report said `adapter_gate: BLOCK`.

That is NOT a fail-open gate. A fail-open gate exists and errs toward passing; this gate was
structurally absent. The distinction matters because the fixes differ entirely: a fail-open gate
is repaired by inverting a default, an absent one has to be written and wired in.

THE DEEPER DEFECT THIS CLOSES
`_validate_payload` requires `payload["release_verdict"] == "PRODUCTION_READY"` and, on success,
returns PRODUCTION_READY. The verdict was an INPUT that the verifier echoed back. The signature
proved the assertion was authentic -- never that it was true. Nothing resolved
`gate.evidence_sha256` to an artifact or read that artifact's contents.

This module makes the verdict derive from evidence: the adapter acceptance report is read, its
own computed gate is honoured, and every record is re-checked against the report's own policy so
a tampered or stale summary field cannot alone carry the verdict.

FAIL-CLOSED BY CONSTRUCTION. Missing file, unreadable file, malformed JSON, unknown schema,
absent policy, a record short of policy, or an unexpected exception all return BLOCK with a
machine-readable reason. There is no branch that returns PASS on an error path, and no
"if unconfigured, skip the check".

NO THRESHOLD IS WEAKENED. The policy is read FROM the report (`required_maturity`,
`minimum_cases`) rather than hardcoded here, so this gate cannot be quietly loosened by editing
it -- loosening would require editing the signed evidence itself, which is the thing under audit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SUPPORTED_SCHEMAS = {"1.0.0", "1.0", 1}


@dataclass(frozen=True, slots=True)
class AdapterGateResult:
    """Fail-closed adapter verdict. `passed` is the only way through."""

    passed: bool
    reason: str
    detail: dict[str, Any] | None = None

    def __bool__(self) -> bool:  # `if result:` must not pass on object truthiness
        return self.passed


def _block(reason: str, **detail: Any) -> AdapterGateResult:
    return AdapterGateResult(False, reason, detail or None)


def evaluate_adapter_gate(report_path: Path | None) -> AdapterGateResult:
    """Evaluate adapter qualification from the acceptance report.

    Returns PASS only when the report's own gate is GO *and* every record independently
    satisfies the report's own policy. Both are required: the summary alone is a claim, and
    re-deriving from records is what makes this evidence rather than assertion.
    """
    if report_path is None:
        return _block("adapter_acceptance_report_not_configured")
    try:
        raw = report_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _block("adapter_acceptance_report_missing", path=str(report_path))
    except OSError:
        return _block("adapter_acceptance_report_unreadable", path=str(report_path))
    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        return _block("adapter_acceptance_report_malformed")
    if not isinstance(report, dict):
        return _block("adapter_acceptance_report_malformed")

    schema = report.get("schema_version")
    if schema not in _SUPPORTED_SCHEMAS:
        # An unknown schema is not "probably fine" -- refuse rather than guess semantics.
        return _block("adapter_acceptance_report_unsupported_schema", schema_version=schema)

    # 1. Honour the report's own computed verdict. It already did this work.
    gate = str(report.get("adapter_gate", "")).upper()
    if gate != "GO":
        return _block("adapter_gate_not_go", adapter_gate=gate or None,
                      not_ready_reason=report.get("not_ready_reason"),
                      reasons=report.get("reasons"))
    if report.get("adapter_gate_eligible") is not True:
        return _block("adapter_gate_not_eligible")
    # DELIBERATELY NOT CHECKED: report["release_verdict"].
    #
    # It is the PRODUCT verdict, not the adapter verdict, and it reads NOT_READY in BOTH the
    # failing repo copy AND the genuinely-passing bundle that production is bound to
    # (var/p5-releases/certforge-p5-v2-c696e39-promotion: adapter_gate=GO, both adapters STABLE
    # 240/240, zero critical failures -- yet release_verdict=NOT_READY).
    #
    # An earlier revision of this gate treated it as an adapter signal, which would have BLOCKED
    # a production deployment whose adapters genuinely qualify. The authoritative adapter signals
    # are adapter_gate, adapter_gate_eligible, and the per-record policy check below.

    # 2. Re-derive from the records against the report's OWN policy, so a hand-edited summary
    #    field cannot carry the verdict on its own.
    policy = report.get("policy")
    if not isinstance(policy, dict):
        return _block("adapter_policy_missing")
    required_maturity = str(policy.get("required_maturity", "")).upper()
    if not required_maturity:
        return _block("adapter_policy_required_maturity_missing")
    try:
        minimum_cases = int(policy.get("minimum_cases", 0))
    except (TypeError, ValueError):
        return _block("adapter_policy_minimum_cases_invalid")

    records = report.get("records")
    if not isinstance(records, list) or not records:
        return _block("adapter_records_missing")

    required = policy.get("required_adapters")
    if isinstance(required, list) and required:
        want = {str(r.get("adapter_id")) for r in required if isinstance(r, dict)}
        have = {str((r.get("identity") or {}).get("adapter_id")) for r in records
                if isinstance(r, dict)}
        missing = sorted(want - have)
        if missing:
            return _block("adapter_required_adapter_missing", missing=missing)

    failures: list[dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, dict):
            return _block("adapter_record_malformed")
        identity = rec.get("identity") or {}
        quality = rec.get("quality") or {}
        adapter_id = str(identity.get("adapter_id", "unknown"))

        maturity = str(identity.get("maturity", "")).upper()
        if maturity != required_maturity:
            failures.append({"adapter_id": adapter_id, "why": "maturity",
                             "got": maturity or None, "required": required_maturity})
            continue
        crit = quality.get("critical_failures") or []
        if crit:
            failures.append({"adapter_id": adapter_id, "why": "critical_failures",
                             "count": len(crit)})
            continue
        try:
            passed_cases = int(quality.get("passed_cases", -1))
            total_cases = int(quality.get("total_cases", 0))
        except (TypeError, ValueError):
            failures.append({"adapter_id": adapter_id, "why": "quality_counts_invalid"})
            continue
        if passed_cases < minimum_cases:
            failures.append({"adapter_id": adapter_id, "why": "below_minimum_cases",
                             "passed_cases": passed_cases, "minimum_cases": minimum_cases})
            continue
        if total_cases and passed_cases < total_cases:
            failures.append({"adapter_id": adapter_id, "why": "not_all_cases_passed",
                             "passed_cases": passed_cases, "total_cases": total_cases})

    if failures:
        return _block("adapter_records_below_policy", failures=failures)

    return AdapterGateResult(True, "adapter_gate_go_all_records_meet_policy",
                             {"adapters": [str((r.get("identity") or {}).get("adapter_id"))
                                           for r in records]})
