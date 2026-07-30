"""Acceptance for the adapter qualification gate (P0 #26804, defect 3).

The ticket's acceptance criterion, verbatim:

    "A test that feeds EXPERIMENTAL/failing adapter records through the live verdict path and
     asserts NOT_READY. Negative control: force the records to STABLE and confirm the test flips
     to PRODUCTION_READY, proving the test actually exercises the gate."

Both directions are required. A test that only asserts BLOCK would pass against a gate that
blocks unconditionally -- which would be useless and would make the product unshippable. The
positive control is what proves the gate DISCRIMINATES rather than merely refuses.

THE REAL COMMITTED ARTIFACT IS USED AS THE FAILING FIXTURE. Not a synthetic mock: the actual
artifacts/p5-adapter-bundle-20260723/adapter-acceptance-report.json that the PHASE_LEDGER cites
while describing it as "gate GO / both STABLE / 240/240". If that file is ever corrected to
genuinely pass, `test_real_committed_artifact_is_blocked` fails loudly and demands re-reading --
which is the correct behaviour, not a nuisance.

NO THRESHOLD IS WEAKENED ANYWHERE IN HERE. The passing fixture is built by RAISING the evidence
(maturity -> STABLE, clearing critical failures, passing all cases), never by lowering policy.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from echo_certification_forge.adapter_gate import evaluate_adapter_gate

REAL_REPORT = (Path(__file__).resolve().parents[1]
               / "artifacts/p5-adapter-bundle-20260723/adapter-acceptance-report.json")


def _load_real() -> dict:
    return json.loads(REAL_REPORT.read_text(encoding="utf-8"))


def _make_passing(base: dict) -> dict:
    """Raise the EVIDENCE to passing. Never lower the policy."""
    d = deepcopy(base)
    d["adapter_gate"] = "GO"
    d["adapter_gate_eligible"] = True
    d["release_verdict"] = "READY"
    d.pop("not_ready_reason", None)
    required_maturity = d["policy"]["required_maturity"]
    for rec in d["records"]:
        rec["identity"]["maturity"] = required_maturity
        rec["quality"]["critical_failures"] = []
        total = int(rec["quality"].get("total_cases") or 0)
        if total:
            rec["quality"]["passed_cases"] = total
        else:
            rec["quality"]["passed_cases"] = int(d["policy"]["minimum_cases"])
    return d


def _write(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "adapter-acceptance-report.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# ─── POSITIVE CONTROL — the gate must let a genuinely qualified set through ──

def test_positive_control_stable_records_pass(tmp_path):
    """If this fails, the gate blocks everything and is worthless."""
    result = evaluate_adapter_gate(_write(tmp_path, _make_passing(_load_real())))
    assert result.passed, f"qualified adapters were blocked: {result.reason} {result.detail}"
    assert bool(result) is True


# ─── THE DEFECT — real committed evidence must BLOCK ────────────────────────

def test_real_committed_artifact_is_blocked():
    """The artifact PHASE_LEDGER cites as 'gate GO / both STABLE / 240/240'.

    It actually says BLOCK / EXPERIMENTAL / 7 / 1 / NOT_READY. This is the P0.
    """
    result = evaluate_adapter_gate(REAL_REPORT)
    assert not result.passed
    assert result.reason == "adapter_gate_not_go"
    assert bool(result) is False


def test_experimental_maturity_blocks_even_when_summary_says_go(tmp_path):
    """A hand-edited summary must not carry the verdict past failing records.

    This is the tampering case: someone flips adapter_gate to GO without fixing the adapters.
    Re-deriving from records is what catches it.
    """
    d = _make_passing(_load_real())
    d["records"][0]["identity"]["maturity"] = "EXPERIMENTAL"
    result = evaluate_adapter_gate(_write(tmp_path, d))
    assert not result.passed
    assert result.reason == "adapter_records_below_policy"
    assert result.detail["failures"][0]["why"] == "maturity"


def test_critical_failures_block(tmp_path):
    d = _make_passing(_load_real())
    d["records"][0]["quality"]["critical_failures"] = ["probe_failed:3"]
    result = evaluate_adapter_gate(_write(tmp_path, d))
    assert not result.passed
    assert result.detail["failures"][0]["why"] == "critical_failures"


def test_below_minimum_cases_blocks(tmp_path):
    d = _make_passing(_load_real())
    d["records"][0]["quality"]["total_cases"] = 0
    d["records"][0]["quality"]["passed_cases"] = int(d["policy"]["minimum_cases"]) - 1
    result = evaluate_adapter_gate(_write(tmp_path, d))
    assert not result.passed
    assert result.detail["failures"][0]["why"] == "below_minimum_cases"


def test_partial_pass_blocks(tmp_path):
    """7 of 11 is not a pass. This is exactly the shape of the real gs343 record."""
    d = _make_passing(_load_real())
    d["records"][0]["quality"]["total_cases"] = 11
    d["records"][0]["quality"]["passed_cases"] = 7
    result = evaluate_adapter_gate(_write(tmp_path, d))
    assert not result.passed
    assert result.detail["failures"][0]["why"] == "not_all_cases_passed"


def test_missing_required_adapter_blocks(tmp_path):
    d = _make_passing(_load_real())
    d["records"] = d["records"][:1]
    result = evaluate_adapter_gate(_write(tmp_path, d))
    assert not result.passed
    assert result.reason == "adapter_required_adapter_missing"


# ─── FAIL-CLOSED ON EVERY ERROR PATH ────────────────────────────────────────

def test_missing_file_blocks(tmp_path):
    assert not evaluate_adapter_gate(tmp_path / "nope.json").passed


def test_unconfigured_blocks():
    """No report configured must NOT mean 'skip the check'."""
    r = evaluate_adapter_gate(None)
    assert not r.passed and r.reason == "adapter_acceptance_report_not_configured"


def test_malformed_blocks(tmp_path):
    p = tmp_path / "adapter-acceptance-report.json"
    p.write_text("{not json", encoding="utf-8")
    assert evaluate_adapter_gate(p).reason == "adapter_acceptance_report_malformed"


def test_unknown_schema_blocks(tmp_path):
    d = _make_passing(_load_real())
    d["schema_version"] = "99.0.0"
    assert evaluate_adapter_gate(_write(tmp_path, d)).reason == \
        "adapter_acceptance_report_unsupported_schema"


def test_missing_policy_blocks(tmp_path):
    d = _make_passing(_load_real())
    del d["policy"]
    assert evaluate_adapter_gate(_write(tmp_path, d)).reason == "adapter_policy_missing"


@pytest.mark.parametrize("field,value", [
    ("adapter_gate", "BLOCK"),
    ("adapter_gate_eligible", False),
    ("release_verdict", "NOT_READY"),
])
def test_each_summary_field_is_load_bearing(tmp_path, field, value):
    """Break one field at a time from a KNOWN-PASSING baseline."""
    d = _make_passing(_load_real())
    d[field] = value
    assert not evaluate_adapter_gate(_write(tmp_path, d)).passed
