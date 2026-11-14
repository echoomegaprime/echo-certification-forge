"""Synthetic report-contract tests; no vendor qualification or certification is claimed."""
from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_helpers():
    spec = importlib.util.spec_from_file_location(
        "p4_contract_fixture_helpers", ROOT / "tests/test_p4_master_report_contract.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def native_report():
    report = load_helpers().completed_report()
    report["completed_phase_gate"] = "P4"
    return report


def profile(report):
    return report["tools"]["clamav_database_profile"]["profile"]


@pytest.fixture
def clock(native_report):
    return datetime.fromtimestamp(profile(native_report)["databases"]["daily"]["build_epoch"] + 60, UTC)


def validate(report, clock):
    load_helpers().load_script("master_acceptance")._p4(report, now=clock)


def test_complete_synthetic_vendor_coverage_and_six_bound_roles_are_consumable(native_report, clock):
    validate(native_report, clock)


def test_old_main_and_bytecode_age_do_not_invalidate_current_daily(native_report, clock):
    for name in ("main", "bytecode"):
        profile(native_report)["databases"][name]["build_epoch"] = int(datetime(2000, 1, 1, tzinfo=UTC).timestamp())
    validate(native_report, clock)


def test_fixed_daily_age_and_future_boundaries_are_inclusive(native_report, clock):
    profile(native_report)["databases"]["daily"]["build_epoch"] = int((clock - timedelta(seconds=172800)).timestamp())
    profile(native_report)["databases"]["main"]["build_epoch"] = int((clock + timedelta(seconds=300)).timestamp())
    validate(native_report, clock)


@pytest.mark.parametrize("case", [
    "historical_profile_missing", "false_passed", "definition_check_missing", "definition_check_false",
    "vendor_failed", "vendor_partial", "vendor_duplicate", "vendor_exit_nonzero", "vendor_exit_boolean",
    "vendor_readwrite", "vendor_marker_missing", "vendor_unsigned", "vendor_log_digest_invalid",
    "cvd_detached_missing", "cld_invented_detached", "wrong_database_path", "wrong_sigtool_argv",
    "missing_fips", "untrusted_certs_override", "profile_manifest_invalid", "wrong_engine",
    "daily_stale", "main_future", "freshness_override", "false_file_size", "invalid_file_hash",
    "custom_definitions", "duplicate_archive_variant", "missing_cvd_sidecar", "missing_scan_role",
    "scan_failed", "scan_exit_nonzero", "scan_exit_boolean", "scan_wrong_engine", "scan_wrong_manifest",
    "scan_wrong_five_file_bytes", "scan_readwrite", "scan_unofficial_allowed", "scan_post_hash_unverified",
])
def test_incomplete_or_unbound_native_report_cannot_satisfy_master_gate(native_report, clock, case):
    report = native_report
    auth = report["tools"]["clamav_database_profile"]
    frozen = profile(report)
    scan = report["images"]["runner"]["malware_scan"]
    bound = scan["database_profile"]
    if case == "historical_profile_missing":
        report.pop("tools")
    elif case == "false_passed":
        report["passed"] = False
    elif case == "definition_check_missing":
        report["checks"].pop("current_official_definitions_authenticated")
    elif case == "definition_check_false":
        report["checks"]["definition_profile_bytes_bound"] = False
    elif case == "vendor_failed":
        auth["passed"] = False
    elif case == "vendor_partial":
        auth["commands"].pop()
    elif case == "vendor_duplicate":
        auth["commands"][-1] = dict(auth["commands"][0])
    elif case == "vendor_exit_nonzero":
        auth["commands"][0]["exit_code"] = 1
    elif case == "vendor_exit_boolean":
        auth["commands"][0]["exit_code"] = False
    elif case == "vendor_readwrite":
        auth["commands"][0]["readonly_mount_verified"] = False
    elif case == "vendor_marker_missing":
        auth["commands"][0]["sanitized_logs"] = "TARGET|Header parsed only"
    elif case == "vendor_unsigned":
        auth["commands"][0]["sanitized_logs"] += "\nTARGET|Verification: Unsigned container"
    elif case == "vendor_log_digest_invalid":
        auth["commands"][0]["logs_sha256"] = ""
    elif case == "cvd_detached_missing":
        auth["commands"] = [row for row in auth["commands"]
                            if not (row["database"] == "main" and row["kind"] == "detached")]
    elif case == "cld_invented_detached":
        auth["commands"].append({**auth["commands"][0], "database": "daily", "kind": "detached"})
    elif case == "wrong_database_path":
        auth["commands"][0]["path"] = "bytecode.cvd"
    elif case == "wrong_sigtool_argv":
        auth["commands"][0]["argv"][-1] = "--info=/tmp/main.cvd"
    elif case == "missing_fips":
        auth["commands"][0]["argv"].remove("--fips-limits")
    elif case == "untrusted_certs_override":
        auth["commands"][0]["argv"].append("--cvdcertsdir=/untrusted")
    elif case == "profile_manifest_invalid":
        frozen["manifest_sha256"] = "invalid"
    elif case == "wrong_engine":
        frozen["engine_reference"] = "clamav/clamav@sha256:" + "c" * 64
    elif case == "daily_stale":
        frozen["databases"]["daily"]["build_epoch"] = int(clock.timestamp()) - 172801
    elif case == "main_future":
        frozen["databases"]["main"]["build_epoch"] = int(clock.timestamp()) + 301
    elif case == "freshness_override":
        frozen["daily_max_age_seconds"] = 604800
    elif case == "false_file_size":
        frozen["files"]["main.cvd"]["size_bytes"] = False
    elif case == "invalid_file_hash":
        frozen["files"]["main.cvd"]["sha256"] = "unknown"
    elif case == "custom_definitions":
        frozen["files"]["local.gdb"] = dict(frozen["files"]["main.cvd"], path="local.gdb")
    elif case == "duplicate_archive_variant":
        frozen["files"]["daily.cvd"] = dict(frozen["files"]["daily.cld"], path="daily.cvd")
    elif case == "missing_cvd_sidecar":
        frozen["files"].pop("main-63.cvd.sign")
    elif case == "missing_scan_role":
        report["images"].pop("verifier")
    elif case == "scan_failed":
        scan["passed"] = False
    elif case == "scan_exit_nonzero":
        scan["exit_code"] = 2
    elif case == "scan_exit_boolean":
        scan["exit_code"] = False
    elif case == "scan_wrong_engine":
        scan["scanner_image"] = "clamav/clamav@sha256:" + "c" * 64
    elif case == "scan_wrong_manifest":
        bound["manifest_sha256"] = "c" * 64
    elif case == "scan_wrong_five_file_bytes":
        bound["files"]["main.cvd"]["sha256"] = "c" * 64
    elif case == "scan_readwrite":
        bound["readonly_mount_verified"] = False
    elif case == "scan_unofficial_allowed":
        bound["official_db_only"] = False
    elif case == "scan_post_hash_unverified":
        bound["pre_post_bytes_verified"] = False
    else:
        raise AssertionError(case)
    with pytest.raises(ValueError, match="P4"):
        validate(report, clock)


def test_report_owned_timestamp_cannot_replace_current_admission_clock(native_report):
    # A historic qualification time cannot make yesterday's stale snapshot current.
    frozen = profile(native_report)
    epoch = int(datetime.now(UTC).timestamp()) - 172801
    frozen["databases"]["daily"]["build_epoch"] = epoch
    native_report["tools"]["clamav_database_profile"]["qualified_at_utc"] = (
        datetime.fromtimestamp(epoch + 10, UTC).isoformat())
    with pytest.raises(ValueError, match="stale"):
        load_helpers().load_script("master_acceptance")._p4(native_report)


@pytest.mark.parametrize("qualification", ["missing", "invalid", "naive", "future"])
def test_qualification_timestamp_is_required_aware_and_bounded(native_report, clock, qualification):
    auth = native_report["tools"]["clamav_database_profile"]
    if qualification == "missing":
        auth.pop("qualified_at_utc")
    elif qualification == "invalid":
        auth["qualified_at_utc"] = "unknown"
    elif qualification == "naive":
        auth["qualified_at_utc"] = clock.replace(tzinfo=None).isoformat()
    else:
        auth["qualified_at_utc"] = (clock + timedelta(seconds=301)).isoformat()
    with pytest.raises(ValueError, match="qualification timestamp"):
        validate(native_report, clock)


@pytest.mark.parametrize("invalid_gate", ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "SDK", "CI",
                                         "P4_missing_time", "P4_future_time"])
def test_all_supplied_phase_inputs_are_checked_before_key_access_or_master(
    native_report, tmp_path, monkeypatch, invalid_gate
):
    # Synthetic admission inputs only. Real validators run; key and MASTER are sentinels.
    import json
    from types import SimpleNamespace

    consumer = load_helpers().load_script("master_acceptance")
    source = "a" * 40
    p4 = native_report
    inputs = {
        "P1": {"passed": True},
        "P2": {"passed": True, "run_outcome": "COMPLETE"},
        "P3": {"passed": True, "run_outcome": "COMPLETE"},
        "P4": p4,
        "P5": {"adapter_gate_eligible": True, "adapter_gate": "GO",
               "accepted_adapters": ["gs343", "r2d2"],
               "records": [{"identity": {"maturity": "STABLE"},
                            "quality": {"passed_cases": 240, "total_cases": 240, "critical_failures": []}}
                           for _ in range(2)]},
        "P6": {"passed": True, "checks_total": 12, "checks_passed": 12},
        "P7": {"passed": True, "scenarios": {"synthetic": {"passed": True}}},
        "SDK": {"capability_count": 61,
                "capabilities": {f"echo.cert.synthetic.{index}": {
                    "operation": "GET /synthetic", "input_schema": {}, "output_schema": {}}
                    for index in range(61)}},
        "CI": {"status": "completed", "conclusion": "success", "head_sha": source},
    }
    if invalid_gate in {"P1", "P2", "P3", "P6", "P7"}:
        inputs[invalid_gate]["passed"] = False
    elif invalid_gate == "P4":
        profile(p4)["databases"]["daily"]["build_epoch"] = int(datetime.now(UTC).timestamp()) - 172801
    elif invalid_gate == "P4_missing_time":
        p4["tools"]["clamav_database_profile"].pop("qualified_at_utc")
    elif invalid_gate == "P4_future_time":
        p4["tools"]["clamav_database_profile"]["qualified_at_utc"] = (
            datetime.now(UTC) + timedelta(hours=1)).isoformat()
    elif invalid_gate == "P5":
        inputs["P5"]["adapter_gate_eligible"] = False
    elif invalid_gate == "SDK":
        inputs["SDK"]["capability_count"] = 0
    else:
        inputs["CI"]["status"] = "queued"

    paths = {}
    for name, value in inputs.items():
        path = tmp_path / (name.lower() + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        paths[name.lower()] = path
    accessed = []

    def forbidden_key_read():
        accessed.append("private_key")
        raise AssertionError("private key must not be read before phase admission")

    def forbidden_master(**kwargs):
        accessed.append("MASTER")
        raise AssertionError("MASTER must not run before phase admission")

    args = SimpleNamespace(**paths, source_commit=source,
                           signing_key=SimpleNamespace(read_bytes=forbidden_key_read))
    monkeypatch.setattr(consumer, "parse_args", lambda: args)
    monkeypatch.setattr(consumer, "MasterAcceptanceRunner", forbidden_master)
    with pytest.raises(ValueError):
        consumer.main()
    assert accessed == []


@pytest.mark.parametrize("command_index", [0, 4])
def test_outdated_engine_warning_is_rejected_even_with_zero_exit_and_passed_marker(
    native_report, clock, command_index
):
    command = native_report["tools"]["clamav_database_profile"]["commands"][command_index]
    assert command["passed"] is True and command["exit_code"] == 0
    command["sanitized_logs"] += "\nTARGET|THIS VERSION OF THE CLAMAV ENGINE IS OUTDATED."
    with pytest.raises(ValueError, match="P4"):
        validate(native_report, clock)


def test_fresh_daily_cannot_be_claimed_as_qualified_years_before_it_existed(native_report, clock):
    auth = native_report["tools"]["clamav_database_profile"]
    assert clock.timestamp() - profile(native_report)["databases"]["daily"]["build_epoch"] == 60
    auth["qualified_at_utc"] = datetime(2000, 1, 1, tzinfo=UTC).isoformat()
    with pytest.raises(ValueError, match="predates"):
        validate(native_report, clock)
