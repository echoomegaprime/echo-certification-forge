from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def completed_report() -> dict:
    # Synthetic contract fixture only: no real P4 execution or certification is claimed.
    epoch = int(datetime.now(UTC).timestamp())
    engine = "clamav/clamav@sha256:" + "a" * 64
    digest = "b" * 64
    databases = {}
    files = {}
    commands = []
    for name, extension, version, age in (
        ("main", "cvd", 63, 10 * 365 * 86400),
        ("daily", "cld", 28182, 60),
        ("bytecode", "cvd", 339, 365 * 86400),
    ):
        path = f"{name}.{extension}"
        databases[name] = {
            "path": path, "version": version, "signatures": 100,
            "required_functionality_level": 90, "build_epoch": epoch - age,
            "header_sha256": hashlib.sha256(("synthetic-header:" + name).encode()).hexdigest(),
        }
        names = [path]
        if extension == "cvd":
            names.append(f"{name}-{version}.cvd.sign")
        for filename in names:
            files[filename] = {
                "path": filename, "size_bytes": 512,
                "sha256": hashlib.sha256(("synthetic-file:" + filename).encode()).hexdigest(),
            }
        checks = [("container", ["--fips-limits", "--info=/var/lib/clamav/" + path], "Verification OK.")]
        if extension == "cvd":
            checks.append(("detached", ["--verify=/var/lib/clamav/" + path], "Successfully verified"))
        for kind, argv, log in checks:
            commands.append({
                "database": name, "path": path, "kind": kind, "argv": ["sigtool", *argv],
                "exit_code": 0, "logs_sha256": hashlib.sha256(log.encode()).hexdigest(),
                "sanitized_logs": "TARGET|" + log, "readonly_mount_verified": True, "passed": True,
            })
    profile = {
        "manifest_sha256": digest, "engine_reference": engine,
        "files": files, "databases": databases,
        "daily_max_age_seconds": 172800, "future_clock_skew_seconds": 300,
    }
    from echo_certification_forge.runtime_identity import _harness_digest

    expectation = {
        "harness_sha256": _harness_digest(ROOT),
        "declaration_sha256": {
            "pyproject.toml": hashlib.sha256((ROOT / "pyproject.toml").read_bytes()).hexdigest(),
            "images/requirements.lock": hashlib.sha256((ROOT / "images/requirements.lock").read_bytes()).hexdigest(),
        },
    }
    containment = {name: True for name in (
        "read_only_root", "network_none", "all_capabilities_dropped", "no_new_privileges",
        "apparmor", "memory_limited", "pids_limited", "cpu_limited", "docker_socket_absent",
    )}
    limits = {
        "timeout_seconds": 8.0, "memory": "128m", "pids": 32, "cpus": 0.25,
        "workspace_size": "16m", "file_size_bytes": 1024 * 1024, "nofile": 64,
    }
    images = {}
    for role in ("runner", "custody", "anchor", "signer", "worker", "verifier"):
        images[role] = {"malware_scan": {
            "passed": True, "exit_code": 0, "scanner_image": engine,
            "database_profile": {
                "manifest_sha256": digest, "files": {name: dict(row) for name, row in files.items()},
                "readonly_mount_verified": True, "official_db_only": True, "pre_post_bytes_verified": True,
            },
        }}
        reference = "synthetic-p4-" + role + ":a"
        image_id = "sha256:" + hashlib.sha256(("synthetic-image:" + role).encode()).hexdigest()
        images[role].update({
            "primary_reference": reference, "image_digest": image_id,
            "lockfile_sha256": expectation["declaration_sha256"]["images/requirements.lock"],
            "containment": dict(containment),
            "runtime_packaging": {
                "passed": True, "exit_code": 0, "timed_out": False,
                "oom_killed": False, "cancelled": False,
                "container_id": hashlib.sha256(("synthetic-container:" + role).encode()).hexdigest(),
                "image_id": image_id, "configured_image": reference,
                "uid": 65532, "gid": 65532,
                "harness_sha256": expectation["harness_sha256"],
                "declaration_sha256": dict(expectation["declaration_sha256"]),
                "expected_harness_sha256": expectation["harness_sha256"],
                "expected_declaration_sha256": dict(expectation["declaration_sha256"]),
                "containment": dict(containment), "execution_limits": dict(limits),
                "logs_sha256": hashlib.sha256(json.dumps({
                    "uid": 65532, "gid": 65532, **expectation,
                }, sort_keys=True).encode()).hexdigest(),
            },
        })
    return {
        "phase": "P4", "passed": True, "run_outcome": "COMPLETE",
        "release_verdict": "NOT_READY", "source_commit": "a" * 40,
        "checks": {
            "sealed_twelve_image_manifest_verified": True, "public_verifier_passed": True,
            "current_official_definitions_authenticated": True, "definition_profile_bytes_bound": True,
            "all_runtime_packaging_verified": True,
        },
        "tools": {"clamav_image": engine, "clamav_database_profile": {
            "passed": True, "profile": profile, "commands": commands,
            "qualified_at_utc": datetime.fromtimestamp(epoch, UTC).isoformat(),
        }},
        "images": images, "runtime_packaging_expectation": copy.deepcopy(expectation),
        "cleanup": {"unrelated_container_ids_preserved": True, "ephemeral_private_files_removed": True},
    }


def test_successful_producer_report_is_consumable_without_changing_master_gate(tmp_path: Path) -> None:
    producer = load_script("p4_hostile_acceptance")
    consumer = load_script("master_acceptance")
    report = completed_report()
    output = tmp_path / "p4.json"

    producer.write_acceptance_report(output, report)

    gate = consumer._gate("P4", output, consumer._p4)
    assert gate == {"state": "COMPLETE", "evidence_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    emitted = json.loads(output.read_text())
    assert emitted["source_commit"] == "a" * 40
    assert emitted["release_verdict"] == "NOT_READY"


@pytest.mark.parametrize("failure", ["checks", "empty_checks", "outcome", "passed", "containers", "private_files"])
def test_incomplete_producer_report_cannot_satisfy_master_gate(tmp_path: Path, failure: str) -> None:
    producer = load_script("p4_hostile_acceptance")
    consumer = load_script("master_acceptance")
    report = completed_report()
    # A stale marker must be removed if a later verification or cleanup fails.
    report["completed_phase_gate"] = "P4"
    if failure == "checks":
        report["checks"]["public_verifier_passed"] = False
    elif failure == "empty_checks":
        report["checks"] = {}
    elif failure == "outcome":
        report["run_outcome"] = "INFRA_FAILED"
    elif failure == "passed":
        report["passed"] = False
    elif failure == "containers":
        report["cleanup"]["unrelated_container_ids_preserved"] = False
    else:
        report["cleanup"]["ephemeral_private_files_removed"] = False
    output = tmp_path / "p4.json"

    producer.write_acceptance_report(output, report)

    with pytest.raises(ValueError, match="P4 gate is incomplete"):
        consumer._gate("P4", output, consumer._p4)
    assert "completed_phase_gate" not in json.loads(output.read_text())


def test_wrapper_failure_removes_previously_completed_marker(tmp_path: Path) -> None:
    producer = load_script("p4_hostile_acceptance")
    wrapper = load_script("p4_hostile_acceptance_exact")
    consumer = load_script("master_acceptance")
    output = tmp_path / "p4.json"
    producer.write_acceptance_report(output, completed_report())

    result = wrapper.enrich_report(output_path=output, harness=producer, capture={}, return_code=1)

    assert result["passed"] is False
    assert "completed_phase_gate" not in result
    with pytest.raises(ValueError, match="P4 gate is incomplete"):
        consumer._gate("P4", output, consumer._p4)


@pytest.mark.parametrize("scenario", ["success", "nonzero", "malformed", "interrupted"])
def test_exact_entrypoint_publishes_only_after_complete_enrichment(tmp_path: Path, monkeypatch, scenario: str) -> None:
    producer = load_script("p4_hostile_acceptance")
    wrapper = load_script("p4_hostile_acceptance_exact")
    consumer = load_script("master_acceptance")
    output = tmp_path / "p4.json"
    capture = {
        "result": {
            "exit_code": 0, "timed_out": False, "oom_killed": False,
            "containment": {"network_none": True},
            "logs": json.dumps({"passed": True, "private_key_loaded": False,
                                "sbom_valid": True, "admission": {"allowed": True}}),
        },
        "artifacts": {}, "execution_limits": {},
    }
    if scenario == "malformed":
        capture["result"] = None

    def core_main():
        producer.write_acceptance_report(output, completed_report())
        # Even a successful core result is pending while the wrapper is running.
        with pytest.raises(ValueError, match="P4 gate is incomplete"):
            consumer._gate("P4", output, consumer._p4)
        if scenario == "interrupted":
            raise RuntimeError("simulated interruption after core serialization")
        return 1 if scenario == "nonzero" else 0

    def capture_override(original, *, artifacts, capture: dict):
        capture.update(captured)
        return original

    captured = capture
    monkeypatch.setattr(producer, "main", core_main)
    monkeypatch.setattr(wrapper, "load_harness", lambda: producer)
    monkeypatch.setattr(wrapper, "parse_wrapper_paths", lambda argv: (tmp_path / "manifest.json", output))
    monkeypatch.setattr(wrapper, "resolve_runner_artifacts", lambda *args: {})
    monkeypatch.setattr(wrapper, "make_execute_container_override", capture_override)
    if scenario in {"malformed", "interrupted"}:
        with pytest.raises((AttributeError, RuntimeError)):
            wrapper.main([])
    else:
        assert wrapper.main([]) == (0 if scenario == "success" else 1)
    if scenario == "success":
        assert consumer._gate("P4", output, consumer._p4)["state"] == "COMPLETE"
    else:
        with pytest.raises(ValueError, match="P4 gate is incomplete"):
            consumer._gate("P4", output, consumer._p4)


def runtime_report() -> dict:
    report = completed_report()
    report["completed_phase_gate"] = "P4"
    return report


@pytest.mark.parametrize("missing", ["expectation", "check", "one_proof", "all_proofs", "role"])
def test_legacy_complete_markers_do_not_replace_all_six_runtime_packaging_proofs(missing):
    report = runtime_report()
    if missing == "expectation":
        report.pop("runtime_packaging_expectation")
    elif missing == "check":
        report["checks"].pop("all_runtime_packaging_verified")
    elif missing == "role":
        report["images"].pop("verifier")
    else:
        roles = ["runner"] if missing == "one_proof" else list(report["images"])
        for role in roles:
            report["images"][role].pop("runtime_packaging")
    with pytest.raises(ValueError, match="P4"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("field", ["harness_sha256", "declaration_sha256"])
def test_consistently_forged_source_expectation_is_rejected_even_when_all_roles_agree(field):
    report = runtime_report()
    expected = report["runtime_packaging_expectation"]
    if field == "harness_sha256":
        expected[field] = "f" * 64
        for image in report["images"].values():
            image["runtime_packaging"][field] = "f" * 64
            image["runtime_packaging"]["expected_harness_sha256"] = "f" * 64
    else:
        expected[field] = {name: "f" * 64 for name in expected[field]}
        for image in report["images"].values():
            image["lockfile_sha256"] = "f" * 64
            image["runtime_packaging"][field] = dict(expected[field])
            image["runtime_packaging"]["expected_declaration_sha256"] = dict(expected[field])
    with pytest.raises(ValueError, match="runtime packaging source expectation mismatch"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("field,value", [
    ("passed", False), ("passed", 1), ("exit_code", 1), ("exit_code", False), ("exit_code", "0"),
    ("timed_out", True), ("oom_killed", True), ("cancelled", True),
    ("uid", 0), ("gid", 0), ("uid", "65532"), ("gid", "65532"),
    ("container_id", "short-id"), ("image_id", "sha256:" + "f" * 64),
    ("configured_image", "unrelated-role:a"), ("harness_sha256", "f" * 64),
    ("expected_harness_sha256", "f" * 64), ("logs_sha256", ""),
])
def test_malformed_or_failed_runtime_proof_cannot_satisfy_owner_admission(field, value):
    report = runtime_report()
    report["images"]["runner"]["runtime_packaging"][field] = value
    with pytest.raises(ValueError, match="P4 runtime packaging"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("field", ["timed_out", "oom_killed", "cancelled", "execution_limits"])
def test_missing_runtime_execution_facts_fail_closed(field):
    report = runtime_report()
    report["images"]["runner"]["runtime_packaging"].pop(field)
    with pytest.raises(ValueError, match="P4 runtime packaging"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("field", ["declaration_sha256", "expected_declaration_sha256"])
@pytest.mark.parametrize("mutation", ["missing", "wrong", "extra"])
def test_every_role_must_bind_exactly_the_actual_two_source_declarations(field, mutation):
    report = runtime_report()
    declarations = report["images"]["runner"]["runtime_packaging"][field]
    if mutation == "missing":
        declarations.pop("pyproject.toml")
    elif mutation == "wrong":
        declarations["images/requirements.lock"] = "f" * 64
    else:
        declarations["unmeasured-extra"] = "f" * 64
    with pytest.raises(ValueError, match="runtime packaging measurement mismatch"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("case", ["reused_container", "swapped_role", "unbound_lockfile", "invalid_image", "empty_reference"])
def test_runtime_measurement_must_match_its_own_unique_container_image_and_lockfile(case):
    report = runtime_report()
    runner = report["images"]["runner"]
    other = report["images"]["worker"]["runtime_packaging"]
    if case == "reused_container":
        runner["runtime_packaging"]["container_id"] = other["container_id"]
    elif case == "swapped_role":
        runner["runtime_packaging"] = copy.deepcopy(other)
    elif case == "unbound_lockfile":
        runner["lockfile_sha256"] = "f" * 64
    elif case == "invalid_image":
        runner["image_digest"] = runner["runtime_packaging"]["image_id"] = "mutable-image:a"
    else:
        runner["primary_reference"] = runner["runtime_packaging"]["configured_image"] = ""
    with pytest.raises(ValueError, match="P4 runtime packaging"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("field,value", [
    ("timeout_seconds", 16.0), ("memory", "256m"), ("pids", 64), ("cpus", 0.5),
    ("workspace_size", "32m"), ("file_size_bytes", 2 * 1024 * 1024), ("nofile", 128),
    ("unknown_limit", True),
])
def test_all_original_baseline_resource_caps_remain_required_by_owner_admission(field, value):
    report = runtime_report()
    report["images"]["runner"]["runtime_packaging"]["execution_limits"][field] = value
    with pytest.raises(ValueError, match="runtime packaging execution limits mismatch"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("name", [
    "read_only_root", "network_none", "all_capabilities_dropped", "no_new_privileges",
    "apparmor", "memory_limited", "pids_limited", "cpu_limited", "docker_socket_absent",
])
def test_each_original_containment_check_is_required_even_when_both_records_agree(name):
    report = runtime_report()
    image = report["images"]["runner"]
    image["containment"][name] = False
    image["runtime_packaging"]["containment"][name] = False
    with pytest.raises(ValueError, match="runtime packaging containment mismatch"):
        load_script("master_acceptance")._p4(report)


@pytest.mark.parametrize("case", ["missing", "integer_true", "different_record"])
def test_containment_requires_complete_literal_booleans_and_matching_image_record(case):
    report = runtime_report()
    image = report["images"]["runner"]
    proof = image["runtime_packaging"]
    if case == "missing":
        proof["containment"].pop("network_none")
    elif case == "integer_true":
        proof["containment"] = {name: 1 for name in proof["containment"]}
        image["containment"] = dict(proof["containment"])
    else:
        image["containment"]["network_none"] = False
    with pytest.raises(ValueError, match="runtime packaging containment mismatch"):
        load_script("master_acceptance")._p4(report)
