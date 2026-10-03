from __future__ import annotations

import hashlib
import importlib.util
import json
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
    # Contract fixture only: no real P4 execution or certification is claimed.
    return {
        "phase": "P4",
        "passed": True,
        "run_outcome": "COMPLETE",
        "release_verdict": "NOT_READY",
        "source_commit": "a" * 40,
        "checks": {"sealed_twelve_image_manifest_verified": True, "public_verifier_passed": True},
        "cleanup": {
            "unrelated_container_ids_preserved": True,
            "ephemeral_private_files_removed": True,
        },
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
