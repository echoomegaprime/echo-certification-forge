from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_p4_hardening.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_p4_hardening_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_fixture(tmp_path: Path, *, mutate: str | None = None) -> Path:
    verifier = load_verifier()
    harness = tmp_path / "harness.py"
    core = tmp_path / "core.py"
    harness.write_text("# harness\n", encoding="utf-8")
    core.write_text("# core\n", encoding="utf-8")
    artifacts = {}
    targets = {
        "attestation": "/input/runner.attestation.json",
        "policy": "/input/runner.admission-policy.json",
        "sbom": "/input/runner.spdx.json",
    }
    for name, target in targets.items():
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        artifacts[name] = {
            "source": str(path),
            "target": target,
            "sha256": verifier.sha256_file(path),
            "read_only": True,
        }
    containment = {
        "read_only_root": True,
        "network_none": True,
        "all_capabilities_dropped": True,
        "no_new_privileges": True,
        "apparmor": True,
        "memory_limited": True,
        "pids_limited": True,
        "cpu_limited": True,
        "docker_socket_absent": True,
    }
    report = {
        "passed": True,
        "run_outcome": "COMPLETE",
        "release_verdict": "NOT_READY",
        "harness": {
            "path": str(harness),
            "sha256": verifier.sha256_file(harness),
            "core_path": str(core),
            "core_sha256": verifier.sha256_file(core),
            "service_health_deadline_seconds": 30,
        },
        "service_runtime": {
            "verifier": {
                "passed": True,
                "exit_code": 0,
                "timed_out": False,
                "oom_killed": False,
                "private_key_mounted": False,
                "execution_limits": {
                    "timeout_seconds": 60,
                    "memory": "256m",
                    "pids": 64,
                    "workspace_size": "8m",
                    "nofile": 256,
                },
                "containment": containment,
                "artifacts": artifacts,
                "output": {
                    "passed": True,
                    "private_key_loaded": False,
                    "sbom_valid": True,
                    "admission": {"allowed": True},
                },
            }
        },
        "checks": {
            "public_verifier_passed": True,
            "bounded_service_health_deadline_recorded": True,
        },
        "cleanup": {
            "unrelated_container_ids_preserved": True,
            "ephemeral_private_files_removed": True,
            "residual_private_paths": [],
        },
    }
    if mutate == "broad_mount":
        report["service_runtime"]["verifier"]["artifacts"]["workspace"] = {
            "source": str(tmp_path),
            "target": "/input",
            "sha256": "0" * 64,
            "read_only": True,
        }
    elif mutate == "deadline":
        report["harness"]["service_health_deadline_seconds"] = 12
    elif mutate == "artifact_hash":
        report["service_runtime"]["verifier"]["artifacts"]["sbom"]["sha256"] = "0" * 64
    elif mutate == "private_key":
        report["service_runtime"]["verifier"]["private_key_mounted"] = True
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_verify_report_accepts_exact_hardened_evidence(tmp_path: Path) -> None:
    verifier = load_verifier()
    result = verifier.verify_report(write_fixture(tmp_path))
    assert result["passed"] is True
    assert result["failures"] == []


def test_verify_report_rejects_broad_mount(tmp_path: Path) -> None:
    verifier = load_verifier()
    result = verifier.verify_report(write_fixture(tmp_path, mutate="broad_mount"))
    assert result["passed"] is False
    assert "public_verifier_artifact_set_invalid" in result["failures"]


def test_verify_report_rejects_deadline_regression(tmp_path: Path) -> None:
    verifier = load_verifier()
    result = verifier.verify_report(write_fixture(tmp_path, mutate="deadline"))
    assert result["passed"] is False
    assert "service_health_deadline_invalid" in result["failures"]


def test_verify_report_rejects_artifact_hash_drift(tmp_path: Path) -> None:
    verifier = load_verifier()
    result = verifier.verify_report(write_fixture(tmp_path, mutate="artifact_hash"))
    assert result["passed"] is False
    assert "public_verifier_artifact_invalid:sbom" in result["failures"]


def test_verify_report_rejects_private_key_mount(tmp_path: Path) -> None:
    verifier = load_verifier()
    result = verifier.verify_report(write_fixture(tmp_path, mutate="private_key"))
    assert result["passed"] is False
    assert "private_key_mounted" in result["failures"]
