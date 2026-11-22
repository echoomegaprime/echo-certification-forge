from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "p4_hostile_acceptance_exact.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("p4_hostile_acceptance_exact_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def containment() -> dict[str, bool]:
    return {
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


def test_override_uses_only_three_exact_read_only_artifacts(tmp_path: Path) -> None:
    wrapper = load_wrapper()
    artifacts: dict[str, Path] = {}
    for name in ("attestation", "policy", "sbom"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        artifacts[name] = path
    observed: dict[str, object] = {}

    def original(**kwargs):
        observed.update(kwargs)
        return {
            "exit_code": 0,
            "timed_out": False,
            "oom_killed": False,
            "logs": '{"admission":{"allowed":true},"passed":true,"private_key_loaded":false,"sbom_valid":true}\n',
            "sanitized_logs": "TARGET|verified",
            "containment": containment(),
        }

    capture: dict[str, object] = {}
    override = wrapper.make_execute_container_override(
        original,
        artifacts=artifacts,
        capture=capture,
    )
    result = override(
        image="verifier@sha256:" + "1" * 64,
        role="verifier",
        case="public-verify",
        ownership_token="owner.test",
        entrypoint="python",
        command=["-m", "echo_certification_forge.verifier_cli"],
        mounts=[(tmp_path, "/input", True)],
    )

    assert result["exit_code"] == 0
    assert observed["mounts"] == [
        (artifacts["attestation"].resolve(), "/input/runner.attestation.json", True),
        (artifacts["policy"].resolve(), "/input/runner.admission-policy.json", True),
        (artifacts["sbom"].resolve(), "/input/runner.spdx.json", True),
    ]
    assert observed["timeout_seconds"] == 60
    assert observed["memory"] == "256m"
    assert observed["pids"] == 64
    assert observed["workspace_size"] == "8m"
    assert observed["nofile"] == 256
    assert capture["private_key_mounted"] is False
    assert all(item["read_only"] for item in capture["artifacts"].values())


def test_override_does_not_change_non_verifier_calls(tmp_path: Path) -> None:
    wrapper = load_wrapper()
    artifacts = {}
    for name in ("attestation", "policy", "sbom"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        artifacts[name] = path
    observed = {}

    def original(**kwargs):
        observed.update(kwargs)
        return {"ok": True}

    override = wrapper.make_execute_container_override(original, artifacts=artifacts, capture={})
    result = override(role="runner", case="baseline", mounts=[])
    assert result == {"ok": True}
    assert observed == {"role": "runner", "case": "baseline", "mounts": []}


def test_override_rejects_artifact_set_drift(tmp_path: Path) -> None:
    wrapper = load_wrapper()
    with pytest.raises(RuntimeError, match="artifact set mismatch"):
        wrapper.make_execute_container_override(
            lambda **kwargs: kwargs,
            artifacts={"attestation": tmp_path / "a.json"},
            capture={},
        )


def test_enrich_report_records_exact_verifier_evidence(tmp_path: Path, monkeypatch) -> None:
    wrapper = load_wrapper()
    harness_path = tmp_path / "p4_hostile_acceptance.py"
    harness_path.write_text("# core\n", encoding="utf-8")
    wrapper.LEGACY_HARNESS = harness_path
    wrapper.HERE = SCRIPT
    output_path = tmp_path / "report.json"
    output_path.write_text(
        json.dumps(
            {
                "passed": True,
                "run_outcome": "COMPLETE",
                "release_verdict": "NOT_READY",
                "service_runtime": {"verifier": {"passed": True}},
                "checks": {"existing": True},
            }
        ),
        encoding="utf-8",
    )
    artifacts = {}
    for name in ("attestation", "policy", "sbom"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        artifacts[name] = {
            "source": str(path),
            "target": f"/input/{name}.json",
            "sha256": wrapper.sha256_file(path),
            "read_only": True,
        }
    logs = '{"admission":{"allowed":true},"passed":true,"private_key_loaded":false,"sbom_valid":true}\n'
    capture = {
        "result": {
            "exit_code": 0,
            "timed_out": False,
            "oom_killed": False,
            "logs": logs,
            "sanitized_logs": "TARGET|verified",
            "containment": containment(),
        },
        "artifacts": artifacts,
        "execution_limits": {
            "timeout_seconds": 60,
            "memory": "256m",
            "pids": 64,
            "workspace_size": "8m",
            "nofile": 256,
        },
        "private_key_mounted": False,
    }
    harness = SimpleNamespace(parse_last_json=lambda value: json.loads(value.strip()))

    report = wrapper.enrich_report(
        output_path=output_path,
        harness=harness,
        capture=capture,
        return_code=0,
    )

    verifier = report["service_runtime"]["verifier"]
    assert verifier["passed"] is True
    assert verifier["private_key_mounted"] is False
    assert verifier["artifacts"] == artifacts
    assert verifier["execution_limits"]["timeout_seconds"] == 60
    assert report["checks"]["public_verifier_passed"] is True
    assert report["passed"] is True
    assert report["run_outcome"] == "COMPLETE"


def test_enrich_report_fails_closed_when_verifier_not_reached(tmp_path: Path) -> None:
    wrapper = load_wrapper()
    harness_path = tmp_path / "p4_hostile_acceptance.py"
    harness_path.write_text("# core\n", encoding="utf-8")
    wrapper.LEGACY_HARNESS = harness_path
    output_path = tmp_path / "report.json"
    output_path.write_text(
        json.dumps(
            {
                "passed": False,
                "run_outcome": "INFRA_FAILED",
                "release_verdict": "NOT_READY",
                "checks": {},
            }
        ),
        encoding="utf-8",
    )

    report = wrapper.enrich_report(
        output_path=output_path,
        harness=SimpleNamespace(parse_last_json=lambda value: {}),
        capture={},
        return_code=1,
    )

    assert report["checks"]["public_verifier_passed"] is False
    assert report["passed"] is False
    assert report["run_outcome"] == "INFRA_FAILED"
    assert report["release_verdict"] == "NOT_READY"
