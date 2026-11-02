"""Malformed resource profiles must stop before acquisition or process creation."""
from __future__ import annotations

import dataclasses
import json
import subprocess

import pytest

from echo_certification_forge import run_worker
from echo_certification_forge.runtime_identity import _sandbox_inputs, load_runtime_profile
from echo_certification_forge.sandbox import DockerSandbox, SandboxError
from echo_certification_forge.signing import Ed25519VerdictSigner


INVALID_RESOURCES = [
    ("cpus", 1), ("cpus", 1.0), ("cpus", True), ("cpus", None),
    ("cpus", "0"), ("cpus", "-1"), ("cpus", "nan"), ("cpus", "inf"),
    ("cpus", ""), ("timeout_s", "90"), ("timeout_s", True),
    ("timeout_s", None), ("timeout_s", 0), ("timeout_s", -1),
    ("timeout_s", float("nan")), ("timeout_s", float("inf")),
    ("timeout_s", 10 ** 400),
    ("memory", 512), ("memory", "0"), ("tmpfs_size", True),
    ("tmpfs_size", "-64m"), ("pids_limit", True), ("pids_limit", 1.0),
    ("pids_limit", 0),
]


@pytest.mark.parametrize("field,value", INVALID_RESOURCES)
def test_malformed_resource_is_not_measured_as_executable(field, value):
    sandbox = dataclasses.replace(DockerSandbox(), **{field: value})
    with pytest.raises(ValueError, match="runtime_resource_limit_invalid"):
        _sandbox_inputs(sandbox)


@pytest.mark.parametrize("field,value", INVALID_RESOURCES)
def test_direct_sandbox_rejects_malformed_resource_before_launch(field, value, tmp_path, monkeypatch):
    def forbidden_launch(*args, **kwargs):
        pytest.fail("malformed resource reached the external process boundary")

    monkeypatch.setattr(subprocess, "Popen", forbidden_launch)
    sandbox = dataclasses.replace(DockerSandbox(), **{field: value})
    with pytest.raises(SandboxError, match="resource limit invalid"):
        sandbox.run(["python", "journey.py"], tmp_path)


@pytest.mark.parametrize("schema", ["certforge.runtime.v1", "certforge.runtime.v2"])
@pytest.mark.parametrize("field,value", [("timeout_s", "90"), ("cpus", 1)])
def test_operator_profile_rejects_resources_with_nonexecutable_types(schema, field, value, tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"schema_version": schema, "sandbox": {field: value}}))
    with pytest.raises(ValueError, match="runtime_resource_limit_invalid"):
        load_runtime_profile(path)


@pytest.mark.parametrize("field,value", [("timeout_s", "90"), ("cpus", 1)])
def test_invalid_resources_stop_worker_before_acquisition(field, value, tmp_path, monkeypatch, store, manifest):
    def forbidden_acquisition(*args, **kwargs):
        pytest.fail("malformed resource acquired customer input")

    monkeypatch.setattr(run_worker, "acquire_target", forbidden_acquisition)
    result = run_worker.run(
        "invalid-resource", "resource-test", {"type": "local", "path": str(tmp_path)},
        store=store, manifest=manifest, signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset({"resource-test"}), journey=["python", "journey.py"],
        sandbox=dataclasses.replace(DockerSandbox(), **{field: value}),
    )
    assert result == {"run_id": "invalid-resource", "error": "runtime_identity_unavailable"}
    assert not (store.evidence_root / ".worker").exists()


@pytest.mark.parametrize("cpus,timeout", [("1.0", 90.0), ("0.5", 1), ("2", 0.25)])
def test_valid_resource_types_keep_actual_command_and_identity_aligned(cpus, timeout, tmp_path):
    sandbox = DockerSandbox(cpus=cpus, timeout_s=timeout)
    measured = _sandbox_inputs(sandbox)
    command = sandbox.build_command(["python", "journey.py"], tmp_path)
    assert command[command.index("--cpus") + 1] == cpus
    assert all(isinstance(part, str) for part in command)
    assert measured["cpus"] == cpus
    assert measured["timeout_s"] == timeout


class _InertProcess:
    """Model only the external launch/cleanup boundary; no child or container exists."""

    def __init__(self):
        self.returncode = 0
        self.events = []

    def terminate(self):
        self.events.append("terminate")

    def kill(self):
        self.events.append("kill")

    def wait(self, timeout):
        self.events.append("wait")
        if "kill" not in self.events:
            raise subprocess.TimeoutExpired("inert", timeout)
        return 0

    def communicate(self, timeout=None):
        self.events.append("communicate")
        return "bounded output", ""


def test_valid_timeout_terminates_and_reaps_owned_process(tmp_path, monkeypatch):
    from echo_certification_forge import sandbox as module

    process = _InertProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    clock = iter([0.0, 2.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    result = DockerSandbox(timeout_s=1).run(["python", "journey.py"], tmp_path)
    assert result.timed_out is True
    assert result.returncode == 124
    assert process.events == ["terminate", "wait", "kill", "wait", "communicate"]


def test_execution_guard_failure_still_terminates_and_reaps_owned_process(tmp_path, monkeypatch):
    process = _InertProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    def guard():
        raise RuntimeError("lease lost")

    with pytest.raises(RuntimeError, match="lease lost"):
        DockerSandbox(timeout_s=1).run(["python", "journey.py"], tmp_path, guard)
    assert process.events == ["terminate", "wait", "kill", "wait", "communicate"]
