"""P4 must measure the executable package in every isolated role image."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from echo_certification_forge import runtime_identity

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/p4_hostile_acceptance.py"
IMAGE = "p4-fixture-runner:a"
IMAGE_ID = "sha256:" + "a" * 64
CONTAINMENT = (
    "read_only_root", "network_none", "all_capabilities_dropped", "no_new_privileges",
    "apparmor", "memory_limited", "pids_limited", "cpu_limited", "docker_socket_absent",
)


@pytest.fixture
def harness():
    spec = importlib.util.spec_from_file_location("p4_runtime_packaging_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def source(tmp_path):
    package = tmp_path / "source/src/echo_certification_forge"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b'"""Synthetic public package."""\n')
    (package / "executor.py").write_bytes(b"def execute(): return 1\n")
    (package / "runtime_identity.py").write_bytes(Path(runtime_identity.__file__).read_bytes())
    root = package.parents[1]
    (root / "images").mkdir()
    (root / "pyproject.toml").write_bytes(b"[project]\nname='synthetic-fixture'\nversion='0'\n")
    (root / "images/requirements.lock").write_bytes(b"synthetic-dependency==1.0\n")
    return root


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def payload(expected):
    return {"uid": 65532, "gid": 65532, **copy.deepcopy(expected)}


def result(expected):
    return {
        "container_id": "c" * 64,
        "image_id": IMAGE_ID,
        "configured_image": IMAGE,
        "exit_code": 0,
        "timed_out": False,
        "oom_killed": False,
        "cancelled": False,
        "logs": json.dumps(payload(expected)),
        "containment": {name: True for name in CONTAINMENT},
    }


def probe(harness, expected):
    return harness.basic_runtime_probe(
        image=IMAGE, expected_image_id=IMAGE_ID, role=harness.ImageRole.RUNNER,
        ownership_token="synthetic-owner", expected=expected,
    )


def test_expectation_uses_actual_executable_package_and_both_declarations(harness, source):
    expected = harness.runtime_packaging_expectation(source)
    assert expected == {
        "harness_sha256": runtime_identity._harness_digest(source),
        "declaration_sha256": {
            "pyproject.toml": digest(source / "pyproject.toml"),
            "images/requirements.lock": digest(source / "images/requirements.lock"),
        },
    }


@pytest.mark.parametrize("path", [
    "src/echo_certification_forge/executor.py", "pyproject.toml", "images/requirements.lock",
])
def test_expectation_changes_when_any_measured_input_changes(harness, source, path):
    original = harness.runtime_packaging_expectation(source)
    changed = source / path
    changed.write_bytes(changed.read_bytes() + b"# changed public bytes\n")
    current = harness.runtime_packaging_expectation(source)
    assert current["harness_sha256"] != original["harness_sha256"]
    if path.startswith("src/"):
        assert current["declaration_sha256"] == original["declaration_sha256"]
    else:
        assert current["declaration_sha256"][path] != original["declaration_sha256"][path]


def test_success_records_actual_measured_identity_and_preserves_original_limits(
        harness, source, monkeypatch):
    expected = harness.runtime_packaging_expectation(source)
    actual = result(expected)
    observed = {}

    def execute(**kwargs):
        observed.update(kwargs)
        return actual

    monkeypatch.setattr(harness, "execute_container", execute)
    returned = probe(harness, expected)
    assert returned is actual
    proof = returned["runtime_packaging"]
    assert proof["passed"] is True
    assert proof["image_id"] == IMAGE_ID
    assert proof["configured_image"] == IMAGE
    assert proof["container_id"] == actual["container_id"]
    assert proof["harness_sha256"] == proof["expected_harness_sha256"] == expected["harness_sha256"]
    assert proof["declaration_sha256"] == proof["expected_declaration_sha256"] == expected["declaration_sha256"]
    assert proof["uid"] == proof["gid"] == 65532
    assert proof["containment"] == {name: True for name in CONTAINMENT}
    assert proof["logs_sha256"] == hashlib.sha256(actual["logs"].encode()).hexdigest()
    assert observed["image"] == IMAGE and observed["role"] == "runner"
    assert observed["ownership_token"] == "synthetic-owner"
    assert observed["memory"] == "128m" and observed["pids"] == 32
    assert observed["timeout_seconds"] == 8
    assert observed["nofile"] == 64 and observed["workspace_size"] == "16m"
    assert observed["file_size_bytes"] == 1024 * 1024
    assert not observed.get("mounts") and not observed.get("environment")


@pytest.mark.parametrize("field,value", [
    ("exit_code", 1), ("exit_code", 137), ("exit_code", False), ("exit_code", "0"),
    ("exit_code", None), ("timed_out", True), ("oom_killed", True), ("cancelled", True),
    ("image_id", "sha256:" + "b" * 64), ("configured_image", "different-image:a"),
])
def test_failed_or_drifted_execution_cannot_supply_packaging_proof(
        harness, source, monkeypatch, field, value):
    expected = harness.runtime_packaging_expectation(source)
    actual = result(expected)
    actual[field] = value
    monkeypatch.setattr(harness, "execute_container", lambda **_: actual)
    with pytest.raises(RuntimeError):
        probe(harness, expected)
    assert "runtime_packaging" not in actual


@pytest.mark.parametrize("field", ["timed_out", "oom_killed", "cancelled", "image_id", "configured_image"])
def test_missing_execution_facts_fail_closed(harness, source, monkeypatch, field):
    expected = harness.runtime_packaging_expectation(source)
    actual = result(expected)
    del actual[field]
    monkeypatch.setattr(harness, "execute_container", lambda **_: actual)
    with pytest.raises(RuntimeError):
        probe(harness, expected)


@pytest.mark.parametrize("name", CONTAINMENT)
def test_every_original_containment_requirement_remains_mandatory(
        harness, source, monkeypatch, name):
    expected = harness.runtime_packaging_expectation(source)
    actual = result(expected)
    actual["containment"][name] = False
    monkeypatch.setattr(harness, "execute_container", lambda **_: actual)
    with pytest.raises(RuntimeError):
        probe(harness, expected)


@pytest.mark.parametrize("containment", [{}, {"read_only_root": True}, {name: 1 for name in CONTAINMENT}])
def test_missing_or_nonboolean_containment_cannot_vacuously_pass(
        harness, source, monkeypatch, containment):
    expected = harness.runtime_packaging_expectation(source)
    actual = result(expected)
    actual["containment"] = containment
    monkeypatch.setattr(harness, "execute_container", lambda **_: actual)
    with pytest.raises(RuntimeError):
        probe(harness, expected)


@pytest.mark.parametrize("mutation", [
    "missing_harness", "wrong_harness", "missing_declaration", "extra_declaration",
    "wrong_declaration", "uid_root", "gid_root", "string_uid", "string_gid",
])
def test_missing_or_wrong_measured_runtime_bytes_and_user_fail_closed(
        harness, source, monkeypatch, mutation):
    expected = harness.runtime_packaging_expectation(source)
    measured = payload(expected)
    if mutation == "missing_harness":
        del measured["harness_sha256"]
    elif mutation == "wrong_harness":
        measured["harness_sha256"] = "f" * 64
    elif mutation == "missing_declaration":
        del measured["declaration_sha256"]["pyproject.toml"]
    elif mutation == "extra_declaration":
        measured["declaration_sha256"]["unrelated"] = "f" * 64
    elif mutation == "wrong_declaration":
        measured["declaration_sha256"]["images/requirements.lock"] = "f" * 64
    else:
        measured[mutation.split("_")[-1] if mutation.startswith("string_") else mutation.split("_")[0]] = (
            "65532" if mutation.startswith("string_") else 0
        )
    actual = result(expected)
    actual["logs"] = json.dumps(measured)
    monkeypatch.setattr(harness, "execute_container", lambda **_: actual)
    with pytest.raises(RuntimeError):
        probe(harness, expected)


@pytest.mark.parametrize("change", [None, "missing_project", "missing_lock", "wrong_project", "wrong_lock", "wrong_source"])
def test_actual_probe_code_measures_installed_package_and_rejects_missing_or_changed_bytes(
        harness, source, tmp_path, monkeypatch, change):
    expected = harness.runtime_packaging_expectation(source)
    installed = tmp_path / "installed/echo_certification_forge"
    shutil.copytree(source / "src/echo_certification_forge", installed)
    data = installed / "runtime_data"
    data.mkdir()
    shutil.copyfile(source / "pyproject.toml", data / "pyproject.toml")
    shutil.copyfile(source / "images/requirements.lock", data / "requirements.lock")
    if change:
        target = (installed / "executor.py" if change == "wrong_source"
                  else data / ("pyproject.toml" if change.endswith("project") else "requirements.lock"))
        if change.startswith("missing_"):
            target.unlink()
        else:
            target.write_bytes(target.read_bytes() + b"# changed bytes\n")
    executed = []

    def execute(**kwargs):
        command = kwargs["command"]
        assert command[0] == "-c" and len(command) == 2
        output = io.StringIO()
        actual = result(expected)
        with monkeypatch.context() as scope:
            # Model installed layout while executing the genuine digest implementation.
            scope.setattr(runtime_identity, "_PACKAGE", installed)
            scope.setattr(runtime_identity, "__file__", str(installed / "runtime_identity.py"))
            scope.setattr(harness.os, "getuid", lambda: 65532, raising=False)
            scope.setattr(harness.os, "getgid", lambda: 65532, raising=False)
            try:
                with redirect_stdout(output):
                    exec(compile(command[1], "<actual P4 image probe>", "exec"), {"__name__": "__main__"})
            except (OSError, ValueError) as exc:
                actual["exit_code"] = 1
                output.write(type(exc).__name__ + ": " + str(exc))
        actual["logs"] = output.getvalue()
        executed.append(actual)
        return actual

    monkeypatch.setattr(harness, "execute_container", execute)
    if change is None:
        assert probe(harness, expected)["runtime_packaging"]["harness_sha256"] == expected["harness_sha256"]
    else:
        with pytest.raises(RuntimeError):
            probe(harness, expected)
    assert len(executed) == 1
    if change and change.startswith("missing_"):
        assert executed[0]["exit_code"] == 1
    else:
        measured = json.loads(executed[0]["logs"])
        if change is None:
            assert measured["harness_sha256"] == expected["harness_sha256"]
        else:
            assert measured["harness_sha256"] != expected["harness_sha256"]
