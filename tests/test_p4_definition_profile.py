"""Canonical profile integration tests use mocks; no Docker or vendor verdicts."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "p4_definition_profile_test_harness", ROOT / "scripts/p4_hostile_acceptance.py")
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)

ENGINE = "clamav/clamav@sha256:" + "a" * 64
MANIFEST_SHA = "b" * 64


@pytest.fixture(autouse=True)
def forbid_real_docker(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("integration unit test attempted an unmocked external operation")
    monkeypatch.setattr(HARNESS, "run", forbidden)
    monkeypatch.setattr(HARNESS, "container_ids", forbidden)
    monkeypatch.setattr(HARNESS, "create_container", forbidden)
    monkeypatch.setattr(HARNESS, "remove_exact", forbidden)


@pytest.fixture
def snapshot(tmp_path):
    directory = tmp_path / "qualified-synthetic-profile"
    directory.mkdir()
    return {
        "directory": directory, "manifest_sha256": MANIFEST_SHA,
        "engine_reference": ENGINE, "manifest_bytes": b"synthetic",
        "daily_max_age_seconds": 172800, "future_clock_skew_seconds": 300,
        "files": {name: {"path": name, "size_bytes": 1, "sha256": "c" * 64}
                  for name in ("main.cvd", "daily.cld", "bytecode.cvd",
                               "main-63.cvd.sign", "bytecode-339.cvd.sign")},
        "databases": {
            "main": {"path": "main.cvd", "version": 63},
            "daily": {"path": "daily.cld", "version": 28182},
            "bytecode": {"path": "bytecode.cvd", "version": 339},
        },
    }


class DockerFake:
    def __init__(self, monkeypatch, snapshot, *, status=0, logs=None,
                 mount_change=None, fail_action=None, validation_failure=None):
        self.snapshot = snapshot
        self.status = status
        self.logs = logs
        self.mount_change = mount_change
        self.fail_action = fail_action
        self.validation_failure = validation_failure
        self.created = []
        self.removed = []
        self.commands = []
        self.validations = []
        monkeypatch.setattr(HARNESS, "create_container", self.create)
        monkeypatch.setattr(HARNESS, "remove_exact", self.removed.append)
        monkeypatch.setattr(HARNESS, "run", self.run)
        monkeypatch.setattr(HARNESS, "validate_database_snapshot", self.validate)

    def validate(self, directory, digest, engine):
        self.validations.append((directory, digest, engine))
        if self.validation_failure == len(self.validations):
            raise ValueError("synthetic profile drift")
        return self.snapshot

    def create(self, **kwargs):
        self.created.append(kwargs)
        return f"owned-unit-{len(self.created)}"

    def run(self, command, **kwargs):
        self.commands.append((command, kwargs))
        assert command[0] == "docker"
        action = command[1]
        if action == self.fail_action:
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 1))
        number = int(command[-1].rsplit("-", 1)[-1]) - 1
        create = self.created[number]
        if action == "inspect":
            mounts = [{"Type": "bind", "Destination": "/var/lib/clamav", "RW": False,
                       "Source": str(self.snapshot["directory"].resolve())}]
            if self.mount_change:
                mounts = self.mount_change(copy.deepcopy(mounts))
            output = json.dumps([{"Mounts": mounts}])
        elif action == "start":
            output = ""
        elif action == "wait":
            output = str(self.status)
        elif action == "logs":
            output = self.logs
            if output is None:
                output = ("Successfully verified vendor signature" if "-detached" in create["case"]
                          else "Verification OK.")
        else:
            raise AssertionError(f"unexpected Docker action {action}")
        return subprocess.CompletedProcess(command, 0, output, "")


def test_vendor_authentication_uses_all_three_actual_databases_and_exact_offline_commands(
        snapshot, monkeypatch):
    docker = DockerFake(monkeypatch, snapshot)
    result = HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
    assert result["passed"] is True
    qualified = HARNESS.parse_utc_iso(result["qualified_at_utc"])
    assert qualified.utcoffset().total_seconds() == 0
    assert len(docker.created) == len(docker.removed) == 5
    assert len(docker.validations) == 2
    assert Counter(item["database"] for item in result["commands"]) == {
        "main": 2, "daily": 1, "bytecode": 2}
    actual = [item["argv"] for item in result["commands"]]
    assert ["sigtool", "--verify=/var/lib/clamav/main.cvd"] in actual
    assert ["sigtool", "--verify=/var/lib/clamav/bytecode.cvd"] in actual
    assert ["sigtool", "--fips-limits", "--info=/var/lib/clamav/daily.cld"] in actual
    assert not any("--verify=/var/lib/clamav/daily.cld" in command for command in actual)
    for created in docker.created:
        assert created["image"] == ENGINE
        assert created["entrypoint"] == "sigtool"
        assert created["role"] == "scanner"
        assert created["ownership_token"] == "owner.test"
        assert created["mounts"] == [(snapshot["directory"], "/var/lib/clamav", True)]
        assert (created["memory"], created["pids"], created["workspace_size"], created["nofile"]) == (
            "2g", 64, "8m", 256)
    for command in result["commands"]:
        assert command["exit_code"] == 0
        assert command["readonly_mount_verified"] is True
        assert command["passed"] is True
        assert len(command["logs_sha256"]) == 64
    assert result["profile"]["manifest_sha256"] == MANIFEST_SHA
    assert "directory" not in result["profile"]


def test_authentication_rebinds_the_validated_snapshot_instead_of_caller_omissions(
        snapshot, monkeypatch):
    docker = DockerFake(monkeypatch, snapshot)
    caller = {**snapshot, "databases": {}, "files": {}}
    result = HARNESS.verify_clamav_database(ENGINE, caller, "owner.test")
    assert result["passed"] is True
    assert len(docker.created) == 5
    assert result["profile"]["files"] == snapshot["files"]


@pytest.mark.parametrize(("status", "logs"), [
    (1, "Successfully verified vendor signature"),
    (0, "no authentication success marker"),
    (0, "Successfully verified vendor signature; UNSIGNED database"),
    (0, "Successfully verified vendor signature\nThis version of the ClamAV engine is outdated"),
])
def test_vendor_authentication_fails_closed_on_tool_or_authentication_warning(
        snapshot, monkeypatch, status, logs):
    docker = DockerFake(monkeypatch, snapshot, status=status, logs=logs)
    result = HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
    assert result["passed"] is False
    assert result["commands"][-1]["passed"] is False
    assert docker.removed == ["owned-unit-1"]


def test_container_info_requires_its_own_verification_marker(snapshot, monkeypatch):
    docker = DockerFake(monkeypatch, snapshot, logs="Successfully verified vendor signature")
    result = HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
    assert result["passed"] is False
    assert len(result["commands"]) == 2
    assert result["commands"][-1]["kind"] == "container"
    assert docker.removed == ["owned-unit-1", "owned-unit-2"]


def _writable(mounts):
    mounts[0]["RW"] = True
    return mounts


def _wrong_source(mounts):
    mounts[0]["Source"] += "-different"
    return mounts


def _volume(mounts):
    mounts[0]["Type"] = "volume"
    return mounts


@pytest.mark.parametrize("mount_change", [
    _writable, _wrong_source, _volume, lambda mounts: [],
    lambda mounts: [*mounts, copy.deepcopy(mounts[0])],
])
@pytest.mark.parametrize("operation", ["authenticate", "scan"])
def test_actual_inspect_mount_must_match_the_frozen_readonly_bind(
        snapshot, tmp_path, monkeypatch, mount_change, operation):
    docker = DockerFake(monkeypatch, snapshot, mount_change=mount_change)
    with pytest.raises(RuntimeError, match="read-only"):
        if operation == "authenticate":
            HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
        else:
            HARNESS.clamav_scan(ENGINE, tmp_path / "synthetic-image.tar",
                               HARNESS.ImageRole.RUNNER, "owner.test", database_profile=snapshot)
    assert docker.removed == ["owned-unit-1"]
    assert not any(command[0][1] == "start" for command in docker.commands)


@pytest.mark.parametrize("operation", ["authenticate", "scan"])
@pytest.mark.parametrize("action", ["inspect", "start", "wait", "logs"])
def test_owned_verification_and_scan_containers_are_cleaned_after_tool_exception(
        snapshot, tmp_path, monkeypatch, operation, action):
    docker = DockerFake(monkeypatch, snapshot, fail_action=action)
    with pytest.raises(subprocess.TimeoutExpired):
        if operation == "authenticate":
            HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
        else:
            HARNESS.clamav_scan(ENGINE, tmp_path / "synthetic-image.tar",
                               HARNESS.ImageRole.RUNNER, "owner.test", database_profile=snapshot)
    assert docker.removed == ["owned-unit-1"]


@pytest.mark.parametrize("operation", ["authenticate", "scan"])
def test_profile_is_revalidated_before_any_container_creation(
        snapshot, tmp_path, monkeypatch, operation):
    docker = DockerFake(monkeypatch, snapshot, validation_failure=1)
    with pytest.raises(ValueError, match="profile drift"):
        if operation == "authenticate":
            HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
        else:
            HARNESS.clamav_scan(ENGINE, tmp_path / "synthetic-image.tar",
                               HARNESS.ImageRole.RUNNER, "owner.test", database_profile=snapshot)
    assert not docker.created
    assert not docker.removed


@pytest.mark.parametrize("operation", ["authenticate", "scan"])
def test_post_operation_profile_drift_rejects_result_and_cleans_owned_containers(
        snapshot, tmp_path, monkeypatch, operation):
    docker = DockerFake(monkeypatch, snapshot, validation_failure=2)
    with pytest.raises(ValueError, match="profile drift"):
        if operation == "authenticate":
            HARNESS.verify_clamav_database(ENGINE, snapshot, "owner.test")
        else:
            HARNESS.clamav_scan(ENGINE, tmp_path / "synthetic-image.tar",
                               HARNESS.ImageRole.RUNNER, "owner.test", database_profile=snapshot)
    assert len(docker.created) == len(docker.removed) == (5 if operation == "authenticate" else 1)


def test_scan_uses_validated_profile_official_only_and_unchanged_resource_limits(
        snapshot, tmp_path, monkeypatch):
    docker = DockerFake(monkeypatch, snapshot, logs="clean image")
    caller = {**snapshot, "files": {}}
    tar_path = tmp_path / "synthetic-image.tar"
    result = HARNESS.clamav_scan(ENGINE, tar_path, HARNESS.ImageRole.RUNNER,
                                 "owner.test", database_profile=caller)
    assert result["passed"] is True
    assert result["database_missing"] is False
    created = docker.created[0]
    assert created["command"] == ["--infected", "--no-summary", "--official-db-only=yes",
                                   "--database=/var/lib/clamav", "/scan/image.tar"]
    assert "--fips-limits" not in created["command"]
    assert created["entrypoint"] == "clamscan"
    assert created["mounts"] == [(tar_path, "/scan/image.tar", True),
                                  (snapshot["directory"], "/var/lib/clamav", True)]
    assert (created["memory"], created["pids"], created["workspace_size"],
            created["file_size_bytes"], created["nofile"]) == ("2g", 128, "8m", 1024 ** 3, 256)
    assert len(docker.validations) == 2
    assert result["database_profile"] == {
        "manifest_sha256": MANIFEST_SHA, "files": snapshot["files"],
        "readonly_mount_verified": True, "official_db_only": True,
        "pre_post_bytes_verified": True}
    assert docker.removed == ["owned-unit-1"]
    assert result["logs_sha256"] == hashlib.sha256(b"clean image").hexdigest()


@pytest.mark.parametrize(("status", "logs"), [
    (1, "malware identified"), (2, "scanner error"),
    (0, "No supported database files found"), (0, "LibClamAV Error: malformed database"),
    (0, "This version of the ClamAV engine is outdated"),
])
def test_scan_rejects_nonzero_missing_or_incompatible_engine_even_when_exit_zero(
        snapshot, tmp_path, monkeypatch, status, logs):
    docker = DockerFake(monkeypatch, snapshot, status=status, logs=logs)
    result = HARNESS.clamav_scan(ENGINE, tmp_path / "synthetic-image.tar",
                                HARNESS.ImageRole.RUNNER, "owner.test", database_profile=snapshot)
    assert result["passed"] is False
    assert docker.removed == ["owned-unit-1"]


def _argv(tmp_path, workspace, definitions, output):
    return ["p4_hostile_acceptance.py",
            "--images", str(tmp_path / "images.json"),
            "--sealed-manifest", str(tmp_path / "sealed.json"),
            "--base-digest", "sha256:" + "c" * 64,
            "--source-commit", "d" * 40,
            "--trivy", str(tmp_path / "trivy"),
            "--cosign", str(tmp_path / "cosign"),
            "--clamav-image", ENGINE,
            "--clamav-db-dir", str(definitions),
            "--clamav-db-manifest-sha256", MANIFEST_SHA,
            "--workspace", str(workspace), "--output", str(output)]


@pytest.mark.parametrize("relation", ["equal", "definitions-inside-workspace", "workspace-inside-definitions"])
def test_cli_rejects_both_ancestor_relations_before_modifying_either_input(
        tmp_path, monkeypatch, relation):
    if relation == "equal":
        workspace = definitions = tmp_path / "shared"
    elif relation == "definitions-inside-workspace":
        workspace = tmp_path / "workspace"
        definitions = workspace / "definitions"
    else:
        definitions = tmp_path / "definitions"
        workspace = definitions / "workspace"
    definitions.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    definition_marker = definitions / "keep-definition"
    workspace_marker = workspace / "keep-attempt"
    definition_marker.write_bytes(b"immutable-input")
    workspace_marker.write_bytes(b"earlier-attempt")
    output = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, workspace, definitions, output))
    with pytest.raises(RuntimeError, match="outside the disposable workspace"):
        HARNESS.main()
    assert definition_marker.read_bytes() == b"immutable-input"
    assert workspace_marker.read_bytes() == b"earlier-attempt"
    assert not output.exists()


@pytest.mark.parametrize("same_path", [False, True])
def test_cli_rejects_output_inside_or_equal_to_definition_input_before_workspace_creation(
        tmp_path, monkeypatch, same_path):
    definitions = tmp_path / "definitions"
    definitions.mkdir()
    marker = definitions / "keep"
    marker.write_bytes(b"immutable-input")
    workspace = tmp_path / "fresh-workspace"
    output = definitions if same_path else definitions / "report.json"
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, workspace, definitions, output))
    with pytest.raises(RuntimeError, match="must not contain acceptance output"):
        HARNESS.main()
    assert marker.read_bytes() == b"immutable-input"
    assert not workspace.exists()
    if not same_path:
        assert not output.exists()


@pytest.mark.parametrize("existing", ["workspace", "output"])
def test_cli_preserves_prior_attempt_workspace_and_output(
        tmp_path, monkeypatch, existing):
    definitions = tmp_path / "definitions"
    definitions.mkdir()
    marker = definitions / "keep-definition"
    marker.write_bytes(b"immutable-input")
    workspace = tmp_path / "workspace"
    output = tmp_path / "report.json"
    if existing == "workspace":
        workspace.mkdir()
        prior = workspace / "keep-attempt"
        prior.write_bytes(b"previous-evidence")
    else:
        prior = output
        prior.write_bytes(b"previous-evidence")
    monkeypatch.setattr(sys, "argv", _argv(tmp_path, workspace, definitions, output))
    with pytest.raises(RuntimeError, match="previous attempts|previous evidence"):
        HARNESS.main()
    assert prior.read_bytes() == b"previous-evidence"
    assert marker.read_bytes() == b"immutable-input"
    if existing == "output":
        assert not workspace.exists()


@pytest.mark.parametrize("missing", ["--clamav-db-dir", "--clamav-db-manifest-sha256"])
def test_cli_requires_explicit_definition_input_without_bundled_database_fallback(
        tmp_path, monkeypatch, missing):
    workspace, definitions, output = (tmp_path / name for name in ("workspace", "definitions", "out.json"))
    arguments = _argv(tmp_path, workspace, definitions, output)
    index = arguments.index(missing)
    del arguments[index:index + 2]
    monkeypatch.setattr(sys, "argv", arguments)
    with pytest.raises(SystemExit) as exc:
        HARNESS.main()
    assert exc.value.code == 2
    assert not workspace.exists()
    assert not output.exists()
