"""Stored sandbox limits must be safe for argv and deadline arithmetic before launch."""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from echo_certification_forge import sandbox as module
from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxError
from test_sandbox_lifecycle import fake_docker, _owned_removal

BAD_RESOURCES = [
    *[(field, value) for field in ("memory", "tmpfs_size") for value in
      (None, True, 512, 1.5, [], {}, "", "0", "0m", "-1m", "1.5g", "512M",
       " 512m", "512m ", "1e3", "512m --privileged")],
    *[("cpus", value) for value in
      (None, True, 1, 1.0, [], {}, "", "0", "-1", "nan", "NaN", "inf", "-inf",
       "1e9999", "invalid", Decimal("1"))],
    *[("timeout_s", value) for value in
      (None, True, False, "90", [], {}, 0, -1, float("nan"), float("inf"),
       float("-inf"), Decimal("1"), 10 ** 10000)],
    *[("pids_limit", value) for value in (None, True, False, "128", 128.0, [], {}, 0, -1)],
]


@pytest.mark.parametrize(("field", "value"), BAD_RESOURCES, ids=[
    f"{field}-{index}" for index, (field, _value) in enumerate(BAD_RESOURCES)])
def test_invalid_stored_resource_is_rejected_before_popen(tmp_path, monkeypatch, field, value):
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("invalid stored resource reached subprocess launch")

    monkeypatch.setattr(module.subprocess, "Popen", forbidden)
    sandbox = replace(DockerSandbox(), **{field: value})
    with pytest.raises(SandboxError, match="resource limit invalid"):
        sandbox.validate_resources()
    with pytest.raises(SandboxError, match="resource limit invalid"):
        sandbox.build_command(["python", "fixture.py"], tmp_path)
    with pytest.raises(SandboxError, match="resource limit invalid"):
        sandbox.run(["python", "fixture.py"], tmp_path)
    assert calls == []


@pytest.mark.parametrize("changes", [
    {}, {"memory": "1", "tmpfs_size": "1k", "cpus": "0.25", "pids_limit": 1, "timeout_s": 1},
    {"memory": "2g", "tmpfs_size": "256m", "cpus": "2.0", "pids_limit": 256, "timeout_s": 120},
    {"memory": "1024k", "tmpfs_size": "64m", "cpus": "1e-3", "timeout_s": 0.01},
])
def test_supported_literals_keep_the_exact_effective_limits_and_hardening(tmp_path, changes):
    sandbox = replace(DockerSandbox(), **changes)
    assert sandbox.validate_resources() is None
    command = sandbox.build_command(["python", "fixture.py"], tmp_path)
    for flag, expected in (("--memory", sandbox.memory), ("--memory-swap", sandbox.memory),
                           ("--cpus", sandbox.cpus), ("--pids-limit", str(sandbox.pids_limit)),
                           ("--network", "none"), ("--user", sandbox.user), ("--cap-drop", "ALL")):
        assert command[command.index(flag) + 1] == expected
    assert "--read-only" in command
    assert "--pull=never" in command
    assert "no-new-privileges" in command
    assert f"/tmp:rw,noexec,nosuid,size={sandbox.tmpfs_size}" in command
    assert command[-3:] == [DEFAULT_IMAGE, "python", "fixture.py"]


def test_default_timeout_type_runs_through_deadline_arithmetic_with_inert_transport(
        tmp_path, monkeypatch, fake_docker):
    fake_docker.configure()
    sandbox = DockerSandbox(docker=fake_docker.command)
    assert type(sandbox.timeout_s) in (int, float) and sandbox.timeout_s == 90.0
    launches = []
    actual_popen = module.subprocess.Popen

    def observe_launch(*args, **kwargs):
        # Observe transport construction while preserving real subprocess/cleanup behavior.
        launches.append((args, kwargs))
        return actual_popen(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", observe_launch)
    result = sandbox.run(["inert-journey", "fixture-only"], tmp_path)
    assert result.returncode == 0
    assert result.timed_out is False
    assert "synthetic-journey-output" in result.stdout
    assert len(fake_docker.actions("run")) == 1
    assert launches[0][1]["shell"] is False
    _owned_removal(fake_docker)
