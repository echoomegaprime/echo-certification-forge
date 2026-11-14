"""Operator runtime profiles reach both CLIs without granting callers runtime knobs."""
from __future__ import annotations

import json

import pytest

from echo_certification_forge import dispatch_worker, run_worker
from echo_certification_forge.sandbox import DockerSandbox
from echo_certification_forge.signing import Ed25519VerdictSigner


@pytest.mark.parametrize("entrypoint", ["worker", "dispatcher"])
@pytest.mark.parametrize("configured", [False, True])
def test_cli_uses_operator_profile_or_preserves_generic_default(
    tmp_path, monkeypatch, entrypoint, configured
):
    module = run_worker if entrypoint == "worker" else dispatch_worker
    captured = {}
    signer = Ed25519VerdictSigner.generate()
    monkeypatch.setattr(module, "_load_signer", lambda _path: signer)
    monkeypatch.setenv("ECHO_CERTFORGE_API_KEY_PEPPER", "synthetic-test-pepper-" + "x" * 32)
    monkeypatch.delenv("ECHO_CERTFORGE_RUNTIME_PROFILE", raising=False)
    monkeypatch.delenv("ECHO_CERTFORGE_SANDBOX_IMAGE", raising=False)
    if entrypoint == "worker":
        def execute(*_args, **kwargs):
            captured.update(kwargs)
            return {"run_outcome": "COMPLETE", "release_verdict": "NOT_READY"}
        monkeypatch.setattr(module, "run", execute)
        arguments = ["--run-id", "synthetic-cli", "--tenant", "synthetic-tenant",
                     "--target-json", json.dumps({"type": "local", "path": str(tmp_path)})]
        expected_exit = 0
    else:
        def dispatch(*_args, **kwargs):
            captured.update(kwargs["worker_options"])
            return None, None
        monkeypatch.setattr(module, "dispatch_once", dispatch)
        arguments = ["--once"]
        expected_exit = 3
    arguments += ["--sandbox", "--non-production-compat", "--db", str(tmp_path / "test.sqlite"),
                  "--evidence-root", str(tmp_path / "evidence")]
    expected = DockerSandbox()
    if configured:
        profile = tmp_path / "operator-profile.json"
        profile.write_text(json.dumps({
            "schema_version": "certforge.runtime.v1", "journey": None,
            "sandbox": {"image": "sha256:" + "a" * 64, "memory": "2g",
                        "cpus": "0.75", "pids_limit": 64, "tmpfs_size": "32m", "timeout_s": 120},
        }), encoding="utf-8")
        arguments += ["--runtime-profile", str(profile)]
        expected = DockerSandbox(image="sha256:" + "a" * 64, memory="2g",
                                 cpus="0.75", pids_limit=64, tmpfs_size="32m", timeout_s=120)
    assert module.main(arguments) == expected_exit
    assert captured["sandbox"] == expected
    effective = captured.get("runtime_profile")
    if configured:
        assert effective is not None
    if effective is not None:
        assert effective.sandbox == captured["sandbox"]
    assert captured["signer"] is signer


@pytest.mark.parametrize("entrypoint", ["worker", "dispatcher"])
def test_cli_bad_operator_profile_never_reaches_execution(
    tmp_path, monkeypatch, entrypoint, capsys
):
    module = run_worker if entrypoint == "worker" else dispatch_worker
    monkeypatch.setattr(module, "_load_signer", lambda _path: Ed25519VerdictSigner.generate())
    monkeypatch.setenv("ECHO_CERTFORGE_API_KEY_PEPPER", "synthetic-test-pepper-" + "x" * 32)
    profile = tmp_path / "invalid-profile.json"
    profile.write_text(json.dumps({
        "schema_version": "certforge.runtime.v1",
        "sandbox": {"image": "python:latest", "extra_env": {"SECRET": "synthetic-not-for-output"}},
    }), encoding="utf-8")
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid operator profile reached execution or dispatch")
    if entrypoint == "worker":
        monkeypatch.setattr(module, "run", forbidden)
        arguments = ["--run-id", "synthetic-cli", "--tenant", "synthetic-tenant",
                     "--target-json", json.dumps({"type": "local", "path": str(tmp_path)})]
    else:
        monkeypatch.setattr(module, "dispatch_once", forbidden)
        arguments = ["--once"]
    arguments += ["--sandbox", "--runtime-profile", str(profile), "--non-production-compat",
                  "--db", str(tmp_path / "test.sqlite"), "--evidence-root", str(tmp_path / "evidence")]
    assert module.main(arguments) == 2
    output = capsys.readouterr().out
    assert "runtime_profile_invalid" in output
    assert "synthetic-not-for-output" not in output


@pytest.mark.parametrize("image", [
    "--env=F=@sha256:" + "a" * 64, "--privileged", "-v",
    "python:latest", "", "sha256:" + "a" * 63, "sha256:" + "A" * 64,
    "registry.test/worker@sha256:" + "b" * 65,
])
def test_invalid_image_never_reaches_process_launch(tmp_path, monkeypatch, image):
    import echo_certification_forge.sandbox as sandbox_module
    from echo_certification_forge.sandbox import SandboxError

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid image reached process launch")
    monkeypatch.setattr(sandbox_module.subprocess, "Popen", forbidden)
    with pytest.raises(SandboxError):
        DockerSandbox(image=image).run(["python3", "-c", "pass"], tmp_path)


@pytest.mark.parametrize(("image", "local_only"), [
    ("sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558", True),
    ("registry.test/team/worker@sha256:" + "b" * 64, False),
])
def test_full_image_identity_preserves_conditional_pull_behavior(tmp_path, image, local_only):
    command = DockerSandbox(image=image).build_command(["python3", "-c", "pass"], tmp_path)
    assert image in command
    assert ("--pull=never" in command) is local_only
    assert command.index(image) < command.index("python3")
