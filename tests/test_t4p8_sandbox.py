"""T4.P8 acceptance — isolated execution sandbox for untrusted journeys.

The hardening flags are asserted on the constructed `docker run` argv (verifiable without Docker);
the executor's journey-runner injection is proven with fakes; a real-Docker path runs behind a skip.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import pytest

from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.sandbox import (
    DEFAULT_IMAGE, DockerSandbox, SandboxError, sandboxed_journey_runner,
)
from echo_certification_forge.signing import Ed25519VerdictSigner
from production_e2e_support import trusted_generic_production_e2e


def _real_sandbox_image() -> str:
    reference = os.environ.get("ECHO_CERTFORGE_TEST_SANDBOX_IMAGE")
    if reference is None:
        return DEFAULT_IMAGE
    if re.fullmatch(r"sha256:[0-9a-f]{64}", reference) is None:
        raise ValueError("CI fixture must be a full local Docker image ID")
    return reference


def test_build_command_has_all_hardening_flags(tmp_path):
    cmd = DockerSandbox().build_command(["python3", "hello.py"], tmp_path)
    joined = " ".join(cmd)
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network none" in joined            # no egress
    assert "--memory 512m" in joined and "--memory-swap 512m" in joined  # no swap escape
    assert "--pids-limit 128" in joined          # no fork bomb
    assert "--read-only" in cmd                  # no writable rootfs
    assert "--tmpfs" in cmd and "noexec" in joined
    assert "--user 65534:65534" in joined        # non-root
    assert "--cap-drop ALL" in joined            # no capabilities
    assert "--security-opt no-new-privileges" in joined
    assert f"{tmp_path.resolve()}:/work:ro" in joined   # source mounted READ-ONLY
    assert "-w /work" in joined
    assert DEFAULT_IMAGE in cmd                  # pinned full local image ID
    assert cmd[-2:] == ["python3", "hello.py"]   # argv last
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", DEFAULT_IMAGE)
    assert "--pull=never" in cmd                  # missing local content cannot fall back to a tag


def test_empty_argv_rejected(tmp_path):
    with pytest.raises(SandboxError, match="empty journey argv"):
        DockerSandbox().build_command([], tmp_path)


def test_unavailable_runtime_is_a_harness_failure_not_a_pass(tmp_path):
    # a bogus docker binary -> SandboxError -> runner reports passed=False (never a silent pass)
    runner = sandboxed_journey_runner(DockerSandbox(docker=("definitely-not-docker-xyz",)))
    passed, detail = runner(["python3", "hello.py"], tmp_path)
    assert passed is False
    assert detail["isolation"] == "docker"
    assert detail["error"].startswith("sandbox_unavailable")


def _benign(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    return root


def test_executor_uses_injected_journey_runner(store, manifest, target, environment, tmp_path):
    store.register_run("cert-sbx", target, environment, manifest.manifest_id, manifest.digest)
    signer = Ed25519VerdictSigner.generate()
    ex = RunExecutor(store, manifest, signer)

    calls: list = []
    def fake_runner(argv, workdir):
        calls.append((argv, Path(workdir)))
        return True, {"executed": True, "isolation": "docker", "argv": argv}

    result = ex.execute(
        "cert-sbx", target.tenant_id, _benign(tmp_path),
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=["python3", "hello.py"], journey_runner=fake_runner,
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
        production_e2e_attestation=trusted_generic_production_e2e(target, environment),
    )
    assert calls and calls[0][0] == ["python3", "hello.py"]   # the injected runner was used
    assert result.release_verdict == "PRODUCTION_READY"
    assert store.list_rule_results("cert-sbx", target.tenant_id)["critical_journeys"].passed is True


def test_executor_injected_runner_failure_blocks_ready(store, manifest, target, environment, tmp_path):
    store.register_run("cert-sbx", target, environment, manifest.manifest_id, manifest.digest)
    ex = RunExecutor(store, manifest, Ed25519VerdictSigner.generate())
    result = ex.execute(
        "cert-sbx", target.tenant_id, _benign(tmp_path),
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=["python3", "hello.py"],
        journey_runner=lambda argv, wd: (False, {"executed": True, "isolation": "docker"}),
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
    )
    assert result.release_verdict == "NOT_READY"  # journey failed in the sandbox


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_real_docker_sandbox_runs_benign_and_blocks_network(tmp_path):
    src = _benign(tmp_path)
    sandbox = DockerSandbox(image=_real_sandbox_image(), timeout_s=60.0)
    # benign journey runs to completion inside the container
    ok = sandbox.run(["python3", "hello.py"], src)
    assert ok.returncode == 0 and "ok" in ok.stdout
    # egress is blocked (--network none): a socket connect must fail
    (src / "net.py").write_text(
        "import socket,sys\n"
        "try:\n socket.create_connection(('1.1.1.1',53),timeout=3); print('NET_OK')\n"
        "except Exception as e:\n print('NET_BLOCKED'); sys.exit(7)\n",
        encoding="utf-8",
    )
    net = sandbox.run(["python3", "net.py"], src)
    assert net.returncode == 7 and "NET_BLOCKED" in net.stdout


def test_real_sandbox_image_uses_default_when_ci_fixture_is_unset(monkeypatch):
    monkeypatch.delenv("ECHO_CERTFORGE_TEST_SANDBOX_IMAGE", raising=False)
    assert _real_sandbox_image() == DEFAULT_IMAGE


def test_real_sandbox_image_accepts_only_full_local_ci_fixture(monkeypatch):
    image = "sha256:" + "a" * 64
    monkeypatch.setenv("ECHO_CERTFORGE_TEST_SANDBOX_IMAGE", image)
    assert _real_sandbox_image() == image


@pytest.mark.parametrize("reference", ["", "python:latest", "sha256:abc", "sha256:" + "A" * 64,
                                       "repository@sha256:" + "a" * 64])
def test_invalid_ci_fixture_fails_instead_of_falling_back(monkeypatch, reference):
    monkeypatch.setenv("ECHO_CERTFORGE_TEST_SANDBOX_IMAGE", reference)
    with pytest.raises(ValueError, match="full local Docker image ID"):
        _real_sandbox_image()


def test_local_id_uses_no_pull_while_registry_digest_keeps_existing_acquisition(tmp_path):
    local = DockerSandbox(image="sha256:" + "a" * 64).build_command(["python3", "hello.py"], tmp_path)
    registry = DockerSandbox(image="repository/runtime@sha256:" + "b" * 64).build_command(
        ["python3", "hello.py"], tmp_path)
    assert "--pull=never" in local
    assert "--pull=never" not in registry


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_missing_local_image_fails_without_registry_pull(tmp_path):
    source = _benign(tmp_path)
    sandbox = DockerSandbox(image="sha256:" + "0" * 64, timeout_s=20.0)
    result = sandbox.run(["python3", "hello.py"], source)
    assert result.returncode != 0
    assert "pull access denied" not in result.stderr.lower()
