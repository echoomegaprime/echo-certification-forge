"""T4.P8 acceptance — isolated execution sandbox for untrusted journeys.

The hardening flags are asserted on the constructed `docker run` argv (verifiable without Docker);
the executor's journey-runner injection is proven with fakes; a real-Docker path runs behind a skip.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.sandbox import (
    DEFAULT_IMAGE,
    DockerSandbox,
    SandboxError,
    SandboxResult,
    normalize_memory_limit,
    sandboxed_journey_runner,
)
from echo_certification_forge.signing import Ed25519VerdictSigner


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
    assert DEFAULT_IMAGE in cmd                  # pinned @sha256 image
    assert cmd[-2:] == ["python3", "hello.py"]   # argv last
    assert "@sha256:" in DEFAULT_IMAGE           # image is digest-pinned, not a mutable tag


def test_empty_argv_rejected(tmp_path):
    with pytest.raises(SandboxError, match="empty journey argv"):
        DockerSandbox().build_command([], tmp_path)


@pytest.mark.parametrize(
    ("raw", "normalized"),
    (("128m", "128m"), ("1024M", "1024m"), ("1G", "1g"), ("4g", "4g")),
)
def test_memory_limit_is_bounded_and_normalized(raw, normalized):
    assert normalize_memory_limit(raw) == normalized


@pytest.mark.parametrize("raw", ("", "0m", "127m", "5g", "512", "1.5g", "unlimited"))
def test_memory_limit_rejects_unbounded_or_malformed_values(raw):
    with pytest.raises(ValueError, match="sandbox memory"):
        normalize_memory_limit(raw)


def test_custom_memory_limit_stays_cgroup_bounded(tmp_path):
    cmd = DockerSandbox(memory="1G").build_command(["python3", "hello.py"], tmp_path)
    joined = " ".join(cmd)
    assert "--memory 1g" in joined
    assert "--memory-swap 1g" in joined


def test_effective_resource_limits_are_recorded_in_journey_evidence(tmp_path):
    class StubSandbox:
        image = "example.invalid/runtime@sha256:" + ("a" * 64)
        memory = "1G"
        cpus = "1.5"
        pids_limit = 96
        tmpfs_size = "80m"

        @staticmethod
        def run(argv, workdir, execution_guard=None):
            return SandboxResult(0, "ok", "", False)

    passed, detail = sandboxed_journey_runner(StubSandbox())(
        ["python3", "hello.py"],
        tmp_path,
    )
    assert passed is True
    assert detail["resource_limits"] == {
        "memory": "1g",
        "cpus": "1.5",
        "pids": 96,
        "tmpfs": "80m",
    }


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
    sandbox = DockerSandbox(timeout_s=60.0)
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
