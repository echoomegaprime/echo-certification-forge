"""Isolated execution sandbox — runs an UNTRUSTED critical-journey inside a locked-down container.

The certification harness must execute target-supplied code to exercise real journeys (SPEC 2.3),
but that code is hostile until proven otherwise. This module confines it to a Docker container
(SPEC 14.2 "Level 2: container isolation") with every host escape closed:

  * ``--network none``            — no outbound networking (SPEC 22.4 restricted egress)
  * ``--memory/--cpus/--pids``    — resource quotas (no fork bombs / OOM the host)
  * ``--read-only`` + tmpfs       — no writable host/root filesystem; scratch is a capped noexec tmpfs
  * ``--user 65534`` (nobody)     — non-root runtime
  * ``--cap-drop ALL`` + ``no-new-privileges`` — no capabilities, no privilege escalation
  * source mounted ``:ro``        — the target tree is read-only inside the container
  * full immutable image identity — local ID or repository@sha256
  * ``--rm`` + host-side timeout  — the harness terminates only what it launched (SPEC 2.5)

The trusted orchestration (acquisition, scanning, signing) runs on the host and NEVER executes
target code — only the journey runs, and only inside the sandbox.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Qualified offline runtime; its upstream recipe and delivered OCI index are bound
# in images/sandbox/runtime-input.json. Provision and admit it before deployment.
DEFAULT_IMAGE = "sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558"


class SandboxError(RuntimeError):
    """The sandbox runtime is unavailable or failed to launch (distinct from a target-code failure)."""


@dataclass(frozen=True, slots=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


@dataclass(frozen=True, slots=True)
class DockerSandbox:
    image: str = DEFAULT_IMAGE
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 128
    tmpfs_size: str = "64m"
    timeout_s: float = 90.0
    user: str = "65534:65534"  # nobody:nogroup
    docker: tuple[str, ...] = ("docker",)
    extra_env: dict[str, str] = field(default_factory=dict)

    def build_command(self, argv: list[str], workdir: Path) -> list[str]:
        """Construct the fully-hardened `docker run` argv. Pure — no side effects, unit-testable."""
        if not argv:
            raise SandboxError("empty journey argv")
        cmd: list[str] = [
            *self.docker, "run", "--rm",
            "--network", "none",
            "--memory", self.memory,
            "--memory-swap", self.memory,          # no swap escape past the memory cap
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={self.tmpfs_size}",
            "--user", self.user,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{workdir.resolve()}:/work:ro",
            "-w", "/work",
        ]
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.image):
            # A local content ID must already be acquired and qualified. Never
            # reinterpret a missing local ID as a registry repository/tag.
            cmd.insert(len(self.docker) + 2, "--pull=never")
        for key, value in sorted(self.extra_env.items()):
            cmd += ["--env", f"{key}={value}"]
        cmd += [self.image, *argv]
        return cmd

    def run(
        self,
        argv: list[str],
        workdir: Path,
        execution_guard: Callable[[], None] | None = None,
    ) -> SandboxResult:
        cmd = self.build_command(argv, workdir)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
        except FileNotFoundError as exc:  # docker binary absent
            raise SandboxError(f"docker unavailable: {exc}") from exc
        deadline = time.monotonic() + self.timeout_s
        while True:
            try:
                if execution_guard is not None:
                    execution_guard()
            except BaseException:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                proc.communicate()
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                stdout, _stderr = proc.communicate()
                return SandboxResult(124, stdout[-8000:], "sandbox timeout", True)
            try:
                stdout, stderr = proc.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        return SandboxResult(proc.returncode, stdout[-8000:], stderr[-4000:], False)


def sandboxed_journey_runner(
    sandbox: DockerSandbox,
    execution_guard: Callable[[], None] | None = None,
):
    """Adapt a DockerSandbox to the executor's journey-runner signature
    ``(argv, workdir) -> (passed, detail)``. A SandboxError (runtime unavailable) is a HARNESS
    failure surfaced as passed=False with a distinct reason (never silently a pass)."""
    def _run(argv: list[str], workdir: Path) -> tuple[bool, dict]:
        try:
            result = sandbox.run(argv, workdir, execution_guard)
        except SandboxError as exc:
            return False, {"executed": True, "isolation": "docker", "error": f"sandbox_unavailable:{exc}"}
        return result.returncode == 0, {
            "executed": True, "isolation": "docker", "image": sandbox.image,
            "argv": argv, "returncode": result.returncode, "timed_out": result.timed_out,
            "stdout_tail": result.stdout[-2000:], "stderr_tail": result.stderr[-2000:],
        }
    return _run
