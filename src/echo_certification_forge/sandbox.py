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
  * pinned image by @sha256       — no unpinned/mutable base
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

# Pinned minimal Python base (same digest the P4 supply-chain pipeline pins). Override per policy.
DEFAULT_IMAGE = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
DEFAULT_MEMORY = "512m"
MIN_MEMORY_MIB = 128
MAX_MEMORY_MIB = 4096
_MEMORY_LIMIT = re.compile(r"^([1-9][0-9]*)([mMgG])$")
_PINNED_IMAGE = re.compile(r"(?:^|@)sha256:([0-9a-f]{64})$")


class SandboxError(RuntimeError):
    """The sandbox runtime is unavailable or failed to launch (distinct from a target-code failure)."""


def normalize_memory_limit(value: str) -> str:
    """Validate and normalize a bounded Docker memory limit."""
    match = _MEMORY_LIMIT.fullmatch(value.strip())
    if match is None:
        raise ValueError("sandbox memory must be a whole number followed by m or g")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    memory_mib = amount if unit == "m" else amount * 1024
    if not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB:
        raise ValueError(
            f"sandbox memory must be between {MIN_MEMORY_MIB}m and {MAX_MEMORY_MIB // 1024}g"
        )
    return f"{amount}{unit}"


@dataclass(frozen=True, slots=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


@dataclass(frozen=True, slots=True)
class DockerSandbox:
    image: str = DEFAULT_IMAGE
    memory: str = DEFAULT_MEMORY
    cpus: str = "1.0"
    pids_limit: int = 128
    tmpfs_size: str = "64m"
    timeout_s: float = 90.0
    user: str = "65534:65534"  # nobody:nogroup
    docker: tuple[str, ...] = ("docker",)
    extra_env: dict[str, str] = field(default_factory=dict)

    def image_sha256(self) -> str:
        match = _PINNED_IMAGE.search(self.image)
        if match is None:
            raise SandboxError("sandbox image must be pinned by sha256 digest")
        return match.group(1)

    def resource_limits(self) -> dict[str, str | int]:
        try:
            memory = normalize_memory_limit(self.memory)
        except ValueError as exc:
            raise SandboxError(str(exc)) from exc
        return {
            "memory": memory,
            "cpus": self.cpus,
            "pids": self.pids_limit,
            "tmpfs": self.tmpfs_size,
        }

    def build_command(self, argv: list[str], workdir: Path) -> list[str]:
        """Construct the fully-hardened `docker run` argv. Pure — no side effects, unit-testable."""
        if not argv:
            raise SandboxError("empty journey argv")
        self.image_sha256()
        memory = str(self.resource_limits()["memory"])
        cmd: list[str] = [
            *self.docker, "run", "--rm",
            "--network", "none",
            "--memory", memory,
            "--memory-swap", memory,               # no swap escape past the memory cap
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
            "resource_limits": sandbox.resource_limits(),
            "argv": argv, "returncode": result.returncode, "timed_out": result.timed_out,
            "stdout_tail": result.stdout[-2000:], "stderr_tail": result.stderr[-2000:],
        }
    return _run
