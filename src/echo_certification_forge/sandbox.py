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

import codecs
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Qualified offline runtime; its upstream recipe and delivered OCI index are bound
# in images/sandbox/runtime-input.json. Provision and admit it before deployment.
DEFAULT_IMAGE = "sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558"


class SandboxError(RuntimeError):
    """The sandbox runtime is unavailable or failed to launch (distinct from a target-code failure)."""
    owner_receipt: dict | None = None
    container_absence_verified: bool = False


@dataclass(frozen=True, slots=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


class _StreamTail:
    """Drain a pipe without allowing customer output to grow host memory."""
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.value = ""
        self.failed = False
        self.lock = threading.Lock()

    def drain(self, stream) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while raw := stream.read(8192):
                value = decoder.decode(raw)
                with self.lock:
                    self.value = (self.value + value)[-self.limit:]
            value = decoder.decode(b"", final=True)
            with self.lock:
                self.value = (self.value + value)[-self.limit:]
        except Exception:
            with self.lock:
                self.failed = True
        finally:
            try:
                stream.close()
            except Exception:
                with self.lock:
                    self.failed = True

    def snapshot(self) -> tuple[str, bool]:
        with self.lock:
            return self.value, self.failed


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

    def validate_resources(self) -> None:
        """Validate the stored types consumed by Docker argv and deadline arithmetic."""
        for value in (self.memory, self.tmpfs_size):
            if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*[kmg]?", value):
                raise SandboxError("sandbox resource limit invalid")
        if not isinstance(self.cpus, str) or type(self.timeout_s) not in (int, float):
            raise SandboxError("sandbox resource limit invalid")
        for value in (self.cpus, self.timeout_s):
            try:
                number = float(value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise SandboxError("sandbox resource limit invalid") from exc
            if not math.isfinite(number) or number <= 0:
                raise SandboxError("sandbox resource limit invalid")
        if type(self.pids_limit) is not int or self.pids_limit < 1:
            raise SandboxError("sandbox resource limit invalid")


    def validate_image(self) -> None:
        """Reject mutable or option-like image tokens before Docker argv is built."""
        if (not isinstance(self.image, str)
                or re.fullmatch(r"(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}",
                                self.image) is None):
            raise SandboxError("sandbox image must be a full immutable identity")

    def build_command(self, argv: list[str], workdir: Path) -> list[str]:
        """Construct the fully-hardened `docker run` argv. Pure — no side effects, unit-testable."""
        if not argv:
            raise SandboxError("empty journey argv")
        self.validate_resources()
        self.validate_image()
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

    def _control(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                [*self.docker, *arguments], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10, shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError("sandbox cleanup control unavailable") from exc
        if len(result.stdout) > 16384 or len(result.stderr) > 4096:
            raise SandboxError("sandbox cleanup control output invalid")
        return result

    def _inspect_container(self, identifier: str) -> dict | None:
        # Select public identity fields only, never arbitrary target environment.
        template = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
                    '"Created":{{json .Created}},"Config":{"Image":{{json .Config.Image}},'
                    '"Labels":{"echo.certforge.journey_owner":'
                    '{{json (index .Config.Labels "echo.certforge.journey_owner")}}}}}')
        result = self._control(["inspect", "--type", "container", "--format", template, identifier])
        missing = {
            "Error: No such object: " + identifier,
            "Error: No such container: " + identifier,
            "Error response from daemon: No such container: " + identifier,
            "Error response from daemon: No such object: " + identifier,
        }
        if result.returncode == 1 and result.stderr.strip() in missing and result.stdout.strip() in ("", "[]"):
            return None
        if result.returncode != 0:
            raise SandboxError("sandbox container inspection unverified")
        try:
            value = json.loads(result.stdout)
        except ValueError as exc:
            raise SandboxError("sandbox container identity invalid") from exc
        if not isinstance(value, dict):
            raise SandboxError("sandbox container identity invalid")
        return value

    def _read_cid(self, path: Path) -> str | None:
        try:
            before = path.lstat()
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 1 <= before.st_size <= 128):
            raise SandboxError("sandbox CID receipt invalid")
        def stable(info):
            return info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or stable(opened) != stable(before):
                raise SandboxError("sandbox CID receipt changed")
            raw = handle.read(129)
            after = os.fstat(handle.fileno())
            if (stable(after) != stable(opened) or after.st_ctime_ns != opened.st_ctime_ns
                    or len(raw) != before.st_size):
                raise SandboxError("sandbox CID receipt changed")
        final = path.lstat()
        if stable(final) != stable(before) or final.st_ctime_ns != before.st_ctime_ns:
            raise SandboxError("sandbox CID receipt changed")
        try:
            cid = raw.decode("ascii").strip()
        except UnicodeError as exc:
            raise SandboxError("sandbox CID receipt invalid") from exc
        if re.fullmatch(r"[0-9a-f]{64}", cid) is None:
            raise SandboxError("sandbox CID receipt invalid")
        return cid

    def _cleanup_owned(
        self, *, name: str, token: str, cid_path: Path, started: datetime, aborted: bool,
    ) -> None:
        cid = self._read_cid(cid_path)
        observed = self._inspect_container(cid or name)
        if observed is not None:
            observed_id = observed.get("Id")
            config = observed.get("Config")
            try:
                created = datetime.fromisoformat(str(observed.get("Created")).replace("Z", "+00:00"))
            except ValueError as exc:
                raise SandboxError("sandbox container ownership unverified") from exc
            if (not isinstance(observed_id, str) or re.fullmatch(r"[0-9a-f]{64}", observed_id) is None
                    or (cid is not None and observed_id != cid)
                    or observed.get("Name") != "/" + name
                    or not isinstance(config, dict) or config.get("Image") != self.image
                    or not isinstance(config.get("Labels"), dict)
                    or config["Labels"].get("echo.certforge.journey_owner") != token
                    or not isinstance(observed.get("Image"), str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", observed["Image"]) is None
                    or created.tzinfo is None
                    or not started - timedelta(seconds=300) <= created <= datetime.now(UTC) + timedelta(seconds=300)):
                raise SandboxError("sandbox container ownership unverified")
            if self.image.startswith("sha256:"):
                expected_image_id = self.image
            else:
                # A registry manifest digest and a Docker local content ID are
                # distinct identities. Resolve the requested immutable pin.
                image = self._control(["image", "inspect", "--format", "{{json .Id}}", self.image])
                try:
                    expected_image_id = json.loads(image.stdout)
                except ValueError as exc:
                    raise SandboxError("sandbox image identity unverified") from exc
                if (image.returncode != 0 or not isinstance(expected_image_id, str)
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id) is None):
                    raise SandboxError("sandbox image identity unverified")
            if observed["Image"] != expected_image_id:
                raise SandboxError("sandbox image identity mismatch")
            cid = observed_id
            removed = self._control(["rm", "--force", cid])
            if removed.returncode != 0:
                raise SandboxError("sandbox owned container removal unverified")
            if self._inspect_container(cid) is not None:
                raise SandboxError("sandbox owned container remains")
        elif aborted and cid is None:
            # A timed-out create might still be accepted by the daemon. Keep its
            # public task receipt and fail closed instead of claiming absence.
            raise SandboxError("sandbox aborted before container creation was reconciled")
        health = self._control(["info", "--format", "{{json .ServerVersion}}"])
        try:
            version = json.loads(health.stdout)
        except ValueError as exc:
            raise SandboxError("sandbox daemon health unverified") from exc
        if health.returncode != 0 or not isinstance(version, str) or re.match(r"^[0-9]+\.[0-9]+", version) is None:
            raise SandboxError("sandbox daemon health unverified")
        inventory = self._control(["ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"])
        if inventory.returncode != 0 or inventory.stdout.strip():
            raise SandboxError("sandbox owned container absence unverified")

    @staticmethod
    def _stop_client(proc) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except OSError as exc:
            if proc.poll() is None:
                raise SandboxError("sandbox client termination unverified") from exc

    def run(
        self,
        argv: list[str],
        workdir: Path,
        execution_guard: Callable[[], None] | None = None,
    ) -> SandboxResult:
        cmd = self.build_command(argv, workdir)
        token = uuid.uuid4().hex
        name = "certforge-journey-" + token
        session = Path(tempfile.mkdtemp(prefix="certforge-sandbox-"))
        if os.name == "posix":
            session.chmod(0o700)
        cid_path = session / "cid"
        started = datetime.now(UTC)
        receipt = {"name": name, "owner_token": token, "image": self.image,
                   "started_at": started.isoformat(), "cid_path": str(cid_path)}
        descriptor = os.open(session / "owner.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, sort_keys=True)
        cmd[len(self.docker) + 1:len(self.docker) + 1] = [
            "--name", name, "--label", "echo.certforge.journey_owner=" + token,
            "--cidfile", str(cid_path),
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False, bufsize=0)
        except OSError as exc:
            shutil.rmtree(session)
            raise SandboxError("docker unavailable") from exc
        stdout_tail, stderr_tail = _StreamTail(8000), _StreamTail(4000)
        threads: list[threading.Thread] = []
        primary: BaseException | None = None
        cleanup_error: BaseException | None = None
        container_closed = False
        timed_out = False
        try:
            for stream, tail in ((proc.stdout, stdout_tail), (proc.stderr, stderr_tail)):
                if stream is None:
                    raise SandboxError("sandbox output pipe unavailable")
                thread = threading.Thread(target=tail.drain, args=(stream,), daemon=True)
                thread.start()
                threads.append(thread)
            deadline = time.monotonic() + self.timeout_s
            while True:
                if execution_guard is not None:
                    execution_guard()
                if stdout_tail.snapshot()[1] or stderr_tail.snapshot()[1]:
                    raise SandboxError("sandbox output read failed")
                if proc.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                time.sleep(min(0.05, remaining))
        except BaseException as exc:
            primary = exc
        finally:
            try:
                self._stop_client(proc)
            except BaseException as exc:
                cleanup_error = exc
            try:
                self._cleanup_owned(name=name, token=token, cid_path=cid_path,
                                    started=started, aborted=timed_out or primary is not None)
                container_closed = True
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
            for thread in threads:
                thread.join(timeout=2)
            if any(thread.is_alive() for thread in threads):
                cleanup_error = cleanup_error or SandboxError("sandbox output drain unverified")
            if stdout_tail.snapshot()[1] or stderr_tail.snapshot()[1]:
                cleanup_error = cleanup_error or SandboxError("sandbox output read failed")
            if cleanup_error is None:
                try:
                    shutil.rmtree(session)
                except OSError as exc:
                    cleanup_error = SandboxError("sandbox task receipt cleanup unverified")
                    cleanup_error.__cause__ = exc
        if cleanup_error is not None:
            error = SandboxError("sandbox cleanup unverified; owner=" + name + "; receipt=" + str(session))
            error.__cause__ = cleanup_error
            # Carry the public ownership receipt even if a failed local rmtree
            # removed only part of its directory. Never claim file retention.
            error.owner_receipt = receipt
            error.container_absence_verified = container_closed
            if primary is not None:
                if isinstance(primary, SandboxError):
                    primary.owner_receipt = receipt
                    primary.container_absence_verified = container_closed
                raise primary from error
            raise error
        if primary is not None:
            raise primary
        stdout, _ = stdout_tail.snapshot()
        stderr, _ = stderr_tail.snapshot()
        return SandboxResult(124 if timed_out else proc.returncode, stdout,
                             "sandbox timeout" if timed_out else stderr, timed_out)



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
            detail = {"executed": True, "isolation": "docker", "error": f"sandbox_unavailable:{exc}"}
            if exc.owner_receipt is not None:
                detail["cleanup"] = {"owner_receipt": exc.owner_receipt,
                                     "container_absence_verified": exc.container_absence_verified}
            return False, detail
        return result.returncode == 0, {
            "executed": True, "isolation": "docker", "image": sandbox.image,
            "argv": argv, "returncode": result.returncode, "timed_out": result.timed_out,
            "stdout_tail": result.stdout[-2000:], "stderr_tail": result.stderr[-2000:],
        }
    return _run
