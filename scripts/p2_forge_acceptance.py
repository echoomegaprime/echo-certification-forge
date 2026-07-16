#!/usr/bin/env python3
"""Real FORGE P2 acceptance using the local Docker Engine Unix API.

The script creates uniquely labelled, non-root, network-denied containers from
an already-present immutable image. It never pulls images, touches unrelated
containers, mounts the Docker socket into a target, or loads verdict-signing
material.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import platform
import secrets
import socket
import sys
import tempfile
import time
import urllib.parse
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from echo_certification_forge.canonical import sha256_bytes, sha256_json, to_utc_iso
from echo_certification_forge.runner import (
    AuthenticationFailure,
    ControlPlaneTransportAuthority,
    EvidenceChunk,
    ExpiredCredential,
    IsolationFailure,
    IsolationProfile,
    ReplayDetected,
    ResourceLimits,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerLeaseState,
    RunnerStore,
    TrustedTransportRegistry,
    build_docker_create_payload,
    create_transport_request,
    extract_archive_safely,
    validate_docker_inspect,
)

DEFAULT_IMAGE = "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
SOCKET_PATH = "/var/run/docker.sock"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 30.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


class DockerAPI:
    def __init__(self, socket_path: str = SOCKET_PATH) -> None:
        self.socket_path = socket_path

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
        timeout: float = 30.0,
        raw: bool = False,
    ) -> Any:
        connection = UnixHTTPConnection(self.socket_path, timeout=timeout)
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            content = response.read()
        finally:
            connection.close()
        if response.status not in expected:
            raise RuntimeError(
                f"docker_api_error method={method} path={path} status={response.status} "
                f"body={content.decode('utf-8', errors='replace')[:2000]}"
            )
        if raw:
            return content
        if not content:
            return None
        return json.loads(content.decode("utf-8"))

    def ping(self) -> str:
        return self.request("GET", "/_ping", expected=(200,), raw=True).decode("ascii")

    def version(self) -> dict[str, Any]:
        return self.request("GET", "/version")

    def info(self) -> dict[str, Any]:
        return self.request("GET", "/info")

    def container_ids(self) -> set[str]:
        rows = self.request("GET", "/containers/json?all=1")
        return {row["Id"] for row in rows}

    def create(self, name: str, payload: dict[str, Any]) -> str:
        result = self.request(
            "POST",
            "/containers/create?name=" + urllib.parse.quote(name, safe=""),
            payload,
            expected=(201,),
        )
        return result["Id"]

    def start(self, container_id: str) -> None:
        self.request("POST", f"/containers/{container_id}/start", expected=(204,))

    def inspect(self, container_id: str) -> dict[str, Any]:
        return self.request("GET", f"/containers/{container_id}/json")

    def stats(self, container_id: str) -> dict[str, Any]:
        return self.request("GET", f"/containers/{container_id}/stats?stream=false", timeout=15.0)

    def logs(self, container_id: str) -> str:
        content = self.request(
            "GET",
            f"/containers/{container_id}/logs?stdout=1&stderr=1&timestamps=0",
            raw=True,
        )
        return decode_docker_logs(content)

    def stop(self, container_id: str, seconds: int = 1) -> None:
        self.request("POST", f"/containers/{container_id}/stop?t={seconds}", expected=(204, 304))

    def kill(self, container_id: str) -> None:
        self.request("POST", f"/containers/{container_id}/kill?signal=KILL", expected=(204, 409))

    def remove(self, container_id: str) -> None:
        self.request("DELETE", f"/containers/{container_id}?force=1&v=1", expected=(204, 404))


def decode_docker_logs(content: bytes) -> str:
    if len(content) < 8 or content[0] not in (0, 1, 2):
        return content.decode("utf-8", errors="replace")
    parts: list[bytes] = []
    offset = 0
    while offset + 8 <= len(content):
        length = int.from_bytes(content[offset + 4 : offset + 8], "big")
        start = offset + 8
        end = start + length
        if end > len(content):
            parts.append(content[offset:])
            break
        parts.append(content[start:end])
        offset = end
    return b"".join(parts).decode("utf-8", errors="replace")


def wait_not_running(api: DockerAPI, container_id: str, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        inspect = api.inspect(container_id)
        if not inspect["State"]["Running"]:
            return inspect
        if time.monotonic() >= deadline:
            raise TimeoutError(f"container {container_id} exceeded {timeout_seconds}s")
        time.sleep(0.1)


def cpu_effective_cores(before: dict[str, Any], after: dict[str, Any]) -> float:
    cpu_delta = (
        after["cpu_stats"]["cpu_usage"]["total_usage"]
        - before["cpu_stats"]["cpu_usage"]["total_usage"]
    )
    system_delta = after["cpu_stats"]["system_cpu_usage"] - before["cpu_stats"]["system_cpu_usage"]
    online = after["cpu_stats"].get("online_cpus") or len(
        after["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1]
    )
    if system_delta <= 0:
        return 0.0
    return cpu_delta / system_delta * online


def make_profile(
    image_digest: str,
    *,
    pids: int = 32,
    cpu: float = 0.25,
    disk_bytes: int = 8 * 1024 * 1024,
    file_size_bytes: int = 8 * 1024 * 1024,
) -> IsolationProfile:
    return IsolationProfile(
        profile_id="certforge.p2.forge",
        profile_version="1.0.0",
        image_digest=image_digest,
        user="65532:65532",
        limits=ResourceLimits(
            cpu_cores=cpu,
            memory_bytes=64 * 1024 * 1024,
            pids=pids,
            disk_bytes=disk_bytes,
            file_size_bytes=file_size_bytes,
            wall_time_seconds=5,
            heartbeat_interval_seconds=2,
            lease_ttl_seconds=10,
        ),
    )


def run_container_case(
    api: DockerAPI,
    *,
    case: str,
    profile: IsolationProfile,
    command: tuple[str, ...],
    owned_ids: set[str],
    expect_timeout: bool = False,
    cancel: bool = False,
    sample_cpu: bool = False,
    runtime_seconds: float = 5.0,
) -> dict[str, Any]:
    suffix = secrets.token_hex(5)
    run_id = f"p2.{case}.{suffix}"
    tenant_id = "tenant.p2"
    ownership_token = f"owner.{suffix}"
    payload = build_docker_create_payload(
        profile,
        run_id=run_id,
        tenant_id=tenant_id,
        ownership_token=ownership_token,
        command=command,
    )
    name = f"certforge-p2-{case}-{suffix}"
    container_id = api.create(name, payload)
    owned_ids.add(container_id)
    created = api.inspect(container_id)
    issues_at_create = validate_docker_inspect(created, profile)
    if created["Image"] != profile.image_digest:
        issues_at_create = tuple(sorted(set(issues_at_create + ("image_identity_mismatch",))))
    api.start(container_id)
    started = api.inspect(container_id)
    cpu_result: float | None = None
    timed_out = False
    cancelled = False
    if sample_cpu:
        time.sleep(0.4)
        before = api.stats(container_id)
        time.sleep(1.5)
        after = api.stats(container_id)
        cpu_result = cpu_effective_cores(before, after)
        api.kill(container_id)
    elif cancel:
        time.sleep(0.4)
        api.stop(container_id, seconds=1)
        cancelled = True
    else:
        try:
            wait_not_running(api, container_id, runtime_seconds)
        except TimeoutError:
            timed_out = True
            api.kill(container_id)
    final = wait_not_running(api, container_id, 5.0)
    logs = api.logs(container_id)
    return {
        "case": case,
        "container_id": container_id,
        "container_name": name,
        "run_id": run_id,
        "ownership_token": ownership_token,
        "image": final["Image"],
        "created_inspect_issues": list(issues_at_create),
        "host_config": {
            "ReadonlyRootfs": final["HostConfig"].get("ReadonlyRootfs"),
            "NetworkMode": final["HostConfig"].get("NetworkMode"),
            "CapDrop": final["HostConfig"].get("CapDrop"),
            "SecurityOpt": final["HostConfig"].get("SecurityOpt"),
            "Memory": final["HostConfig"].get("Memory"),
            "MemorySwap": final["HostConfig"].get("MemorySwap"),
            "NanoCpus": final["HostConfig"].get("NanoCpus"),
            "PidsLimit": final["HostConfig"].get("PidsLimit"),
            "Tmpfs": final["HostConfig"].get("Tmpfs"),
        },
        "state": final["State"],
        "logs": logs,
        "timed_out": timed_out,
        "cancelled": cancelled,
        "cpu_effective_cores": cpu_result,
        "passed": (
            not issues_at_create
            and (not expect_timeout or timed_out)
            and (not cancel or cancelled)
            and (cpu_result is None or cpu_result <= profile.limits.cpu_cores + 0.35)
        ),
    }


def transport_acceptance(root: Path) -> dict[str, Any]:
    now = datetime(2026, 7, 16, 5, 30, tzinfo=UTC)
    authority = ControlPlaneTransportAuthority.generate()
    registry = TrustedTransportRegistry.empty()
    registry.add_pem(authority.public_key_pem)
    runner = RunnerEphemeralIdentity.generate()
    store = RunnerStore(root / "transport.sqlite3")
    scopes = tuple(command.value for command in RunnerCommand)
    credential = authority.issue(
        credential_id="credential.p2",
        run_id="run.transport",
        tenant_id="tenant.p2",
        runner_id="runner.forge",
        runner_public_key_pem=runner.public_key_pem,
        scopes=scopes,
        issued_at=now,
        ttl=timedelta(minutes=5),
    )
    store.create_lease(credential, registry, now=now, lease_ttl=timedelta(seconds=10))

    heartbeat = create_transport_request(
        request_id="heartbeat.1",
        credential=credential,
        nonce="nonce-transport-00000001",
        command=RunnerCommand.HEARTBEAT,
        sequence=1,
        issued_at=now,
        body={"health": "ok"},
    )
    store.heartbeat(heartbeat, registry, now=now + timedelta(seconds=1))
    replay_blocked = False
    try:
        store.heartbeat(heartbeat, registry, now=now + timedelta(seconds=2))
    except ReplayDetected:
        replay_blocked = True
    retry = create_transport_request(
        request_id="heartbeat.1",
        credential=credential,
        nonce="nonce-transport-00000002",
        command=RunnerCommand.HEARTBEAT,
        sequence=1,
        issued_at=now + timedelta(seconds=2),
        body={"health": "ok"},
    )
    idempotent_sequence = store.heartbeat(retry, registry, now=now + timedelta(seconds=2))["last_sequence"]

    transition1 = create_transport_request(
        request_id="transition.1",
        credential=credential,
        nonce="nonce-transport-00000003",
        command=RunnerCommand.TRANSITION,
        sequence=2,
        issued_at=now + timedelta(seconds=2),
        body={"to_state": "STARTING"},
    )
    store.transition(transition1, registry, to_state=RunnerLeaseState.STARTING, now=now + timedelta(seconds=2))
    transition2 = create_transport_request(
        request_id="transition.2",
        credential=credential,
        nonce="nonce-transport-00000004",
        command=RunnerCommand.TRANSITION,
        sequence=3,
        issued_at=now + timedelta(seconds=3),
        body={"to_state": "RUNNING"},
    )
    store.transition(transition2, registry, to_state=RunnerLeaseState.RUNNING, now=now + timedelta(seconds=3))

    evidence = b"evidence-stream"
    first_part, second_part = evidence[:8], evidence[8:]
    chunk1 = EvidenceChunk(
        artifact_id="artifact.transport",
        chunk_index=0,
        total_chunks=2,
        content_sha256=sha256_bytes(evidence),
        chunk_sha256=sha256_bytes(first_part),
        payload_b64=base64.b64encode(first_part).decode(),
    )
    evidence_request1 = create_transport_request(
        request_id="evidence.1",
        credential=credential,
        nonce="nonce-transport-00000005",
        command=RunnerCommand.EVIDENCE_CHUNK,
        sequence=4,
        issued_at=now + timedelta(seconds=3),
        body={"artifact_id": chunk1.artifact_id, "chunk_index": 0},
    )
    store.append_evidence_chunk(evidence_request1, registry, chunk1, now=now + timedelta(seconds=3))
    interrupted = store.evidence_status("run.transport", "tenant.p2", "artifact.transport")
    chunk2 = EvidenceChunk(
        artifact_id="artifact.transport",
        chunk_index=1,
        total_chunks=2,
        content_sha256=sha256_bytes(evidence),
        chunk_sha256=sha256_bytes(second_part),
        payload_b64=base64.b64encode(second_part).decode(),
    )
    evidence_request2 = create_transport_request(
        request_id="evidence.2",
        credential=credential,
        nonce="nonce-transport-00000006",
        command=RunnerCommand.EVIDENCE_CHUNK,
        sequence=5,
        issued_at=now + timedelta(seconds=4),
        body={"artifact_id": chunk2.artifact_id, "chunk_index": 1},
    )
    store.append_evidence_chunk(evidence_request2, registry, chunk2, now=now + timedelta(seconds=4))
    complete = store.evidence_status("run.transport", "tenant.p2", "artifact.transport")

    cancel = create_transport_request(
        request_id="cancel.1",
        credential=credential,
        nonce="nonce-transport-00000007",
        command=RunnerCommand.CANCEL,
        sequence=6,
        issued_at=now + timedelta(seconds=4),
        body={"reason": "acceptance"},
    )
    cancellation = store.request_cancellation(cancel, registry, reason="acceptance", now=now + timedelta(seconds=4))

    untrusted_blocked = False
    try:
        TrustedTransportRegistry.empty().verify(credential)
    except AuthenticationFailure:
        untrusted_blocked = True

    expired = authority.issue(
        credential_id="credential.expired",
        run_id="run.expired",
        tenant_id="tenant.p2",
        runner_id="runner.forge",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=now - timedelta(minutes=2),
        ttl=timedelta(minutes=1),
    )
    expired_blocked = False
    try:
        store.register_credential(expired, registry, now=now)
    except ExpiredCredential:
        expired_blocked = True

    orphan_runner = RunnerEphemeralIdentity.generate()
    orphan_credential = authority.issue(
        credential_id="credential.orphan",
        run_id="run.orphan",
        tenant_id="tenant.p2",
        runner_id="runner.orphan",
        runner_public_key_pem=orphan_runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=now,
        ttl=timedelta(minutes=1),
    )
    store.create_lease(orphan_credential, registry, now=now, lease_ttl=timedelta(seconds=2))
    orphaned = store.reap_orphans(now=now + timedelta(seconds=3))

    cross_tenant_blocked = False
    try:
        store.get_lease("run.transport", "tenant.other")
    except KeyError:
        cross_tenant_blocked = True

    archive_traversal_blocked = False
    archive_symlink_blocked = False
    archive_root = root / "archives"
    archive_root.mkdir(parents=True, exist_ok=True)
    traversal = archive_root / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "escape")
    try:
        extract_archive_safely(traversal, archive_root / "traversal-out", max_total_bytes=1024)
    except (IsolationFailure, ValueError):
        archive_traversal_blocked = not (archive_root / "escape.txt").exists()
    symlink_archive = archive_root / "symlink.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (0o120777 << 16)
    with zipfile.ZipFile(symlink_archive, "w") as archive:
        archive.writestr(link, "../outside")
    try:
        extract_archive_safely(symlink_archive, archive_root / "symlink-out", max_total_bytes=1024)
    except IsolationFailure:
        archive_symlink_blocked = True

    checks = {
        "untrusted_control_plane_blocked": untrusted_blocked,
        "expired_credential_blocked": expired_blocked,
        "replay_blocked": replay_blocked,
        "idempotent_retry_preserved_sequence": idempotent_sequence == 1,
        "evidence_interruption_detected": interrupted["complete"] is False,
        "evidence_completion_verified": complete["complete"] is True,
        "cancellation_recorded": cancellation["state"] is RunnerLeaseState.CANCELLING,
        "lost_heartbeat_reaped": orphaned == ["run.orphan"],
        "cross_tenant_read_blocked": cross_tenant_blocked,
        "archive_traversal_blocked": archive_traversal_blocked,
        "archive_symlink_blocked": archive_symlink_blocked,
        "transport_key_separated_from_runner_key": authority.key_id != runner.key_id,
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "transport_key_id": authority.key_id,
        "runner_key_id": runner.key_id,
        "evidence_status": complete,
        "orphaned_runs": orphaned,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    api = DockerAPI()
    owned_ids: set[str] = set()
    before_ids = api.container_ids()
    started_at = datetime.now(UTC)
    cases: dict[str, Any] = {}
    cleanup_errors: list[str] = []
    try:
        version = api.version()
        info = api.info()
        if api.ping() != "OK":
            raise RuntimeError("docker_ping_failed")
        profile = make_profile(args.image)
        isolation_command = (
            "sh",
            "-c",
            "set +e; "
            "echo uid=$(id -u); "
            "grep -E '^(CapEff|Seccomp|NoNewPrivs):' /proc/self/status; "
            "echo interfaces=$(ls /sys/class/net | tr '\\n' ','); "
            "echo root_mount=$(grep ' / ' /proc/mounts | head -1); "
            "echo memory_max=$(cat /sys/fs/cgroup/memory.max); "
            "echo pids_max=$(cat /sys/fs/cgroup/pids.max); "
            "echo cpu_max=$(cat /sys/fs/cgroup/cpu.max); "
            "if echo x >/certforge-root-write 2>/dev/null; then echo root_write=allowed; else echo root_write=denied; fi; "
            "if echo scratch >/tmp/scratch 2>/dev/null; then echo tmp_write=allowed; else echo tmp_write=denied; fi; "
            "if wget -T 2 -qO /tmp/exfil http://1.1.1.1 2>/dev/null; then echo exfil=allowed; else echo exfil=denied; fi",
        )
        cases["isolation"] = run_container_case(
            api,
            case="isolation",
            profile=profile,
            command=isolation_command,
            owned_ids=owned_ids,
        )
        isolation_logs = cases["isolation"]["logs"]
        cases["isolation"]["semantic_checks"] = {
            "non_root": "uid=65532" in isolation_logs,
            "capabilities_dropped": "CapEff:\t0000000000000000" in isolation_logs,
            "seccomp_enforced": "Seccomp:\t2" in isolation_logs,
            "no_new_privileges": "NoNewPrivs:\t1" in isolation_logs,
            "loopback_only": "interfaces=lo," in isolation_logs,
            "rootfs_write_denied": "root_write=denied" in isolation_logs,
            "tmpfs_writable_by_runner": "tmp_write=allowed" in isolation_logs,
            "network_exfiltration_denied": (
                "exfil=denied" in isolation_logs and "can't create /tmp/exfil" not in isolation_logs
            ),
            "memory_limit_visible": "memory_max=67108864" in isolation_logs,
            "pid_limit_visible": "pids_max=32" in isolation_logs,
        }
        cases["isolation"]["passed"] = cases["isolation"]["passed"] and all(
            cases["isolation"]["semantic_checks"].values()
        )

        cases["cpu_exhaustion"] = run_container_case(
            api,
            case="cpu",
            profile=profile,
            command=("sh", "-c", "while :; do :; done"),
            owned_ids=owned_ids,
            sample_cpu=True,
        )
        pid_profile = make_profile(args.image, pids=16)
        cases["pid_exhaustion"] = run_container_case(
            api,
            case="pids",
            profile=pid_profile,
            command=(
                "sh",
                "-c",
                "i=0; while [ $i -lt 64 ]; do sleep 10 & i=$((i+1)); done; wait",
            ),
            owned_ids=owned_ids,
            runtime_seconds=2.0,
        )
        pid_logs = cases["pid_exhaustion"]["logs"].lower()
        cases["pid_exhaustion"]["pid_denial_observed"] = (
            "can't fork" in pid_logs or "resource temporarily unavailable" in pid_logs
        )
        cases["pid_exhaustion"]["passed"] = (
            not cases["pid_exhaustion"]["created_inspect_issues"]
            and cases["pid_exhaustion"]["host_config"]["PidsLimit"] == 16
            and cases["pid_exhaustion"]["pid_denial_observed"]
        )
        cases["disk_fill"] = run_container_case(
            api,
            case="disk",
            profile=profile,
            command=(
                "sh",
                "-c",
                "set +e; dd if=/dev/zero of=/workspace/fill.bin bs=1M count=32 2>&1; "
                "echo dd_exit=$?; df -k /workspace",
            ),
            owned_ids=owned_ids,
        )
        disk_logs = cases["disk_fill"]["logs"].lower()
        cases["disk_fill"]["quota_denial_observed"] = (
            "no space left" in disk_logs or "file size limit" in disk_logs
        )
        cases["disk_fill"]["passed"] = (
            cases["disk_fill"]["passed"] and cases["disk_fill"]["quota_denial_observed"]
        )
        file_profile = make_profile(
            args.image,
            file_size_bytes=1024 * 1024,
            disk_bytes=8 * 1024 * 1024,
        )
        cases["file_size_limit"] = run_container_case(
            api,
            case="fsize",
            profile=file_profile,
            command=(
                "sh",
                "-c",
                "set +e; dd if=/dev/zero of=/workspace/file.bin bs=1M count=4 2>&1; "
                "echo dd_exit=$?; ls -l /workspace/file.bin 2>/dev/null || true",
            ),
            owned_ids=owned_ids,
        )
        file_logs = cases["file_size_limit"]["logs"].lower()
        cases["file_size_limit"]["file_size_denial_observed"] = (
            "file size limit" in file_logs or "dd_exit=153" in file_logs
        )
        cases["file_size_limit"]["passed"] = (
            cases["file_size_limit"]["passed"]
            and cases["file_size_limit"]["file_size_denial_observed"]
        )
        cases["hostile_install_script"] = run_container_case(
            api,
            case="install",
            profile=profile,
            command=(
                "sh",
                "-c",
                "set +e; echo install_started; "
                "if echo owned >/etc/certforge-owned 2>/dev/null; then echo root_mutation=allowed; else echo root_mutation=denied; fi; "
                "if wget -T 2 -qO /tmp/install-exfil http://1.1.1.1 2>/dev/null; then echo install_exfil=allowed; else echo install_exfil=denied; fi; "
                "echo install_finished",
            ),
            owned_ids=owned_ids,
        )
        install_logs = cases["hostile_install_script"]["logs"]
        cases["hostile_install_script"]["hostile_actions_denied"] = (
            "install_started" in install_logs
            and "root_mutation=denied" in install_logs
            and "install_exfil=denied" in install_logs
            and "can't create /tmp/install-exfil" not in install_logs
            and "install_finished" in install_logs
        )
        cases["hostile_install_script"]["passed"] = (
            cases["hostile_install_script"]["passed"]
            and cases["hostile_install_script"]["hostile_actions_denied"]
        )
        cases["timeout"] = run_container_case(
            api,
            case="timeout",
            profile=profile,
            command=("sh", "-c", "sleep 30"),
            owned_ids=owned_ids,
            expect_timeout=True,
            runtime_seconds=1.0,
        )
        cases["cancellation"] = run_container_case(
            api,
            case="cancel",
            profile=profile,
            command=("sh", "-c", "sleep 30"),
            owned_ids=owned_ids,
            cancel=True,
        )
        cases["runner_crash"] = run_container_case(
            api,
            case="crash",
            profile=profile,
            command=("sh", "-c", "kill -SEGV $$"),
            owned_ids=owned_ids,
        )
        cases["runner_crash"]["crash_observed"] = cases["runner_crash"]["state"].get("ExitCode") != 0
        cases["runner_crash"]["passed"] = (
            cases["runner_crash"]["passed"] and cases["runner_crash"]["crash_observed"]
        )

        with tempfile.TemporaryDirectory(prefix="certforge-p2-transport-") as temp:
            transport = transport_acceptance(Path(temp))

        all_case_passed = all(case["passed"] for case in cases.values())
        passed = all_case_passed and transport["passed"]
        report: dict[str, Any] = {
            "schema_version": "1.0.0",
            "phase": "P2",
            "run_outcome": "COMPLETE" if passed else "INCONCLUSIVE",
            "release_verdict": "NOT_READY",
            "started_at_utc": to_utc_iso(started_at),
            "completed_at_utc": to_utc_iso(datetime.now(UTC)),
            "host": {
                "node": platform.node(),
                "platform": platform.platform(),
                "python": sys.version,
                "uid": os.getuid(),
                "gid": os.getgid(),
            },
            "docker": {
                "version": version,
                "security_options": info.get("SecurityOptions"),
                "cgroup_version": info.get("CgroupVersion"),
                "cgroup_driver": info.get("CgroupDriver"),
                "storage_driver": info.get("Driver"),
                "docker_root_dir": info.get("DockerRootDir"),
                "containers_before": len(before_ids),
            },
            "runner_image_digest": args.image,
            "isolation_profile_digest": profile.identity_digest,
            "cases": cases,
            "transport": transport,
            "passed": passed,
        }
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema_version": "1.0.0",
            "phase": "P2",
            "run_outcome": "INFRA_FAILED",
            "release_verdict": "NOT_READY",
            "started_at_utc": to_utc_iso(started_at),
            "completed_at_utc": to_utc_iso(datetime.now(UTC)),
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "cases": cases,
            "passed": False,
        }
    finally:
        for container_id in sorted(owned_ids):
            try:
                api.remove(container_id)
            except Exception as exc:  # noqa: BLE001
                cleanup_errors.append(f"{container_id}:{type(exc).__name__}:{exc}")
        after_ids = api.container_ids()
        unrelated_preserved = before_ids == after_ids
        report["cleanup"] = {
            "owned_container_ids": sorted(owned_ids),
            "errors": cleanup_errors,
            "unrelated_container_ids_preserved": unrelated_preserved,
            "containers_after": len(after_ids),
        }
        report["passed"] = bool(report.get("passed")) and not cleanup_errors and unrelated_preserved
        if not report["passed"] and report.get("run_outcome") == "COMPLETE":
            report["run_outcome"] = "INCONCLUSIVE"
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        report["report_sha256"] = sha256_bytes(encoded.encode("utf-8"))
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
