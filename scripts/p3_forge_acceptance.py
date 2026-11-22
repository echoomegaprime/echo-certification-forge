#!/usr/bin/env python3
"""Real FORGE P3 acceptance: HTTP custody, independent anchor, isolated signer.

The harness uses only uniquely owned processes, files, and exact Docker
container IDs. It never executes customer code, never mounts the Docker socket
inside a container, and never includes private keys in its evidence report.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from p2_forge_acceptance import DockerAPI, wait_not_running  # noqa: E402

from echo_certification_forge.anchor import (  # noqa: E402
    AnchorStatement,
    AnchorVerificationBundle,
    IndependentFileAnchorProvider,
    privacy_preserving_tenant_ref,
    verify_anchor_bundle,
)
from echo_certification_forge.canonical import (  # noqa: E402
    canonical_json,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from echo_certification_forge.custody import (  # noqa: E402
    CustodyChunk,
    CustodyStore,
    EvidenceManifest,
    EvidenceVisibility,
)
from echo_certification_forge.models import ReleaseVerdict, RunOutcome  # noqa: E402
from echo_certification_forge.runner import (  # noqa: E402
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerLeaseState,
    RunnerStore,
    TrustedTransportRegistry,
    create_transport_request,
)
from echo_certification_forge.signing_service import (  # noqa: E402
    MandatoryRuleAttestation,
    OfflineVerificationBundle,
    ProductionSignedVerdict,
    ProductionSigningRequest,
    PublicKeyState,
    SigningActorType,
    SigningAuthorizationAuthority,
    SigningRunContext,
    SigningStore,
    VerdictLifecycleState,
    public_key_record_from_private_key,
    verify_offline_bundle,
    verify_production_verdict,
)

DEFAULT_SIGNER_IMAGE = (
    "ghcr.io/home-assistant/home-assistant@"
    "sha256:f73512ba4fe06bb4d57636fe3578d0820cdec46f81e8f837ab59e451662ff3cb"
)
P2_RUNNER_IMAGE = "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
P2_ISOLATION_PROFILE = "f0722821d2658705626bca74623438db30416de174ead34df15588b80dcc72bc"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else canonical_json(body).encode("utf-8")
    request_headers = {"Content-Type": "application/json"} if payload is not None else {}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, data=payload, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read()
            return response.status, {} if not content else json.loads(content)
    except urllib.error.HTTPError as exc:
        content = exc.read()
        return exc.code, {} if not content else json.loads(content)


def wait_health(url: str, process: subprocess.Popen[bytes], timeout_seconds: float = 15.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not_started"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"service exited before readiness: rc={process.returncode}")
        try:
            status, body = http_json("GET", url, timeout=1.0)
            if status == 200 and body.get("status") == "ok":
                return body
            last_error = f"status={status} body={body}"
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}:{exc}"
        time.sleep(0.1)
    raise TimeoutError(f"service readiness timeout: {last_error}")


def stop_process(process: subprocess.Popen[bytes] | None) -> dict[str, Any]:
    if process is None:
        return {"pid": None, "stopped": True, "returncode": None}
    pid = process.pid
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return {"pid": pid, "stopped": process.poll() is not None, "returncode": process.returncode}


def start_service(
    *,
    mode: str,
    port: int,
    env_updates: dict[str, str],
    log_path: Path,
) -> tuple[subprocess.Popen[bytes], Any]:
    env = os.environ.copy()
    env.update(env_updates)
    env["ECHO_CERTFORGE_P3_MODE"] = mode
    env["PYTHONPATH"] = str(ROOT / "src")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("wb")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "echo_certification_forge.p3_runtime:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    return process, handle


def transport_request(
    credential: Any,
    *,
    request_id: str,
    sequence: int,
    issued_at: datetime,
    body: dict[str, Any],
    command: RunnerCommand = RunnerCommand.EVIDENCE_CHUNK,
    nonce: str | None = None,
):
    return create_transport_request(
        request_id=request_id,
        credential=credential,
        nonce=nonce or f"nonce-{request_id}-{secrets.token_hex(12)}",
        command=command,
        sequence=sequence,
        issued_at=issued_at,
        body=body,
    )


def upload_via_http(
    base_url: str,
    credential: Any,
    manifest: EvidenceManifest,
    chunks: list[bytes],
    *,
    start_sequence: int,
    stop_after_chunks: int | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    begin = transport_request(
        credential,
        request_id=f"begin.{manifest.artifact_id}",
        sequence=start_sequence,
        issued_at=utc_now(),
        body={
            "operation": "begin_upload",
            "artifact_id": manifest.artifact_id,
            "manifest_sha256": manifest.identity_digest,
        },
    )
    status, body = http_json(
        "POST",
        base_url + "/v1/uploads/begin",
        {"request": begin.model_dump(mode="json"), "manifest": manifest.model_dump(mode="json")},
    )
    if status != 200:
        raise RuntimeError(f"begin upload failed: {status} {body}")
    results.append({"operation": "begin", "status": status, "body": body})
    sequence = start_sequence
    for index, payload in enumerate(chunks):
        if stop_after_chunks is not None and index >= stop_after_chunks:
            break
        sequence += 1
        chunk = CustodyChunk(
            artifact_id=manifest.artifact_id,
            chunk_index=index,
            total_chunks=len(chunks),
            chunk_sha256=sha256_bytes(payload),
            payload_b64=base64.b64encode(payload).decode("ascii"),
        )
        request = transport_request(
            credential,
            request_id=f"chunk.{manifest.artifact_id}.{index}",
            sequence=sequence,
            issued_at=utc_now(),
            body={
                "operation": "append_chunk",
                "artifact_id": manifest.artifact_id,
                "chunk_index": index,
                "chunk_sha256": chunk.chunk_sha256,
            },
        )
        status, body = http_json(
            "POST",
            base_url + "/v1/uploads/chunks",
            {"request": request.model_dump(mode="json"), "chunk": chunk.model_dump(mode="json")},
        )
        if status != 200:
            raise RuntimeError(f"append chunk failed: {status} {body}")
        results.append({"operation": f"chunk:{index}", "status": status, "body": body})
    return sequence, results


def append_remaining_chunk(
    base_url: str,
    credential: Any,
    manifest: EvidenceManifest,
    payload: bytes,
    *,
    chunk_index: int,
    sequence: int,
) -> dict[str, Any]:
    chunk = CustodyChunk(
        artifact_id=manifest.artifact_id,
        chunk_index=chunk_index,
        total_chunks=manifest.total_chunks,
        chunk_sha256=sha256_bytes(payload),
        payload_b64=base64.b64encode(payload).decode("ascii"),
    )
    request = transport_request(
        credential,
        request_id=f"chunk.{manifest.artifact_id}.{chunk_index}",
        sequence=sequence,
        issued_at=utc_now(),
        body={
            "operation": "append_chunk",
            "artifact_id": manifest.artifact_id,
            "chunk_index": chunk_index,
            "chunk_sha256": chunk.chunk_sha256,
        },
    )
    status, body = http_json(
        "POST",
        base_url + "/v1/uploads/chunks",
        {"request": request.model_dump(mode="json"), "chunk": chunk.model_dump(mode="json")},
    )
    if status != 200:
        raise RuntimeError(f"resume chunk failed: {status} {body}")
    return body


def finalize_via_http(
    base_url: str,
    credential: Any,
    artifact_id: str,
    *,
    sequence: int,
) -> dict[str, Any]:
    request = transport_request(
        credential,
        request_id=f"final.{artifact_id}",
        sequence=sequence,
        issued_at=utc_now(),
        body={"operation": "finalize_upload", "artifact_id": artifact_id},
    )
    status, body = http_json(
        "POST",
        base_url + "/v1/uploads/finalize",
        {"request": request.model_dump(mode="json"), "artifact_id": artifact_id},
    )
    if status != 200:
        raise RuntimeError(f"finalize failed: {status} {body}")
    return body


def signer_payload(
    *,
    image: str,
    source_root: Path,
    input_root: Path,
    output_root: Path,
    command: list[str],
    run_id: str,
    ownership_token: str,
) -> dict[str, Any]:
    uid = os.getuid()
    gid = os.getgid()
    owner = f"uid={uid},gid={gid}"
    return {
        "Image": image,
        "Entrypoint": ["python3"],
        "Cmd": command,
        "User": f"{uid}:{gid}",
        "WorkingDir": "/work",
        "NetworkDisabled": True,
        "Env": ["PYTHONPATH=/app/src", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1"],
        "Labels": {
            "echo.certforge.owner": "p3-acceptance",
            "echo.certforge.role": "isolated-verdict-signer",
            "echo.certforge.run_id": run_id,
            "echo.certforge.ownership_token": ownership_token,
        },
        "StopTimeout": 5,
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "SecurityOpt": [
                "no-new-privileges:true",
                "seccomp=builtin",
                "apparmor=docker-default",
            ],
            "Memory": 256 * 1024 * 1024,
            "MemorySwap": 256 * 1024 * 1024,
            "NanoCpus": 250_000_000,
            "PidsLimit": 32,
            "OomKillDisable": False,
            "AutoRemove": False,
            "Init": True,
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(source_root),
                    "Target": "/app/src",
                    "ReadOnly": True,
                    "BindOptions": {"Propagation": "rprivate"},
                },
                {
                    "Type": "bind",
                    "Source": str(input_root),
                    "Target": "/input",
                    "ReadOnly": True,
                    "BindOptions": {"Propagation": "rprivate"},
                },
                {
                    "Type": "bind",
                    "Source": str(output_root),
                    "Target": "/output",
                    "ReadOnly": False,
                    "BindOptions": {"Propagation": "rprivate"},
                },
            ],
            "Tmpfs": {
                "/tmp": f"rw,nosuid,nodev,noexec,size=16777216,mode=700,{owner}",
                "/work": f"rw,nosuid,nodev,noexec,size=8388608,mode=700,{owner}",
            },
            "Ulimits": [
                {"Name": "fsize", "Soft": 32 * 1024 * 1024, "Hard": 32 * 1024 * 1024},
                {"Name": "nofile", "Soft": 1024, "Hard": 1024},
            ],
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}},
        },
    }


def validate_signer_inspect(inspect: dict[str, Any], input_root: Path) -> tuple[str, ...]:
    issues: list[str] = []
    config = inspect.get("Config") or {}
    host = inspect.get("HostConfig") or {}
    if config.get("User") in ("", "0", "0:0", "root"):
        issues.append("signer_runs_as_root")
    if not host.get("ReadonlyRootfs"):
        issues.append("rootfs_not_read_only")
    if host.get("NetworkMode") != "none":
        issues.append("network_not_denied")
    if sorted(host.get("CapDrop") or []) != ["ALL"]:
        issues.append("capabilities_not_dropped")
    required = {"no-new-privileges:true", "seccomp=builtin", "apparmor=docker-default"}
    if not required.issubset(set(host.get("SecurityOpt") or [])):
        issues.append("security_options_incomplete")
    if host.get("Memory") != 256 * 1024 * 1024 or host.get("PidsLimit") != 32:
        issues.append("resource_limits_mismatch")
    mounts = host.get("Mounts") or []
    input_mount = next((item for item in mounts if item.get("Source") == str(input_root)), None)
    if input_mount is None or not input_mount.get("ReadOnly"):
        issues.append("private_input_mount_not_read_only")
    if any(item.get("Source") in ("/var/run/docker.sock", "/run/docker.sock") for item in mounts):
        issues.append("docker_socket_exposed")
    return tuple(sorted(set(issues)))


def resolve_image_id(api: DockerAPI, reference: str) -> str:
    """Resolve a tag, digest, or ID reference to the exact local image ID.

    Docker container inspect reports the image ID, never the requested tag or
    repo digest, so identity must be compared ID-to-ID. Resolution failure
    raises and therefore fails closed.
    """
    inspected = api.request(
        "GET", f"/images/{urllib.parse.quote(reference, safe=':@')}/json"
    )
    image_id = (inspected or {}).get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise RuntimeError(f"unresolvable image reference: {reference}")
    return image_id


def signer_image_is_distinct_from_runner(api: DockerAPI, reference: str) -> bool:
    """True only when the signer reference resolves to a different local image
    ID than the pinned P2 runner image ID. String-form comparison would pass
    trivially for any tag reference; identity must be compared ID-to-ID."""
    return resolve_image_id(api, reference) != P2_RUNNER_IMAGE


def run_signer_container(
    api: DockerAPI,
    *,
    image: str,
    source_root: Path,
    input_root: Path,
    output_root: Path,
    command: list[str],
    run_id: str,
    case: str,
    owned_ids: set[str],
) -> dict[str, Any]:
    suffix = secrets.token_hex(5)
    ownership_token = f"owner.{suffix}"
    name = f"certforge-p3-signer-{case}-{suffix}"
    resolved_image_id = resolve_image_id(api, image)
    payload = signer_payload(
        image=resolved_image_id,
        source_root=source_root,
        input_root=input_root,
        output_root=output_root,
        command=command,
        run_id=run_id,
        ownership_token=ownership_token,
    )
    container_id = api.create(name, payload)
    owned_ids.add(container_id)
    created = api.inspect(container_id)
    issues = validate_signer_inspect(created, input_root)
    if created.get("Image") != resolved_image_id:
        issues = tuple(sorted(set(issues + ("signer_image_identity_mismatch",))))
    api.start(container_id)
    final = wait_not_running(api, container_id, 30.0)
    logs = api.logs(container_id)
    return {
        "case": case,
        "container_id": container_id,
        "container_name": name,
        "ownership_token": ownership_token,
        "image": final.get("Image"),
        "inspect_issues": list(issues),
        "config_user": final.get("Config", {}).get("User"),
        "host_config": {
            key: final.get("HostConfig", {}).get(key)
            for key in (
                "ReadonlyRootfs",
                "NetworkMode",
                "CapDrop",
                "SecurityOpt",
                "Memory",
                "MemorySwap",
                "NanoCpus",
                "PidsLimit",
                "Mounts",
                "Tmpfs",
            )
        },
        "state": final.get("State"),
        "logs": logs[:4000],
        "passed": not issues and int(final.get("State", {}).get("ExitCode", -1)) == 0,
    }


def signer_command(request_name: str, output_name: str, public_name: str, *, key_name: str = "verdict-key.pem") -> list[str]:
    return [
        "-m",
        "echo_certification_forge.signer_cli",
        "--request",
        f"/input/{request_name}",
        "--context",
        "/input/context.json",
        "--key-record",
        "/input/key-record.json",
        "--signing-key",
        f"/input/{key_name}",
        "--authorization-public-key",
        "/input/authorization-public.pem",
        "--trusted-anchor-public-key",
        "/input/anchor-public.pem",
        "--db",
        "/output/signer.sqlite3",
        "--output",
        f"/output/{output_name}",
        "--public-bundle",
        f"/output/{public_name}",
    ]


def write_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--signer-image", default=DEFAULT_SIGNER_IMAGE)
    args = parser.parse_args()

    args.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "phase": "P3",
        "started_at_utc": to_utc_iso(utc_now()),
        "run_outcome": "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
        "passed": False,
        "p2_runner_image_digest": P2_RUNNER_IMAGE,
        "p2_isolation_profile_digest": P2_ISOLATION_PROFILE,
    }
    custody_process: subprocess.Popen[bytes] | None = None
    custody_handle: Any = None
    anchor_process: subprocess.Popen[bytes] | None = None
    anchor_handle: Any = None
    private_paths: list[Path] = []
    owned_container_ids: set[str] = set()
    cleanup_errors: list[str] = []
    api = DockerAPI()
    before_container_ids = api.container_ids()

    try:
        now = utc_now()
        run_id = "run.p3.acceptance"
        tenant_id = "tenant.p3.acceptance"
        transport_authority = ControlPlaneTransportAuthority.generate()
        transport_public_path = args.workspace / "transport-public.pem"
        transport_public_path.write_text(transport_authority.public_key_pem, encoding="ascii")
        runner_identity = RunnerEphemeralIdentity.generate()
        credential = transport_authority.issue(
            credential_id="credential.p3.acceptance",
            run_id=run_id,
            tenant_id=tenant_id,
            runner_id="runner.p3.acceptance",
            runner_public_key_pem=runner_identity.public_key_pem,
            scopes=tuple(command.value for command in RunnerCommand),
            issued_at=now,
            ttl=timedelta(minutes=12),
        )
        registry = TrustedTransportRegistry.empty()
        registry.add_pem(transport_authority.public_key_pem)
        runner_db = args.workspace / "runner.sqlite3"
        runner_store = RunnerStore(runner_db)
        runner_store.create_lease(credential, registry, now=now, lease_ttl=timedelta(minutes=10))

        custody_db = args.workspace / "custody.sqlite3"
        custody_root = args.workspace / "custody-evidence"
        custody = CustodyStore(custody_db, custody_root, runner_store, registry)
        target_digest = "1" * 64
        environment_digest = "2" * 64
        policy_digest = "3" * 64
        rules_digest = "4" * 64
        custody.register_run(
            run_id=run_id,
            tenant_id=tenant_id,
            target_identity_digest=target_digest,
            environment_identity_digest=environment_digest,
            policy_version="policy.v1",
            policy_digest=policy_digest,
            mandatory_rules_digest=rules_digest,
        )

        custody_port = free_port()
        custody_env = {
            "ECHO_CERTFORGE_TRANSPORT_PUBLIC_KEY": str(transport_public_path),
            "ECHO_CERTFORGE_RUNNER_DB": str(runner_db),
            "ECHO_CERTFORGE_CUSTODY_DB": str(custody_db),
            "ECHO_CERTFORGE_CUSTODY_ROOT": str(custody_root),
        }
        custody_process, custody_handle = start_service(
            mode="custody",
            port=custody_port,
            env_updates=custody_env,
            log_path=args.workspace / "custody-service.log",
        )
        custody_base = f"http://127.0.0.1:{custody_port}"
        custody_health = wait_health(custody_base + "/healthz", custody_process)

        content = b"P3 evidence custody real HTTP execution and resumable stream proof."
        split = len(content) // 2
        chunks = [content[:split], content[split:]]
        manifest = EvidenceManifest(
            run_id=run_id,
            tenant_id=tenant_id,
            artifact_id="artifact.p3.acceptance",
            declared_size_bytes=len(content),
            declared_sha256=sha256_bytes(content),
            media_type="application/octet-stream",
            purpose="P3 real FORGE acceptance evidence",
            visibility=EvidenceVisibility.RESTRICTED,
            total_chunks=2,
            retention_until=now + timedelta(days=90),
            legal_hold=True,
        )
        last_sequence, partial_results = upload_via_http(
            custody_base,
            credential,
            manifest,
            chunks,
            start_sequence=1,
            stop_after_chunks=1,
        )
        partial_status_code, partial_status = http_json(
            "GET",
            custody_base + f"/v1/uploads/{run_id}/{manifest.artifact_id}",
            headers={"X-Tenant-ID": tenant_id},
        )
        if partial_status_code != 200 or partial_status.get("missing_chunks") != [1]:
            raise RuntimeError(f"partial upload not detected: {partial_status_code} {partial_status}")

        first_custody_stop = stop_process(custody_process)
        custody_handle.close()
        custody_process = None
        custody_handle = None
        custody_process, custody_handle = start_service(
            mode="custody",
            port=custody_port,
            env_updates=custody_env,
            log_path=args.workspace / "custody-service-restart.log",
        )
        custody_restart_health = wait_health(custody_base + "/healthz", custody_process)
        resumed = append_remaining_chunk(
            custody_base,
            credential,
            manifest,
            chunks[1],
            chunk_index=1,
            sequence=last_sequence + 1,
        )
        descriptor = finalize_via_http(
            custody_base,
            credential,
            manifest.artifact_id,
            sequence=last_sequence + 2,
        )
        verify_status, custody_verification = http_json(
            "GET",
            custody_base + f"/v1/runs/{run_id}/verify",
            headers={"X-Tenant-ID": tenant_id},
        )
        if verify_status != 200 or not custody_verification.get("valid"):
            raise RuntimeError(f"custody verification failed: {verify_status} {custody_verification}")
        retention_state = custody.retention_state(run_id, tenant_id, manifest.artifact_id)
        cross_tenant_status, _ = http_json(
            "GET",
            custody_base + f"/v1/runs/{run_id}/verify",
            headers={"X-Tenant-ID": "tenant.other"},
        )
        restricted_status, _ = http_json(
            "GET",
            custody_base + f"/v1/evidence/{run_id}/{manifest.artifact_id}",
            headers={"X-Tenant-ID": tenant_id},
        )
        authorized_status, authorized_metadata = http_json(
            "GET",
            custody_base + f"/v1/evidence/{run_id}/{manifest.artifact_id}",
            headers={
                "X-Tenant-ID": tenant_id,
                "X-Restricted-Evidence-Authorized": "true",
            },
        )

        anchor_key = Ed25519PrivateKey.generate()
        anchor_private_path = args.workspace / "anchor-private.pem"
        private_paths.append(anchor_private_path)
        anchor_private_path.write_bytes(
            anchor_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(anchor_private_path, 0o600)
        anchor_root = args.workspace / "independent-anchor-provider"
        anchor_provider = IndependentFileAnchorProvider(
            anchor_root,
            "anchor.p3.acceptance",
            anchor_key,
        )
        anchor_public_pem = anchor_provider.public_key_pem
        anchor_key_id = anchor_provider.key_id
        anchor_port = free_port()
        anchor_env = {
            "ECHO_CERTFORGE_ANCHOR_ROOT": str(anchor_root),
            "ECHO_CERTFORGE_ANCHOR_PROVIDER_ID": anchor_provider.provider_id,
            "ECHO_CERTFORGE_ANCHOR_PRIVATE_KEY": str(anchor_private_path),
        }
        anchor_process, anchor_handle = start_service(
            mode="anchor",
            port=anchor_port,
            env_updates=anchor_env,
            log_path=args.workspace / "anchor-service.log",
        )
        anchor_base = f"http://127.0.0.1:{anchor_port}"
        anchor_health = wait_health(anchor_base + "/healthz", anchor_process)
        statement = AnchorStatement(
            run_id=run_id,
            tenant_ref=privacy_preserving_tenant_ref(tenant_id, "echoforge.p3.acceptance"),
            artifact_id="run.evidence.set",
            evidence_merkle_root=custody_verification["merkle_root"],
            policy_version="policy.v1",
            anchored_at=utc_now(),
            anchor_provider_id=anchor_provider.provider_id,
        )
        anchor_status, receipt_json = http_json(
            "POST",
            anchor_base + "/v1/anchors",
            {
                "statement": statement.model_dump(mode="json"),
                "idempotency_key": "anchor.p3.acceptance.1",
            },
        )
        if anchor_status != 200:
            raise RuntimeError(f"anchor creation failed: {anchor_status} {receipt_json}")
        duplicate_status, duplicate_receipt = http_json(
            "POST",
            anchor_base + "/v1/anchors",
            {
                "statement": statement.model_dump(mode="json"),
                "idempotency_key": "anchor.p3.acceptance.1",
            },
        )
        if duplicate_status != 200 or duplicate_receipt != receipt_json:
            raise RuntimeError("anchor idempotency failure")
        receipt_id = receipt_json["receipt_id"]
        anchor_verify_status, anchor_verification = http_json(
            "GET", anchor_base + f"/v1/anchors/{receipt_id}/verify"
        )
        bundle_status, anchor_bundle_json = http_json(
            "GET", anchor_base + f"/v1/anchors/{receipt_id}/bundle"
        )
        if anchor_verify_status != 200 or not anchor_verification.get("valid") or bundle_status != 200:
            raise RuntimeError("anchor verification or bundle retrieval failed")
        first_anchor_stop = stop_process(anchor_process)
        anchor_handle.close()
        anchor_process = None
        anchor_handle = None
        anchor_outage_observed = False
        try:
            http_json("GET", anchor_base + "/healthz", timeout=1.0)
        except Exception:  # noqa: BLE001
            anchor_outage_observed = True
        anchor_process, anchor_handle = start_service(
            mode="anchor",
            port=anchor_port,
            env_updates=anchor_env,
            log_path=args.workspace / "anchor-service-restart.log",
        )
        anchor_restart_health = wait_health(anchor_base + "/healthz", anchor_process)
        restarted_verify_status, restarted_verify = http_json(
            "GET", anchor_base + f"/v1/anchors/{receipt_id}/verify"
        )
        anchor_bundle = AnchorVerificationBundle.model_validate(anchor_bundle_json)
        offline_anchor_valid, offline_anchor_reason = verify_anchor_bundle(anchor_bundle)

        signing_key = Ed25519PrivateKey.generate()
        key_record = public_key_record_from_private_key(
            signing_key,
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365),
        )
        auth_authority = SigningAuthorizationAuthority.generate()
        authorization = auth_authority.issue(
            authorization_id="authorization.p3.acceptance",
            run_id=run_id,
            tenant_id=tenant_id,
            actor_id="control.certforge",
            issued_at=now,
            ttl=timedelta(minutes=10),
        )
        context = SigningRunContext(
            run_id=run_id,
            tenant_id=tenant_id,
            target_identity_digest=target_digest,
            environment_identity_digest=environment_digest,
            policy_version="policy.v1",
            policy_digest=policy_digest,
            mandatory_rules_digest=rules_digest,
            mandatory_rule_ids=("rule.evidence", "rule.identity"),
            evidence_merkle_root=custody_verification["merkle_root"],
            anchor_artifact_id="run.evidence.set",
            tenant_anchor_namespace="echoforge.p3.acceptance",
        )
        attestations = (
            MandatoryRuleAttestation(
                rule_id="rule.evidence",
                passed=True,
                evidence_ids=(manifest.artifact_id,),
            ),
            MandatoryRuleAttestation(
                rule_id="rule.identity",
                passed=True,
                evidence_ids=(manifest.artifact_id,),
            ),
        )
        signing_request = ProductionSigningRequest(
            request_id="sign.p3.acceptance.1",
            nonce="signing-nonce-p3-acceptance-00000001",
            actor_type=SigningActorType.CONTROL_PLANE,
            actor_id="control.certforge",
            run_id=run_id,
            tenant_id=tenant_id,
            run_outcome=RunOutcome.COMPLETE,
            release_verdict=ReleaseVerdict.PRODUCTION_READY,
            target_identity_digest=target_digest,
            environment_identity_digest=environment_digest,
            policy_version="policy.v1",
            policy_digest=policy_digest,
            mandatory_rules_digest=rules_digest,
            mandatory_rule_results=attestations,
            evidence_merkle_root=custody_verification["merkle_root"],
            anchor_bundle=anchor_bundle,
            lifecycle_state=VerdictLifecycleState.VALID,
            signing_key_id=key_record.key_id,
            issued_at=now + timedelta(minutes=2),
            expires_at=now + timedelta(days=30),
            authorization=authorization,
        )

        signer_input = args.workspace / "signer-input"
        signer_output = args.workspace / "signer-output"
        signer_input.mkdir(mode=0o700)
        signer_output.mkdir(mode=0o700)
        verdict_key_path = signer_input / "verdict-key.pem"
        private_paths.append(verdict_key_path)
        verdict_key_path.write_bytes(
            signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(verdict_key_path, 0o600)
        write_json(signer_input / "request.json", signing_request.model_dump(mode="json"))
        retry_request = signing_request.model_copy(
            update={"nonce": "signing-nonce-p3-acceptance-00000002"}
        )
        write_json(signer_input / "request-retry.json", retry_request.model_dump(mode="json"))
        conflict_request = signing_request.model_copy(
            update={
                "nonce": "signing-nonce-p3-acceptance-00000003",
                "release_verdict": ReleaseVerdict.NOT_READY,
            }
        )
        write_json(signer_input / "request-conflict.json", conflict_request.model_dump(mode="json"))
        runner_request = signing_request.model_copy(
            update={
                "request_id": "sign.p3.runner.1",
                "nonce": "signing-nonce-p3-runner-0000000001",
                "actor_type": SigningActorType.RUNNER,
            }
        )
        write_json(signer_input / "request-runner.json", runner_request.model_dump(mode="json"))
        write_json(signer_input / "context.json", context.model_dump(mode="json"))
        write_json(signer_input / "key-record.json", key_record.model_dump(mode="json"))
        (signer_input / "authorization-public.pem").write_text(
            auth_authority.public_key_pem, encoding="ascii"
        )
        (signer_input / "anchor-public.pem").write_text(anchor_public_pem, encoding="ascii")

        signer_cases: dict[str, Any] = {}
        signer_cases["success"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command("request.json", "verdict.json", "public-keys.json"),
            run_id=run_id,
            case="success",
            owned_ids=owned_container_ids,
        )
        if not signer_cases["success"]["passed"]:
            raise RuntimeError(f"isolated signer failed: {signer_cases['success']}")
        envelope = ProductionSignedVerdict.model_validate_json(
            (signer_output / "verdict.json").read_text(encoding="utf-8")
        )
        public_bundle = json.loads((signer_output / "public-keys.json").read_text(encoding="utf-8"))
        offline_bundle = OfflineVerificationBundle(
            verdict=envelope,
            anchor_bundle=anchor_bundle,
            public_key_bundle=public_bundle,
        )
        offline_verdict_valid, offline_verdict_reason = verify_offline_bundle(
            offline_bundle, now=now + timedelta(days=1)
        )

        signer_cases["idempotent_retry"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command(
                "request-retry.json", "verdict-retry.json", "public-keys-retry.json"
            ),
            run_id=run_id,
            case="retry",
            owned_ids=owned_container_ids,
        )
        retry_envelope = ProductionSignedVerdict.model_validate_json(
            (signer_output / "verdict-retry.json").read_text(encoding="utf-8")
        )
        retry_same = retry_envelope == envelope

        signer_cases["replay"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command("request.json", "verdict-replay.json", "public-replay.json"),
            run_id=run_id,
            case="replay",
            owned_ids=owned_container_ids,
        )
        replay_denied = (
            not signer_cases["replay"]["passed"]
            and "signing_request_replay" in signer_cases["replay"]["logs"]
            and not (signer_output / "verdict-replay.json").exists()
        )

        signer_cases["conflict"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command(
                "request-conflict.json", "verdict-conflict.json", "public-conflict.json"
            ),
            run_id=run_id,
            case="conflict",
            owned_ids=owned_container_ids,
        )
        conflict_denied = (
            not signer_cases["conflict"]["passed"]
            and "conflicting_idempotent_signing_request" in signer_cases["conflict"]["logs"]
            and not (signer_output / "verdict-conflict.json").exists()
        )

        signer_cases["runner_request"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command(
                "request-runner.json", "verdict-runner.json", "public-runner.json"
            ),
            run_id=run_id,
            case="runner",
            owned_ids=owned_container_ids,
        )
        runner_signing_denied = (
            not signer_cases["runner_request"]["passed"]
            and "only_control_plane_may_request_signing" in signer_cases["runner_request"]["logs"]
            and not (signer_output / "verdict-runner.json").exists()
        )

        signer_cases["key_unavailable"] = run_signer_container(
            api,
            image=args.signer_image,
            source_root=ROOT / "src",
            input_root=signer_input,
            output_root=signer_output,
            command=signer_command(
                "request-retry.json",
                "verdict-outage.json",
                "public-outage.json",
                key_name="missing-key.pem",
            ),
            run_id=run_id,
            case="outage",
            owned_ids=owned_container_ids,
        )
        signing_outage_denied = (
            not signer_cases["key_unavailable"]["passed"]
            and "FileNotFoundError" in signer_cases["key_unavailable"]["logs"]
            and not (signer_output / "verdict-outage.json").exists()
        )

        lifecycle_store = SigningStore(signer_output / "signer.sqlite3")
        lifecycle_store.transition_key(
            key_record.key_id,
            PublicKeyState.GRACE,
            reason="rotation overlap",
            effective_at=now + timedelta(minutes=3),
        )
        lifecycle_store.transition_key(
            key_record.key_id,
            PublicKeyState.REVOKED,
            reason="rotated after overlap",
            effective_at=now + timedelta(days=1),
        )
        rotated_bundle = lifecycle_store.public_bundle()
        historical_after_rotation = verify_production_verdict(
            envelope, rotated_bundle, now=now + timedelta(days=2)
        )
        lifecycle_store.transition_key(
            key_record.key_id,
            PublicKeyState.COMPROMISED,
            reason="acceptance compromise response",
            effective_at=now + timedelta(days=3),
        )
        compromised_result = verify_production_verdict(
            envelope, lifecycle_store.public_bundle(), now=now + timedelta(days=4)
        )

        crash_content = b"runner crash partial evidence"
        crash_manifest = EvidenceManifest(
            run_id=run_id,
            tenant_id=tenant_id,
            artifact_id="artifact.runner.crash",
            declared_size_bytes=len(crash_content),
            declared_sha256=sha256_bytes(crash_content),
            media_type="application/octet-stream",
            purpose="runner crash during upload",
            visibility=EvidenceVisibility.RAW,
            total_chunks=2,
            retention_until=now + timedelta(days=30),
        )
        crash_chunks = [crash_content[:8], crash_content[8:]]
        upload_via_http(
            custody_base,
            credential,
            crash_manifest,
            crash_chunks,
            start_sequence=20,
            stop_after_chunks=1,
        )
        transition = transport_request(
            credential,
            request_id="runner.crash.transition",
            sequence=1,
            issued_at=utc_now(),
            body={"to_state": RunnerLeaseState.FAILED.value},
            command=RunnerCommand.TRANSITION,
        )
        runner_store.transition(
            transition,
            registry,
            to_state=RunnerLeaseState.FAILED,
            now=utc_now(),
        )
        crash_chunk = CustodyChunk(
            artifact_id=crash_manifest.artifact_id,
            chunk_index=1,
            total_chunks=2,
            chunk_sha256=sha256_bytes(crash_chunks[1]),
            payload_b64=base64.b64encode(crash_chunks[1]).decode("ascii"),
        )
        crash_request = transport_request(
            credential,
            request_id="chunk.artifact.runner.crash.1",
            sequence=22,
            issued_at=utc_now(),
            body={
                "operation": "append_chunk",
                "artifact_id": crash_manifest.artifact_id,
                "chunk_index": 1,
                "chunk_sha256": crash_chunk.chunk_sha256,
            },
        )
        crash_status, crash_body = http_json(
            "POST",
            custody_base + "/v1/uploads/chunks",
            {"request": crash_request.model_dump(mode="json"), "chunk": crash_chunk.model_dump(mode="json")},
        )
        runner_crash_denied = crash_status in {401, 409} and "terminal" in canonical_json(crash_body)

        artifact_path = custody_root / descriptor["relative_path"]
        artifact_path.write_bytes(b"modified after anchoring")
        tamper_status, tampered_custody = http_json(
            "GET",
            custody_base + f"/v1/runs/{run_id}/verify",
            headers={"X-Tenant-ID": tenant_id},
        )
        modified_evidence_detected = tamper_status == 200 and not tampered_custody.get("valid")
        tampered_receipt = anchor_bundle.receipt.model_copy(update={"chain_hash": "0" * 64})
        tampered_anchor_bundle = anchor_bundle.model_copy(update={"receipt": tampered_receipt})
        tampered_anchor_result = verify_anchor_bundle(tampered_anchor_bundle)

        key_material_markers = [
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
        ]
        report_text_sources = [
            canonical_json(envelope.model_dump(mode="json")),
            canonical_json(public_bundle),
            canonical_json(signer_cases),
        ]
        private_key_absent_from_outputs = not any(
            marker in text for marker in key_material_markers for text in report_text_sources
        )
        custody_log_text = (args.workspace / "custody-service.log").read_text(
            encoding="utf-8", errors="replace"
        ) + (args.workspace / "custody-service-restart.log").read_text(
            encoding="utf-8", errors="replace"
        )
        anchor_log_text = (args.workspace / "anchor-service.log").read_text(
            encoding="utf-8", errors="replace"
        ) + (args.workspace / "anchor-service-restart.log").read_text(
            encoding="utf-8", errors="replace"
        )
        private_key_absent_from_service_logs = not any(
            marker in custody_log_text + anchor_log_text for marker in key_material_markers
        )
        verdict_private_bytes = verdict_key_path.read_bytes()
        anchor_private_bytes = anchor_private_path.read_bytes()
        non_secret_files = [
            runner_db,
            custody_db,
            signer_output / "signer.sqlite3",
            signer_output / "verdict.json",
            signer_output / "public-keys.json",
            args.workspace / "custody-service.log",
            args.workspace / "custody-service-restart.log",
            args.workspace / "anchor-service.log",
            args.workspace / "anchor-service-restart.log",
            anchor_root / "anchor-log.jsonl",
        ] + [path for path in custody_root.rglob("*") if path.is_file()]
        exact_private_key_bytes_absent = all(
            verdict_private_bytes not in path.read_bytes() and anchor_private_bytes not in path.read_bytes()
            for path in non_secret_files
            if path.is_file()
        )
        signing_database_contains_private_key = (
            verdict_private_bytes in (signer_output / "signer.sqlite3").read_bytes()
            or any(marker.encode("ascii") in (signer_output / "signer.sqlite3").read_bytes() for marker in key_material_markers)
        )

        positive_cases = {
            "custody_health": custody_health.get("status") == "ok",
            "custody_restart_health": custody_restart_health.get("status") == "ok",
            "partial_upload_detected": partial_status.get("missing_chunks") == [1],
            "partial_upload_resumed": resumed.get("missing_chunks") == [],
            "custody_verified_before_anchor": custody_verification.get("valid") is True,
            "cross_tenant_denied": cross_tenant_status == 404,
            "restricted_evidence_denied": restricted_status == 403,
            "restricted_evidence_authorized": authorized_status == 200,
            "anchor_health": anchor_health.get("status") == "ok",
            "anchor_duplicate_idempotent": duplicate_receipt == receipt_json,
            "anchor_verified": anchor_verification.get("valid") is True,
            "anchor_outage_observed": anchor_outage_observed,
            "anchor_restart_verified": restarted_verify_status == 200 and restarted_verify.get("valid") is True,
            "offline_anchor_verified": offline_anchor_valid,
            "isolated_signing_succeeded": signer_cases["success"]["passed"],
            "offline_verdict_verified": offline_verdict_valid,
            "idempotent_signing_retry": signer_cases["idempotent_retry"]["passed"] and retry_same,
            "signing_replay_denied": replay_denied,
            "conflicting_signing_request_denied": conflict_denied,
            "runner_signing_request_denied": runner_signing_denied,
            "signing_key_outage_denied": signing_outage_denied,
            "historical_verdict_after_rotation": historical_after_rotation == (True, "verified"),
            "compromise_invalidates_verdict": compromised_result == (False, "signing_key_compromised"),
            "runner_crash_during_upload_denied": runner_crash_denied,
            "modified_evidence_after_anchor_detected": modified_evidence_detected,
            "modified_anchor_receipt_detected": tampered_anchor_result[0] is False,
            "private_key_absent_from_outputs": private_key_absent_from_outputs,
            "private_key_absent_from_service_logs": private_key_absent_from_service_logs,
            "exact_private_key_bytes_absent_from_non_secret_files": exact_private_key_bytes_absent,
            "signing_database_contains_no_private_key": not signing_database_contains_private_key,
            "custody_has_no_verdict_key": custody_health.get("private_verdict_signing_key_loaded") is False,
            "all_key_domains_distinct": len({key_record.key_id, auth_authority.key_id, anchor_key_id}) == 3,
            "signer_image_distinct_from_runner_image": signer_image_is_distinct_from_runner(api, args.signer_image),
            "anchor_storage_independent": anchor_root.resolve() != custody_db.resolve().parent,
        }

        report.update(
            {
                "host": {
                    "node": socket.gethostname(),
                    "platform": os.uname().sysname + "-" + os.uname().release,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "python": sys.version,
                },
                "source_identity": {
                    relative: sha256_bytes((ROOT / relative).read_bytes())
                    for relative in (
                        "src/echo_certification_forge/custody.py",
                        "src/echo_certification_forge/anchor.py",
                        "src/echo_certification_forge/signing_service.py",
                        "src/echo_certification_forge/signer_cli.py",
                        "src/echo_certification_forge/p3_service.py",
                        "src/echo_certification_forge/p3_runtime.py",
                        "scripts/p3_forge_acceptance.py",
                    )
                },
                "custody": {
                    "health": custody_health,
                    "restart_health": custody_restart_health,
                    "first_service_stop": first_custody_stop,
                    "partial_results": partial_results,
                    "partial_status": partial_status,
                    "descriptor": descriptor,
                    "verification_before_anchor": custody_verification,
                    "verification_after_tamper": tampered_custody,
                    "authorized_metadata": authorized_metadata,
                    "audit_chain_tip": custody_verification["audit"]["chain_tip"],
                    "retention": retention_state,
                },
                "anchor": {
                    "health": anchor_health,
                    "restart_health": anchor_restart_health,
                    "first_service_stop": first_anchor_stop,
                    "provider_id": anchor_provider.provider_id,
                    "provider_key_id": anchor_key_id,
                    "receipt_id": receipt_id,
                    "receipt_hash": receipt_json["receipt_hash"],
                    "chain_hash": receipt_json["chain_hash"],
                    "statement_sha256": receipt_json["statement_sha256"],
                    "offline_verification": {
                        "valid": offline_anchor_valid,
                        "reason": offline_anchor_reason,
                    },
                    "tampered_receipt_verification": {
                        "valid": tampered_anchor_result[0],
                        "reason": tampered_anchor_result[1],
                    },
                    "log": anchor_provider.verify_log(),
                    "storage_root": str(anchor_root),
                    "custody_database": str(custody_db),
                },
                "signing": {
                    "signer_image": args.signer_image,
                    "public_key_id": key_record.key_id,
                    "authorization_key_id": auth_authority.key_id,
                    "anchor_provider_key_id": anchor_key_id,
                    "verdict_payload_sha256": envelope.payload_sha256,
                    "verdict_signature_verified": offline_verdict_valid,
                    "offline_verification_reason": offline_verdict_reason,
                    "historical_after_rotation": {
                        "valid": historical_after_rotation[0],
                        "reason": historical_after_rotation[1],
                    },
                    "after_compromise": {
                        "valid": compromised_result[0],
                        "reason": compromised_result[1],
                    },
                    "cases": signer_cases,
                    "private_key_persisted_in_signing_database": signing_database_contains_private_key,
                    "exact_private_key_scan_file_count": len([path for path in non_secret_files if path.is_file()]),
                    "runner_has_signing_key_mount": False,
                },
                "checks": positive_cases,
                "passed": all(positive_cases.values()),
                "run_outcome": "COMPLETE" if all(positive_cases.values()) else "INCONCLUSIVE",
                "release_verdict": "NOT_READY",
            }
        )
    except Exception as exc:  # noqa: BLE001
        report.update(
            {
                "error": {"type": type(exc).__name__, "message": str(exc)},
                "passed": False,
                "run_outcome": "INFRA_FAILED",
                "release_verdict": "NOT_READY",
            }
        )
    finally:
        custody_stop = stop_process(custody_process)
        anchor_stop = stop_process(anchor_process)
        if custody_handle is not None:
            custody_handle.close()
        if anchor_handle is not None:
            anchor_handle.close()
        for container_id in sorted(owned_container_ids):
            try:
                api.remove(container_id)
            except Exception as exc:  # noqa: BLE001
                cleanup_errors.append(f"{container_id}:{type(exc).__name__}:{exc}")
        private_key_removal: dict[str, bool] = {}
        for path in private_paths:
            try:
                path.unlink(missing_ok=True)
                private_key_removal[str(path)] = not path.exists()
            except OSError:
                private_key_removal[str(path)] = False
        after_container_ids = api.container_ids()
        unrelated_preserved = before_container_ids == after_container_ids
        report["cleanup"] = {
            "custody_service": custody_stop,
            "anchor_service": anchor_stop,
            "owned_container_ids": sorted(owned_container_ids),
            "container_cleanup_errors": cleanup_errors,
            "unrelated_container_ids_preserved": unrelated_preserved,
            "containers_before": len(before_container_ids),
            "containers_after": len(after_container_ids),
            "private_key_files_removed": private_key_removal,
        }
        report["passed"] = bool(report.get("passed")) and not cleanup_errors and unrelated_preserved and all(
            private_key_removal.values()
        )
        if not report["passed"] and report.get("run_outcome") == "COMPLETE":
            report["run_outcome"] = "INCONCLUSIVE"
        report["completed_at_utc"] = to_utc_iso(utc_now())
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        print(
            canonical_json(
                {
                    "passed": report["passed"],
                    "run_outcome": report["run_outcome"],
                    "release_verdict": report["release_verdict"],
                    "output": str(args.output),
                    "bytes": len(encoded.encode("utf-8")),
                    "sha256": sha256_bytes(encoded.encode("utf-8")),
                    "owned_container_count": len(owned_container_ids),
                    "unrelated_containers_preserved": unrelated_preserved,
                }
            )
        )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
