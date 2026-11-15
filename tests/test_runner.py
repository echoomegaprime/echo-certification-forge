from __future__ import annotations

import base64
import io
import json
import os
import sqlite3
import stat
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from echo_certification_forge.canonical import sha256_bytes, sha256_json
from echo_certification_forge.runner import (
    AuthenticationFailure,
    ControlPlaneTransportAuthority,
    EvidenceChunk,
    ExpiredCredential,
    IsolationFailure,
    IsolationProfile,
    LeaseFailure,
    ReplayDetected,
    RequestConflict,
    ResourceLimits,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerLeaseState,
    RunnerResponse,
    RunnerStore,
    SignedRunCredential,
    TransportRequest,
    TrustedTransportRegistry,
    assert_no_symlinks,
    build_docker_create_payload,
    create_transport_request,
    extract_archive_safely,
    prepare_workspace,
    validate_docker_inspect,
    verify_runner_response,
    verify_workspace_owner,
)

NOW = datetime(2026, 7, 16, 5, 30, tzinfo=UTC)
IMAGE = "sha256:" + "1" * 64


def limits(**overrides: object) -> ResourceLimits:
    values: dict[str, object] = {
        "cpu_cores": 0.5,
        "memory_bytes": 64 * 1024 * 1024,
        "pids": 32,
        "disk_bytes": 8 * 1024 * 1024,
        "file_size_bytes": 2 * 1024 * 1024,
        "wall_time_seconds": 5,
        "heartbeat_interval_seconds": 2,
        "lease_ttl_seconds": 10,
    }
    values.update(overrides)
    return ResourceLimits(**values)


def profile(**overrides: object) -> IsolationProfile:
    values: dict[str, object] = {
        "profile_id": "certforge.p2",
        "profile_version": "1.0.0",
        "image_digest": IMAGE,
        "user": "65532:65532",
        "limits": limits(),
    }
    values.update(overrides)
    return IsolationProfile(**values)


class Fixture:
    def __init__(self, tmp_path: Path, *, ttl: timedelta = timedelta(minutes=5)) -> None:
        self.authority = ControlPlaneTransportAuthority.generate()
        self.registry = TrustedTransportRegistry.empty()
        self.registry.add_pem(self.authority.public_key_pem)
        self.runner = RunnerEphemeralIdentity.generate()
        self.store = RunnerStore(tmp_path / "runner.sqlite3")
        self.credential = self.authority.issue(
            credential_id="credential.1",
            run_id="run.1",
            tenant_id="tenant.1",
            runner_id="runner.1",
            runner_public_key_pem=self.runner.public_key_pem,
            scopes=tuple(command.value for command in RunnerCommand),
            issued_at=NOW,
            ttl=ttl,
        )
        self.store.create_lease(self.credential, self.registry, now=NOW, lease_ttl=timedelta(seconds=20))

    def request(
        self,
        command: RunnerCommand,
        *,
        request_id: str,
        nonce: str,
        sequence: int,
        body: dict[str, object] | None = None,
        issued_at: datetime = NOW,
        credential: SignedRunCredential | None = None,
    ) -> TransportRequest:
        return create_transport_request(
            request_id=request_id,
            credential=credential or self.credential,
            nonce=nonce,
            command=command,
            sequence=sequence,
            issued_at=issued_at,
            body=body or {},
        )


def test_resource_limits_and_profile_are_strict() -> None:
    assert limits().model_dump()["pids"] == 32
    with pytest.raises(ValidationError, match="file_size_bytes"):
        limits(file_size_bytes=9 * 1024 * 1024)
    with pytest.raises(ValidationError, match="heartbeat interval"):
        limits(heartbeat_interval_seconds=10, lease_ttl_seconds=10)
    with pytest.raises(ValidationError):
        ResourceLimits(**limits().model_dump(), unknown=True)
    assert profile().identity_digest == sha256_json(profile().model_dump(mode="json"))
    with pytest.raises(ValidationError, match="image_digest"):
        profile(image_digest="latest")
    with pytest.raises(ValidationError, match="cap_drop"):
        profile(cap_drop=())


def test_credential_signing_registry_and_tamper() -> None:
    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
    registry = TrustedTransportRegistry.empty()
    assert registry.add_pem(authority.public_key_pem) == authority.key_id
    credential = authority.issue(
        credential_id="credential.1",
        run_id="run.1",
        tenant_id="tenant.1",
        runner_id="runner.1",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=NOW,
        ttl=timedelta(minutes=1),
    )
    assert registry.verify(credential).runner_key_id == runner.key_id
    untrusted = TrustedTransportRegistry.empty()
    with pytest.raises(AuthenticationFailure, match="untrusted_control_plane_key"):
        untrusted.verify(credential)
    tampered = credential.model_copy(update={"signature_b64": base64.b64encode(b"x" * 64).decode()})
    with pytest.raises(AuthenticationFailure, match="invalid_credential_signature"):
        registry.verify(tampered)
    wrong_claims = credential.claims.model_copy(update={"control_plane_key_id": "ed25519:" + "0" * 32})
    payload = wrong_claims.model_dump(mode="json")
    signature = authority._private_key.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    mismatched = SignedRunCredential(
        claims=wrong_claims,
        signature_b64=base64.b64encode(signature).decode(),
        key_id=authority.key_id,
    )
    with pytest.raises(AuthenticationFailure, match="credential_key_id_mismatch"):
        registry.verify(mismatched)
    with pytest.raises(ValidationError, match="15 minutes"):
        authority.issue(
            credential_id="credential.2",
            run_id="run.2",
            tenant_id="tenant.1",
            runner_id="runner.1",
            runner_public_key_pem=runner.public_key_pem,
            scopes=(RunnerCommand.HEARTBEAT.value,),
            issued_at=NOW,
            ttl=timedelta(minutes=16),
        )


def test_runner_response_signing_and_verification(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    request = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="request.1",
        nonce="nonce-000000000001",
        sequence=1,
    )
    response = fx.runner.sign_response(
        response_id="response.1",
        request=request,
        status="ACCEPTED",
        body={"heartbeat": "accepted"},
        issued_at=NOW,
    )
    assert verify_runner_response(response, fx.runner.public_key_pem) == (True, "verified")
    other = RunnerEphemeralIdentity.generate()
    assert verify_runner_response(response, other.public_key_pem) == (False, "runner_key_id_mismatch")
    broken = response.model_copy(update={"signature_b64": "not-base64"})
    assert verify_runner_response(broken, fx.runner.public_key_pem) == (False, "invalid_runner_signature")
    with pytest.raises(ValueError):
        verify_runner_response(response, ControlPlaneTransportAuthority.generate().public_key_pem.replace("PUBLIC", "PRIVATE"))


def test_transport_models_reject_hash_and_identity_errors(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    request = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="request.1",
        nonce="nonce-000000000001",
        sequence=1,
        body={"x": 1},
    )
    with pytest.raises(ValidationError, match="body_sha256"):
        TransportRequest(**{**request.model_dump(), "body_sha256": "0" * 64})
    with pytest.raises(ValidationError):
        TransportRequest(**{**request.model_dump(), "extra": True})
    response = RunnerResponse(
        response_id="response.1",
        request_id="request.1",
        run_id="run.1",
        tenant_id="tenant.1",
        runner_id="runner.1",
        sequence=1,
        issued_at=NOW,
        status="ACCEPTED",
        body={},
        body_sha256=sha256_json({}),
        runner_key_id=fx.runner.key_id,
        signature_b64="pending",
    )
    with pytest.raises(ValidationError, match="response body_sha256"):
        RunnerResponse(**{**response.model_dump(), "body_sha256": "0" * 64})


def test_lease_authentication_heartbeat_replay_and_idempotency(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    heartbeat = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="heartbeat.1",
        nonce="nonce-000000000001",
        sequence=1,
        body={"status": "alive"},
    )
    lease = fx.store.heartbeat(heartbeat, fx.registry, now=NOW + timedelta(seconds=1))
    assert lease["last_sequence"] == 1
    with pytest.raises(ReplayDetected, match="nonce_replayed"):
        fx.store.heartbeat(heartbeat, fx.registry, now=NOW + timedelta(seconds=2))
    retry = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="heartbeat.1",
        nonce="nonce-000000000002",
        sequence=1,
        body={"status": "alive"},
        issued_at=NOW + timedelta(seconds=2),
    )
    assert fx.store.heartbeat(retry, fx.registry, now=NOW + timedelta(seconds=2))["last_sequence"] == 1
    conflict = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="heartbeat.1",
        nonce="nonce-000000000003",
        sequence=1,
        body={"status": "different"},
    )
    with pytest.raises(RequestConflict, match="request_id_content_conflict"):
        fx.store.heartbeat(conflict, fx.registry, now=NOW + timedelta(seconds=3))


def test_authentication_rejects_expired_unregistered_revoked_scope_and_identity(tmp_path: Path) -> None:
    authority = ControlPlaneTransportAuthority.generate()
    registry = TrustedTransportRegistry.empty()
    registry.add_pem(authority.public_key_pem)
    runner = RunnerEphemeralIdentity.generate()
    store = RunnerStore(tmp_path / "runner.sqlite3")
    expired = authority.issue(
        credential_id="credential.expired",
        run_id="run.expired",
        tenant_id="tenant.1",
        runner_id="runner.1",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=NOW - timedelta(minutes=2),
        ttl=timedelta(minutes=1),
    )
    with pytest.raises(ExpiredCredential):
        store.register_credential(expired, registry, now=NOW)

    fx = Fixture(tmp_path / "active")
    request = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="request.1",
        nonce="nonce-000000000001",
        sequence=1,
    )
    different_store = RunnerStore(tmp_path / "unregistered.sqlite3")
    with pytest.raises(AuthenticationFailure, match="credential_not_registered"):
        different_store.authenticate(request, fx.registry, now=NOW)
    fx.store.revoke_credential("credential.1", now=NOW)
    with pytest.raises(AuthenticationFailure, match="credential_revoked"):
        fx.store.authenticate(request, fx.registry, now=NOW)
    with pytest.raises(KeyError):
        fx.store.revoke_credential("missing", now=NOW)

    limited_runner = RunnerEphemeralIdentity.generate()
    limited = fx.authority.issue(
        credential_id="credential.limited",
        run_id="run.limited",
        tenant_id="tenant.1",
        runner_id="runner.limited",
        runner_public_key_pem=limited_runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=NOW,
        ttl=timedelta(minutes=1),
    )
    limited_store = RunnerStore(tmp_path / "limited.sqlite3")
    limited_store.create_lease(limited, fx.registry, now=NOW)
    wrong_scope = create_transport_request(
        request_id="request.scope",
        credential=limited,
        nonce="nonce-000000000004",
        command=RunnerCommand.CANCEL,
        sequence=1,
        issued_at=NOW,
        body={},
    )
    with pytest.raises(AuthenticationFailure, match="scope_not_granted"):
        limited_store.authenticate(wrong_scope, fx.registry, now=NOW)
    identity_mismatch = request.model_copy(update={"tenant_id": "tenant.2"})
    with pytest.raises(AuthenticationFailure, match="request_identity_mismatch"):
        fx.store.authenticate(identity_mismatch, fx.registry, now=NOW)


def test_request_timestamp_and_lease_expiration_fail_closed(tmp_path: Path) -> None:
    fx = Fixture(tmp_path, ttl=timedelta(seconds=5))
    future = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="future.1",
        nonce="nonce-000000000001",
        sequence=1,
        issued_at=NOW + timedelta(minutes=5),
    )
    with pytest.raises(AuthenticationFailure, match="timestamp"):
        fx.store.authenticate(future, fx.registry, now=NOW)
    expired = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="expired.1",
        nonce="nonce-000000000002",
        sequence=1,
        issued_at=NOW,
    )
    with pytest.raises(ExpiredCredential):
        fx.store.authenticate(expired, fx.registry, now=NOW + timedelta(seconds=6))


def test_transitions_are_valid_idempotent_and_append_only(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    start = fx.request(
        RunnerCommand.TRANSITION,
        request_id="transition.start",
        nonce="nonce-000000000001",
        sequence=1,
        body={"to_state": RunnerLeaseState.STARTING.value},
    )
    assert fx.store.transition(start, fx.registry, to_state=RunnerLeaseState.STARTING, now=NOW)["state"] is RunnerLeaseState.STARTING
    retry = fx.request(
        RunnerCommand.TRANSITION,
        request_id="transition.start",
        nonce="nonce-000000000002",
        sequence=1,
        body={"to_state": RunnerLeaseState.STARTING.value},
    )
    assert fx.store.transition(retry, fx.registry, to_state=RunnerLeaseState.STARTING, now=NOW)["state"] is RunnerLeaseState.STARTING
    mismatch = fx.request(
        RunnerCommand.TRANSITION,
        request_id="transition.start",
        nonce="nonce-000000000003",
        sequence=1,
        body={"to_state": RunnerLeaseState.RUNNING.value},
    )
    with pytest.raises(RequestConflict):
        fx.store.transition(mismatch, fx.registry, to_state=RunnerLeaseState.RUNNING, now=NOW)
    illegal = fx.request(
        RunnerCommand.TRANSITION,
        request_id="transition.illegal",
        nonce="nonce-000000000004",
        sequence=2,
    )
    with pytest.raises(LeaseFailure, match="illegal_runner_transition"):
        fx.store.transition(illegal, fx.registry, to_state=RunnerLeaseState.COMPLETED, now=NOW)
    connection = sqlite3.connect(fx.store.database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM runner_transitions")
    finally:
        connection.close()


def test_cancellation_and_terminal_behavior(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    cancel = fx.request(
        RunnerCommand.CANCEL,
        request_id="cancel.1",
        nonce="nonce-000000000001",
        sequence=1,
    )
    lease = fx.store.request_cancellation(cancel, fx.registry, reason="operator request", now=NOW)
    assert lease["state"] is RunnerLeaseState.CANCELLING
    retry = fx.request(
        RunnerCommand.CANCEL,
        request_id="cancel.1",
        nonce="nonce-000000000002",
        sequence=1,
    )
    assert fx.store.request_cancellation(retry, fx.registry, reason="operator request", now=NOW)["state"] is RunnerLeaseState.CANCELLING
    done = fx.request(
        RunnerCommand.TRANSITION,
        request_id="transition.cancelled",
        nonce="nonce-000000000003",
        sequence=2,
    )
    assert fx.store.transition(done, fx.registry, to_state=RunnerLeaseState.CANCELLED, now=NOW)["state"] is RunnerLeaseState.CANCELLED
    heartbeat = fx.request(
        RunnerCommand.HEARTBEAT,
        request_id="heartbeat.after",
        nonce="nonce-000000000004",
        sequence=3,
    )
    with pytest.raises(LeaseFailure, match="terminal"):
        fx.store.heartbeat(heartbeat, fx.registry, now=NOW)
    with pytest.raises(ValueError, match="reason"):
        fx.store.request_cancellation(cancel.model_copy(update={"nonce": "nonce-000000000005"}), fx.registry, reason="", now=NOW)


def test_orphan_detection_is_durable_and_idempotent(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    assert fx.store.reap_orphans(now=NOW + timedelta(seconds=21)) == ["run.1"]
    assert fx.store.get_lease("run.1", "tenant.1")["state"] is RunnerLeaseState.ORPHANED
    assert fx.store.reap_orphans(now=NOW + timedelta(seconds=22)) == []
    with pytest.raises(KeyError):
        fx.store.get_lease("run.1", "tenant.other")


def chunk(artifact_id: str, index: int, total: int, content: bytes, part: bytes) -> EvidenceChunk:
    return EvidenceChunk(
        artifact_id=artifact_id,
        chunk_index=index,
        total_chunks=total,
        content_sha256=sha256_bytes(content),
        chunk_sha256=sha256_bytes(part),
        payload_b64=base64.b64encode(part).decode(),
    )


def test_evidence_streaming_interruption_completion_and_cross_tenant(tmp_path: Path) -> None:
    fx = Fixture(tmp_path)
    content = b"abcdef"
    first = chunk("artifact.1", 0, 2, content, b"abc")
    request1 = fx.request(
        RunnerCommand.EVIDENCE_CHUNK,
        request_id="evidence.1",
        nonce="nonce-000000000001",
        sequence=1,
    )
    fx.store.append_evidence_chunk(request1, fx.registry, first, now=NOW)
    incomplete = fx.store.evidence_status("run.1", "tenant.1", "artifact.1")
    assert incomplete["complete"] is False
    request2 = fx.request(
        RunnerCommand.EVIDENCE_CHUNK,
        request_id="evidence.2",
        nonce="nonce-000000000002",
        sequence=2,
    )
    fx.store.append_evidence_chunk(request2, fx.registry, chunk("artifact.1", 1, 2, content, b"def"), now=NOW)
    completed = fx.store.evidence_status("run.1", "tenant.1", "artifact.1")
    assert completed["complete"] is True
    assert completed["assembled_sha256"] == sha256_bytes(content)
    retry = fx.request(
        RunnerCommand.EVIDENCE_CHUNK,
        request_id="evidence.2",
        nonce="nonce-000000000003",
        sequence=2,
    )
    assert fx.store.append_evidence_chunk(
        retry, fx.registry, chunk("artifact.1", 1, 2, content, b"def"), now=NOW
    )["chunk_index"] == 1
    with pytest.raises(KeyError):
        fx.store.evidence_status("run.1", "tenant.other", "artifact.1")
    with pytest.raises(KeyError):
        fx.store.evidence_status("run.1", "tenant.1", "missing")
    connection = sqlite3.connect(fx.store.database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE runner_evidence_chunks SET chunk_index = 99")
    finally:
        connection.close()


def test_evidence_chunk_validation() -> None:
    with pytest.raises(ValidationError, match="chunk_index"):
        EvidenceChunk(
            artifact_id="artifact.1",
            chunk_index=1,
            total_chunks=1,
            content_sha256="0" * 64,
            chunk_sha256="0" * 64,
            payload_b64="",
        )
    with pytest.raises(ValidationError, match="payload_b64"):
        EvidenceChunk(
            artifact_id="artifact.1",
            chunk_index=0,
            total_chunks=1,
            content_sha256="0" * 64,
            chunk_sha256="0" * 64,
            payload_b64="!!!",
        )
    with pytest.raises(ValidationError, match="chunk_sha256"):
        EvidenceChunk(
            artifact_id="artifact.1",
            chunk_index=0,
            total_chunks=1,
            content_sha256="0" * 64,
            chunk_sha256="0" * 64,
            payload_b64=base64.b64encode(b"x").decode(),
        )


def test_docker_payload_enforces_isolation_and_exact_labels(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    evidence_dir = tmp_path / "evidence"
    input_dir.mkdir()
    evidence_dir.mkdir()
    current = profile()
    payload = build_docker_create_payload(
        current,
        run_id="run.1",
        tenant_id="tenant.1",
        ownership_token="owner.1",
        command=("sh", "-c", "true"),
        input_directory=input_dir,
        evidence_directory=evidence_dir,
    )
    host = payload["HostConfig"]
    assert payload["Image"] == IMAGE
    assert payload["User"] == "65532:65532"
    assert payload["NetworkDisabled"] is True
    assert host["ReadonlyRootfs"] is True
    assert host["NetworkMode"] == "none"
    assert host["CapDrop"] == ["ALL"]
    assert set(host["SecurityOpt"]) == {
        "no-new-privileges:true",
        "seccomp=builtin",
        "apparmor=docker-default",
    }
    assert host["PidsLimit"] == 32
    assert host["Memory"] == host["MemorySwap"] == 64 * 1024 * 1024
    assert host["Tmpfs"]["/workspace"].find("size=8388608") > 0
    assert "uid=65532" in host["Tmpfs"]["/workspace"]
    assert "gid=65532" in host["Tmpfs"]["/workspace"]
    assert "uid=65532" in host["Tmpfs"]["/tmp"]
    assert host["Mounts"][0]["ReadOnly"] is True
    assert host["Mounts"][1]["Target"] == "/evidence-out"
    assert payload["Labels"]["echo.certforge.isolation_profile"] == current.identity_digest
    with pytest.raises(FileNotFoundError):
        build_docker_create_payload(
            current,
            run_id="run.2",
            tenant_id="tenant.1",
            ownership_token="owner.2",
            command=("true",),
            input_directory=tmp_path / "missing",
        )


def test_docker_inspect_validation_detects_every_critical_drift() -> None:
    current = profile()
    payload = build_docker_create_payload(
        current,
        run_id="run.1",
        tenant_id="tenant.1",
        ownership_token="owner.1",
        command=("true",),
    )
    inspect = {
        "Config": {"User": payload["User"], "Labels": payload["Labels"]},
        "HostConfig": payload["HostConfig"],
        "NetworkSettings": {"Networks": {}},
    }
    assert validate_docker_inspect(inspect, current) == ()
    drifted = json.loads(json.dumps(inspect))
    drifted["Config"]["User"] = "0:0"
    drifted["Config"]["Labels"]["echo.certforge.isolation_profile"] = "bad"
    drifted["HostConfig"]["ReadonlyRootfs"] = False
    drifted["HostConfig"]["NetworkMode"] = "bridge"
    drifted["HostConfig"]["CapDrop"] = []
    drifted["HostConfig"]["SecurityOpt"] = []
    drifted["HostConfig"]["Memory"] = 1
    drifted["HostConfig"]["MemorySwap"] = 2
    drifted["HostConfig"]["NanoCpus"] = 3
    drifted["HostConfig"]["PidsLimit"] = 4
    drifted["HostConfig"]["Mounts"] = [{"Source": "/var/run/docker.sock"}]
    drifted["NetworkSettings"]["Networks"] = {"bridge": {}}
    issues = validate_docker_inspect(drifted, current)
    assert "user_mismatch" in issues
    assert "rootfs_not_read_only" in issues
    assert "network_not_denied" in issues
    assert "capabilities_not_fully_dropped" in issues
    assert "security_options_incomplete" in issues
    assert "profile_identity_mismatch" in issues
    assert "docker_socket_exposed" in issues
    assert sum(item.startswith("limit_mismatch:") for item in issues) == 4


def test_workspace_owner_marker_and_symlink_detection(tmp_path: Path) -> None:
    workspace = prepare_workspace(
        tmp_path / "workspaces",
        run_id="run.1",
        tenant_id="tenant.1",
        ownership_token="owner.1",
    )
    if os.name != "nt":
        assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert verify_workspace_owner(
        workspace, run_id="run.1", tenant_id="tenant.1", ownership_token="owner.1"
    )
    assert not verify_workspace_owner(
        workspace, run_id="run.1", tenant_id="tenant.1", ownership_token="wrong"
    )
    with pytest.raises(FileExistsError):
        prepare_workspace(
            tmp_path / "workspaces",
            run_id="run.1",
            tenant_id="tenant.1",
            ownership_token="owner.1",
        )
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    try:
        os.symlink(target, workspace / "link")
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    with pytest.raises(IsolationFailure, match="symlink_not_allowed"):
        assert_no_symlinks(workspace)


def test_safe_zip_extraction_rejects_traversal_symlink_and_size(tmp_path: Path) -> None:
    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as archive:
        archive.writestr("folder/file.txt", "safe")
    destination = tmp_path / "good-out"
    assert extract_archive_safely(good, destination, max_total_bytes=100) == ("folder/file.txt",)
    assert (destination / "folder" / "file.txt").read_text() == "safe"

    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "bad")
    with pytest.raises(ValueError, match="traverse"):
        extract_archive_safely(traversal, tmp_path / "traversal-out", max_total_bytes=100)

    symlink_zip = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(symlink_zip, "w") as archive:
        archive.writestr(info, "../outside")
    with pytest.raises(IsolationFailure, match="symlink"):
        extract_archive_safely(symlink_zip, tmp_path / "symlink-out", max_total_bytes=100)

    large = tmp_path / "large.zip"
    with zipfile.ZipFile(large, "w") as archive:
        archive.writestr("large.bin", b"x" * 101)
    with pytest.raises(IsolationFailure, match="size_limit"):
        extract_archive_safely(large, tmp_path / "large-out", max_total_bytes=100)


def test_safe_tar_extraction_rejects_links_and_special_members(tmp_path: Path) -> None:
    good = tmp_path / "good.tar"
    with tarfile.open(good, "w") as archive:
        data = b"safe"
        info = tarfile.TarInfo("folder/file.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    assert extract_archive_safely(good, tmp_path / "tar-out", max_total_bytes=100) == ("folder/file.txt",)

    linked = tmp_path / "linked.tar"
    with tarfile.open(linked, "w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../outside"
        archive.addfile(info)
    with pytest.raises(IsolationFailure, match="special_member"):
        extract_archive_safely(linked, tmp_path / "linked-out", max_total_bytes=100)

    fifo = tmp_path / "fifo.tar"
    with tarfile.open(fifo, "w") as archive:
        info = tarfile.TarInfo("pipe")
        info.type = tarfile.FIFOTYPE
        archive.addfile(info)
    with pytest.raises(IsolationFailure, match="special_member"):
        extract_archive_safely(fifo, tmp_path / "fifo-out", max_total_bytes=100)

    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"not an archive")
    with pytest.raises(IsolationFailure, match="unsupported_archive"):
        extract_archive_safely(unknown, tmp_path / "unknown-out", max_total_bytes=100)
    with pytest.raises(ValueError, match="positive"):
        extract_archive_safely(good, tmp_path / "zero-out", max_total_bytes=0)
