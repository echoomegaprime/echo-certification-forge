"""Authenticated runner transport, durable leases, and isolation policy contracts.

This module is control-plane code. It never executes customer code and never
loads verdict-signing keys. Transport identities are short-lived and distinct
from release-verdict signing identities.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import (
    canonical_json,
    contained_path,
    parse_utc_iso,
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)


class RunnerError(RuntimeError):
    """Base runner-contract failure."""


class AuthenticationFailure(RunnerError):
    """Transport identity or signature validation failed."""


class ExpiredCredential(AuthenticationFailure):
    """The run-scoped credential is no longer valid."""


class ReplayDetected(AuthenticationFailure):
    """A previously consumed nonce was presented again."""


class RequestConflict(AuthenticationFailure):
    """A request id was reused with different content."""


class LeaseFailure(RunnerError):
    """Lease state, ownership, or heartbeat validation failed."""


class IsolationFailure(RunnerError):
    """Isolation policy or host-observable runtime proof is invalid."""


class RunnerLeaseState(StrEnum):
    ISSUED = "ISSUED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ORPHANED = "ORPHANED"


class RunnerCommand(StrEnum):
    HEARTBEAT = "runner.heartbeat"
    TRANSITION = "runner.transition"
    CANCEL = "runner.cancel"
    EVIDENCE_CHUNK = "runner.evidence_chunk"


TERMINAL_RUNNER_STATES = frozenset(
    {
        RunnerLeaseState.CANCELLED,
        RunnerLeaseState.COMPLETED,
        RunnerLeaseState.FAILED,
        RunnerLeaseState.ORPHANED,
    }
)

_ALLOWED_RUNNER_TRANSITIONS: dict[RunnerLeaseState, frozenset[RunnerLeaseState]] = {
    RunnerLeaseState.ISSUED: frozenset({RunnerLeaseState.STARTING, RunnerLeaseState.CANCELLING, RunnerLeaseState.FAILED}),
    RunnerLeaseState.STARTING: frozenset({RunnerLeaseState.RUNNING, RunnerLeaseState.CANCELLING, RunnerLeaseState.FAILED}),
    RunnerLeaseState.RUNNING: frozenset(
        {RunnerLeaseState.CANCELLING, RunnerLeaseState.COMPLETED, RunnerLeaseState.FAILED}
    ),
    RunnerLeaseState.CANCELLING: frozenset({RunnerLeaseState.CANCELLED, RunnerLeaseState.FAILED}),
}


class ResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_cores: float = Field(gt=0.0, le=64.0)
    memory_bytes: int = Field(ge=16 * 1024 * 1024, le=256 * 1024 * 1024 * 1024)
    pids: int = Field(ge=4, le=4096)
    disk_bytes: int = Field(ge=1024 * 1024, le=1024 * 1024 * 1024 * 1024)
    file_size_bytes: int = Field(ge=64 * 1024, le=1024 * 1024 * 1024 * 1024)
    wall_time_seconds: int = Field(ge=1, le=24 * 60 * 60)
    heartbeat_interval_seconds: int = Field(ge=1, le=300)
    lease_ttl_seconds: int = Field(ge=2, le=900)

    @model_validator(mode="after")
    def validate_relationships(self) -> "ResourceLimits":
        if self.file_size_bytes > self.disk_bytes:
            raise ValueError("file_size_bytes may not exceed disk_bytes")
        if self.heartbeat_interval_seconds >= self.lease_ttl_seconds:
            raise ValueError("heartbeat interval must be shorter than the lease TTL")
        return self


class IsolationProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str
    profile_version: str
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    user: str = Field(pattern=r"^[1-9][0-9]*:[1-9][0-9]*$")
    read_only_root: Literal[True] = True
    network_mode: Literal["none"] = "none"
    cap_drop: tuple[Literal["ALL"], ...] = ("ALL",)
    no_new_privileges: Literal[True] = True
    seccomp_profile: Literal["builtin"] = "builtin"
    apparmor_profile: str = "docker-default"
    limits: ResourceLimits

    @model_validator(mode="after")
    def validate_identifiers(self) -> "IsolationProfile":
        require_identifier(self.profile_id, "profile_id")
        require_identifier(self.profile_version, "profile_version")
        if self.cap_drop != ("ALL",):
            raise ValueError("all Linux capabilities must be dropped")
        require_identifier(self.apparmor_profile, "apparmor_profile")
        return self

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class RunCredentialClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    credential_id: str
    run_id: str
    tenant_id: str
    runner_id: str
    runner_public_key_pem: str
    runner_key_id: str
    scopes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    control_plane_key_id: str

    @model_validator(mode="after")
    def validate_claims(self) -> "RunCredentialClaims":
        for field_name in ("credential_id", "run_id", "tenant_id", "runner_id"):
            require_identifier(getattr(self, field_name), field_name)
        if not self.scopes:
            raise ValueError("at least one transport scope is required")
        normalized_scopes = tuple(sorted(set(self.scopes)))
        if normalized_scopes != self.scopes:
            raise ValueError("scopes must be unique and sorted")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("credential timestamps must be timezone-aware")
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(minutes=15):
            raise ValueError("credential lifetime must be greater than zero and no more than 15 minutes")
        key = serialization.load_pem_public_key(self.runner_public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("runner public key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        expected = f"ed25519:{sha256_bytes(raw)[:32]}"
        if expected != self.runner_key_id:
            raise ValueError("runner key id does not match runner public key")
        return self


class SignedRunCredential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: RunCredentialClaims
    signature_b64: str
    key_id: str

    @property
    def payload_sha256(self) -> str:
        return sha256_json(self.claims.model_dump(mode="json"))


class TransportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    request_id: str
    run_id: str
    tenant_id: str
    runner_id: str
    nonce: str = Field(min_length=16, max_length=256)
    command: RunnerCommand
    sequence: int = Field(ge=1)
    issued_at: datetime
    credential: SignedRunCredential
    body: dict[str, Any]
    body_sha256: str

    @model_validator(mode="after")
    def validate_request(self) -> "TransportRequest":
        for field_name in ("request_id", "run_id", "tenant_id", "runner_id"):
            require_identifier(getattr(self, field_name), field_name)
        require_sha256(self.body_sha256, "body_sha256")
        if self.body_sha256 != sha256_json(self.body):
            raise ValueError("body_sha256 does not match body")
        if self.issued_at.tzinfo is None:
            raise ValueError("request issued_at must be timezone-aware")
        return self

    @property
    def request_sha256(self) -> str:
        # Nonce and transport timestamp are intentionally excluded so a client
        # can retry the same semantic request with a fresh nonce. Reusing the
        # original nonce remains a hard replay failure.
        payload = self.model_dump(mode="json", exclude={"credential", "nonce", "issued_at"})
        payload["credential_payload_sha256"] = self.credential.payload_sha256
        return sha256_json(payload)


class EvidenceChunk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str
    chunk_index: int = Field(ge=0)
    total_chunks: int = Field(ge=1, le=1_000_000)
    content_sha256: str
    chunk_sha256: str
    payload_b64: str

    @model_validator(mode="after")
    def validate_chunk(self) -> "EvidenceChunk":
        require_identifier(self.artifact_id, "artifact_id")
        require_sha256(self.content_sha256, "content_sha256")
        require_sha256(self.chunk_sha256, "chunk_sha256")
        if self.chunk_index >= self.total_chunks:
            raise ValueError("chunk_index must be less than total_chunks")
        try:
            payload = base64.b64decode(self.payload_b64, validate=True)
        except ValueError as exc:
            raise ValueError("payload_b64 is invalid") from exc
        if sha256_bytes(payload) != self.chunk_sha256:
            raise ValueError("chunk_sha256 does not match payload")
        return self


class RunnerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    response_id: str
    request_id: str
    run_id: str
    tenant_id: str
    runner_id: str
    sequence: int = Field(ge=1)
    issued_at: datetime
    status: Literal["ACCEPTED", "REJECTED", "COMPLETED"]
    body: dict[str, Any]
    body_sha256: str
    runner_key_id: str
    signature_b64: str

    @model_validator(mode="after")
    def validate_response(self) -> "RunnerResponse":
        for field_name in ("response_id", "request_id", "run_id", "tenant_id", "runner_id"):
            require_identifier(getattr(self, field_name), field_name)
        require_sha256(self.body_sha256, "body_sha256")
        if self.body_sha256 != sha256_json(self.body):
            raise ValueError("response body_sha256 does not match body")
        if self.issued_at.tzinfo is None:
            raise ValueError("response issued_at must be timezone-aware")
        return self

    def signed_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature_b64"})


class ControlPlaneTransportAuthority:
    """Issues short-lived transport credentials; never signs release verdicts."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "ControlPlaneTransportAuthority":
        return cls(Ed25519PrivateKey.generate())

    @property
    def key_id(self) -> str:
        raw = self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def issue(
        self,
        *,
        credential_id: str,
        run_id: str,
        tenant_id: str,
        runner_id: str,
        runner_public_key_pem: str,
        scopes: Iterable[str],
        issued_at: datetime,
        ttl: timedelta,
    ) -> SignedRunCredential:
        key = serialization.load_pem_public_key(runner_public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("runner public key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        claims = RunCredentialClaims(
            credential_id=credential_id,
            run_id=run_id,
            tenant_id=tenant_id,
            runner_id=runner_id,
            runner_public_key_pem=runner_public_key_pem,
            runner_key_id=f"ed25519:{sha256_bytes(raw)[:32]}",
            scopes=tuple(sorted(set(scopes))),
            issued_at=issued_at,
            expires_at=issued_at + ttl,
            control_plane_key_id=self.key_id,
        )
        payload = canonical_json(claims.model_dump(mode="json")).encode("utf-8")
        signature = self._private_key.sign(payload)
        return SignedRunCredential(
            claims=claims,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            key_id=self.key_id,
        )


@dataclass(slots=True)
class TrustedTransportRegistry:
    keys: dict[str, Ed25519PublicKey]
    key_tenants: dict[str, str | None] = field(default_factory=dict)

    @classmethod
    def empty(cls) -> "TrustedTransportRegistry":
        return cls(keys={})

    def add_pem(self, public_key_pem: str, *, tenant_id: str | None = None) -> str:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("transport public key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        self.keys[key_id] = key
        self.key_tenants[key_id] = tenant_id
        return key_id

    def remove(self, key_id: str) -> None:
        self.keys.pop(key_id, None)
        self.key_tenants.pop(key_id, None)

    def public_key_pem(self, key_id: str) -> str:
        key = self.keys.get(key_id)
        if key is None:
            raise AuthenticationFailure("untrusted_control_plane_key")
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def verify(self, credential: SignedRunCredential) -> RunCredentialClaims:
        key = self.keys.get(credential.key_id)
        if key is None:
            raise AuthenticationFailure("untrusted_control_plane_key")
        payload = canonical_json(credential.claims.model_dump(mode="json")).encode("utf-8")
        try:
            signature = base64.b64decode(credential.signature_b64, validate=True)
            key.verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise AuthenticationFailure("invalid_credential_signature") from exc
        if credential.claims.control_plane_key_id != credential.key_id:
            raise AuthenticationFailure("credential_key_id_mismatch")
        tenant_id = self.key_tenants.get(credential.key_id)
        if tenant_id is not None and credential.claims.tenant_id != tenant_id:
            raise AuthenticationFailure("credential_tenant_mismatch")
        return credential.claims


class RunnerEphemeralIdentity:
    """Per-run runner response identity held only for the run lifetime."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "RunnerEphemeralIdentity":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    def sign_response(
        self,
        *,
        response_id: str,
        request: TransportRequest,
        status: Literal["ACCEPTED", "REJECTED", "COMPLETED"],
        body: dict[str, Any],
        issued_at: datetime,
    ) -> RunnerResponse:
        unsigned = RunnerResponse(
            response_id=response_id,
            request_id=request.request_id,
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            runner_id=request.runner_id,
            sequence=request.sequence,
            issued_at=issued_at,
            status=status,
            body=body,
            body_sha256=sha256_json(body),
            runner_key_id=self.key_id,
            signature_b64="pending",
        )
        signature = self._private_key.sign(canonical_json(unsigned.signed_payload()).encode("utf-8"))
        return unsigned.model_copy(update={"signature_b64": base64.b64encode(signature).decode("ascii")})


def verify_runner_response(response: RunnerResponse, runner_public_key_pem: str) -> tuple[bool, str]:
    key = serialization.load_pem_public_key(runner_public_key_pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("runner public key must be Ed25519")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    if response.runner_key_id != expected_key_id:
        return False, "runner_key_id_mismatch"
    try:
        signature = base64.b64decode(response.signature_b64, validate=True)
        key.verify(signature, canonical_json(response.signed_payload()).encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False, "invalid_runner_signature"
    return True, "verified"


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    claims: RunCredentialClaims
    idempotent: bool


class RunnerStore:
    """Durable replay, lease, transition, cancellation, and evidence state."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runner_credentials (
                    credential_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    runner_key_id TEXT NOT NULL,
                    runner_public_key_pem TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS runner_requests (
                    request_id TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runner_nonces (
                    nonce TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL REFERENCES runner_requests(request_id),
                    seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runner_leases (
                    run_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL REFERENCES runner_credentials(credential_id),
                    state TEXT NOT NULL,
                    lease_expires_at TEXT NOT NULL,
                    last_heartbeat_at TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL DEFAULT 0,
                    cancel_requested_at TEXT,
                    cancellation_reason TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runner_transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runner_leases(run_id),
                    request_id TEXT NOT NULL UNIQUE,
                    sequence INTEGER NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS runner_evidence_chunks (
                    run_id TEXT NOT NULL REFERENCES runner_leases(run_id),
                    tenant_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    chunk_sha256 TEXT NOT NULL,
                    payload_b64 TEXT NOT NULL,
                    request_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, artifact_id, chunk_index)
                );
                CREATE TRIGGER IF NOT EXISTS runner_requests_no_update
                BEFORE UPDATE ON runner_requests BEGIN SELECT RAISE(ABORT, 'runner_requests are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_requests_no_delete
                BEFORE DELETE ON runner_requests BEGIN SELECT RAISE(ABORT, 'runner_requests are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_nonces_no_update
                BEFORE UPDATE ON runner_nonces BEGIN SELECT RAISE(ABORT, 'runner_nonces are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_nonces_no_delete
                BEFORE DELETE ON runner_nonces BEGIN SELECT RAISE(ABORT, 'runner_nonces are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_transitions_no_update
                BEFORE UPDATE ON runner_transitions BEGIN SELECT RAISE(ABORT, 'runner_transitions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_transitions_no_delete
                BEFORE DELETE ON runner_transitions BEGIN SELECT RAISE(ABORT, 'runner_transitions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_evidence_no_update
                BEFORE UPDATE ON runner_evidence_chunks BEGIN SELECT RAISE(ABORT, 'runner evidence is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS runner_evidence_no_delete
                BEFORE DELETE ON runner_evidence_chunks BEGIN SELECT RAISE(ABORT, 'runner evidence is append-only'); END;
                """
            )
            connection.commit()
        finally:
            connection.close()

    def register_credential(
        self,
        credential: SignedRunCredential,
        registry: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
    ) -> RunCredentialClaims:
        claims = registry.verify(credential)
        current = now or utc_now()
        if current >= claims.expires_at:
            raise ExpiredCredential("credential_expired")
        connection = self._connect()
        try:
            existing = connection.execute(
                "SELECT * FROM runner_credentials WHERE credential_id = ?", (claims.credential_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["run_id"] != claims.run_id
                    or existing["tenant_id"] != claims.tenant_id
                    or existing["runner_key_id"] != claims.runner_key_id
                ):
                    raise RequestConflict("credential_id_conflict")
                return claims
            connection.execute(
                """
                INSERT INTO runner_credentials(
                    credential_id, run_id, tenant_id, runner_id, runner_key_id,
                    runner_public_key_pem, scopes_json, issued_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claims.credential_id,
                    claims.run_id,
                    claims.tenant_id,
                    claims.runner_id,
                    claims.runner_key_id,
                    claims.runner_public_key_pem,
                    canonical_json(list(claims.scopes)),
                    to_utc_iso(claims.issued_at),
                    to_utc_iso(claims.expires_at),
                ),
            )
            connection.commit()
            return claims
        finally:
            connection.close()

    def revoke_credential(self, credential_id: str, *, now: datetime | None = None) -> None:
        current = now or utc_now()
        connection = self._connect()
        try:
            updated = connection.execute(
                "UPDATE runner_credentials SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL",
                (to_utc_iso(current), credential_id),
            ).rowcount
            if updated == 0:
                raise KeyError(credential_id)
            connection.commit()
        finally:
            connection.close()

    def create_lease(
        self,
        credential: SignedRunCredential,
        registry: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
        lease_ttl: timedelta = timedelta(minutes=2),
    ) -> dict[str, Any]:
        current = now or utc_now()
        claims = self.register_credential(credential, registry, now=current)
        if lease_ttl <= timedelta(0):
            raise ValueError("lease_ttl must be positive")
        lease_expires_at = min(current + lease_ttl, claims.expires_at)
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO runner_leases(
                    run_id, tenant_id, runner_id, credential_id, state,
                    lease_expires_at, last_heartbeat_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claims.run_id,
                    claims.tenant_id,
                    claims.runner_id,
                    claims.credential_id,
                    RunnerLeaseState.ISSUED.value,
                    to_utc_iso(lease_expires_at),
                    to_utc_iso(current),
                    to_utc_iso(current),
                    to_utc_iso(current),
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError as exc:
            raise RequestConflict("run_lease_already_exists") from exc
        finally:
            connection.close()
        return self.get_lease(claims.run_id, claims.tenant_id)

    def authenticate(
        self,
        request: TransportRequest,
        registry: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
        clock_skew: timedelta = timedelta(minutes=2),
    ) -> AuthenticationResult:
        current = now or utc_now()
        claims = registry.verify(request.credential)
        if current >= claims.expires_at:
            raise ExpiredCredential("credential_expired")
        if request.issued_at > current + clock_skew or request.issued_at < claims.issued_at - clock_skew:
            raise AuthenticationFailure("request_timestamp_outside_allowed_window")
        if (request.run_id, request.tenant_id, request.runner_id) != (
            claims.run_id,
            claims.tenant_id,
            claims.runner_id,
        ):
            raise AuthenticationFailure("request_identity_mismatch")
        if request.command.value not in claims.scopes:
            raise AuthenticationFailure("scope_not_granted")

        connection = self._connect()
        try:
            credential_row = connection.execute(
                "SELECT revoked_at, expires_at FROM runner_credentials WHERE credential_id = ?",
                (claims.credential_id,),
            ).fetchone()
            if credential_row is None:
                raise AuthenticationFailure("credential_not_registered")
            if credential_row["revoked_at"] is not None:
                raise AuthenticationFailure("credential_revoked")
            if current >= parse_utc_iso(credential_row["expires_at"]):
                raise ExpiredCredential("credential_expired")

            if connection.execute("SELECT 1 FROM runner_nonces WHERE nonce = ?", (request.nonce,)).fetchone():
                raise ReplayDetected("nonce_replayed")
            existing = connection.execute(
                "SELECT request_sha256 FROM runner_requests WHERE request_id = ?", (request.request_id,)
            ).fetchone()
            idempotent = existing is not None
            if existing is not None and existing["request_sha256"] != request.request_sha256:
                raise RequestConflict("request_id_content_conflict")
            if existing is None:
                connection.execute(
                    "INSERT INTO runner_requests(request_id, request_sha256, first_seen_at) VALUES (?, ?, ?)",
                    (request.request_id, request.request_sha256, to_utc_iso(current)),
                )
            connection.execute(
                "INSERT INTO runner_nonces(nonce, request_id, seen_at) VALUES (?, ?, ?)",
                (request.nonce, request.request_id, to_utc_iso(current)),
            )
            connection.commit()
            return AuthenticationResult(claims=claims, idempotent=idempotent)
        finally:
            connection.close()

    def heartbeat(
        self,
        request: TransportRequest,
        registry: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
        lease_ttl: timedelta = timedelta(minutes=2),
    ) -> dict[str, Any]:
        if request.command is not RunnerCommand.HEARTBEAT:
            raise LeaseFailure("heartbeat_command_required")
        current = now or utc_now()
        auth = self.authenticate(request, registry, now=current)
        if auth.idempotent:
            return self.get_lease(request.run_id, request.tenant_id)
        connection = self._connect()
        try:
            row = self._lease_row(connection, request.run_id, request.tenant_id)
            state = RunnerLeaseState(row["state"])
            if state in TERMINAL_RUNNER_STATES:
                raise LeaseFailure("terminal_lease_cannot_heartbeat")
            if current >= parse_utc_iso(row["lease_expires_at"]):
                raise LeaseFailure("lease_expired")
            if request.sequence <= row["last_sequence"]:
                raise LeaseFailure("heartbeat_sequence_not_monotonic")
            new_expiry = min(current + lease_ttl, auth.claims.expires_at)
            connection.execute(
                """
                UPDATE runner_leases
                SET last_heartbeat_at = ?, lease_expires_at = ?, last_sequence = ?, updated_at = ?
                WHERE run_id = ? AND tenant_id = ?
                """,
                (
                    to_utc_iso(current),
                    to_utc_iso(new_expiry),
                    request.sequence,
                    to_utc_iso(current),
                    request.run_id,
                    request.tenant_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return self.get_lease(request.run_id, request.tenant_id)

    def transition(
        self,
        request: TransportRequest,
        registry: TrustedTransportRegistry,
        *,
        to_state: RunnerLeaseState,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if request.command is not RunnerCommand.TRANSITION:
            raise LeaseFailure("transition_command_required")
        current = now or utc_now()
        auth = self.authenticate(request, registry, now=current)
        connection = self._connect()
        try:
            row = self._lease_row(connection, request.run_id, request.tenant_id)
            if auth.idempotent:
                prior = connection.execute(
                    "SELECT to_state FROM runner_transitions WHERE request_id = ?", (request.request_id,)
                ).fetchone()
                if prior is None or prior["to_state"] != to_state.value:
                    raise RequestConflict("idempotent_transition_target_mismatch")
                return self._row_to_lease(row)
            from_state = RunnerLeaseState(row["state"])
            if current >= parse_utc_iso(row["lease_expires_at"]):
                raise LeaseFailure("lease_expired")
            if to_state not in _ALLOWED_RUNNER_TRANSITIONS.get(from_state, frozenset()):
                raise LeaseFailure(f"illegal_runner_transition:{from_state.value}->{to_state.value}")
            if request.sequence <= row["last_sequence"]:
                raise LeaseFailure("transition_sequence_not_monotonic")
            connection.execute(
                """
                INSERT INTO runner_transitions(run_id, request_id, sequence, from_state, to_state, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request.run_id,
                    request.request_id,
                    request.sequence,
                    from_state.value,
                    to_state.value,
                    to_utc_iso(current),
                ),
            )
            connection.execute(
                """
                UPDATE runner_leases SET state = ?, last_sequence = ?, updated_at = ?
                WHERE run_id = ? AND tenant_id = ?
                """,
                (
                    to_state.value,
                    request.sequence,
                    to_utc_iso(current),
                    request.run_id,
                    request.tenant_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return self.get_lease(request.run_id, request.tenant_id)

    def request_cancellation(
        self,
        request: TransportRequest,
        registry: TrustedTransportRegistry,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if request.command is not RunnerCommand.CANCEL:
            raise LeaseFailure("cancel_command_required")
        if not reason.strip() or len(reason) > 512:
            raise ValueError("cancellation reason is required and limited to 512 characters")
        current = now or utc_now()
        auth = self.authenticate(request, registry, now=current)
        connection = self._connect()
        try:
            row = self._lease_row(connection, request.run_id, request.tenant_id)
            state = RunnerLeaseState(row["state"])
            if auth.idempotent:
                return self._row_to_lease(row)
            if current >= parse_utc_iso(row["lease_expires_at"]):
                raise LeaseFailure("lease_expired")
            if state in TERMINAL_RUNNER_STATES:
                raise LeaseFailure("terminal_lease_cannot_cancel")
            if request.sequence <= row["last_sequence"]:
                raise LeaseFailure("cancel_sequence_not_monotonic")
            connection.execute(
                """
                INSERT INTO runner_transitions(run_id, request_id, sequence, from_state, to_state, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request.run_id,
                    request.request_id,
                    request.sequence,
                    state.value,
                    RunnerLeaseState.CANCELLING.value,
                    to_utc_iso(current),
                ),
            )
            connection.execute(
                """
                UPDATE runner_leases
                SET state = ?, last_sequence = ?, cancel_requested_at = ?,
                    cancellation_reason = ?, updated_at = ?
                WHERE run_id = ? AND tenant_id = ?
                """,
                (
                    RunnerLeaseState.CANCELLING.value,
                    request.sequence,
                    to_utc_iso(current),
                    reason,
                    to_utc_iso(current),
                    request.run_id,
                    request.tenant_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        return self.get_lease(request.run_id, request.tenant_id)

    def append_evidence_chunk(
        self,
        request: TransportRequest,
        registry: TrustedTransportRegistry,
        chunk: EvidenceChunk,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if request.command is not RunnerCommand.EVIDENCE_CHUNK:
            raise LeaseFailure("evidence_chunk_command_required")
        current = now or utc_now()
        auth = self.authenticate(request, registry, now=current)
        connection = self._connect()
        try:
            lease_row = self._lease_row(connection, request.run_id, request.tenant_id)
            if current >= parse_utc_iso(lease_row["lease_expires_at"]):
                raise LeaseFailure("lease_expired")
            if RunnerLeaseState(lease_row["state"]) in TERMINAL_RUNNER_STATES:
                raise LeaseFailure("terminal_lease_cannot_accept_evidence")
            if auth.idempotent:
                existing = connection.execute(
                    "SELECT * FROM runner_evidence_chunks WHERE request_id = ?", (request.request_id,)
                ).fetchone()
                if existing is None or existing["chunk_sha256"] != chunk.chunk_sha256:
                    raise RequestConflict("idempotent_evidence_chunk_mismatch")
                return dict(existing)
            connection.execute(
                """
                INSERT INTO runner_evidence_chunks(
                    run_id, tenant_id, artifact_id, chunk_index, total_chunks,
                    content_sha256, chunk_sha256, payload_b64, request_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.run_id,
                    request.tenant_id,
                    chunk.artifact_id,
                    chunk.chunk_index,
                    chunk.total_chunks,
                    chunk.content_sha256,
                    chunk.chunk_sha256,
                    chunk.payload_b64,
                    request.request_id,
                    to_utc_iso(current),
                ),
            )
            connection.commit()
            row = connection.execute(
                "SELECT * FROM runner_evidence_chunks WHERE request_id = ?", (request.request_id,)
            ).fetchone()
            assert row is not None
            return dict(row)
        except sqlite3.IntegrityError as exc:
            raise RequestConflict("evidence_chunk_conflict") from exc
        finally:
            connection.close()

    def evidence_status(self, run_id: str, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            self._lease_row(connection, run_id, tenant_id)
            rows = connection.execute(
                """
                SELECT * FROM runner_evidence_chunks
                WHERE run_id = ? AND tenant_id = ? AND artifact_id = ? ORDER BY chunk_index
                """,
                (run_id, tenant_id, artifact_id),
            ).fetchall()
            if not rows:
                raise KeyError(artifact_id)
            totals = {row["total_chunks"] for row in rows}
            content_hashes = {row["content_sha256"] for row in rows}
            expected_total = next(iter(totals)) if len(totals) == 1 else -1
            received = [row["chunk_index"] for row in rows]
            complete = (
                len(totals) == 1
                and len(content_hashes) == 1
                and received == list(range(expected_total))
            )
            assembled_sha256: str | None = None
            if complete:
                assembled = b"".join(base64.b64decode(row["payload_b64"], validate=True) for row in rows)
                assembled_sha256 = sha256_bytes(assembled)
                complete = assembled_sha256 == next(iter(content_hashes))
            return {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "artifact_id": artifact_id,
                "received_chunks": received,
                "expected_total_chunks": expected_total,
                "complete": complete,
                "assembled_sha256": assembled_sha256,
            }
        finally:
            connection.close()

    def reap_orphans(self, *, now: datetime | None = None) -> list[str]:
        current = now or utc_now()
        current_iso = to_utc_iso(current)
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM runner_leases
                WHERE state NOT IN (?, ?, ?, ?)
                  AND lease_expires_at <= ?
                ORDER BY run_id
                """,
                (
                    RunnerLeaseState.CANCELLED.value,
                    RunnerLeaseState.COMPLETED.value,
                    RunnerLeaseState.FAILED.value,
                    RunnerLeaseState.ORPHANED.value,
                    current_iso,
                ),
            ).fetchall()
            orphaned: list[str] = []
            for row in rows:
                sequence = row["last_sequence"] + 1
                request_id = f"reaper:{row['run_id']}:{sequence}"
                connection.execute(
                    """
                    INSERT INTO runner_transitions(run_id, request_id, sequence, from_state, to_state, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["run_id"],
                        request_id,
                        sequence,
                        row["state"],
                        RunnerLeaseState.ORPHANED.value,
                        current_iso,
                    ),
                )
                connection.execute(
                    """
                    UPDATE runner_leases SET state = ?, last_sequence = ?, updated_at = ? WHERE run_id = ?
                    """,
                    (RunnerLeaseState.ORPHANED.value, sequence, current_iso, row["run_id"]),
                )
                orphaned.append(row["run_id"])
            connection.commit()
            return orphaned
        finally:
            connection.close()

    def get_lease(self, run_id: str, tenant_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            return self._row_to_lease(self._lease_row(connection, run_id, tenant_id))
        finally:
            connection.close()

    @staticmethod
    def _lease_row(connection: sqlite3.Connection, run_id: str, tenant_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM runner_leases WHERE run_id = ? AND tenant_id = ?", (run_id, tenant_id)
        ).fetchone()
        if row is None:
            raise KeyError(run_id)
        return row

    @staticmethod
    def _row_to_lease(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["state"] = RunnerLeaseState(result["state"])
        return result


def create_transport_request(
    *,
    request_id: str,
    credential: SignedRunCredential,
    nonce: str,
    command: RunnerCommand,
    sequence: int,
    issued_at: datetime,
    body: dict[str, Any],
) -> TransportRequest:
    claims = credential.claims
    return TransportRequest(
        request_id=request_id,
        run_id=claims.run_id,
        tenant_id=claims.tenant_id,
        runner_id=claims.runner_id,
        nonce=nonce,
        command=command,
        sequence=sequence,
        issued_at=issued_at,
        credential=credential,
        body=body,
        body_sha256=sha256_json(body),
    )


def build_docker_create_payload(
    profile: IsolationProfile,
    *,
    run_id: str,
    tenant_id: str,
    ownership_token: str,
    command: Iterable[str],
    input_directory: Path | None = None,
    evidence_directory: Path | None = None,
) -> dict[str, Any]:
    require_identifier(run_id, "run_id")
    require_identifier(tenant_id, "tenant_id")
    require_identifier(ownership_token, "ownership_token")
    labels = {
        "echo.certforge.run_id": run_id,
        "echo.certforge.tenant_id": tenant_id,
        "echo.certforge.ownership_token": ownership_token,
        "echo.certforge.isolation_profile": profile.identity_digest,
        "echo.certforge.runner_image": profile.image_digest,
    }
    mounts: list[dict[str, Any]] = []
    if input_directory is not None:
        source = input_directory.resolve(strict=True)
        if source == Path(source.anchor):
            raise IsolationFailure("input_directory_may_not_be_filesystem_root")
        mounts.append(
            {
                "Type": "bind",
                "Source": str(source),
                "Target": "/input",
                "ReadOnly": True,
                "BindOptions": {"Propagation": "rprivate"},
            }
        )
    if evidence_directory is not None:
        source = evidence_directory.resolve(strict=True)
        if source == Path(source.anchor):
            raise IsolationFailure("evidence_directory_may_not_be_filesystem_root")
        mounts.append(
            {
                "Type": "bind",
                "Source": str(source),
                "Target": "/evidence-out",
                "ReadOnly": False,
                "BindOptions": {"Propagation": "rprivate"},
            }
        )
    limits = profile.limits
    user_id, group_id = profile.user.split(":", 1)
    tmpfs_owner = f"uid={user_id},gid={group_id}"
    tmpfs_opts = f"rw,nosuid,nodev,noexec,size={limits.disk_bytes},mode=700,{tmpfs_owner}"
    return {
        "Image": profile.image_digest,
        "User": profile.user,
        "Cmd": list(command),
        "WorkingDir": "/workspace",
        "NetworkDisabled": True,
        "Labels": labels,
        "StopTimeout": min(30, limits.wall_time_seconds),
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "SecurityOpt": [
                "no-new-privileges:true",
                "seccomp=builtin",
                f"apparmor={profile.apparmor_profile}",
            ],
            "Memory": limits.memory_bytes,
            "MemorySwap": limits.memory_bytes,
            "NanoCpus": int(limits.cpu_cores * 1_000_000_000),
            "PidsLimit": limits.pids,
            "OomKillDisable": False,
            "AutoRemove": False,
            "Init": True,
            "Mounts": mounts,
            "Tmpfs": {
                "/tmp": f"rw,nosuid,nodev,noexec,size=16777216,mode=700,{tmpfs_owner}",
                "/run": f"rw,nosuid,nodev,noexec,size=8388608,mode=700,{tmpfs_owner}",
                "/workspace": tmpfs_opts,
            },
            "Ulimits": [
                {"Name": "fsize", "Soft": limits.file_size_bytes, "Hard": limits.file_size_bytes},
                {"Name": "nofile", "Soft": 1024, "Hard": 1024},
                {"Name": "nproc", "Soft": limits.pids, "Hard": limits.pids},
            ],
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}},
        },
    }


def validate_docker_inspect(inspect: dict[str, Any], profile: IsolationProfile) -> tuple[str, ...]:
    issues: list[str] = []
    config = inspect.get("Config") or {}
    host = inspect.get("HostConfig") or {}
    network = inspect.get("NetworkSettings") or {}
    labels = config.get("Labels") or {}
    if config.get("User") != profile.user:
        issues.append("user_mismatch")
    if not host.get("ReadonlyRootfs"):
        issues.append("rootfs_not_read_only")
    networks = network.get("Networks") or {}
    if host.get("NetworkMode") != "none" or any(name != "none" for name in networks):
        issues.append("network_not_denied")
    if sorted(host.get("CapDrop") or []) != ["ALL"]:
        issues.append("capabilities_not_fully_dropped")
    security = set(host.get("SecurityOpt") or [])
    required_security = {
        "no-new-privileges:true",
        "seccomp=builtin",
        f"apparmor={profile.apparmor_profile}",
    }
    if not required_security.issubset(security):
        issues.append("security_options_incomplete")
    limits = profile.limits
    expected = {
        "Memory": limits.memory_bytes,
        "MemorySwap": limits.memory_bytes,
        "NanoCpus": int(limits.cpu_cores * 1_000_000_000),
        "PidsLimit": limits.pids,
    }
    for field_name, expected_value in expected.items():
        if host.get(field_name) != expected_value:
            issues.append(f"limit_mismatch:{field_name}")
    if labels.get("echo.certforge.isolation_profile") != profile.identity_digest:
        issues.append("profile_identity_mismatch")
    mounts = host.get("Mounts") or []
    for mount in mounts:
        if mount.get("Source") in ("/var/run/docker.sock", "/run/docker.sock"):
            issues.append("docker_socket_exposed")
    return tuple(sorted(set(issues)))


def prepare_workspace(root: Path, *, run_id: str, tenant_id: str, ownership_token: str) -> Path:
    require_identifier(run_id, "run_id")
    require_identifier(tenant_id, "tenant_id")
    require_identifier(ownership_token, "ownership_token")
    root.mkdir(parents=True, exist_ok=True)
    workspace = contained_path(root, f"{tenant_id}/{run_id}")
    workspace.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(workspace, 0o700)
    marker = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "ownership_token": ownership_token,
    }
    (workspace / ".certforge-owner.json").write_text(canonical_json(marker), encoding="utf-8")
    return workspace


def verify_workspace_owner(workspace: Path, *, run_id: str, tenant_id: str, ownership_token: str) -> bool:
    marker_path = workspace / ".certforge-owner.json"
    if not marker_path.is_file() or marker_path.is_symlink():
        return False
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return marker == {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "ownership_token": ownership_token,
    }


def _validated_archive_name(name: str, destination: Path) -> Path:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        raise IsolationFailure("archive_member_is_absolute")
    return contained_path(destination, normalized)


def extract_archive_safely(archive_path: Path, destination: Path, *, max_total_bytes: int) -> tuple[str, ...]:
    if max_total_bytes <= 0:
        raise ValueError("max_total_bytes must be positive")
    destination.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    total = 0
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                target = _validated_archive_name(member.filename, destination)
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise IsolationFailure("archive_symlink_not_allowed")
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                total += member.file_size
                if total > max_total_bytes:
                    raise IsolationFailure("archive_expanded_size_limit_exceeded")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target.open("xb") as sink:
                    while chunk := source.read(1024 * 1024):
                        sink.write(chunk)
                extracted.append(member.filename)
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                target = _validated_archive_name(member.name, destination)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise IsolationFailure("archive_special_member_not_allowed")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise IsolationFailure("archive_member_type_not_supported")
                total += member.size
                if total > max_total_bytes:
                    raise IsolationFailure("archive_expanded_size_limit_exceeded")
                source = archive.extractfile(member)
                if source is None:
                    raise IsolationFailure("archive_member_content_missing")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as sink:
                    while chunk := source.read(1024 * 1024):
                        sink.write(chunk)
                extracted.append(member.name)
    else:
        raise IsolationFailure("unsupported_archive_format")
    return tuple(extracted)


def assert_no_symlinks(root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    for path in resolved_root.rglob("*"):
        if path.is_symlink():
            raise IsolationFailure(f"symlink_not_allowed:{path.relative_to(resolved_root).as_posix()}")


def build_admitted_docker_create_payload(
    profile: IsolationProfile,
    *,
    attestation: "ImageAttestation",
    admission_policy: "ImageAdmissionPolicy",
    run_id: str,
    tenant_id: str,
    ownership_token: str,
    command: Iterable[str],
    input_directory: Path | None = None,
    evidence_directory: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a production Docker payload only after exact image admission.

    The legacy payload builder remains available for P1/P2 regression fixtures. New
    production allocation paths must call this function so an unknown, drifted,
    expired, revoked, compromised, or role-mismatched image fails closed before
    Docker receives a create request.
    """
    from .supply_chain import ImageAdmissionPolicy, ImageAttestation, ImageRole, evaluate_image_admission

    if not isinstance(attestation, ImageAttestation) or not isinstance(admission_policy, ImageAdmissionPolicy):
        raise IsolationFailure("image_admission_contract_invalid")
    decision = evaluate_image_admission(attestation, admission_policy, now=now)
    if not decision.allowed:
        raise IsolationFailure("image_admission_denied:" + ",".join(decision.reasons))
    if decision.role is not ImageRole.RUNNER:
        raise IsolationFailure("image_admission_role_is_not_runner")
    if decision.image_digest != profile.image_digest:
        raise IsolationFailure("isolation_profile_image_digest_mismatch")
    payload = build_docker_create_payload(
        profile,
        run_id=run_id,
        tenant_id=tenant_id,
        ownership_token=ownership_token,
        command=command,
        input_directory=input_directory,
        evidence_directory=evidence_directory,
    )
    payload["Labels"]["echo.certforge.image_attestation_key"] = decision.attestation_key_id
    payload["Labels"]["echo.certforge.image_admission_policy"] = admission_policy.policy_id
    return payload


def assert_no_nested_archives(root: Path) -> None:
    """Reject recursive archive payloads after a bounded first-level extraction."""
    resolved_root = root.resolve(strict=True)
    for path in resolved_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            nested = zipfile.is_zipfile(path) or tarfile.is_tarfile(path)
        except OSError as exc:
            raise IsolationFailure(f"nested_archive_probe_failed:{path.name}") from exc
        if nested:
            raise IsolationFailure(f"nested_archive_not_allowed:{path.relative_to(resolved_root).as_posix()}")
