"""Production evidence custody bound to authenticated P2 runner leases.

The custody service is outside the runner. It accepts only authenticated,
run-scoped uploads, stores immutable chunk and artifact records, maintains a
tamper-evident audit chain, and computes deterministic Merkle roots.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator, Literal

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
from .evidence import merkle_root
from .runner import (
    RunnerCommand,
    RunnerLeaseState,
    RunnerStore,
    TERMINAL_RUNNER_STATES,
    TransportRequest,
    TrustedTransportRegistry,
)

_ZERO_HASH = "0" * 64


class CustodyError(RuntimeError):
    """Base custody failure."""


class CustodyAuthenticationError(CustodyError):
    """Run, tenant, transport, or lease validation failed."""


class EvidenceConflict(CustodyError):
    """An immutable evidence identity was reused with conflicting content."""


class EvidenceIncomplete(CustodyError):
    """An upload cannot be finalized because required bytes are absent."""


class EvidenceVisibility(StrEnum):
    RAW = "RAW"
    REDACTED = "REDACTED"
    PUBLIC = "PUBLIC"
    RESTRICTED = "RESTRICTED"


class RetentionEventType(StrEnum):
    RETENTION_SET = "RETENTION_SET"
    LEGAL_HOLD_PLACED = "LEGAL_HOLD_PLACED"
    LEGAL_HOLD_RELEASED = "LEGAL_HOLD_RELEASED"
    INVALIDATED = "INVALIDATED"


class EvidenceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: str
    tenant_id: str
    artifact_id: str
    declared_size_bytes: int = Field(ge=1, le=2 * 1024 * 1024 * 1024)
    declared_sha256: str
    media_type: str = Field(min_length=1, max_length=255)
    purpose: str = Field(min_length=1, max_length=256)
    visibility: EvidenceVisibility
    total_chunks: int = Field(ge=1, le=1_000_000)
    retention_until: datetime
    legal_hold: bool = False

    @model_validator(mode="after")
    def validate_manifest(self) -> "EvidenceManifest":
        for name in ("run_id", "tenant_id", "artifact_id"):
            require_identifier(getattr(self, name), name)
        require_sha256(self.declared_sha256, "declared_sha256")
        if self.retention_until.tzinfo is None:
            raise ValueError("retention_until must be timezone-aware")
        if not self.media_type.strip() or "/" not in self.media_type:
            raise ValueError("media_type must be a non-empty MIME type")
        if not self.purpose.strip():
            raise ValueError("purpose is required")
        return self

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class CustodyChunk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str
    chunk_index: int = Field(ge=0)
    total_chunks: int = Field(ge=1, le=1_000_000)
    chunk_sha256: str
    payload_b64: str

    @model_validator(mode="after")
    def validate_chunk(self) -> "CustodyChunk":
        require_identifier(self.artifact_id, "artifact_id")
        require_sha256(self.chunk_sha256, "chunk_sha256")
        if self.chunk_index >= self.total_chunks:
            raise ValueError("chunk_index must be less than total_chunks")
        try:
            payload = base64.b64decode(self.payload_b64, validate=True)
        except ValueError as exc:
            raise ValueError("payload_b64 is invalid") from exc
        if not payload:
            raise ValueError("evidence chunks may not be empty")
        if sha256_bytes(payload) != self.chunk_sha256:
            raise ValueError("chunk_sha256 does not match payload")
        return self

    @property
    def payload(self) -> bytes:
        return base64.b64decode(self.payload_b64, validate=True)


class CustodyStore:
    """SQLite metadata plus filesystem blobs, isolated from runner storage."""

    def __init__(
        self,
        db_path: Path,
        evidence_root: Path,
        runner_store: RunnerStore,
        transport_registry: TrustedTransportRegistry,
    ) -> None:
        self.db_path = db_path
        self.evidence_root = evidence_root
        self.runner_store = runner_store
        self.transport_registry = transport_registry
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS custody_runs (
            run_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            target_identity_digest TEXT NOT NULL,
            environment_identity_digest TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            mandatory_rules_digest TEXT NOT NULL,
            last_sequence INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS upload_manifests (
            run_id TEXT NOT NULL REFERENCES custody_runs(run_id),
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(run_id, artifact_id)
        );
        CREATE TABLE IF NOT EXISTS custody_chunks (
            run_id TEXT NOT NULL REFERENCES custody_runs(run_id),
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            total_chunks INTEGER NOT NULL,
            chunk_sha256 TEXT NOT NULL,
            payload_b64 TEXT NOT NULL,
            request_id TEXT NOT NULL UNIQUE,
            sequence INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(run_id, artifact_id, chunk_index),
            UNIQUE(run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS evidence_artifacts (
            artifact_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES custody_runs(run_id),
            tenant_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            relative_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            media_type TEXT NOT NULL,
            purpose TEXT NOT NULL,
            visibility TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            leaf_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, ordinal),
            UNIQUE(run_id, artifact_id)
        );
        CREATE TABLE IF NOT EXISTS upload_finalizations (
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            request_id TEXT NOT NULL UNIQUE,
            sequence INTEGER NOT NULL,
            artifact_sha256 TEXT NOT NULL,
            leaf_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(run_id, artifact_id),
            UNIQUE(run_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS custody_requests (
            request_id TEXT PRIMARY KEY,
            request_sha256 TEXT NOT NULL,
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS retention_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            retention_until TEXT,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS custody_audit (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_json TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            prev_chain_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_custody_audit_run ON custody_audit(run_id, event_id);
        CREATE INDEX IF NOT EXISTS idx_custody_chunks_upload ON custody_chunks(run_id, artifact_id, chunk_index);
        CREATE TRIGGER IF NOT EXISTS manifests_no_update BEFORE UPDATE ON upload_manifests
        BEGIN SELECT RAISE(ABORT, 'upload manifests are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS manifests_no_delete BEFORE DELETE ON upload_manifests
        BEGIN SELECT RAISE(ABORT, 'upload manifests are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS chunks_no_update BEFORE UPDATE ON custody_chunks
        BEGIN SELECT RAISE(ABORT, 'custody chunks are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS chunks_no_delete BEFORE DELETE ON custody_chunks
        BEGIN SELECT RAISE(ABORT, 'custody chunks are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS artifacts_no_update BEFORE UPDATE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence artifacts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS artifacts_no_delete BEFORE DELETE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence artifacts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS finalizations_no_update BEFORE UPDATE ON upload_finalizations
        BEGIN SELECT RAISE(ABORT, 'upload finalizations are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS finalizations_no_delete BEFORE DELETE ON upload_finalizations
        BEGIN SELECT RAISE(ABORT, 'upload finalizations are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS custody_requests_no_update BEFORE UPDATE ON custody_requests
        BEGIN SELECT RAISE(ABORT, 'custody requests are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS custody_requests_no_delete BEFORE DELETE ON custody_requests
        BEGIN SELECT RAISE(ABORT, 'custody requests are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_no_update BEFORE UPDATE ON retention_events
        BEGIN SELECT RAISE(ABORT, 'retention events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS retention_no_delete BEFORE DELETE ON retention_events
        BEGIN SELECT RAISE(ABORT, 'retention events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS custody_audit_no_update BEFORE UPDATE ON custody_audit
        BEGIN SELECT RAISE(ABORT, 'custody audit is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS custody_audit_no_delete BEFORE DELETE ON custody_audit
        BEGIN SELECT RAISE(ABORT, 'custody audit is append-only'); END;
        """
        with self._connection() as connection:
            connection.executescript(schema)

    def register_run(
        self,
        *,
        run_id: str,
        tenant_id: str,
        target_identity_digest: str,
        environment_identity_digest: str,
        policy_version: str,
        policy_digest: str,
        mandatory_rules_digest: str,
    ) -> dict[str, Any]:
        for name, value in (("run_id", run_id), ("tenant_id", tenant_id), ("policy_version", policy_version)):
            require_identifier(value, name)
        for name, value in (
            ("target_identity_digest", target_identity_digest),
            ("environment_identity_digest", environment_identity_digest),
            ("policy_digest", policy_digest),
            ("mandatory_rules_digest", mandatory_rules_digest),
        ):
            require_sha256(value, name)
        now = to_utc_iso(utc_now())
        values = (
            run_id,
            tenant_id,
            target_identity_digest,
            environment_identity_digest,
            policy_version,
            policy_digest,
            mandatory_rules_digest,
            now,
        )
        with self._connection() as connection:
            existing = connection.execute("SELECT * FROM custody_runs WHERE run_id = ?", (run_id,)).fetchone()
            if existing is not None:
                expected = tuple(existing[key] for key in (
                    "run_id", "tenant_id", "target_identity_digest", "environment_identity_digest",
                    "policy_version", "policy_digest", "mandatory_rules_digest", "created_at",
                ))
                if expected[:-1] != values[:-1]:
                    raise EvidenceConflict("run_identity_conflict")
                return dict(existing)
            connection.execute(
                """
                INSERT INTO custody_runs(
                    run_id, tenant_id, target_identity_digest, environment_identity_digest,
                    policy_version, policy_digest, mandatory_rules_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._append_audit(connection, run_id, tenant_id, "RUN_REGISTERED", {
                "target_identity_digest": target_identity_digest,
                "environment_identity_digest": environment_identity_digest,
                "policy_version": policy_version,
                "policy_digest": policy_digest,
                "mandatory_rules_digest": mandatory_rules_digest,
            }, now)
        return self.get_run(run_id, tenant_id)

    def get_run(self, run_id: str, tenant_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM custody_runs WHERE run_id = ? AND tenant_id = ?", (run_id, tenant_id)
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        return dict(row)

    def begin_upload(
        self,
        request: TransportRequest,
        manifest: EvidenceManifest,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now or utc_now()
        if request.command is not RunnerCommand.EVIDENCE_CHUNK:
            raise CustodyAuthenticationError("evidence_chunk_scope_required")
        if (manifest.run_id, manifest.tenant_id) != (request.run_id, request.tenant_id):
            raise CustodyAuthenticationError("manifest_transport_identity_mismatch")
        if request.body != {
            "operation": "begin_upload",
            "artifact_id": manifest.artifact_id,
            "manifest_sha256": manifest.identity_digest,
        }:
            raise CustodyAuthenticationError("begin_upload_body_mismatch")
        prior = self._authenticate_request(request, "begin_upload", current)
        if prior is not None:
            return prior
        self.get_run(request.run_id, request.tenant_id)
        now_iso = to_utc_iso(current)
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT * FROM upload_manifests WHERE run_id = ? AND artifact_id = ?",
                (request.run_id, manifest.artifact_id),
            ).fetchone()
            if existing is not None:
                if existing["manifest_sha256"] != manifest.identity_digest:
                    raise EvidenceConflict("artifact_manifest_conflict")
                result = self._manifest_result(existing)
            else:
                connection.execute(
                    """
                    INSERT INTO upload_manifests(
                        run_id, tenant_id, artifact_id, manifest_json, manifest_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.run_id,
                        request.tenant_id,
                        manifest.artifact_id,
                        canonical_json(manifest.model_dump(mode="json")),
                        manifest.identity_digest,
                        now_iso,
                    ),
                )
                self._advance_sequence(connection, request)
                self._append_audit(connection, request.run_id, request.tenant_id, "UPLOAD_BEGUN", {
                    "artifact_id": manifest.artifact_id,
                    "manifest_sha256": manifest.identity_digest,
                    "visibility": manifest.visibility.value,
                    "purpose": manifest.purpose,
                }, now_iso)
                row = connection.execute(
                    "SELECT * FROM upload_manifests WHERE run_id = ? AND artifact_id = ?",
                    (request.run_id, manifest.artifact_id),
                ).fetchone()
                assert row is not None
                result = self._manifest_result(row)
            self._record_request(connection, request, "begin_upload", result, now_iso)
        return result

    def append_chunk(
        self,
        request: TransportRequest,
        chunk: CustodyChunk,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now or utc_now()
        if request.command is not RunnerCommand.EVIDENCE_CHUNK:
            raise CustodyAuthenticationError("evidence_chunk_scope_required")
        expected_body = {
            "operation": "append_chunk",
            "artifact_id": chunk.artifact_id,
            "chunk_index": chunk.chunk_index,
            "chunk_sha256": chunk.chunk_sha256,
        }
        if request.body != expected_body:
            raise CustodyAuthenticationError("append_chunk_body_mismatch")
        prior = self._authenticate_request(request, "append_chunk", current)
        if prior is not None:
            return prior
        now_iso = to_utc_iso(current)
        with self._connection() as connection:
            manifest_row = self._manifest_row(connection, request.run_id, request.tenant_id, chunk.artifact_id)
            manifest = EvidenceManifest.model_validate_json(manifest_row["manifest_json"])
            if chunk.total_chunks != manifest.total_chunks:
                raise EvidenceConflict("chunk_total_mismatch")
            existing = connection.execute(
                "SELECT * FROM custody_chunks WHERE run_id = ? AND artifact_id = ? AND chunk_index = ?",
                (request.run_id, chunk.artifact_id, chunk.chunk_index),
            ).fetchone()
            if existing is not None:
                raise EvidenceConflict("duplicate_chunk")
            received_size = connection.execute(
                "SELECT COALESCE(SUM(LENGTH(payload_b64)), 0) AS encoded FROM custody_chunks WHERE run_id = ? AND artifact_id = ?",
                (request.run_id, chunk.artifact_id),
            ).fetchone()["encoded"]
            if int(received_size) + len(chunk.payload_b64) > ((manifest.declared_size_bytes + 2) // 3) * 4 + 4 * manifest.total_chunks:
                raise EvidenceConflict("declared_size_exceeded")
            self._advance_sequence(connection, request)
            connection.execute(
                """
                INSERT INTO custody_chunks(
                    run_id, tenant_id, artifact_id, chunk_index, total_chunks,
                    chunk_sha256, payload_b64, request_id, sequence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.run_id,
                    request.tenant_id,
                    chunk.artifact_id,
                    chunk.chunk_index,
                    chunk.total_chunks,
                    chunk.chunk_sha256,
                    chunk.payload_b64,
                    request.request_id,
                    request.sequence,
                    now_iso,
                ),
            )
            result = self._upload_status(connection, request.run_id, request.tenant_id, chunk.artifact_id)
            self._append_audit(connection, request.run_id, request.tenant_id, "CHUNK_ACCEPTED", {
                "artifact_id": chunk.artifact_id,
                "chunk_index": chunk.chunk_index,
                "chunk_sha256": chunk.chunk_sha256,
                "sequence": request.sequence,
            }, now_iso)
            self._record_request(connection, request, "append_chunk", result, now_iso)
        return result

    def finalize_upload(
        self,
        request: TransportRequest,
        artifact_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        require_identifier(artifact_id, "artifact_id")
        current = now or utc_now()
        expected_body = {"operation": "finalize_upload", "artifact_id": artifact_id}
        if request.command is not RunnerCommand.EVIDENCE_CHUNK or request.body != expected_body:
            raise CustodyAuthenticationError("finalize_upload_body_mismatch")
        prior = self._authenticate_request(request, "finalize_upload", current)
        if prior is not None:
            return prior
        now_iso = to_utc_iso(current)
        with self._connection() as connection:
            manifest_row = self._manifest_row(connection, request.run_id, request.tenant_id, artifact_id)
            manifest = EvidenceManifest.model_validate_json(manifest_row["manifest_json"])
            existing = connection.execute(
                "SELECT * FROM evidence_artifacts WHERE run_id = ? AND artifact_id = ?",
                (request.run_id, artifact_id),
            ).fetchone()
            if existing is not None:
                result = dict(existing)
                self._record_request(connection, request, "finalize_upload", result, now_iso)
                return result
            rows = connection.execute(
                """
                SELECT * FROM custody_chunks
                WHERE run_id = ? AND tenant_id = ? AND artifact_id = ? ORDER BY chunk_index
                """,
                (request.run_id, request.tenant_id, artifact_id),
            ).fetchall()
            received = [int(row["chunk_index"]) for row in rows]
            expected = list(range(manifest.total_chunks))
            if received != expected:
                raise EvidenceIncomplete(f"missing_chunks:{sorted(set(expected) - set(received))}")
            content = b"".join(base64.b64decode(row["payload_b64"], validate=True) for row in rows)
            if len(content) != manifest.declared_size_bytes:
                raise EvidenceConflict("artifact_size_mismatch")
            digest = sha256_bytes(content)
            if digest != manifest.declared_sha256:
                raise EvidenceConflict("artifact_digest_mismatch")
            ordinal_row = connection.execute(
                "SELECT COALESCE(MAX(ordinal), 0) + 1 AS next_ordinal FROM evidence_artifacts WHERE run_id = ?",
                (request.run_id,),
            ).fetchone()
            ordinal = int(ordinal_row["next_ordinal"])
            relative_path = (
                f"{request.tenant_id}/{request.run_id}/{manifest.visibility.value.lower()}/{artifact_id}.bin"
            )
            descriptor = {
                "artifact_id": artifact_id,
                "run_id": request.run_id,
                "tenant_id": request.tenant_id,
                "ordinal": ordinal,
                "relative_path": relative_path,
                "size_bytes": len(content),
                "sha256": digest,
                "media_type": manifest.media_type,
                "purpose": manifest.purpose,
                "visibility": manifest.visibility.value,
                "manifest_sha256": manifest.identity_digest,
                "created_at": now_iso,
            }
            leaf_hash = sha256_json(descriptor)
            destination = contained_path(self.evidence_root, relative_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise EvidenceConflict("artifact_path_already_exists")
            fd, temporary_name = tempfile.mkstemp(prefix=f".{artifact_id}.", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_name, destination)
                self._advance_sequence(connection, request)
                connection.execute(
                    """
                    INSERT INTO evidence_artifacts(
                        artifact_id, run_id, tenant_id, ordinal, relative_path, size_bytes,
                        sha256, media_type, purpose, visibility, manifest_sha256, leaf_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact_id,
                        request.run_id,
                        request.tenant_id,
                        ordinal,
                        relative_path,
                        len(content),
                        digest,
                        manifest.media_type,
                        manifest.purpose,
                        manifest.visibility.value,
                        manifest.identity_digest,
                        leaf_hash,
                        now_iso,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO upload_finalizations(
                        run_id, tenant_id, artifact_id, request_id, sequence,
                        artifact_sha256, leaf_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.run_id,
                        request.tenant_id,
                        artifact_id,
                        request.request_id,
                        request.sequence,
                        digest,
                        leaf_hash,
                        now_iso,
                    ),
                )
                event_type = (
                    RetentionEventType.LEGAL_HOLD_PLACED
                    if manifest.legal_hold
                    else RetentionEventType.RETENTION_SET
                )
                connection.execute(
                    """
                    INSERT INTO retention_events(
                        run_id, tenant_id, artifact_id, event_type, retention_until,
                        actor, reason, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.run_id,
                        request.tenant_id,
                        artifact_id,
                        event_type.value,
                        to_utc_iso(manifest.retention_until),
                        "custody.service",
                        "manifest policy",
                        now_iso,
                    ),
                )
                self._append_audit(connection, request.run_id, request.tenant_id, "ARTIFACT_FINALIZED", {
                    "artifact_id": artifact_id,
                    "artifact_sha256": digest,
                    "leaf_hash": leaf_hash,
                    "ordinal": ordinal,
                    "visibility": manifest.visibility.value,
                }, now_iso)
                result = {**descriptor, "leaf_hash": leaf_hash}
                self._record_request(connection, request, "finalize_upload", result, now_iso)
            except Exception:
                Path(temporary_name).unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise
        return result

    def upload_status(self, run_id: str, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            return self._upload_status(connection, run_id, tenant_id, artifact_id)

    def get_artifact(
        self,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
        *,
        allow_restricted: bool = False,
    ) -> tuple[dict[str, Any], bytes]:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM evidence_artifacts
                WHERE run_id = ? AND tenant_id = ? AND artifact_id = ?
                """,
                (run_id, tenant_id, artifact_id),
            ).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        descriptor = dict(row)
        if descriptor["visibility"] == EvidenceVisibility.RESTRICTED.value and not allow_restricted:
            raise PermissionError("restricted_evidence_requires_explicit_authorization")
        path = contained_path(self.evidence_root, descriptor["relative_path"])
        content = path.read_bytes()
        if len(content) != descriptor["size_bytes"] or sha256_bytes(content) != descriptor["sha256"]:
            raise CustodyError("artifact_integrity_failure")
        return descriptor, content

    def append_retention_event(
        self,
        *,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
        event_type: RetentionEventType,
        actor: str,
        reason: str,
        retention_until: datetime | None = None,
    ) -> dict[str, Any]:
        require_identifier(actor, "actor")
        if not reason.strip():
            raise ValueError("retention reason is required")
        if retention_until is not None and retention_until.tzinfo is None:
            raise ValueError("retention_until must be timezone-aware")
        self.get_artifact(run_id, tenant_id, artifact_id, allow_restricted=True)
        now_iso = to_utc_iso(utc_now())
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO retention_events(
                    run_id, tenant_id, artifact_id, event_type, retention_until,
                    actor, reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    tenant_id,
                    artifact_id,
                    event_type.value,
                    None if retention_until is None else to_utc_iso(retention_until),
                    actor,
                    reason,
                    now_iso,
                ),
            )
            self._append_audit(connection, run_id, tenant_id, "RETENTION_EVENT", {
                "artifact_id": artifact_id,
                "event_type": event_type.value,
                "actor": actor,
                "reason": reason,
                "retention_until": None if retention_until is None else to_utc_iso(retention_until),
            }, now_iso)
            row = connection.execute("SELECT * FROM retention_events WHERE event_id = ?", (cursor.lastrowid,)).fetchone()
            assert row is not None
            return dict(row)

    def retention_state(self, run_id: str, tenant_id: str, artifact_id: str) -> dict[str, Any]:
        self.get_artifact(run_id, tenant_id, artifact_id, allow_restricted=True)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM retention_events
                WHERE run_id = ? AND tenant_id = ? AND artifact_id = ? ORDER BY event_id
                """,
                (run_id, tenant_id, artifact_id),
            ).fetchall()
        legal_hold = False
        retention_until: str | None = None
        invalidated = False
        for row in rows:
            event_type = RetentionEventType(row["event_type"])
            if event_type is RetentionEventType.LEGAL_HOLD_PLACED:
                legal_hold = True
            elif event_type is RetentionEventType.LEGAL_HOLD_RELEASED:
                legal_hold = False
            elif event_type is RetentionEventType.RETENTION_SET:
                retention_until = row["retention_until"]
            elif event_type is RetentionEventType.INVALIDATED:
                invalidated = True
        return {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "artifact_id": artifact_id,
            "legal_hold": legal_hold,
            "retention_until": retention_until,
            "invalidated": invalidated,
            "event_count": len(rows),
        }

    def delete_artifact(self, *_: Any, **__: Any) -> None:
        raise PermissionError("evidence_deletion_not_supported_by_custody_contract")

    def verify_run(self, run_id: str, tenant_id: str) -> dict[str, Any]:
        self.get_run(run_id, tenant_id)
        invalid: list[dict[str, str]] = []
        leaf_hashes: list[str] = []
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence_artifacts
                WHERE run_id = ? AND tenant_id = ? ORDER BY ordinal
                """,
                (run_id, tenant_id),
            ).fetchall()
            manifest_rows = connection.execute(
                "SELECT artifact_id FROM upload_manifests WHERE run_id = ? AND tenant_id = ?",
                (run_id, tenant_id),
            ).fetchall()
            finalized = {
                row["artifact_id"]
                for row in connection.execute(
                    "SELECT artifact_id FROM upload_finalizations WHERE run_id = ? AND tenant_id = ?",
                    (run_id, tenant_id),
                ).fetchall()
            }
        for expected_ordinal, row in enumerate(rows, start=1):
            descriptor = {
                "artifact_id": row["artifact_id"],
                "run_id": row["run_id"],
                "tenant_id": row["tenant_id"],
                "ordinal": row["ordinal"],
                "relative_path": row["relative_path"],
                "size_bytes": row["size_bytes"],
                "sha256": row["sha256"],
                "media_type": row["media_type"],
                "purpose": row["purpose"],
                "visibility": row["visibility"],
                "manifest_sha256": row["manifest_sha256"],
                "created_at": row["created_at"],
            }
            reasons: list[str] = []
            leaf_hash = sha256_json(descriptor)
            if int(row["ordinal"]) != expected_ordinal:
                reasons.append("ordinal_gap")
            if leaf_hash != row["leaf_hash"]:
                reasons.append("leaf_hash_mismatch")
            try:
                path = contained_path(self.evidence_root, row["relative_path"])
                content = path.read_bytes()
                if len(content) != int(row["size_bytes"]):
                    reasons.append("size_mismatch")
                if sha256_bytes(content) != row["sha256"]:
                    reasons.append("digest_mismatch")
            except (OSError, ValueError):
                reasons.append("artifact_unavailable")
            if reasons:
                invalid.append({"artifact_id": row["artifact_id"], "reason": ",".join(sorted(reasons))})
            leaf_hashes.append(leaf_hash)
        incomplete = sorted(row["artifact_id"] for row in manifest_rows if row["artifact_id"] not in finalized)
        audit = self.verify_audit(run_id, tenant_id)
        return {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "valid": bool(rows) and not invalid and not incomplete and audit["valid"],
            "artifact_count": len(rows),
            "invalid_artifacts": invalid,
            "incomplete_artifacts": incomplete,
            "merkle_root": merkle_root(leaf_hashes),
            "audit": audit,
        }

    def verify_audit(self, run_id: str, tenant_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM custody_audit
                WHERE run_id = ? AND tenant_id = ? ORDER BY event_id
                """,
                (run_id, tenant_id),
            ).fetchall()
        previous = _ZERO_HASH
        failures: list[int] = []
        for row in rows:
            calculated_event_hash = sha256_json(json.loads(row["event_json"]))
            calculated_chain = sha256_bytes(bytes.fromhex(previous) + bytes.fromhex(calculated_event_hash))
            if (
                row["event_hash"] != calculated_event_hash
                or row["prev_chain_hash"] != previous
                or row["chain_hash"] != calculated_chain
            ):
                failures.append(int(row["event_id"]))
            previous = calculated_chain
        return {
            "valid": bool(rows) and not failures,
            "event_count": len(rows),
            "chain_tip": previous,
            "invalid_event_ids": failures,
        }

    def _authenticate_request(
        self,
        request: TransportRequest,
        operation: str,
        current: datetime,
    ) -> dict[str, Any] | None:
        auth = self.runner_store.authenticate(request, self.transport_registry, now=current)
        lease = self.runner_store.get_lease(request.run_id, request.tenant_id)
        if lease["runner_id"] != request.runner_id:
            raise CustodyAuthenticationError("lease_runner_mismatch")
        if current >= parse_utc_iso(lease["lease_expires_at"]):
            raise CustodyAuthenticationError("lease_expired")
        if RunnerLeaseState(lease["state"]) in TERMINAL_RUNNER_STATES:
            raise CustodyAuthenticationError("terminal_lease_rejected")
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT * FROM custody_requests WHERE request_id = ?", (request.request_id,)
            ).fetchone()
        if auth.idempotent:
            if existing is None:
                return None
            if existing["request_sha256"] != request.request_sha256 or existing["operation"] != operation:
                raise EvidenceConflict("idempotent_request_conflict")
            return json.loads(existing["result_json"])
        if existing is not None:
            raise EvidenceConflict("request_identity_conflict")
        return None

    def _advance_sequence(self, connection: sqlite3.Connection, request: TransportRequest) -> None:
        row = connection.execute(
            "SELECT last_sequence FROM custody_runs WHERE run_id = ? AND tenant_id = ?",
            (request.run_id, request.tenant_id),
        ).fetchone()
        if row is None:
            raise KeyError(request.run_id)
        if request.sequence <= int(row["last_sequence"]):
            raise EvidenceConflict("evidence_sequence_rollback")
        connection.execute(
            "UPDATE custody_runs SET last_sequence = ? WHERE run_id = ? AND tenant_id = ?",
            (request.sequence, request.run_id, request.tenant_id),
        )

    @staticmethod
    def _record_request(
        connection: sqlite3.Connection,
        request: TransportRequest,
        operation: str,
        result: dict[str, Any],
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO custody_requests(
                request_id, request_sha256, run_id, tenant_id, operation, result_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.request_id,
                request.request_sha256,
                request.run_id,
                request.tenant_id,
                operation,
                canonical_json(result),
                created_at,
            ),
        )

    @staticmethod
    def _manifest_result(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "tenant_id": row["tenant_id"],
            "artifact_id": row["artifact_id"],
            "manifest_sha256": row["manifest_sha256"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _manifest_row(
        connection: sqlite3.Connection,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM upload_manifests
            WHERE run_id = ? AND tenant_id = ? AND artifact_id = ?
            """,
            (run_id, tenant_id, artifact_id),
        ).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        return row

    def _upload_status(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
    ) -> dict[str, Any]:
        manifest_row = self._manifest_row(connection, run_id, tenant_id, artifact_id)
        manifest = EvidenceManifest.model_validate_json(manifest_row["manifest_json"])
        received = [
            int(row["chunk_index"])
            for row in connection.execute(
                """
                SELECT chunk_index FROM custody_chunks
                WHERE run_id = ? AND tenant_id = ? AND artifact_id = ? ORDER BY chunk_index
                """,
                (run_id, tenant_id, artifact_id),
            ).fetchall()
        ]
        final = connection.execute(
            "SELECT 1 FROM upload_finalizations WHERE run_id = ? AND tenant_id = ? AND artifact_id = ?",
            (run_id, tenant_id, artifact_id),
        ).fetchone()
        missing = sorted(set(range(manifest.total_chunks)) - set(received))
        return {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "artifact_id": artifact_id,
            "received_chunks": received,
            "missing_chunks": missing,
            "expected_total_chunks": manifest.total_chunks,
            "complete": final is not None,
            "manifest_sha256": manifest.identity_digest,
        }

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        run_id: str,
        tenant_id: str,
        event_type: str,
        details: dict[str, Any],
        created_at: str,
    ) -> None:
        previous = connection.execute(
            "SELECT chain_hash FROM custody_audit WHERE run_id = ? ORDER BY event_id DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        prev_chain_hash = _ZERO_HASH if previous is None else str(previous["chain_hash"])
        event = {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "details": details,
            "created_at": created_at,
        }
        event_hash = sha256_json(event)
        chain_hash = sha256_bytes(bytes.fromhex(prev_chain_hash) + bytes.fromhex(event_hash))
        connection.execute(
            """
            INSERT INTO custody_audit(
                run_id, tenant_id, event_type, event_json, event_hash,
                prev_chain_hash, chain_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                tenant_id,
                event_type,
                canonical_json(event),
                event_hash,
                prev_chain_hash,
                chain_hash,
                created_at,
            ),
        )
