"""Authenticated worker-heartbeat and adapter-inventory telemetry.

The subscriber telemetry surface must never infer runner availability from quota or
trust an unsigned adapter catalog.  This module accepts only control-plane-issued,
short-lived runner credentials paired with Ed25519-signed runner responses, then
projects a bounded tenant-scoped snapshot.  Missing and stale reports remain
explicitly non-green.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .adapter_transport import parse_verified_adapter_bundle
from .canonical import canonical_json, parse_utc_iso, sha256_json, to_utc_iso, utc_now
from .runner import (
    RunnerCommand,
    RunnerResponse,
    SignedRunCredential,
    TrustedTransportRegistry,
    verify_runner_response,
)
from .windows_package import WindowsPackageResultBody


class OperationalTelemetryError(RuntimeError):
    """An operational report failed authentication or monotonicity checks."""

    def __init__(self, code: str, status_code: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class SignedOperationalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: SignedRunCredential
    response: RunnerResponse


class WorkerHeartbeatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["worker_heartbeat"]
    health: Literal["HEALTHY", "DEGRADED"]
    capacity_total: int = Field(ge=1, le=100_000)
    capacity_available: int = Field(ge=0, le=100_000)
    active_run_count: int = Field(ge=0, le=100_000)
    worker_image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class OperationalTelemetryRegistry:
    """Durable verified reports sharing the control-plane SQLite database."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS authenticated_operational_reports (
                    response_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    report_kind TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authenticated_worker_heartbeats (
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    response_id TEXT NOT NULL UNIQUE,
                    sequence INTEGER NOT NULL,
                    health TEXT NOT NULL,
                    capacity_total INTEGER NOT NULL,
                    capacity_available INTEGER NOT NULL,
                    active_run_count INTEGER NOT NULL,
                    worker_image_sha256 TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    control_plane_key_id TEXT NOT NULL,
                    runner_key_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, runner_id)
                );
                CREATE INDEX IF NOT EXISTS idx_authenticated_heartbeat_tenant_time
                    ON authenticated_worker_heartbeats(tenant_id, observed_at DESC);
                CREATE TABLE IF NOT EXISTS authenticated_windows_package_results (
                    run_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    response_id TEXT NOT NULL UNIQUE,
                    sequence INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    control_plane_key_id TEXT NOT NULL,
                    runner_key_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, tenant_id)
                );
                CREATE INDEX IF NOT EXISTS idx_windows_package_result_tenant_time
                    ON authenticated_windows_package_results(tenant_id, observed_at DESC);
                CREATE TABLE IF NOT EXISTS authenticated_adapter_inventory (
                    tenant_id TEXT NOT NULL,
                    adapter_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    identity_digest TEXT NOT NULL,
                    maturity TEXT NOT NULL,
                    quality_score REAL NOT NULL,
                    quality_cases INTEGER NOT NULL,
                    execution_node TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,
                    response_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    control_plane_key_id TEXT NOT NULL,
                    runner_key_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, adapter_id)
                );
                CREATE INDEX IF NOT EXISTS idx_authenticated_adapter_tenant_maturity
                    ON authenticated_adapter_inventory(tenant_id, maturity);
                CREATE TABLE IF NOT EXISTS operational_quarantines (
                    tenant_id TEXT NOT NULL,
                    subject_type TEXT NOT NULL CHECK(subject_type IN ('runner', 'adapter')),
                    subject_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    quarantined_by TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    released_by TEXT,
                    release_reason TEXT,
                    released_at TEXT,
                    PRIMARY KEY(tenant_id, subject_type, subject_id)
                );
                CREATE INDEX IF NOT EXISTS idx_operational_quarantine_active
                    ON operational_quarantines(tenant_id, subject_type, released_at);
                CREATE TABLE IF NOT EXISTS operational_trust_keys (
                    tenant_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'OVERLAP', 'RETIRED', 'BLOCKED')),
                    replaces_key_id TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    retired_at TEXT,
                    PRIMARY KEY(tenant_id, key_id)
                );
                CREATE TABLE IF NOT EXISTS operational_key_rotations (
                    tenant_id TEXT NOT NULL,
                    rotation_id TEXT NOT NULL,
                    old_key_id TEXT NOT NULL,
                    new_key_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('OVERLAP', 'FINALIZED', 'BLOCKED')),
                    reason TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    overlap_expires_at TEXT NOT NULL,
                    finalized_by TEXT,
                    finalized_at TEXT,
                    PRIMARY KEY(tenant_id, rotation_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_operational_rotation_active
                    ON operational_key_rotations(tenant_id) WHERE state = 'OVERLAP';
                CREATE TABLE IF NOT EXISTS operational_runner_enrollments (
                    tenant_id TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED')),
                    runner_key_id TEXT NOT NULL,
                    worker_image_sha256 TEXT NOT NULL,
                    enrolled_by TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    revoked_by TEXT,
                    revoked_at TEXT,
                    revoke_reason TEXT,
                    PRIMARY KEY(tenant_id, runner_id)
                );
                CREATE TABLE IF NOT EXISTS operational_enrollment_policy (
                    tenant_id TEXT PRIMARY KEY,
                    enforced INTEGER NOT NULL CHECK(enforced IN (0, 1)),
                    enabled_by TEXT NOT NULL,
                    enabled_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(
                connection,
                "authenticated_worker_heartbeats",
                "control_plane_key_id",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                connection,
                "authenticated_adapter_inventory",
                "control_plane_key_id",
                "TEXT NOT NULL DEFAULT ''",
            )

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        existing = {
            str(row["name"])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def hydrate_transport_registry(self, trusted: TrustedTransportRegistry) -> None:
        """Apply durable tenant trust state after static bootstrap keys are loaded."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, key_id, public_key_pem, state
                FROM operational_trust_keys ORDER BY created_at, key_id
                """
            ).fetchall()
        for row in rows:
            key_id = str(row["key_id"])
            if row["state"] in {"ACTIVE", "OVERLAP"}:
                loaded_id = trusted.add_pem(
                    str(row["public_key_pem"]), tenant_id=str(row["tenant_id"])
                )
                if loaded_id != key_id:
                    trusted.remove(loaded_id)
                    raise OperationalTelemetryError("operational_trust_key_id_mismatch", 500)
            else:
                trusted.remove(key_id)

    def begin_key_rotation(
        self,
        tenant_id: str,
        *,
        old_key_id: str,
        new_public_key_pem: str,
        reason: str,
        actor: str,
        trusted: TrustedTransportRegistry,
        overlap_seconds: int = 3600,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Start a bounded old/new overlap without accepting private key material."""
        current = now or utc_now()
        if old_key_id not in trusted.keys:
            raise OperationalTelemetryError("old_operational_key_not_trusted", 404)
        bound_tenant = trusted.key_tenants.get(old_key_id)
        if bound_tenant is not None and bound_tenant != tenant_id:
            raise OperationalTelemetryError("old_operational_key_tenant_mismatch", 403)
        candidate = TrustedTransportRegistry.empty()
        try:
            new_key_id = candidate.add_pem(new_public_key_pem, tenant_id=tenant_id)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise OperationalTelemetryError("new_operational_key_invalid", 422) from exc
        if new_key_id == old_key_id:
            raise OperationalTelemetryError("operational_rotation_key_unchanged", 409)
        started_at = to_utc_iso(current)
        expires_at = to_utc_iso(current + timedelta(seconds=overlap_seconds))
        rotation_id = "oprot-" + sha256_json(
            {
                "tenant_id": tenant_id,
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "started_at": started_at,
            }
        )[:24]
        old_public_key_pem = trusted.public_key_pem(old_key_id)
        with self._connect() as connection:
            active = connection.execute(
                "SELECT 1 FROM operational_key_rotations WHERE tenant_id = ? AND state = 'OVERLAP'",
                (tenant_id,),
            ).fetchone()
            if active is not None:
                raise OperationalTelemetryError("operational_rotation_already_active", 409)
            connection.execute(
                """
                INSERT INTO operational_trust_keys(
                    tenant_id, key_id, public_key_pem, state, replaces_key_id,
                    created_by, created_at, retired_at
                ) VALUES (?, ?, ?, 'ACTIVE', NULL, ?, ?, NULL)
                ON CONFLICT(tenant_id, key_id) DO NOTHING
                """,
                (tenant_id, old_key_id, old_public_key_pem, actor, started_at),
            )
            connection.execute(
                """
                INSERT INTO operational_trust_keys(
                    tenant_id, key_id, public_key_pem, state, replaces_key_id,
                    created_by, created_at, retired_at
                ) VALUES (?, ?, ?, 'OVERLAP', ?, ?, ?, NULL)
                ON CONFLICT(tenant_id, key_id) DO UPDATE SET
                    public_key_pem=excluded.public_key_pem,
                    state='OVERLAP', replaces_key_id=excluded.replaces_key_id,
                    created_by=excluded.created_by, created_at=excluded.created_at,
                    retired_at=NULL
                """,
                (
                    tenant_id,
                    new_key_id,
                    new_public_key_pem,
                    old_key_id,
                    actor,
                    started_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO operational_key_rotations(
                    tenant_id, rotation_id, old_key_id, new_key_id, state,
                    reason, started_by, started_at, overlap_expires_at,
                    finalized_by, finalized_at
                ) VALUES (?, ?, ?, ?, 'OVERLAP', ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    tenant_id,
                    rotation_id,
                    old_key_id,
                    new_key_id,
                    reason,
                    actor,
                    started_at,
                    expires_at,
                ),
            )
        trusted.add_pem(new_public_key_pem, tenant_id=tenant_id)
        return {
            "rotation_id": rotation_id,
            "state": "OVERLAP",
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "started_at": started_at,
            "overlap_expires_at": expires_at,
            "proof_received": False,
        }

    def key_rotation_status(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT rotation_id, old_key_id, new_key_id, state, reason,
                       started_at, overlap_expires_at, finalized_at
                FROM operational_key_rotations
                WHERE tenant_id=? ORDER BY started_at DESC LIMIT 25
                """,
                (tenant_id,),
            ).fetchall()
            result = []
            for row in rows:
                result.append(
                    {
                        "rotation_id": str(row["rotation_id"]),
                        "old_key_id": str(row["old_key_id"]),
                        "new_key_id": str(row["new_key_id"]),
                        "state": str(row["state"]),
                        "reason": str(row["reason"]),
                        "started_at": str(row["started_at"]),
                        "overlap_expires_at": str(row["overlap_expires_at"]),
                        "finalized_at": (
                            str(row["finalized_at"]) if row["finalized_at"] is not None else None
                        ),
                        "proof_received": self._rotation_proof_exists(
                            connection,
                            tenant_id,
                            str(row["new_key_id"]),
                            str(row["started_at"]),
                        ),
                    }
                )
        return result

    @staticmethod
    def _rotation_proof_exists(
        connection: sqlite3.Connection,
        tenant_id: str,
        new_key_id: str,
        started_at: str,
    ) -> bool:
        row = connection.execute(
            """
            SELECT 1 FROM (
                SELECT control_plane_key_id, received_at
                FROM authenticated_worker_heartbeats WHERE tenant_id = ?
                UNION ALL
                SELECT control_plane_key_id, received_at
                FROM authenticated_adapter_inventory WHERE tenant_id = ?
            ) WHERE control_plane_key_id = ? AND received_at >= ? LIMIT 1
            """,
            (tenant_id, tenant_id, new_key_id, started_at),
        ).fetchone()
        return row is not None

    def finalize_key_rotation(
        self,
        tenant_id: str,
        *,
        rotation_id: str,
        actor: str,
        trusted: TrustedTransportRegistry,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Retire the old key only after a new-key-authenticated operational report."""
        current = to_utc_iso(now or utc_now())
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT old_key_id, new_key_id, state, started_at, overlap_expires_at
                FROM operational_key_rotations
                WHERE tenant_id = ? AND rotation_id = ?
                """,
                (tenant_id, rotation_id),
            ).fetchone()
            if row is None:
                raise OperationalTelemetryError("operational_rotation_not_found", 404)
            if row["state"] == "FINALIZED":
                return {
                    "rotation_id": rotation_id,
                    "state": "FINALIZED",
                    "old_key_id": str(row["old_key_id"]),
                    "new_key_id": str(row["new_key_id"]),
                    "proof_received": True,
                    "idempotent": True,
                }
            if row["state"] != "OVERLAP":
                raise OperationalTelemetryError("operational_rotation_blocked", 409)
            if not self._rotation_proof_exists(
                connection,
                tenant_id,
                str(row["new_key_id"]),
                str(row["started_at"]),
            ):
                raise OperationalTelemetryError("new_operational_key_unproven", 409)
            connection.execute(
                """
                UPDATE operational_key_rotations
                SET state='FINALIZED', finalized_by=?, finalized_at=?
                WHERE tenant_id=? AND rotation_id=? AND state='OVERLAP'
                """,
                (actor, current, tenant_id, rotation_id),
            )
            connection.execute(
                """
                UPDATE operational_trust_keys SET state='RETIRED', retired_at=?
                WHERE tenant_id=? AND key_id=?
                """,
                (current, tenant_id, str(row["old_key_id"])),
            )
            connection.execute(
                """
                UPDATE operational_trust_keys SET state='ACTIVE'
                WHERE tenant_id=? AND key_id=?
                """,
                (tenant_id, str(row["new_key_id"])),
            )
        trusted.remove(str(row["old_key_id"]))
        return {
            "rotation_id": rotation_id,
            "state": "FINALIZED",
            "old_key_id": str(row["old_key_id"]),
            "new_key_id": str(row["new_key_id"]),
            "proof_received": True,
            "idempotent": False,
            "finalized_at": current,
        }

    def reconcile_key_rotations(
        self,
        trusted: TrustedTransportRegistry,
        *,
        now: datetime,
    ) -> None:
        """Fail closed when an overlap expires before the new key proves possession."""
        current = to_utc_iso(now)
        blocked: list[tuple[str, str]] = []
        finalized: list[str] = []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, rotation_id, old_key_id, new_key_id, started_at
                FROM operational_key_rotations
                WHERE state='OVERLAP' AND overlap_expires_at <= ?
                """,
                (current,),
            ).fetchall()
            for row in rows:
                tenant_id = str(row["tenant_id"])
                old_key_id = str(row["old_key_id"])
                new_key_id = str(row["new_key_id"])
                if self._rotation_proof_exists(
                    connection, tenant_id, new_key_id, str(row["started_at"])
                ):
                    state = "FINALIZED"
                    connection.execute(
                        """
                        UPDATE operational_trust_keys SET state='RETIRED', retired_at=?
                        WHERE tenant_id=? AND key_id=?
                        """,
                        (current, tenant_id, old_key_id),
                    )
                    connection.execute(
                        "UPDATE operational_trust_keys SET state='ACTIVE' WHERE tenant_id=? AND key_id=?",
                        (tenant_id, new_key_id),
                    )
                    finalized.append(old_key_id)
                else:
                    state = "BLOCKED"
                    connection.execute(
                        """
                        UPDATE operational_trust_keys SET state='BLOCKED', retired_at=?
                        WHERE tenant_id=? AND key_id IN (?, ?)
                        """,
                        (current, tenant_id, old_key_id, new_key_id),
                    )
                    blocked.append((old_key_id, new_key_id))
                connection.execute(
                    """
                    UPDATE operational_key_rotations
                    SET state=?, finalized_by='system:overlap-expiry', finalized_at=?
                    WHERE tenant_id=? AND rotation_id=?
                    """,
                    (state, current, tenant_id, str(row["rotation_id"])),
                )
        for key_id in finalized:
            trusted.remove(key_id)
        for old_key_id, new_key_id in blocked:
            trusted.remove(old_key_id)
            trusted.remove(new_key_id)

    def enroll_runner(
        self,
        tenant_id: str,
        *,
        runner_id: str,
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Pin a known authenticated runner to its signing identity and image digest."""
        current = to_utc_iso(now or utc_now())
        with self._connect() as connection:
            source = connection.execute(
                """
                SELECT runner_key_id, worker_image_sha256
                FROM authenticated_worker_heartbeats
                WHERE tenant_id=? AND runner_id=?
                """,
                (tenant_id, runner_id),
            ).fetchone()
            if source is None:
                raise OperationalTelemetryError("authenticated_runner_not_found", 404)
            connection.execute(
                """
                INSERT INTO operational_runner_enrollments(
                    tenant_id, runner_id, status, runner_key_id, worker_image_sha256,
                    enrolled_by, enrolled_at, revoked_by, revoked_at, revoke_reason
                ) VALUES (?, ?, 'ACTIVE', ?, ?, ?, ?, NULL, NULL, NULL)
                ON CONFLICT(tenant_id, runner_id) DO UPDATE SET
                    status='ACTIVE', runner_key_id=excluded.runner_key_id,
                    worker_image_sha256=excluded.worker_image_sha256,
                    enrolled_by=excluded.enrolled_by, enrolled_at=excluded.enrolled_at,
                    revoked_by=NULL, revoked_at=NULL, revoke_reason=NULL
                """,
                (
                    tenant_id,
                    runner_id,
                    str(source["runner_key_id"]),
                    str(source["worker_image_sha256"]),
                    actor,
                    current,
                ),
            )
            connection.execute(
                """
                INSERT INTO operational_enrollment_policy(tenant_id, enforced, enabled_by, enabled_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    enforced=1, enabled_by=excluded.enabled_by, enabled_at=excluded.enabled_at
                """,
                (tenant_id, actor, current),
            )
        return {
            "runner_id": runner_id,
            "status": "ACTIVE",
            "runner_key_id": str(source["runner_key_id"]),
            "worker_image_sha256": str(source["worker_image_sha256"]),
            "enrollment_enforced": True,
            "enrolled_at": current,
        }

    def revoke_runner_enrollment(
        self,
        tenant_id: str,
        *,
        runner_id: str,
        reason: str,
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = to_utc_iso(now or utc_now())
        with self._connect() as connection:
            changed = connection.execute(
                """
                UPDATE operational_runner_enrollments
                SET status='REVOKED', revoked_by=?, revoked_at=?, revoke_reason=?
                WHERE tenant_id=? AND runner_id=? AND status='ACTIVE'
                """,
                (actor, current, reason, tenant_id, runner_id),
            ).rowcount
            if changed != 1:
                raise OperationalTelemetryError("active_runner_enrollment_not_found", 404)
        return {
            "runner_id": runner_id,
            "status": "REVOKED",
            "reason": reason,
            "revoked_at": current,
        }

    def remediate_adapter_maturity(
        self,
        tenant_id: str,
        *,
        reason: str,
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Atomically quarantine every authenticated adapter that is not STABLE."""
        current = to_utc_iso(now or utc_now())
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT adapter_id, maturity FROM authenticated_adapter_inventory
                WHERE tenant_id=? AND maturity <> 'STABLE' ORDER BY adapter_id
                """,
                (tenant_id,),
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    INSERT INTO operational_quarantines(
                        tenant_id, subject_type, subject_id, reason, quarantined_by,
                        quarantined_at, released_by, release_reason, released_at
                    ) VALUES (?, 'adapter', ?, ?, ?, ?, NULL, NULL, NULL)
                    ON CONFLICT(tenant_id, subject_type, subject_id) DO UPDATE SET
                        reason=excluded.reason, quarantined_by=excluded.quarantined_by,
                        quarantined_at=excluded.quarantined_at, released_by=NULL,
                        release_reason=NULL, released_at=NULL
                    """,
                    (tenant_id, str(row["adapter_id"]), reason, actor, current),
                )
            stable = connection.execute(
                """
                SELECT COUNT(*) AS count FROM authenticated_adapter_inventory
                WHERE tenant_id=? AND maturity='STABLE'
                """,
                (tenant_id,),
            ).fetchone()
        return {
            "remediated": len(rows),
            "quarantined_adapter_ids": [str(row["adapter_id"]) for row in rows],
            "remaining_stable": int(stable["count"]),
            "maturity_status": "STABLE" if int(stable["count"]) > 0 else "UNAVAILABLE",
            "remediated_at": current,
        }

    def quarantine(
        self,
        tenant_id: str,
        *,
        subject_type: Literal["runner", "adapter"],
        subject_id: str,
        reason: str,
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Remove one authenticated runner or adapter from operational eligibility."""
        current = to_utc_iso(now or utc_now())
        source_table, source_column = (
            ("authenticated_worker_heartbeats", "runner_id")
            if subject_type == "runner"
            else ("authenticated_adapter_inventory", "adapter_id")
        )
        with self._connect() as connection:
            known = connection.execute(
                f"SELECT 1 FROM {source_table} WHERE tenant_id = ? AND {source_column} = ?",
                (tenant_id, subject_id),
            ).fetchone()
            if known is None:
                raise OperationalTelemetryError("operational_subject_not_found", 404)
            existing = connection.execute(
                """
                SELECT reason, quarantined_by, quarantined_at, released_at
                FROM operational_quarantines
                WHERE tenant_id = ? AND subject_type = ? AND subject_id = ?
                """,
                (tenant_id, subject_type, subject_id),
            ).fetchone()
            if existing is not None and existing["released_at"] is None:
                return {
                    "quarantined": True,
                    "idempotent": True,
                    "subject_type": subject_type,
                    "subject_id": subject_id,
                    "reason": str(existing["reason"]),
                    "quarantined_by": str(existing["quarantined_by"]),
                    "quarantined_at": str(existing["quarantined_at"]),
                }
            connection.execute(
                """
                INSERT INTO operational_quarantines(
                    tenant_id, subject_type, subject_id, reason,
                    quarantined_by, quarantined_at, released_by,
                    release_reason, released_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                ON CONFLICT(tenant_id, subject_type, subject_id) DO UPDATE SET
                    reason=excluded.reason,
                    quarantined_by=excluded.quarantined_by,
                    quarantined_at=excluded.quarantined_at,
                    released_by=NULL,
                    release_reason=NULL,
                    released_at=NULL
                """,
                (tenant_id, subject_type, subject_id, reason, actor, current),
            )
        return {
            "quarantined": True,
            "idempotent": False,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "reason": reason,
            "quarantined_by": actor,
            "quarantined_at": current,
        }

    def release_quarantine(
        self,
        tenant_id: str,
        *,
        subject_type: Literal["runner", "adapter"],
        subject_id: str,
        reason: str,
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Restore eligibility while retaining the quarantine record and audit history."""
        current = to_utc_iso(now or utc_now())
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT 1 FROM operational_quarantines
                WHERE tenant_id = ? AND subject_type = ? AND subject_id = ?
                  AND released_at IS NULL
                """,
                (tenant_id, subject_type, subject_id),
            ).fetchone()
            if existing is None:
                raise OperationalTelemetryError("active_quarantine_not_found", 404)
            connection.execute(
                """
                UPDATE operational_quarantines
                SET released_by = ?, release_reason = ?, released_at = ?
                WHERE tenant_id = ? AND subject_type = ? AND subject_id = ?
                  AND released_at IS NULL
                """,
                (actor, reason, current, tenant_id, subject_type, subject_id),
            )
        return {
            "quarantined": False,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "release_reason": reason,
            "released_by": actor,
            "released_at": current,
        }

    def _authenticate(
        self,
        report: SignedOperationalReport,
        trusted: TrustedTransportRegistry,
        *,
        required_scope: RunnerCommand,
        now: datetime,
    ) -> Any:
        self.reconcile_key_rotations(trusted, now=now)
        try:
            claims = trusted.verify(report.credential)
        except Exception as exc:  # authentication failures stay detail-bounded
            raise OperationalTelemetryError("untrusted_operational_credential", 401) from exc
        response = report.response
        if required_scope.value not in claims.scopes:
            raise OperationalTelemetryError("operational_scope_not_granted", 403)
        if (
            response.run_id,
            response.tenant_id,
            response.runner_id,
            response.runner_key_id,
        ) != (
            claims.run_id,
            claims.tenant_id,
            claims.runner_id,
            claims.runner_key_id,
        ):
            raise OperationalTelemetryError("operational_identity_mismatch", 401)
        if response.issued_at < claims.issued_at or response.issued_at >= claims.expires_at:
            raise OperationalTelemetryError("operational_response_outside_credential_lifetime", 401)
        if now >= claims.expires_at or response.issued_at > now + timedelta(minutes=2):
            raise OperationalTelemetryError("operational_credential_expired_or_future", 401)
        verified, _reason = verify_runner_response(response, claims.runner_public_key_pem)
        if not verified:
            raise OperationalTelemetryError("invalid_operational_runner_signature", 401)
        return claims

    @staticmethod
    def _reserve_report(
        connection: sqlite3.Connection,
        report: SignedOperationalReport,
        *,
        report_kind: str,
        received_at: str,
    ) -> bool:
        response = report.response
        existing = connection.execute(
            "SELECT report_kind, body_sha256 FROM authenticated_operational_reports WHERE response_id = ?",
            (response.response_id,),
        ).fetchone()
        if existing is not None:
            if existing["report_kind"] != report_kind or existing["body_sha256"] != response.body_sha256:
                raise OperationalTelemetryError("operational_response_id_conflict", 409)
            return False
        connection.execute(
            """
            INSERT INTO authenticated_operational_reports(
                response_id, tenant_id, runner_id, report_kind, body_sha256, received_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                response.response_id,
                response.tenant_id,
                response.runner_id,
                report_kind,
                response.body_sha256,
                received_at,
            ),
        )
        return True

    def ingest_worker_heartbeat(
        self,
        report: SignedOperationalReport,
        trusted: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now or utc_now()
        claims = self._authenticate(
            report, trusted, required_scope=RunnerCommand.HEARTBEAT, now=current
        )
        response = report.response
        if response.status != "ACCEPTED":
            raise OperationalTelemetryError("worker_heartbeat_status_invalid", 422)
        try:
            body = WorkerHeartbeatBody.model_validate(response.body)
        except ValueError as exc:
            raise OperationalTelemetryError("worker_heartbeat_body_invalid", 422) from exc
        if body.capacity_available > body.capacity_total:
            raise OperationalTelemetryError("worker_heartbeat_capacity_invalid", 422)
        if body.active_run_count > body.capacity_total:
            raise OperationalTelemetryError("worker_heartbeat_active_count_invalid", 422)

        received_at = to_utc_iso(current)
        observed_at = to_utc_iso(response.issued_at)
        with self._connect() as connection:
            policy = connection.execute(
                "SELECT enforced FROM operational_enrollment_policy WHERE tenant_id=?",
                (response.tenant_id,),
            ).fetchone()
            if policy is not None and int(policy["enforced"]) == 1:
                enrollment = connection.execute(
                    """
                    SELECT status, runner_key_id, worker_image_sha256
                    FROM operational_runner_enrollments
                    WHERE tenant_id=? AND runner_id=?
                    """,
                    (response.tenant_id, response.runner_id),
                ).fetchone()
                if enrollment is None or enrollment["status"] != "ACTIVE":
                    raise OperationalTelemetryError("runner_not_enrolled", 403)
                if (
                    enrollment["runner_key_id"] != claims.runner_key_id
                    or enrollment["worker_image_sha256"] != body.worker_image_sha256
                ):
                    raise OperationalTelemetryError("runner_enrollment_identity_mismatch", 409)
            if not self._reserve_report(
                connection, report, report_kind="worker_heartbeat", received_at=received_at
            ):
                return {"accepted": True, "idempotent": True, "runner_id": response.runner_id}
            existing = connection.execute(
                """
                SELECT sequence, observed_at FROM authenticated_worker_heartbeats
                WHERE tenant_id = ? AND runner_id = ?
                """,
                (response.tenant_id, response.runner_id),
            ).fetchone()
            if existing is not None and (
                response.sequence <= int(existing["sequence"])
                or response.issued_at <= parse_utc_iso(str(existing["observed_at"]))
            ):
                raise OperationalTelemetryError("worker_heartbeat_not_monotonic", 409)
            connection.execute(
                """
                INSERT INTO authenticated_worker_heartbeats(
                    tenant_id, runner_id, run_id, response_id, sequence, health,
                    capacity_total, capacity_available, active_run_count,
                    worker_image_sha256, credential_id, control_plane_key_id, runner_key_id,
                    observed_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, runner_id) DO UPDATE SET
                    run_id=excluded.run_id, response_id=excluded.response_id,
                    sequence=excluded.sequence, health=excluded.health,
                    capacity_total=excluded.capacity_total,
                    capacity_available=excluded.capacity_available,
                    active_run_count=excluded.active_run_count,
                    worker_image_sha256=excluded.worker_image_sha256,
                    credential_id=excluded.credential_id,
                    control_plane_key_id=excluded.control_plane_key_id,
                    runner_key_id=excluded.runner_key_id,
                    observed_at=excluded.observed_at, received_at=excluded.received_at
                """,
                (
                    response.tenant_id,
                    response.runner_id,
                    response.run_id,
                    response.response_id,
                    response.sequence,
                    body.health,
                    body.capacity_total,
                    body.capacity_available,
                    body.active_run_count,
                    body.worker_image_sha256,
                    claims.credential_id,
                    report.credential.key_id,
                    claims.runner_key_id,
                    observed_at,
                    received_at,
                ),
            )
        return {"accepted": True, "idempotent": False, "runner_id": response.runner_id}

    def ingest_adapter_inventory(
        self,
        report: SignedOperationalReport,
        trusted: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = now or utc_now()
        claims = self._authenticate(
            report, trusted, required_scope=RunnerCommand.TRANSITION, now=current
        )
        response = report.response
        if response.status != "COMPLETED":
            raise OperationalTelemetryError("adapter_inventory_status_invalid", 422)
        try:
            records = parse_verified_adapter_bundle(
                response,
                claims.runner_public_key_pem,
                expected_run_id=claims.run_id,
                expected_tenant_id=claims.tenant_id,
                allowed_runner_ids=(claims.runner_id,),
            )
        except (TypeError, ValueError) as exc:
            raise OperationalTelemetryError("adapter_inventory_bundle_invalid", 422) from exc
        if not records:
            raise OperationalTelemetryError("adapter_inventory_empty", 422)

        received_at = to_utc_iso(current)
        observed_at = to_utc_iso(response.issued_at)
        with self._connect() as connection:
            policy = connection.execute(
                "SELECT enforced FROM operational_enrollment_policy WHERE tenant_id=?",
                (claims.tenant_id,),
            ).fetchone()
            if policy is not None and int(policy["enforced"]) == 1:
                enrollment = connection.execute(
                    """
                    SELECT status, runner_key_id FROM operational_runner_enrollments
                    WHERE tenant_id=? AND runner_id=?
                    """,
                    (claims.tenant_id, claims.runner_id),
                ).fetchone()
                if enrollment is None or enrollment["status"] != "ACTIVE":
                    raise OperationalTelemetryError("runner_not_enrolled", 403)
                if enrollment["runner_key_id"] != claims.runner_key_id:
                    raise OperationalTelemetryError("runner_enrollment_identity_mismatch", 409)
            if not self._reserve_report(
                connection, report, report_kind="adapter_inventory", received_at=received_at
            ):
                return {"accepted": True, "idempotent": True, "adapter_count": len(records)}
            for record in records:
                existing = connection.execute(
                    """
                    SELECT observed_at FROM authenticated_adapter_inventory
                    WHERE tenant_id = ? AND adapter_id = ?
                    """,
                    (claims.tenant_id, record.identity.adapter_id),
                ).fetchone()
                if existing is not None and response.issued_at <= parse_utc_iso(
                    str(existing["observed_at"])
                ):
                    raise OperationalTelemetryError("adapter_inventory_not_newer", 409)
                connection.execute(
                    """
                    INSERT INTO authenticated_adapter_inventory(
                        tenant_id, adapter_id, version, identity_digest, maturity,
                        quality_score, quality_cases, execution_node, result_sha256,
                        response_id, runner_id, credential_id, runner_key_id,
                        control_plane_key_id,
                        observed_at, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, adapter_id) DO UPDATE SET
                        version=excluded.version,
                        identity_digest=excluded.identity_digest,
                        maturity=excluded.maturity,
                        quality_score=excluded.quality_score,
                        quality_cases=excluded.quality_cases,
                        execution_node=excluded.execution_node,
                        result_sha256=excluded.result_sha256,
                        response_id=excluded.response_id,
                        runner_id=excluded.runner_id,
                        credential_id=excluded.credential_id,
                        control_plane_key_id=excluded.control_plane_key_id,
                        runner_key_id=excluded.runner_key_id,
                        observed_at=excluded.observed_at,
                        received_at=excluded.received_at
                    """,
                    (
                        claims.tenant_id,
                        record.identity.adapter_id,
                        record.identity.version,
                        record.identity.identity_digest,
                        record.identity.maturity.value,
                        record.quality.score,
                        record.quality.total_cases,
                        record.execution_node,
                        record.result_sha256,
                        response.response_id,
                        claims.runner_id,
                        claims.credential_id,
                        claims.runner_key_id,
                        report.credential.key_id,
                        observed_at,
                        received_at,
                    ),
                )
        return {"accepted": True, "idempotent": False, "adapter_count": len(records)}

    def ingest_windows_package_result(
        self,
        report: SignedOperationalReport,
        trusted: TrustedTransportRegistry,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Accept one enrolled, signed, digest-pinned P8C Windows package observation."""
        current = now or utc_now()
        claims = self._authenticate(
            report, trusted, required_scope=RunnerCommand.TRANSITION, now=current
        )
        response = report.response
        if response.status != "COMPLETED":
            raise OperationalTelemetryError("windows_package_result_status_invalid", 422)
        try:
            body = WindowsPackageResultBody.model_validate(response.body)
        except ValueError as exc:
            raise OperationalTelemetryError("windows_package_result_body_invalid", 422) from exc
        received_at = to_utc_iso(current)
        observed_at = to_utc_iso(response.issued_at)
        with self._connect() as connection:
            binding = connection.execute(
                """
                SELECT r.state AS reservation_state, r.target_type,
                       r.target_reference, r.target_identity_digest,
                       d.target_json, runs.state AS run_state,
                       runs.environment_identity_digest
                FROM subscriber_run_reservations r
                JOIN subscriber_run_dispatches d
                  ON d.run_id=r.run_id AND d.organization_id=r.organization_id
                JOIN runs
                  ON runs.run_id=r.run_id AND runs.tenant_id=r.organization_id
                WHERE r.organization_id=? AND r.run_id=?
                """,
                (response.tenant_id, response.run_id),
            ).fetchone()
            if (
                binding is None
                or binding["reservation_state"] != "BOUND"
                or binding["run_state"] != "QUEUED"
                or binding["target_type"] != "package"
            ):
                raise OperationalTelemetryError("windows_package_run_not_dispatchable", 409)
            spec = json.loads(str(binding["target_json"]))
            if (
                spec.get("type") != "package"
                or spec.get("path") != body.reference
                or spec.get("artifact_sha256") != body.artifact_sha256
                or spec.get("source_commit") != body.source_commit
                or binding["target_reference"] != body.reference
                or binding["environment_identity_digest"]
                != body.environment_identity_digest
            ):
                raise OperationalTelemetryError("windows_package_result_binding_mismatch", 409)
            declared_digest = sha256_json(
                {
                    "tenant_id": response.tenant_id,
                    "target_type": "package",
                    "artifact_sha256": body.artifact_sha256,
                    "source_commit": body.source_commit,
                    "reference": body.reference,
                }
            )
            if declared_digest != binding["target_identity_digest"]:
                raise OperationalTelemetryError("windows_package_declared_digest_mismatch", 409)
            enrollment = connection.execute(
                """
                SELECT status, runner_key_id, worker_image_sha256
                FROM operational_runner_enrollments
                WHERE tenant_id=? AND runner_id=?
                """,
                (response.tenant_id, response.runner_id),
            ).fetchone()
            if enrollment is None or enrollment["status"] != "ACTIVE":
                raise OperationalTelemetryError("runner_not_enrolled", 403)
            if (
                enrollment["runner_key_id"] != claims.runner_key_id
                or enrollment["worker_image_sha256"] != body.worker_image_sha256
            ):
                raise OperationalTelemetryError("runner_enrollment_identity_mismatch", 409)
            if not self._reserve_report(
                connection,
                report,
                report_kind="windows_package_result",
                received_at=received_at,
            ):
                return {
                    "accepted": True,
                    "idempotent": True,
                    "run_id": response.run_id,
                    "ready_candidate": body.ready_candidate,
                }
            existing = connection.execute(
                """
                SELECT 1 FROM authenticated_windows_package_results
                WHERE run_id=? AND tenant_id=?
                """,
                (response.run_id, response.tenant_id),
            ).fetchone()
            if existing is not None:
                raise OperationalTelemetryError("windows_package_result_already_recorded", 409)
            connection.execute(
                """
                INSERT INTO authenticated_windows_package_results(
                    run_id, tenant_id, runner_id, response_id, sequence,
                    body_json, body_sha256, credential_id, control_plane_key_id,
                    runner_key_id, observed_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response.run_id,
                    response.tenant_id,
                    response.runner_id,
                    response.response_id,
                    response.sequence,
                    canonical_json(body.model_dump(mode="json")),
                    response.body_sha256,
                    claims.credential_id,
                    report.credential.key_id,
                    claims.runner_key_id,
                    observed_at,
                    received_at,
                ),
            )
        return {
            "accepted": True,
            "idempotent": False,
            "run_id": response.run_id,
            "ready_candidate": body.ready_candidate,
        }

    def windows_package_result(self, run_id: str, tenant_id: str) -> dict[str, Any] | None:
        """Return a verified stored result for the key-holding finalizer."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT runner_id, response_id, body_json, body_sha256,
                       runner_key_id, observed_at, received_at
                FROM authenticated_windows_package_results
                WHERE run_id=? AND tenant_id=?
                """,
                (run_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        return {**dict(row), "body": json.loads(str(row["body_json"]))}

    def snapshot(
        self,
        tenant_id: str,
        *,
        now: datetime | None = None,
        heartbeat_freshness: timedelta = timedelta(minutes=5),
    ) -> dict[str, Any]:
        current = now or utc_now()
        with self._connect() as connection:
            heartbeats = connection.execute(
                """
                SELECT runner_id, health, capacity_total, capacity_available,
                       active_run_count, worker_image_sha256, observed_at
                FROM authenticated_worker_heartbeats
                WHERE tenant_id = ? ORDER BY observed_at DESC
                """,
                (tenant_id,),
            ).fetchall()
            adapters = connection.execute(
                """
                SELECT adapter_id, version, identity_digest, maturity,
                       quality_score, quality_cases, execution_node, observed_at
                FROM authenticated_adapter_inventory
                WHERE tenant_id = ? ORDER BY adapter_id
                """,
                (tenant_id,),
            ).fetchall()
            quarantines = connection.execute(
                """
                SELECT subject_type, subject_id, reason, quarantined_by, quarantined_at
                FROM operational_quarantines
                WHERE tenant_id = ? AND released_at IS NULL
                ORDER BY subject_type, subject_id
                """,
                (tenant_id,),
            ).fetchall()
            enrollment_policy = connection.execute(
                "SELECT enforced FROM operational_enrollment_policy WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            enrollments = connection.execute(
                """
                SELECT runner_id, status, runner_key_id, worker_image_sha256, enrolled_at
                FROM operational_runner_enrollments WHERE tenant_id=?
                """,
                (tenant_id,),
            ).fetchall()

        runner_quarantines = {
            str(row["subject_id"]): row for row in quarantines if row["subject_type"] == "runner"
        }
        adapter_quarantines = {
            str(row["subject_id"]): row for row in quarantines if row["subject_type"] == "adapter"
        }
        enrollment_enforced = (
            enrollment_policy is not None and int(enrollment_policy["enforced"]) == 1
        )
        active_enrollments = {
            str(row["runner_id"]): row for row in enrollments if row["status"] == "ACTIVE"
        }

        fresh = [
            row
            for row in heartbeats
            if row["runner_id"] not in runner_quarantines
            and (
                not enrollment_enforced
                or str(row["runner_id"]) in active_enrollments
            )
            and current - parse_utc_iso(str(row["observed_at"])) <= heartbeat_freshness
        ]
        if not heartbeats:
            runner_health = "NO_AUTHENTICATED_HEARTBEATS"
            runner_reason = "No authenticated worker heartbeat has been received for this tenant."
        elif len(runner_quarantines) == len(heartbeats):
            runner_health = "QUARANTINED"
            runner_reason = "Every authenticated runner is quarantined and excluded from capacity."
        elif enrollment_enforced and not active_enrollments:
            runner_health = "UNENROLLED"
            runner_reason = "Enrollment enforcement is active and no runner is durably enrolled."
        elif not fresh:
            runner_health = "STALE"
            runner_reason = (
                "No enrolled authenticated runner has a fresh heartbeat."
                if enrollment_enforced
                else "All authenticated worker heartbeats are older than the freshness window."
            )
        elif runner_quarantines:
            runner_health = "DEGRADED"
            runner_reason = "At least one authenticated runner is quarantined and excluded from capacity."
        elif any(row["health"] != "HEALTHY" for row in fresh):
            runner_health = "DEGRADED"
            runner_reason = "At least one fresh authenticated worker reports degraded health."
        else:
            runner_health = "HEALTHY"
            runner_reason = "Fresh Ed25519-signed worker heartbeats are verified."

        eligible_adapters = [
            row for row in adapters if row["adapter_id"] not in adapter_quarantines
        ]
        stable_count = sum(1 for row in eligible_adapters if row["maturity"] == "STABLE")
        adapter_total = len(adapters)
        if adapter_total == 0:
            inventory_status = "EMPTY"
            maturity_status = "UNAVAILABLE"
            adapter_reason = "The authenticated adapter registry contains no entries for this tenant."
        elif not eligible_adapters:
            inventory_status = "QUARANTINED"
            maturity_status = "UNAVAILABLE"
            adapter_reason = "Every authenticated adapter is quarantined and excluded from execution."
        else:
            inventory_status = "AVAILABLE"
            maturity_status = (
                "STABLE"
                if stable_count == len(eligible_adapters)
                else "MIXED"
            )
            adapter_reason = (
                "Authenticated adapters remain available, but quarantined entries are excluded."
                if adapter_quarantines
                else "Adapter identities and maturity were verified from signed runner bundles."
            )

        return {
            "runner": {
                "health": runner_health,
                "reason": runner_reason,
                "source": "authenticated_ed25519_worker_reports",
                "registered": len(heartbeats),
                "fresh": len(fresh),
                "quarantined": len(runner_quarantines),
                "enrollment_enforced": enrollment_enforced,
                "enrolled": len(active_enrollments),
                "capacity_total": sum(int(row["capacity_total"]) for row in fresh),
                "capacity_available": sum(int(row["capacity_available"]) for row in fresh),
                "active_run_count": sum(int(row["active_run_count"]) for row in fresh),
                "latest_heartbeat_at": str(heartbeats[0]["observed_at"]) if heartbeats else None,
                "entries": [
                    {
                        "runner_id": str(row["runner_id"]),
                        "health": str(row["health"]),
                        "worker_image_sha256": str(row["worker_image_sha256"]),
                        "observed_at": str(row["observed_at"]),
                        "enrolled": (
                            not enrollment_enforced
                            or str(row["runner_id"]) in active_enrollments
                        ),
                        "quarantined": str(row["runner_id"]) in runner_quarantines,
                        "quarantine_reason": (
                            str(runner_quarantines[str(row["runner_id"])]["reason"])
                            if str(row["runner_id"]) in runner_quarantines
                            else None
                        ),
                    }
                    for row in heartbeats
                ],
            },
            "adapters": {
                "inventory_status": inventory_status,
                "maturity_status": maturity_status,
                "reason": adapter_reason,
                "source": "authenticated_signed_adapter_bundles",
                "total": adapter_total,
                "available": len(eligible_adapters),
                "quarantined": len(adapter_quarantines),
                "stable": stable_count,
                "entries": [
                    {
                        "adapter_id": str(row["adapter_id"]),
                        "version": str(row["version"]),
                        "identity_digest": str(row["identity_digest"]),
                        "maturity": str(row["maturity"]),
                        "quality_score": float(row["quality_score"]),
                        "quality_cases": int(row["quality_cases"]),
                        "execution_node": str(row["execution_node"]),
                        "observed_at": str(row["observed_at"]),
                        "quarantined": str(row["adapter_id"]) in adapter_quarantines,
                        "quarantine_reason": (
                            str(adapter_quarantines[str(row["adapter_id"])]["reason"])
                            if str(row["adapter_id"]) in adapter_quarantines
                            else None
                        ),
                    }
                    for row in adapters
                ],
            },
            "snapshot_sha256": sha256_json(
                {
                    "tenant_id": tenant_id,
                    "heartbeat_count": len(heartbeats),
                    "fresh_heartbeat_count": len(fresh),
                    "adapter_count": adapter_total,
                    "latest_heartbeat_at": str(heartbeats[0]["observed_at"]) if heartbeats else None,
                    "adapter_observed_at": [str(row["observed_at"]) for row in adapters],
                    "active_quarantines": [
                        {
                            "subject_type": str(row["subject_type"]),
                            "subject_id": str(row["subject_id"]),
                            "reason": str(row["reason"]),
                            "quarantined_at": str(row["quarantined_at"]),
                        }
                        for row in quarantines
                    ],
                    "enrollment_enforced": enrollment_enforced,
                    "active_enrollments": sorted(active_enrollments),
                }
            ),
        }
