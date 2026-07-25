"""Authenticated worker-heartbeat and adapter-inventory telemetry.

The subscriber telemetry surface must never infer runner availability from quota or
trust an unsigned adapter catalog.  This module accepts only control-plane-issued,
short-lived runner credentials paired with Ed25519-signed runner responses, then
projects a bounded tenant-scoped snapshot.  Missing and stale reports remain
explicitly non-green.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .adapter_transport import parse_verified_adapter_bundle
from .canonical import parse_utc_iso, sha256_json, to_utc_iso, utc_now
from .runner import (
    RunnerCommand,
    RunnerResponse,
    SignedRunCredential,
    TrustedTransportRegistry,
    verify_runner_response,
)


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
                    runner_key_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, runner_id)
                );
                CREATE INDEX IF NOT EXISTS idx_authenticated_heartbeat_tenant_time
                    ON authenticated_worker_heartbeats(tenant_id, observed_at DESC);
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
                """
            )

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

    @staticmethod
    def _authenticate(
        report: SignedOperationalReport,
        trusted: TrustedTransportRegistry,
        *,
        required_scope: RunnerCommand,
        now: datetime,
    ) -> Any:
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
                    worker_image_sha256, credential_id, runner_key_id,
                    observed_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, runner_id) DO UPDATE SET
                    run_id=excluded.run_id, response_id=excluded.response_id,
                    sequence=excluded.sequence, health=excluded.health,
                    capacity_total=excluded.capacity_total,
                    capacity_available=excluded.capacity_available,
                    active_run_count=excluded.active_run_count,
                    worker_image_sha256=excluded.worker_image_sha256,
                    credential_id=excluded.credential_id,
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
                        observed_at, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        observed_at,
                        received_at,
                    ),
                )
        return {"accepted": True, "idempotent": False, "adapter_count": len(records)}

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

        runner_quarantines = {
            str(row["subject_id"]): row for row in quarantines if row["subject_type"] == "runner"
        }
        adapter_quarantines = {
            str(row["subject_id"]): row for row in quarantines if row["subject_type"] == "adapter"
        }

        fresh = [
            row
            for row in heartbeats
            if row["runner_id"] not in runner_quarantines
            and current - parse_utc_iso(str(row["observed_at"])) <= heartbeat_freshness
        ]
        if not heartbeats:
            runner_health = "NO_AUTHENTICATED_HEARTBEATS"
            runner_reason = "No authenticated worker heartbeat has been received for this tenant."
        elif len(runner_quarantines) == len(heartbeats):
            runner_health = "QUARANTINED"
            runner_reason = "Every authenticated runner is quarantined and excluded from capacity."
        elif not fresh:
            runner_health = "STALE"
            runner_reason = "All authenticated worker heartbeats are older than the freshness window."
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
                if stable_count == len(eligible_adapters) and not adapter_quarantines
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
                }
            ),
        }
