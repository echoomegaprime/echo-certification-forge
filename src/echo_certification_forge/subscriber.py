"""Subscriber governance, tenant authorization, quotas, metering, and audit custody."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import (
    canonical_json,
    parse_utc_iso,
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)

_ZERO_HASH = "0" * 64
_TERMINAL_RUN_STATES = ("COMPLETED", "CANCELLED", "INFRASTRUCTURE_FAILURE")


class OrganizationStatus(StrEnum):
    TRIALING = "TRIALING"
    ACTIVE = "ACTIVE"
    PAST_DUE = "PAST_DUE"
    SUSPENDED = "SUSPENDED"
    CANCELLED = "CANCELLED"


class UserStatus(StrEnum):
    INVITED = "INVITED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DEACTIVATED = "DEACTIVATED"


class MemberRole(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"
    BILLING = "BILLING"


class Permission(StrEnum):
    RUN_READ = "runs:read"
    RUN_CREATE = "runs:create"
    RUN_CANCEL = "runs:cancel"
    RELEASE_GATE = "release-gates:evaluate"
    PROJECT_READ = "projects:read"
    PROJECT_MANAGE = "projects:manage"
    MEMBER_MANAGE = "members:manage"
    API_KEY_MANAGE = "api-keys:manage"
    GOVERNANCE_READ = "governance:read"
    GOVERNANCE_MANAGE = "governance:manage"
    POLICY_PACK_MANAGE = "policy-packs:manage"
    PRIVATE_WORKER_MANAGE = "private-workers:manage"
    USAGE_READ = "usage:read"
    AUDIT_READ = "audit:read"
    BILLING_MANAGE = "billing:manage"


class ApiKeyStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class SubscriberError(RuntimeError):
    """Fail-closed subscriber-plane error with a stable public machine code."""

    def __init__(self, status_code: int, code: str, *, retry_after: int | None = None) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.retry_after = retry_after


class PlanDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(pattern=r"^[a-z][a-z0-9-]{1,31}$")
    display_name: str = Field(min_length=1, max_length=80)
    max_projects: int = Field(ge=1, le=100_000)
    max_api_keys: int = Field(ge=1, le=10_000)
    monthly_certification_runs: int = Field(ge=1, le=10_000_000)
    concurrent_runs: int = Field(ge=1, le=10_000)
    requests_per_minute: int = Field(ge=1, le=1_000_000)
    default_retention_days: int = Field(ge=1, le=3650)
    maximum_retention_days: int = Field(ge=1, le=3650)
    max_policy_packs: int = Field(ge=0, le=10_000)
    max_private_workers: int = Field(ge=0, le=10_000)
    release_gates: bool = False
    white_label_reports: bool = False
    audit_exports: bool = False
    custom_policy_packs: bool = False
    private_workers: bool = False
    customer_managed_keys: bool = False
    local_only_execution: bool = False

    @model_validator(mode="after")
    def validate_retention(self) -> "PlanDefinition":
        if self.default_retention_days > self.maximum_retention_days:
            raise ValueError("default_retention_days exceeds maximum_retention_days")
        if self.private_workers != (self.max_private_workers > 0):
            raise ValueError("private_workers must match max_private_workers")
        if self.custom_policy_packs != (self.max_policy_packs > 0):
            raise ValueError("custom_policy_packs must match max_policy_packs")
        return self


@dataclass(frozen=True, slots=True)
class PendingSubscriberIntake:
    reservation: RunReservation
    request: dict[str, Any]
    target_spec: dict[str, Any]
    journey: list[str] | None


class SubscriberPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.2\.2$")
    policy_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    api_key_max_ttl_days: int = Field(ge=1, le=3650)
    api_key_secret_bytes: int = Field(ge=24, le=64)
    rate_window_seconds: int = Field(ge=1, le=3600)
    rate_limit_scope: str = Field(pattern=r"^api_key_global$")
    audit_denied_requests: bool
    reservation_ttl_seconds: int = Field(ge=30, le=86_400)
    worker_claim_lease_seconds: int = Field(ge=5, le=3600)
    worker_heartbeat_interval_seconds: int = Field(ge=1, le=1200)
    dispatch_claim_lease_seconds: int = Field(ge=5, le=3600)
    max_dispatch_attempts: int = Field(ge=1, le=100)
    plans: tuple[PlanDefinition, ...] = Field(min_length=1)
    role_permissions: dict[MemberRole, frozenset[Permission]]
    past_due_read_permissions: frozenset[Permission]

    @model_validator(mode="after")
    def validate_unique_plans(self) -> "SubscriberPolicy":
        codes = [plan.code for plan in self.plans]
        if len(codes) != len(set(codes)):
            raise ValueError("plan codes must be unique")
        if MemberRole.OWNER not in self.role_permissions:
            raise ValueError("OWNER permissions are required")
        if set(self.role_permissions[MemberRole.OWNER]) != set(Permission):
            raise ValueError("OWNER must hold every subscriber permission")
        if self.worker_heartbeat_interval_seconds * 2 >= self.worker_claim_lease_seconds:
            raise ValueError("worker heartbeat interval must be less than half the claim lease")
        return self

    @classmethod
    def load(cls, path: Path) -> "SubscriberPolicy":
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def plan(self, code: str) -> PlanDefinition:
        for plan in self.plans:
            if plan.code == code:
                return plan
        raise SubscriberError(422, "plan_unknown")


@dataclass(frozen=True, slots=True)
class SubscriberPrincipal:
    organization_id: str
    user_id: str
    role: MemberRole
    key_id: str
    scopes: frozenset[Permission]
    organization_status: OrganizationStatus
    plan_code: str


@dataclass(frozen=True, slots=True)
class ProvisionedOrganization:
    organization_id: str
    owner_user_id: str
    bootstrap_api_key: str
    plan_code: str
    status: OrganizationStatus


@dataclass(frozen=True, slots=True)
class RunReservation:
    organization_id: str
    idempotency_key: str
    request_digest: str
    created: bool
    project_id: str | None = None
    policy_version: str | None = None
    target_type: str | None = None
    target_reference: str | None = None
    target_identity_digest: str | None = None


@dataclass(frozen=True, slots=True)
class WorkerRunClaim:
    organization_id: str
    run_id: str
    idempotency_key: str
    project_id: str
    policy_version: str
    target_type: str
    target_reference: str
    target_identity_digest: str
    retention_days: int
    claim_token: str
    lease_expires_at: str


@dataclass(frozen=True, slots=True)
class WorkerExecutionAuthorization:
    retention_days: int
    governance_version: int
    subscription_version: int


@dataclass(frozen=True, slots=True)
class SubscriberDispatch:
    run_id: str
    organization_id: str
    idempotency_key: str
    target_spec: dict[str, Any]
    journey: list[str] | None
    claim_token: str
    lease_expires_at: str
    attempts: int


class SubscriberGovernance:
    """Authoritative subscriber control plane sharing the Certification Forge SQLite database."""

    def __init__(
        self,
        db_path: Path,
        policy: SubscriberPolicy,
        token_pepper: bytes,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if len(token_pepper) < 32:
            raise ValueError("subscriber API-key pepper must contain at least 32 bytes")
        self.db_path = db_path
        self.policy = policy
        self._token_pepper = bytes(token_pepper)
        self._clock = clock
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("subscriber clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _connection(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {
            str(row["name"])
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        }

    def _migrate_legacy_platform_tables(self) -> None:
        """Archive incompatible prototype tables atomically before creating P7 schemas."""
        layouts = {
            "subscriber_users": {
                "current": {
                    "user_id",
                    "email",
                    "display_name",
                    "status",
                    "created_at",
                    "updated_at",
                },
                "legacy": {"user_id", "email", "created_at"},
                "archive": "legacy_platform_subscriber_users",
            },
            "subscriber_api_keys": {
                "current": {
                    "key_id",
                    "organization_id",
                    "user_id",
                    "name",
                    "token_digest",
                    "token_prefix",
                    "scopes_json",
                    "status",
                    "expires_at",
                    "created_at",
                    "revoked_at",
                    "last_used_at",
                },
                "legacy": {
                    "key_id",
                    "organization_id",
                    "project_id",
                    "key_prefix",
                    "secret_sha256",
                    "role",
                    "created_at",
                    "revoked_at",
                },
                "archive": "legacy_platform_subscriber_api_keys",
            },
        }
        connection = self._connect()
        try:
            connection.isolation_level = None
            connection.execute("BEGIN IMMEDIATE")
            for table, layout in layouts.items():
                columns = self._table_columns(connection, table)
                if not columns or layout["current"].issubset(columns):
                    continue
                if not layout["legacy"].issubset(columns):
                    raise RuntimeError(f"incompatible subscriber schema: {table}")
                archive = str(layout["archive"])
                if self._table_columns(connection, archive):
                    raise RuntimeError(f"legacy subscriber archive already exists: {archive}")
                connection.execute(f'ALTER TABLE "{table}" RENAME TO "{archive}"')
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        self._migrate_legacy_platform_tables()
        schema = """
        CREATE TABLE IF NOT EXISTS subscriber_plans (
            plan_code TEXT PRIMARY KEY,
            definition_json TEXT NOT NULL,
            definition_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_organizations (
            organization_id TEXT PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_memberships (
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            user_id TEXT NOT NULL REFERENCES subscriber_users(user_id),
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS subscriber_subscriptions (
            organization_id TEXT PRIMARY KEY REFERENCES subscriber_organizations(organization_id),
            plan_code TEXT NOT NULL REFERENCES subscriber_plans(plan_code),
            status TEXT NOT NULL,
            billing_provider TEXT,
            provider_customer_ref TEXT,
            current_period_start TEXT NOT NULL,
            current_period_end TEXT NOT NULL,
            last_provider_occurred_at TEXT,
            last_provider_sequence INTEGER,
            last_provider_event_id TEXT,
            cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_billing_events (
            provider_event_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            provider_occurred_at TEXT NOT NULL,
            provider_sequence INTEGER NOT NULL CHECK(provider_sequence >= 0),
            processing_outcome TEXT NOT NULL DEFAULT 'APPLIED'
                CHECK(processing_outcome IN ('APPLIED','REJECTED_STALE')),
            payload_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_projects (
            project_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            slug TEXT NOT NULL,
            name TEXT NOT NULL,
            target_reference TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (organization_id, slug)
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_projects_org
            ON subscriber_projects(organization_id, created_at);
        CREATE TABLE IF NOT EXISTS subscriber_api_keys (
            key_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            user_id TEXT NOT NULL REFERENCES subscriber_users(user_id),
            name TEXT NOT NULL,
            token_digest TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            status TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_api_keys_org
            ON subscriber_api_keys(organization_id, created_at);
        CREATE TABLE IF NOT EXISTS subscriber_usage_events (
            usage_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            meter TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            UNIQUE (organization_id, meter, idempotency_key)
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_usage_period
            ON subscriber_usage_events(organization_id, meter, occurred_at);
        CREATE TABLE IF NOT EXISTS subscriber_rate_limits (
            organization_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            action TEXT NOT NULL,
            window_started_at TEXT NOT NULL,
            request_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, key_id, action)
        );
        CREATE TABLE IF NOT EXISTS subscriber_run_reservations (
            organization_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            run_id TEXT,
            project_id TEXT,
            policy_version TEXT,
            target_type TEXT,
            target_reference TEXT,
            target_identity_digest TEXT,
            dispatch_target_json TEXT,
            dispatch_journey_json TEXT,
            submit_request_json TEXT,
            state TEXT NOT NULL,
            worker_id TEXT,
            worker_attestation_sha256 TEXT,
            execution_location TEXT,
            signing_authority TEXT,
            signing_key_id TEXT,
            claim_token TEXT,
            lease_expires_at TEXT,
            last_heartbeat_at TEXT,
            execution_started_at TEXT,
            governance_version INTEGER,
            subscription_version INTEGER,
            consumed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, idempotency_key),
            UNIQUE (run_id)
        );
        CREATE TABLE IF NOT EXISTS subscriber_run_dispatches (
            run_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            target_json TEXT NOT NULL,
            journey_json TEXT,
            state TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            claim_token TEXT,
            lease_owner TEXT,
            lease_expires_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (organization_id, idempotency_key)
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_dispatch_ready
            ON subscriber_run_dispatches(state, created_at);
        CREATE TABLE IF NOT EXISTS subscriber_governance (
            organization_id TEXT PRIMARY KEY REFERENCES subscriber_organizations(organization_id),
            config_json TEXT NOT NULL,
            config_sha256 TEXT NOT NULL,
            version INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_policy_packs (
            policy_pack_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (organization_id, name, version)
        );
        CREATE TABLE IF NOT EXISTS subscriber_policy_pack_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            policy_pack_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_ref TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_private_workers (
            worker_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES subscriber_organizations(organization_id),
            display_name TEXT NOT NULL,
            attestation_sha256 TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_audit_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            actor_ref TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            prev_chain_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_audit_org
            ON subscriber_audit_events(organization_id, event_id);

        CREATE TRIGGER IF NOT EXISTS no_update_subscriber_audit
        BEFORE UPDATE ON subscriber_audit_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_audit_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_subscriber_audit
        BEFORE DELETE ON subscriber_audit_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_audit_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_subscriber_usage
        BEFORE UPDATE ON subscriber_usage_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_usage_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_subscriber_usage
        BEFORE DELETE ON subscriber_usage_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_usage_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_subscriber_billing_events
        BEFORE UPDATE ON subscriber_billing_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_billing_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_subscriber_billing_events
        BEFORE DELETE ON subscriber_billing_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_billing_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_subscriber_policy_packs
        BEFORE UPDATE ON subscriber_policy_packs
        BEGIN SELECT RAISE(ABORT, 'subscriber_policy_packs are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_subscriber_policy_packs
        BEFORE DELETE ON subscriber_policy_packs
        BEGIN SELECT RAISE(ABORT, 'subscriber_policy_packs are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_subscriber_policy_events
        BEFORE UPDATE ON subscriber_policy_pack_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_policy_pack_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_subscriber_policy_events
        BEFORE DELETE ON subscriber_policy_pack_events
        BEGIN SELECT RAISE(ABORT, 'subscriber_policy_pack_events are append-only'); END;
        """
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            connection.executescript(schema)
            membership_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(subscriber_memberships)"
                ).fetchall()
            }
            if "status" not in membership_columns:
                connection.execute(
                    "ALTER TABLE subscriber_memberships ADD COLUMN status TEXT"
                )
                connection.execute(
                    """
                    UPDATE subscriber_memberships
                    SET status = COALESCE(
                        (
                            SELECT CASE
                                WHEN u.status = 'ACTIVE' THEN 'ACTIVE'
                                ELSE 'INVITED'
                            END
                            FROM subscriber_users u
                            WHERE u.user_id = subscriber_memberships.user_id
                        ),
                        'INVITED'
                    )
                    WHERE status IS NULL
                    """
                )
            subscription_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(subscriber_subscriptions)"
                ).fetchall()
            }
            for column_name, column_type in (
                ("last_provider_occurred_at", "TEXT"),
                ("last_provider_sequence", "INTEGER"),
                ("last_provider_event_id", "TEXT"),
                ("version", "INTEGER NOT NULL DEFAULT 1"),
            ):
                if column_name not in subscription_columns:
                    connection.execute(
                        f"ALTER TABLE subscriber_subscriptions "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
            billing_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(subscriber_billing_events)"
                ).fetchall()
            }
            missing_billing_columns = {
                "provider_occurred_at",
                "provider_sequence",
                "processing_outcome",
            } - billing_columns
            if missing_billing_columns:
                connection.execute("DROP TRIGGER IF EXISTS no_update_subscriber_billing_events")
                if "provider_occurred_at" in missing_billing_columns:
                    connection.execute(
                        "ALTER TABLE subscriber_billing_events "
                        "ADD COLUMN provider_occurred_at TEXT"
                    )
                if "provider_sequence" in missing_billing_columns:
                    connection.execute(
                        "ALTER TABLE subscriber_billing_events "
                        "ADD COLUMN provider_sequence INTEGER"
                    )
                if "processing_outcome" in missing_billing_columns:
                    connection.execute(
                        "ALTER TABLE subscriber_billing_events "
                        "ADD COLUMN processing_outcome TEXT"
                    )
                connection.execute(
                    """
                    UPDATE subscriber_billing_events
                    SET provider_occurred_at = COALESCE(provider_occurred_at, created_at),
                        provider_sequence = COALESCE(
                            provider_sequence,
                            (
                                SELECT COUNT(*)
                                FROM subscriber_billing_events prior
                                WHERE prior.organization_id =
                                      subscriber_billing_events.organization_id
                                  AND prior.rowid <= subscriber_billing_events.rowid
                            )
                        ),
                        processing_outcome = COALESCE(processing_outcome, 'APPLIED')
                    """
                )
                connection.execute(
                    """
                    CREATE TRIGGER no_update_subscriber_billing_events
                    BEFORE UPDATE ON subscriber_billing_events
                    BEGIN
                        SELECT RAISE(ABORT, 'subscriber_billing_events are append-only');
                    END
                    """
                )
            connection.execute(
                """
                UPDATE subscriber_subscriptions
                SET last_provider_occurred_at = (
                        SELECT e.provider_occurred_at
                        FROM subscriber_billing_events e
                        WHERE e.organization_id =
                              subscriber_subscriptions.organization_id
                          AND e.processing_outcome = 'APPLIED'
                        ORDER BY e.provider_sequence DESC,
                                 e.provider_occurred_at DESC
                        LIMIT 1
                    ),
                    last_provider_sequence = (
                        SELECT e.provider_sequence
                        FROM subscriber_billing_events e
                        WHERE e.organization_id =
                              subscriber_subscriptions.organization_id
                          AND e.processing_outcome = 'APPLIED'
                        ORDER BY e.provider_sequence DESC,
                                 e.provider_occurred_at DESC
                        LIMIT 1
                    ),
                    last_provider_event_id = (
                        SELECT e.provider_event_id
                        FROM subscriber_billing_events e
                        WHERE e.organization_id =
                              subscriber_subscriptions.organization_id
                          AND e.processing_outcome = 'APPLIED'
                        ORDER BY e.provider_sequence DESC,
                                 e.provider_occurred_at DESC
                        LIMIT 1
                    )
                WHERE last_provider_sequence IS NULL
                  AND EXISTS (
                      SELECT 1 FROM subscriber_billing_events e
                      WHERE e.organization_id =
                            subscriber_subscriptions.organization_id
                        AND e.processing_outcome = 'APPLIED'
                  )
                """
            )
            reservation_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(subscriber_run_reservations)"
                ).fetchall()
            }
            for column_name, column_type in (
                ("project_id", "TEXT"),
                ("policy_version", "TEXT"),
                ("target_type", "TEXT"),
                ("target_reference", "TEXT"),
                ("target_identity_digest", "TEXT"),
                ("dispatch_target_json", "TEXT"),
                ("dispatch_journey_json", "TEXT"),
                ("submit_request_json", "TEXT"),
                ("worker_id", "TEXT"),
                ("worker_attestation_sha256", "TEXT"),
                ("execution_location", "TEXT"),
                ("signing_authority", "TEXT"),
                ("signing_key_id", "TEXT"),
                ("claim_token", "TEXT"),
                ("lease_expires_at", "TEXT"),
                ("last_heartbeat_at", "TEXT"),
                ("execution_started_at", "TEXT"),
                ("governance_version", "INTEGER"),
                ("subscription_version", "INTEGER"),
                ("consumed_at", "TEXT"),
            ):
                if column_name not in reservation_columns:
                    connection.execute(
                        f"ALTER TABLE subscriber_run_reservations "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
            for plan in self.policy.plans:
                definition = plan.model_dump(mode="json")
                encoded = canonical_json(definition)
                digest = sha256_bytes(encoded.encode("utf-8"))
                existing = connection.execute(
                    "SELECT definition_sha256 FROM subscriber_plans WHERE plan_code = ?",
                    (plan.code,),
                ).fetchone()
                if existing is not None and existing["definition_sha256"] != digest:
                    raise RuntimeError(f"subscriber plan definition drift: {plan.code}")
                connection.execute(
                    """
                    INSERT OR IGNORE INTO subscriber_plans(
                        plan_code, definition_json, definition_sha256, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (plan.code, encoded, digest, now),
                )
            governance_rows = connection.execute(
                """
                SELECT organization_id, config_json, version
                FROM subscriber_governance
                """
            ).fetchall()
            for governance_row in governance_rows:
                config = json.loads(str(governance_row["config_json"]))
                if "customer_signing_key_id" in config:
                    continue
                config["customer_signing_key_id"] = None
                encoded = canonical_json(config)
                next_version = int(governance_row["version"]) + 1
                organization_id = str(governance_row["organization_id"])
                connection.execute(
                    """
                    UPDATE subscriber_governance
                    SET config_json = ?, config_sha256 = ?, version = ?, updated_at = ?
                    WHERE organization_id = ?
                    """,
                    (
                        encoded,
                        sha256_bytes(encoded.encode("utf-8")),
                        next_version,
                        now,
                        organization_id,
                    ),
                )
                self._append_audit(
                    connection,
                    organization_id=organization_id,
                    actor_ref="certforge.migration",
                    action="governance.schema_migrate",
                    resource_type="governance",
                    resource_id=organization_id,
                    outcome="allowed",
                    details={
                        "version": next_version,
                        "added_field": "customer_signing_key_id",
                    },
                )

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{secrets.token_hex(12)}"

    def _token_digest(self, token: str) -> str:
        return hmac.new(self._token_pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        actor_ref: str,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        details: Mapping[str, Any] | None = None,
    ) -> int:
        require_identifier(organization_id, "organization_id")
        require_identifier(actor_ref, "actor_ref")
        require_identifier(action, "action")
        require_identifier(resource_type, "resource_type")
        require_identifier(resource_id, "resource_id")
        require_identifier(outcome, "outcome")
        created_at = to_utc_iso(self._now())
        details_json = canonical_json(dict(details or {}))
        previous = connection.execute(
            """
            SELECT chain_hash FROM subscriber_audit_events
            WHERE organization_id = ? ORDER BY event_id DESC LIMIT 1
            """,
            (organization_id,),
        ).fetchone()
        prev_chain_hash = _ZERO_HASH if previous is None else str(previous["chain_hash"])
        record = {
            "organization_id": organization_id,
            "actor_ref": actor_ref,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "details": json.loads(details_json),
            "created_at": created_at,
        }
        record_hash = sha256_json(record)
        chain_hash = sha256_bytes(bytes.fromhex(prev_chain_hash) + bytes.fromhex(record_hash))
        cursor = connection.execute(
            """
            INSERT INTO subscriber_audit_events(
                organization_id, actor_ref, action, resource_type, resource_id,
                outcome, details_json, created_at, record_hash, prev_chain_hash, chain_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                organization_id,
                actor_ref,
                action,
                resource_type,
                resource_id,
                outcome,
                details_json,
                created_at,
                record_hash,
                prev_chain_hash,
                chain_hash,
            ),
        )
        return int(cursor.lastrowid)

    def _plan_for_org(
        self, connection: sqlite3.Connection, organization_id: str
    ) -> tuple[PlanDefinition, sqlite3.Row]:
        row = connection.execute(
            """
            SELECT s.*, o.status AS organization_status
            FROM subscriber_subscriptions s
            JOIN subscriber_organizations o USING (organization_id)
            WHERE s.organization_id = ?
            """,
            (organization_id,),
        ).fetchone()
        if row is None:
            raise SubscriberError(404, "organization_not_found")
        return self.policy.plan(str(row["plan_code"])), row

    def provision_organization(
        self,
        *,
        slug: str,
        display_name: str,
        owner_email: str,
        owner_display_name: str,
        plan_code: str = "developer",
        status: OrganizationStatus = OrganizationStatus.TRIALING,
        organization_id: str | None = None,
        owner_user_id: str | None = None,
    ) -> ProvisionedOrganization:
        require_identifier(slug, "slug")
        if not display_name.strip() or not owner_display_name.strip():
            raise ValueError("organization and owner display names are required")
        email = owner_email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise ValueError("owner_email is invalid")
        plan = self.policy.plan(plan_code)
        organization_id = organization_id or self._new_id("org")
        user_id = owner_user_id or self._new_id("usr")
        require_identifier(organization_id, "organization_id")
        require_identifier(user_id, "owner_user_id")
        now = self._now()
        now_text = to_utc_iso(now)
        period_end = to_utc_iso(now + timedelta(days=30))
        governance = {
            "allowed_policy_ids": [],
            "retention_days": plan.default_retention_days,
            "private_worker_only": False,
            "report_brand_name": None,
            "report_logo_url": None,
            "customer_managed_signing": False,
            "customer_signing_key_id": None,
            "local_only_execution": plan.local_only_execution,
        }
        with self._connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO subscriber_organizations(
                    organization_id, slug, display_name, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (organization_id, slug, display_name.strip(), status.value, now_text, now_text),
            )
            connection.execute(
                """
                INSERT INTO subscriber_users(
                    user_id, email, display_name, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    email,
                    owner_display_name.strip(),
                    UserStatus.ACTIVE.value,
                    now_text,
                    now_text,
                ),
            )
            connection.execute(
                """
                INSERT INTO subscriber_memberships(
                    organization_id, user_id, role, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    organization_id,
                    user_id,
                    MemberRole.OWNER.value,
                    UserStatus.ACTIVE.value,
                    now_text,
                    now_text,
                ),
            )
            connection.execute(
                """
                INSERT INTO subscriber_subscriptions(
                    organization_id, plan_code, status, current_period_start,
                    current_period_end, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    organization_id,
                    plan.code,
                    status.value,
                    now_text,
                    period_end,
                    now_text,
                    now_text,
                ),
            )
            encoded_governance = canonical_json(governance)
            connection.execute(
                """
                INSERT INTO subscriber_governance(
                    organization_id, config_json, config_sha256, version, updated_at
                ) VALUES (?, ?, ?, 1, ?)
                """,
                (
                    organization_id,
                    encoded_governance,
                    sha256_bytes(encoded_governance.encode("utf-8")),
                    now_text,
                ),
            )
            bootstrap_key = self._create_api_key(
                connection,
                organization_id=organization_id,
                user_id=user_id,
                name="bootstrap-owner",
                scopes=frozenset(Permission),
                expires_at=now + timedelta(days=self.policy.api_key_max_ttl_days),
                actor_ref="control-plane",
            )
            self._append_audit(
                connection,
                organization_id=organization_id,
                actor_ref="control-plane",
                action="organization.provision",
                resource_type="organization",
                resource_id=organization_id,
                outcome="allowed",
                details={"plan_code": plan.code, "status": status.value, "owner_user_id": user_id},
            )
        return ProvisionedOrganization(
            organization_id=organization_id,
            owner_user_id=user_id,
            bootstrap_api_key=bootstrap_key,
            plan_code=plan.code,
            status=status,
        )

    def _create_api_key(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        user_id: str,
        name: str,
        scopes: frozenset[Permission],
        expires_at: datetime,
        actor_ref: str,
    ) -> str:
        if not name.strip():
            raise ValueError("API key name is required")
        membership = connection.execute(
            """
            SELECT m.role, m.status AS membership_status, u.status AS user_status
            FROM subscriber_memberships m
            JOIN subscriber_users u USING (user_id)
            WHERE m.organization_id = ? AND m.user_id = ?
            """,
            (organization_id, user_id),
        ).fetchone()
        if membership is None:
            raise SubscriberError(404, "member_not_found")
        if (
            membership["membership_status"] != UserStatus.ACTIVE.value
            or membership["user_status"] != UserStatus.ACTIVE.value
        ):
            raise SubscriberError(403, "member_inactive")
        allowed = self.policy.role_permissions[MemberRole(str(membership["role"]))]
        if not scopes or not scopes.issubset(allowed):
            raise SubscriberError(403, "api_key_scope_escalation")
        plan, _ = self._plan_for_org(connection, organization_id)
        now = self._now()
        active_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM subscriber_api_keys
                WHERE organization_id = ? AND status = ? AND expires_at > ?
                """,
                (
                    organization_id,
                    ApiKeyStatus.ACTIVE.value,
                    to_utc_iso(now),
                ),
            ).fetchone()[0]
        )
        if active_count >= plan.max_api_keys:
            raise SubscriberError(429, "api_key_quota_exceeded")
        maximum = now + timedelta(days=self.policy.api_key_max_ttl_days)
        if expires_at.tzinfo is None or expires_at <= now or expires_at > maximum:
            raise SubscriberError(422, "api_key_expiry_invalid")
        key_id = self._new_id("key")
        secret = secrets.token_urlsafe(self.policy.api_key_secret_bytes)
        token = f"ecf_live_{key_id}.{secret}"
        connection.execute(
            """
            INSERT INTO subscriber_api_keys(
                key_id, organization_id, user_id, name, token_digest, token_prefix,
                scopes_json, status, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                organization_id,
                user_id,
                name.strip(),
                self._token_digest(token),
                token[:20],
                canonical_json(sorted(scope.value for scope in scopes)),
                ApiKeyStatus.ACTIVE.value,
                to_utc_iso(expires_at),
                to_utc_iso(now),
            ),
        )
        self._append_audit(
            connection,
            organization_id=organization_id,
            actor_ref=actor_ref,
            action="api_key.create",
            resource_type="api_key",
            resource_id=key_id,
            outcome="allowed",
            details={"name": name.strip(), "scopes": sorted(scope.value for scope in scopes)},
        )
        return token

    def create_api_key(
        self,
        principal: SubscriberPrincipal,
        *,
        name: str,
        scopes: Collection[Permission],
        expires_at: datetime,
        user_id: str | None = None,
    ) -> str:
        self.require(principal, Permission.API_KEY_MANAGE)
        requested = frozenset(scopes)
        if not requested.issubset(principal.scopes):
            raise SubscriberError(403, "api_key_scope_escalation")
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.API_KEY_MANAGE
            )
            return self._create_api_key(
                connection,
                organization_id=principal.organization_id,
                user_id=user_id or principal.user_id,
                name=name,
                scopes=requested,
                expires_at=expires_at,
                actor_ref=principal.user_id,
            )

    def authenticate(
        self,
        token: str,
        *,
        tenant_hint: str | None,
        permission: Permission,
        action: str,
    ) -> SubscriberPrincipal:
        if not token.startswith("ecf_live_key_") or "." not in token:
            raise SubscriberError(401, "api_key_invalid")
        key_id = token.removeprefix("ecf_live_").split(".", 1)[0]
        require_identifier(key_id, "key_id")
        now = self._now()
        denied_audit: dict[str, Any] | None = None
        try:
            with self._connection(immediate=True) as connection:
                row = connection.execute(
                    """
                    SELECT k.*, m.role, m.status AS membership_status,
                           u.status AS user_status, o.status AS organization_status,
                           s.plan_code
                    FROM subscriber_api_keys k
                    JOIN subscriber_memberships m
                      ON m.organization_id = k.organization_id AND m.user_id = k.user_id
                    JOIN subscriber_users u ON u.user_id = k.user_id
                    JOIN subscriber_organizations o ON o.organization_id = k.organization_id
                    JOIN subscriber_subscriptions s ON s.organization_id = k.organization_id
                    WHERE k.key_id = ?
                    """,
                    (key_id,),
                ).fetchone()
                if row is None or not hmac.compare_digest(
                    str(row["token_digest"]), self._token_digest(token)
                ):
                    raise SubscriberError(401, "api_key_invalid")
                organization_id = str(row["organization_id"])
                actor_ref = str(row["user_id"])

                def deny(code: str) -> None:
                    nonlocal denied_audit
                    denied_audit = {
                        "organization_id": organization_id,
                        "actor_ref": actor_ref,
                        "resource_id": key_id,
                        "details": {
                            "reason": code,
                            "permission": permission.value,
                            "request_action": action,
                        },
                    }

                if tenant_hint is None or tenant_hint != organization_id:
                    deny("tenant_mismatch")
                    raise SubscriberError(404, "tenant_not_found")
                if row["status"] != ApiKeyStatus.ACTIVE.value:
                    deny("api_key_revoked")
                    raise SubscriberError(401, "api_key_revoked")
                if parse_utc_iso(str(row["expires_at"])) <= now:
                    deny("api_key_expired")
                    raise SubscriberError(401, "api_key_expired")
                if (
                    row["membership_status"] != UserStatus.ACTIVE.value
                    or row["user_status"] != UserStatus.ACTIVE.value
                ):
                    deny("member_inactive")
                    raise SubscriberError(403, "member_inactive")
                scopes = frozenset(
                    Permission(item) for item in json.loads(row["scopes_json"])
                )
                principal = SubscriberPrincipal(
                    organization_id=organization_id,
                    user_id=actor_ref,
                    role=MemberRole(str(row["role"])),
                    key_id=key_id,
                    scopes=scopes,
                    organization_status=OrganizationStatus(
                        str(row["organization_status"])
                    ),
                    plan_code=str(row["plan_code"]),
                )
                try:
                    self._require_with_connection(connection, principal, permission)
                    self._consume_rate_limit(connection, principal, action, now)
                except SubscriberError as exc:
                    deny(exc.code)
                    raise
                connection.execute(
                    "UPDATE subscriber_api_keys SET last_used_at = ? WHERE key_id = ?",
                    (to_utc_iso(now), key_id),
                )
                self._append_audit(
                    connection,
                    organization_id=organization_id,
                    actor_ref=principal.user_id,
                    action="request.authorize",
                    resource_type="api_key",
                    resource_id=key_id,
                    outcome="allowed",
                    details={"permission": permission.value, "request_action": action},
                )
                return principal
        except SubscriberError:
            if denied_audit is not None and self.policy.audit_denied_requests:
                with self._connection(immediate=True) as connection:
                    self._append_audit(
                        connection,
                        organization_id=str(denied_audit["organization_id"]),
                        actor_ref=str(denied_audit["actor_ref"]),
                        action="request.deny",
                        resource_type="api_key",
                        resource_id=str(denied_audit["resource_id"]),
                        outcome="denied",
                        details=denied_audit["details"],
                    )
            raise

    def resolve_request_audit_actor(self, token: str) -> dict[str, str] | None:
        if not token.startswith("ecf_live_key_") or "." not in token:
            return None
        key_id = token.removeprefix("ecf_live_").split(".", 1)[0]
        try:
            require_identifier(key_id, "key_id")
        except ValueError:
            return None
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT key_id, organization_id, user_id, token_digest
                FROM subscriber_api_keys
                WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()
        if row is None or not hmac.compare_digest(
            str(row["token_digest"]), self._token_digest(token)
        ):
            return None
        return {
            "organization_id": str(row["organization_id"]),
            "actor_ref": str(row["user_id"]),
            "key_id": str(row["key_id"]),
        }

    def audit_request_outcome(
        self,
        *,
        organization_id: str,
        actor_ref: str,
        key_id: str,
        method: str,
        path: str,
        status_code: int,
        tenant_hint: str | None,
        reason: str | None = None,
    ) -> None:
        outcome = (
            "allowed"
            if status_code < 400
            else "error"
            if status_code >= 500
            else "denied"
        )
        with self._connection(immediate=True) as connection:
            self._append_audit(
                connection,
                organization_id=organization_id,
                actor_ref=actor_ref,
                action="request.outcome",
                resource_type="api_key",
                resource_id=key_id,
                outcome=outcome,
                details={
                    "method": method,
                    "path": path,
                    "status_code": status_code,
                    "tenant_hint_matches": tenant_hint == organization_id,
                    "reason": reason or f"http_{status_code}",
                },
            )

    def audit_resource_event(
        self,
        principal: SubscriberPrincipal,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Append a tenant-scoped domain audit event after reauthorizing the actor."""
        with self._connection(immediate=True) as connection:
            self._require_with_connection(connection, principal, Permission.RUN_READ)
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome="allowed",
                details=details,
            )

    def require(self, principal: SubscriberPrincipal, permission: Permission) -> None:
        with self._connection() as connection:
            self._require_with_connection(connection, principal, permission)

    def require_plan_feature(self, principal: SubscriberPrincipal, feature: str) -> None:
        plan = self.policy.plan(principal.plan_code)
        value = plan.model_dump(mode="python").get(feature)
        if value is not True:
            raise SubscriberError(403, f"{feature}_not_entitled")

    def _require_with_connection(
        self,
        connection: sqlite3.Connection,
        principal: SubscriberPrincipal,
        permission: Permission,
    ) -> None:
        row = connection.execute(
            """
            SELECT o.status AS organization_status, u.status AS user_status,
                   m.status AS membership_status, m.role, s.plan_code,
                   s.current_period_end, k.status AS key_status,
                   k.expires_at AS key_expires_at, k.scopes_json AS key_scopes_json
            FROM subscriber_organizations o
            JOIN subscriber_subscriptions s USING (organization_id)
            JOIN subscriber_memberships m USING (organization_id)
            JOIN subscriber_users u USING (user_id)
            JOIN subscriber_api_keys k
              ON k.key_id = ?
             AND k.organization_id = o.organization_id
             AND k.user_id = u.user_id
            WHERE o.organization_id = ? AND u.user_id = ?
            """,
            (principal.key_id, principal.organization_id, principal.user_id),
        ).fetchone()
        if row is None:
            raise SubscriberError(403, "membership_missing")
        if row["key_status"] != ApiKeyStatus.ACTIVE.value:
            raise SubscriberError(401, "api_key_inactive")
        if parse_utc_iso(str(row["key_expires_at"])) <= self._now():
            raise SubscriberError(401, "api_key_expired")
        if (
            row["membership_status"] != UserStatus.ACTIVE.value
            or row["user_status"] != UserStatus.ACTIVE.value
        ):
            raise SubscriberError(403, "member_inactive")
        organization_status = OrganizationStatus(str(row["organization_status"]))
        if organization_status is OrganizationStatus.PAST_DUE:
            if permission not in self.policy.past_due_read_permissions:
                raise SubscriberError(402, "subscription_past_due")
        elif organization_status is OrganizationStatus.SUSPENDED:
            raise SubscriberError(403, "organization_suspended")
        elif organization_status is OrganizationStatus.CANCELLED:
            raise SubscriberError(403, "organization_cancelled")
        elif parse_utc_iso(str(row["current_period_end"])) <= self._now():
            if permission not in self.policy.past_due_read_permissions:
                raise SubscriberError(402, "subscription_period_expired")
        role = MemberRole(str(row["role"]))
        key_scopes = frozenset(
            Permission(item) for item in json.loads(str(row["key_scopes_json"]))
        )
        if permission not in self.policy.role_permissions[role] or permission not in key_scopes:
            raise SubscriberError(403, "permission_denied")

    def _consume_rate_limit(
        self,
        connection: sqlite3.Connection,
        principal: SubscriberPrincipal,
        action: str,
        now: datetime,
    ) -> None:
        require_identifier(action, "action")
        plan = self.policy.plan(principal.plan_code)
        bucket = self.policy.rate_limit_scope
        row = connection.execute(
            """
            SELECT window_started_at, request_count FROM subscriber_rate_limits
            WHERE organization_id = ? AND key_id = ? AND action = ?
            """,
            (principal.organization_id, principal.key_id, bucket),
        ).fetchone()
        window_seconds = self.policy.rate_window_seconds
        if row is None or (now - parse_utc_iso(str(row["window_started_at"]))).total_seconds() >= window_seconds:
            connection.execute(
                """
                INSERT INTO subscriber_rate_limits(
                    organization_id, key_id, action, window_started_at, request_count, updated_at
                ) VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(organization_id, key_id, action) DO UPDATE SET
                    window_started_at=excluded.window_started_at,
                    request_count=1,
                    updated_at=excluded.updated_at
                """,
                (
                    principal.organization_id,
                    principal.key_id,
                    bucket,
                    to_utc_iso(now),
                    to_utc_iso(now),
                ),
            )
            return
        count = int(row["request_count"])
        if count >= plan.requests_per_minute:
            elapsed = int((now - parse_utc_iso(str(row["window_started_at"]))).total_seconds())
            retry_after = max(1, window_seconds - elapsed)
            raise SubscriberError(429, "rate_limit_exceeded", retry_after=retry_after)
        connection.execute(
            """
            UPDATE subscriber_rate_limits SET request_count = request_count + 1, updated_at = ?
            WHERE organization_id = ? AND key_id = ? AND action = ?
            """,
            (
                to_utc_iso(now),
                principal.organization_id,
                principal.key_id,
                bucket,
            ),
        )

    def create_project(
        self,
        principal: SubscriberPrincipal,
        *,
        slug: str,
        name: str,
        target_reference: str,
    ) -> dict[str, Any]:
        self.require(principal, Permission.PROJECT_MANAGE)
        require_identifier(slug, "slug")
        if not name.strip() or not target_reference.strip():
            raise ValueError("project name and target_reference are required")
        now = to_utc_iso(self._now())
        project_id = self._new_id("prj")
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.PROJECT_MANAGE
            )
            plan, _ = self._plan_for_org(connection, principal.organization_id)
            count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_projects
                    WHERE organization_id = ? AND status = 'ACTIVE'
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
            if count >= plan.max_projects:
                raise SubscriberError(429, "project_quota_exceeded")
            try:
                connection.execute(
                    """
                    INSERT INTO subscriber_projects(
                        project_id, organization_id, slug, name, target_reference,
                        status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
                    """,
                    (
                        project_id,
                        principal.organization_id,
                        slug,
                        name.strip(),
                        target_reference.strip(),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SubscriberError(409, "project_slug_conflict") from exc
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="project.create",
                resource_type="project",
                resource_id=project_id,
                outcome="allowed",
                details={"slug": slug, "target_reference": target_reference.strip()},
            )
            return {
                "project_id": project_id,
                "organization_id": principal.organization_id,
                "slug": slug,
                "name": name.strip(),
                "target_reference": target_reference.strip(),
                "status": "ACTIVE",
                "created_at": now,
                "updated_at": now,
            }

    def list_projects(self, principal: SubscriberPrincipal) -> list[dict[str, Any]]:
        self.require(principal, Permission.PROJECT_READ)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT project_id, organization_id, slug, name, target_reference,
                       status, created_at, updated_at
                FROM subscriber_projects WHERE organization_id = ?
                ORDER BY created_at, project_id
                """,
                (principal.organization_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_project(
        self, principal: SubscriberPrincipal, project_id: str, *, required_status: str | None = None
    ) -> dict[str, Any]:
        self.require(principal, Permission.PROJECT_READ)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT project_id, organization_id, slug, name, target_reference,
                       status, created_at, updated_at
                FROM subscriber_projects
                WHERE project_id = ? AND organization_id = ?
                """,
                (project_id, principal.organization_id),
            ).fetchone()
        if row is None or (required_status is not None and row["status"] != required_status):
            raise SubscriberError(404, "project_not_found")
        return dict(row)

    def archive_project(
        self, principal: SubscriberPrincipal, project_id: str
    ) -> None:
        self.require(principal, Permission.PROJECT_MANAGE)
        require_identifier(project_id, "project_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.PROJECT_MANAGE
            )
            row = connection.execute(
                """
                SELECT status FROM subscriber_projects
                WHERE project_id = ? AND organization_id = ?
                """,
                (project_id, principal.organization_id),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "project_not_found")
            if row["status"] == "ARCHIVED":
                return
            connection.execute(
                """
                UPDATE subscriber_projects SET status = 'ARCHIVED', updated_at = ?
                WHERE project_id = ? AND organization_id = ?
                """,
                (now, project_id, principal.organization_id),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="project.archive",
                resource_type="project",
                resource_id=project_id,
                outcome="allowed",
            )

    def list_api_keys(self, principal: SubscriberPrincipal) -> list[dict[str, Any]]:
        self.require(principal, Permission.API_KEY_MANAGE)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT key_id, user_id, name, token_prefix, scopes_json, status,
                       expires_at, created_at, revoked_at, last_used_at
                FROM subscriber_api_keys WHERE organization_id = ?
                ORDER BY created_at, key_id
                """,
                (principal.organization_id,),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "scopes_json"},
                "scopes": json.loads(row["scopes_json"]),
            }
            for row in rows
        ]

    def revoke_api_key(self, principal: SubscriberPrincipal, key_id: str) -> None:
        self.require(principal, Permission.API_KEY_MANAGE)
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.API_KEY_MANAGE
            )
            row = connection.execute(
                """
                SELECT status FROM subscriber_api_keys
                WHERE key_id = ? AND organization_id = ?
                """,
                (key_id, principal.organization_id),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "api_key_not_found")
            if row["status"] == ApiKeyStatus.REVOKED.value:
                return
            connection.execute(
                """
                UPDATE subscriber_api_keys SET status = ?, revoked_at = ?
                WHERE key_id = ? AND organization_id = ?
                """,
                (
                    ApiKeyStatus.REVOKED.value,
                    now,
                    key_id,
                    principal.organization_id,
                ),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="api_key.revoke",
                resource_type="api_key",
                resource_id=key_id,
                outcome="allowed",
            )

    def invite_member(
        self,
        principal: SubscriberPrincipal,
        *,
        email: str,
        display_name: str,
        role: MemberRole,
    ) -> str:
        self.require(principal, Permission.MEMBER_MANAGE)
        if role is MemberRole.OWNER:
            raise SubscriberError(422, "owner_role_transfer_required")
        normalized_email = email.strip().lower()
        if "@" not in normalized_email or not display_name.strip():
            raise ValueError("valid member email and display name are required")
        user_id = self._new_id("usr")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.MEMBER_MANAGE
            )
            existing = connection.execute(
                "SELECT user_id FROM subscriber_users WHERE email = ?", (normalized_email,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO subscriber_users(
                        user_id, email, display_name, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        normalized_email,
                        display_name.strip(),
                        UserStatus.INVITED.value,
                        now,
                        now,
                    ),
                )
            else:
                user_id = str(existing["user_id"])
            try:
                connection.execute(
                    """
                    INSERT INTO subscriber_memberships(
                        organization_id, user_id, role, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal.organization_id,
                        user_id,
                        role.value,
                        UserStatus.INVITED.value,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SubscriberError(409, "membership_exists") from exc
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="member.invite",
                resource_type="member",
                resource_id=user_id,
                outcome="allowed",
                details={"role": role.value},
            )
        return user_id

    def activate_member(
        self, principal: SubscriberPrincipal, user_id: str
    ) -> None:
        self.require(principal, Permission.MEMBER_MANAGE)
        require_identifier(user_id, "user_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.MEMBER_MANAGE
            )
            membership = connection.execute(
                """
                SELECT 1 FROM subscriber_memberships
                WHERE organization_id = ? AND user_id = ?
                """,
                (principal.organization_id, user_id),
            ).fetchone()
            if membership is None:
                raise SubscriberError(404, "member_not_found")
            connection.execute(
                """
                UPDATE subscriber_memberships SET status = ?, updated_at = ?
                WHERE organization_id = ? AND user_id = ?
                """,
                (
                    UserStatus.ACTIVE.value,
                    now,
                    principal.organization_id,
                    user_id,
                ),
            )
            connection.execute(
                """
                UPDATE subscriber_users SET status = ?, updated_at = ?
                WHERE user_id = ? AND status = ?
                """,
                (
                    UserStatus.ACTIVE.value,
                    now,
                    user_id,
                    UserStatus.INVITED.value,
                ),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="member.activate",
                resource_type="member",
                resource_id=user_id,
                outcome="allowed",
            )

    def list_members(self, principal: SubscriberPrincipal) -> list[dict[str, Any]]:
        self.require(principal, Permission.MEMBER_MANAGE)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT m.user_id, u.email, u.display_name, m.role,
                       m.status, u.status AS user_status,
                       m.created_at, m.updated_at
                FROM subscriber_memberships m
                JOIN subscriber_users u USING (user_id)
                WHERE m.organization_id = ?
                ORDER BY m.created_at, m.user_id
                """,
                (principal.organization_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_member_role(
        self,
        principal: SubscriberPrincipal,
        user_id: str,
        role: MemberRole,
    ) -> None:
        self.require(principal, Permission.MEMBER_MANAGE)
        if role is MemberRole.OWNER:
            raise SubscriberError(422, "owner_role_transfer_required")
        require_identifier(user_id, "user_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.MEMBER_MANAGE
            )
            row = connection.execute(
                """
                SELECT role FROM subscriber_memberships
                WHERE organization_id = ? AND user_id = ?
                """,
                (principal.organization_id, user_id),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "member_not_found")
            if row["role"] == MemberRole.OWNER.value:
                raise SubscriberError(422, "owner_role_transfer_required")
            if row["role"] == role.value:
                return
            connection.execute(
                """
                UPDATE subscriber_memberships SET role = ?, updated_at = ?
                WHERE organization_id = ? AND user_id = ?
                """,
                (role.value, now, principal.organization_id, user_id),
            )
            revoked = connection.execute(
                """
                UPDATE subscriber_api_keys
                SET status = ?, revoked_at = ?
                WHERE organization_id = ? AND user_id = ? AND status = ?
                """,
                (
                    ApiKeyStatus.REVOKED.value,
                    now,
                    principal.organization_id,
                    user_id,
                    ApiKeyStatus.ACTIVE.value,
                ),
            ).rowcount
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="member.role_update",
                resource_type="member",
                resource_id=user_id,
                outcome="allowed",
                details={
                    "from": str(row["role"]),
                    "to": role.value,
                    "revoked_api_keys": revoked,
                },
            )

    def deactivate_member(
        self, principal: SubscriberPrincipal, user_id: str
    ) -> None:
        self.require(principal, Permission.MEMBER_MANAGE)
        require_identifier(user_id, "user_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.MEMBER_MANAGE
            )
            row = connection.execute(
                """
                SELECT role, status FROM subscriber_memberships
                WHERE organization_id = ? AND user_id = ?
                """,
                (principal.organization_id, user_id),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "member_not_found")
            if row["role"] == MemberRole.OWNER.value:
                raise SubscriberError(422, "owner_role_transfer_required")
            if row["status"] == UserStatus.DEACTIVATED.value:
                return
            connection.execute(
                """
                UPDATE subscriber_memberships SET status = ?, updated_at = ?
                WHERE organization_id = ? AND user_id = ?
                """,
                (
                    UserStatus.DEACTIVATED.value,
                    now,
                    principal.organization_id,
                    user_id,
                ),
            )
            revoked = connection.execute(
                """
                UPDATE subscriber_api_keys
                SET status = ?, revoked_at = ?
                WHERE organization_id = ? AND user_id = ? AND status = ?
                """,
                (
                    ApiKeyStatus.REVOKED.value,
                    now,
                    principal.organization_id,
                    user_id,
                    ApiKeyStatus.ACTIVE.value,
                ),
            ).rowcount
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="member.deactivate",
                resource_type="member",
                resource_id=user_id,
                outcome="allowed",
                details={"revoked_api_keys": revoked},
            )

    def subscription(self, principal: SubscriberPrincipal) -> dict[str, Any]:
        self.require(principal, Permission.GOVERNANCE_READ)
        with self._connection() as connection:
            plan, row = self._plan_for_org(connection, principal.organization_id)
        return {
            "organization_id": principal.organization_id,
            "plan": plan.model_dump(mode="json"),
            "status": row["status"],
            "current_period_start": row["current_period_start"],
            "current_period_end": row["current_period_end"],
            "cancel_at_period_end": bool(row["cancel_at_period_end"]),
        }

    def request_subscription_cancellation(self, principal: SubscriberPrincipal) -> dict[str, Any]:
        self.require(principal, Permission.BILLING_MANAGE)
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.BILLING_MANAGE
            )
            connection.execute(
                """
                UPDATE subscriber_subscriptions
                SET cancel_at_period_end = 1, updated_at = ?
                WHERE organization_id = ?
                """,
                (now, principal.organization_id),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="subscription.cancel_at_period_end",
                resource_type="subscription",
                resource_id=principal.organization_id,
                outcome="allowed",
            )
        return self.subscription(principal)

    def _reconcile_governance_for_plan(
        self,
        connection: sqlite3.Connection,
        organization_id: str,
        plan: PlanDefinition,
        now: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT config_json, version FROM subscriber_governance
            WHERE organization_id = ?
            """,
            (organization_id,),
        ).fetchone()
        if row is None:
            raise SubscriberError(503, "governance_config_missing")
        try:
            config = json.loads(str(row["config_json"]))
            prior = dict(config)
            retention_days = int(config["retention_days"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SubscriberError(503, "governance_config_invalid") from exc
        config["retention_days"] = max(
            1, min(retention_days, plan.maximum_retention_days)
        )
        if not plan.private_workers:
            config["private_worker_only"] = False
        if not plan.white_label_reports:
            config["report_brand_name"] = None
            config["report_logo_url"] = None
        if not plan.customer_managed_keys:
            config["customer_managed_signing"] = False
            config["customer_signing_key_id"] = None
        if not plan.local_only_execution:
            config["local_only_execution"] = False
        if config == prior:
            return
        encoded = canonical_json(config)
        next_version = int(row["version"]) + 1
        connection.execute(
            """
            UPDATE subscriber_governance
            SET config_json = ?, config_sha256 = ?, version = ?, updated_at = ?
            WHERE organization_id = ?
            """,
            (
                encoded,
                sha256_bytes(encoded.encode("utf-8")),
                next_version,
                now,
                organization_id,
            ),
        )
        self._append_audit(
            connection,
            organization_id=organization_id,
            actor_ref="billing-provider",
            action="governance.plan_reconcile",
            resource_type="governance",
            resource_id=organization_id,
            outcome="allowed",
            details={
                "plan_code": plan.code,
                "version": next_version,
                "retention_days": config["retention_days"],
            },
        )

    def _revoke_nonstarted_runs(
        self,
        connection: sqlite3.Connection,
        organization_id: str,
        now: str,
        reason: str,
    ) -> int:
        rows = connection.execute(
            """
            SELECT idempotency_key, run_id
            FROM subscriber_run_reservations
            WHERE organization_id = ?
              AND execution_started_at IS NULL
              AND state IN ('RESERVED', 'BOUND', 'EXECUTING')
            """,
            (organization_id,),
        ).fetchall()
        cancelled_runs = 0
        for row in rows:
            run_id = row["run_id"]
            if run_id is not None:
                run = connection.execute(
                    "SELECT state FROM runs WHERE run_id = ? AND tenant_id = ?",
                    (run_id, organization_id),
                ).fetchone()
                if run is not None and str(run["state"]) == "QUEUED":
                    self._transition_run_with_connection(
                        connection,
                        str(run_id),
                        organization_id,
                        "QUEUED",
                        "CANCELLED",
                        "billing-provider",
                        reason,
                        "p7.subscriber",
                        now,
                    )
                    connection.execute(
                        """
                        UPDATE runs SET run_outcome = 'CANCELLED', updated_at = ?
                        WHERE run_id = ? AND tenant_id = ?
                        """,
                        (now, run_id, organization_id),
                    )
                    cancelled_runs += 1
                connection.execute(
                    """
                    UPDATE subscriber_run_dispatches
                    SET state = 'CANCELLED', claim_token = NULL, lease_owner = NULL,
                        lease_expires_at = NULL, last_error = ?, updated_at = ?
                    WHERE run_id = ? AND organization_id = ?
                      AND state IN ('PENDING', 'CLAIMED')
                    """,
                    (reason, now, run_id, organization_id),
                )
            connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'RELEASED', claim_token = NULL, lease_expires_at = NULL,
                    last_heartbeat_at = NULL, updated_at = ?
                WHERE organization_id = ? AND idempotency_key = ?
                  AND execution_started_at IS NULL
                  AND state IN ('RESERVED', 'BOUND', 'EXECUTING')
                """,
                (now, organization_id, row["idempotency_key"]),
            )
        if rows:
            self._append_audit(
                connection,
                organization_id=organization_id,
                actor_ref="billing-provider",
                action="certification.revoke_nonstarted",
                resource_type="subscription",
                resource_id=organization_id,
                outcome="allowed",
                details={
                    "reason": reason,
                    "reservations_released": len(rows),
                    "runs_cancelled": cancelled_runs,
                },
            )
        return len(rows)

    def apply_billing_event(
        self,
        *,
        organization_id: str,
        provider_event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        provider_occurred_at: datetime,
        provider_sequence: int,
        plan_code: str | None = None,
    ) -> OrganizationStatus:
        require_identifier(organization_id, "organization_id")
        require_identifier(provider_event_id, "provider_event_id")
        if not isinstance(provider_occurred_at, datetime) or provider_occurred_at.tzinfo is None:
            raise SubscriberError(422, "billing_event_timestamp_invalid")
        if (
            isinstance(provider_sequence, bool)
            or not isinstance(provider_sequence, int)
            or provider_sequence < 0
        ):
            raise SubscriberError(422, "billing_event_sequence_invalid")
        occurred_at = to_utc_iso(provider_occurred_at)
        event_statuses = {
            "subscription.activated": OrganizationStatus.ACTIVE,
            "subscription.renewed": OrganizationStatus.ACTIVE,
            "subscription.plan_changed": OrganizationStatus.ACTIVE,
            "subscription.reactivated": OrganizationStatus.ACTIVE,
            "payment.failed": OrganizationStatus.PAST_DUE,
            "subscription.suspended": OrganizationStatus.SUSPENDED,
            "subscription.cancelled": OrganizationStatus.CANCELLED,
        }
        if event_type not in event_statuses:
            raise SubscriberError(422, "billing_event_unknown")
        period_required = event_type in {
            "subscription.activated",
            "subscription.renewed",
            "subscription.plan_changed",
            "subscription.reactivated",
        }
        if event_type == "subscription.plan_changed" and plan_code is None:
            raise SubscriberError(422, "billing_plan_required")
        if plan_code is not None and not period_required:
            raise SubscriberError(422, "billing_plan_not_allowed")
        if plan_code is not None:
            self.policy.plan(plan_code)
        encoded = canonical_json(dict(payload))
        digest = sha256_json(
            {
                "organization_id": organization_id,
                "event_type": event_type,
                "plan_code": plan_code,
                "provider_occurred_at": occurred_at,
                "provider_sequence": provider_sequence,
                "payload": json.loads(encoded),
            }
        )
        period_start_value = payload.get("current_period_start")
        period_end_value = payload.get("current_period_end")
        if period_required and (
            period_start_value is None or period_end_value is None
        ):
            raise SubscriberError(422, "billing_period_required")
        if (period_start_value is None) != (period_end_value is None):
            raise SubscriberError(422, "billing_period_incomplete")
        period_start: str | None = None
        period_end: str | None = None
        if period_start_value is not None and period_end_value is not None:
            if not isinstance(period_start_value, str) or not isinstance(
                period_end_value, str
            ):
                raise SubscriberError(422, "billing_period_invalid")
            try:
                parsed_start = parse_utc_iso(period_start_value)
                parsed_end = parse_utc_iso(period_end_value)
            except ValueError as exc:
                raise SubscriberError(422, "billing_period_invalid") from exc
            if parsed_end <= parsed_start:
                raise SubscriberError(422, "billing_period_invalid")
            period_start = to_utc_iso(parsed_start)
            period_end = to_utc_iso(parsed_end)
        now = to_utc_iso(self._now())
        stale_event = False
        target = event_statuses[event_type]
        with self._connection(immediate=True) as connection:
            existing = connection.execute(
                """
                SELECT organization_id, event_type, payload_sha256,
                       provider_occurred_at, provider_sequence, processing_outcome
                FROM subscriber_billing_events
                WHERE provider_event_id = ?
                """,
                (provider_event_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["organization_id"] != organization_id
                    or existing["event_type"] != event_type
                    or existing["payload_sha256"] != digest
                    or existing["provider_occurred_at"] != occurred_at
                    or existing["provider_sequence"] != provider_sequence
                ):
                    raise SubscriberError(409, "billing_event_conflict")
                if existing["processing_outcome"] == "REJECTED_STALE":
                    raise SubscriberError(409, "billing_event_stale")
                row = connection.execute(
                    "SELECT status FROM subscriber_organizations WHERE organization_id = ?",
                    (organization_id,),
                ).fetchone()
                if row is None:
                    raise SubscriberError(404, "organization_not_found")
                return OrganizationStatus(str(row["status"]))
            row = connection.execute(
                """
                SELECT o.status, s.last_provider_occurred_at, s.last_provider_sequence
                FROM subscriber_organizations o
                JOIN subscriber_subscriptions s
                  ON s.organization_id = o.organization_id
                WHERE o.organization_id = ?
                """,
                (organization_id,),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "organization_not_found")
            current = OrganizationStatus(str(row["status"]))
            last_sequence = row["last_provider_sequence"]
            last_occurred_at = row["last_provider_occurred_at"]
            stale_event = last_sequence is not None and (
                provider_sequence <= int(last_sequence)
                or (
                    last_occurred_at is not None
                    and parse_utc_iso(occurred_at) < parse_utc_iso(str(last_occurred_at))
                )
            )
            if stale_event:
                connection.execute(
                    """
                    INSERT INTO subscriber_billing_events(
                        provider_event_id, organization_id, event_type,
                        provider_occurred_at, provider_sequence, processing_outcome,
                        payload_sha256, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'REJECTED_STALE', ?, ?, ?)
                    """,
                    (
                        provider_event_id,
                        organization_id,
                        event_type,
                        occurred_at,
                        provider_sequence,
                        digest,
                        encoded,
                        now,
                    ),
                )
                self._append_audit(
                    connection,
                    organization_id=organization_id,
                    actor_ref="billing-provider",
                    action="subscription.transition",
                    resource_type="subscription",
                    resource_id=organization_id,
                    outcome="denied",
                    details={
                        "reason": "billing_event_stale",
                        "event_type": event_type,
                        "provider_event_id": provider_event_id,
                        "provider_occurred_at": occurred_at,
                        "provider_sequence": provider_sequence,
                        "last_provider_occurred_at": last_occurred_at,
                        "last_provider_sequence": last_sequence,
                    },
                )
            else:
                if event_type in {"subscription.renewed", "subscription.plan_changed"}:
                    target = current
                allowed = {
                    OrganizationStatus.TRIALING: {
                        OrganizationStatus.ACTIVE,
                        OrganizationStatus.PAST_DUE,
                        OrganizationStatus.SUSPENDED,
                        OrganizationStatus.CANCELLED,
                    },
                    OrganizationStatus.ACTIVE: {
                        OrganizationStatus.PAST_DUE,
                        OrganizationStatus.SUSPENDED,
                        OrganizationStatus.CANCELLED,
                    },
                    OrganizationStatus.PAST_DUE: {
                        OrganizationStatus.ACTIVE,
                        OrganizationStatus.SUSPENDED,
                        OrganizationStatus.CANCELLED,
                    },
                    OrganizationStatus.SUSPENDED: {
                        OrganizationStatus.ACTIVE,
                        OrganizationStatus.CANCELLED,
                    },
                    OrganizationStatus.CANCELLED: set(),
                }
                if target != current and target not in allowed[current]:
                    raise SubscriberError(409, "subscription_transition_invalid")
                connection.execute(
                    """
                    INSERT INTO subscriber_billing_events(
                        provider_event_id, organization_id, event_type,
                        provider_occurred_at, provider_sequence, processing_outcome,
                        payload_sha256, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'APPLIED', ?, ?, ?)
                    """,
                    (
                        provider_event_id,
                        organization_id,
                        event_type,
                        occurred_at,
                        provider_sequence,
                        digest,
                        encoded,
                        now,
                    ),
                )
                connection.execute(
                    """
                    UPDATE subscriber_organizations SET status = ?, updated_at = ?
                    WHERE organization_id = ?
                    """,
                    (target.value, now, organization_id),
                )
                if period_required:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions
                        SET status = ?, plan_code = COALESCE(?, plan_code),
                            current_period_start = ?, current_period_end = ?,
                            last_provider_occurred_at = ?,
                            last_provider_sequence = ?,
                            last_provider_event_id = ?, version = version + 1,
                            updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (
                            target.value,
                            plan_code,
                            period_start,
                            period_end,
                            occurred_at,
                            provider_sequence,
                            provider_event_id,
                            now,
                            organization_id,
                        ),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions
                        SET status = ?, plan_code = COALESCE(?, plan_code),
                            last_provider_occurred_at = ?,
                            last_provider_sequence = ?,
                            last_provider_event_id = ?, version = version + 1,
                            updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (
                            target.value,
                            plan_code,
                            occurred_at,
                            provider_sequence,
                            provider_event_id,
                            now,
                            organization_id,
                        ),
                    )
                if plan_code is not None:
                    self._reconcile_governance_for_plan(
                        connection,
                        organization_id,
                        self.policy.plan(plan_code),
                        now,
                    )
                if target in {
                    OrganizationStatus.PAST_DUE,
                    OrganizationStatus.SUSPENDED,
                    OrganizationStatus.CANCELLED,
                }:
                    self._revoke_nonstarted_runs(
                        connection,
                        organization_id,
                        now,
                        f"subscription_{target.value.lower()}",
                    )
                self._append_audit(
                    connection,
                    organization_id=organization_id,
                    actor_ref="billing-provider",
                    action="subscription.transition",
                    resource_type="subscription",
                    resource_id=organization_id,
                    outcome="allowed",
                    details={
                        "from": current.value,
                        "to": target.value,
                        "event_type": event_type,
                        "provider_event_id": provider_event_id,
                        "provider_occurred_at": occurred_at,
                        "provider_sequence": provider_sequence,
                        "plan_code": plan_code,
                    },
                )
        if stale_event:
            raise SubscriberError(409, "billing_event_stale")
        return target

    def governance_config(self, principal: SubscriberPrincipal) -> dict[str, Any]:
        self.require(principal, Permission.GOVERNANCE_READ)
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT config_json, config_sha256, version, updated_at
                FROM subscriber_governance WHERE organization_id = ?
                """,
                (principal.organization_id,),
            ).fetchone()
        if row is None:
            raise SubscriberError(503, "governance_config_missing")
        return {
            "organization_id": principal.organization_id,
            "config": json.loads(row["config_json"]),
            "config_sha256": row["config_sha256"],
            "version": row["version"],
            "updated_at": row["updated_at"],
        }

    def update_governance(
        self,
        principal: SubscriberPrincipal,
        config: Mapping[str, Any],
        *,
        expected_version: int,
    ) -> dict[str, Any]:
        self.require(principal, Permission.GOVERNANCE_MANAGE)
        allowed_keys = {
            "allowed_policy_ids",
            "retention_days",
            "private_worker_only",
            "report_brand_name",
            "report_logo_url",
            "customer_managed_signing",
            "customer_signing_key_id",
            "local_only_execution",
        }
        if set(config) != allowed_keys:
            raise SubscriberError(422, "governance_config_shape_invalid")
        allowed_policy_ids = config["allowed_policy_ids"]
        if not isinstance(allowed_policy_ids, list) or any(
            not isinstance(value, str) or not value for value in allowed_policy_ids
        ):
            raise SubscriberError(422, "governance_policy_ids_invalid")
        retention_days = config["retention_days"]
        if isinstance(retention_days, bool) or not isinstance(retention_days, int):
            raise SubscriberError(422, "governance_retention_invalid")
        if config["report_brand_name"] is not None and (
            not isinstance(config["report_brand_name"], str)
            or not str(config["report_brand_name"]).strip()
            or len(str(config["report_brand_name"])) > 120
        ):
            raise SubscriberError(422, "governance_brand_invalid")
        if config["report_logo_url"] is not None and (
            not isinstance(config["report_logo_url"], str)
            or not str(config["report_logo_url"]).startswith("https://")
            or len(str(config["report_logo_url"])) > 2048
        ):
            raise SubscriberError(422, "governance_logo_invalid")
        for name in (
            "private_worker_only",
            "customer_managed_signing",
            "local_only_execution",
        ):
            if not isinstance(config[name], bool):
                raise SubscriberError(422, f"governance_{name}_invalid")
        customer_signing_key_id = config["customer_signing_key_id"]
        if customer_signing_key_id is not None:
            if not isinstance(customer_signing_key_id, str):
                raise SubscriberError(422, "governance_signing_key_invalid")
            try:
                require_identifier(customer_signing_key_id, "customer_signing_key_id")
            except ValueError as exc:
                raise SubscriberError(422, "governance_signing_key_invalid") from exc
        if bool(config["customer_managed_signing"]) != (
            customer_signing_key_id is not None
        ):
            raise SubscriberError(422, "governance_signing_key_required")
        now = to_utc_iso(self._now())
        encoded = canonical_json(dict(config))
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.GOVERNANCE_MANAGE
            )
            plan, _ = self._plan_for_org(connection, principal.organization_id)
            if not 1 <= retention_days <= plan.maximum_retention_days:
                raise SubscriberError(422, "retention_exceeds_plan")
            if config["private_worker_only"] and not plan.private_workers:
                raise SubscriberError(403, "private_workers_not_entitled")
            if config["report_brand_name"] is not None and not plan.white_label_reports:
                raise SubscriberError(403, "white_label_not_entitled")
            if config["customer_managed_signing"] and not plan.customer_managed_keys:
                raise SubscriberError(403, "customer_managed_keys_not_entitled")
            if config["local_only_execution"] and not plan.local_only_execution:
                raise SubscriberError(403, "local_only_execution_not_entitled")
            row = connection.execute(
                "SELECT version FROM subscriber_governance WHERE organization_id = ?",
                (principal.organization_id,),
            ).fetchone()
            if row is None:
                raise SubscriberError(503, "governance_config_missing")
            if int(row["version"]) != expected_version:
                raise SubscriberError(409, "governance_version_conflict")
            next_version = expected_version + 1
            connection.execute(
                """
                UPDATE subscriber_governance
                SET config_json = ?, config_sha256 = ?, version = ?, updated_at = ?
                WHERE organization_id = ?
                """,
                (
                    encoded,
                    sha256_bytes(encoded.encode("utf-8")),
                    next_version,
                    now,
                    principal.organization_id,
                ),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="governance.update",
                resource_type="governance",
                resource_id=principal.organization_id,
                outcome="allowed",
                details={"version": next_version, "config_sha256": sha256_bytes(encoded.encode())},
            )
        return self.governance_config(principal)

    def create_policy_pack(
        self,
        principal: SubscriberPrincipal,
        *,
        name: str,
        version: str,
        manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.require(principal, Permission.POLICY_PACK_MANAGE)
        require_identifier(version, "version")
        if not name.strip():
            raise ValueError("policy pack name is required")
        encoded = canonical_json(dict(manifest))
        if len(encoded.encode("utf-8")) > 1_000_000:
            raise SubscriberError(413, "policy_pack_too_large")
        policy_pack_id = self._new_id("ppk")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.POLICY_PACK_MANAGE
            )
            plan, _ = self._plan_for_org(connection, principal.organization_id)
            if not plan.custom_policy_packs:
                raise SubscriberError(403, "custom_policy_packs_not_entitled")
            count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_policy_packs
                    WHERE organization_id = ?
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
            if count >= plan.max_policy_packs:
                raise SubscriberError(429, "policy_pack_quota_exceeded")
            try:
                connection.execute(
                    """
                    INSERT INTO subscriber_policy_packs(
                        policy_pack_id, organization_id, name, version,
                        manifest_json, manifest_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        policy_pack_id,
                        principal.organization_id,
                        name.strip(),
                        version,
                        encoded,
                        sha256_bytes(encoded.encode("utf-8")),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SubscriberError(409, "policy_pack_version_conflict") from exc
            connection.execute(
                """
                INSERT INTO subscriber_policy_pack_events(
                    organization_id, policy_pack_id, event_type, actor_ref, created_at
                ) VALUES (?, ?, 'CREATED', ?, ?)
                """,
                (principal.organization_id, policy_pack_id, principal.user_id, now),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="policy_pack.create",
                resource_type="policy_pack",
                resource_id=policy_pack_id,
                outcome="allowed",
                details={"name": name.strip(), "version": version},
            )
        return {
            "policy_pack_id": policy_pack_id,
            "name": name.strip(),
            "version": version,
            "manifest_sha256": sha256_bytes(encoded.encode("utf-8")),
            "created_at": now,
        }

    def list_policy_packs(
        self, principal: SubscriberPrincipal
    ) -> list[dict[str, Any]]:
        self.require(principal, Permission.GOVERNANCE_READ)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT policy_pack_id, name, version, manifest_json,
                       manifest_sha256, created_at
                FROM subscriber_policy_packs
                WHERE organization_id = ?
                ORDER BY created_at, policy_pack_id
                """,
                (principal.organization_id,),
            ).fetchall()
        return [
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key != "manifest_json"
                },
                "manifest": json.loads(row["manifest_json"]),
            }
            for row in rows
        ]

    def register_private_worker(
        self,
        principal: SubscriberPrincipal,
        *,
        display_name: str,
        attestation_sha256: str,
    ) -> dict[str, Any]:
        self.require(principal, Permission.PRIVATE_WORKER_MANAGE)
        if not display_name.strip() or len(attestation_sha256) != 64:
            raise ValueError("worker display name and SHA-256 attestation are required")
        int(attestation_sha256, 16)
        worker_id = self._new_id("wrk")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.PRIVATE_WORKER_MANAGE
            )
            plan, _ = self._plan_for_org(connection, principal.organization_id)
            if not plan.private_workers:
                raise SubscriberError(403, "private_workers_not_entitled")
            count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_private_workers
                    WHERE organization_id = ? AND status = 'ACTIVE'
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
            if count >= plan.max_private_workers:
                raise SubscriberError(429, "private_worker_quota_exceeded")
            connection.execute(
                """
                INSERT INTO subscriber_private_workers(
                    worker_id, organization_id, display_name, attestation_sha256,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)
                """,
                (
                    worker_id,
                    principal.organization_id,
                    display_name.strip(),
                    attestation_sha256.lower(),
                    now,
                    now,
                ),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="private_worker.register",
                resource_type="private_worker",
                resource_id=worker_id,
                outcome="allowed",
                details={"attestation_sha256": attestation_sha256.lower()},
            )
        return {
            "worker_id": worker_id,
            "display_name": display_name.strip(),
            "attestation_sha256": attestation_sha256.lower(),
            "status": "ACTIVE",
            "created_at": now,
        }

    def list_private_workers(
        self, principal: SubscriberPrincipal
    ) -> list[dict[str, Any]]:
        self.require(principal, Permission.PRIVATE_WORKER_MANAGE)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT worker_id, display_name, attestation_sha256, status,
                       created_at, updated_at
                FROM subscriber_private_workers
                WHERE organization_id = ?
                ORDER BY created_at, worker_id
                """,
                (principal.organization_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def revoke_private_worker(
        self, principal: SubscriberPrincipal, worker_id: str
    ) -> None:
        self.require(principal, Permission.PRIVATE_WORKER_MANAGE)
        require_identifier(worker_id, "worker_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            self._require_with_connection(
                connection, principal, Permission.PRIVATE_WORKER_MANAGE
            )
            row = connection.execute(
                """
                SELECT status FROM subscriber_private_workers
                WHERE worker_id = ? AND organization_id = ?
                """,
                (worker_id, principal.organization_id),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "private_worker_not_found")
            if row["status"] == "REVOKED":
                return
            connection.execute(
                """
                UPDATE subscriber_private_workers
                SET status = 'REVOKED', updated_at = ?
                WHERE worker_id = ? AND organization_id = ?
                """,
                (now, worker_id, principal.organization_id),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="private_worker.revoke",
                resource_type="private_worker",
                resource_id=worker_id,
                outcome="allowed",
            )

    def _billing_period(self, subscription: sqlite3.Row) -> tuple[str, str]:
        try:
            parsed_start = parse_utc_iso(str(subscription["current_period_start"]))
            parsed_end = parse_utc_iso(str(subscription["current_period_end"]))
        except (TypeError, ValueError) as exc:
            raise SubscriberError(503, "billing_period_invalid") from exc
        if parsed_end <= parsed_start:
            raise SubscriberError(503, "billing_period_invalid")
        return to_utc_iso(parsed_start), to_utc_iso(parsed_end)

    def _transition_run_with_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        organization_id: str,
        expected_state: str,
        next_state: str,
        actor: str,
        reason: str,
        workflow_version: str,
        now: str,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE runs SET state = ?, updated_at = ?
            WHERE run_id = ? AND tenant_id = ? AND state = ?
            """,
            (next_state, now, run_id, organization_id, expected_state),
        )
        if cursor.rowcount != 1:
            raise SubscriberError(409, "worker_run_state_changed")
        connection.execute(
            """
            INSERT INTO state_events(
                run_id, tenant_id, prior_state, next_state, actor,
                reason, workflow_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                organization_id,
                expected_state,
                next_state,
                actor,
                reason,
                workflow_version,
                now,
            ),
        )

    def _compensate_crash_meter(
        self,
        connection: sqlite3.Connection,
        organization_id: str,
        idempotency_key: str,
        run_id: str,
        occurred_at: str,
        *,
        key_prefix: str = "claim-crash",
        reason: str = "expired_worker_claim_after_execution_start",
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO subscriber_usage_events(
                organization_id, meter, quantity, idempotency_key,
                metadata_json, occurred_at
            ) VALUES (?, 'certification_runs', -1, ?, ?, ?)
            """,
            (
                organization_id,
                f"{key_prefix}:{idempotency_key}",
                canonical_json(
                    {
                        "reason": reason,
                        "run_id": run_id,
                    }
                ),
                occurred_at,
            ),
        )

    def _recover_expired_claims(
        self,
        connection: sqlite3.Connection,
        organization_id: str | None,
        now: datetime,
    ) -> int:
        now_text = to_utc_iso(now)
        parameters: list[Any] = [now_text]
        organization_filter = ""
        if organization_id is not None:
            organization_filter = "AND r.organization_id = ?"
            parameters.append(organization_id)
        rows = connection.execute(
            f"""
            SELECT r.organization_id, r.idempotency_key, r.run_id, r.state,
                   runs.state AS run_state,
                   COALESCE(
                       (
                           SELECT u.occurred_at
                           FROM subscriber_usage_events u
                           WHERE u.organization_id = r.organization_id
                             AND u.meter = 'certification_runs'
                             AND u.idempotency_key = r.idempotency_key
                             AND u.quantity > 0
                           LIMIT 1
                       ),
                       r.created_at
                   ) AS metered_at
            FROM subscriber_run_reservations AS r
            JOIN runs
              ON runs.run_id = r.run_id
             AND runs.tenant_id = r.organization_id
            WHERE r.state IN ('EXECUTING', 'STARTED')
              AND r.lease_expires_at IS NOT NULL
              AND r.lease_expires_at <= ?
              {organization_filter}
            ORDER BY r.created_at, r.idempotency_key
            """,
            tuple(parameters),
        ).fetchall()
        for row in rows:
            run_state = str(row["run_state"])
            row_organization = str(row["organization_id"])
            idempotency_key = str(row["idempotency_key"])
            run_id = str(row["run_id"])
            if row["state"] == "EXECUTING" and run_state == "QUEUED":
                connection.execute(
                    """
                    UPDATE subscriber_run_reservations
                    SET state = 'BOUND', worker_id = NULL,
                        worker_attestation_sha256 = NULL,
                        execution_location = NULL, signing_authority = NULL,
                        signing_key_id = NULL, claim_token = NULL,
                        lease_expires_at = NULL, last_heartbeat_at = NULL,
                        consumed_at = NULL, updated_at = ?
                    WHERE organization_id = ? AND idempotency_key = ?
                      AND state = 'EXECUTING'
                    """,
                    (now_text, row_organization, idempotency_key),
                )
                connection.execute(
                    """
                    UPDATE subscriber_run_dispatches
                    SET state = 'PENDING', claim_token = NULL,
                        lease_owner = NULL, lease_expires_at = NULL,
                        last_error = 'expired_pre_start_claim_requeued',
                        updated_at = ?
                    WHERE run_id = ? AND state = 'CLAIMED'
                    """,
                    (now_text, run_id),
                )
                outcome = "requeued"
                compensated = False
            else:
                if run_state not in _TERMINAL_RUN_STATES:
                    self._transition_run_with_connection(
                        connection,
                        run_id,
                        row_organization,
                        run_state,
                        "INFRASTRUCTURE_FAILURE",
                        "certforge.claim-recovery",
                        "worker_claim_lease_expired",
                        "p7.subscriber",
                        now_text,
                    )
                    connection.execute(
                        """
                        UPDATE runs SET run_outcome = 'INFRA_FAILED', updated_at = ?
                        WHERE run_id = ? AND tenant_id = ?
                        """,
                        (now_text, run_id, row_organization),
                    )
                    run_state = "INFRASTRUCTURE_FAILURE"
                connection.execute(
                    """
                    UPDATE subscriber_run_reservations
                    SET state = 'RELEASED', claim_token = NULL,
                        lease_expires_at = NULL, updated_at = ?
                    WHERE organization_id = ? AND idempotency_key = ?
                      AND state IN ('EXECUTING', 'STARTED')
                    """,
                    (now_text, row_organization, idempotency_key),
                )
                dispatch_state = "COMPLETE" if run_state == "COMPLETED" else "FAILED"
                connection.execute(
                    """
                    UPDATE subscriber_run_dispatches
                    SET state = ?, claim_token = NULL, lease_owner = NULL,
                        lease_expires_at = NULL, last_error = ?,
                        updated_at = ?
                    WHERE run_id = ? AND state IN ('PENDING', 'CLAIMED')
                    """,
                    (
                        dispatch_state,
                        None if dispatch_state == "COMPLETE" else "worker_claim_lease_expired",
                        now_text,
                        run_id,
                    ),
                )
                compensated = run_state != "COMPLETED"
                if compensated:
                    self._compensate_crash_meter(
                        connection,
                        row_organization,
                        idempotency_key,
                        run_id,
                        str(row["metered_at"]),
                    )
                outcome = "terminalized"
            self._append_audit(
                connection,
                organization_id=row_organization,
                actor_ref="certforge.claim-recovery",
                action="certification.worker_claim_recovered",
                resource_type="certification",
                resource_id=run_id,
                outcome="allowed",
                details={
                    "recovery": outcome,
                    "prior_claim_state": str(row["state"]),
                    "run_state": run_state,
                    "meter_compensated": compensated,
                },
            )
        return len(rows)

    def recover_expired_claims(self, organization_id: str | None = None) -> int:
        if organization_id is not None:
            require_identifier(organization_id, "organization_id")
        with self._connection(immediate=True) as connection:
            return self._recover_expired_claims(
                connection, organization_id, self._now()
            )

    def _reconcile_run_reservations(
        self, connection: sqlite3.Connection, organization_id: str, now: str
    ) -> None:
        runs_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
        ).fetchone()
        if runs_table is None:
            raise SubscriberError(503, "certification_store_unavailable")
        cutoff = to_utc_iso(
            parse_utc_iso(now)
            - timedelta(seconds=self.policy.reservation_ttl_seconds)
        )
        stale = connection.execute(
            """
            SELECT r.idempotency_key, r.request_digest, r.run_id, r.created_at,
                   (
                       SELECT u.occurred_at
                       FROM subscriber_usage_events u
                       WHERE u.organization_id = r.organization_id
                         AND u.meter = 'certification_runs'
                         AND u.idempotency_key = r.idempotency_key
                         AND u.quantity > 0
                       LIMIT 1
                   ) AS metered_at
            FROM subscriber_run_reservations r
            WHERE r.organization_id = ?
              AND r.state IN ('RESERVED', 'BOUND')
              AND r.created_at <= ?
              AND (
                  r.run_id IS NULL
                  OR NOT EXISTS (
                      SELECT 1 FROM runs
                      WHERE runs.run_id = r.run_id AND runs.tenant_id = r.organization_id
                  )
              )
            ORDER BY created_at, idempotency_key
            """,
            (organization_id, cutoff),
        ).fetchall()
        for row in stale:
            idempotency_key = str(row["idempotency_key"])
            connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'RELEASED', updated_at = ?
                WHERE organization_id = ? AND idempotency_key = ?
                  AND state IN ('RESERVED', 'BOUND')
                """,
                (now, organization_id, idempotency_key),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO subscriber_usage_events(
                    organization_id, meter, quantity, idempotency_key,
                    metadata_json, occurred_at
                ) VALUES (?, 'certification_runs', -1, ?, ?, ?)
                """,
                (
                    organization_id,
                    f"stale-release:{idempotency_key}",
                    canonical_json(
                        {
                            "reason": "stale_run_reservation",
                            "request_digest": row["request_digest"],
                            "run_id": row["run_id"],
                        }
                    ),
                    row["metered_at"] or row["created_at"],
                ),
            )
            self._append_audit(
                connection,
                organization_id=organization_id,
                actor_ref="certforge.reconciler",
                action="certification.release",
                resource_type="reservation",
                resource_id=sha256_bytes(idempotency_key.encode())[:32],
                outcome="allowed",
                details={
                    "reason": "stale_run_reservation",
                    "meter_compensated": True,
                },
            )
        connection.execute(
            f"""
            UPDATE subscriber_run_reservations
            SET state = 'RELEASED', updated_at = ?
            WHERE organization_id = ? AND state IN ('BOUND', 'EXECUTING', 'STARTED') AND run_id IN (
                SELECT run_id FROM runs WHERE tenant_id = ? AND state IN ({",".join("?" for _ in _TERMINAL_RUN_STATES)})
            )
            """,
            (now, organization_id, organization_id, *_TERMINAL_RUN_STATES),
        )

    def reserve_certification_run(
        self,
        principal: SubscriberPrincipal,
        *,
        project_id: str,
        idempotency_key: str,
        request_digest: str,
        policy_version: str,
        target_type: str | None = None,
        target_reference: str | None = None,
        target_identity_digest: str | None = None,
        dispatch_target_spec: Mapping[str, Any] | None = None,
        journey: list[str] | None = None,
        submit_request: Mapping[str, Any] | None = None,
    ) -> RunReservation:
        self.require(principal, Permission.RUN_CREATE)
        self.get_project(principal, project_id, required_status="ACTIVE")
        if target_type is not None:
            require_identifier(target_type, "target_type")
        if target_reference is not None and not target_reference.strip():
            raise ValueError("target_reference is required")
        if target_identity_digest is not None:
            require_sha256(target_identity_digest, "target_identity_digest")
        dispatch_target_json = (
            canonical_json(dict(dispatch_target_spec))
            if dispatch_target_spec is not None
            else None
        )
        dispatch_journey_json = (
            canonical_json(journey) if journey is not None else None
        )
        submit_request_json = (
            canonical_json(dict(submit_request)) if submit_request is not None else None
        )
        if (dispatch_target_json is None) != (submit_request_json is None):
            raise ValueError(
                "dispatch_target_spec and submit_request must be supplied together"
            )
        now = self._now()
        now_text = to_utc_iso(now)
        with self._connection(immediate=True) as connection:
            self._require_with_connection(connection, principal, Permission.RUN_CREATE)
            project = connection.execute(
                """
                SELECT status FROM subscriber_projects
                WHERE organization_id = ? AND project_id = ?
                """,
                (principal.organization_id, project_id),
            ).fetchone()
            if project is None:
                raise SubscriberError(404, "project_not_found")
            if project["status"] != "ACTIVE":
                raise SubscriberError(409, "project_not_active")
            governance = connection.execute(
                "SELECT config_json FROM subscriber_governance WHERE organization_id = ?",
                (principal.organization_id,),
            ).fetchone()
            if governance is None:
                raise SubscriberError(503, "governance_config_missing")
            config = json.loads(governance["config_json"])
            allowed_policies = config["allowed_policy_ids"]
            if allowed_policies and policy_version not in allowed_policies:
                raise SubscriberError(403, "policy_not_allowed")
            existing = connection.execute(
                """
                SELECT request_digest, state, project_id, policy_version, target_type,
                       target_reference, target_identity_digest,
                       dispatch_target_json, dispatch_journey_json, submit_request_json
                FROM subscriber_run_reservations
                WHERE organization_id = ? AND idempotency_key = ?
                """,
                (principal.organization_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise SubscriberError(409, "idempotency_conflict")
                expected_binding = (
                    project_id,
                    policy_version,
                    target_type,
                    target_reference,
                    target_identity_digest,
                )
                actual_binding = (
                    existing["project_id"],
                    existing["policy_version"],
                    existing["target_type"],
                    existing["target_reference"],
                    existing["target_identity_digest"],
                )
                if all(item is not None for item in expected_binding) and actual_binding != expected_binding:
                    raise SubscriberError(409, "run_reservation_binding_conflict")
                expected_dispatch = (
                    dispatch_target_json,
                    dispatch_journey_json,
                    submit_request_json,
                )
                actual_dispatch = (
                    existing["dispatch_target_json"],
                    existing["dispatch_journey_json"],
                    existing["submit_request_json"],
                )
                if dispatch_target_json is not None and actual_dispatch != expected_dispatch:
                    raise SubscriberError(409, "run_dispatch_binding_conflict")
                return RunReservation(
                    principal.organization_id,
                    idempotency_key,
                    request_digest,
                    False,
                    project_id,
                    policy_version,
                    target_type,
                    target_reference,
                    target_identity_digest,
                )
            plan, subscription = self._plan_for_org(connection, principal.organization_id)
            if OrganizationStatus(str(subscription["organization_status"])) not in {
                OrganizationStatus.TRIALING,
                OrganizationStatus.ACTIVE,
            }:
                raise SubscriberError(402, "subscription_not_writable")
            period_start, period_end = self._billing_period(subscription)
            if not parse_utc_iso(period_start) <= now < parse_utc_iso(period_end):
                raise SubscriberError(402, "subscription_period_inactive")
            self._reconcile_run_reservations(connection, principal.organization_id, now_text)
            active = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_run_reservations
                    WHERE organization_id = ? AND state IN ('RESERVED', 'BOUND', 'EXECUTING', 'STARTED')
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
            if active >= plan.concurrent_runs:
                raise SubscriberError(429, "concurrent_run_quota_exceeded")
            used = int(
                connection.execute(
                    """
                    SELECT COALESCE(SUM(quantity), 0) FROM subscriber_usage_events
                    WHERE organization_id = ? AND meter = 'certification_runs'
                      AND occurred_at >= ? AND occurred_at < ?
                    """,
                    (principal.organization_id, period_start, period_end),
                ).fetchone()[0]
            )
            if used >= plan.monthly_certification_runs:
                raise SubscriberError(429, "monthly_run_quota_exceeded")
            connection.execute(
                """
                INSERT INTO subscriber_run_reservations(
                    organization_id, idempotency_key, request_digest,
                    project_id, policy_version, target_type, target_reference,
                    target_identity_digest, dispatch_target_json,
                    dispatch_journey_json, submit_request_json,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?)
                """,
                (
                    principal.organization_id,
                    idempotency_key,
                    request_digest,
                    project_id,
                    policy_version,
                    target_type,
                    target_reference,
                    target_identity_digest,
                    dispatch_target_json,
                    dispatch_journey_json,
                    submit_request_json,
                    now_text,
                    now_text,
                ),
            )
            connection.execute(
                """
                INSERT INTO subscriber_usage_events(
                    organization_id, meter, quantity, idempotency_key,
                    metadata_json, occurred_at
                ) VALUES (?, 'certification_runs', 1, ?, ?, ?)
                """,
                (
                    principal.organization_id,
                    idempotency_key,
                    canonical_json({"project_id": project_id, "policy_version": policy_version}),
                    now_text,
                ),
            )
            self._append_audit(
                connection,
                organization_id=principal.organization_id,
                actor_ref=principal.user_id,
                action="certification.reserve",
                resource_type="project",
                resource_id=project_id,
                outcome="allowed",
                details={"idempotency_key_sha256": sha256_bytes(idempotency_key.encode())},
            )
            return RunReservation(
                principal.organization_id,
                idempotency_key,
                request_digest,
                True,
                project_id,
                policy_version,
                target_type,
                target_reference,
                target_identity_digest,
            )

    def rerun_dispatch_template(
        self, principal: SubscriberPrincipal, run_id: str
    ) -> tuple[dict[str, Any], list[str] | None]:
        """Return the exact tenant-owned dispatch contract for a governed rerun."""
        require_identifier(run_id, "run_id")
        self.require(principal, Permission.RUN_CREATE)
        with self._connection() as connection:
            self._require_with_connection(connection, principal, Permission.RUN_CREATE)
            row = connection.execute(
                """
                SELECT d.target_json, d.journey_json
                FROM subscriber_run_dispatches d
                JOIN runs r ON r.run_id = d.run_id
                WHERE d.run_id = ? AND d.organization_id = ? AND r.tenant_id = ?
                """,
                (run_id, principal.organization_id, principal.organization_id),
            ).fetchone()
        if row is None:
            raise SubscriberError(409, "source_run_not_rerunnable")
        try:
            target = json.loads(str(row["target_json"]))
            journey = (
                json.loads(str(row["journey_json"]))
                if row["journey_json"] is not None
                else None
            )
        except json.JSONDecodeError as exc:
            raise SubscriberError(503, "source_dispatch_invalid") from exc
        if not isinstance(target, dict) or (
            journey is not None and not isinstance(journey, list)
        ):
            raise SubscriberError(503, "source_dispatch_invalid")
        return target, journey

    def pending_intake_requests(self, limit: int = 100) -> list[PendingSubscriberIntake]:
        if limit <= 0 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT organization_id, idempotency_key, request_digest,
                       project_id, policy_version, target_type, target_reference,
                       target_identity_digest, dispatch_target_json,
                       dispatch_journey_json, submit_request_json
                FROM subscriber_run_reservations
                WHERE state = 'RESERVED'
                  AND dispatch_target_json IS NOT NULL
                  AND submit_request_json IS NOT NULL
                ORDER BY created_at, idempotency_key
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        pending: list[PendingSubscriberIntake] = []
        for row in rows:
            try:
                target_spec = json.loads(str(row["dispatch_target_json"]))
                request = json.loads(str(row["submit_request_json"]))
                journey = (
                    json.loads(str(row["dispatch_journey_json"]))
                    if row["dispatch_journey_json"] is not None
                    else None
                )
            except json.JSONDecodeError as exc:
                raise SubscriberError(503, "pending_intake_invalid") from exc
            if not isinstance(target_spec, dict) or not isinstance(request, dict):
                raise SubscriberError(503, "pending_intake_invalid")
            if journey is not None and not isinstance(journey, list):
                raise SubscriberError(503, "pending_intake_invalid")
            pending.append(
                PendingSubscriberIntake(
                    reservation=RunReservation(
                        organization_id=str(row["organization_id"]),
                        idempotency_key=str(row["idempotency_key"]),
                        request_digest=str(row["request_digest"]),
                        created=False,
                        project_id=str(row["project_id"]),
                        policy_version=str(row["policy_version"]),
                        target_type=str(row["target_type"]),
                        target_reference=str(row["target_reference"]),
                        target_identity_digest=str(row["target_identity_digest"]),
                    ),
                    request=request,
                    target_spec=target_spec,
                    journey=journey,
                )
            )
        return pending

    def materialize_reserved_run(
        self,
        reservation: RunReservation,
        *,
        run_id: str,
        target_type: str,
        target_reference: str,
        target_identity_digest: str,
        environment_identity_digest: str,
        environment_json: Mapping[str, Any],
        manifest_id: str,
        manifest_digest: str,
        target_spec: Mapping[str, Any],
        journey: list[str] | None,
        source_run_id: str | None = None,
    ) -> bool:
        require_identifier(run_id, "run_id")
        require_identifier(target_type, "target_type")
        require_identifier(manifest_id, "manifest_id")
        require_sha256(target_identity_digest, "target_identity_digest")
        require_sha256(environment_identity_digest, "environment_identity_digest")
        require_sha256(manifest_digest, "manifest_digest")
        if source_run_id is not None:
            require_identifier(source_run_id, "source_run_id")
        if reservation.policy_version != manifest_id:
            raise SubscriberError(422, "policy_unknown")
        if not target_reference.strip():
            raise ValueError("target_reference is required")
        now = to_utc_iso(self._now())
        target_identity_json = canonical_json(
            {
                "tenant_id": reservation.organization_id,
                "target_type": target_type,
                "declared_identity_digest": target_identity_digest,
                "reference": target_reference,
            }
        )
        environment_identity_json = canonical_json(dict(environment_json))
        target_json = canonical_json(dict(target_spec))
        journey_json = canonical_json(journey) if journey is not None else None
        created = False
        terminal_error: SubscriberError | None = None
        with self._connection(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT r.state, r.run_id, r.project_id, r.policy_version,
                       r.target_type, r.target_reference, r.target_identity_digest,
                       p.status AS project_status, o.status AS organization_status,
                       s.status AS subscription_status
                FROM subscriber_run_reservations AS r
                INNER JOIN subscriber_projects AS p
                    ON p.organization_id = r.organization_id
                   AND p.project_id = r.project_id
                INNER JOIN subscriber_organizations AS o
                    ON o.organization_id = r.organization_id
                INNER JOIN subscriber_subscriptions AS s
                    ON s.organization_id = r.organization_id
                WHERE r.organization_id = ? AND r.idempotency_key = ?
                  AND r.request_digest = ?
                """,
                (
                    reservation.organization_id,
                    reservation.idempotency_key,
                    reservation.request_digest,
                ),
            ).fetchone()
            existing_run = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise SubscriberError(409, "run_reservation_binding_missing")
            terminal_replay = bool(
                row["state"] == "RELEASED"
                and row["run_id"] == run_id
                and existing_run is not None
                and existing_run["state"] in _TERMINAL_RUN_STATES
            )
            active = terminal_replay or (
                row["state"] in {"RESERVED", "BOUND"}
                and row["project_status"] == "ACTIVE"
                and row["organization_status"] in {"TRIALING", "ACTIVE"}
                and row["subscription_status"] in {"TRIALING", "ACTIVE"}
            )
            if not active:
                if (
                    existing_run is not None
                    and existing_run["tenant_id"] == reservation.organization_id
                    and existing_run["state"] in {"CREATED", "QUEUED"}
                ):
                    self._transition_run_with_connection(
                        connection,
                        run_id,
                        reservation.organization_id,
                        str(existing_run["state"]),
                        "CANCELLED",
                        "certforge.intake",
                        "reservation_inactive_before_binding",
                        "p7.subscriber",
                        now,
                    )
                    connection.execute(
                        """
                        UPDATE runs SET run_outcome = 'CANCELLED', updated_at = ?
                        WHERE run_id = ? AND tenant_id = ?
                        """,
                        (now, run_id, reservation.organization_id),
                    )
                terminal_error = SubscriberError(409, "run_reservation_inactive")
            else:
                expected_binding = (
                    reservation.project_id,
                    reservation.policy_version,
                    target_type,
                    target_reference,
                    target_identity_digest,
                )
                actual_binding = (
                    row["project_id"],
                    row["policy_version"],
                    row["target_type"],
                    row["target_reference"],
                    row["target_identity_digest"],
                )
                if actual_binding != expected_binding:
                    raise SubscriberError(409, "run_reservation_binding_conflict")
                if existing_run is None:
                    rerun_sequence: int | None = None
                    if source_run_id is not None:
                        source = connection.execute(
                            "SELECT tenant_id, state FROM runs WHERE run_id = ?",
                            (source_run_id,),
                        ).fetchone()
                        if (
                            source is None
                            or source["tenant_id"] != reservation.organization_id
                            or source["state"] not in _TERMINAL_RUN_STATES
                        ):
                            raise SubscriberError(409, "source_run_not_terminal")
                        rerun_sequence = int(
                            connection.execute(
                                "SELECT COALESCE(MAX(rerun_sequence), 0) + 1 AS sequence "
                                "FROM runs WHERE tenant_id = ? AND source_run_id = ?",
                                (reservation.organization_id, source_run_id),
                            ).fetchone()["sequence"]
                        )
                    connection.execute(
                        """
                        INSERT INTO runs(
                            run_id, tenant_id, target_identity_json,
                            target_identity_digest, environment_identity_json,
                            environment_identity_digest, rule_manifest_id,
                            rule_manifest_digest, run_outcome, state, created_at,
                            updated_at, policy_version, target_reference, project_id,
                            source_run_id, rerun_sequence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'INCONCLUSIVE',
                                  'CREATED', ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            reservation.organization_id,
                            target_identity_json,
                            target_identity_digest,
                            environment_identity_json,
                            environment_identity_digest,
                            manifest_id,
                            manifest_digest,
                            now,
                            now,
                            reservation.policy_version,
                            target_reference,
                            reservation.project_id,
                            source_run_id,
                            rerun_sequence,
                        ),
                    )
                    existing_run = connection.execute(
                        "SELECT * FROM runs WHERE run_id = ?",
                        (run_id,),
                    ).fetchone()
                    created = True
                expected_run = (
                    reservation.organization_id,
                    reservation.project_id,
                    reservation.policy_version,
                    target_type,
                    target_reference,
                    target_identity_digest,
                    environment_identity_digest,
                    manifest_id,
                    manifest_digest,
                    source_run_id,
                )
                actual_run = (
                    existing_run["tenant_id"],
                    existing_run["project_id"],
                    existing_run["policy_version"],
                    json.loads(existing_run["target_identity_json"]).get(
                        "target_type"
                    ),
                    existing_run["target_reference"],
                    existing_run["target_identity_digest"],
                    existing_run["environment_identity_digest"],
                    existing_run["rule_manifest_id"],
                    existing_run["rule_manifest_digest"],
                    existing_run["source_run_id"],
                )
                if actual_run != expected_run:
                    raise SubscriberError(409, "run_materialization_conflict")
                if existing_run["state"] == "CREATED":
                    self._transition_run_with_connection(
                        connection,
                        run_id,
                        reservation.organization_id,
                        "CREATED",
                        "QUEUED",
                        "certforge.intake",
                        "accepted",
                        "p7.subscriber",
                        now,
                    )
                elif existing_run["state"] != "QUEUED":
                    if not (
                        row["state"] == "BOUND"
                        and row["run_id"] == run_id
                        and existing_run["state"] in _TERMINAL_RUN_STATES
                    ):
                        raise SubscriberError(409, "run_materialization_state_conflict")
                idempotency = connection.execute(
                    """
                    SELECT request_digest, run_id FROM idempotency_keys
                    WHERE tenant_id = ? AND idempotency_key = ?
                    """,
                    (reservation.organization_id, reservation.idempotency_key),
                ).fetchone()
                if idempotency is None:
                    connection.execute(
                        """
                        INSERT INTO idempotency_keys(
                            tenant_id, idempotency_key, request_digest,
                            run_id, created_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            reservation.organization_id,
                            reservation.idempotency_key,
                            reservation.request_digest,
                            run_id,
                            now,
                        ),
                    )
                elif (
                    idempotency["request_digest"] != reservation.request_digest
                    or idempotency["run_id"] != run_id
                ):
                    raise SubscriberError(409, "idempotency_conflict")
                if not terminal_replay:
                    cursor = connection.execute(
                        """
                        UPDATE subscriber_run_reservations
                        SET run_id = ?, state = 'BOUND', updated_at = ?
                        WHERE organization_id = ? AND idempotency_key = ?
                          AND request_digest = ? AND state IN ('RESERVED', 'BOUND')
                          AND (run_id IS NULL OR run_id = ?)
                        """,
                        (
                            run_id,
                            now,
                            reservation.organization_id,
                            reservation.idempotency_key,
                            reservation.request_digest,
                            run_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise SubscriberError(409, "run_reservation_conflict")
                dispatch = connection.execute(
                    """
                    SELECT target_json, journey_json
                    FROM subscriber_run_dispatches WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
                if dispatch is None and not terminal_replay:
                    connection.execute(
                        """
                        INSERT INTO subscriber_run_dispatches(
                            run_id, organization_id, idempotency_key,
                            target_json, journey_json, state, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
                        """,
                        (
                            run_id,
                            reservation.organization_id,
                            reservation.idempotency_key,
                            target_json,
                            journey_json,
                            now,
                            now,
                        ),
                    )
                elif (
                    dispatch["target_json"] != target_json
                    or dispatch["journey_json"] != journey_json
                ):
                    raise SubscriberError(409, "run_dispatch_binding_conflict")
                self._append_audit(
                    connection,
                    organization_id=reservation.organization_id,
                    actor_ref="certforge.intake",
                    action="certification.materialize",
                    resource_type="certification",
                    resource_id=run_id,
                    outcome="allowed",
                    details={"created": created},
                )
        if terminal_error is not None:
            raise terminal_error
        return created

    def bind_run(
        self,
        reservation: RunReservation,
        run_id: str,
        *,
        target_spec: Mapping[str, Any],
        journey: list[str] | None,
    ) -> None:
        require_identifier(run_id, "run_id")
        target_json = canonical_json(dict(target_spec))
        journey_json = canonical_json(journey) if journey is not None else None
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            binding = connection.execute(
                """
                SELECT r.project_id, r.policy_version, r.target_type, r.target_reference,
                       r.target_identity_digest, r.run_id, r.state,
                       p.status AS project_status, x.tenant_id, x.project_id AS run_project_id,
                       x.policy_version AS run_policy_version,
                       json_extract(x.target_identity_json, '$.target_type') AS run_target_type,
                       x.target_reference AS run_target_reference,
                       x.target_identity_digest AS run_target_identity_digest,
                       x.state AS run_state
                FROM subscriber_run_reservations r
                JOIN subscriber_projects p
                  ON p.organization_id = r.organization_id
                 AND p.project_id = r.project_id
                JOIN runs x ON x.run_id = ?
                WHERE r.organization_id = ? AND r.idempotency_key = ?
                  AND r.request_digest = ?
                """,
                (
                    run_id,
                    reservation.organization_id,
                    reservation.idempotency_key,
                    reservation.request_digest,
                ),
            ).fetchone()
            if binding is None:
                raise SubscriberError(409, "run_reservation_binding_missing")
            if any(
                binding[field] is None
                for field in (
                    "project_id",
                    "policy_version",
                    "target_type",
                    "target_reference",
                    "target_identity_digest",
                )
            ):
                raise SubscriberError(409, "run_reservation_binding_incomplete")
            persisted_binding = (
                binding["tenant_id"],
                binding["run_project_id"],
                binding["run_policy_version"],
                binding["run_target_type"],
                binding["run_target_reference"],
                binding["run_target_identity_digest"],
            )
            reservation_binding = (
                reservation.organization_id,
                binding["project_id"],
                binding["policy_version"],
                binding["target_type"],
                binding["target_reference"],
                binding["target_identity_digest"],
            )
            if persisted_binding != reservation_binding:
                raise SubscriberError(409, "run_reservation_binding_conflict")
            if (
                binding["run_id"] == run_id
                and binding["state"] in {"BOUND", "EXECUTING", "STARTED", "RELEASED"}
            ):
                dispatch = connection.execute(
                    """
                    SELECT target_json, journey_json
                    FROM subscriber_run_dispatches WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
                if dispatch is None and binding["state"] == "BOUND":
                    connection.execute(
                        """
                        INSERT INTO subscriber_run_dispatches(
                            run_id, organization_id, idempotency_key,
                            target_json, journey_json, state, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
                        """,
                        (
                            run_id,
                            reservation.organization_id,
                            reservation.idempotency_key,
                            target_json,
                            journey_json,
                            now,
                            now,
                        ),
                    )
                elif dispatch is not None and (
                    dispatch["target_json"] != target_json
                    or dispatch["journey_json"] != journey_json
                ):
                    raise SubscriberError(409, "run_dispatch_binding_conflict")
                return
            expected = (
                reservation.organization_id,
                binding["project_id"],
                binding["policy_version"],
                binding["target_type"],
                binding["target_reference"],
                binding["target_identity_digest"],
                "QUEUED",
                "ACTIVE",
            )
            actual = (
                *persisted_binding,
                binding["run_state"],
                binding["project_status"],
            )
            if actual != expected:
                raise SubscriberError(409, "run_reservation_binding_conflict")
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET run_id = ?, state = 'BOUND', updated_at = ?
                WHERE organization_id = ? AND idempotency_key = ?
                  AND request_digest = ? AND state IN ('RESERVED', 'BOUND')
                  AND (run_id IS NULL OR run_id = ?)
                """,
                (
                    run_id,
                    now,
                    reservation.organization_id,
                    reservation.idempotency_key,
                    reservation.request_digest,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "run_reservation_conflict")
            connection.execute(
                """
                INSERT INTO subscriber_run_dispatches(
                    run_id, organization_id, idempotency_key,
                    target_json, journey_json, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (
                    run_id,
                    reservation.organization_id,
                    reservation.idempotency_key,
                    target_json,
                    journey_json,
                    now,
                    now,
                ),
            )
            self._append_audit(
                connection,
                organization_id=reservation.organization_id,
                actor_ref="certforge.intake",
                action="certification.bind",
                resource_type="certification",
                resource_id=run_id,
                outcome="allowed",
            )

    def _recover_expired_dispatches(
        self, connection: sqlite3.Connection, now: datetime
    ) -> int:
        now_text = to_utc_iso(now)
        terminalized = connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET state = CASE
                    WHEN (
                        SELECT state FROM runs
                        WHERE runs.run_id = subscriber_run_dispatches.run_id
                          AND runs.tenant_id =
                              subscriber_run_dispatches.organization_id
                    ) = 'COMPLETED'
                    THEN 'COMPLETE'
                    ELSE 'FAILED'
                END,
                claim_token = NULL, lease_owner = NULL, lease_expires_at = NULL,
                last_error = CASE
                    WHEN (
                        SELECT state FROM runs
                        WHERE runs.run_id = subscriber_run_dispatches.run_id
                          AND runs.tenant_id =
                              subscriber_run_dispatches.organization_id
                    ) = 'COMPLETED'
                    THEN NULL
                    ELSE 'worker_terminal_state'
                END,
                updated_at = ?
            WHERE state = 'CLAIMED'
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at <= ?
              AND EXISTS (
                  SELECT 1 FROM runs
                  WHERE runs.run_id = subscriber_run_dispatches.run_id
                    AND runs.tenant_id =
                        subscriber_run_dispatches.organization_id
                    AND runs.state IN (
                        'COMPLETED', 'CANCELLED', 'INFRASTRUCTURE_FAILURE'
                    )
              )
            """,
            (now_text, now_text),
        ).rowcount
        rows = connection.execute(
            """
            SELECT d.run_id, d.organization_id, d.idempotency_key, d.attempts,
                   COALESCE(
                       (
                           SELECT u.occurred_at
                           FROM subscriber_usage_events u
                           WHERE u.organization_id = d.organization_id
                             AND u.meter = 'certification_runs'
                             AND u.idempotency_key = d.idempotency_key
                             AND u.quantity > 0
                           LIMIT 1
                       ),
                       d.created_at
                   ) AS metered_at
            FROM subscriber_run_dispatches AS d
            JOIN subscriber_run_reservations AS r
              ON r.run_id = d.run_id
             AND r.organization_id = d.organization_id
            JOIN runs
              ON runs.run_id = d.run_id
             AND runs.tenant_id = d.organization_id
            WHERE d.state = 'CLAIMED'
              AND d.lease_expires_at IS NOT NULL
              AND d.lease_expires_at <= ?
              AND r.state = 'BOUND'
              AND runs.state = 'QUEUED'
            """,
            (now_text,),
        ).fetchall()
        for row in rows:
            if int(row["attempts"]) >= self.policy.max_dispatch_attempts:
                self._transition_run_with_connection(
                    connection,
                    str(row["run_id"]),
                    str(row["organization_id"]),
                    "QUEUED",
                    "INFRASTRUCTURE_FAILURE",
                    "certforge.dispatch-recovery",
                    "dispatch_attempts_exhausted",
                    "p7.subscriber",
                    now_text,
                )
                connection.execute(
                    """
                    UPDATE runs SET run_outcome = 'INFRA_FAILED', updated_at = ?
                    WHERE run_id = ? AND tenant_id = ?
                    """,
                    (now_text, row["run_id"], row["organization_id"]),
                )
                connection.execute(
                    """
                    UPDATE subscriber_run_reservations
                    SET state = 'RELEASED', updated_at = ?
                    WHERE run_id = ? AND organization_id = ? AND state = 'BOUND'
                    """,
                    (now_text, row["run_id"], row["organization_id"]),
                )
                self._compensate_crash_meter(
                    connection,
                    str(row["organization_id"]),
                    str(row["idempotency_key"]),
                    str(row["run_id"]),
                    str(row["metered_at"]),
                    key_prefix="dispatch-crash",
                    reason="dispatch_attempts_exhausted_before_execution_start",
                )
                next_state = "FAILED"
                error = "dispatch_attempts_exhausted"
            else:
                next_state = "PENDING"
                error = "dispatch_lease_expired"
            connection.execute(
                """
                UPDATE subscriber_run_dispatches
                SET state = ?, claim_token = NULL, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = ?, updated_at = ?
                WHERE run_id = ? AND state = 'CLAIMED'
                """,
                (next_state, error, now_text, row["run_id"]),
            )
            self._append_audit(
                connection,
                organization_id=str(row["organization_id"]),
                actor_ref="certforge.dispatch-recovery",
                action="certification.dispatch_recovered",
                resource_type="certification",
                resource_id=str(row["run_id"]),
                outcome="allowed",
                details={
                    "recovery": next_state.lower(),
                    "attempts": int(row["attempts"]),
                    "meter_compensated": next_state == "FAILED",
                },
            )
        return terminalized + len(rows)

    def claim_dispatch(
        self,
        dispatcher_id: str,
        *,
        run_id: str | None = None,
        organization_id: str | None = None,
        worker_id: str | None = None,
        worker_attestation_sha256: str | None = None,
        execution_location: str = "local",
        signing_authority: str = "platform",
        signing_key_id: str | None = None,
    ) -> SubscriberDispatch | None:
        require_identifier(dispatcher_id, "dispatcher_id")
        if run_id is not None:
            require_identifier(run_id, "run_id")
        if organization_id is not None:
            require_identifier(organization_id, "organization_id")
        now_value = self._now()
        now = to_utc_iso(now_value)
        lease_expires_at = to_utc_iso(
            now_value + timedelta(seconds=self.policy.dispatch_claim_lease_seconds)
        )
        claim_token = secrets.token_urlsafe(24)
        with self._connection(immediate=True) as connection:
            self._recover_expired_claims(connection, organization_id, now_value)
            self._recover_expired_dispatches(connection, now_value)
            filters = ["d.state = 'PENDING'", "r.state = 'BOUND'", "runs.state = 'QUEUED'"]
            parameters: list[Any] = []
            if run_id is not None:
                filters.append("d.run_id = ?")
                parameters.append(run_id)
            if organization_id is not None:
                filters.append("d.organization_id = ?")
                parameters.append(organization_id)
            rows = connection.execute(
                f"""
                SELECT d.run_id, d.organization_id, d.idempotency_key,
                       d.target_json, d.journey_json, d.attempts
                FROM subscriber_run_dispatches AS d
                JOIN subscriber_run_reservations AS r
                  ON r.run_id = d.run_id
                 AND r.organization_id = d.organization_id
                JOIN runs
                  ON runs.run_id = d.run_id
                 AND runs.tenant_id = d.organization_id
                WHERE {' AND '.join(filters)}
                ORDER BY d.created_at, d.run_id
                """,
                tuple(parameters),
            ).fetchall()
            row = None
            for candidate in rows:
                if signing_key_id is not None:
                    target_spec = json.loads(str(candidate["target_json"]))
                    try:
                        self._resolve_worker_governance(
                            connection,
                            str(candidate["organization_id"]),
                            target_type=str(target_spec.get("type", "")),
                            worker_id=worker_id,
                            worker_attestation_sha256=worker_attestation_sha256,
                            execution_location=execution_location,
                            signing_authority=signing_authority,
                            signing_key_id=signing_key_id,
                        )
                    except (SubscriberError, TypeError, ValueError):
                        continue
                row = candidate
                break
            if row is None:
                return None
            cursor = connection.execute(
                """
                UPDATE subscriber_run_dispatches
                SET state = 'CLAIMED', attempts = attempts + 1,
                    claim_token = ?, lease_owner = ?, lease_expires_at = ?,
                    last_error = NULL, updated_at = ?
                WHERE run_id = ? AND state = 'PENDING'
                """,
                (
                    claim_token,
                    dispatcher_id,
                    lease_expires_at,
                    now,
                    row["run_id"],
                ),
            )
            if cursor.rowcount != 1:
                return None
            self._append_audit(
                connection,
                organization_id=str(row["organization_id"]),
                actor_ref=dispatcher_id,
                action="certification.dispatch_claim",
                resource_type="certification",
                resource_id=str(row["run_id"]),
                outcome="allowed",
                details={"lease_expires_at": lease_expires_at},
            )
            journey = (
                json.loads(str(row["journey_json"]))
                if row["journey_json"] is not None
                else None
            )
            return SubscriberDispatch(
                run_id=str(row["run_id"]),
                organization_id=str(row["organization_id"]),
                idempotency_key=str(row["idempotency_key"]),
                target_spec=json.loads(str(row["target_json"])),
                journey=journey,
                claim_token=claim_token,
                lease_expires_at=lease_expires_at,
                attempts=int(row["attempts"]) + 1,
            )

    def finish_dispatch(
        self,
        dispatch: SubscriberDispatch,
        *,
        error: str | None = None,
    ) -> str:
        if error is not None and not error.strip():
            raise ValueError("dispatch error must not be empty")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT d.state, d.attempts, d.idempotency_key,
                       runs.state AS run_state, r.state AS reservation_state,
                       COALESCE(
                           (
                               SELECT u.occurred_at
                               FROM subscriber_usage_events u
                               WHERE u.organization_id = d.organization_id
                                 AND u.meter = 'certification_runs'
                                 AND u.idempotency_key = d.idempotency_key
                                 AND u.quantity > 0
                               LIMIT 1
                           ),
                           d.created_at
                       ) AS metered_at
                FROM subscriber_run_dispatches AS d
                JOIN runs
                  ON runs.run_id = d.run_id
                 AND runs.tenant_id = d.organization_id
                JOIN subscriber_run_reservations AS r
                  ON r.run_id = d.run_id
                 AND r.organization_id = d.organization_id
                WHERE d.run_id = ? AND d.organization_id = ?
                  AND d.claim_token = ?
                """,
                (
                    dispatch.run_id,
                    dispatch.organization_id,
                    dispatch.claim_token,
                ),
            ).fetchone()
            if row is None:
                raise SubscriberError(409, "dispatch_claim_inactive")
            run_state = str(row["run_state"])
            if run_state == "COMPLETED":
                state = "COMPLETE"
            elif run_state in {"CANCELLED", "INFRASTRUCTURE_FAILURE"}:
                state = "FAILED"
            elif error is not None and row["reservation_state"] == "RELEASED":
                self._transition_run_with_connection(
                    connection,
                    dispatch.run_id,
                    dispatch.organization_id,
                    run_state,
                    "INFRASTRUCTURE_FAILURE",
                    "certforge.dispatcher",
                    "worker_exception_after_claim_release",
                    "p7.subscriber",
                    now,
                )
                connection.execute(
                    """
                    UPDATE runs SET run_outcome = 'INFRA_FAILED', updated_at = ?
                    WHERE run_id = ? AND tenant_id = ?
                    """,
                    (now, dispatch.run_id, dispatch.organization_id),
                )
                self._compensate_crash_meter(
                    connection,
                    dispatch.organization_id,
                    str(row["idempotency_key"]),
                    dispatch.run_id,
                    str(row["metered_at"]),
                    key_prefix="dispatch-worker-error",
                    reason="worker_exception_after_claim_release",
                )
                state = "FAILED"
            elif error is not None and int(row["attempts"]) < self.policy.max_dispatch_attempts:
                state = "PENDING"
            else:
                state = "FAILED"
            connection.execute(
                """
                UPDATE subscriber_run_dispatches
                SET state = ?, claim_token = NULL, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = ?, updated_at = ?
                WHERE run_id = ? AND organization_id = ? AND claim_token = ?
                """,
                (
                    state,
                    error,
                    now,
                    dispatch.run_id,
                    dispatch.organization_id,
                    dispatch.claim_token,
                ),
            )
            return state

    def dispatch_status(self, run_id: str, organization_id: str) -> dict[str, Any]:
        require_identifier(run_id, "run_id")
        require_identifier(organization_id, "organization_id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT run_id, organization_id, state, attempts, lease_owner,
                       lease_expires_at, last_error, created_at, updated_at
                FROM subscriber_run_dispatches
                WHERE run_id = ? AND organization_id = ?
                """,
                (run_id, organization_id),
            ).fetchone()
        if row is None:
            raise SubscriberError(404, "dispatch_not_found")
        return dict(row)

    def _resolve_worker_governance(
        self,
        connection: sqlite3.Connection,
        organization_id: str,
        *,
        target_type: str,
        worker_id: str | None,
        worker_attestation_sha256: str | None,
        execution_location: str,
        signing_authority: str,
        signing_key_id: str,
    ) -> WorkerExecutionAuthorization:
        plan, subscription = self._plan_for_org(connection, organization_id)
        status = OrganizationStatus(str(subscription["organization_status"]))
        if status not in {OrganizationStatus.TRIALING, OrganizationStatus.ACTIVE}:
            raise SubscriberError(403, "subscriber_not_entitled")
        period_start, period_end = self._billing_period(subscription)
        now = self._now()
        if not parse_utc_iso(period_start) <= now < parse_utc_iso(period_end):
            raise SubscriberError(403, "subscription_period_inactive")
        row = connection.execute(
            "SELECT config_json, version FROM subscriber_governance WHERE organization_id = ?",
            (organization_id,),
        ).fetchone()
        if row is None:
            raise SubscriberError(503, "governance_config_missing")
        try:
            config = json.loads(str(row["config_json"]))
            configured_retention = int(config["retention_days"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SubscriberError(503, "governance_config_invalid") from exc
        if configured_retention <= 0:
            raise SubscriberError(503, "governance_retention_invalid")
        retention_days = min(configured_retention, plan.maximum_retention_days)

        if bool(config.get("private_worker_only")):
            if not plan.private_workers:
                raise SubscriberError(403, "private_workers_not_entitled")
            if worker_id is None or worker_attestation_sha256 is None:
                raise SubscriberError(403, "private_worker_identity_required")
            require_identifier(worker_id, "worker_id")
            require_sha256(worker_attestation_sha256, "worker_attestation_sha256")
            worker = connection.execute(
                """
                SELECT attestation_sha256, status
                FROM subscriber_private_workers
                WHERE organization_id = ? AND worker_id = ?
                """,
                (organization_id, worker_id),
            ).fetchone()
            if (
                worker is None
                or worker["status"] != "ACTIVE"
                or not hmac.compare_digest(
                    str(worker["attestation_sha256"]),
                    worker_attestation_sha256.lower(),
                )
            ):
                raise SubscriberError(403, "private_worker_identity_invalid")

        require_identifier(execution_location, "execution_location")
        if bool(config.get("local_only_execution")):
            if not plan.local_only_execution:
                raise SubscriberError(403, "local_execution_not_entitled")
            if target_type != "local" or execution_location != "local":
                raise SubscriberError(403, "local_execution_required")

        require_identifier(signing_authority, "signing_authority")
        require_identifier(signing_key_id, "signing_key_id")
        if bool(config.get("customer_managed_signing")):
            configured_key_id = config.get("customer_signing_key_id")
            if (
                not plan.customer_managed_keys
                or signing_authority != "customer"
                or not isinstance(configured_key_id, str)
                or not configured_key_id
                or not hmac.compare_digest(configured_key_id, signing_key_id)
            ):
                raise SubscriberError(403, "customer_signing_authority_required")
        elif signing_authority != "platform":
            raise SubscriberError(403, "platform_signing_authority_required")
        return WorkerExecutionAuthorization(
            retention_days=retention_days,
            governance_version=int(row["version"]),
            subscription_version=int(subscription["version"]),
        )

    def claim_worker_run(
        self,
        *,
        run_id: str,
        organization_id: str,
        policy_version: str,
        target_type: str,
        target_reference: str,
        worker_id: str | None,
        worker_attestation_sha256: str | None,
        execution_location: str,
        signing_authority: str,
        signing_key_id: str,
    ) -> WorkerRunClaim:
        require_identifier(run_id, "run_id")
        require_identifier(organization_id, "organization_id")
        require_identifier(policy_version, "policy_version")
        require_identifier(target_type, "target_type")
        if not target_reference.strip():
            raise ValueError("target_reference is required")
        now_value = self._now()
        now = to_utc_iso(now_value)
        claim_token = secrets.token_urlsafe(24)
        lease_expires_at = to_utc_iso(
            now_value + timedelta(seconds=self.policy.worker_claim_lease_seconds)
        )
        with self._connection(immediate=True) as connection:
            self._recover_expired_claims(connection, organization_id, now_value)
            binding = connection.execute(
                """
                SELECT r.idempotency_key, r.request_digest, r.project_id,
                       r.policy_version, r.target_type, r.target_reference,
                       r.target_identity_digest, r.state,
                       x.tenant_id, x.project_id AS run_project_id,
                       x.policy_version AS run_policy_version,
                       json_extract(x.target_identity_json, '$.target_type') AS run_target_type,
                       x.target_reference AS run_target_reference,
                       x.target_identity_digest AS run_target_identity_digest,
                       x.state AS run_state, p.status AS project_status
                FROM subscriber_run_reservations r
                JOIN runs x ON x.run_id = r.run_id
                JOIN subscriber_projects p
                  ON p.organization_id = r.organization_id
                 AND p.project_id = r.project_id
                WHERE r.organization_id = ? AND r.run_id = ?
                """,
                (organization_id, run_id),
            ).fetchone()
            if binding is None:
                raise SubscriberError(409, "worker_run_reservation_missing")
            if binding["state"] != "BOUND":
                raise SubscriberError(409, "worker_run_already_claimed")
            expected = (
                "BOUND",
                organization_id,
                binding["project_id"],
                binding["policy_version"],
                binding["target_type"],
                binding["target_reference"],
                binding["target_identity_digest"],
                "QUEUED",
                "ACTIVE",
            )
            actual = (
                binding["state"],
                binding["tenant_id"],
                binding["run_project_id"],
                binding["run_policy_version"],
                binding["run_target_type"],
                binding["run_target_reference"],
                binding["run_target_identity_digest"],
                binding["run_state"],
                binding["project_status"],
            )
            if actual != expected:
                raise SubscriberError(409, "worker_run_binding_conflict")
            if binding["policy_version"] != policy_version:
                raise SubscriberError(409, "worker_policy_binding_conflict")
            if (
                binding["target_type"] != target_type
                or binding["target_reference"] != target_reference
            ):
                raise SubscriberError(409, "worker_target_binding_conflict")
            authorization = self._resolve_worker_governance(
                connection,
                organization_id,
                target_type=target_type,
                worker_id=worker_id,
                worker_attestation_sha256=worker_attestation_sha256,
                execution_location=execution_location,
                signing_authority=signing_authority,
                signing_key_id=signing_key_id,
            )
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'EXECUTING', worker_id = ?,
                    worker_attestation_sha256 = ?, execution_location = ?,
                    signing_authority = ?, signing_key_id = ?,
                    claim_token = ?, lease_expires_at = ?,
                    last_heartbeat_at = ?, consumed_at = ?, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND state = 'BOUND'
                """,
                (
                    worker_id,
                    worker_attestation_sha256.lower()
                    if worker_attestation_sha256 is not None
                    else None,
                    execution_location,
                    signing_authority,
                    signing_key_id,
                    claim_token,
                    lease_expires_at,
                    now,
                    now,
                    now,
                    organization_id,
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "worker_run_already_claimed")
            self._append_audit(
                connection,
                organization_id=organization_id,
                actor_ref=worker_id or "certforge.platform-worker",
                action="certification.worker_claim",
                resource_type="certification",
                resource_id=run_id,
                outcome="allowed",
                details={
                    "execution_location": execution_location,
                    "signing_authority": signing_authority,
                    "lease_expires_at": lease_expires_at,
                },
            )
            return WorkerRunClaim(
                organization_id=organization_id,
                run_id=run_id,
                idempotency_key=str(binding["idempotency_key"]),
                project_id=str(binding["project_id"]),
                policy_version=str(binding["policy_version"]),
                target_type=str(binding["target_type"]),
                target_reference=str(binding["target_reference"]),
                target_identity_digest=str(binding["target_identity_digest"]),
                retention_days=authorization.retention_days,
                claim_token=claim_token,
                lease_expires_at=lease_expires_at,
            )

    def authorize_worker_execution(
        self,
        claim: WorkerRunClaim,
        *,
        target_identity: Mapping[str, Any],
        target_identity_digest: str,
        environment_identity: Mapping[str, Any],
        environment_identity_digest: str,
    ) -> WorkerExecutionAuthorization:
        require_sha256(target_identity_digest, "target_identity_digest")
        require_sha256(environment_identity_digest, "environment_identity_digest")
        target_data = dict(target_identity)
        environment_data = dict(environment_identity)
        if sha256_json(target_data) != target_identity_digest:
            raise SubscriberError(409, "worker_target_identity_mismatch")
        if sha256_json(environment_data) != environment_identity_digest:
            raise SubscriberError(409, "worker_environment_identity_mismatch")
        canonical_target = canonical_json(target_data)
        canonical_environment = canonical_json(environment_data)
        now_value = self._now()
        now = to_utc_iso(now_value)
        lease_expires_at = to_utc_iso(
            now_value + timedelta(seconds=self.policy.worker_claim_lease_seconds)
        )
        with self._connection(immediate=True) as connection:
            reservation = connection.execute(
                """
                SELECT r.target_type, r.worker_id, r.worker_attestation_sha256,
                       r.execution_location, r.signing_authority, r.signing_key_id,
                       r.state, r.project_id, r.policy_version, r.target_reference,
                       r.target_identity_digest, r.claim_token, r.lease_expires_at,
                       runs.state AS run_state,
                       runs.project_id AS run_project_id,
                       runs.policy_version AS run_policy_version,
                       json_extract(
                           runs.target_identity_json, '$.target_type'
                       ) AS run_target_type,
                       runs.target_reference AS run_target_reference,
                       runs.target_identity_digest AS run_target_identity_digest,
                       runs.environment_identity_digest
                           AS run_environment_identity_digest
                FROM subscriber_run_reservations AS r
                INNER JOIN runs
                    ON runs.run_id = r.run_id
                   AND runs.tenant_id = r.organization_id
                WHERE r.organization_id = ?
                  AND r.run_id = ?
                  AND r.idempotency_key = ?
                """,
                (claim.organization_id, claim.run_id, claim.idempotency_key),
            ).fetchone()
            if reservation is None or reservation["state"] != "EXECUTING":
                raise SubscriberError(409, "worker_run_claim_inactive")
            if (
                reservation["claim_token"] is None
                or not hmac.compare_digest(
                    str(reservation["claim_token"]), claim.claim_token
                )
            ):
                raise SubscriberError(409, "worker_run_claim_token_invalid")
            if (
                reservation["lease_expires_at"] is None
                or parse_utc_iso(str(reservation["lease_expires_at"])) <= now_value
            ):
                raise SubscriberError(409, "worker_run_claim_expired")
            if reservation["run_state"] != "QUEUED":
                raise SubscriberError(409, "worker_run_not_queued")
            if (
                reservation["project_id"] != reservation["run_project_id"]
                or reservation["policy_version"] != reservation["run_policy_version"]
                or reservation["target_type"] != reservation["run_target_type"]
                or reservation["target_reference"]
                != reservation["run_target_reference"]
                or reservation["target_identity_digest"]
                != reservation["run_target_identity_digest"]
            ):
                raise SubscriberError(409, "worker_run_binding_changed")
            if (
                target_identity_digest != claim.target_identity_digest
                or target_identity_digest != reservation["target_identity_digest"]
                or target_identity_digest != reservation["run_target_identity_digest"]
                or target_identity.get("tenant_id") != claim.organization_id
                or target_identity.get("target_type") != claim.target_type
                or target_identity.get("canonical_ref") != claim.target_reference
            ):
                raise SubscriberError(409, "worker_target_identity_mismatch")
            if (
                environment_identity_digest
                != reservation["run_environment_identity_digest"]
            ):
                raise SubscriberError(409, "worker_environment_identity_mismatch")
            authorization = self._resolve_worker_governance(
                connection,
                claim.organization_id,
                target_type=str(reservation["target_type"]),
                worker_id=reservation["worker_id"],
                worker_attestation_sha256=reservation["worker_attestation_sha256"],
                execution_location=str(reservation["execution_location"]),
                signing_authority=str(reservation["signing_authority"]),
                signing_key_id=str(reservation["signing_key_id"]),
            )
            cursor = connection.execute(
                """
                UPDATE runs
                SET target_identity_json = ?, target_identity_digest = ?,
                    environment_identity_json = ?,
                    environment_identity_digest = ?, updated_at = ?
                WHERE run_id = ? AND tenant_id = ? AND state = 'QUEUED'
                  AND target_identity_digest = ?
                  AND environment_identity_digest = ?
                """,
                (
                    canonical_target,
                    target_identity_digest,
                    canonical_environment,
                    environment_identity_digest,
                    now,
                    claim.run_id,
                    claim.organization_id,
                    claim.target_identity_digest,
                    environment_identity_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "worker_identity_reconciliation_conflict")
            self._transition_run_with_connection(
                connection,
                claim.run_id,
                claim.organization_id,
                "QUEUED",
                "ACQUIRING_TARGET",
                "certforge.run-worker",
                "subscriber_execution_started",
                "p7.subscriber",
                now,
            )
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'STARTED', execution_started_at = ?,
                    governance_version = ?, subscription_version = ?,
                    lease_expires_at = ?, last_heartbeat_at = ?, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                  AND state = 'EXECUTING' AND claim_token = ?
                """,
                (
                    now,
                    authorization.governance_version,
                    authorization.subscription_version,
                    lease_expires_at,
                    now,
                    now,
                    claim.organization_id,
                    claim.run_id,
                    claim.idempotency_key,
                    claim.claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "worker_run_claim_inactive")
            self._append_audit(
                connection,
                organization_id=claim.organization_id,
                actor_ref="certforge.run-worker",
                action="certification.execution_start",
                resource_type="certification",
                resource_id=claim.run_id,
                outcome="allowed",
                details={
                    "governance_version": authorization.governance_version,
                    "subscription_version": authorization.subscription_version,
                    "lease_expires_at": lease_expires_at,
                    "target_identity_digest": target_identity_digest,
                    "environment_identity_digest": environment_identity_digest,
                },
            )
            return authorization

    def heartbeat_worker_claim(self, claim: WorkerRunClaim) -> str:
        now_value = self._now()
        now = to_utc_iso(now_value)
        lease_expires_at = to_utc_iso(
            now_value + timedelta(seconds=self.policy.worker_claim_lease_seconds)
        )
        with self._connection(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET lease_expires_at = ?, last_heartbeat_at = ?, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                  AND claim_token = ? AND state IN ('EXECUTING', 'STARTED')
                  AND lease_expires_at > ?
                """,
                (
                    lease_expires_at,
                    now,
                    now,
                    claim.organization_id,
                    claim.run_id,
                    claim.idempotency_key,
                    claim.claim_token,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "worker_run_claim_inactive")
        return lease_expires_at

    def assert_worker_claim_active(self, claim: WorkerRunClaim) -> None:
        now = self._now()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT state, claim_token, lease_expires_at
                FROM subscriber_run_reservations
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                """,
                (claim.organization_id, claim.run_id, claim.idempotency_key),
            ).fetchone()
        if (
            row is None
            or row["state"] not in {"EXECUTING", "STARTED"}
            or row["claim_token"] is None
            or not hmac.compare_digest(str(row["claim_token"]), claim.claim_token)
            or row["lease_expires_at"] is None
            or parse_utc_iso(str(row["lease_expires_at"])) <= now
        ):
            raise SubscriberError(409, "worker_run_claim_inactive")

    def fail_worker_execution(self, claim: WorkerRunClaim, *, reason: str) -> None:
        require_identifier(reason, "reason")
        now_value = self._now()
        now = to_utc_iso(now_value)
        with self._connection(immediate=True) as connection:
            reservation = connection.execute(
                """
                SELECT state, claim_token, lease_expires_at
                FROM subscriber_run_reservations
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                """,
                (claim.organization_id, claim.run_id, claim.idempotency_key),
            ).fetchone()
            run = connection.execute(
                "SELECT state FROM runs WHERE run_id = ? AND tenant_id = ?",
                (claim.run_id, claim.organization_id),
            ).fetchone()
            if (
                reservation is None
                or reservation["state"] not in {"EXECUTING", "STARTED"}
                or reservation["claim_token"] is None
                or not hmac.compare_digest(
                    str(reservation["claim_token"]), claim.claim_token
                )
                or reservation["lease_expires_at"] is None
                or parse_utc_iso(str(reservation["lease_expires_at"])) <= now_value
            ):
                raise SubscriberError(409, "worker_run_claim_inactive")
            if run is not None and str(run["state"]) not in _TERMINAL_RUN_STATES:
                self._transition_run_with_connection(
                    connection,
                    claim.run_id,
                    claim.organization_id,
                    str(run["state"]),
                    "INFRASTRUCTURE_FAILURE",
                    "certforge.run-worker",
                    reason,
                    "p7.subscriber",
                    now,
                )
                connection.execute(
                    """
                    UPDATE runs SET run_outcome = 'INFRA_FAILED', updated_at = ?
                    WHERE run_id = ? AND tenant_id = ?
                    """,
                    (now, claim.run_id, claim.organization_id),
                )
            connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'RELEASED', claim_token = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                  AND claim_token = ?
                """,
                (
                    now,
                    claim.organization_id,
                    claim.run_id,
                    claim.idempotency_key,
                    claim.claim_token,
                ),
            )
            connection.execute(
                """
                UPDATE subscriber_run_dispatches
                SET state = 'FAILED', claim_token = NULL, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = ?, updated_at = ?
                WHERE run_id = ? AND organization_id = ?
                  AND state IN ('PENDING', 'CLAIMED')
                """,
                (reason, now, claim.run_id, claim.organization_id),
            )
            self._append_audit(
                connection,
                organization_id=claim.organization_id,
                actor_ref="certforge.run-worker",
                action="certification.worker_fail",
                resource_type="certification",
                resource_id=claim.run_id,
                outcome="denied",
                details={"reason": reason, "claim_fenced": True},
            )

    def complete_worker_execution(self, claim: WorkerRunClaim, envelope: Any) -> None:
        payload = getattr(envelope, "payload", None)
        if not isinstance(payload, dict):
            raise TypeError("signed verdict envelope payload is required")
        if (
            payload.get("run_id") != claim.run_id
            or payload.get("tenant_id") != claim.organization_id
        ):
            raise SubscriberError(409, "worker_completion_identity_mismatch")
        now_value = self._now()
        now = to_utc_iso(now_value)
        with self._connection(immediate=True) as connection:
            reservation = connection.execute(
                """
                SELECT state, claim_token, lease_expires_at
                FROM subscriber_run_reservations
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                """,
                (claim.organization_id, claim.run_id, claim.idempotency_key),
            ).fetchone()
            run = connection.execute(
                """
                SELECT state FROM runs WHERE run_id = ? AND tenant_id = ?
                """,
                (claim.run_id, claim.organization_id),
            ).fetchone()
            if (
                reservation is None
                or reservation["state"] != "STARTED"
                or reservation["claim_token"] is None
                or not hmac.compare_digest(
                    str(reservation["claim_token"]), claim.claim_token
                )
                or reservation["lease_expires_at"] is None
                or parse_utc_iso(str(reservation["lease_expires_at"])) <= now_value
            ):
                raise SubscriberError(409, "worker_run_claim_inactive")
            if run is None or run["state"] != "CALCULATING_VERDICT":
                raise SubscriberError(409, "worker_completion_state_conflict")
            connection.execute(
                """
                INSERT INTO signed_verdicts(
                    run_id, tenant_id, payload_json, payload_sha256,
                    signature_b64, key_id, public_key_pem, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim.run_id,
                    claim.organization_id,
                    canonical_json(payload),
                    envelope.payload_sha256,
                    envelope.signature_b64,
                    envelope.key_id,
                    envelope.public_key_pem,
                    now,
                ),
            )
            self._transition_run_with_connection(
                connection,
                claim.run_id,
                claim.organization_id,
                "CALCULATING_VERDICT",
                "FINALIZING_REPORT",
                "certforge.executor",
                "finalize",
                "t4.p5",
                now,
            )
            self._transition_run_with_connection(
                connection,
                claim.run_id,
                claim.organization_id,
                "FINALIZING_REPORT",
                "REGISTERING_RESULT",
                "certforge.executor",
                "register",
                "t4.p5",
                now,
            )
            self._transition_run_with_connection(
                connection,
                claim.run_id,
                claim.organization_id,
                "REGISTERING_RESULT",
                "COMPLETED",
                "certforge.executor",
                "complete",
                "t4.p5",
                now,
            )
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'RELEASED', claim_token = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                  AND state = 'STARTED' AND claim_token = ?
                """,
                (
                    now,
                    claim.organization_id,
                    claim.run_id,
                    claim.idempotency_key,
                    claim.claim_token,
                ),
            )
            if cursor.rowcount != 1:
                raise SubscriberError(409, "worker_run_claim_inactive")
            connection.execute(
                """
                UPDATE subscriber_run_dispatches
                SET state = 'COMPLETE', claim_token = NULL, lease_owner = NULL,
                    lease_expires_at = NULL, last_error = NULL, updated_at = ?
                WHERE run_id = ? AND organization_id = ?
                  AND state IN ('PENDING', 'CLAIMED')
                """,
                (now, claim.run_id, claim.organization_id),
            )
            self._append_audit(
                connection,
                organization_id=claim.organization_id,
                actor_ref="certforge.run-worker",
                action="certification.worker_complete",
                resource_type="certification",
                resource_id=claim.run_id,
                outcome="allowed",
                details={"claim_fenced": True},
            )

    def finish_worker_claim(
        self, claim: WorkerRunClaim, *, reason: str, require_active: bool = False
    ) -> None:
        require_identifier(reason, "reason")
        now_value = self._now()
        now = to_utc_iso(now_value)
        with self._connection(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE subscriber_run_reservations
                SET state = 'RELEASED', claim_token = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE organization_id = ? AND run_id = ? AND idempotency_key = ?
                  AND claim_token = ? AND state IN ('EXECUTING', 'STARTED')
                  AND (? = 0 OR lease_expires_at > ?)
                """,
                (
                    now,
                    claim.organization_id,
                    claim.run_id,
                    claim.idempotency_key,
                    claim.claim_token,
                    int(require_active),
                    now,
                ),
            )
            if require_active and cursor.rowcount != 1:
                raise SubscriberError(409, "worker_run_claim_inactive")
            if cursor.rowcount == 1:
                run = connection.execute(
                    """
                    SELECT state FROM runs
                    WHERE run_id = ? AND tenant_id = ?
                    """,
                    (claim.run_id, claim.organization_id),
                ).fetchone()
                if run is not None and str(run["state"]) in _TERMINAL_RUN_STATES:
                    dispatch_state = (
                        "COMPLETE" if str(run["state"]) == "COMPLETED" else "FAILED"
                    )
                    connection.execute(
                        """
                        UPDATE subscriber_run_dispatches
                        SET state = ?, claim_token = NULL, lease_owner = NULL,
                            lease_expires_at = NULL, last_error = ?, updated_at = ?
                        WHERE run_id = ? AND organization_id = ?
                          AND state IN ('PENDING', 'CLAIMED')
                        """,
                        (
                            dispatch_state,
                            None
                            if dispatch_state == "COMPLETE"
                            else f"worker_terminal:{run['state']}",
                            now,
                            claim.run_id,
                            claim.organization_id,
                        ),
                    )
                self._append_audit(
                    connection,
                    organization_id=claim.organization_id,
                    actor_ref="certforge.run-worker",
                    action="certification.worker_finish",
                    resource_type="certification",
                    resource_id=claim.run_id,
                    outcome="allowed",
                    details={"reason": reason},
                )

    def release_reservation(
        self, reservation: RunReservation, *, reason: str, compensate_meter: bool
    ) -> None:
        require_identifier(reason, "reason")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT r.state, r.created_at,
                       (
                           SELECT u.occurred_at
                           FROM subscriber_usage_events u
                           WHERE u.organization_id = r.organization_id
                             AND u.meter = 'certification_runs'
                             AND u.idempotency_key = r.idempotency_key
                             AND u.quantity > 0
                           LIMIT 1
                       ) AS metered_at
                FROM subscriber_run_reservations r
                WHERE r.organization_id = ? AND r.idempotency_key = ?
                """,
                (reservation.organization_id, reservation.idempotency_key),
            ).fetchone()
            if row is None or row["state"] == "RELEASED":
                return
            connection.execute(
                """
                UPDATE subscriber_run_reservations SET state = 'RELEASED', updated_at = ?
                WHERE organization_id = ? AND idempotency_key = ?
                """,
                (now, reservation.organization_id, reservation.idempotency_key),
            )
            if compensate_meter:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO subscriber_usage_events(
                        organization_id, meter, quantity, idempotency_key,
                        metadata_json, occurred_at
                    ) VALUES (?, 'certification_runs', -1, ?, ?, ?)
                    """,
                    (
                        reservation.organization_id,
                        f"release:{reservation.idempotency_key}",
                        canonical_json({"reason": reason}),
                        row["metered_at"] or row["created_at"],
                    ),
                )
            self._append_audit(
                connection,
                organization_id=reservation.organization_id,
                actor_ref="certforge.intake",
                action="certification.release",
                resource_type="reservation",
                resource_id=sha256_bytes(reservation.idempotency_key.encode())[:32],
                outcome="allowed",
                details={"reason": reason, "meter_compensated": compensate_meter},
            )

    def usage_summary(self, principal: SubscriberPrincipal) -> dict[str, Any]:
        self.require(principal, Permission.USAGE_READ)
        with self._connection() as connection:
            plan, subscription = self._plan_for_org(connection, principal.organization_id)
            period_start, period_end = self._billing_period(subscription)
            rows = connection.execute(
                """
                SELECT meter, COALESCE(SUM(quantity), 0) AS quantity
                FROM subscriber_usage_events
                WHERE organization_id = ? AND occurred_at >= ? AND occurred_at < ?
                GROUP BY meter ORDER BY meter
                """,
                (principal.organization_id, period_start, period_end),
            ).fetchall()
            active = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_run_reservations
                    WHERE organization_id = ? AND state IN ('RESERVED', 'BOUND', 'EXECUTING', 'STARTED')
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
        meters = {str(row["meter"]): int(row["quantity"]) for row in rows}
        return {
            "organization_id": principal.organization_id,
            "period_started_at": period_start,
            "period_ended_at": period_end,
            "meters": meters,
            "limits": {
                "monthly_certification_runs": plan.monthly_certification_runs,
                "concurrent_runs": plan.concurrent_runs,
                "requests_per_minute": plan.requests_per_minute,
            },
            "active_run_reservations": active,
        }

    def list_audit_events(
        self, principal: SubscriberPrincipal, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        self.require(principal, Permission.AUDIT_READ)
        if not 1 <= limit <= 1000:
            raise ValueError("audit limit must be between 1 and 1000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT event_id, organization_id, actor_ref, action, resource_type,
                       resource_id, outcome, details_json, created_at,
                       record_hash, prev_chain_hash, chain_hash
                FROM subscriber_audit_events
                WHERE organization_id = ? ORDER BY event_id DESC LIMIT ?
                """,
                (principal.organization_id, limit),
            ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "details_json"},
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def verify_audit(self, principal: SubscriberPrincipal) -> dict[str, Any]:
        self.require(principal, Permission.AUDIT_READ)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM subscriber_audit_events
                WHERE organization_id = ? ORDER BY event_id
                """,
                (principal.organization_id,),
            ).fetchall()
        previous = _ZERO_HASH
        invalid_event_ids: list[int] = []
        for row in rows:
            record = {
                "organization_id": row["organization_id"],
                "actor_ref": row["actor_ref"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "outcome": row["outcome"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            record_hash = sha256_json(record)
            chain_hash = sha256_bytes(bytes.fromhex(previous) + bytes.fromhex(record_hash))
            if (
                row["record_hash"] != record_hash
                or row["prev_chain_hash"] != previous
                or row["chain_hash"] != chain_hash
            ):
                invalid_event_ids.append(int(row["event_id"]))
            previous = str(row["chain_hash"])
        return {
            "organization_id": principal.organization_id,
            "valid": not invalid_event_ids,
            "event_count": len(rows),
            "invalid_event_ids": invalid_event_ids,
            "chain_tip": previous,
        }

    def entitlement(self, tenant_id: str) -> tuple[bool, str]:
        require_identifier(tenant_id, "tenant_id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT o.status, s.current_period_end
                FROM subscriber_organizations o
                JOIN subscriber_subscriptions s USING (organization_id)
                WHERE o.organization_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        if row is None:
            return False, "subscriber_unknown"
        status = OrganizationStatus(str(row["status"]))
        if status not in {OrganizationStatus.TRIALING, OrganizationStatus.ACTIVE}:
            return False, f"subscription_{status.value.lower()}"
        if parse_utc_iso(str(row["current_period_end"])) <= self._now():
            return False, "subscription_period_expired"
        return True, "entitled"

    def retention_days(self, tenant_id: str) -> int:
        require_identifier(tenant_id, "tenant_id")
        with self._connection() as connection:
            plan, _ = self._plan_for_org(connection, tenant_id)
            row = connection.execute(
                """
                SELECT config_json FROM subscriber_governance WHERE organization_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        if row is None:
            raise SubscriberError(503, "governance_config_missing")
        days = json.loads(row["config_json"]).get("retention_days")
        if isinstance(days, bool) or not isinstance(days, int) or days < 1:
            raise SubscriberError(503, "governance_retention_invalid")
        return min(days, plan.maximum_retention_days)
