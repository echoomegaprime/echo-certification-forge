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


class SubscriberPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^1\.0\.0$")
    policy_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    api_key_max_ttl_days: int = Field(ge=1, le=3650)
    api_key_secret_bytes: int = Field(ge=24, le=64)
    rate_window_seconds: int = Field(ge=1, le=3600)
    rate_limit_scope: str = Field(pattern=r"^api_key_global$")
    audit_denied_requests: bool
    reservation_ttl_seconds: int = Field(ge=30, le=86_400)
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

    def _initialize(self) -> None:
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
            cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_billing_events (
            provider_event_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
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
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, idempotency_key),
            UNIQUE (run_id)
        );
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
    ) -> ProvisionedOrganization:
        require_identifier(slug, "slug")
        if not display_name.strip() or not owner_display_name.strip():
            raise ValueError("organization and owner display names are required")
        email = owner_email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise ValueError("owner_email is invalid")
        plan = self.policy.plan(plan_code)
        organization_id = self._new_id("org")
        user_id = self._new_id("usr")
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
                   s.current_period_end
            FROM subscriber_organizations o
            JOIN subscriber_subscriptions s USING (organization_id)
            JOIN subscriber_memberships m USING (organization_id)
            JOIN subscriber_users u USING (user_id)
            WHERE o.organization_id = ? AND u.user_id = ?
            """,
            (principal.organization_id, principal.user_id),
        ).fetchone()
        if row is None:
            raise SubscriberError(403, "membership_missing")
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
        if permission not in self.policy.role_permissions[role] or permission not in principal.scopes:
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

    def activate_member(self, organization_id: str, user_id: str, *, actor_ref: str) -> None:
        require_identifier(actor_ref, "actor_ref")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            membership = connection.execute(
                """
                SELECT 1 FROM subscriber_memberships
                WHERE organization_id = ? AND user_id = ?
                """,
                (organization_id, user_id),
            ).fetchone()
            if membership is None:
                raise SubscriberError(404, "member_not_found")
            connection.execute(
                """
                UPDATE subscriber_memberships SET status = ?, updated_at = ?
                WHERE organization_id = ? AND user_id = ?
                """,
                (UserStatus.ACTIVE.value, now, organization_id, user_id),
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
                organization_id=organization_id,
                actor_ref=actor_ref,
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

    def apply_billing_event(
        self,
        *,
        organization_id: str,
        provider_event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        plan_code: str | None = None,
    ) -> OrganizationStatus:
        require_identifier(organization_id, "organization_id")
        require_identifier(provider_event_id, "provider_event_id")
        event_statuses = {
            "subscription.activated": OrganizationStatus.ACTIVE,
            "payment.failed": OrganizationStatus.PAST_DUE,
            "subscription.suspended": OrganizationStatus.SUSPENDED,
            "subscription.cancelled": OrganizationStatus.CANCELLED,
        }
        if event_type not in event_statuses:
            raise SubscriberError(422, "billing_event_unknown")
        if plan_code is not None:
            self.policy.plan(plan_code)
        encoded = canonical_json(dict(payload))
        digest = sha256_json(
            {
                "organization_id": organization_id,
                "event_type": event_type,
                "plan_code": plan_code,
                "payload": json.loads(encoded),
            }
        )
        period_start_value = payload.get("current_period_start")
        period_end_value = payload.get("current_period_end")
        if (period_start_value is None) != (period_end_value is None):
            raise SubscriberError(422, "billing_period_incomplete")
        period_start: str | None = None
        period_end: str | None = None
        if period_start_value is not None and period_end_value is not None:
            if not isinstance(period_start_value, str) or not isinstance(
                period_end_value, str
            ):
                raise SubscriberError(422, "billing_period_invalid")
            parsed_start = parse_utc_iso(period_start_value)
            parsed_end = parse_utc_iso(period_end_value)
            if parsed_end <= parsed_start:
                raise SubscriberError(422, "billing_period_invalid")
            period_start = to_utc_iso(parsed_start)
            period_end = to_utc_iso(parsed_end)
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            existing = connection.execute(
                """
                SELECT organization_id, event_type, payload_sha256
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
                ):
                    raise SubscriberError(409, "billing_event_conflict")
                row = connection.execute(
                    "SELECT status FROM subscriber_organizations WHERE organization_id = ?",
                    (organization_id,),
                ).fetchone()
                if row is None:
                    raise SubscriberError(404, "organization_not_found")
                return OrganizationStatus(str(row["status"]))
            row = connection.execute(
                "SELECT status FROM subscriber_organizations WHERE organization_id = ?",
                (organization_id,),
            ).fetchone()
            if row is None:
                raise SubscriberError(404, "organization_not_found")
            current = OrganizationStatus(str(row["status"]))
            target = event_statuses[event_type]
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
                    provider_event_id, organization_id, event_type, payload_sha256,
                    payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (provider_event_id, organization_id, event_type, digest, encoded, now),
            )
            connection.execute(
                """
                UPDATE subscriber_organizations SET status = ?, updated_at = ?
                WHERE organization_id = ?
                """,
                (target.value, now, organization_id),
            )
            if plan_code is None:
                if period_start is None:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions SET status = ?, updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (target.value, now, organization_id),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions
                        SET status = ?, current_period_start = ?,
                            current_period_end = ?, updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (
                            target.value,
                            period_start,
                            period_end,
                            now,
                            organization_id,
                        ),
                    )
            else:
                if period_start is None:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions
                        SET status = ?, plan_code = ?, updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (target.value, plan_code, now, organization_id),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE subscriber_subscriptions
                        SET status = ?, plan_code = ?, current_period_start = ?,
                            current_period_end = ?, updated_at = ?
                        WHERE organization_id = ?
                        """,
                        (
                            target.value,
                            plan_code,
                            period_start,
                            period_end,
                            now,
                            organization_id,
                        ),
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
                    "plan_code": plan_code,
                },
            )
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
        now = to_utc_iso(self._now())
        encoded = canonical_json(dict(config))
        with self._connection(immediate=True) as connection:
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

    def _period_start(self, now: datetime) -> str:
        return to_utc_iso(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))

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
            SELECT r.idempotency_key, r.request_digest, r.run_id
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
                    now,
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
            WHERE organization_id = ? AND state = 'BOUND' AND run_id IN (
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
    ) -> RunReservation:
        self.require(principal, Permission.RUN_CREATE)
        self.get_project(principal, project_id, required_status="ACTIVE")
        now = self._now()
        now_text = to_utc_iso(now)
        with self._connection(immediate=True) as connection:
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
                SELECT request_digest, state FROM subscriber_run_reservations
                WHERE organization_id = ? AND idempotency_key = ?
                """,
                (principal.organization_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise SubscriberError(409, "idempotency_conflict")
                return RunReservation(
                    principal.organization_id, idempotency_key, request_digest, False
                )
            plan, subscription = self._plan_for_org(connection, principal.organization_id)
            if OrganizationStatus(str(subscription["organization_status"])) not in {
                OrganizationStatus.TRIALING,
                OrganizationStatus.ACTIVE,
            }:
                raise SubscriberError(402, "subscription_not_writable")
            self._reconcile_run_reservations(connection, principal.organization_id, now_text)
            active = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_run_reservations
                    WHERE organization_id = ? AND state IN ('RESERVED', 'BOUND')
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
                      AND occurred_at >= ?
                    """,
                    (principal.organization_id, self._period_start(now)),
                ).fetchone()[0]
            )
            if used >= plan.monthly_certification_runs:
                raise SubscriberError(429, "monthly_run_quota_exceeded")
            connection.execute(
                """
                INSERT INTO subscriber_run_reservations(
                    organization_id, idempotency_key, request_digest,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, 'RESERVED', ?, ?)
                """,
                (
                    principal.organization_id,
                    idempotency_key,
                    request_digest,
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
                principal.organization_id, idempotency_key, request_digest, True
            )

    def bind_run(self, reservation: RunReservation, run_id: str) -> None:
        require_identifier(run_id, "run_id")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
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
            self._append_audit(
                connection,
                organization_id=reservation.organization_id,
                actor_ref="certforge.intake",
                action="certification.bind",
                resource_type="certification",
                resource_id=run_id,
                outcome="allowed",
            )

    def release_reservation(
        self, reservation: RunReservation, *, reason: str, compensate_meter: bool
    ) -> None:
        require_identifier(reason, "reason")
        now = to_utc_iso(self._now())
        with self._connection(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT state FROM subscriber_run_reservations
                WHERE organization_id = ? AND idempotency_key = ?
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
                        now,
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
        now = self._now()
        with self._connection() as connection:
            plan, _ = self._plan_for_org(connection, principal.organization_id)
            rows = connection.execute(
                """
                SELECT meter, COALESCE(SUM(quantity), 0) AS quantity
                FROM subscriber_usage_events
                WHERE organization_id = ? AND occurred_at >= ?
                GROUP BY meter ORDER BY meter
                """,
                (principal.organization_id, self._period_start(now)),
            ).fetchall()
            active = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM subscriber_run_reservations
                    WHERE organization_id = ? AND state IN ('RESERVED', 'BOUND')
                    """,
                    (principal.organization_id,),
                ).fetchone()[0]
            )
        meters = {str(row["meter"]): int(row["quantity"]) for row in rows}
        return {
            "organization_id": principal.organization_id,
            "period_started_at": self._period_start(now),
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
        return days
