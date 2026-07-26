"""Persistent release integration and subscriber governance for P6/P7."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from .canonical import (
    canonical_json,
    parse_utc_iso,
    require_identifier,
    require_sha256,
    sha256_json,
    to_utc_iso,
    utc_now,
)


class PlatformError(RuntimeError):
    """Fail-closed platform authorization or integrity failure."""

    def __init__(self, code: str, status_code: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ApiPrincipal:
    key_id: str
    organization_id: str
    project_id: str
    tenant_id: str
    role: str


_PLAN_LIMITS = {
    "developer": {
        "certification_runs": 25,
        "concurrent_runs": 1,
        "worker_minutes": 300,
        "model_tokens": 500_000,
        "evidence_storage_bytes": 2_000_000_000,
        "retention_days": 14,
        "entitlements": ["certify", "basic_reports", "public_verification"],
    },
    "professional": {
        "certification_runs": 500,
        "concurrent_runs": 8,
        "worker_minutes": 20_000,
        "model_tokens": 20_000_000,
        "evidence_storage_bytes": 100_000_000_000,
        "retention_days": 180,
        "entitlements": [
            "certify",
            "full_evidence",
            "release_gates",
            "security_adapters",
            "public_verification",
        ],
    },
    "enterprise": {
        "certification_runs": 10_000,
        "concurrent_runs": 64,
        "worker_minutes": 500_000,
        "model_tokens": 500_000_000,
        "evidence_storage_bytes": 5_000_000_000_000,
        "retention_days": 2555,
        "entitlements": [
            "certify",
            "full_evidence",
            "release_gates",
            "security_adapters",
            "private_workers",
            "custom_policies",
            "audit_exports",
            "public_verification",
            "legal_hold",
        ],
    },
    "sovereign": {
        "certification_runs": 1_000_000,
        "concurrent_runs": 256,
        "worker_minutes": 10_000_000,
        "model_tokens": 10_000_000_000,
        "evidence_storage_bytes": 50_000_000_000_000,
        "retention_days": 36500,
        "entitlements": [
            "certify",
            "full_evidence",
            "release_gates",
            "security_adapters",
            "private_workers",
            "custom_policies",
            "audit_exports",
            "public_verification",
            "legal_hold",
            "customer_managed_keys",
            "local_only_execution",
        ],
    },
}

_ROLES = frozenset({"owner", "admin", "operator", "viewer"})
_BILLING_STATES = frozenset({"trialing", "active", "past_due", "canceled", "unpaid"})
_ACTIVE_BILLING_STATES = frozenset({"trialing", "active"})
_TERMINAL_RUN_STATES = (
    "COMPLETED",
    "CANCELLED",
    "INFRASTRUCTURE_FAILURE",
)


class CertificationPlatform:
    """SQLite-backed P6/P7 integration, metering, billing, and audit plane."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _api_key_columns(connection: sqlite3.Connection) -> frozenset[str]:
        return frozenset(
            str(row[1])
            for row in connection.execute("PRAGMA table_info(subscriber_api_keys)")
        )

    @classmethod
    def _uses_legacy_api_key_schema(cls, connection: sqlite3.Connection) -> bool:
        columns = cls._api_key_columns(connection)
        return "token_prefix" in columns and "key_prefix" not in columns

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS commercial_plans (
            plan_id TEXT PRIMARY KEY,
            limits_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS organizations (
            organization_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
            name TEXT NOT NULL,
            target_reference TEXT NOT NULL,
            required_policy TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(organization_id, name)
        );
        CREATE TABLE IF NOT EXISTS subscriber_users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memberships (
            organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
            user_id TEXT NOT NULL REFERENCES subscriber_users(user_id),
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            organization_id TEXT PRIMARY KEY REFERENCES organizations(organization_id),
            plan_id TEXT NOT NULL REFERENCES commercial_plans(plan_id),
            status TEXT NOT NULL,
            provider_customer_id TEXT,
            provider_subscription_id TEXT,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriber_api_keys (
            key_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
            project_id TEXT NOT NULL REFERENCES projects(project_id),
            key_prefix TEXT NOT NULL,
            secret_sha256 TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_subscriber_keys_prefix
            ON subscriber_api_keys(key_prefix);
        CREATE TABLE IF NOT EXISTS quota_reservations (
            organization_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            unit TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(organization_id, idempotency_key, unit)
        );
        CREATE TABLE IF NOT EXISTS usage_events (
            usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            unit TEXT NOT NULL,
            amount INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(organization_id, unit, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS platform_audit_events (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            project_id TEXT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS billing_webhook_events (
            event_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS release_integration_events (
            source TEXT NOT NULL,
            event_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            target_reference TEXT NOT NULL,
            target_digest TEXT NOT NULL,
            environment_digest TEXT NOT NULL,
            policy_digest TEXT NOT NULL,
            priority TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(source, event_id)
        );
        CREATE TABLE IF NOT EXISTS deployment_attempts (
            attempt_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            deployment_environment TEXT NOT NULL,
            target_identity_digest TEXT NOT NULL,
            artifact_sha256 TEXT NOT NULL,
            environment_identity_digest TEXT NOT NULL,
            rule_manifest_digest TEXT NOT NULL,
            evidence_merkle_root TEXT NOT NULL,
            signing_key_id TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS legal_holds (
            hold_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            run_id TEXT,
            reason TEXT NOT NULL,
            active INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            released_at TEXT
        );
        CREATE TABLE IF NOT EXISTS public_verifications (
            verification_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        """
        now = to_utc_iso(utc_now())
        with self._connect() as connection:
            with connection:
                connection.executescript(schema)
                for plan_id, limits in _PLAN_LIMITS.items():
                    connection.execute(
                        """INSERT INTO commercial_plans(plan_id, limits_json, created_at)
                           VALUES (?, ?, ?)
                           ON CONFLICT(plan_id) DO UPDATE SET limits_json=excluded.limits_json""",
                        (plan_id, canonical_json(limits), now),
                    )

    def bootstrap(
        self,
        *,
        organization_id: str,
        tenant_id: str,
        organization_name: str,
        project_id: str,
        project_name: str,
        target_reference: str,
        required_policy: str,
        owner_user_id: str,
        owner_email: str,
        plan_id: str = "developer",
        billing_status: str = "trialing",
    ) -> dict[str, str]:
        for name, value in (
            ("organization_id", organization_id),
            ("tenant_id", tenant_id),
            ("project_id", project_id),
            ("required_policy", required_policy),
            ("owner_user_id", owner_user_id),
            ("plan_id", plan_id),
        ):
            require_identifier(value, name)
        if billing_status not in _BILLING_STATES:
            raise PlatformError("invalid_billing_status", 422)
        if plan_id not in _PLAN_LIMITS:
            raise PlatformError("unknown_plan", 422)
        if not all(
            item.strip()
            for item in (
                organization_name,
                project_name,
                target_reference,
                owner_email,
            )
        ):
            raise PlatformError("bootstrap_fields_required", 422)
        now = utc_now()
        period_end = now + timedelta(days=30)
        raw_key = "ecf_" + secrets.token_urlsafe(32)
        key_id = "key-" + secrets.token_hex(12)
        with self._connect() as connection:
            with connection:
                connection.execute(
                    "INSERT INTO organizations VALUES (?, ?, ?, ?)",
                    (organization_id, tenant_id, organization_name, to_utc_iso(now)),
                )
                connection.execute(
                    "INSERT INTO projects VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        project_id,
                        organization_id,
                        project_name,
                        target_reference,
                        required_policy,
                        to_utc_iso(now),
                    ),
                )
                connection.execute(
                    "INSERT INTO subscriber_users VALUES (?, ?, ?)",
                    (owner_user_id, owner_email.lower(), to_utc_iso(now)),
                )
                connection.execute(
                    "INSERT INTO memberships VALUES (?, ?, ?, ?)",
                    (
                        organization_id,
                        owner_user_id,
                        "owner",
                        to_utc_iso(now),
                    ),
                )
                connection.execute(
                    """INSERT INTO subscriptions(
                           organization_id, plan_id, status, period_start, period_end, updated_at
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        organization_id,
                        plan_id,
                        billing_status,
                        to_utc_iso(now),
                        to_utc_iso(period_end),
                        to_utc_iso(now),
                    ),
                )
                if self._uses_legacy_api_key_schema(connection):
                    connection.execute(
                        """INSERT INTO subscriber_api_keys(
                               key_id, organization_id, user_id, name,
                               token_digest, token_prefix, scopes_json, status,
                               expires_at, created_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            key_id,
                            organization_id,
                            owner_user_id,
                            "Bootstrap owner key",
                            hashlib.sha256(raw_key.encode()).hexdigest(),
                            raw_key[:16],
                            canonical_json(["certforge.*"]),
                            "active",
                            None,
                            to_utc_iso(now),
                        ),
                    )
                else:
                    connection.execute(
                        """INSERT INTO subscriber_api_keys(
                               key_id, organization_id, project_id, key_prefix,
                               secret_sha256, role, created_at
                           ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            key_id,
                            organization_id,
                            project_id,
                            raw_key[:16],
                            hashlib.sha256(raw_key.encode()).hexdigest(),
                            "owner",
                            to_utc_iso(now),
                        ),
                    )
        self.audit(
            organization_id,
            project_id,
            f"user:{owner_user_id}",
            "organization.bootstrap",
            "organization",
            organization_id,
            {"plan_id": plan_id, "billing_status": billing_status},
        )
        return {
            "organization_id": organization_id,
            "tenant_id": tenant_id,
            "project_id": project_id,
            "key_id": key_id,
            "api_key": raw_key,
        }

    def authenticate(self, raw_key: str) -> ApiPrincipal:
        if not raw_key or len(raw_key) < 24:
            raise PlatformError("invalid_api_key", 401)
        digest = hashlib.sha256(raw_key.encode()).hexdigest()
        with self._connect() as connection:
            if self._uses_legacy_api_key_schema(connection):
                rows = connection.execute(
                    """SELECT k.key_id, k.organization_id,
                              p.project_id, o.tenant_id,
                              COALESCE(m.role, 'viewer') AS role,
                              k.token_digest AS secret_sha256
                         FROM subscriber_api_keys k
                         JOIN organizations o
                           ON o.organization_id=k.organization_id
                         JOIN projects p
                           ON p.project_id=(
                              SELECT p2.project_id FROM projects p2
                               WHERE p2.organization_id=k.organization_id
                               ORDER BY p2.created_at, p2.project_id LIMIT 1
                           )
                         LEFT JOIN memberships m
                           ON m.organization_id=k.organization_id
                          AND m.user_id=k.user_id
                        WHERE k.token_prefix=?
                          AND k.revoked_at IS NULL
                          AND LOWER(COALESCE(k.status, 'active'))='active'
                          AND (k.expires_at IS NULL OR k.expires_at>?)""",
                    (raw_key[:16], to_utc_iso(utc_now())),
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT k.*, o.tenant_id
                         FROM subscriber_api_keys k
                         JOIN organizations o ON o.organization_id=k.organization_id
                        WHERE k.key_prefix=? AND k.revoked_at IS NULL""",
                    (raw_key[:16],),
                ).fetchall()
        row = next(
            (
                candidate
                for candidate in rows
                if hmac.compare_digest(candidate["secret_sha256"], digest)
            ),
            None,
        )
        if row is None:
            raise PlatformError("invalid_api_key", 401)
        return ApiPrincipal(
            key_id=row["key_id"],
            organization_id=row["organization_id"],
            project_id=row["project_id"],
            tenant_id=row["tenant_id"],
            role=row["role"],
        )

    @staticmethod
    def require_role(principal: ApiPrincipal, *roles: str) -> None:
        if principal.role not in roles:
            raise PlatformError("role_forbidden", 403)

    def subscription(self, organization_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT s.*, p.limits_json
                     FROM subscriptions s
                     JOIN commercial_plans p ON p.plan_id=s.plan_id
                    WHERE s.organization_id=?""",
                (organization_id,),
            ).fetchone()
        if row is None:
            raise PlatformError("subscription_missing", 402)
        result = dict(row)
        result["limits"] = json.loads(result.pop("limits_json"))
        return result

    def reserve_run(self, principal: ApiPrincipal, idempotency_key: str) -> None:
        require_identifier(idempotency_key, "idempotency_key")
        subscription = self.subscription(principal.organization_id)
        if subscription["status"] not in _ACTIVE_BILLING_STATES:
            raise PlatformError("billing_not_current", 402)
        if parse_utc_iso(subscription["period_end"]) <= utc_now():
            raise PlatformError("subscription_period_expired", 402)
        limits = subscription["limits"]
        if "certify" not in limits["entitlements"]:
            raise PlatformError("certification_not_entitled", 403)
        with self._connect() as connection:
            with connection:
                existing = connection.execute(
                    """SELECT 1 FROM quota_reservations
                        WHERE organization_id=? AND idempotency_key=? AND unit='certification_runs'""",
                    (principal.organization_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    return
                used = connection.execute(
                    """SELECT COALESCE(SUM(amount),0) AS used
                         FROM usage_events
                        WHERE organization_id=? AND unit='certification_runs'
                          AND created_at>=? AND created_at<?""",
                    (
                        principal.organization_id,
                        subscription["period_start"],
                        subscription["period_end"],
                    ),
                ).fetchone()["used"]
                active_runs = connection.execute(
                    """SELECT COUNT(*) AS count FROM runs
                        WHERE tenant_id=? AND state NOT IN (?, ?, ?)""",
                    (principal.tenant_id, *_TERMINAL_RUN_STATES),
                ).fetchone()["count"]
                if int(used) >= int(limits["certification_runs"]):
                    raise PlatformError("certification_run_quota_exceeded", 429)
                if int(active_runs) >= int(limits["concurrent_runs"]):
                    raise PlatformError("concurrent_run_quota_exceeded", 429)
                now = to_utc_iso(utc_now())
                connection.execute(
                    "INSERT INTO quota_reservations VALUES (?, ?, 'certification_runs', 1, ?)",
                    (principal.organization_id, idempotency_key, now),
                )
                connection.execute(
                    """INSERT INTO usage_events(
                           organization_id, project_id, unit, amount, idempotency_key, created_at
                       ) VALUES (?, ?, 'certification_runs', 1, ?, ?)""",
                    (
                        principal.organization_id,
                        principal.project_id,
                        idempotency_key,
                        now,
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "quota.reserve",
            "certification_run",
            idempotency_key,
            {"amount": 1},
        )

    def meter(
        self,
        principal: ApiPrincipal,
        *,
        unit: str,
        amount: int,
        idempotency_key: str,
    ) -> dict[str, int]:
        if unit not in {
            "worker_minutes",
            "model_tokens",
            "evidence_storage_bytes",
        }:
            raise PlatformError("unsupported_metering_unit", 422)
        if amount <= 0:
            raise PlatformError("metering_amount_must_be_positive", 422)
        subscription = self.subscription(principal.organization_id)
        if subscription["status"] not in _ACTIVE_BILLING_STATES:
            raise PlatformError("billing_not_current", 402)
        limit = int(subscription["limits"][unit])
        with self._connect() as connection:
            with connection:
                used = int(
                    connection.execute(
                        """SELECT COALESCE(SUM(amount),0) AS used FROM usage_events
                            WHERE organization_id=? AND unit=? AND created_at>=? AND created_at<?""",
                        (
                            principal.organization_id,
                            unit,
                            subscription["period_start"],
                            subscription["period_end"],
                        ),
                    ).fetchone()["used"]
                )
                if used + amount > limit:
                    raise PlatformError(f"{unit}_budget_exceeded", 429)
                connection.execute(
                    """INSERT INTO usage_events(
                           organization_id, project_id, unit, amount, idempotency_key, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        principal.organization_id,
                        principal.project_id,
                        unit,
                        amount,
                        idempotency_key,
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "usage.meter",
            unit,
            idempotency_key,
            {"amount": amount},
        )
        return {"used": used + amount, "limit": limit}

    def apply_billing_event(
        self,
        *,
        raw_body: bytes,
        signature: str,
        timestamp: int,
        secret: str,
    ) -> dict[str, Any]:
        if abs(int(utc_now().timestamp()) - timestamp) > 300:
            raise PlatformError("billing_signature_expired", 401)
        expected = hmac.new(
            secret.encode(),
            f"{timestamp}.".encode() + raw_body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise PlatformError("billing_signature_invalid", 401)
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise PlatformError("billing_payload_invalid", 422) from exc
        event_id = str(payload.get("event_id", ""))
        organization_id = str(payload.get("organization_id", ""))
        status = str(payload.get("status", ""))
        plan_id = str(payload.get("plan_id", ""))
        require_identifier(event_id, "event_id")
        require_identifier(organization_id, "organization_id")
        if status not in _BILLING_STATES or plan_id not in _PLAN_LIMITS:
            raise PlatformError("billing_payload_invalid", 422)
        payload_sha256 = hashlib.sha256(raw_body).hexdigest()
        with self._connect() as connection:
            with connection:
                replay = connection.execute(
                    "SELECT payload_sha256 FROM billing_webhook_events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if replay is not None:
                    if replay["payload_sha256"] != payload_sha256:
                        raise PlatformError("billing_event_conflict", 409)
                    return {"event_id": event_id, "status": "replayed"}
                period_start = str(payload.get("period_start", ""))
                period_end = str(payload.get("period_end", ""))
                parse_utc_iso(period_start)
                parse_utc_iso(period_end)
                connection.execute(
                    """UPDATE subscriptions
                          SET plan_id=?, status=?, provider_customer_id=?,
                              provider_subscription_id=?, period_start=?, period_end=?,
                              updated_at=?
                        WHERE organization_id=?""",
                    (
                        plan_id,
                        status,
                        payload.get("provider_customer_id"),
                        payload.get("provider_subscription_id"),
                        period_start,
                        period_end,
                        to_utc_iso(utc_now()),
                        organization_id,
                    ),
                )
                if connection.total_changes == 0:
                    raise PlatformError("organization_not_found", 404)
                connection.execute(
                    "INSERT INTO billing_webhook_events VALUES (?, ?, ?, ?)",
                    (
                        event_id,
                        organization_id,
                        payload_sha256,
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            organization_id,
            None,
            "billing-webhook",
            "billing.status",
            "subscription",
            organization_id,
            {"status": status, "plan_id": plan_id, "event_id": event_id},
        )
        return {"event_id": event_id, "status": status, "plan_id": plan_id}

    def ingest_release_event(
        self,
        principal: ApiPrincipal,
        *,
        source: str,
        event_id: str,
        target_reference: str,
        target_digest: str,
        environment_digest: str,
        policy_digest: str,
        priority: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if source not in {"git", "build", "registry", "staging"}:
            raise PlatformError("unsupported_release_event_source", 422)
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            raise PlatformError("invalid_queue_priority", 422)
        require_identifier(event_id, "event_id")
        for name, value in (
            ("target_digest", target_digest),
            ("environment_digest", environment_digest),
            ("policy_digest", policy_digest),
        ):
            require_sha256(value, name)
        payload_sha256 = sha256_json(payload)
        with self._connect() as connection:
            with connection:
                existing = connection.execute(
                    "SELECT * FROM release_integration_events WHERE source=? AND event_id=?",
                    (source, event_id),
                ).fetchone()
                if existing is not None:
                    if existing["payload_sha256"] != payload_sha256:
                        raise PlatformError("release_event_conflict", 409)
                    return {
                        "event_id": event_id,
                        "deduplicated": True,
                        "queue_key": f"{source}:{event_id}",
                    }
                connection.execute(
                    """INSERT INTO release_integration_events VALUES
                       (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        source,
                        event_id,
                        principal.organization_id,
                        principal.project_id,
                        target_reference,
                        target_digest,
                        environment_digest,
                        policy_digest,
                        priority,
                        payload_sha256,
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "release_event.ingest",
            source,
            event_id,
            {"priority": priority, "payload_sha256": payload_sha256},
        )
        return {
            "event_id": event_id,
            "deduplicated": False,
            "queue_key": f"{source}:{event_id}",
        }

    def record_deployment(
        self,
        principal: ApiPrincipal,
        *,
        attempt_id: str,
        run_id: str,
        deployment_environment: str,
        target_identity_digest: str,
        artifact_sha256: str,
        environment_identity_digest: str,
        rule_manifest_digest: str,
        evidence_merkle_root: str,
        signing_key_id: str,
        allowed: bool,
        reasons: tuple[str, ...],
    ) -> None:
        for name, value in (
            ("attempt_id", attempt_id),
            ("run_id", run_id),
            ("deployment_environment", deployment_environment),
            ("signing_key_id", signing_key_id),
        ):
            require_identifier(value, name)
        for name, value in (
            ("target_identity_digest", target_identity_digest),
            ("artifact_sha256", artifact_sha256),
            ("environment_identity_digest", environment_identity_digest),
            ("rule_manifest_digest", rule_manifest_digest),
            ("evidence_merkle_root", evidence_merkle_root),
        ):
            require_sha256(value, name)
        with self._connect() as connection:
            with connection:
                connection.execute(
                    """INSERT INTO deployment_attempts VALUES
                       (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        attempt_id,
                        principal.organization_id,
                        principal.project_id,
                        run_id,
                        deployment_environment,
                        target_identity_digest,
                        artifact_sha256,
                        environment_identity_digest,
                        rule_manifest_digest,
                        evidence_merkle_root,
                        signing_key_id,
                        int(allowed),
                        canonical_json(list(reasons)),
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "deployment.authorize",
            "deployment",
            attempt_id,
            {"allowed": allowed, "reasons": list(reasons), "run_id": run_id},
        )

    def create_legal_hold(
        self,
        principal: ApiPrincipal,
        *,
        hold_id: str,
        run_id: str | None,
        reason: str,
    ) -> dict[str, Any]:
        self.require_role(principal, "owner", "admin")
        subscription = self.subscription(principal.organization_id)
        if "legal_hold" not in subscription["limits"]["entitlements"]:
            raise PlatformError("legal_hold_not_entitled", 403)
        require_identifier(hold_id, "hold_id")
        if run_id is not None:
            require_identifier(run_id, "run_id")
        if not reason.strip():
            raise PlatformError("legal_hold_reason_required", 422)
        with self._connect() as connection:
            with connection:
                connection.execute(
                    "INSERT INTO legal_holds VALUES (?, ?, ?, ?, ?, 1, ?, NULL)",
                    (
                        hold_id,
                        principal.organization_id,
                        principal.tenant_id,
                        run_id,
                        reason,
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "legal_hold.create",
            "legal_hold",
            hold_id,
            {"run_id": run_id, "reason": reason},
        )
        return {"hold_id": hold_id, "active": True, "run_id": run_id}

    def release_legal_hold(
        self, principal: ApiPrincipal, hold_id: str
    ) -> dict[str, Any]:
        self.require_role(principal, "owner", "admin")
        with self._connect() as connection:
            with connection:
                cursor = connection.execute(
                    """UPDATE legal_holds SET active=0, released_at=?
                        WHERE hold_id=? AND organization_id=? AND active=1""",
                    (to_utc_iso(utc_now()), hold_id, principal.organization_id),
                )
                if cursor.rowcount != 1:
                    raise PlatformError("legal_hold_not_found", 404)
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "legal_hold.release",
            "legal_hold",
            hold_id,
            {},
        )
        return {"hold_id": hold_id, "active": False}

    def publish_verification(
        self, principal: ApiPrincipal, run_id: str
    ) -> str:
        subscription = self.subscription(principal.organization_id)
        if "public_verification" not in subscription["limits"]["entitlements"]:
            raise PlatformError("public_verification_not_entitled", 403)
        require_identifier(run_id, "run_id")
        verification_id = "verify-" + secrets.token_urlsafe(24)
        with self._connect() as connection:
            with connection:
                connection.execute(
                    "INSERT INTO public_verifications VALUES (?, ?, ?, ?, ?, NULL)",
                    (
                        verification_id,
                        principal.organization_id,
                        principal.tenant_id,
                        run_id,
                        to_utc_iso(utc_now()),
                    ),
                )
        self.audit(
            principal.organization_id,
            principal.project_id,
            f"api_key:{principal.key_id}",
            "verification.publish",
            "certification",
            run_id,
            {"verification_id": verification_id},
        )
        return verification_id

    def public_verification(self, verification_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM public_verifications WHERE verification_id=?",
                (verification_id,),
            ).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise PlatformError("verification_not_found", 404)
        return dict(row)

    def revoke_public_verification(
        self, principal: ApiPrincipal, verification_id: str
    ) -> None:
        self.require_role(principal, "owner", "admin")
        with self._connect() as connection:
            with connection:
                cursor = connection.execute(
                    """UPDATE public_verifications SET revoked_at=?
                        WHERE verification_id=? AND organization_id=? AND revoked_at IS NULL""",
                    (
                        to_utc_iso(utc_now()),
                        verification_id,
                        principal.organization_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise PlatformError("verification_not_found", 404)

    def audit(
        self,
        organization_id: str,
        project_id: str | None,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        detail: dict[str, Any],
    ) -> None:
        with self._connect() as connection:
            with connection:
                connection.execute(
                    """INSERT INTO platform_audit_events(
                           organization_id, project_id, actor, action, object_type,
                           object_id, detail_json, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        organization_id,
                        project_id,
                        actor,
                        action,
                        object_type,
                        object_id,
                        canonical_json(detail),
                        to_utc_iso(utc_now()),
                    ),
                )

    def audit_log(self, principal: ApiPrincipal, limit: int = 100) -> list[dict[str, Any]]:
        self.require_role(principal, "owner", "admin", "operator", "viewer")
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT * FROM platform_audit_events
                    WHERE organization_id=? ORDER BY audit_id DESC LIMIT ?""",
                (principal.organization_id, min(max(limit, 1), 500)),
            ).fetchall()
        return [
            {**dict(row), "detail": json.loads(row["detail_json"])}
            for row in rows
        ]

    def usage_summary(self, principal: ApiPrincipal) -> dict[str, Any]:
        subscription = self.subscription(principal.organization_id)
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT unit, COALESCE(SUM(amount),0) AS used
                     FROM usage_events
                    WHERE organization_id=? AND created_at>=? AND created_at<?
                    GROUP BY unit""",
                (
                    principal.organization_id,
                    subscription["period_start"],
                    subscription["period_end"],
                ),
            ).fetchall()
        used = {row["unit"]: int(row["used"]) for row in rows}
        return {
            "plan_id": subscription["plan_id"],
            "billing_status": subscription["status"],
            "period_start": subscription["period_start"],
            "period_end": subscription["period_end"],
            "limits": subscription["limits"],
            "used": used,
        }
