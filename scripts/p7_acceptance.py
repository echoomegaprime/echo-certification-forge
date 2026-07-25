"""Reproducible P7 subscriber-governance acceptance evidence generator."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from echo_certification_forge.canonical import parse_utc_iso
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.run_worker import run
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    MemberRole,
    OrganizationStatus,
    Permission,
    SubscriberError,
    SubscriberGovernance,
    SubscriberPolicy,
)
from echo_certification_forge.policy import RuleManifest

PEPPER = b"certforge-p7-acceptance-only-pepper-material"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def headers(organization_id: str, api_key: str) -> dict[str, str]:
    return {
        "X-Tenant-ID": organization_id,
        "Authorization": f"Bearer {api_key}",
    }


def record(
    scenarios: dict[str, dict[str, Any]],
    name: str,
    passed: bool,
    **details: Any,
) -> None:
    scenarios[name] = {"passed": passed, **details}


def main() -> int:
    workspace = REPO / "var" / "p7-acceptance-runtime"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    db = workspace / "certforge.sqlite3"
    store = EvidenceStore(db, workspace / "evidence")
    policy_path = REPO / "policies" / "subscriber-governance.v1.json"
    contract_path = REPO / "contracts" / "subscriber-governance.v1.json"
    policy = SubscriberPolicy.load(policy_path)
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    manifest = RuleManifest.load(REPO / "policies" / "mandatory-rules.v1.json")
    governance = SubscriberGovernance(db, policy, PEPPER)
    client = TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                governance,
            )
        )
    )
    scenarios: dict[str, dict[str, Any]] = {}

    alpha = governance.provision_organization(
        slug="p7-alpha",
        display_name="P7 Alpha",
        owner_email="owner@p7-alpha.example",
        owner_display_name="P7 Alpha Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    beta = governance.provision_organization(
        slug="p7-beta",
        display_name="P7 Beta",
        owner_email="owner@p7-beta.example",
        owner_display_name="P7 Beta Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    alpha_headers = headers(alpha.organization_id, alpha.bootstrap_api_key)

    cross = client.get(
        "/v1/subscriber/me",
        headers=headers(beta.organization_id, alpha.bootstrap_api_key),
    )
    record(
        scenarios,
        "tenant_isolation",
        cross.status_code == 404 and cross.json().get("detail") == "tenant_not_found",
        status_code=cross.status_code,
        detail=cross.json().get("detail"),
    )

    project = client.post(
        "/v1/subscriber/projects",
        headers=alpha_headers,
        json={
            "slug": "release-service",
            "name": "Release Service",
            "target_reference": "https://github.com/example/release-service",
        },
    )
    project_id = project.json().get("project_id")
    submit_body = {
        "tenant_id": alpha.organization_id,
        "project_id": project_id,
        "target": {
            "target_type": "git",
            "identity_digest": digest("p7-target"),
            "reference": "https://github.com/example/release-service@abc123",
        },
        "environment": {
            "identity_digest": digest("p7-environment"),
            "runner_image_digest": "sha256:" + digest("p7-runner"),
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": "p7-acceptance-run-0001",
    }
    submitted = client.post("/v1/certifications", headers=alpha_headers, json=submit_body)
    replay = client.post("/v1/certifications", headers=alpha_headers, json=submit_body)
    record(
        scenarios,
        "governed_intake_default_block",
        submitted.status_code == 201
        and replay.status_code == 200
        and submitted.json().get("release_verdict") == "NOT_READY"
        and submitted.json().get("run_id") == replay.json().get("run_id"),
        create_status=submitted.status_code,
        replay_status=replay.status_code,
        run_id=submitted.json().get("run_id"),
        release_verdict=submitted.json().get("release_verdict"),
    )

    usage = client.get("/v1/subscriber/usage", headers=alpha_headers)
    record(
        scenarios,
        "metering_idempotency",
        usage.status_code == 200
        and usage.json().get("meters", {}).get("certification_runs") == 1,
        usage=usage.json(),
    )

    second_run = dict(submit_body)
    second_run["idempotency_key"] = "p7-acceptance-run-0002"
    second_run["target"] = {
        **submit_body["target"],
        "identity_digest": digest("p7-target-2"),
    }
    concurrent = client.post("/v1/certifications", headers=alpha_headers, json=second_run)
    record(
        scenarios,
        "concurrent_quota",
        concurrent.status_code == 429
        and concurrent.json().get("detail") == "concurrent_run_quota_exceeded",
        status_code=concurrent.status_code,
        detail=concurrent.json().get("detail"),
    )

    alpha_principal = governance.authenticate(
        alpha.bootstrap_api_key,
        tenant_hint=alpha.organization_id,
        permission=Permission.API_KEY_MANAGE,
        action="acceptance.key.create",
    )
    read_key = governance.create_api_key(
        alpha_principal,
        name="read-only",
        scopes={Permission.PROJECT_READ},
        expires_at=datetime.now(UTC) + timedelta(days=10),
    )
    write_denied = client.post(
        "/v1/subscriber/projects",
        headers=headers(alpha.organization_id, read_key),
        json={
            "slug": "forbidden",
            "name": "Forbidden",
            "target_reference": "https://github.com/example/forbidden",
        },
    )
    record(
        scenarios,
        "authorization_scope",
        write_denied.status_code == 403
        and write_denied.json().get("detail") == "permission_denied",
        status_code=write_denied.status_code,
        detail=write_denied.json().get("detail"),
    )

    billing_base = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=alpha.organization_id,
        provider_event_id="p7-payment-failed",
        event_type="payment.failed",
        payload={"invoice": "p7-invoice"},
        provider_occurred_at=billing_base,
        provider_sequence=1,
    )
    past_due_write = client.post(
        "/v1/subscriber/projects",
        headers=alpha_headers,
        json={
            "slug": "past-due",
            "name": "Past Due",
            "target_reference": "https://github.com/example/past-due",
        },
    )
    record(
        scenarios,
        "billing_failure_fail_closed",
        past_due_write.status_code == 402
        and past_due_write.json().get("detail") == "subscription_past_due",
        status_code=past_due_write.status_code,
        detail=past_due_write.json().get("detail"),
    )
    governance.apply_billing_event(
        organization_id=alpha.organization_id,
        provider_event_id="p7-payment-recovered",
        event_type="subscription.activated",
        payload={"invoice": "p7-invoice", "paid": True},
        provider_occurred_at=billing_base + timedelta(seconds=1),
        provider_sequence=2,
    )

    audit = client.get("/v1/subscriber/audit/verify", headers=alpha_headers)
    immutable_update_blocked = False
    immutable_delete_blocked = False
    with closing(sqlite3.connect(db)) as connection:
        denied_audits = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM subscriber_audit_events
                WHERE organization_id = ? AND action = 'request.deny'
                  AND outcome = 'denied'
                """,
                (alpha.organization_id,),
            ).fetchone()[0]
        )
        try:
            connection.execute(
                "UPDATE subscriber_audit_events SET outcome = 'forged' WHERE event_id = 1"
            )
        except sqlite3.IntegrityError:
            immutable_update_blocked = True
        try:
            connection.execute("DELETE FROM subscriber_audit_events WHERE event_id = 1")
        except sqlite3.IntegrityError:
            immutable_delete_blocked = True
    record(
        scenarios,
        "immutable_audit_chain",
        audit.status_code == 200
        and audit.json().get("valid") is True
        and denied_audits >= 1
        and immutable_update_blocked
        and immutable_delete_blocked,
        event_count=audit.json().get("event_count"),
        chain_tip=audit.json().get("chain_tip"),
        denied_audits=denied_audits,
        update_blocked=immutable_update_blocked,
        delete_blocked=immutable_delete_blocked,
    )

    config = client.get("/v1/subscriber/governance", headers=alpha_headers).json()
    denied_config = dict(config["config"])
    denied_config["private_worker_only"] = True
    private_worker_denied = client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": config["version"], "config": denied_config},
    )
    record(
        scenarios,
        "safe_plan_defaults",
        private_worker_denied.status_code == 403
        and private_worker_denied.json().get("detail")
        == "private_workers_not_entitled",
        status_code=private_worker_denied.status_code,
        detail=private_worker_denied.json().get("detail"),
        default_governance=config["config"],
    )

    revoked_key_id = read_key.removeprefix("ecf_live_").split(".", 1)[0]
    governance.revoke_api_key(alpha_principal, revoked_key_id)
    revoked = client.get(
        "/v1/subscriber/projects", headers=headers(alpha.organization_id, read_key)
    )
    record(
        scenarios,
        "api_key_lifecycle",
        revoked.status_code == 401 and revoked.json().get("detail") == "api_key_revoked",
        status_code=revoked.status_code,
        detail=revoked.json().get("detail"),
    )

    alpha_owner = governance.authenticate(
        alpha.bootstrap_api_key,
        tenant_hint=alpha.organization_id,
        permission=Permission.MEMBER_MANAGE,
        action="acceptance.member.manage",
    )
    member_id = governance.invite_member(
        alpha_owner,
        email="acceptance-member@p7-alpha.example",
        display_name="Acceptance Member",
        role=MemberRole.VIEWER,
    )
    activated = client.post(
        f"/v1/subscriber/members/{member_id}/activate",
        headers=alpha_headers,
    )
    member_key = governance.create_api_key(
        alpha_owner,
        name="acceptance-member",
        scopes={Permission.PROJECT_READ},
        expires_at=datetime.now(UTC) + timedelta(days=10),
        user_id=member_id,
    )
    deactivated = client.delete(
        f"/v1/subscriber/members/{member_id}",
        headers=alpha_headers,
    )
    member_denied = client.get(
        "/v1/subscriber/projects",
        headers=headers(alpha.organization_id, member_key),
    )
    record(
        scenarios,
        "member_lifecycle_revocation",
        activated.status_code == 204
        and deactivated.status_code == 204
        and member_denied.status_code == 401
        and member_denied.json().get("detail") == "api_key_revoked",
        activate_status=activated.status_code,
        deactivate_status=deactivated.status_code,
        revoked_status=member_denied.status_code,
    )

    enterprise = governance.provision_organization(
        slug="p7-enterprise",
        display_name="P7 Enterprise",
        owner_email="owner@p7-enterprise.example",
        owner_display_name="P7 Enterprise Owner",
        plan_code="enterprise",
        status=OrganizationStatus.ACTIVE,
    )
    enterprise_headers = headers(
        enterprise.organization_id, enterprise.bootstrap_api_key
    )
    lifecycle_project = client.post(
        "/v1/subscriber/projects",
        headers=enterprise_headers,
        json={
            "slug": "lifecycle-project",
            "name": "Lifecycle Project",
            "target_reference": "https://github.com/example/lifecycle-project",
        },
    )
    project_archived = client.delete(
        f"/v1/subscriber/projects/{lifecycle_project.json().get('project_id')}",
        headers=enterprise_headers,
    )
    lifecycle_worker = client.post(
        "/v1/subscriber/private-workers",
        headers=enterprise_headers,
        json={
            "display_name": "Lifecycle Worker",
            "attestation_sha256": digest("p7-lifecycle-worker"),
        },
    )
    worker_revoked = client.delete(
        f"/v1/subscriber/private-workers/{lifecycle_worker.json().get('worker_id')}",
        headers=enterprise_headers,
    )
    worker_state = client.get(
        "/v1/subscriber/private-workers", headers=enterprise_headers
    )
    record(
        scenarios,
        "resource_lifecycle_revocation",
        lifecycle_project.status_code == 201
        and project_archived.status_code == 204
        and lifecycle_worker.status_code == 201
        and worker_revoked.status_code == 204
        and worker_state.status_code == 200
        and worker_state.json()[0].get("status") == "REVOKED",
        project_archive_status=project_archived.status_code,
        worker_revoke_status=worker_revoked.status_code,
        worker_status=(
            worker_state.json()[0].get("status")
            if worker_state.status_code == 200 and worker_state.json()
            else None
        ),
    )

    expired = governance.provision_organization(
        slug="p7-expired",
        display_name="P7 Expired",
        owner_email="owner@p7-expired.example",
        owner_display_name="P7 Expired Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    expired_headers = headers(expired.organization_id, expired.bootstrap_api_key)
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions SET current_period_end = ?
            WHERE organization_id = ?
            """,
            (
                (datetime.now(UTC) - timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
                expired.organization_id,
            ),
        )
        connection.commit()
    expired_read = client.get(
        "/v1/subscriber/projects", headers=expired_headers
    )
    expired_write = client.post(
        "/v1/subscriber/projects",
        headers=expired_headers,
        json={
            "slug": "expired-write",
            "name": "Expired Write",
            "target_reference": "https://github.com/example/expired-write",
        },
    )
    record(
        scenarios,
        "expired_subscription_read_only",
        expired_read.status_code == 200
        and expired_write.status_code == 402
        and expired_write.json().get("detail") == "subscription_period_expired",
        read_status=expired_read.status_code,
        write_status=expired_write.status_code,
        detail=expired_write.json().get("detail"),
    )

    recovery = governance.provision_organization(
        slug="p7-recovery",
        display_name="P7 Recovery",
        owner_email="owner@p7-recovery.example",
        owner_display_name="P7 Recovery Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    recovery_headers = headers(
        recovery.organization_id, recovery.bootstrap_api_key
    )
    recovery_project = client.post(
        "/v1/subscriber/projects",
        headers=recovery_headers,
        json={
            "slug": "recovery-project",
            "name": "Recovery Project",
            "target_reference": "https://github.com/example/recovery-project",
        },
    ).json()
    recovery_principal = governance.authenticate(
        recovery.bootstrap_api_key,
        tenant_hint=recovery.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.recovery.reserve",
    )
    governance.reserve_certification_run(
        recovery_principal,
        project_id=recovery_project["project_id"],
        idempotency_key="p7-stale-reservation-0001",
        request_digest=digest("p7-stale-request"),
        policy_version=manifest.manifest_id,
    )
    stale_reservation_at = (
        datetime.now(UTC)
        - timedelta(seconds=policy.reservation_ttl_seconds + 1)
    ).isoformat().replace("+00:00", "Z")
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_reservations SET created_at = ?
            WHERE organization_id = ? AND idempotency_key = ?
            """,
            (
                stale_reservation_at,
                recovery.organization_id,
                "p7-stale-reservation-0001",
            ),
        )
        connection.commit()
    governance.reserve_certification_run(
        recovery_principal,
        project_id=recovery_project["project_id"],
        idempotency_key="p7-stale-reservation-0002",
        request_digest=digest("p7-replacement-request"),
        policy_version=manifest.manifest_id,
    )
    recovery_usage = governance.usage_summary(
        governance.authenticate(
            recovery.bootstrap_api_key,
            tenant_hint=recovery.organization_id,
            permission=Permission.USAGE_READ,
            action="acceptance.recovery.usage",
        )
    )
    record(
        scenarios,
        "stale_reservation_recovery",
        recovery_usage["meters"].get("certification_runs") == 1
        and recovery_usage["active_run_reservations"] == 1,
        usage=recovery_usage,
    )

    governance.apply_billing_event(
        organization_id=beta.organization_id,
        provider_event_id="p7-tenant-bound-event",
        event_type="payment.failed",
        payload={"invoice": "shared-event"},
        provider_occurred_at=billing_base,
        provider_sequence=1,
    )
    billing_conflict = None
    try:
        governance.apply_billing_event(
            organization_id=alpha.organization_id,
            provider_event_id="p7-tenant-bound-event",
            event_type="payment.failed",
            payload={"invoice": "shared-event"},
            provider_occurred_at=billing_base,
            provider_sequence=1,
        )
    except SubscriberError as exc:
        billing_conflict = exc.code
    record(
        scenarios,
        "billing_event_tenant_binding",
        billing_conflict == "billing_event_conflict",
        detail=billing_conflict,
    )

    beta_headers = headers(beta.organization_id, beta.bootstrap_api_key)
    for _ in range(policy.plan("developer").requests_per_minute):
        response = client.get("/v1/subscriber/me", headers=beta_headers)
        if response.status_code != 200:
            break
    rate_denied = client.get("/v1/subscriber/projects", headers=beta_headers)
    record(
        scenarios,
        "global_api_key_rate_limit",
        rate_denied.status_code == 429
        and rate_denied.json().get("detail") == "rate_limit_exceeded",
        status_code=rate_denied.status_code,
        detail=rate_denied.json().get("detail"),
        retry_after=rate_denied.headers.get("retry-after"),
    )

    worker_active = governance.provision_organization(
        slug="p7-worker-active",
        display_name="P7 Worker Active",
        owner_email="owner@p7-worker-active.example",
        owner_display_name="P7 Worker Active Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    worker_suspended = governance.provision_organization(
        slug="p7-worker-suspended",
        display_name="P7 Worker Suspended",
        owner_email="owner@p7-worker-suspended.example",
        owner_display_name="P7 Worker Suspended Owner",
        plan_code="developer",
        status=OrganizationStatus.SUSPENDED,
    )
    worker_source = workspace / "worker-source"
    worker_source.mkdir()
    worker_marker = workspace / "suspended-worker-executed"
    (worker_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(worker_marker)!r}).write_text('executed', encoding='utf-8')\n"
        "print('ok')\n",
        encoding="utf-8",
    )
    suspended_worker_result = run(
        "p7-worker-suspended",
        worker_suspended.organization_id,
        {"type": "local", "path": str(worker_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset({worker_suspended.organization_id}),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    active_worker_result = run(
        "p7-worker-retention",
        worker_active.organization_id,
        {"type": "local", "path": str(worker_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset(),
        subscribers=governance,
        journey=[sys.executable, "-c", "print('ok')"],
    )
    with closing(sqlite3.connect(db)) as connection:
        retention_rows = connection.execute(
            """
            SELECT retention_class, expires_at, created_at
            FROM evidence_retention
            WHERE run_id = ? AND tenant_id = ?
            """,
            ("p7-worker-retention", worker_active.organization_id),
        ).fetchall()
    retention_is_seven_days = bool(retention_rows) and all(
        row[0] == "subscriber-7d"
        and timedelta(days=6, hours=23)
        <= parse_utc_iso(row[1]) - parse_utc_iso(row[2])
        <= timedelta(days=7, minutes=1)
        for row in retention_rows
    )
    record(
        scenarios,
        "worker_entitlement_and_plan_retention",
        suspended_worker_result.get("state") == "INFRASTRUCTURE_FAILURE"
        and suspended_worker_result.get("signed") is False
        and not worker_marker.exists()
        and active_worker_result.get("state") == "COMPLETED"
        and retention_is_seven_days,
        suspended_state=suspended_worker_result.get("state"),
        active_state=active_worker_result.get("state"),
        retention_classes=sorted({row[0] for row in retention_rows}),
    )

    ordered = governance.provision_organization(
        slug="p7-billing-order",
        display_name="P7 Billing Order",
        owner_email="owner@p7-billing-order.example",
        owner_display_name="P7 Billing Order Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    ordered_at = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=ordered.organization_id,
        provider_event_id="p7-order-suspend",
        event_type="subscription.suspended",
        payload={"reason": "risk"},
        provider_occurred_at=ordered_at,
        provider_sequence=20,
    )
    stale_order_code = None
    try:
        governance.apply_billing_event(
            organization_id=ordered.organization_id,
            provider_event_id="p7-order-delayed-activate",
            event_type="subscription.activated",
            payload={"reason": "delayed"},
            provider_occurred_at=ordered_at - timedelta(minutes=5),
            provider_sequence=10,
        )
    except SubscriberError as exc:
        stale_order_code = exc.code
    with closing(sqlite3.connect(db)) as connection:
        ordered_status = connection.execute(
            "SELECT status FROM subscriber_organizations WHERE organization_id = ?",
            (ordered.organization_id,),
        ).fetchone()[0]
        rejected_order = connection.execute(
            """
            SELECT provider_sequence, processing_outcome
            FROM subscriber_billing_events WHERE provider_event_id = ?
            """,
            ("p7-order-delayed-activate",),
        ).fetchone()
    record(
        scenarios,
        "billing_provider_ordering",
        stale_order_code == "billing_event_stale"
        and ordered_status == OrganizationStatus.SUSPENDED.value
        and rejected_order == (10, "REJECTED_STALE"),
        detail=stale_order_code,
        organization_status=ordered_status,
        rejected_event=list(rejected_order) if rejected_order else None,
    )

    valid_governance_update = client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": config["version"], "config": config["config"]},
    )
    stale_governance_update = client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": config["version"], "config": config["config"]},
    )
    with closing(sqlite3.connect(db)) as connection:
        outcome_rows = connection.execute(
            """
            SELECT details_json FROM subscriber_audit_events
            WHERE organization_id = ? AND action = 'request.outcome'
              AND outcome = 'denied'
            """,
            (alpha.organization_id,),
        ).fetchall()
    denied_outcomes = {
        (details["path"], details["status_code"], details["reason"])
        for details in (json.loads(row[0]) for row in outcome_rows)
    }
    record(
        scenarios,
        "final_request_outcome_audit",
        valid_governance_update.status_code == 200
        and stale_governance_update.status_code == 409
        and ("/v1/subscriber/me", 404, "tenant_not_found") in denied_outcomes
        and (
            "/v1/certifications",
            429,
            "concurrent_run_quota_exceeded",
        )
        in denied_outcomes
        and (
            "/v1/subscriber/governance",
            403,
            "private_workers_not_entitled",
        )
        in denied_outcomes
        and (
            "/v1/subscriber/governance",
            409,
            "governance_version_conflict",
        )
        in denied_outcomes,
        denied_outcomes=sorted([list(item) for item in denied_outcomes]),
    )

    cycle = governance.provision_organization(
        slug="p7-billing-cycle",
        display_name="P7 Billing Cycle",
        owner_email="owner@p7-billing-cycle.example",
        owner_display_name="P7 Billing Cycle Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    cycle_headers = headers(cycle.organization_id, cycle.bootstrap_api_key)
    cycle_project = client.post(
        "/v1/subscriber/projects",
        headers=cycle_headers,
        json={
            "slug": "billing-cycle",
            "name": "Billing Cycle",
            "target_reference": "https://github.com/example/billing-cycle",
        },
    ).json()
    cycle_principal = governance.authenticate(
        cycle.bootstrap_api_key,
        tenant_hint=cycle.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.billing-cycle.reserve",
    )
    cycle_now = datetime.now(UTC)
    month_start = cycle_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    prior_month_usage = month_start - timedelta(days=1)
    cycle_start = prior_month_usage - timedelta(days=1)
    cycle_end = cycle_now + timedelta(days=40)
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions
            SET current_period_start = ?, current_period_end = ?
            WHERE organization_id = ?
            """,
            (
                cycle_start.isoformat().replace("+00:00", "Z"),
                cycle_end.isoformat().replace("+00:00", "Z"),
                cycle.organization_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO subscriber_usage_events(
                organization_id, meter, quantity, idempotency_key,
                metadata_json, occurred_at
            ) VALUES (?, 'certification_runs', ?, 'prior-calendar-month', '{}', ?)
            """,
            (
                cycle.organization_id,
                policy.plan("developer").monthly_certification_runs,
                prior_month_usage.isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.commit()
    cross_month_code = None
    try:
        governance.reserve_certification_run(
            cycle_principal,
            project_id=cycle_project["project_id"],
            idempotency_key="p7-cross-month-denied",
            request_digest=digest("p7-cross-month-denied"),
            policy_version=manifest.manifest_id,
        )
    except SubscriberError as exc:
        cross_month_code = exc.code
    cycle_usage = governance.usage_summary(
        governance.authenticate(
            cycle.bootstrap_api_key,
            tenant_hint=cycle.organization_id,
            permission=Permission.USAGE_READ,
            action="acceptance.billing-cycle.usage",
        )
    )
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions
            SET current_period_start = ?, current_period_end = ?
            WHERE organization_id = ?
            """,
            (
                month_start.isoformat().replace("+00:00", "Z"),
                cycle_end.isoformat().replace("+00:00", "Z"),
                cycle.organization_id,
            ),
        )
        connection.commit()
    rollover = governance.reserve_certification_run(
        cycle_principal,
        project_id=cycle_project["project_id"],
        idempotency_key="p7-new-cycle-allowed",
        request_digest=digest("p7-new-cycle-allowed"),
        policy_version=manifest.manifest_id,
    )
    record(
        scenarios,
        "authoritative_billing_period_quota",
        cross_month_code == "monthly_run_quota_exceeded"
        and cycle_usage["meters"].get("certification_runs")
        == policy.plan("developer").monthly_certification_runs
        and cycle_usage["period_started_at"]
        == cycle_start.isoformat().replace("+00:00", "Z")
        and cycle_usage["period_ended_at"]
        == cycle_end.isoformat().replace("+00:00", "Z")
        and rollover.created,
        detail=cross_month_code,
        usage=cycle_usage,
        rollover_created=rollover.created,
    )

    record(
        scenarios,
        "versioned_policy_contract",
        contract.get("schema_version") == policy.schema_version
        and contract.get("contract_id") == "certforge.subscriber-governance.v1"
        and contract.get("authentication", {}).get("denied_request_audit_required")
        is True,
        contract_id=contract.get("contract_id"),
        schema_version=contract.get("schema_version"),
    )

    report = {
        "schema_version": "1.0.0",
        "phase": "P7",
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "python": sys.version,
        "platform": platform.platform(),
        "policy_id": policy.policy_id,
        "contract_id": contract["contract_id"],
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.digest,
        "scenarios": scenarios,
        "passed": all(item["passed"] for item in scenarios.values()),
        "release_verdict": "NOT_READY",
        "release_note": "P7 completion does not override unresolved P5/P6 and hosted-CI blockers.",
    }
    output = REPO / "artifacts" / "p7_acceptance_report.json"
    output.write_bytes(
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    client.close()
    shutil.rmtree(workspace)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
