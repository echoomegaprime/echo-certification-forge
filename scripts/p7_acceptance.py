"""Reproducible P7 subscriber-governance acceptance evidence generator."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sqlite3
import sys
import threading
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from echo_certification_forge.acquisition import acquire_target
from echo_certification_forge.canonical import parse_utc_iso
from echo_certification_forge.dispatch_worker import dispatch_once
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.intake import SubmitRequest
from echo_certification_forge.models import TargetIdentity
from echo_certification_forge.run_worker import _worker_environment, run
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


def submit_local_run(
    client: TestClient,
    manifest: RuleManifest,
    organization_id: str,
    api_key: str,
    source: Path,
    *,
    key: str,
    journey: list[str] | None = None,
) -> tuple[str, TargetIdentity]:
    project = client.post(
        "/v1/subscriber/projects",
        headers=headers(organization_id, api_key),
        json={
            "slug": f"local-{key[-6:]}",
            "name": f"Local {key}",
            "target_reference": source.resolve(strict=False).as_posix(),
        },
    )
    if project.status_code != 201:
        raise RuntimeError(f"local project setup failed: {project.text}")
    acquired = acquire_target(
        {"type": "local", "path": str(source)},
        source.parent / ".unused-acquisition-destination",
    )
    target = TargetIdentity(
        tenant_id=organization_id,
        target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref,
        artifact_sha256=acquired.artifact_sha256,
    )
    environment = _worker_environment()
    payload = {
        "tenant_id": organization_id,
        "project_id": project.json()["project_id"],
        "target": {
            "target_type": "local",
            "identity_digest": target.identity_digest,
            "reference": target.canonical_ref,
        },
        "environment": {
            "identity_digest": environment.identity_digest,
            "runner_image_digest": "sha256:" + environment.runner_image_sha256,
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": key,
    }
    if journey is not None:
        payload["journey"] = journey
    response = client.post(
        "/v1/certifications",
        headers=headers(organization_id, api_key),
        json=payload,
    )
    if response.status_code != 201:
        raise RuntimeError(f"local run setup failed: {response.text}")
    return str(response.json()["run_id"]), target


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
        payload={
            "invoice": "p7-invoice",
            "paid": True,
            "current_period_start": (billing_base - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z"),
            "current_period_end": (billing_base + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        },
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
        status=OrganizationStatus.ACTIVE,
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
    active_worker_run_id, _active_target = submit_local_run(
        client,
        manifest,
        worker_active.organization_id,
        worker_active.bootstrap_api_key,
        worker_source,
        key="p7-worker-retention-0001",
    )
    suspended_worker_run_id, _suspended_target = submit_local_run(
        client,
        manifest,
        worker_suspended.organization_id,
        worker_suspended.bootstrap_api_key,
        worker_source,
        key="p7-worker-suspended-0001",
    )
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            "UPDATE subscriber_organizations SET status = 'SUSPENDED' "
            "WHERE organization_id = ?",
            (worker_suspended.organization_id,),
        )
        connection.execute(
            "UPDATE subscriber_subscriptions SET status = 'SUSPENDED' "
            "WHERE organization_id = ?",
            (worker_suspended.organization_id,),
        )
        connection.commit()
    suspended_worker_result = run(
        suspended_worker_run_id,
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
        active_worker_run_id,
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
            (active_worker_run_id, worker_active.organization_id),
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
        suspended_worker_result.get("error") == "subscriber_worker_claim_denied"
        and suspended_worker_result.get("detail") == "subscriber_not_entitled"
        and not worker_marker.exists()
        and active_worker_result.get("state") == "COMPLETED"
        and retention_is_seven_days,
        suspended_state=suspended_worker_result.get("state"),
        active_state=active_worker_result.get("state"),
        retention_classes=sorted({row[0] for row in retention_rows}),
    )

    direct_worker = run(
        "p7-direct-unreserved",
        worker_active.organization_id,
        {"type": "local", "path": str(workspace / "missing-source")},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
    )
    claim_org = governance.provision_organization(
        slug="p7-worker-claim",
        display_name="P7 Worker Claim",
        owner_email="owner@p7-worker-claim.example",
        owner_display_name="P7 Worker Claim Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    claim_run_id, claim_target = submit_local_run(
        client,
        manifest,
        claim_org.organization_id,
        claim_org.bootstrap_api_key,
        worker_source,
        key="p7-worker-claim-0001",
    )
    claim_signer = Ed25519VerdictSigner.generate()
    worker_claim = governance.claim_worker_run(
        run_id=claim_run_id,
        organization_id=claim_org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=claim_target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=claim_signer.key_id,
    )
    duplicate_claim_code = None
    try:
        governance.claim_worker_run(
            run_id=claim_run_id,
            organization_id=claim_org.organization_id,
            policy_version=manifest.manifest_id,
            target_type="local",
            target_reference=claim_target.canonical_ref,
            worker_id=None,
            worker_attestation_sha256=None,
            execution_location="local",
            signing_authority="platform",
            signing_key_id=claim_signer.key_id,
        )
    except SubscriberError as exc:
        duplicate_claim_code = exc.code
    governance.finish_worker_claim(worker_claim, reason="acceptance_complete")
    claim_cleanup = client.post(
        f"/v1/certifications/{claim_run_id}/cancel",
        headers=headers(claim_org.organization_id, claim_org.bootstrap_api_key),
    )
    record(
        scenarios,
        "strict_worker_reservation_claim",
        direct_worker.get("error") == "subscriber_worker_claim_denied"
        and direct_worker.get("detail") == "worker_run_reservation_missing"
        and duplicate_claim_code == "worker_run_already_claimed"
        and claim_cleanup.status_code == 200,
        direct_invocation=direct_worker,
        duplicate_claim_code=duplicate_claim_code,
        cleanup_status=claim_cleanup.status_code,
    )

    controlled = governance.provision_organization(
        slug="p7-worker-controls",
        display_name="P7 Worker Controls",
        owner_email="owner@p7-worker-controls.example",
        owner_display_name="P7 Worker Controls Owner",
        plan_code="sovereign",
        status=OrganizationStatus.ACTIVE,
    )
    controlled_governance = governance.authenticate(
        controlled.bootstrap_api_key,
        tenant_hint=controlled.organization_id,
        permission=Permission.GOVERNANCE_MANAGE,
        action="acceptance.worker-controls.governance",
    )
    controlled_workers = governance.authenticate(
        controlled.bootstrap_api_key,
        tenant_hint=controlled.organization_id,
        permission=Permission.PRIVATE_WORKER_MANAGE,
        action="acceptance.worker-controls.worker",
    )
    controlled_signer = Ed25519VerdictSigner.generate()
    controlled_config = governance.governance_config(controlled_governance)
    next_controlled_config = dict(controlled_config["config"])
    next_controlled_config.update(
        {
            "private_worker_only": True,
            "customer_managed_signing": True,
            "customer_signing_key_id": controlled_signer.key_id,
        }
    )
    governance.update_governance(
        controlled_governance,
        next_controlled_config,
        expected_version=controlled_config["version"],
    )
    controlled_attestation = digest("p7-controlled-worker")
    controlled_worker = governance.register_private_worker(
        controlled_workers,
        display_name="P7 Controlled Worker",
        attestation_sha256=controlled_attestation,
    )
    controlled_run_id, _controlled_target = submit_local_run(
        client,
        manifest,
        controlled.organization_id,
        controlled.bootstrap_api_key,
        worker_source,
        key="p7-worker-controls-0001",
    )
    wrong_identity = run(
        controlled_run_id,
        controlled.organization_id,
        {"type": "local", "path": str(worker_source)},
        store=store,
        manifest=manifest,
        signer=controlled_signer,
        subscribers=governance,
        worker_id=controlled_worker["worker_id"],
        worker_attestation_sha256=digest("p7-wrong-worker"),
        execution_location="local",
        signing_authority="customer",
    )
    wrong_location = run(
        controlled_run_id,
        controlled.organization_id,
        {"type": "local", "path": str(worker_source)},
        store=store,
        manifest=manifest,
        signer=controlled_signer,
        subscribers=governance,
        worker_id=controlled_worker["worker_id"],
        worker_attestation_sha256=controlled_attestation,
        execution_location="remote",
        signing_authority="customer",
    )
    wrong_signer = run(
        controlled_run_id,
        controlled.organization_id,
        {"type": "local", "path": str(worker_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        worker_id=controlled_worker["worker_id"],
        worker_attestation_sha256=controlled_attestation,
        execution_location="local",
        signing_authority="platform",
    )
    rejected_platform_dispatch, _ = dispatch_once(
        governance,
        run,
        dispatcher_id="p7-platform-dispatcher",
        run_id=controlled_run_id,
        organization_id=controlled.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": Ed25519VerdictSigner.generate(),
            "subscribers": governance,
        },
    )
    accepted_controlled_dispatch, controlled_result = dispatch_once(
        governance,
        run,
        dispatcher_id="p7-customer-dispatcher",
        run_id=controlled_run_id,
        organization_id=controlled.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": controlled_signer,
            "subscribers": governance,
            "worker_id": controlled_worker["worker_id"],
            "worker_attestation_sha256": controlled_attestation,
            "execution_location": "local",
            "signing_authority": "customer",
        },
    )
    record(
        scenarios,
        "persisted_execution_governance_controls",
        wrong_identity.get("detail") == "private_worker_identity_invalid"
        and wrong_location.get("detail") == "local_execution_required"
        and wrong_signer.get("detail") == "customer_signing_authority_required"
        and rejected_platform_dispatch is None
        and accepted_controlled_dispatch is not None
        and controlled_result is not None
        and controlled_result.get("state") == "COMPLETED"
        and controlled_result.get("signer_public_key_id") == controlled_signer.key_id,
        private_worker_denial=wrong_identity.get("detail"),
        execution_location_denial=wrong_location.get("detail"),
        signing_denial=wrong_signer.get("detail"),
        platform_dispatch_claimed=rejected_platform_dispatch is not None,
        positive_state=controlled_result.get("state") if controlled_result else None,
    )

    race_org = governance.provision_organization(
        slug="p7-authorization-race",
        display_name="P7 Authorization Race",
        owner_email="owner@p7-authorization-race.example",
        owner_display_name="P7 Authorization Race Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    race_principal = governance.authenticate(
        race_org.bootstrap_api_key,
        tenant_hint=race_org.organization_id,
        permission=Permission.PROJECT_MANAGE,
        action="acceptance.authorization-race",
    )
    original_require = governance.require

    def suspend_after_authorization(candidate, permission):
        original_require(candidate, permission)
        with closing(sqlite3.connect(db)) as connection:
            connection.execute(
                "UPDATE subscriber_organizations SET status = 'SUSPENDED' "
                "WHERE organization_id = ?",
                (race_org.organization_id,),
            )
            connection.execute(
                "UPDATE subscriber_subscriptions SET status = 'SUSPENDED' "
                "WHERE organization_id = ?",
                (race_org.organization_id,),
            )
            connection.commit()

    governance.require = suspend_after_authorization  # type: ignore[method-assign]
    race_code = None
    try:
        governance.create_project(
            race_principal,
            slug="raced",
            name="Raced",
            target_reference="https://github.com/example/raced",
        )
    except SubscriberError as exc:
        race_code = exc.code
    finally:
        governance.require = original_require  # type: ignore[method-assign]
    with closing(sqlite3.connect(db)) as connection:
        raced_projects = connection.execute(
            "SELECT COUNT(*) FROM subscriber_projects WHERE organization_id = ?",
            (race_org.organization_id,),
        ).fetchone()[0]
    record(
        scenarios,
        "transactional_mutation_authorization",
        race_code == "organization_suspended" and raced_projects == 0,
        detail=race_code,
        mutated_projects=raced_projects,
    )

    downgrade = governance.provision_organization(
        slug="p7-plan-downgrade",
        display_name="P7 Plan Downgrade",
        owner_email="owner@p7-plan-downgrade.example",
        owner_display_name="P7 Plan Downgrade Owner",
        plan_code="enterprise",
        status=OrganizationStatus.ACTIVE,
    )
    downgrade_principal = governance.authenticate(
        downgrade.bootstrap_api_key,
        tenant_hint=downgrade.organization_id,
        permission=Permission.GOVERNANCE_MANAGE,
        action="acceptance.plan-downgrade",
    )
    downgrade_config = governance.governance_config(downgrade_principal)
    premium_config = dict(downgrade_config["config"])
    premium_config.update(
        {
            "retention_days": 700,
            "private_worker_only": True,
            "customer_managed_signing": True,
            "customer_signing_key_id": Ed25519VerdictSigner.generate().key_id,
        }
    )
    governance.update_governance(
        downgrade_principal,
        premium_config,
        expected_version=downgrade_config["version"],
    )
    before_downgrade = governance.governance_config(downgrade_principal)
    downgrade_at = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=downgrade.organization_id,
        provider_event_id="p7-plan-downgrade-event",
        event_type="subscription.plan_changed",
        payload={
            "current_period_start": downgrade_at.isoformat().replace("+00:00", "Z"),
            "current_period_end": (downgrade_at + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        },
        provider_occurred_at=downgrade_at,
        provider_sequence=1,
        plan_code="developer",
    )
    after_downgrade = governance.governance_config(downgrade_principal)
    record(
        scenarios,
        "atomic_plan_downgrade_reconciliation",
        after_downgrade["version"] == before_downgrade["version"] + 1
        and after_downgrade["config"]["retention_days"] == 14
        and after_downgrade["config"]["private_worker_only"] is False
        and after_downgrade["config"]["customer_managed_signing"] is False
        and after_downgrade["config"]["customer_signing_key_id"] is None
        and governance.retention_days(downgrade.organization_id) == 14,
        version=after_downgrade["version"],
        governance=after_downgrade["config"],
    )

    required_period = governance.provision_organization(
        slug="p7-period-required",
        display_name="P7 Period Required",
        owner_email="owner@p7-period-required.example",
        owner_display_name="P7 Period Required Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    with closing(sqlite3.connect(db)) as connection:
        period_before = connection.execute(
            """
            SELECT plan_code, status, current_period_start, current_period_end
            FROM subscriber_subscriptions WHERE organization_id = ?
            """,
            (required_period.organization_id,),
        ).fetchone()
    missing_period_code = None
    invalid_period_code = None
    try:
        governance.apply_billing_event(
            organization_id=required_period.organization_id,
            provider_event_id="p7-period-missing",
            event_type="subscription.renewed",
            payload={},
            provider_occurred_at=datetime.now(UTC),
            provider_sequence=1,
        )
    except SubscriberError as exc:
        missing_period_code = exc.code
    try:
        governance.apply_billing_event(
            organization_id=required_period.organization_id,
            provider_event_id="p7-period-invalid",
            event_type="subscription.plan_changed",
            payload={
                "current_period_start": "2026-08-02T00:00:00Z",
                "current_period_end": "2026-08-01T00:00:00Z",
            },
            provider_occurred_at=datetime.now(UTC),
            provider_sequence=2,
            plan_code="professional",
        )
    except SubscriberError as exc:
        invalid_period_code = exc.code
    with closing(sqlite3.connect(db)) as connection:
        period_after = connection.execute(
            """
            SELECT plan_code, status, current_period_start, current_period_end
            FROM subscriber_subscriptions WHERE organization_id = ?
            """,
            (required_period.organization_id,),
        ).fetchone()
        invalid_period_events = connection.execute(
            """
            SELECT COUNT(*) FROM subscriber_billing_events
            WHERE provider_event_id IN ('p7-period-missing', 'p7-period-invalid')
            """
        ).fetchone()[0]
    record(
        scenarios,
        "required_billing_periods",
        missing_period_code == "billing_period_required"
        and invalid_period_code == "billing_period_invalid"
        and period_before == period_after
        and invalid_period_events == 0,
        missing_period_code=missing_period_code,
        invalid_period_code=invalid_period_code,
        prior_state=list(period_before),
        resulting_state=list(period_after),
    )

    audit_errors = governance.provision_organization(
        slug="p7-audit-errors",
        display_name="P7 Audit Errors",
        owner_email="owner@p7-audit-errors.example",
        owner_display_name="P7 Audit Errors Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    audit_error_headers = headers(
        audit_errors.organization_id, audit_errors.bootstrap_api_key
    )
    validation_error = client.get(
        "/v1/subscriber/audit",
        headers=audit_error_headers,
        params={"limit": 0},
    )
    original_list_policy_packs = governance.list_policy_packs

    def explode_policy_list(_principal):
        raise RuntimeError("acceptance unhandled error")

    governance.list_policy_packs = explode_policy_list  # type: ignore[method-assign]
    try:
        unhandled_error = client.get(
            "/v1/subscriber/policy-packs",
            headers=audit_error_headers,
        )
    finally:
        governance.list_policy_packs = original_list_policy_packs  # type: ignore[method-assign]
    with closing(sqlite3.connect(db)) as connection:
        error_outcomes = connection.execute(
            """
            SELECT outcome, details_json FROM subscriber_audit_events
            WHERE organization_id = ? AND action = 'request.outcome'
            ORDER BY event_id DESC LIMIT 2
            """,
            (audit_errors.organization_id,),
        ).fetchall()
    audited_errors = {
        (
            json.loads(row[1])["path"],
            row[0],
            json.loads(row[1])["status_code"],
            json.loads(row[1])["reason"],
        )
        for row in error_outcomes
    }
    record(
        scenarios,
        "audited_validation_and_unhandled_errors",
        validation_error.status_code == 422
        and unhandled_error.status_code == 500
        and (
            "/v1/subscriber/audit",
            "denied",
            422,
            "request_validation_error",
        )
        in audited_errors
        and (
            "/v1/subscriber/policy-packs",
            "error",
            500,
            "unhandled_exception",
        )
        in audited_errors,
        validation_status=validation_error.status_code,
        unhandled_status=unhandled_error.status_code,
        audited_outcomes=sorted([list(item) for item in audited_errors]),
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
            payload={
                "reason": "delayed",
                "current_period_start": (ordered_at - timedelta(days=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "current_period_end": (ordered_at + timedelta(days=29))
                .isoformat()
                .replace("+00:00", "Z"),
            },
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

    dispatch_org = governance.provision_organization(
        slug="p7-durable-dispatch",
        display_name="P7 Durable Dispatch",
        owner_email="owner@p7-durable-dispatch.example",
        owner_display_name="P7 Durable Dispatch Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    dispatch_source = workspace / "dispatch-source"
    dispatch_source.mkdir()
    dispatch_marker = workspace / "dispatch-executed"
    (dispatch_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(dispatch_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    dispatch_journey = [sys.executable, "journey.py"]
    dispatch_run_id, _dispatch_target = submit_local_run(
        client,
        manifest,
        dispatch_org.organization_id,
        dispatch_org.bootstrap_api_key,
        dispatch_source,
        key="p7-durable-dispatch-0001",
        journey=dispatch_journey,
    )
    abandoned_dispatch = governance.claim_dispatch(
        "p7-abandoned-dispatcher",
        run_id=dispatch_run_id,
        organization_id=dispatch_org.organization_id,
    )
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE run_id = ? AND organization_id = ?
            """,
            (dispatch_run_id, dispatch_org.organization_id),
        )
        connection.commit()
    dispatched, dispatch_result = dispatch_once(
        governance,
        run,
        dispatcher_id="p7-acceptance-dispatcher",
        run_id=dispatch_run_id,
        organization_id=dispatch_org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": Ed25519VerdictSigner.generate(),
            "subscribers": governance,
        },
    )
    dispatch_state = governance.dispatch_status(
        dispatch_run_id, dispatch_org.organization_id
    )
    record(
        scenarios,
        "durable_exact_run_dispatch",
        abandoned_dispatch is not None
        and dispatched is not None
        and dispatched.run_id == dispatch_run_id
        and dispatched.attempts == 2
        and dispatched.journey == dispatch_journey
        and dispatch_result is not None
        and dispatch_result.get("state") == "COMPLETED"
        and dispatch_state["state"] == "COMPLETE"
        and dispatch_marker.exists(),
        run_id=dispatch_run_id,
        dispatch_attempts=dispatched.attempts if dispatched else None,
        dispatch_state=dispatch_state["state"],
        worker_state=dispatch_result.get("state") if dispatch_result else None,
    )

    intake_org = governance.provision_organization(
        slug="p7-durable-intake",
        display_name="P7 Durable Intake",
        owner_email="owner@p7-durable-intake.example",
        owner_display_name="P7 Durable Intake Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    intake_project_response = client.post(
        "/v1/subscriber/projects",
        headers=headers(intake_org.organization_id, intake_org.bootstrap_api_key),
        json={
            "slug": "durable-intake-app",
            "name": "Durable Intake App",
            "target_reference": "local:durable-intake",
        },
    )
    intake_source = workspace / "durable-intake-source"
    intake_source.mkdir()
    intake_marker = workspace / "durable-intake-executed"
    (intake_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(intake_marker)!r}).write_text('recovered', encoding='utf-8')\n",
        encoding="utf-8",
    )
    intake_acquired = acquire_target(
        {"type": "local", "path": str(intake_source)},
        workspace / ".unused-durable-intake-acquisition",
    )
    intake_target = TargetIdentity(
        tenant_id=intake_org.organization_id,
        target_type=intake_acquired.target_type,
        canonical_ref=intake_acquired.canonical_ref,
        artifact_sha256=intake_acquired.artifact_sha256,
    )
    intake_request = SubmitRequest.model_validate(
        {
            "tenant_id": intake_org.organization_id,
            "project_id": intake_project_response.json()["project_id"],
            "target": {
                "target_type": "local",
                "identity_digest": intake_target.identity_digest,
                "reference": intake_acquired.canonical_ref,
                "path": intake_source.resolve().as_posix(),
            },
            "environment": {
                "identity_digest": _worker_environment().identity_digest,
                "runner_image_digest": "sha256:"
                + _worker_environment().runner_image_sha256,
            },
            "policy_version": manifest.manifest_id,
            "idempotency_key": "p7-durable-intake-0001",
            "journey": [sys.executable, "journey.py"],
        }
    )
    intake_principal = governance.authenticate(
        intake_org.bootstrap_api_key,
        tenant_hint=intake_org.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.durable-intake.reserve",
    )
    intake_reservation = governance.reserve_certification_run(
        intake_principal,
        project_id=str(intake_request.project_id),
        idempotency_key=intake_request.idempotency_key,
        request_digest=intake_request.request_digest(),
        policy_version=intake_request.policy_version,
        target_type=intake_request.target.target_type,
        target_reference=intake_request.target.reference,
        target_identity_digest=intake_request.target.identity_digest,
        dispatch_target_spec=intake_request.target.worker_spec(),
        journey=intake_request.journey,
        submit_request=intake_request.model_dump(exclude_none=True),
    )
    recovered_dispatch, recovered_result = dispatch_once(
        governance,
        run,
        dispatcher_id="p7-durable-intake-dispatcher",
        run_id=intake_request.run_id(manifest.digest),
        organization_id=intake_org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": Ed25519VerdictSigner.generate(),
            "subscribers": governance,
        },
    )
    record(
        scenarios,
        "durable_intake_crash_gap_recovery",
        intake_project_response.status_code == 201
        and intake_reservation.created
        and recovered_dispatch is not None
        and recovered_dispatch.run_id == intake_request.run_id(manifest.digest)
        and recovered_result is not None
        and recovered_result.get("state") == "COMPLETED"
        and intake_marker.exists()
        and governance.pending_intake_requests() == [],
        run_id=intake_request.run_id(manifest.digest),
        dispatch_state=(
            governance.dispatch_status(
                intake_request.run_id(manifest.digest), intake_org.organization_id
            )["state"]
            if recovered_dispatch
            else None
        ),
        worker_state=recovered_result.get("state") if recovered_result else None,
    )

    crash_org = governance.provision_organization(
        slug="p7-lease-recovery",
        display_name="P7 Lease Recovery",
        owner_email="owner@p7-lease-recovery.example",
        owner_display_name="P7 Lease Recovery Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    crash_run_id, crash_target = submit_local_run(
        client,
        manifest,
        crash_org.organization_id,
        crash_org.bootstrap_api_key,
        worker_source,
        key="p7-lease-recovery-0001",
    )
    crash_dispatch = governance.claim_dispatch(
        "p7-crash-dispatcher",
        run_id=crash_run_id,
        organization_id=crash_org.organization_id,
    )
    crash_signer = Ed25519VerdictSigner.generate()
    crash_claim = governance.claim_worker_run(
        run_id=crash_run_id,
        organization_id=crash_org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=crash_target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=crash_signer.key_id,
    )
    governance.authorize_worker_execution(
        crash_claim,
        target_identity=crash_target.to_dict(),
        target_identity_digest=crash_target.identity_digest,
        environment_identity=_worker_environment().to_dict(),
        environment_identity_digest=_worker_environment().identity_digest,
    )
    heartbeat_expiry = governance.heartbeat_worker_claim(crash_claim)
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_reservations
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE organization_id = ? AND run_id = ?
            """,
            (crash_org.organization_id, crash_run_id),
        )
        connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE organization_id = ? AND run_id = ?
            """,
            (crash_org.organization_id, crash_run_id),
        )
        connection.commit()
    recovered = governance.recover_expired_claims(crash_org.organization_id)
    crash_usage = governance.usage_summary(
        governance.authenticate(
            crash_org.bootstrap_api_key,
            tenant_hint=crash_org.organization_id,
            permission=Permission.USAGE_READ,
            action="acceptance.lease-recovery.usage",
        )
    )
    crash_run = store.get_run(crash_run_id, crash_org.organization_id)
    crash_dispatch_state = governance.dispatch_status(
        crash_run_id, crash_org.organization_id
    )["state"]
    record(
        scenarios,
        "leased_worker_heartbeat_crash_recovery",
        crash_dispatch is not None
        and parse_utc_iso(heartbeat_expiry) > datetime.now(UTC)
        and recovered == 1
        and crash_run["state"] == "INFRASTRUCTURE_FAILURE"
        and crash_dispatch_state == "FAILED"
        and crash_usage["meters"].get("certification_runs") == 0
        and crash_usage["active_run_reservations"] == 0,
        heartbeat_expiry=heartbeat_expiry,
        recovered_claims=recovered,
        run_state=crash_run["state"],
        dispatch_state=crash_dispatch_state,
        usage=crash_usage,
    )

    prestart_org = governance.provision_organization(
        slug="p7-prestart-recovery",
        display_name="P7 Prestart Recovery",
        owner_email="owner@p7-prestart-recovery.example",
        owner_display_name="P7 Prestart Recovery Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    prestart_run_id, prestart_target = submit_local_run(
        client,
        manifest,
        prestart_org.organization_id,
        prestart_org.bootstrap_api_key,
        worker_source,
        key="p7-prestart-recovery-0001",
    )
    prestart_dispatch = governance.claim_dispatch(
        "p7-prestart-dispatcher",
        run_id=prestart_run_id,
        organization_id=prestart_org.organization_id,
    )
    prestart_claim = governance.claim_worker_run(
        run_id=prestart_run_id,
        organization_id=prestart_org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=prestart_target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=Ed25519VerdictSigner.generate().key_id,
    )
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_reservations
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE run_id = ? AND organization_id = ?
            """,
            (prestart_run_id, prestart_org.organization_id),
        )
        connection.commit()
    prestart_recovered = governance.recover_expired_claims(
        prestart_org.organization_id
    )
    prestart_usage = governance.usage_summary(
        governance.authenticate(
            prestart_org.bootstrap_api_key,
            tenant_hint=prestart_org.organization_id,
            permission=Permission.USAGE_READ,
            action="acceptance.prestart-recovery.usage",
        )
    )
    record(
        scenarios,
        "expired_prestart_claim_requeue",
        prestart_dispatch is not None
        and prestart_claim.run_id == prestart_run_id
        and prestart_recovered == 1
        and store.get_run(prestart_run_id, prestart_org.organization_id)["state"]
        == "QUEUED"
        and governance.dispatch_status(
            prestart_run_id, prestart_org.organization_id
        )["state"]
        == "PENDING"
        and prestart_usage["meters"].get("certification_runs") == 1
        and prestart_usage["active_run_reservations"] == 1,
        recovered_claims=prestart_recovered,
        usage=prestart_usage,
    )

    plan_change_at = ordered_at + timedelta(minutes=1)
    preserved_status = governance.apply_billing_event(
        organization_id=ordered.organization_id,
        provider_event_id="p7-suspended-plan-change",
        event_type="subscription.plan_changed",
        payload={
            "current_period_start": plan_change_at.isoformat().replace("+00:00", "Z"),
            "current_period_end": (plan_change_at + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        },
        provider_occurred_at=plan_change_at,
        provider_sequence=21,
        plan_code="professional",
    )
    with closing(sqlite3.connect(db)) as connection:
        preserved_plan = connection.execute(
            """
            SELECT o.status, s.status, s.plan_code
            FROM subscriber_organizations o
            JOIN subscriber_subscriptions s USING (organization_id)
            WHERE o.organization_id = ?
            """,
            (ordered.organization_id,),
        ).fetchone()
    record(
        scenarios,
        "plan_change_preserves_suspension",
        preserved_status is OrganizationStatus.SUSPENDED
        and preserved_plan
        == (
            OrganizationStatus.SUSPENDED.value,
            OrganizationStatus.SUSPENDED.value,
            "professional",
        ),
        lifecycle_status=preserved_status.value,
        persisted=list(preserved_plan),
    )

    boundary_org = governance.provision_organization(
        slug="p7-execution-boundary",
        display_name="P7 Execution Boundary",
        owner_email="owner@p7-execution-boundary.example",
        owner_display_name="P7 Execution Boundary Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    boundary_marker = workspace / "boundary-executed"
    boundary_source = workspace / "boundary-source"
    boundary_source.mkdir()
    (boundary_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(boundary_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    boundary_run_id, _boundary_target = submit_local_run(
        client,
        manifest,
        boundary_org.organization_id,
        boundary_org.bootstrap_api_key,
        boundary_source,
        key="p7-execution-boundary-0001",
    )
    boundary_entered = threading.Event()
    boundary_release = threading.Event()
    boundary_authorize = governance.authorize_worker_execution

    def wait_at_execution_boundary(claim, **identity):
        boundary_entered.set()
        if not boundary_release.wait(timeout=10):
            raise RuntimeError("execution boundary synchronization failed")
        return boundary_authorize(claim, **identity)

    governance.authorize_worker_execution = wait_at_execution_boundary  # type: ignore[method-assign]
    boundary_result: dict[str, Any] = {}

    def execute_boundary_run() -> None:
        boundary_result.update(
            run(
                boundary_run_id,
                boundary_org.organization_id,
                {"type": "local", "path": str(boundary_source)},
                store=store,
                manifest=manifest,
                signer=Ed25519VerdictSigner.generate(),
                subscribers=governance,
                journey=[sys.executable, "journey.py"],
            )
        )

    boundary_thread = threading.Thread(target=execute_boundary_run)
    boundary_thread.start()
    boundary_reached = boundary_entered.wait(timeout=10)
    if boundary_reached:
        governance.apply_billing_event(
            organization_id=boundary_org.organization_id,
            provider_event_id="p7-boundary-suspension",
            event_type="subscription.suspended",
            payload={"reason": "risk"},
            provider_occurred_at=datetime.now(UTC),
            provider_sequence=1,
        )
    boundary_release.set()
    boundary_thread.join(timeout=15)
    governance.authorize_worker_execution = boundary_authorize  # type: ignore[method-assign]
    record(
        scenarios,
        "suspension_wins_execution_boundary",
        boundary_reached
        and not boundary_thread.is_alive()
        and boundary_result.get("error") == "subscriber_execution_denied"
        and boundary_result.get("state") == "CANCELLED"
        and not boundary_marker.exists(),
        boundary_reached=boundary_reached,
        worker_result=boundary_result,
        customer_code_executed=boundary_marker.exists(),
    )

    identity_org = governance.provision_organization(
        slug="p7-identity-reconciliation",
        display_name="P7 Identity Reconciliation",
        owner_email="owner@p7-identity-reconciliation.example",
        owner_display_name="P7 Identity Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    identity_source = workspace / "identity-source"
    identity_source.mkdir()
    identity_marker = workspace / "identity-executed"
    (identity_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(identity_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    identity_run_id, identity_target = submit_local_run(
        client,
        manifest,
        identity_org.organization_id,
        identity_org.bootstrap_api_key,
        identity_source,
        key="p7-identity-reconciliation-0001",
        journey=[sys.executable, "journey.py"],
    )
    identity_result = run(
        identity_run_id,
        identity_org.organization_id,
        {"type": "local", "path": str(identity_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    identity_row = store.get_run(identity_run_id, identity_org.organization_id)
    record(
        scenarios,
        "canonical_identity_reconciliation",
        identity_result.get("state") == "COMPLETED"
        and identity_result.get("signed") is True
        and identity_marker.exists()
        and json.loads(identity_row["target_identity_json"]) == identity_target.to_dict()
        and json.loads(identity_row["environment_identity_json"])
        == _worker_environment().to_dict(),
        worker_result=identity_result,
        target_identity=json.loads(identity_row["target_identity_json"]),
        environment_identity=json.loads(identity_row["environment_identity_json"]),
    )

    drift_source = workspace / "identity-drift-source"
    drift_source.mkdir()
    drift_marker = workspace / "identity-drift-executed"
    (drift_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(drift_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    drift_run_id, _drift_target = submit_local_run(
        client,
        manifest,
        identity_org.organization_id,
        identity_org.bootstrap_api_key,
        drift_source,
        key="p7-identity-reconciliation-0002",
        journey=[sys.executable, "journey.py"],
    )
    (drift_source / "post-submit-change.txt").write_text("drift\n", encoding="utf-8")
    drift_result = run(
        drift_run_id,
        identity_org.organization_id,
        {"type": "local", "path": str(drift_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    record(
        scenarios,
        "acquired_identity_digest_mismatch_fails_closed",
        drift_result.get("state") == "INFRASTRUCTURE_FAILURE"
        and drift_result.get("detail") == "worker_target_identity_mismatch"
        and not drift_marker.exists()
        and store.latest_signed_verdict(
            drift_run_id, identity_org.organization_id
        )
        is None,
        worker_result=drift_result,
        customer_code_executed=drift_marker.exists(),
    )

    with closing(sqlite3.connect(db)) as connection:
        atomicity_rows = connection.execute(
            """
            SELECT runs.run_id, runs.state, r.state, d.state,
                   r.idempotency_key, runs.target_reference, d.last_error
            FROM runs
            LEFT JOIN subscriber_run_reservations r
              ON r.run_id = runs.run_id AND r.organization_id = runs.tenant_id
            LEFT JOIN subscriber_run_dispatches d
              ON d.run_id = runs.run_id AND d.organization_id = runs.tenant_id
            WHERE runs.project_id IS NOT NULL
              AND runs.state = 'QUEUED'
              AND (r.state != 'BOUND' OR d.run_id IS NULL)
            """
        ).fetchall()
    record(
        scenarios,
        "atomic_run_reservation_outbox_invariant",
        not atomicity_rows,
        violations=[list(row) for row in atomicity_rows],
    )

    original_policy = governance.policy
    governance.policy = policy.model_copy(
        update={
            "worker_claim_lease_seconds": 10,
            "worker_heartbeat_interval_seconds": 1,
        }
    )
    heartbeat_org = governance.provision_organization(
        slug="p7-heartbeat-storage-loss",
        display_name="P7 Heartbeat Storage Loss",
        owner_email="owner@p7-heartbeat-storage-loss.example",
        owner_display_name="P7 Heartbeat Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    heartbeat_source = workspace / "heartbeat-source"
    heartbeat_source.mkdir()
    heartbeat_marker = workspace / "heartbeat-completed"
    (heartbeat_source / "journey.py").write_text(
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(5)\n"
        f"Path({str(heartbeat_marker)!r}).write_text('completed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    heartbeat_run_id, _heartbeat_target = submit_local_run(
        client,
        manifest,
        heartbeat_org.organization_id,
        heartbeat_org.bootstrap_api_key,
        heartbeat_source,
        key="p7-heartbeat-storage-loss-0001",
        journey=[sys.executable, "journey.py"],
    )
    original_heartbeat = governance.heartbeat_worker_claim

    def fail_heartbeat_storage(_claim):
        raise sqlite3.OperationalError("simulated heartbeat storage loss")

    governance.heartbeat_worker_claim = fail_heartbeat_storage  # type: ignore[method-assign]
    heartbeat_result = run(
        heartbeat_run_id,
        heartbeat_org.organization_id,
        {"type": "local", "path": str(heartbeat_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    governance.heartbeat_worker_claim = original_heartbeat  # type: ignore[method-assign]
    record(
        scenarios,
        "heartbeat_storage_loss_fences_customer_process",
        heartbeat_result.get("error") == "subscriber_execution_fenced"
        and heartbeat_result.get("detail") == "worker_run_heartbeat_storage_failed"
        and not heartbeat_marker.exists()
        and store.latest_signed_verdict(
            heartbeat_run_id, heartbeat_org.organization_id
        )
        is None,
        worker_result=heartbeat_result,
        customer_code_completed=heartbeat_marker.exists(),
    )
    governance.policy = original_policy

    completion_now = [datetime.now(UTC)]
    completion_governance = SubscriberGovernance(
        db,
        original_policy,
        PEPPER,
        clock=lambda: completion_now[0],
    )
    completion_org = completion_governance.provision_organization(
        slug="p7-expired-completion",
        display_name="P7 Expired Completion",
        owner_email="owner@p7-expired-completion.example",
        owner_display_name="P7 Completion Owner",
        plan_code="developer",
        status=OrganizationStatus.ACTIVE,
    )
    completion_source = workspace / "completion-source"
    completion_source.mkdir()
    (completion_source / "journey.py").write_text(
        "print('completion')\n", encoding="utf-8"
    )
    completion_run_id, _completion_target = submit_local_run(
        client,
        manifest,
        completion_org.organization_id,
        completion_org.bootstrap_api_key,
        completion_source,
        key="p7-expired-completion-0001",
        journey=[sys.executable, "journey.py"],
    )
    original_complete = completion_governance.complete_worker_execution

    def expire_completion_lease(claim, envelope):
        completion_now[0] += timedelta(
            seconds=completion_governance.policy.worker_claim_lease_seconds + 1
        )
        return original_complete(claim, envelope)

    completion_governance.complete_worker_execution = expire_completion_lease  # type: ignore[method-assign]
    completion_result = run(
        completion_run_id,
        completion_org.organization_id,
        {"type": "local", "path": str(completion_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=completion_governance,
        journey=[sys.executable, "journey.py"],
    )
    completion_recovered = completion_governance.recover_expired_claims(
        completion_org.organization_id
    )
    record(
        scenarios,
        "expired_lease_cannot_commit_signed_completion",
        completion_result.get("error") == "subscriber_execution_fenced"
        and completion_result.get("detail") == "worker_run_claim_inactive"
        and store.latest_signed_verdict(
            completion_run_id, completion_org.organization_id
        )
        is None
        and completion_recovered == 1
        and store.get_run(
            completion_run_id, completion_org.organization_id
        )["state"]
        == "INFRASTRUCTURE_FAILURE",
        worker_result=completion_result,
        recovered_claims=completion_recovered,
    )

    record(
        scenarios,
        "versioned_policy_contract",
        contract.get("schema_version") == policy.schema_version
        and contract.get("schema_version") == "1.2.2"
        and contract.get("contract_id") == "certforge.subscriber-governance.v1"
        and contract.get("authentication", {}).get("denied_request_audit_required")
        is True
        and contract.get("worker_execution", {}).get("claim_precondition")
        is not None
        and contract.get("authorization", {}).get("mutation_consistency")
        is not None,
        contract_id=contract.get("contract_id"),
        schema_version=contract.get("schema_version"),
    )

    report = {
        "schema_version": "1.2.2",
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
