"""P7 acceptance coverage for subscriber productization and governance."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.models import RunState
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    MemberRole,
    OrganizationStatus,
    Permission,
    SubscriberError,
    SubscriberGovernance,
    SubscriberPolicy,
)

PEPPER = b"p7-acceptance-pepper-material-32-bytes-minimum"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _policy() -> SubscriberPolicy:
    return SubscriberPolicy.load(
        Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
    )


def _stack(tmp_path: Path, manifest, *, policy: SubscriberPolicy | None = None):
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(db, policy or _policy(), PEPPER)
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
    return store, governance, client


def _provision(
    governance: SubscriberGovernance,
    slug: str,
    *,
    plan_code: str = "developer",
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
):
    return governance.provision_organization(
        slug=slug,
        display_name=f"{slug} Inc",
        owner_email=f"owner@{slug}.example",
        owner_display_name=f"{slug} Owner",
        plan_code=plan_code,
        status=status,
    )


def _headers(organization_id: str, token: str) -> dict[str, str]:
    return {
        "X-Tenant-ID": organization_id,
        "Authorization": f"Bearer {token}",
    }


def _owner(
    governance: SubscriberGovernance,
    organization_id: str,
    token: str,
    permission: Permission = Permission.PROJECT_MANAGE,
):
    return governance.authenticate(
        token,
        tenant_hint=organization_id,
        permission=permission,
        action=f"acceptance.{permission.value.replace(':', '_')}",
    )


def _project(client: TestClient, organization_id: str, token: str, slug: str = "app"):
    return client.post(
        "/v1/subscriber/projects",
        headers=_headers(organization_id, token),
        json={
            "slug": slug,
            "name": f"{slug} Project",
            "target_reference": f"https://github.com/example/{slug}",
        },
    )


def _submit_body(manifest, organization_id: str, project_id: str, key: str) -> dict:
    return {
        "tenant_id": organization_id,
        "project_id": project_id,
        "target": {
            "target_type": "git",
            "identity_digest": _digest(f"target-{key}"),
            "reference": f"https://github.com/example/repo@{key}",
        },
        "environment": {
            "identity_digest": _digest("environment"),
            "runner_image_digest": "sha256:" + _digest("runner"),
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": key,
    }


def test_tenant_authentication_isolation_and_project_quota(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    alpha = _provision(governance, "alpha")
    beta = _provision(governance, "beta")

    me = client.get(
        "/v1/subscriber/me",
        headers=_headers(alpha.organization_id, alpha.bootstrap_api_key),
    )
    assert me.status_code == 200
    assert me.json()["organization_id"] == alpha.organization_id

    cross_tenant = client.get(
        "/v1/subscriber/me",
        headers=_headers(beta.organization_id, alpha.bootstrap_api_key),
    )
    assert cross_tenant.status_code == 404
    assert cross_tenant.json()["detail"] == "tenant_not_found"

    assert _project(client, alpha.organization_id, alpha.bootstrap_api_key, "one").status_code == 201
    assert _project(client, alpha.organization_id, alpha.bootstrap_api_key, "two").status_code == 201
    over_quota = _project(client, alpha.organization_id, alpha.bootstrap_api_key, "three")
    assert over_quota.status_code == 429
    assert over_quota.json()["detail"] == "project_quota_exceeded"

    beta_projects = client.get(
        "/v1/subscriber/projects",
        headers=_headers(beta.organization_id, beta.bootstrap_api_key),
    )
    assert beta_projects.status_code == 200
    assert beta_projects.json() == []


def test_role_and_api_key_scopes_prevent_privilege_escalation(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "roles")
    owner = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.MEMBER_MANAGE,
    )
    viewer_id = governance.invite_member(
        owner,
        email="viewer@roles.example",
        display_name="Viewer",
        role=MemberRole.VIEWER,
    )
    governance.activate_member(org.organization_id, viewer_id, actor_ref=owner.user_id)
    viewer_token = governance.create_api_key(
        owner,
        name="viewer",
        scopes=frozenset({Permission.PROJECT_READ, Permission.RUN_READ}),
        expires_at=datetime.now(UTC) + timedelta(days=10),
        user_id=viewer_id,
    )

    list_response = client.get(
        "/v1/subscriber/projects",
        headers=_headers(org.organization_id, viewer_token),
    )
    assert list_response.status_code == 200

    create_response = _project(client, org.organization_id, viewer_token)
    assert create_response.status_code == 403
    assert create_response.json()["detail"] == "permission_denied"

    with pytest.raises(SubscriberError, match="api_key_scope_escalation"):
        governance.create_api_key(
            owner,
            name="escalated",
            scopes={Permission.PROJECT_MANAGE},
            expires_at=datetime.now(UTC) + timedelta(days=10),
            user_id=viewer_id,
        )


def test_governed_submission_is_idempotent_metered_and_concurrency_limited(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "runs")
    project = _project(client, org.organization_id, org.bootstrap_api_key).json()
    headers = _headers(org.organization_id, org.bootstrap_api_key)
    body = _submit_body(manifest, org.organization_id, project["project_id"], "run-key-0001")

    first = client.post("/v1/certifications", headers=headers, json=body)
    replay = client.post("/v1/certifications", headers=headers, json=body)
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["run_id"] == first.json()["run_id"]

    concurrent = client.post(
        "/v1/certifications",
        headers=headers,
        json=_submit_body(
            manifest, org.organization_id, project["project_id"], "run-key-0002"
        ),
    )
    assert concurrent.status_code == 429
    assert concurrent.json()["detail"] == "concurrent_run_quota_exceeded"

    store.transition_state(
        first.json()["run_id"],
        org.organization_id,
        RunState.CANCELLED,
        "acceptance",
        "release concurrency reservation",
        "p7",
    )
    second = client.post(
        "/v1/certifications",
        headers=headers,
        json=_submit_body(
            manifest, org.organization_id, project["project_id"], "run-key-0002"
        ),
    )
    assert second.status_code == 201

    usage = client.get("/v1/subscriber/usage", headers=headers)
    assert usage.status_code == 200
    assert usage.json()["meters"]["certification_runs"] == 2
    assert usage.json()["active_run_reservations"] == 1


def test_rejected_submission_compensates_meter_and_preserves_default_block(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "reject")
    project = _project(client, org.organization_id, org.bootstrap_api_key).json()
    headers = _headers(org.organization_id, org.bootstrap_api_key)
    body = _submit_body(manifest, org.organization_id, project["project_id"], "bad-policy-001")
    body["policy_version"] = "policy.unknown"

    response = client.post("/v1/certifications", headers=headers, json=body)
    assert response.status_code == 422
    assert response.json()["detail"] == "policy_unknown"

    usage = client.get("/v1/subscriber/usage", headers=headers).json()
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0


def test_persisted_rate_limit_returns_retry_after(tmp_path, manifest):
    policy = _policy()
    plans = tuple(
        plan.model_copy(update={"requests_per_minute": 2})
        if plan.code == "developer"
        else plan
        for plan in policy.plans
    )
    limited_policy = policy.model_copy(update={"plans": plans})
    _store, governance, client = _stack(tmp_path, manifest, policy=limited_policy)
    org = _provision(governance, "limited")
    headers = _headers(org.organization_id, org.bootstrap_api_key)

    assert client.get("/v1/subscriber/me", headers=headers).status_code == 200
    assert client.get("/v1/subscriber/me", headers=headers).status_code == 200
    denied = client.get("/v1/subscriber/me", headers=headers)
    assert denied.status_code == 429
    assert denied.json()["detail"] == "rate_limit_exceeded"
    assert int(denied.headers["retry-after"]) >= 1


def test_billing_lifecycle_is_idempotent_and_fail_closed(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "billing")
    headers = _headers(org.organization_id, org.bootstrap_api_key)

    status = governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-payment-failed",
        event_type="payment.failed",
        payload={"invoice": "inv-1"},
    )
    assert status is OrganizationStatus.PAST_DUE
    assert (
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-payment-failed",
            event_type="payment.failed",
            payload={"invoice": "inv-1"},
        )
        is OrganizationStatus.PAST_DUE
    )
    with pytest.raises(SubscriberError, match="billing_event_conflict"):
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-payment-failed",
            event_type="payment.failed",
            payload={"invoice": "different"},
        )

    read_allowed = client.get("/v1/subscriber/projects", headers=headers)
    assert read_allowed.status_code == 200
    write_blocked = _project(client, org.organization_id, org.bootstrap_api_key)
    assert write_blocked.status_code == 402
    assert write_blocked.json()["detail"] == "subscription_past_due"

    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-suspend",
        event_type="subscription.suspended",
        payload={"reason": "risk"},
    )
    suspended = client.get("/v1/subscriber/projects", headers=headers)
    assert suspended.status_code == 403
    assert suspended.json()["detail"] == "organization_suspended"


def test_governance_controls_enforce_plan_entitlements_and_versions(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    developer = _provision(governance, "dev-governance")
    headers = _headers(developer.organization_id, developer.bootstrap_api_key)
    current = client.get("/v1/subscriber/governance", headers=headers).json()
    config = dict(current["config"])
    config["private_worker_only"] = True

    denied = client.put(
        "/v1/subscriber/governance",
        headers=headers,
        json={"expected_version": current["version"], "config": config},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "private_workers_not_entitled"

    config = dict(current["config"])
    config["retention_days"] = 15
    over_retention = client.put(
        "/v1/subscriber/governance",
        headers=headers,
        json={"expected_version": current["version"], "config": config},
    )
    assert over_retention.status_code == 422
    assert over_retention.json()["detail"] == "retention_exceeds_plan"

    professional = _provision(governance, "professional", plan_code="professional")
    professional_headers = _headers(
        professional.organization_id, professional.bootstrap_api_key
    )
    pro_current = client.get(
        "/v1/subscriber/governance", headers=professional_headers
    ).json()
    pro_config = dict(pro_current["config"])
    pro_config["retention_days"] = 90
    pro_config["report_brand_name"] = "Professional Certification"
    updated = client.put(
        "/v1/subscriber/governance",
        headers=professional_headers,
        json={"expected_version": pro_current["version"], "config": pro_config},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    stale = client.put(
        "/v1/subscriber/governance",
        headers=professional_headers,
        json={"expected_version": 1, "config": pro_config},
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == "governance_version_conflict"

    policy_pack = client.post(
        "/v1/subscriber/policy-packs",
        headers=professional_headers,
        json={
            "name": "Strict Customer Policy",
            "version": "1.0.0",
            "manifest": {"mandatory": ["tenant_isolation", "evidence_integrity"]},
        },
    )
    assert policy_pack.status_code == 201

    private_worker = client.post(
        "/v1/subscriber/private-workers",
        headers=professional_headers,
        json={"display_name": "Dedicated", "attestation_sha256": _digest("worker")},
    )
    assert private_worker.status_code == 403
    assert private_worker.json()["detail"] == "private_workers_not_entitled"


def test_enterprise_private_worker_and_developer_release_gate_are_plan_gated(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    enterprise = _provision(governance, "enterprise", plan_code="enterprise")
    enterprise_headers = _headers(
        enterprise.organization_id, enterprise.bootstrap_api_key
    )
    worker = client.post(
        "/v1/subscriber/private-workers",
        headers=enterprise_headers,
        json={"display_name": "Enterprise Worker", "attestation_sha256": _digest("worker")},
    )
    assert worker.status_code == 201
    assert worker.json()["status"] == "ACTIVE"

    developer = _provision(governance, "release-dev")
    release = client.post(
        "/v1/release-gates/evaluate",
        headers=_headers(developer.organization_id, developer.bootstrap_api_key),
        json={
            "run_id": "cert-does-not-exist",
            "target_identity_digest": _digest("target"),
            "environment_identity_digest": _digest("environment"),
            "rule_manifest_digest": manifest.digest,
        },
    )
    assert release.status_code == 403
    assert release.json()["detail"] == "release_gates_not_entitled"


def test_api_key_revocation_and_audit_chain_are_immutable(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "audit")
    owner = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.API_KEY_MANAGE,
    )
    token = governance.create_api_key(
        owner,
        name="automation",
        scopes={Permission.PROJECT_READ},
        expires_at=datetime.now(UTC) + timedelta(days=10),
    )
    key_id = token.removeprefix("ecf_live_").split(".", 1)[0]
    governance.revoke_api_key(owner, key_id)
    revoked = client.get(
        "/v1/subscriber/projects", headers=_headers(org.organization_id, token)
    )
    assert revoked.status_code == 401
    assert revoked.json()["detail"] == "api_key_revoked"

    headers = _headers(org.organization_id, org.bootstrap_api_key)
    assert _project(client, org.organization_id, org.bootstrap_api_key).status_code == 201
    verified = client.get("/v1/subscriber/audit/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["event_count"] > 0

    with sqlite3.connect(governance.db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE subscriber_audit_events SET outcome = 'forged' WHERE event_id = 1"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM subscriber_audit_events WHERE event_id = 1")


def test_storage_failure_returns_service_unavailable_without_legacy_fallback(
    tmp_path, manifest, monkeypatch
):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "storage-failure")

    def unavailable():
        raise sqlite3.OperationalError("simulated storage outage")

    monkeypatch.setattr(governance, "_connect", unavailable)
    response = client.get(
        "/v1/subscriber/me",
        headers=_headers(org.organization_id, org.bootstrap_api_key),
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "subscriber_governance_unavailable"


def test_rate_limit_is_global_and_denied_requests_are_immutably_audited(
    tmp_path, manifest
):
    policy = _policy()
    plans = tuple(
        plan.model_copy(update={"requests_per_minute": 2})
        if plan.code == "developer"
        else plan
        for plan in policy.plans
    )
    _store, governance, client = _stack(
        tmp_path, manifest, policy=policy.model_copy(update={"plans": plans})
    )
    org = _provision(governance, "global-rate")
    headers = _headers(org.organization_id, org.bootstrap_api_key)

    assert client.get("/v1/subscriber/me", headers=headers).status_code == 200
    assert client.get("/v1/subscriber/projects", headers=headers).status_code == 200
    denied = client.get("/v1/subscriber/usage", headers=headers)
    assert denied.status_code == 429
    assert denied.json()["detail"] == "rate_limit_exceeded"

    tenant_mismatch = client.get(
        "/v1/subscriber/me",
        headers=_headers("org_not_the_authenticated_tenant", org.bootstrap_api_key),
    )
    assert tenant_mismatch.status_code == 404

    with sqlite3.connect(governance.db_path) as connection:
        rows = connection.execute(
            """
            SELECT outcome, details_json FROM subscriber_audit_events
            WHERE organization_id = ? AND action = 'request.deny'
            ORDER BY event_id
            """,
            (org.organization_id,),
        ).fetchall()
    reasons = {json.loads(row[1])["reason"] for row in rows}
    assert reasons == {"rate_limit_exceeded", "tenant_mismatch"}


def test_membership_lifecycle_is_tenant_scoped_and_revokes_credentials(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    alpha = _provision(governance, "member-alpha")
    beta = _provision(governance, "member-beta")
    alpha_owner = _owner(
        governance,
        alpha.organization_id,
        alpha.bootstrap_api_key,
        Permission.MEMBER_MANAGE,
    )
    beta_owner = _owner(
        governance,
        beta.organization_id,
        beta.bootstrap_api_key,
        Permission.MEMBER_MANAGE,
    )
    shared_email = "shared-member@example.test"
    alpha_member = governance.invite_member(
        alpha_owner,
        email=shared_email,
        display_name="Shared Member",
        role=MemberRole.VIEWER,
    )
    beta_member = governance.invite_member(
        beta_owner,
        email=shared_email,
        display_name="Shared Member",
        role=MemberRole.VIEWER,
    )
    assert alpha_member == beta_member

    alpha_headers = _headers(alpha.organization_id, alpha.bootstrap_api_key)
    activated = client.post(
        f"/v1/subscriber/members/{alpha_member}/activate",
        headers=alpha_headers,
    )
    assert activated.status_code == 204
    alpha_key = governance.create_api_key(
        alpha_owner,
        name="alpha-viewer",
        scopes={Permission.PROJECT_READ},
        expires_at=datetime.now(UTC) + timedelta(days=10),
        user_id=alpha_member,
    )
    with pytest.raises(SubscriberError, match="member_inactive"):
        governance.create_api_key(
            beta_owner,
            name="beta-viewer",
            scopes={Permission.PROJECT_READ},
            expires_at=datetime.now(UTC) + timedelta(days=10),
            user_id=beta_member,
        )

    deactivated = client.delete(
        f"/v1/subscriber/members/{alpha_member}",
        headers=alpha_headers,
    )
    assert deactivated.status_code == 204
    denied = client.get(
        "/v1/subscriber/projects",
        headers=_headers(alpha.organization_id, alpha_key),
    )
    assert denied.status_code == 401
    assert denied.json()["detail"] == "api_key_revoked"


def test_project_and_private_worker_lifecycle_release_plan_capacity(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    developer = _provision(governance, "project-lifecycle")
    developer_headers = _headers(
        developer.organization_id, developer.bootstrap_api_key
    )
    first = _project(
        client, developer.organization_id, developer.bootstrap_api_key, "one"
    ).json()
    assert _project(
        client, developer.organization_id, developer.bootstrap_api_key, "two"
    ).status_code == 201
    assert (
        client.delete(
            f"/v1/subscriber/projects/{first['project_id']}",
            headers=developer_headers,
        ).status_code
        == 204
    )
    assert _project(
        client, developer.organization_id, developer.bootstrap_api_key, "three"
    ).status_code == 201

    enterprise = _provision(
        governance, "worker-lifecycle", plan_code="enterprise"
    )
    enterprise_headers = _headers(
        enterprise.organization_id, enterprise.bootstrap_api_key
    )
    worker = client.post(
        "/v1/subscriber/private-workers",
        headers=enterprise_headers,
        json={
            "display_name": "Revocable Worker",
            "attestation_sha256": _digest("revocable-worker"),
        },
    )
    assert worker.status_code == 201
    worker_id = worker.json()["worker_id"]
    assert (
        client.delete(
            f"/v1/subscriber/private-workers/{worker_id}",
            headers=enterprise_headers,
        ).status_code
        == 204
    )
    workers = client.get(
        "/v1/subscriber/private-workers", headers=enterprise_headers
    ).json()
    assert workers[0]["status"] == "REVOKED"


def test_lifecycle_mutations_cannot_cross_tenant_boundaries(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    alpha = _provision(governance, "lifecycle-alpha", plan_code="enterprise")
    beta = _provision(governance, "lifecycle-beta", plan_code="enterprise")
    alpha_headers = _headers(alpha.organization_id, alpha.bootstrap_api_key)
    beta_headers = _headers(beta.organization_id, beta.bootstrap_api_key)

    beta_project = _project(
        client, beta.organization_id, beta.bootstrap_api_key, "beta-project"
    ).json()
    project_denied = client.delete(
        f"/v1/subscriber/projects/{beta_project['project_id']}",
        headers=alpha_headers,
    )
    assert project_denied.status_code == 404
    assert project_denied.json()["detail"] == "project_not_found"

    beta_owner = _owner(
        governance,
        beta.organization_id,
        beta.bootstrap_api_key,
        Permission.MEMBER_MANAGE,
    )
    beta_member = governance.invite_member(
        beta_owner,
        email="beta-only-member@example.test",
        display_name="Beta Only",
        role=MemberRole.VIEWER,
    )
    member_denied = client.delete(
        f"/v1/subscriber/members/{beta_member}",
        headers=alpha_headers,
    )
    assert member_denied.status_code == 404
    assert member_denied.json()["detail"] == "member_not_found"

    beta_worker = client.post(
        "/v1/subscriber/private-workers",
        headers=beta_headers,
        json={
            "display_name": "Beta Worker",
            "attestation_sha256": _digest("beta-worker"),
        },
    ).json()
    worker_denied = client.delete(
        f"/v1/subscriber/private-workers/{beta_worker['worker_id']}",
        headers=alpha_headers,
    )
    assert worker_denied.status_code == 404
    assert worker_denied.json()["detail"] == "private_worker_not_found"


def test_billing_events_are_tenant_bound_and_expired_period_is_read_only(
    tmp_path, manifest
):
    _store, governance, client = _stack(tmp_path, manifest)
    alpha = _provision(governance, "billing-alpha")
    beta = _provision(governance, "billing-beta")
    payload = {"invoice": "shared-provider-event"}
    governance.apply_billing_event(
        organization_id=alpha.organization_id,
        provider_event_id="evt-tenant-bound",
        event_type="payment.failed",
        payload=payload,
    )
    with pytest.raises(SubscriberError, match="billing_event_conflict"):
        governance.apply_billing_event(
            organization_id=beta.organization_id,
            provider_event_id="evt-tenant-bound",
            event_type="payment.failed",
            payload=payload,
        )

    expired_at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat().replace(
        "+00:00", "Z"
    )
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions SET current_period_end = ?
            WHERE organization_id = ?
            """,
            (expired_at, beta.organization_id),
        )
        connection.commit()
    beta_headers = _headers(beta.organization_id, beta.bootstrap_api_key)
    assert (
        client.get("/v1/subscriber/projects", headers=beta_headers).status_code
        == 200
    )
    write = _project(client, beta.organization_id, beta.bootstrap_api_key)
    assert write.status_code == 402
    assert write.json()["detail"] == "subscription_period_expired"


def test_stale_reservation_is_released_and_metering_is_compensated(
    tmp_path, manifest
):
    now = [datetime(2026, 7, 25, 12, 0, tzinfo=UTC)]
    policy = _policy()
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(
        db,
        policy,
        PEPPER,
        clock=lambda: now[0],
    )
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
    org = _provision(governance, "stale-reservation")
    project = _project(
        client, org.organization_id, org.bootstrap_api_key
    ).json()
    principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.RUN_CREATE,
    )
    first = governance.reserve_certification_run(
        principal,
        project_id=project["project_id"],
        idempotency_key="stale-reservation-0001",
        request_digest=_digest("stale-request"),
        policy_version=manifest.manifest_id,
    )
    assert first.created is True

    now[0] += timedelta(seconds=policy.reservation_ttl_seconds + 1)
    second = governance.reserve_certification_run(
        principal,
        project_id=project["project_id"],
        idempotency_key="stale-reservation-0002",
        request_digest=_digest("replacement-request"),
        policy_version=manifest.manifest_id,
    )
    assert second.created is True
    usage = governance.usage_summary(
        _owner(
            governance,
            org.organization_id,
            org.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["meters"]["certification_runs"] == 1
    assert usage["active_run_reservations"] == 1


def test_subscriber_policy_and_contract_are_versioned_and_consistent():
    root = Path(__file__).parents[1]
    policy = _policy()
    contract = json.loads(
        (root / "contracts" / "subscriber-governance.v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["schema_version"] == policy.schema_version
    assert contract["contract_id"] == "certforge.subscriber-governance.v1"
    assert contract["authentication"]["rate_limit_scope"] == (
        "global per API key across subscriber endpoints"
    )
    assert policy.rate_limit_scope == "api_key_global"
    assert policy.audit_denied_requests is True
