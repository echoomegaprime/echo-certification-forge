"""P7 acceptance coverage for subscriber productization and governance."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.acquisition import AcquiredTarget, acquire_target
from echo_certification_forge.canonical import parse_utc_iso
from echo_certification_forge.dispatch_worker import dispatch_once
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.intake import SubmitRequest
from echo_certification_forge.models import (
    RunState,
    TargetIdentity,
    declared_target_identity_digest,
)
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


def _submit_local_run(
    client: TestClient,
    manifest,
    organization_id: str,
    token: str,
    source: Path,
    *,
    key: str,
    journey: list[str] | None = None,
) -> tuple[str, TargetIdentity]:
    project_response = _project(
        client,
        organization_id,
        token,
        slug=f"local-{key[-6:]}",
    )
    assert project_response.status_code == 201
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
        "project_id": project_response.json()["project_id"],
        "target": {
            "target_type": "local",
            "identity_digest": target.identity_digest,
            "reference": acquired.canonical_ref,
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
        headers=_headers(organization_id, token),
        json=payload,
    )
    assert response.status_code == 201
    return response.json()["run_id"], target


def test_legacy_platform_subscriber_tables_are_archived_before_p7_schema(
    tmp_path,
):
    database_path = tmp_path / "certforge.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE subscriber_users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE subscriber_api_keys (
                key_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                secret_sha256 TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            INSERT INTO subscriber_users VALUES (
                'legacy-user', 'legacy@example.test', '2026-01-01T00:00:00Z'
            );
            INSERT INTO subscriber_api_keys VALUES (
                'legacy-key', 'legacy-org', 'legacy-project', 'ecf_legacy',
                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'OWNER', '2026-01-01T00:00:00Z', NULL
            );
            """
        )

    SubscriberGovernance(database_path, _policy(), PEPPER)

    with sqlite3.connect(database_path) as connection:
        current_user_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(subscriber_users)")
        }
        current_key_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(subscriber_api_keys)")
        }
        archived_user = connection.execute(
            "SELECT user_id, email FROM legacy_platform_subscriber_users"
        ).fetchone()
        archived_key = connection.execute(
            "SELECT key_id, key_prefix FROM legacy_platform_subscriber_api_keys"
        ).fetchone()

    assert {"display_name", "status", "updated_at"} <= current_user_columns
    assert {"user_id", "name", "token_digest", "scopes_json", "status"} <= current_key_columns
    assert archived_user == ("legacy-user", "legacy@example.test")
    assert archived_key == ("legacy-key", "ecf_legacy")


def test_unknown_subscriber_schema_fails_closed(tmp_path):
    database_path = tmp_path / "certforge.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE subscriber_users (user_id TEXT PRIMARY KEY, unexpected TEXT)"
        )

    with pytest.raises(RuntimeError, match="incompatible subscriber schema: subscriber_users"):
        SubscriberGovernance(database_path, _policy(), PEPPER)


def test_active_manifest_rollover_creates_distinct_subscriber_reservation(
    tmp_path,
    manifest,
):
    store, governance, first_client = _stack(tmp_path, manifest)
    provisioned = _provision(governance, "rollover", plan_code="enterprise")
    project = _project(
        first_client,
        provisioned.organization_id,
        provisioned.bootstrap_api_key,
        "rollover-app",
    )
    assert project.status_code == 201
    payload = _submit_body(
        manifest,
        provisioned.organization_id,
        project.json()["project_id"],
        "stable-client-key",
    )
    first = first_client.post(
        "/v1/certifications",
        headers=_headers(provisioned.organization_id, provisioned.bootstrap_api_key),
        json=payload,
    )
    assert first.status_code == 201

    rolled_manifest = replace(manifest, digest=_digest("rolled-policy-content"))
    second_client = TestClient(
        create_app(
            ServiceContext(
                store,
                rolled_manifest,
                TrustedPublicKeyRegistry.empty(),
                governance,
            )
        )
    )
    second = second_client.post(
        "/v1/certifications",
        headers=_headers(provisioned.organization_id, provisioned.bootstrap_api_key),
        json=payload,
    )

    assert second.status_code == 201
    assert second.json()["run_id"] != first.json()["run_id"]
    with sqlite3.connect(tmp_path / "certforge.sqlite3") as connection:
        reservations = connection.execute(
            """
            SELECT idempotency_key, request_digest
            FROM subscriber_run_reservations
            WHERE organization_id = ?
            ORDER BY idempotency_key
            """,
            (provisioned.organization_id,),
        ).fetchall()
    assert len(reservations) == 2
    assert len({row[0] for row in reservations}) == 2
    assert len({row[1] for row in reservations}) == 2


def test_subscriber_oci_without_sandbox_fails_and_releases_claim(
    tmp_path,
    manifest,
    monkeypatch,
):
    store, governance, client = _stack(tmp_path, manifest)
    provisioned = _provision(governance, "oci-no-sandbox", plan_code="enterprise")
    project = _project(
        client,
        provisioned.organization_id,
        provisioned.bootstrap_api_key,
        "oci-app",
    )
    assert project.status_code == 201
    principal = governance.authenticate(
        provisioned.bootstrap_api_key,
        tenant_hint=provisioned.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.oci.reserve",
    )
    digest = "sha256:" + _digest("subscriber-oci-image")
    repository = "registry.example.test/echo/app"
    reference = f"{repository}@{digest}"
    target_spec = {"type": "oci", "repository": repository, "digest": digest}
    reservation = governance.reserve_certification_run(
        principal,
        project_id=project.json()["project_id"],
        idempotency_key="subscriber-oci-no-sandbox",
        request_digest=_digest("subscriber-oci-request"),
        policy_version=manifest.manifest_id,
        target_type="oci",
        target_reference=reference,
        target_identity_digest=_digest("subscriber-oci-declared-target"),
    )
    environment = _worker_environment()
    run_id = "cert_" + _digest("subscriber-oci-run")[:40]
    governance.materialize_reserved_run(
        reservation,
        run_id=run_id,
        target_type="oci",
        target_reference=reference,
        target_identity_digest=_digest("subscriber-oci-declared-target"),
        environment_identity_digest=environment.identity_digest,
        environment_json=environment.to_dict(),
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        target_spec=target_spec,
        journey=["python3", "app/hello.py"],
    )
    rootfs = tmp_path / "oci-rootfs"
    rootfs.mkdir()
    monkeypatch.setattr(
        "echo_certification_forge.run_worker.acquire_target",
        lambda *_args, **_kwargs: AcquiredTarget(
            rootfs,
            "oci",
            reference,
            digest.split(":", 1)[1],
        ),
    )

    result = run(
        run_id,
        provisioned.organization_id,
        target_spec,
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=["python3", "app/hello.py"],
        sandbox=None,
    )

    assert result["error"] == "oci_journey_requires_sandbox"
    assert (
        store.get_run(run_id, provisioned.organization_id)["state"]
        == RunState.INFRASTRUCTURE_FAILURE.value
    )
    usage = governance.usage_summary(
        _owner(
            governance,
            provisioned.organization_id,
            provisioned.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["active_run_reservations"] == 0
    worker_root = store.evidence_root / ".worker"
    assert not worker_root.exists() or not any(worker_root.iterdir())


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
    governance.activate_member(owner, viewer_id)
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
    terminal_replay = client.post("/v1/certifications", headers=headers, json=body)
    assert terminal_replay.status_code == 200
    assert terminal_replay.json()["run_id"] == first.json()["run_id"]
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
    payment_failed_at = datetime.now(UTC)

    status = governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-payment-failed",
        event_type="payment.failed",
        payload={"invoice": "inv-1"},
        provider_occurred_at=payment_failed_at,
        provider_sequence=1,
    )
    assert status is OrganizationStatus.PAST_DUE
    assert (
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-payment-failed",
            event_type="payment.failed",
            payload={"invoice": "inv-1"},
            provider_occurred_at=payment_failed_at,
            provider_sequence=1,
        )
        is OrganizationStatus.PAST_DUE
    )
    with pytest.raises(SubscriberError, match="billing_event_conflict"):
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-payment-failed",
            event_type="payment.failed",
            payload={"invoice": "different"},
            provider_occurred_at=payment_failed_at,
            provider_sequence=1,
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
        provider_occurred_at=payment_failed_at + timedelta(seconds=1),
        provider_sequence=2,
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
    occurred_at = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=alpha.organization_id,
        provider_event_id="evt-tenant-bound",
        event_type="payment.failed",
        payload=payload,
        provider_occurred_at=occurred_at,
        provider_sequence=1,
    )
    with pytest.raises(SubscriberError, match="billing_event_conflict"):
        governance.apply_billing_event(
            organization_id=beta.organization_id,
            provider_event_id="evt-tenant-bound",
            event_type="payment.failed",
            payload=payload,
            provider_occurred_at=occurred_at,
            provider_sequence=1,
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


@pytest.mark.parametrize(
    "status",
    [OrganizationStatus.SUSPENDED, OrganizationStatus.CANCELLED],
)
def test_run_worker_enforces_live_subscriber_entitlement(
    tmp_path, manifest, status
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, f"worker-{status.value.lower()}")
    marker = tmp_path / f"{status.value.lower()}-executed"
    source = tmp_path / f"{status.value.lower()}-source"
    source.mkdir()
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key=f"worker-{status.value.lower()}-0001",
    )
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            "UPDATE subscriber_organizations SET status = ? WHERE organization_id = ?",
            (status.value, org.organization_id),
        )
        connection.execute(
            "UPDATE subscriber_subscriptions SET status = ? WHERE organization_id = ?",
            (status.value, org.organization_id),
        )

    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset({org.organization_id}),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )

    assert result["error"] == "subscriber_worker_claim_denied"
    assert result["detail"] == "subscriber_not_entitled"
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert marker.exists() is False


def test_run_worker_uses_plan_retention_immediately_before_execution(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-retention", plan_code="developer")
    source = tmp_path / "retention-source"
    source.mkdir()
    (source / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="worker-retention-0001",
    )

    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset(),
        subscribers=governance,
        journey=[sys.executable, "hello.py"],
    )

    assert result["state"] == RunState.COMPLETED.value
    with sqlite3.connect(governance.db_path) as connection:
        rows = connection.execute(
            """
            SELECT retention_class, expires_at, created_at
            FROM evidence_retention
            WHERE run_id = ? AND tenant_id = ?
            """,
            (run_id, org.organization_id),
        ).fetchall()
    assert rows
    assert {row[0] for row in rows} == {"subscriber-7d"}
    assert all(
        timedelta(days=6, hours=23)
        <= parse_utc_iso(row[1]) - parse_utc_iso(row[2])
        <= timedelta(days=7, minutes=1)
        for row in rows
    )


def test_run_worker_fails_closed_when_retention_lookup_fails(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "lookup-failure")
    source = tmp_path / "lookup-failure-source"
    source.mkdir()
    marker = tmp_path / "lookup-failure-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="worker-lookup-failure-0001",
    )

    def broken_authorization(_claim):
        raise sqlite3.OperationalError("simulated governance outage")

    governance.authorize_worker_execution = broken_authorization  # type: ignore[method-assign]

    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset({org.organization_id}),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )

    assert result["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert result["signed"] is False
    assert marker.exists() is False


def test_subscriber_worker_requires_bound_queued_run_before_acquisition(
    tmp_path, manifest
):
    store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-direct")
    missing_source = tmp_path / "must-not-be-acquired"

    result = run(
        "unreserved-run",
        org.organization_id,
        {"type": "local", "path": str(missing_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
    )

    assert result == {
        "run_id": "unreserved-run",
        "error": "subscriber_worker_claim_denied",
        "detail": "worker_run_reservation_missing",
    }
    with pytest.raises(KeyError):
        store.get_run("unreserved-run", org.organization_id)


def test_worker_reservation_is_atomically_consumed(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-claim")
    source = tmp_path / "claim-source"
    source.mkdir()
    (source / "hello.py").write_text("print('claim')\n", encoding="utf-8")
    run_id, target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="worker-claim-0001",
    )
    signer = Ed25519VerdictSigner.generate()
    claim = governance.claim_worker_run(
        run_id=run_id,
        organization_id=org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=signer.key_id,
    )
    with pytest.raises(SubscriberError, match="worker_run_already_claimed"):
        governance.claim_worker_run(
            run_id=run_id,
            organization_id=org.organization_id,
            policy_version=manifest.manifest_id,
            target_type="local",
            target_reference=target.canonical_ref,
            worker_id=None,
            worker_attestation_sha256=None,
            execution_location="local",
            signing_authority="platform",
            signing_key_id=signer.key_id,
        )
    with sqlite3.connect(governance.db_path) as connection:
        state = connection.execute(
            """
            SELECT state FROM subscriber_run_reservations
            WHERE organization_id = ? AND run_id = ?
            """,
            (org.organization_id, run_id),
        ).fetchone()[0]
    assert state == "EXECUTING"
    governance.finish_worker_claim(claim, reason="test_complete")
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value


def test_worker_revalidates_queued_state_immediately_before_execution(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-cancel-race")
    source = tmp_path / "cancel-race-source"
    source.mkdir()
    marker = tmp_path / "cancel-race-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="worker-cancel-race-0001",
    )
    authorize = governance.authorize_worker_execution

    def cancel_before_authorization(claim, **identity):
        store.transition_state(
            run_id,
            org.organization_id,
            RunState.CANCELLED,
            "acceptance",
            "cancel immediately before worker authorization",
            manifest.manifest_id,
        )
        return authorize(claim, **identity)

    governance.authorize_worker_execution = cancel_before_authorization  # type: ignore[method-assign]
    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )

    assert result["state"] == RunState.CANCELLED.value
    assert result["error"] == "subscriber_execution_denied"
    assert result["detail"] == "worker_run_not_queued"
    assert result["signed"] is False
    assert marker.exists() is False


def test_worker_enforces_private_local_and_customer_signing_controls(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-controls", plan_code="sovereign")
    governance_principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.GOVERNANCE_MANAGE,
    )
    worker_principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.PRIVATE_WORKER_MANAGE,
    )
    customer_signer = Ed25519VerdictSigner.generate()
    current = governance.governance_config(governance_principal)
    config = dict(current["config"])
    config["private_worker_only"] = True
    config["customer_managed_signing"] = True
    config["customer_signing_key_id"] = customer_signer.key_id
    governance.update_governance(
        governance_principal,
        config,
        expected_version=current["version"],
    )
    worker_attestation = _digest("sovereign-worker-attestation")
    worker = governance.register_private_worker(
        worker_principal,
        display_name="Sovereign Local Worker",
        attestation_sha256=worker_attestation,
    )
    source = tmp_path / "controlled-source"
    source.mkdir()
    (source / "hello.py").write_text("print('controlled')\n", encoding="utf-8")
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="worker-controls-0001",
    )

    mismatched_target = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(tmp_path / "different-source")},
        store=store,
        manifest=manifest,
        signer=customer_signer,
        subscribers=governance,
        worker_id=worker["worker_id"],
        worker_attestation_sha256=worker_attestation,
        execution_location="local",
        signing_authority="customer",
    )
    assert mismatched_target["detail"] == "worker_target_binding_conflict"

    wrong_worker = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=customer_signer,
        subscribers=governance,
        worker_id=worker["worker_id"],
        worker_attestation_sha256=_digest("wrong-attestation"),
        execution_location="local",
        signing_authority="customer",
    )
    assert wrong_worker["detail"] == "private_worker_identity_invalid"

    remote_execution = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=customer_signer,
        subscribers=governance,
        worker_id=worker["worker_id"],
        worker_attestation_sha256=worker_attestation,
        execution_location="remote",
        signing_authority="customer",
    )
    assert remote_execution["detail"] == "local_execution_required"

    platform_signing = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        worker_id=worker["worker_id"],
        worker_attestation_sha256=worker_attestation,
        execution_location="local",
        signing_authority="platform",
    )
    assert platform_signing["detail"] == "customer_signing_authority_required"

    platform_dispatch, _platform_result = dispatch_once(
        governance,
        run,
        dispatcher_id="platform-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": Ed25519VerdictSigner.generate(),
            "subscribers": governance,
        },
    )
    controlled_dispatch, result = dispatch_once(
        governance,
        run,
        dispatcher_id="customer-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": customer_signer,
            "subscribers": governance,
            "worker_id": worker["worker_id"],
            "worker_attestation_sha256": worker_attestation,
            "execution_location": "local",
            "signing_authority": "customer",
        },
    )
    assert platform_dispatch is None
    assert controlled_dispatch is not None
    assert result is not None and result["state"] == RunState.COMPLETED.value
    assert result["signer_public_key_id"] == customer_signer.key_id

def test_mutation_reauthorizes_inside_write_transaction(tmp_path, manifest):
    _store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, "authorization-race")
    principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.PROJECT_MANAGE,
    )
    original_require = governance.require

    def suspend_after_outer_authorization(
        candidate, permission: Permission
    ) -> None:
        original_require(candidate, permission)
        with sqlite3.connect(governance.db_path) as connection:
            connection.execute(
                "UPDATE subscriber_organizations SET status = 'SUSPENDED' "
                "WHERE organization_id = ?",
                (org.organization_id,),
            )
            connection.execute(
                "UPDATE subscriber_subscriptions SET status = 'SUSPENDED' "
                "WHERE organization_id = ?",
                (org.organization_id,),
            )

    governance.require = suspend_after_outer_authorization  # type: ignore[method-assign]
    with pytest.raises(SubscriberError, match="organization_suspended"):
        governance.create_project(
            principal,
            slug="raced",
            name="Raced Project",
            target_reference="https://github.com/example/raced",
        )
    with sqlite3.connect(governance.db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM subscriber_projects WHERE organization_id = ?",
            (org.organization_id,),
        ).fetchone()[0]
    assert count == 0


def test_plan_downgrade_reconciles_and_caps_retention_atomically(
    tmp_path, manifest
):
    _store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, "downgrade", plan_code="enterprise")
    principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.GOVERNANCE_MANAGE,
    )
    config_row = governance.governance_config(principal)
    config = dict(config_row["config"])
    config.update(
        {
            "retention_days": 700,
            "private_worker_only": True,
            "customer_managed_signing": True,
            "customer_signing_key_id": Ed25519VerdictSigner.generate().key_id,
        }
    )
    governance.update_governance(
        principal,
        config,
        expected_version=config_row["version"],
    )
    before = governance.governance_config(principal)
    period_start = datetime.now(UTC)
    period_end = period_start + timedelta(days=30)

    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-plan-downgrade",
        event_type="subscription.plan_changed",
        payload={
            "current_period_start": period_start.isoformat().replace("+00:00", "Z"),
            "current_period_end": period_end.isoformat().replace("+00:00", "Z"),
        },
        provider_occurred_at=period_start,
        provider_sequence=1,
        plan_code="developer",
    )

    after = governance.governance_config(principal)
    assert after["version"] == before["version"] + 1
    assert after["config"]["retention_days"] == 14
    assert after["config"]["private_worker_only"] is False
    assert after["config"]["customer_managed_signing"] is False
    assert after["config"]["customer_signing_key_id"] is None
    with sqlite3.connect(governance.db_path) as connection:
        corrupted = dict(after["config"])
        corrupted["retention_days"] = 700
        connection.execute(
            "UPDATE subscriber_governance SET config_json = ? WHERE organization_id = ?",
            (json.dumps(corrupted), org.organization_id),
        )
    assert governance.retention_days(org.organization_id) == 14


def test_required_billing_periods_fail_closed_and_preserve_subscription(
    tmp_path, manifest
):
    _store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, "billing-period-required")
    with sqlite3.connect(governance.db_path) as connection:
        before = connection.execute(
            """
            SELECT plan_code, status, current_period_start, current_period_end
            FROM subscriber_subscriptions WHERE organization_id = ?
            """,
            (org.organization_id,),
        ).fetchone()

    with pytest.raises(SubscriberError, match="billing_period_required"):
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-missing-period",
            event_type="subscription.renewed",
            payload={},
            provider_occurred_at=datetime.now(UTC),
            provider_sequence=1,
        )
    with pytest.raises(SubscriberError, match="billing_period_invalid"):
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-invalid-period",
            event_type="subscription.plan_changed",
            payload={
                "current_period_start": "2026-08-02T00:00:00Z",
                "current_period_end": "2026-08-01T00:00:00Z",
            },
            provider_occurred_at=datetime.now(UTC),
            provider_sequence=2,
            plan_code="professional",
        )

    with sqlite3.connect(governance.db_path) as connection:
        after = connection.execute(
            """
            SELECT plan_code, status, current_period_start, current_period_end
            FROM subscriber_subscriptions WHERE organization_id = ?
            """,
            (org.organization_id,),
        ).fetchone()
        event_count = connection.execute(
            """
            SELECT COUNT(*) FROM subscriber_billing_events
            WHERE provider_event_id IN ('evt-missing-period', 'evt-invalid-period')
            """
        ).fetchone()[0]
    assert tuple(after) == tuple(before)
    assert event_count == 0


def test_validation_and_unhandled_errors_are_finally_audited(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "audit-errors")
    headers = _headers(org.organization_id, org.bootstrap_api_key)

    validation = client.get(
        "/v1/subscriber/audit",
        headers=headers,
        params={"limit": 0},
    )
    assert validation.status_code == 422
    assert validation.json()["detail"] == "request_validation_error"

    original = governance.list_policy_packs

    def explode(_principal):
        raise RuntimeError("simulated unhandled failure")

    governance.list_policy_packs = explode  # type: ignore[method-assign]
    try:
        unhandled = client.get(
            "/v1/subscriber/policy-packs",
            headers=headers,
        )
    finally:
        governance.list_policy_packs = original  # type: ignore[method-assign]
    assert unhandled.status_code == 500
    assert unhandled.json() == {"detail": "internal_server_error"}

    with sqlite3.connect(governance.db_path) as connection:
        rows = connection.execute(
            """
            SELECT outcome, details_json FROM subscriber_audit_events
            WHERE organization_id = ? AND action = 'request.outcome'
              AND json_extract(details_json, '$.path') IN (
                  '/v1/subscriber/audit',
                  '/v1/subscriber/policy-packs'
              )
            ORDER BY event_id DESC LIMIT 2
            """,
            (org.organization_id,),
        ).fetchall()
    outcomes = {
        (
            json.loads(row[1])["path"],
            row[0],
            json.loads(row[1])["status_code"],
            json.loads(row[1])["reason"],
        )
        for row in rows
    }
    assert (
        "/v1/subscriber/audit",
        "denied",
        422,
        "request_validation_error",
    ) in outcomes
    assert (
        "/v1/subscriber/policy-packs",
        "error",
        500,
        "unhandled_exception",
    ) in outcomes


def test_billing_provider_order_rejects_delayed_reactivation(tmp_path, manifest):
    _store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, "billing-order")
    suspended_at = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-order-suspend",
        event_type="subscription.suspended",
        payload={"reason": "risk"},
        provider_occurred_at=suspended_at,
        provider_sequence=20,
    )

    with pytest.raises(SubscriberError, match="billing_event_stale"):
        governance.apply_billing_event(
            organization_id=org.organization_id,
            provider_event_id="evt-order-delayed-activate",
            event_type="subscription.activated",
            payload={
                "reason": "delayed",
                "current_period_start": (suspended_at - timedelta(days=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "current_period_end": (suspended_at + timedelta(days=29))
                .isoformat()
                .replace("+00:00", "Z"),
            },
            provider_occurred_at=suspended_at - timedelta(minutes=5),
            provider_sequence=10,
        )

    with sqlite3.connect(governance.db_path) as connection:
        status = connection.execute(
            "SELECT status FROM subscriber_organizations WHERE organization_id = ?",
            (org.organization_id,),
        ).fetchone()[0]
        stale = connection.execute(
            """
            SELECT provider_occurred_at, provider_sequence, processing_outcome
            FROM subscriber_billing_events WHERE provider_event_id = ?
            """,
            ("evt-order-delayed-activate",),
        ).fetchone()
    assert status == OrganizationStatus.SUSPENDED.value
    assert stale[0] == (suspended_at - timedelta(minutes=5)).isoformat().replace(
        "+00:00", "Z"
    )
    assert stale[1:] == (10, "REJECTED_STALE")


def test_existing_billing_schema_migrates_provider_order_state(tmp_path):
    db = tmp_path / "legacy-subscriber.sqlite3"
    created_at = "2026-07-01T00:00:00Z"
    with sqlite3.connect(db) as connection:
        connection.executescript(
            """
            CREATE TABLE subscriber_organizations (
                organization_id TEXT PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE subscriber_subscriptions (
                organization_id TEXT PRIMARY KEY,
                plan_code TEXT NOT NULL,
                status TEXT NOT NULL,
                billing_provider TEXT,
                provider_customer_ref TEXT,
                current_period_start TEXT NOT NULL,
                current_period_end TEXT NOT NULL,
                cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE subscriber_billing_events (
                provider_event_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """
            INSERT INTO subscriber_organizations
            VALUES ('org_legacy', 'legacy', 'Legacy', 'ACTIVE', ?, ?)
            """,
            (created_at, created_at),
        )
        connection.execute(
            """
            INSERT INTO subscriber_subscriptions
            VALUES (
                'org_legacy', 'developer', 'ACTIVE', NULL, NULL,
                '2026-07-01T00:00:00Z', '2026-08-01T00:00:00Z',
                0, ?, ?
            )
            """,
            (created_at, created_at),
        )
        connection.execute(
            """
            INSERT INTO subscriber_billing_events
            VALUES (
                'evt-legacy', 'org_legacy', 'subscription.activated',
                'legacy-digest', '{}', ?
            )
            """,
            (created_at,),
        )
        connection.commit()

    SubscriberGovernance(db, _policy(), PEPPER)

    with sqlite3.connect(db) as connection:
        event = connection.execute(
            """
            SELECT provider_occurred_at, provider_sequence, processing_outcome
            FROM subscriber_billing_events WHERE provider_event_id = 'evt-legacy'
            """
        ).fetchone()
        subscription = connection.execute(
            """
            SELECT last_provider_occurred_at, last_provider_sequence,
                   last_provider_event_id
            FROM subscriber_subscriptions WHERE organization_id = 'org_legacy'
            """
        ).fetchone()
    assert event == (created_at, 1, "APPLIED")
    assert subscription == (created_at, 1, "evt-legacy")


def test_final_request_outcomes_audit_post_auth_denials(tmp_path, manifest):
    _store, governance, client = _stack(tmp_path, manifest)
    alpha = _provision(governance, "audit-alpha")
    beta = _provision(governance, "audit-beta")
    alpha_headers = _headers(alpha.organization_id, alpha.bootstrap_api_key)

    assert client.get(
        "/v1/subscriber/me",
        headers=_headers(beta.organization_id, alpha.bootstrap_api_key),
    ).status_code == 404
    assert _project(
        client, alpha.organization_id, alpha.bootstrap_api_key, "one"
    ).status_code == 201
    assert _project(
        client, alpha.organization_id, alpha.bootstrap_api_key, "two"
    ).status_code == 201
    quota_denied = _project(
        client, alpha.organization_id, alpha.bootstrap_api_key, "three"
    )
    assert quota_denied.status_code == 429
    assert "x-certforge-audit-code" not in quota_denied.headers

    current = client.get("/v1/subscriber/governance", headers=alpha_headers).json()
    disallowed = dict(current["config"])
    disallowed["private_worker_only"] = True
    assert client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": current["version"], "config": disallowed},
    ).status_code == 403
    assert client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": current["version"], "config": current["config"]},
    ).status_code == 200
    assert client.put(
        "/v1/subscriber/governance",
        headers=alpha_headers,
        json={"expected_version": current["version"], "config": current["config"]},
    ).status_code == 409

    with sqlite3.connect(governance.db_path) as connection:
        rows = connection.execute(
            """
            SELECT details_json FROM subscriber_audit_events
            WHERE organization_id = ? AND action = 'request.outcome'
              AND outcome = 'denied'
            """,
            (alpha.organization_id,),
        ).fetchall()
    denied = {
        (details["path"], details["status_code"], details["reason"])
        for details in (json.loads(row[0]) for row in rows)
    }
    assert ("/v1/subscriber/me", 404, "tenant_not_found") in denied
    assert ("/v1/subscriber/projects", 429, "project_quota_exceeded") in denied
    assert (
        "/v1/subscriber/governance",
        403,
        "private_workers_not_entitled",
    ) in denied
    assert ("/v1/subscriber/governance", 409, "governance_version_conflict") in denied


def test_run_quota_uses_authoritative_cross_month_billing_period(
    tmp_path, manifest
):
    policy = _policy()
    limited_policy = policy.model_copy(
        update={
            "plans": tuple(
                plan.model_copy(update={"monthly_certification_runs": 1})
                if plan.code == "developer"
                else plan
                for plan in policy.plans
            )
        }
    )
    _store, governance, client = _stack(tmp_path, manifest, policy=limited_policy)
    org = _provision(governance, "billing-period")
    project = _project(
        client, org.organization_id, org.bootstrap_api_key
    ).json()
    principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.RUN_CREATE,
    )
    now = datetime.now(UTC)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    previous_month_usage = month_start - timedelta(days=1)
    period_start = previous_month_usage - timedelta(days=1)
    period_end = now + timedelta(days=40)
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions
            SET current_period_start = ?, current_period_end = ?
            WHERE organization_id = ?
            """,
            (
                period_start.isoformat().replace("+00:00", "Z"),
                period_end.isoformat().replace("+00:00", "Z"),
                org.organization_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO subscriber_usage_events(
                organization_id, meter, quantity, idempotency_key,
                metadata_json, occurred_at
            ) VALUES (?, 'certification_runs', 1, ?, '{}', ?)
            """,
            (
                org.organization_id,
                "prior-calendar-month-run",
                previous_month_usage.isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.commit()

    with pytest.raises(SubscriberError, match="monthly_run_quota_exceeded"):
        governance.reserve_certification_run(
            principal,
            project_id=project["project_id"],
            idempotency_key="cross-month-denied",
            request_digest=_digest("cross-month-denied"),
            policy_version=manifest.manifest_id,
        )
    usage = governance.usage_summary(
        _owner(
            governance,
            org.organization_id,
            org.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["meters"]["certification_runs"] == 1
    assert usage["period_started_at"] == period_start.isoformat().replace(
        "+00:00", "Z"
    )
    assert usage["period_ended_at"] == period_end.isoformat().replace("+00:00", "Z")

    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions
            SET current_period_start = ?, current_period_end = ?
            WHERE organization_id = ?
            """,
            (
                month_start.isoformat().replace("+00:00", "Z"),
                period_end.isoformat().replace("+00:00", "Z"),
                org.organization_id,
            ),
        )
        connection.commit()
    reservation = governance.reserve_certification_run(
        principal,
        project_id=project["project_id"],
        idempotency_key="new-billing-period-run",
        request_digest=_digest("new-billing-period-run"),
        policy_version=manifest.manifest_id,
    )
    assert reservation.created is True


def test_compensation_remains_in_original_billing_period(tmp_path, manifest):
    now = [datetime(2026, 1, 31, 12, 0, tzinfo=UTC)]
    policy = _policy()
    limited_policy = policy.model_copy(
        update={
            "plans": tuple(
                plan.model_copy(update={"monthly_certification_runs": 1})
                if plan.code == "developer"
                else plan
                for plan in policy.plans
            )
        }
    )
    db = tmp_path / "certforge.sqlite3"
    EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(
        db,
        limited_policy,
        PEPPER,
        clock=lambda: now[0],
    )
    org = _provision(governance, "compensation-period")
    project_principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.PROJECT_MANAGE,
    )
    project = governance.create_project(
        project_principal,
        slug="period-project",
        name="Period Project",
        target_reference="https://github.com/example/period-project",
    )
    run_principal = _owner(
        governance,
        org.organization_id,
        org.bootstrap_api_key,
        Permission.RUN_CREATE,
    )
    old_reservation = governance.reserve_certification_run(
        run_principal,
        project_id=project["project_id"],
        idempotency_key="old-period-run",
        request_digest=_digest("old-period-run"),
        policy_version=manifest.manifest_id,
    )

    now[0] = datetime(2026, 2, 16, 12, 0, tzinfo=UTC)
    with sqlite3.connect(db) as connection:
        connection.execute(
            """
            UPDATE subscriber_subscriptions
            SET current_period_start = '2026-02-15T00:00:00Z',
                current_period_end = '2026-03-15T00:00:00Z'
            WHERE organization_id = ?
            """,
            (org.organization_id,),
        )
        connection.commit()
    governance.release_reservation(
        old_reservation,
        reason="execution_failed",
        compensate_meter=True,
    )
    new_reservation = governance.reserve_certification_run(
        run_principal,
        project_id=project["project_id"],
        idempotency_key="new-period-run",
        request_digest=_digest("new-period-run"),
        policy_version=manifest.manifest_id,
    )
    assert new_reservation.created is True
    governance.release_reservation(
        new_reservation,
        reason="execution_completed",
        compensate_meter=False,
    )
    with pytest.raises(SubscriberError, match="monthly_run_quota_exceeded"):
        governance.reserve_certification_run(
            run_principal,
            project_id=project["project_id"],
            idempotency_key="new-period-extra-run",
            request_digest=_digest("new-period-extra-run"),
            policy_version=manifest.manifest_id,
        )
    usage = governance.usage_summary(
        _owner(
            governance,
            org.organization_id,
            org.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["meters"]["certification_runs"] == 1


def test_api_submission_dispatches_exact_bound_run_to_worker(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "dispatch-e2e")
    source = tmp_path / "dispatch-source"
    source.mkdir()
    marker = tmp_path / "dispatch-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    journey = [sys.executable, "journey.py"]
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="dispatch-e2e-0001",
        journey=journey,
    )
    signer = Ed25519VerdictSigner.generate()
    abandoned = governance.claim_dispatch(
        "abandoned-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
    )
    assert abandoned is not None
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE run_id = ? AND organization_id = ?
            """,
            (run_id, org.organization_id),
        )
        connection.commit()

    dispatch, result = dispatch_once(
        governance,
        run,
        dispatcher_id="acceptance-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": signer,
            "subscribers": governance,
        },
    )

    assert dispatch is not None
    assert dispatch.run_id == run_id
    assert dispatch.attempts == 2
    assert dispatch.target_spec == {
        "path": source.resolve().as_posix(),
        "type": "local",
    }
    assert dispatch.journey == journey
    assert result is not None and result["state"] == RunState.COMPLETED.value
    assert marker.read_text(encoding="utf-8") == "executed"
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "COMPLETE"


@pytest.mark.parametrize("crash_stage", ("reserved", "run_created"))
def test_dispatcher_recovers_crash_after_durable_reservation(
    tmp_path, manifest, crash_stage
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "durable-intake")
    project_response = _project(
        client,
        org.organization_id,
        org.bootstrap_api_key,
        slug="durable-intake-app",
    )
    assert project_response.status_code == 201
    source = tmp_path / "durable-intake-source"
    source.mkdir()
    marker = tmp_path / "durable-intake-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('recovered', encoding='utf-8')\n",
        encoding="utf-8",
    )
    acquired = acquire_target(
        {"type": "local", "path": str(source)},
        tmp_path / ".unused-durable-intake-acquisition",
    )
    target = TargetIdentity(
        tenant_id=org.organization_id,
        target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref,
        artifact_sha256=acquired.artifact_sha256,
    )
    request = SubmitRequest.model_validate(
        {
            "tenant_id": org.organization_id,
            "project_id": project_response.json()["project_id"],
            "target": {
                "target_type": "local",
                "identity_digest": target.identity_digest,
                "reference": acquired.canonical_ref,
                "path": source.resolve().as_posix(),
            },
            "environment": {
                "identity_digest": _worker_environment().identity_digest,
                "runner_image_digest": "sha256:"
                + _worker_environment().runner_image_sha256,
            },
            "policy_version": manifest.manifest_id,
            "idempotency_key": "durable-intake-0001",
            "journey": [sys.executable, "journey.py"],
        }
    )
    principal = governance.authenticate(
        org.bootstrap_api_key,
        tenant_hint=org.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.durable-intake.reserve",
    )
    reservation = governance.reserve_certification_run(
        principal,
        project_id=str(request.project_id),
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest(),
        policy_version=request.policy_version,
        target_type=request.target.target_type,
        target_reference=request.target.reference,
        target_identity_digest=request.target.identity_digest,
        dispatch_target_spec=request.target.worker_spec(),
        journey=request.journey,
        submit_request=request.model_dump(exclude_none=True),
    )
    assert reservation.created is True
    if crash_stage == "run_created":
        store.register_declared_run(
            run_id=request.run_id(manifest.digest),
            tenant_id=org.organization_id,
            target_type=request.target.target_type,
            target_identity_digest=request.target.identity_digest,
            target_reference=request.target.reference,
            project_id=request.project_id,
            environment_identity_digest=request.environment.identity_digest,
            environment_json=request.environment.model_dump(exclude_none=True),
            policy_version=request.policy_version,
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.digest,
        )
        assert store.get_run(request.run_id(manifest.digest), org.organization_id)["state"] == "CREATED"
    else:
        with pytest.raises(KeyError):
            store.get_run(request.run_id(manifest.digest), org.organization_id)

    dispatch, result = dispatch_once(
        governance,
        run,
        dispatcher_id="durable-intake-dispatcher",
        run_id=request.run_id(manifest.digest),
        organization_id=org.organization_id,
        worker_options={
            "store": store,
            "manifest": manifest,
            "signer": Ed25519VerdictSigner.generate(),
            "subscribers": governance,
        },
    )

    assert dispatch is not None
    assert dispatch.run_id == request.run_id(manifest.digest)
    assert result is not None and result["state"] == RunState.COMPLETED.value
    assert marker.read_text(encoding="utf-8") == "recovered"
    assert governance.pending_intake_requests() == []
    assert governance.dispatch_status(request.run_id(manifest.digest), org.organization_id)["state"] == "COMPLETE"


def test_worker_lease_heartbeat_and_started_crash_recovery(tmp_path, manifest):
    now = [datetime.now(UTC)]
    policy = _policy().model_copy(
        update={
            "worker_claim_lease_seconds": 4,
            "worker_heartbeat_interval_seconds": 1,
            "dispatch_claim_lease_seconds": 4,
        }
    )
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(db, policy, PEPPER, clock=lambda: now[0])
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
    org = _provision(governance, "lease-recovery")
    source = tmp_path / "lease-source"
    source.mkdir()
    (source / "hello.py").write_text("print('lease')\n", encoding="utf-8")
    run_id, target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="lease-recovery-0001",
    )
    dispatch = governance.claim_dispatch(
        "lease-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
    )
    assert dispatch is not None
    signer = Ed25519VerdictSigner.generate()
    claim = governance.claim_worker_run(
        run_id=run_id,
        organization_id=org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=signer.key_id,
    )
    authorization = governance.authorize_worker_execution(
        claim,
        target_identity=target.to_dict(),
        target_identity_digest=target.identity_digest,
        environment_identity=_worker_environment().to_dict(),
        environment_identity_digest=_worker_environment().identity_digest,
    )
    assert authorization.subscription_version >= 1

    now[0] += timedelta(seconds=3)
    renewed_expiry = governance.heartbeat_worker_claim(claim)
    assert parse_utc_iso(renewed_expiry) == now[0] + timedelta(seconds=4)
    now[0] += timedelta(seconds=3)
    assert governance.recover_expired_claims(org.organization_id) == 0

    now[0] += timedelta(seconds=2)
    assert governance.recover_expired_claims(org.organization_id) == 1
    assert (
        store.get_run(run_id, org.organization_id)["state"]
        == RunState.INFRASTRUCTURE_FAILURE.value
    )
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "FAILED"
    usage = governance.usage_summary(
        _owner(
            governance,
            org.organization_id,
            org.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0
    with sqlite3.connect(db) as connection:
        compensation = connection.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(quantity), 0)
            FROM subscriber_usage_events
            WHERE organization_id = ? AND idempotency_key = ?
            """,
            (
                org.organization_id,
                f"claim-crash:lease-recovery-0001@{manifest.digest[:16]}",
            ),
        ).fetchone()
    assert compensation == (1, -1)


def test_expired_prestart_worker_claim_requeues_without_compensation(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "prestart-recovery")
    source = tmp_path / "prestart-source"
    source.mkdir()
    (source / "hello.py").write_text("print('prestart')\n", encoding="utf-8")
    run_id, target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="prestart-recovery-0001",
    )
    dispatch = governance.claim_dispatch(
        "prestart-dispatcher",
        run_id=run_id,
        organization_id=org.organization_id,
    )
    assert dispatch is not None
    signer = Ed25519VerdictSigner.generate()
    governance.claim_worker_run(
        run_id=run_id,
        organization_id=org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=signer.key_id,
    )
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_reservations
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE run_id = ? AND organization_id = ?
            """,
            (run_id, org.organization_id),
        )
        connection.commit()

    assert governance.recover_expired_claims(org.organization_id) == 1
    assert store.get_run(run_id, org.organization_id)["state"] == RunState.QUEUED.value
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "PENDING"
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


def test_dispatch_retry_exhaustion_terminalizes_and_compensates(tmp_path, manifest):
    policy = _policy().model_copy(update={"max_dispatch_attempts": 1})
    store, governance, client = _stack(tmp_path, manifest, policy=policy)
    org = _provision(governance, "dispatch-exhaustion")
    source = tmp_path / "dispatch-exhaustion-source"
    source.mkdir()
    (source / "hello.py").write_text("print('dispatch')\n", encoding="utf-8")
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="dispatch-exhaustion-0001",
    )
    assert (
        governance.claim_dispatch(
            "crashing-dispatcher",
            run_id=run_id,
            organization_id=org.organization_id,
        )
        is not None
    )
    with sqlite3.connect(governance.db_path) as connection:
        connection.execute(
            """
            UPDATE subscriber_run_dispatches
            SET lease_expires_at = '2000-01-01T00:00:00Z'
            WHERE run_id = ? AND organization_id = ?
            """,
            (run_id, org.organization_id),
        )
        connection.commit()

    assert (
        governance.claim_dispatch(
            "recovery-dispatcher",
            run_id=run_id,
            organization_id=org.organization_id,
        )
        is None
    )
    assert (
        store.get_run(run_id, org.organization_id)["state"]
        == RunState.INFRASTRUCTURE_FAILURE.value
    )
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "FAILED"
    usage = governance.usage_summary(
        _owner(
            governance,
            org.organization_id,
            org.bootstrap_api_key,
            Permission.USAGE_READ,
        )
    )
    assert usage["meters"]["certification_runs"] == 0
    assert usage["active_run_reservations"] == 0


@pytest.mark.parametrize(
    ("event_type", "expected_status"),
    [
        ("payment.failed", OrganizationStatus.PAST_DUE),
        ("subscription.suspended", OrganizationStatus.SUSPENDED),
        ("subscription.cancelled", OrganizationStatus.CANCELLED),
    ],
)
def test_plan_change_preserves_risk_lifecycle_state(
    tmp_path, manifest, event_type, expected_status
):
    _store, governance, _client = _stack(tmp_path, manifest)
    org = _provision(governance, f"plan-state-{expected_status.value.lower()}")
    occurred_at = datetime.now(UTC)
    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id=f"evt-{expected_status.value.lower()}",
        event_type=event_type,
        payload={"reason": "risk"},
        provider_occurred_at=occurred_at,
        provider_sequence=10,
    )
    status = governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id=f"evt-plan-{expected_status.value.lower()}",
        event_type="subscription.plan_changed",
        payload={
            "current_period_start": occurred_at.isoformat().replace("+00:00", "Z"),
            "current_period_end": (occurred_at + timedelta(days=30))
            .isoformat()
            .replace("+00:00", "Z"),
        },
        provider_occurred_at=occurred_at + timedelta(minutes=1),
        provider_sequence=11,
        plan_code="professional",
    )

    assert status is expected_status
    with sqlite3.connect(governance.db_path) as connection:
        row = connection.execute(
            """
            SELECT o.status, s.status, s.plan_code
            FROM subscriber_organizations o
            JOIN subscriber_subscriptions s USING (organization_id)
            WHERE o.organization_id = ?
            """,
            (org.organization_id,),
        ).fetchone()
    assert row == (expected_status.value, expected_status.value, "professional")


def test_concurrent_suspension_wins_before_execution_boundary(
    tmp_path, manifest, monkeypatch
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "suspension-boundary")
    source = tmp_path / "suspension-source"
    source.mkdir()
    marker = tmp_path / "suspension-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, _target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="suspension-boundary-0001",
    )
    entered_boundary = threading.Event()
    release_boundary = threading.Event()
    original_authorize = governance.authorize_worker_execution

    def blocked_authorize(claim, **identity):
        entered_boundary.set()
        assert release_boundary.wait(timeout=10)
        return original_authorize(claim, **identity)

    monkeypatch.setattr(governance, "authorize_worker_execution", blocked_authorize)
    result_holder: dict[str, dict] = {}

    def execute() -> None:
        result_holder["result"] = run(
            run_id,
            org.organization_id,
            {"type": "local", "path": str(source)},
            store=store,
            manifest=manifest,
            signer=Ed25519VerdictSigner.generate(),
            subscribers=governance,
            journey=[sys.executable, "journey.py"],
        )

    worker = threading.Thread(target=execute)
    worker.start()
    assert entered_boundary.wait(timeout=10)
    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-boundary-suspend",
        event_type="subscription.suspended",
        payload={"reason": "risk"},
        provider_occurred_at=datetime.now(UTC),
        provider_sequence=1,
    )
    release_boundary.set()
    worker.join(timeout=15)
    assert worker.is_alive() is False

    result = result_holder["result"]
    assert result["error"] == "subscriber_execution_denied"
    assert result["state"] == RunState.CANCELLED.value
    assert marker.exists() is False
    assert governance.dispatch_status(run_id, org.organization_id)["state"] == "CANCELLED"


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
    assert contract["worker_execution"]["lookup_failure_mode"].startswith("fail closed")
    assert "current_period_start" in contract["quota_meters"][2]
    assert "final path" in contract["audit"]["final_request_outcomes"]
    assert policy.worker_heartbeat_interval_seconds < policy.worker_claim_lease_seconds
    assert "transactional outbox" in contract["worker_execution"]["dispatch"]


def test_api_worker_reconciles_canonical_identities_and_rejects_digest_drift(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(
        governance, "identity-reconciliation", plan_code="professional"
    )
    source = tmp_path / "identity-source"
    source.mkdir()
    marker = tmp_path / "identity-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, target = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="identity-reconciliation-0001",
        journey=[sys.executable, "journey.py"],
    )
    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    persisted = store.get_run(run_id, org.organization_id)
    assert result["state"] == RunState.COMPLETED.value
    assert result["signed"] is True
    assert marker.exists()
    assert json.loads(persisted["target_identity_json"]) == target.to_dict()
    assert json.loads(persisted["environment_identity_json"]) == _worker_environment().to_dict()
    assert store.latest_signed_verdict(run_id, org.organization_id) is not None

    drift_source = tmp_path / "identity-drift-source"
    drift_source.mkdir()
    drift_marker = tmp_path / "identity-drift-executed"
    (drift_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(drift_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    drift_run_id, _ = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        drift_source,
        key="identity-reconciliation-0002",
        journey=[sys.executable, "journey.py"],
    )
    (drift_source / "post-submit-change.txt").write_text("drift\n", encoding="utf-8")
    drift_result = run(
        drift_run_id,
        org.organization_id,
        {"type": "local", "path": str(drift_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert drift_result["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert drift_result["detail"] == "worker_target_identity_mismatch"
    assert not drift_marker.exists()
    assert store.latest_signed_verdict(drift_run_id, org.organization_id) is None

    environment_source = tmp_path / "environment-drift-source"
    environment_source.mkdir()
    environment_marker = tmp_path / "environment-drift-executed"
    (environment_source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(environment_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    environment_project = _project(
        client,
        org.organization_id,
        org.bootstrap_api_key,
        slug="environment-drift",
    ).json()
    environment_acquired = acquire_target(
        {"type": "local", "path": str(environment_source)},
        environment_source.parent / ".unused-environment-drift",
    )
    environment_target = TargetIdentity(
        tenant_id=org.organization_id,
        target_type=environment_acquired.target_type,
        canonical_ref=environment_acquired.canonical_ref,
        artifact_sha256=environment_acquired.artifact_sha256,
    )
    environment_response = client.post(
        "/v1/certifications",
        headers=_headers(org.organization_id, org.bootstrap_api_key),
        json={
            "tenant_id": org.organization_id,
            "project_id": environment_project["project_id"],
            "target": {
                "target_type": "local",
                "identity_digest": environment_target.identity_digest,
                "reference": environment_target.canonical_ref,
                "path": environment_source.resolve().as_posix(),
            },
            "environment": {
                "identity_digest": _digest("incorrect-worker-environment"),
                "runner_image_digest": "sha256:" + _digest("incorrect-runner"),
            },
            "policy_version": manifest.manifest_id,
            "idempotency_key": "identity-reconciliation-0003",
            "journey": [sys.executable, "journey.py"],
        },
    )
    environment_run_id = environment_response.json()["run_id"]
    environment_result = run(
        environment_run_id,
        org.organization_id,
        {"type": "local", "path": str(environment_source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert environment_response.status_code == 201
    assert environment_result["state"] == RunState.INFRASTRUCTURE_FAILURE.value
    assert environment_result["detail"] == "worker_environment_identity_mismatch"
    assert not environment_marker.exists()
    assert store.latest_signed_verdict(environment_run_id, org.organization_id) is None


def test_api_worker_reconciles_exact_git_commit_without_declared_tree_digest(
    tmp_path, manifest, monkeypatch
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "git-identity-reconciliation", plan_code="professional")
    project_response = _project(
        client,
        org.organization_id,
        org.bootstrap_api_key,
        slug="git-exact-commit",
    )
    assert project_response.status_code == 201

    source = tmp_path / "git-exact-source"
    source.mkdir()
    marker = tmp_path / "git-exact-executed"
    (source / "journey.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    source_commit = "a" * 40
    repository = "https://github.com/echo/example.git"
    reference = f"{repository}@{source_commit}"
    artifact_sha256 = _digest("verified-acquired-git-tree")
    environment = _worker_environment()
    declared_digest = declared_target_identity_digest(
        org.organization_id,
        "git",
        None,
        source_commit,
        reference,
    )
    payload = {
        "tenant_id": org.organization_id,
        "project_id": project_response.json()["project_id"],
        "target": {
            "target_type": "git",
            "identity_digest": declared_digest,
            "reference": reference,
            "source_commit": source_commit,
            "url": repository,
            "ref": source_commit,
        },
        "environment": {
            "identity_digest": environment.identity_digest,
            "runner_image_digest": "sha256:" + environment.runner_image_sha256,
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": "git-identity-reconciliation-0001",
        "journey": [sys.executable, "journey.py"],
    }
    response = client.post(
        "/v1/certifications",
        headers=_headers(org.organization_id, org.bootstrap_api_key),
        json=payload,
    )
    assert response.status_code == 201, response.text
    request = SubmitRequest.model_validate(payload)
    assert request.target.worker_spec()["source_commit"] == source_commit
    monkeypatch.setattr(
        "echo_certification_forge.run_worker.acquire_target",
        lambda _spec, _dest: AcquiredTarget(
            source,
            "git",
            reference,
            artifact_sha256,
            source_commit,
        ),
    )

    result = run(
        response.json()["run_id"],
        org.organization_id,
        request.target.worker_spec(),
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )

    persisted = store.get_run(response.json()["run_id"], org.organization_id)
    expected_target = TargetIdentity(
        tenant_id=org.organization_id,
        target_type="git",
        canonical_ref=reference,
        artifact_sha256=artifact_sha256,
        source_commit=source_commit,
    )
    assert result["state"] == RunState.COMPLETED.value
    assert result["signed"] is True
    assert marker.exists()
    assert json.loads(persisted["target_identity_json"]) == expected_target.to_dict()
    assert persisted["target_identity_digest"] == expected_target.identity_digest

    replay = client.post(
        "/v1/certifications",
        headers=_headers(org.organization_id, org.bootstrap_api_key),
        json=payload,
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["run_id"] == response.json()["run_id"]
    assert replay.json()["target_identity_digest"] == expected_target.identity_digest


def test_atomic_materialization_rolls_back_and_concurrent_suspension_terminalizes(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "atomic-materialization")
    source = tmp_path / "atomic-source"
    source.mkdir()
    (source / "journey.py").write_text("print('atomic')\n", encoding="utf-8")
    project = _project(
        client,
        org.organization_id,
        org.bootstrap_api_key,
        slug="atomic-project",
    ).json()
    acquired = acquire_target(
        {"type": "local", "path": str(source)},
        source.parent / ".unused-atomic-acquisition",
    )
    target = TargetIdentity(
        tenant_id=org.organization_id,
        target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref,
        artifact_sha256=acquired.artifact_sha256,
    )
    environment = _worker_environment()
    request = SubmitRequest.model_validate(
        {
            "tenant_id": org.organization_id,
            "project_id": project["project_id"],
            "target": {
                "target_type": "local",
                "identity_digest": target.identity_digest,
                "reference": target.canonical_ref,
                "path": source.resolve().as_posix(),
            },
            "environment": {
                "identity_digest": environment.identity_digest,
                "runner_image_digest": "sha256:" + environment.runner_image_sha256,
            },
            "policy_version": manifest.manifest_id,
            "idempotency_key": "atomic-materialization-0001",
            "journey": [sys.executable, "journey.py"],
        }
    )
    principal = governance.authenticate(
        org.bootstrap_api_key,
        tenant_hint=org.organization_id,
        permission=Permission.RUN_CREATE,
        action="acceptance.atomic.reserve",
    )
    reservation = governance.reserve_certification_run(
        principal,
        project_id=str(request.project_id),
        idempotency_key=request.idempotency_key,
        request_digest=request.request_digest(),
        policy_version=request.policy_version,
        target_type=request.target.target_type,
        target_reference=request.target.reference,
        target_identity_digest=request.target.identity_digest,
        dispatch_target_spec=request.target.worker_spec(),
        journey=request.journey,
        submit_request=request.model_dump(exclude_none=True),
    )
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_atomic_dispatch
            BEFORE INSERT ON subscriber_run_dispatches
            BEGIN SELECT RAISE(ABORT, 'simulated dispatch failure'); END
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="simulated dispatch failure"):
        governance.materialize_reserved_run(
            reservation,
            run_id=request.run_id(manifest.digest),
            target_type=request.target.target_type,
            target_reference=request.target.reference,
            target_identity_digest=request.target.identity_digest,
            environment_identity_digest=request.environment.identity_digest,
            environment_json=request.environment.model_dump(exclude_none=True),
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.digest,
            target_spec=request.target.worker_spec(),
            journey=request.journey,
        )
    with sqlite3.connect(store.db_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runs WHERE run_id = ?", (request.run_id(manifest.digest),)
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """
                SELECT state FROM subscriber_run_reservations
                WHERE organization_id = ? AND idempotency_key = ?
                """,
                (org.organization_id, request.idempotency_key),
            ).fetchone()[0]
            == "RESERVED"
        )
        connection.execute("DROP TRIGGER fail_atomic_dispatch")

    store.register_declared_run(
        run_id=request.run_id(manifest.digest),
        tenant_id=org.organization_id,
        target_type=request.target.target_type,
        target_identity_digest=request.target.identity_digest,
        target_reference=request.target.reference,
        project_id=request.project_id,
        environment_identity_digest=request.environment.identity_digest,
        environment_json=request.environment.model_dump(exclude_none=True),
        policy_version=request.policy_version,
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
    )
    start = threading.Barrier(2)
    outcomes: list[str] = []

    def materialize() -> None:
        start.wait()
        try:
            governance.materialize_reserved_run(
                reservation,
                run_id=request.run_id(manifest.digest),
                target_type=request.target.target_type,
                target_reference=request.target.reference,
                target_identity_digest=request.target.identity_digest,
                environment_identity_digest=request.environment.identity_digest,
                environment_json=request.environment.model_dump(exclude_none=True),
                manifest_id=manifest.manifest_id,
                manifest_digest=manifest.digest,
                target_spec=request.target.worker_spec(),
                journey=request.journey,
            )
            outcomes.append("materialized")
        except SubscriberError as exc:
            outcomes.append(exc.code)

    materializer = threading.Thread(target=materialize)
    materializer.start()
    start.wait()
    governance.apply_billing_event(
        organization_id=org.organization_id,
        provider_event_id="evt-atomic-suspend",
        event_type="subscription.suspended",
        payload={"reason": "risk"},
        provider_occurred_at=datetime.now(UTC) + timedelta(seconds=1),
        provider_sequence=1,
    )
    materializer.join(timeout=10)
    assert not materializer.is_alive()
    assert outcomes[0] in {"materialized", "run_reservation_inactive"}
    assert store.get_run(request.run_id(manifest.digest), org.organization_id)["state"] == "CANCELLED"
    with sqlite3.connect(store.db_path) as connection:
        reservation_state = connection.execute(
            """
            SELECT state FROM subscriber_run_reservations
            WHERE organization_id = ? AND idempotency_key = ?
            """,
            (org.organization_id, request.idempotency_key),
        ).fetchone()[0]
        pending_dispatches = connection.execute(
            """
            SELECT COUNT(*) FROM subscriber_run_dispatches
            WHERE run_id = ? AND state IN ('PENDING', 'CLAIMED')
            """,
            (request.run_id(manifest.digest),),
        ).fetchone()[0]
    assert reservation_state == "RELEASED"
    assert pending_dispatches == 0


def test_heartbeat_storage_loss_terminates_customer_process_before_signing(
    tmp_path, manifest, monkeypatch
):
    policy = _policy().model_copy(
        update={
            "worker_claim_lease_seconds": 10,
            "worker_heartbeat_interval_seconds": 1,
        }
    )
    store, governance, client = _stack(tmp_path, manifest, policy=policy)
    org = _provision(governance, "heartbeat-loss")
    source = tmp_path / "heartbeat-source"
    source.mkdir()
    marker = tmp_path / "heartbeat-customer-completed"
    (source / "journey.py").write_text(
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(5)\n"
        f"Path({str(marker)!r}).write_text('completed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    run_id, _ = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="heartbeat-loss-0001",
        journey=[sys.executable, "journey.py"],
    )

    def fail_heartbeat(_claim):
        raise sqlite3.OperationalError("simulated heartbeat storage loss")

    monkeypatch.setattr(governance, "heartbeat_worker_claim", fail_heartbeat)
    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert result["error"] == "subscriber_execution_fenced"
    assert result["detail"] == "worker_run_heartbeat_storage_failed"
    assert not marker.exists()
    assert store.latest_signed_verdict(run_id, org.organization_id) is None


def test_expired_lease_cannot_commit_signed_completion(tmp_path, manifest, monkeypatch):
    now = [datetime.now(UTC)]
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(db, _policy(), PEPPER, clock=lambda: now[0])
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
    org = _provision(governance, "completion-expiry")
    source = tmp_path / "completion-expiry-source"
    source.mkdir()
    (source / "journey.py").write_text("print('completion')\n", encoding="utf-8")
    run_id, _ = _submit_local_run(
        client,
        manifest,
        org.organization_id,
        org.bootstrap_api_key,
        source,
        key="completion-expiry-0001",
        journey=[sys.executable, "journey.py"],
    )
    original_complete = governance.complete_worker_execution

    def expire_before_completion(claim, envelope):
        now[0] += timedelta(seconds=governance.policy.worker_claim_lease_seconds + 1)
        return original_complete(claim, envelope)

    monkeypatch.setattr(governance, "complete_worker_execution", expire_before_completion)
    result = run(
        run_id,
        org.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert result["error"] == "subscriber_execution_fenced"
    assert result["detail"] == "worker_run_claim_inactive"
    assert store.latest_signed_verdict(run_id, org.organization_id) is None
    assert governance.recover_expired_claims(org.organization_id) == 1
    assert (
        store.get_run(run_id, org.organization_id)["state"]
        == RunState.INFRASTRUCTURE_FAILURE.value
    )


@pytest.mark.parametrize("deployment", ["staging", "production"])
def test_deploy_environment_boots_and_authenticated_smoke_is_green(
    tmp_path, deployment
):
    repo = Path(__file__).parents[1]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(repo / "src"),
            "ECHO_CERTFORGE_DB": str(tmp_path / f"{deployment}.sqlite3"),
            "ECHO_CERTFORGE_EVIDENCE_ROOT": str(tmp_path / f"{deployment}-evidence"),
            "ECHO_CERTFORGE_POLICY": str(
                repo / "policies" / "mandatory-rules.v1.json"
            ),
            "ECHO_CERTFORGE_SUBSCRIBER_POLICY": str(
                repo / "policies" / "subscriber-governance.v1.json"
            ),
            "ECHO_CERTFORGE_TRUSTED_KEYS": str(tmp_path / "trusted-keys"),
            "ECHO_CERTFORGE_SUBSCRIBERS_ENABLED": "1",
            "ECHO_CERTFORGE_API_KEY_PEPPER": (
                f"p7-{deployment}-deploy-smoke-pepper-material-32-bytes"
            ),
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "echo_certification_forge.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        healthy = False
        for _ in range(100):
            if process.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=1) as response:
                    healthy = response.status == 200
                    if healthy:
                        break
            except OSError:
                time.sleep(0.05)
        output = ""
        if process.poll() is not None and process.stdout is not None:
            output = process.stdout.read()
        assert healthy and process.poll() is None, output
        smoke = subprocess.run(
            [sys.executable, "deploy/smoke_live.py", base],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert smoke.returncode == 0, smoke.stdout + smoke.stderr
        assert "SMOKE GREEN" in smoke.stdout
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _artifact_fixture(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    owner = _provision(governance, "artifact-owner", plan_code="professional")
    other = _provision(governance, "artifact-other", plan_code="professional")
    run_id = "cert-p7-artifact"
    store.register_declared_run(
        run_id,
        owner.organization_id,
        "git",
        _digest("artifact-target"),
        "https://github.com/example/artifact@0123456789abcdef",
        _digest("artifact-environment"),
        {"runner_image_digest": "sha256:" + _digest("artifact-runner")},
        manifest.manifest_id,
        manifest.manifest_id,
        manifest.digest,
    )
    descriptor = store.append_artifact(
        run_id,
        owner.organization_id,
        f"{run_id}-tenant_isolation",
        b"verified customer evidence",
        "application/octet-stream",
        "p8c.acceptance",
    )
    return store, client, owner, other, run_id, descriptor


def test_subscriber_artifact_download_is_bounded_tenant_scoped_and_audited(
    tmp_path, manifest
):
    store, client, owner, other, run_id, descriptor = _artifact_fixture(
        tmp_path, manifest
    )
    route = f"/v1/subscriber/certifications/{run_id}/evidence/{descriptor['artifact_id']}"

    denied = client.get(route)
    assert denied.status_code == 401
    isolated = client.get(
        route,
        headers=_headers(other.organization_id, other.bootstrap_api_key),
    )
    assert isolated.status_code == 404

    owner_headers = _headers(owner.organization_id, owner.bootstrap_api_key)
    downloaded = client.get(route, headers=owner_headers)
    assert downloaded.status_code == 200
    body = downloaded.json()
    content = base64.b64decode(body["payload_base64"], validate=True)
    assert body["encoding"] == "base64"
    assert body["run_id"] == run_id
    assert body["artifact_id"] == descriptor["artifact_id"]
    assert body["sha256"] == descriptor["sha256"]
    assert body["size_bytes"] == len(content) == descriptor["size_bytes"]
    assert hashlib.sha256(content).hexdigest() == body["sha256"]
    assert body["redaction_status"] in {"COMPLETE", "NOT_REQUIRED"}

    audit = client.get("/v1/subscriber/audit", headers=owner_headers)
    event = next(row for row in audit.json() if row["action"] == "evidence.download")
    assert event["resource_id"] == descriptor["artifact_id"]
    assert event["details"] == {
        "run_id": run_id,
        "sha256": descriptor["sha256"],
        "size_bytes": descriptor["size_bytes"],
    }


def test_subscriber_artifact_download_rejects_unverified_bytes(tmp_path, manifest):
    store, client, owner, _other, run_id, descriptor = _artifact_fixture(
        tmp_path, manifest
    )
    artifact = store.evidence_root / descriptor["relative_path"]
    artifact.write_bytes(b"tampered")
    response = client.get(
        f"/v1/subscriber/certifications/{run_id}/evidence/{descriptor['artifact_id']}",
        headers=_headers(owner.organization_id, owner.bootstrap_api_key),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "artifact_integrity_failed"


def test_subscriber_telemetry_is_bounded_tenant_scoped_and_truthful(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    owner = _provision(governance, "telemetry", plan_code="professional")
    other = _provision(governance, "telemetry-other", plan_code="professional")
    run_id = "cert-p7-telemetry"
    store.register_declared_run(
        run_id,
        owner.organization_id,
        "git",
        _digest("telemetry-target"),
        "https://github.com/example/telemetry@0123456789abcdef",
        _digest("telemetry-environment"),
        {"runner_image_digest": "sha256:" + _digest("telemetry-runner")},
        manifest.manifest_id,
        manifest.manifest_id,
        manifest.digest,
    )
    store.transition_state(
        run_id,
        owner.organization_id,
        RunState.QUEUED,
        "p8c.acceptance",
        "accepted for execution",
        "p8c.telemetry.v1",
    )

    assert client.get("/v1/subscriber/telemetry").status_code == 401
    owner_headers = _headers(owner.organization_id, owner.bootstrap_api_key)
    response = client.get("/v1/subscriber/telemetry", headers=owner_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["queue"]["queued"] == body["queue"]["active"] == 1
    assert body["queue"]["total"] == 1
    assert body["capacity"]["active_runs"] == 1
    assert body["capacity"]["concurrent_run_limit"] == 4
    assert body["capacity"]["quota_slots_remaining"] == 3
    assert body["capacity"]["runner_health"] == "NO_AUTHENTICATED_HEARTBEATS"
    assert body["capacity"]["capacity_basis"] == "subscription_quota_only"
    assert body["capacity"]["authenticated_runner_source"]["registered"] == 0
    assert body["capacity"]["authenticated_runner_source"]["source"] == "authenticated_ed25519_worker_reports"
    assert body["budgets"]["certification_runs"]["limit"] == 500
    assert body["adapters"]["inventory_status"] == "EMPTY"
    assert body["adapters"]["maturity_status"] == "UNAVAILABLE"
    assert body["adapters"]["source"] == "authenticated_signed_adapter_bundles"
    assert len(body["authenticated_source_snapshot_sha256"]) == 64
    recent = body["state_machine"]["recent_runs"]
    assert len(recent) == 1 and recent[0]["run_id"] == run_id
    timeline = recent[0]["timeline"]
    assert len(timeline) == 1
    assert timeline[0]["prior_state"] == "CREATED"
    assert timeline[0]["next_state"] == "QUEUED"
    assert timeline[0]["workflow_version"]
    assert timeline[0]["created_at"].endswith("Z")
    assert "actor" not in json.dumps(body)
    assert "accepted for execution" not in json.dumps(body)
    assert owner.bootstrap_api_key not in json.dumps(body)

    isolated = client.get(
        "/v1/subscriber/telemetry",
        headers=_headers(other.organization_id, other.bootstrap_api_key),
    )
    assert isolated.status_code == 200
    assert isolated.json()["queue"]["total"] == 0


def test_subscriber_rerun_creates_immutable_lineage_without_mutating_source(
    tmp_path, manifest
):
    store, governance, client = _stack(tmp_path, manifest)
    owner = _provision(governance, "rerun", plan_code="professional")
    other = _provision(governance, "rerun-other", plan_code="professional")
    source_path = tmp_path / "rerun-source"
    source_path.mkdir()
    (source_path / "journey.py").write_text(
        "print('rerun-source-ok')\n", encoding="utf-8"
    )
    source_run_id, _target = _submit_local_run(
        client,
        manifest,
        owner.organization_id,
        owner.bootstrap_api_key,
        source_path,
        key="subscriber-rerun-source-0001",
        journey=[sys.executable, "journey.py"],
    )
    result = run(
        source_run_id,
        owner.organization_id,
        {"type": "local", "path": str(source_path)},
        store=store,
        manifest=manifest,
        signer=Ed25519VerdictSigner.generate(),
        entitled=frozenset(),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert result["state"] == RunState.COMPLETED.value
    source_before = store.get_run(source_run_id, owner.organization_id)
    evidence_before = store.list_evidence(source_run_id, owner.organization_id)
    verdict_before = store.latest_signed_verdict(
        source_run_id, owner.organization_id
    )
    assert evidence_before and verdict_before is not None

    headers = _headers(owner.organization_id, owner.bootstrap_api_key)
    rerun = client.post(
        f"/v1/subscriber/certifications/{source_run_id}/rerun",
        headers=headers,
        json={"idempotency_key": "desktop-rerun-attempt-01"},
    )
    assert rerun.status_code == 201
    body = rerun.json()
    rerun_id = body["run_id"]
    assert rerun_id != source_run_id
    assert body["source_run_id"] == source_run_id
    assert body["rerun_sequence"] == 1
    assert body["state"] == "QUEUED"
    assert body["release_verdict"] == "NOT_READY"
    assert body["evidence_merkle_root"] is None
    assert body["target_identity_digest"] == source_before["target_identity_digest"]
    assert body["environment_identity_digest"] == source_before[
        "environment_identity_digest"
    ]

    replay = client.post(
        f"/v1/subscriber/certifications/{source_run_id}/rerun",
        headers=headers,
        json={"idempotency_key": "desktop-rerun-attempt-01"},
    )
    assert replay.status_code == 200
    assert replay.json()["run_id"] == rerun_id
    assert replay.json()["rerun_sequence"] == 1

    nonterminal = client.post(
        f"/v1/subscriber/certifications/{rerun_id}/rerun",
        headers=headers,
        json={"idempotency_key": "desktop-rerun-nonterminal"},
    )
    assert nonterminal.status_code == 409
    assert nonterminal.json()["detail"] == "source_run_not_terminal"
    isolated = client.post(
        f"/v1/subscriber/certifications/{source_run_id}/rerun",
        headers=_headers(other.organization_id, other.bootstrap_api_key),
        json={"idempotency_key": "desktop-rerun-isolation"},
    )
    assert isolated.status_code == 404

    assert store.get_run(source_run_id, owner.organization_id) == source_before
    assert store.list_evidence(source_run_id, owner.organization_id) == evidence_before
    assert store.latest_signed_verdict(
        source_run_id, owner.organization_id
    ) == verdict_before
    with pytest.raises(sqlite3.IntegrityError, match="run lineage is immutable"):
        with store._connection() as connection:
            connection.execute(
                "UPDATE runs SET source_run_id = ? WHERE run_id = ?",
                (rerun_id, rerun_id),
            )
    audit = client.get("/v1/subscriber/audit", headers=headers).json()
    event = next(row for row in audit if row["action"] == "certification.rerun")
    assert event["resource_id"] == rerun_id
    assert event["details"]["source_run_id"] == source_run_id
    assert owner.bootstrap_api_key not in json.dumps(audit)


def test_legal_hold_lifecycle_and_public_verification_use_hardened_subscriber_auth(
    tmp_path, manifest
):
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(db, _policy(), PEPPER)
    trusted = TrustedPublicKeyRegistry.empty()
    client = TestClient(create_app(ServiceContext(store, manifest, trusted, governance)))
    owner = _provision(governance, "admin-surface", plan_code="professional")
    source = tmp_path / "admin-surface-source"
    source.mkdir()
    (source / "journey.py").write_text("print('verified')\n", encoding="utf-8")
    run_id, _target = _submit_local_run(
        client,
        manifest,
        owner.organization_id,
        owner.bootstrap_api_key,
        source,
        key="admin-surface-run-0001",
        journey=[sys.executable, "journey.py"],
    )
    signer = Ed25519VerdictSigner.generate()
    trusted.add_pem(signer.public_key_pem)
    result = run(
        run_id,
        owner.organization_id,
        {"type": "local", "path": str(source)},
        store=store,
        manifest=manifest,
        signer=signer,
        entitled=frozenset({owner.organization_id}),
        subscribers=governance,
        journey=[sys.executable, "journey.py"],
    )
    assert result["state"] == RunState.COMPLETED.value
    headers = _headers(owner.organization_id, owner.bootstrap_api_key)

    hold = client.post(
        "/v1/subscriber/legal-holds",
        headers=headers,
        json={"hold_id": "hold-admin-1", "run_id": run_id, "reason": "audit"},
    )
    assert hold.status_code == 201 and hold.json()["active"] is True
    release = client.delete(
        "/v1/subscriber/legal-holds/hold-admin-1", headers=headers
    )
    assert release.status_code == 200 and release.json()["active"] is False

    published = client.post(
        f"/v1/subscriber/certifications/{run_id}/publish", headers=headers
    )
    assert published.status_code == 200
    public = client.get(published.json()["verification_url"])
    assert public.status_code == 200 and public.json()["valid"] is True
    assert public.json()["payload"]["run_id"] == run_id

    lifecycle = client.post(
        f"/v1/subscriber/certifications/{run_id}/lifecycle",
        headers=headers,
        json={"event_type": "REVOKED", "reason": "withdrawn by owner"},
    )
    assert lifecycle.status_code == 200
    assert lifecycle.json()["event_type"] == "REVOKED"
    revoked = client.get(published.json()["verification_url"])
    assert revoked.status_code == 200 and revoked.json()["valid"] is False
    assert "verdict_revoked" in revoked.json()["reasons"]
