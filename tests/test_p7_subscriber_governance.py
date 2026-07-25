"""P7 acceptance: tenant, billing, quota, retention, audit, and public verification."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from echo_certification_forge.canonical import canonical_json, to_utc_iso, utc_now
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.platform import CertificationPlatform
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import (
    Ed25519VerdictSigner,
    TrustedPublicKeyRegistry,
)


def _bootstrap(platform, *, suffix: str, tenant_id: str, plan: str = "professional"):
    return platform.bootstrap(
        organization_id=f"org-{suffix}",
        tenant_id=tenant_id,
        organization_name=f"Organization {suffix}",
        project_id=f"project-{suffix}",
        project_name=f"Project {suffix}",
        target_reference=f"https://example.test/{suffix}",
        required_policy="certforge.release-strict.v1",
        owner_user_id=f"owner-{suffix}",
        owner_email=f"{suffix}@example.test",
        plan_id=plan,
        billing_status="active",
    )


def _subscriber_submit(client: TestClient, key: str, suffix: str):
    digest = hashlib.sha256(suffix.encode()).hexdigest()
    return client.post(
        "/v1/subscriber/certifications",
        headers={"X-CertForge-API-Key": key},
        json={
            "target": {
                "target_type": "git",
                "identity_digest": digest,
                "reference": f"https://example.test/repo@{suffix}",
            },
            "environment": {
                "identity_digest": hashlib.sha256(
                    f"env-{suffix}".encode()
                ).hexdigest()
            },
            "policy_version": "certforge.release-strict.v1",
            "idempotency_key": f"subscriber-{suffix}-key",
        },
    )


def _certify(store, manifest, target, environment, root: Path):
    source = root / "p7-source"
    source.mkdir()
    (source / "journey.py").write_text("print('p7-ok')\n", encoding="utf-8")
    store.register_run(
        "cert-p7",
        target,
        environment,
        manifest.manifest_id,
        manifest.digest,
    )
    signer = Ed25519VerdictSigner.generate()
    result = RunExecutor(store, manifest, signer).execute(
        "cert-p7",
        target.tenant_id,
        source,
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "journey.py"],
        control_attestations={
            "runner_control_channel": True,
            "signing_authority_separation": True,
        },
    )
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    return trusted


def test_p7_tenant_isolation_billing_failure_and_quota_fail_closed(
    store, manifest
):
    platform = CertificationPlatform(store.db_path)
    alpha = _bootstrap(platform, suffix="alpha", tenant_id="tenant-alpha")
    beta = _bootstrap(platform, suffix="beta", tenant_id="tenant-beta")
    billing_secret = "billing-test-secret"
    client = TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                platform=platform,
                billing_webhook_secret=billing_secret,
            )
        )
    )

    submitted = _subscriber_submit(client, alpha["api_key"], "alpha")
    assert submitted.status_code == 201
    alpha_run = submitted.json()["run_id"]
    beta_runs = client.get(
        "/v1/subscriber/certifications",
        headers={"X-CertForge-API-Key": beta["api_key"]},
    )
    assert beta_runs.status_code == 200
    assert all(row["run_id"] != alpha_run for row in beta_runs.json())

    timestamp = int(time.time())
    payload = {
        "event_id": "billing-past-due-alpha",
        "organization_id": alpha["organization_id"],
        "status": "past_due",
        "plan_id": "professional",
        "period_start": to_utc_iso(utc_now() - timedelta(days=1)),
        "period_end": to_utc_iso(utc_now() + timedelta(days=29)),
        "provider_customer_id": "cus_alpha",
        "provider_subscription_id": "sub_alpha",
    }
    raw = canonical_json(payload).encode()
    signature = hmac.new(
        billing_secret.encode(),
        f"{timestamp}.".encode() + raw,
        hashlib.sha256,
    ).hexdigest()
    webhook = client.post(
        "/v1/billing/webhook",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Billing-Timestamp": str(timestamp),
            "X-Billing-Signature": signature,
        },
    )
    assert webhook.status_code == 200
    replay = client.post(
        "/v1/billing/webhook",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Billing-Timestamp": str(timestamp),
            "X-Billing-Signature": signature,
        },
    )
    assert replay.status_code == 200 and replay.json()["status"] == "replayed"
    blocked = _subscriber_submit(client, alpha["api_key"], "alpha-two")
    assert blocked.status_code == 402
    assert blocked.json()["detail"] == "billing_not_current"

    meter = client.post(
        "/v1/subscriber/usage",
        headers={"X-CertForge-API-Key": beta["api_key"]},
        json={
            "unit": "model_tokens",
            "amount": 20_000_001,
            "idempotency_key": "meter-beta-over-budget",
        },
    )
    assert meter.status_code == 429
    assert meter.json()["detail"] == "model_tokens_budget_exceeded"


def test_subscriber_telemetry_is_bounded_tenant_scoped_and_truthful(store, manifest):
    platform = CertificationPlatform(store.db_path)
    account = _bootstrap(platform, suffix="telemetry", tenant_id="tenant-telemetry")
    other = _bootstrap(platform, suffix="telemetry-other", tenant_id="tenant-telemetry-other")
    client = TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                platform=platform,
            )
        )
    )
    submitted = _subscriber_submit(client, account["api_key"], "telemetry")
    assert submitted.status_code == 201
    run_id = submitted.json()["run_id"]
    metered = client.post(
        "/v1/subscriber/usage",
        headers={"X-CertForge-API-Key": account["api_key"]},
        json={
            "unit": "worker_minutes",
            "amount": 7,
            "idempotency_key": "telemetry-worker-minutes",
        },
    )
    assert metered.status_code == 200

    assert client.get("/v1/subscriber/telemetry").status_code == 401
    response = client.get(
        "/v1/subscriber/telemetry",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["queue"]["queued"] == body["queue"]["active"] == 1
    assert body["queue"]["total"] == 1
    assert body["capacity"] == {
        "concurrent_run_limit": 8,
        "active_runs": 1,
        "quota_slots_remaining": 7,
        "runner_health": "UNKNOWN",
        "runner_health_reason": "No authenticated worker-heartbeat contract is available.",
        "capacity_basis": "subscription_quota_only",
    }
    assert body["budgets"]["worker_minutes"] == {
        "used": 7,
        "limit": 20_000,
        "remaining": 19_993,
    }
    assert body["adapters"]["inventory_status"] == "UNAVAILABLE"
    assert body["adapters"]["maturity_status"] == "UNAVAILABLE"
    recent = body["state_machine"]["recent_runs"]
    assert len(recent) == 1 and recent[0]["run_id"] == run_id
    timeline = recent[0]["timeline"]
    assert len(timeline) == 1
    assert timeline[0]["prior_state"] == "CREATED"
    assert timeline[0]["next_state"] == "QUEUED"
    assert timeline[0]["workflow_version"]
    assert timeline[0]["created_at"].endswith("Z")
    assert "actor" not in json.dumps(body) and "accepted for execution" not in json.dumps(body)
    assert account["api_key"] not in json.dumps(body)

    isolated = client.get(
        "/v1/subscriber/telemetry",
        headers={"X-CertForge-API-Key": other["api_key"]},
    )
    assert isolated.status_code == 200
    assert isolated.json()["queue"]["total"] == 0


def test_p7_legal_hold_audit_public_verification_and_revocation(
    store, manifest, target, environment, tmp_path
):
    trusted = _certify(store, manifest, target, environment, tmp_path)
    platform = CertificationPlatform(store.db_path)
    account = _bootstrap(
        platform,
        suffix="enterprise",
        tenant_id=target.tenant_id,
        plan="enterprise",
    )
    client = TestClient(
        create_app(ServiceContext(store, manifest, trusted, platform=platform))
    )
    headers = {"X-CertForge-API-Key": account["api_key"]}
    artifact_id = "cert-p7-rule-tenant_isolation"
    store.set_retention(
        "cert-p7",
        target.tenant_id,
        artifact_id,
        "enterprise",
        to_utc_iso(utc_now() - timedelta(days=1)),
    )

    hold = client.post(
        "/v1/subscriber/legal-holds",
        headers=headers,
        json={
            "hold_id": "hold-p7",
            "run_id": "cert-p7",
            "reason": "active litigation preservation",
        },
    )
    assert hold.status_code == 200 and hold.json()["active"] is True
    assert store.purge_expired_evidence(to_utc_iso(utc_now())) == []
    released = client.delete(
        "/v1/subscriber/legal-holds/hold-p7", headers=headers
    )
    assert released.status_code == 200
    purged = store.purge_expired_evidence(to_utc_iso(utc_now()))
    assert {item["artifact_id"] for item in purged} == {artifact_id}

    published = client.post(
        "/v1/subscriber/certifications/cert-p7/publish",
        headers=headers,
    )
    assert published.status_code == 200
    public = client.get(published.json()["verification_url"])
    assert public.status_code == 200
    assert public.json()["valid"] is True
    assert public.json()["payload"]["release_verdict"] == "PRODUCTION_READY"
    assert "tenant_id" in public.json()["payload"]
    assert account["api_key"] not in json.dumps(public.json())

    lifecycle = client.post(
        "/v1/subscriber/certifications/cert-p7/lifecycle",
        headers=headers,
        json={
            "event_type": "REVOKED",
            "reason": "new critical vulnerability",
        },
    )
    assert lifecycle.status_code == 200
    invalidated = client.get(published.json()["verification_url"])
    assert invalidated.status_code == 200
    assert invalidated.json()["valid"] is False
    assert "verdict_revoked" in invalidated.json()["reasons"]

    audit = client.get("/v1/subscriber/audit", headers=headers)
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()}
    assert {
        "organization.bootstrap",
        "legal_hold.create",
        "legal_hold.release",
        "verification.publish",
        "verdict.lifecycle",
    }.issubset(actions)


def test_subscriber_artifact_download_is_bounded_tenant_scoped_and_audited(
    store, manifest, target, environment, tmp_path
):
    trusted = _certify(store, manifest, target, environment, tmp_path)
    platform = CertificationPlatform(store.db_path)
    account = _bootstrap(
        platform,
        suffix="artifact-owner",
        tenant_id=target.tenant_id,
        plan="professional",
    )
    other = _bootstrap(
        platform,
        suffix="artifact-other",
        tenant_id="tenant-artifact-other",
        plan="professional",
    )
    client = TestClient(
        create_app(ServiceContext(store, manifest, trusted, platform=platform))
    )
    artifact_id = "cert-p7-rule-tenant_isolation"
    descriptor = next(
        item for item in store.list_evidence("cert-p7", target.tenant_id)
        if item["artifact_id"] == artifact_id
    )
    route = f"/v1/subscriber/certifications/cert-p7/evidence/{artifact_id}"

    denied = client.get(route)
    assert denied.status_code == 401
    isolated = client.get(
        route, headers={"X-CertForge-API-Key": other["api_key"]}
    )
    assert isolated.status_code == 404

    downloaded = client.get(
        route, headers={"X-CertForge-API-Key": account["api_key"]}
    )
    assert downloaded.status_code == 200
    body = downloaded.json()
    content = base64.b64decode(body["payload_base64"], validate=True)
    assert body["encoding"] == "base64"
    assert body["run_id"] == "cert-p7"
    assert body["artifact_id"] == artifact_id
    assert body["sha256"] == descriptor["sha256"]
    assert body["size_bytes"] == len(content) == descriptor["size_bytes"]
    assert hashlib.sha256(content).hexdigest() == body["sha256"]
    assert body["redaction_status"] in {"COMPLETE", "NOT_REQUIRED"}

    audit = client.get(
        "/v1/subscriber/audit",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )
    event = next(row for row in audit.json() if row["action"] == "evidence.download")
    assert event["object_id"] == artifact_id
    assert event["detail"] == {
        "run_id": "cert-p7",
        "sha256": descriptor["sha256"],
        "size_bytes": descriptor["size_bytes"],
    }


def test_subscriber_artifact_download_rejects_unverified_bytes(
    store, manifest, target, environment, tmp_path
):
    trusted = _certify(store, manifest, target, environment, tmp_path)
    platform = CertificationPlatform(store.db_path)
    account = _bootstrap(
        platform,
        suffix="artifact-tamper",
        tenant_id=target.tenant_id,
        plan="professional",
    )
    client = TestClient(
        create_app(ServiceContext(store, manifest, trusted, platform=platform))
    )
    artifact_id = "cert-p7-rule-tenant_isolation"
    artifact = store.evidence_root / target.tenant_id / "cert-p7" / "artifacts" / f"{artifact_id}.bin"
    artifact.write_bytes(b"tampered")
    response = client.get(
        f"/v1/subscriber/certifications/cert-p7/evidence/{artifact_id}",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "artifact_integrity_failed"
