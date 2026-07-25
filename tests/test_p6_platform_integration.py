"""P6 platform integration — HTTP admission surface + signed build/registry webhooks.

Exercises the REAL FastAPI app (create_app) end-to-end: certification binding over HTTP,
the deployment admission hook endpoint, outcome + rollback evidence, release status
checks for CI, the tenant-scoped audit trail, and HMAC-verified webhook intake with
run deduplication. Fail-closed on every negative path.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.release_hooks import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookSecretRegistry,
    sign_webhook,
)
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

TENANT = "tenant-alpha"
OTHER_TENANT = "tenant-beta"
SECRET = "p6-webhook-secret-0123456789abcdef"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture
def signer() -> Ed25519VerdictSigner:
    return Ed25519VerdictSigner.generate()


@pytest.fixture
def context(tmp_path: Path, store, manifest, signer) -> ServiceContext:
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    return ServiceContext(
        store=store,
        manifest=manifest,
        trusted_keys=trusted,
        deployment_ledger_path=tmp_path / "deployments.sqlite3",
        webhook_secrets=WebhookSecretRegistry(secrets={TENANT: SECRET}),
    )


@pytest.fixture
def client(context: ServiceContext) -> TestClient:
    return TestClient(create_app(context))


def _certify(store, manifest, signer, environment, tmp_path, run_id, target) -> None:
    store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    workdir = tmp_path / f"src-{run_id}"
    workdir.mkdir()
    (workdir / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    result = RunExecutor(store, manifest, signer).execute(
        run_id,
        target.tenant_id,
        workdir,
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "hello.py"],
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
    )
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings


@pytest.fixture
def certified_target(store, manifest, signer, environment, tmp_path) -> TargetIdentity:
    target = TargetIdentity(
        tenant_id=TENANT,
        target_type="container",
        canonical_ref="registry.echo/app@v1",
        artifact_sha256=_digest("http-app-v1"),
        source_commit="abc123def456",
        dependency_sha256=_digest("dependencies"),
        configuration_sha256=_digest("configuration"),
    )
    _certify(store, manifest, signer, environment, tmp_path, "cert-http-v1", target)
    return target


def _admit_body(
    artifact: str, env: str, environment: EnvironmentIdentity, manifest, deployment_id: str
) -> dict:
    return {
        "artifact_sha256": artifact,
        "deployment_environment": env,
        "environment_identity_digest": environment.identity_digest,
        "rule_manifest_digest": manifest.digest,
        "deployment_id": deployment_id,
        "requested_by": "ci.pipeline",
    }


# --------------------------------------------------------------------------------------
# HTTP admission surface
# --------------------------------------------------------------------------------------


def test_http_full_release_flow(client, certified_target, environment, manifest):
    headers = {"X-Tenant-ID": TENANT}
    artifact = certified_target.artifact_sha256

    # bind certification to the exact artifact digest
    response = client.post("/v1/certifications/cert-http-v1/bindings", headers=headers)
    assert response.status_code == 201
    assert response.json()["artifact_sha256"] == artifact
    # binding is idempotent
    response = client.post("/v1/certifications/cert-http-v1/bindings", headers=headers)
    assert response.status_code == 200
    assert response.json()["created"] is False

    # production before staging -> denied
    response = client.post(
        "/v1/deployments/admissions",
        headers=headers,
        json=_admit_body(artifact, "production", environment, manifest, "deploy-p0"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert "staging_acceptance_missing" in body["reasons"]

    # registry-form digest is accepted for the same exact artifact
    response = client.post(
        "/v1/deployments/admissions",
        headers=headers,
        json=_admit_body(f"sha256:{artifact}", "staging", environment, manifest, "deploy-s1"),
    )
    staging = response.json()
    assert staging["allowed"] is True, staging["reasons"]

    response = client.post(
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        headers=headers,
        json={"status": "SUCCEEDED", "detail": "staging smoke green"},
    )
    assert response.status_code == 201

    response = client.post(
        "/v1/deployments/admissions",
        headers=headers,
        json=_admit_body(artifact, "production", environment, manifest, "deploy-p1"),
    )
    production = response.json()
    assert production["allowed"] is True, production["reasons"]

    # release status check (CI) reports production admissibility
    response = client.get(f"/v1/releases/{artifact}/status", headers=headers)
    status = response.json()
    assert status["certified"] is True
    assert status["gate_allowed"] is True
    assert status["staging_accepted"] is True
    assert status["production_admissible"] is True

    # audit trail is complete and the chain verifies
    response = client.get("/v1/deployments/audit", headers=headers)
    audit = response.json()
    assert audit["chain_valid"] is True
    types = [row["record_type"] for row in audit["records"]]
    assert types.count("BINDING") == 1
    assert types.count("ADMISSION") == 3  # denied production + staging + allowed production
    assert types.count("OUTCOME") == 1


def test_http_admission_requires_tenant_and_is_fail_closed(client, environment, manifest):
    body = _admit_body(_digest("nope"), "staging", environment, manifest, "deploy-x")
    assert client.post("/v1/deployments/admissions", json=body).status_code == 401

    response = client.post(
        "/v1/deployments/admissions", headers={"X-Tenant-ID": TENANT}, json=body
    )
    decision = response.json()
    assert decision["allowed"] is False
    assert "artifact_not_certified" in decision["reasons"]


def test_http_binding_refuses_unsigned_run_and_foreign_tenant(
    client, store, manifest, environment
):
    target = TargetIdentity(
        tenant_id=TENANT,
        target_type="container",
        canonical_ref="registry.echo/app@u1",
        artifact_sha256=_digest("unsigned-app"),
        source_commit="abc123def456",
    )
    store.register_run("cert-unsigned", target, environment, manifest.manifest_id, manifest.digest)
    response = client.post(
        "/v1/certifications/cert-unsigned/bindings", headers={"X-Tenant-ID": TENANT}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "signed_verdict_missing"
    response = client.post(
        "/v1/certifications/cert-unsigned/bindings", headers={"X-Tenant-ID": OTHER_TENANT}
    )
    assert response.status_code == 404


def test_http_rollback_target_and_outcome_errors(client, certified_target, environment, manifest):
    headers = {"X-Tenant-ID": TENANT}
    # nothing deployed -> no rollback target
    response = client.get("/v1/deployments/rollback-target", headers=headers)
    assert response.status_code == 200
    assert response.json()["rollback_target"] is None
    # unknown admission -> 404
    response = client.post(
        "/v1/deployments/admissions/dep-doesnotexist/outcome",
        headers=headers,
        json={"status": "SUCCEEDED", "detail": "x"},
    )
    assert response.status_code == 404


# --------------------------------------------------------------------------------------
# Signed platform webhooks -> certification intake with deduplication
# --------------------------------------------------------------------------------------


def _build_event(event_id: str = "evt-00000001") -> dict:
    return {
        "event_id": event_id,
        "event_type": "build.artifact.published",
        "tenant_id": TENANT,
        "artifact_sha256": _digest("built-artifact"),
        "source_commit": "abc123def456",
        "repository": "https://github.com/echo/app",
        "environment_identity_digest": _digest("build-env"),
        "policy_version": "certforge.release-strict.v1",
    }


def _signed_headers(body: bytes, secret: str = SECRET, timestamp: str | None = None) -> dict:
    ts = timestamp or to_utc_iso(utc_now())
    return {
        "X-Tenant-ID": TENANT,
        TIMESTAMP_HEADER: ts,
        SIGNATURE_HEADER: sign_webhook(secret, ts, body),
        "Content-Type": "application/json",
    }


def test_build_webhook_creates_run_and_deduplicates(client):
    body = json.dumps(_build_event()).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201, response.text
    first = response.json()
    assert first["deduplicated"] is False
    run_id = first["run"]["run_id"]
    assert first["run"]["release_verdict"] == "NOT_READY"  # default-deny until certified

    # exact re-delivery deduplicates
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 200
    assert response.json()["run"]["run_id"] == run_id

    # a DIFFERENT event id describing the SAME artifact also deduplicates to one run
    body2 = json.dumps(_build_event(event_id="evt-00000002")).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body2, headers=_signed_headers(body2))
    assert response.status_code == 200
    assert response.json()["deduplicated"] is True
    assert response.json()["run"]["run_id"] == run_id


def test_registry_webhook_maps_container_target(client):
    event = {
        "event_id": "evt-reg-0001",
        "event_type": "registry.image.pushed",
        "tenant_id": TENANT,
        "image_digest": f"sha256:{_digest('pushed-image')}",
        "image_repository": "registry.echo/app",
        "source_commit": "abc123def456",
        "environment_identity_digest": _digest("registry-env"),
        "policy_version": "certforge.release-strict.v1",
    }
    body = json.dumps(event).encode("utf-8")
    response = client.post("/v1/hooks/registry", content=body, headers=_signed_headers(body))
    assert response.status_code == 201, response.text
    assert response.json()["run"]["state"] == "QUEUED"


def test_webhook_signature_enforcement_is_fail_closed(client):
    body = json.dumps(_build_event()).encode("utf-8")

    # missing signature
    ts = to_utc_iso(utc_now())
    response = client.post(
        "/v1/hooks/build", content=body, headers={"X-Tenant-ID": TENANT, TIMESTAMP_HEADER: ts}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "webhook_signature_missing"

    # wrong secret
    response = client.post(
        "/v1/hooks/build", content=body, headers=_signed_headers(body, secret="wrong-secret")
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "webhook_signature_invalid"

    # signature over a DIFFERENT body
    headers = _signed_headers(json.dumps(_build_event(event_id="evt-tampered")).encode("utf-8"))
    response = client.post("/v1/hooks/build", content=body, headers=headers)
    assert response.status_code == 401

    # stale timestamp
    stale = to_utc_iso(utc_now() - timedelta(seconds=3600))
    response = client.post(
        "/v1/hooks/build", content=body, headers=_signed_headers(body, timestamp=stale)
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "webhook_timestamp_stale"

    # tenant with no registered secret
    headers = _signed_headers(body)
    headers["X-Tenant-ID"] = OTHER_TENANT
    response = client.post("/v1/hooks/build", content=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "webhook_tenant_not_registered"


def test_webhook_tenant_mismatch_between_header_and_body(client, store, manifest):
    event = _build_event()
    event["tenant_id"] = OTHER_TENANT  # body claims another tenant
    body = json.dumps(event).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"
