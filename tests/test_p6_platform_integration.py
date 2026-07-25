"""P6 platform integration — HTTP admission surface + signed build/registry webhooks.

Exercises the REAL FastAPI app (create_app) end-to-end: certification binding over HTTP,
the deployment admission hook endpoint, outcome + rollback evidence, release status
checks for CI, the tenant-scoped audit trail, and HMAC-verified webhook intake with
run deduplication. Fail-closed on every negative path.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets as _secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.deployment_service import (
    DEPLOY_NONCE_HEADER,
    DEPLOY_SIGNATURE_HEADER,
    DEPLOY_TIMESTAMP_HEADER,
    sign_deployment_request,
)
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import EnvironmentIdentity, RunState, TargetIdentity
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
DEPLOY_SECRET = "p6-deploy-credential-alpha-0001"
OTHER_DEPLOY_SECRET = "p6-deploy-credential-beta-0002"


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
        deployment_credentials=WebhookSecretRegistry(
            secrets={TENANT: DEPLOY_SECRET, OTHER_TENANT: OTHER_DEPLOY_SECRET}
        ),
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


def _deploy_headers(
    method: str,
    path: str,
    body: bytes = b"",
    secret: str = DEPLOY_SECRET,
    tenant: str = TENANT,
    timestamp: str | None = None,
    nonce: str | None = None,
    sign_method: str | None = None,
    sign_path: str | None = None,
    sign_tenant: str | None = None,
    sign_body: bytes | None = None,
    omit_nonce: bool = False,
) -> dict:
    """v2 deployment-credential headers binding tenant, method, path, nonce and body.

    The ``sign_*`` overrides let negative tests sign a DIFFERENT canonical string
    than the request actually sent (cross-path retarget, altered method, ...).
    """
    ts = timestamp or to_utc_iso(utc_now())
    used_nonce = nonce or _secrets.token_hex(16)
    headers = {
        "X-Tenant-ID": tenant,
        DEPLOY_TIMESTAMP_HEADER: ts,
        DEPLOY_SIGNATURE_HEADER: sign_deployment_request(
            secret,
            sign_tenant if sign_tenant is not None else tenant,
            sign_method if sign_method is not None else method,
            sign_path if sign_path is not None else path,
            ts,
            used_nonce,
            sign_body if sign_body is not None else body,
        ),
        "Content-Type": "application/json",
    }
    if not omit_nonce:
        headers[DEPLOY_NONCE_HEADER] = used_nonce
    return headers


def _post_signed(client, url: str, body: dict | None = None, **header_kwargs):
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    return client.post(
        url, content=raw or None, headers=_deploy_headers("POST", url, raw, **header_kwargs)
    )


# --------------------------------------------------------------------------------------
# HTTP admission surface
# --------------------------------------------------------------------------------------


def test_http_full_release_flow(client, certified_target, environment, manifest):
    headers = {"X-Tenant-ID": TENANT}
    artifact = certified_target.artifact_sha256

    # bind certification to the exact artifact digest (signed with the deployment credential)
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201
    assert response.json()["artifact_sha256"] == artifact
    # binding is idempotent
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 200
    assert response.json()["created"] is False

    # production before staging -> denied
    response = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-p0"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert "staging_acceptance_missing" in body["reasons"]

    # registry-form digest is accepted for the same exact artifact
    response = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(f"sha256:{artifact}", "staging", environment, manifest, "deploy-s1"),
    )
    staging = response.json()
    assert staging["allowed"] is True, staging["reasons"]

    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging smoke green"},
    )
    assert response.status_code == 201

    response = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-p1"),
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
    raw = json.dumps(body).encode("utf-8")

    # no tenant header at all -> 401
    assert client.post("/v1/deployments/admissions", json=body).status_code == 401

    # tenant header ALONE is not authorization -> 401 fail-closed
    response = client.post(
        "/v1/deployments/admissions", headers={"X-Tenant-ID": TENANT}, json=body
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_missing"

    # properly signed but uncertified -> recorded fail-closed denial
    response = client.post(
        "/v1/deployments/admissions",
        content=raw,
        headers=_deploy_headers("POST", "/v1/deployments/admissions", raw),
    )
    assert response.status_code == 200
    decision = response.json()
    assert decision["allowed"] is False
    assert "artifact_not_certified" in decision["reasons"]


def test_http_mutations_require_deployment_credentials(client, environment, manifest):
    """Blocker 1 negatives: every mutation demands a tenant-bound v2 HMAC credential."""
    url = "/v1/deployments/admissions"
    body = _admit_body(_digest("cred-check"), "staging", environment, manifest, "deploy-c1")
    raw = json.dumps(body).encode("utf-8")

    # wrong secret -> 401
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, secret="wrong-deploy-secret"))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"

    # ANOTHER tenant's valid credential cannot authorize THIS tenant's mutation
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, secret=OTHER_DEPLOY_SECRET))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"

    # stale timestamp -> 401
    stale = to_utc_iso(utc_now() - timedelta(seconds=3600))
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, timestamp=stale))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_timestamp_stale"

    # tenant with no registered deployment credential -> 401
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, tenant="tenant-gamma"))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_tenant_not_registered"

    # missing nonce header -> 401 (v2 signatures REQUIRE a unique nonce)
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, omit_nonce=True))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_nonce_missing"

    # malformed nonce -> 401
    response = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw, nonce="short"))
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_nonce_invalid"

    # unsigned binding mutation -> 401
    response = client.post(
        "/v1/certifications/cert-any/bindings", headers={"X-Tenant-ID": TENANT}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_missing"

    # unsigned outcome mutation -> 401
    response = client.post(
        "/v1/deployments/admissions/dep-x/outcome",
        headers={"X-Tenant-ID": TENANT},
        json={"status": "SUCCEEDED", "detail": "x"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_missing"


def test_http_mutation_signature_binds_method_path_tenant_body(client, environment, manifest):
    """The v2 canonical string covers method, path, tenant and body; altering ANY
    component after signing invalidates the signature (no cross-path retargeting)."""
    url = "/v1/deployments/admissions"
    body = _admit_body(_digest("bind-check"), "staging", environment, manifest, "deploy-b1")
    raw = json.dumps(body).encode("utf-8")

    # cross-path retarget: signature minted for the outcome path cannot authorize admission
    response = client.post(
        url,
        content=raw,
        headers=_deploy_headers(
            "POST", url, raw, sign_path="/v1/deployments/admissions/dep-a/outcome"
        ),
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"

    # altered method in the canonical string -> invalid
    response = client.post(
        url, content=raw, headers=_deploy_headers("POST", url, raw, sign_method="PUT")
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"

    # tenant mismatch between canonical string and X-Tenant-ID header -> invalid
    response = client.post(
        url, content=raw, headers=_deploy_headers("POST", url, raw, sign_tenant=OTHER_TENANT)
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"

    # body altered after signing -> invalid
    tampered = _admit_body(_digest("bind-check"), "production", environment, manifest, "deploy-b1")
    tampered_raw = json.dumps(tampered).encode("utf-8")
    response = client.post(
        url, content=tampered_raw, headers=_deploy_headers("POST", url, raw, sign_body=raw)
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "deployment_credential_signature_invalid"


def test_http_mutation_exact_replay_rejected(client, environment, manifest):
    """An EXACT byte-for-byte replay of an accepted signed mutation is rejected:
    the nonce is consumed atomically on first use."""
    url = "/v1/deployments/admissions"
    body = _admit_body(_digest("replay-check"), "staging", environment, manifest, "deploy-r1")
    raw = json.dumps(body).encode("utf-8")
    headers = _deploy_headers("POST", url, raw)

    first = client.post(url, content=raw, headers=headers)
    assert first.status_code == 200  # fail-closed denial is still an accepted request

    replay = client.post(url, content=raw, headers=headers)
    assert replay.status_code == 401
    assert replay.json()["detail"] == "deployment_credential_nonce_reused"

    # a fresh nonce (new signature) from the same caller works again
    fresh = client.post(url, content=raw, headers=_deploy_headers("POST", url, raw))
    assert fresh.status_code == 200


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
    response = _post_signed(client, "/v1/certifications/cert-unsigned/bindings")
    assert response.status_code == 409
    assert response.json()["detail"] == "signed_verdict_missing"
    response = _post_signed(
        client,
        "/v1/certifications/cert-unsigned/bindings",
        secret=OTHER_DEPLOY_SECRET,
        tenant=OTHER_TENANT,
    )
    assert response.status_code == 404


def test_http_rollback_target_and_outcome_errors(client, certified_target, environment, manifest):
    headers = {"X-Tenant-ID": TENANT}
    # nothing deployed -> no rollback target
    response = client.get("/v1/deployments/rollback-target", headers=headers)
    assert response.status_code == 200
    assert response.json()["rollback_target"] is None
    # unknown admission -> 404
    response = _post_signed(
        client,
        "/v1/deployments/admissions/dep-doesnotexist/outcome",
        {"status": "SUCCEEDED", "detail": "x"},
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


# --------------------------------------------------------------------------------------
# Blocker 4: webhook-declared runs reconcile to the acquired exact identity and deploy
# --------------------------------------------------------------------------------------


def _declared_event(artifact: str, environment, manifest, event_id: str = "evt-reconcile-01") -> dict:
    return {
        "event_id": event_id,
        "event_type": "build.artifact.published",
        "tenant_id": TENANT,
        "artifact_sha256": artifact,
        "source_commit": "abc123def456",
        "repository": "https://github.com/echo/app",
        "environment_identity_digest": environment.identity_digest,
        "policy_version": manifest.manifest_id,
    }


def test_webhook_declared_run_reconciles_certifies_and_deploys_end_to_end(
    client, context, store, manifest, environment, signer, tmp_path
):
    """A webhook-declared run is NOT a dead end: after acquisition reconciles the declared
    commitment to the exact acquired identity, certification and deployment succeed."""
    artifact = _digest("reconcile-artifact")
    body = json.dumps(_declared_event(artifact, environment, manifest)).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201, response.text
    run = response.json()["run"]
    run_id = run["run_id"]
    assert run["state"] == "QUEUED"
    assert run["release_verdict"] == "NOT_READY"  # default-deny until certified

    # worker acquisition produced the EXACT declared artifact -> reconciliation succeeds
    acquired = TargetIdentity(
        tenant_id=TENANT,
        target_type="container",
        canonical_ref="registry.echo/app@abc123def456",
        artifact_sha256=artifact,
        source_commit="abc123def456",
    )
    store.reconcile_declared_target(run_id, TENANT, acquired, environment)
    row = store.get_run(run_id, TENANT)
    assert row["target_identity_digest"] == acquired.identity_digest
    assert "declared_identity_digest" not in json.loads(row["target_identity_json"])

    # real certification of the reconciled run
    workdir = tmp_path / "src-reconciled"
    workdir.mkdir()
    (workdir / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    result = RunExecutor(store, manifest, signer).execute(
        run_id,
        TENANT,
        workdir,
        entitlement=StaticEntitlement(frozenset({TENANT})),
        journey=[sys.executable, "hello.py"],
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
    )
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings

    # the formerly-declared run now BINDS and passes staging -> production admission
    response = _post_signed(client, f"/v1/certifications/{run_id}/bindings")
    assert response.status_code == 201
    assert response.json()["artifact_sha256"] == artifact

    response = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-rec-stg"),
    )
    staging = response.json()
    assert staging["allowed"] is True, staging["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging green"},
    )
    assert response.status_code == 201
    response = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-rec-prd"),
    )
    production = response.json()
    assert production["allowed"] is True, production["reasons"]


def test_reconciliation_refuses_mismatched_artifact_and_run_stays_undeployable(
    client, store, manifest, environment
):
    artifact = _digest("declared-artifact")
    body = json.dumps(
        _declared_event(artifact, environment, manifest, event_id="evt-reconcile-02")
    ).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201
    run_id = response.json()["run"]["run_id"]

    tampered = TargetIdentity(
        tenant_id=TENANT,
        target_type="container",
        canonical_ref="registry.echo/app@abc123def456",
        artifact_sha256=_digest("DIFFERENT-acquired-artifact"),
        source_commit="abc123def456",
    )
    with pytest.raises(ValueError, match="target_declared_artifact_mismatch"):
        store.reconcile_declared_target(run_id, TENANT, tampered, environment)

    # the unreconciled declared run still cannot bind (fail-closed)
    response = _post_signed(client, f"/v1/certifications/{run_id}/bindings")
    assert response.status_code == 409
    assert response.json()["detail"] == "signed_verdict_missing"


def test_reconciliation_window_closes_at_acquisition(client, store, manifest, environment):
    artifact = _digest("window-artifact")
    body = json.dumps(
        _declared_event(artifact, environment, manifest, event_id="evt-reconcile-03")
    ).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201
    run_id = response.json()["run"]["run_id"]

    store.transition_state(run_id, TENANT, RunState.ACQUIRING_TARGET, "test", "begin", "t4.p1")
    acquired = TargetIdentity(
        tenant_id=TENANT,
        target_type="container",
        canonical_ref="registry.echo/app@abc123def456",
        artifact_sha256=artifact,
        source_commit="abc123def456",
    )
    with pytest.raises(ValueError, match="target_reconciliation_window_closed"):
        store.reconcile_declared_target(run_id, TENANT, acquired, environment)


def test_run_worker_executes_webhook_declared_run_end_to_end(
    client, store, manifest, signer, tmp_path
):
    """Full worker path: webhook declares the artifact -> run_worker acquires, reconciles,
    and certifies the SAME run; a wrong declaration fails closed before execution."""
    from echo_certification_forge import run_worker
    from echo_certification_forge.acquisition import acquire_target

    workdir = tmp_path / "src-worker"
    workdir.mkdir()
    (workdir / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    probe = acquire_target({"type": "local", "path": str(workdir)}, tmp_path / "probe")
    worker_environment = run_worker._worker_environment()

    body = json.dumps(
        _declared_event(
            probe.artifact_sha256, worker_environment, manifest, event_id="evt-worker-01"
        )
    ).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201
    run_id = response.json()["run"]["run_id"]

    outcome = run_worker.run(
        run_id,
        TENANT,
        {"type": "local", "path": str(workdir)},
        store=store,
        manifest=manifest,
        signer=signer,
        entitled=frozenset({TENANT}),
        journey=[sys.executable, "hello.py"],
    )
    assert outcome.get("error") is None, outcome
    assert outcome["release_verdict"] == "PRODUCTION_READY"
    assert outcome["target_identity_digest"] == store.get_run(run_id, TENANT)["target_identity_digest"]

    # declaring a DIFFERENT artifact than what acquisition yields fails closed pre-execution
    body = json.dumps(
        _declared_event(
            _digest("wrong-declared-artifact"), worker_environment, manifest,
            event_id="evt-worker-02",
        )
    ).encode("utf-8")
    response = client.post("/v1/hooks/build", content=body, headers=_signed_headers(body))
    assert response.status_code == 201
    bad_run_id = response.json()["run"]["run_id"]
    outcome = run_worker.run(
        bad_run_id,
        TENANT,
        {"type": "local", "path": str(workdir)},
        store=store,
        manifest=manifest,
        signer=signer,
        entitled=frozenset({TENANT}),
        journey=[sys.executable, "hello.py"],
    )
    assert outcome["error"] == "target_reconciliation_failed"
    assert "target_declared_artifact_mismatch" in outcome["detail"]


# --------------------------------------------------------------------------------------
# Policy rollover — run identity binds the server-side ACTIVE manifest digest
# --------------------------------------------------------------------------------------


def test_policy_rollover_creates_new_recertification_run(store, manifest, signer, tmp_path):
    """A manifest rollover that keeps manifest_id but changes rule CONTENT (new digest)
    must NOT deduplicate a replayed submission to the stale pre-rollover run — it must
    deterministically create a NEW recertification run, while replays under the SAME
    digest still deduplicate."""
    import dataclasses

    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)

    def make_client(active_manifest) -> TestClient:
        return TestClient(
            create_app(
                ServiceContext(
                    store=store,
                    manifest=active_manifest,
                    trusted_keys=trusted,
                    deployment_ledger_path=tmp_path / "deployments.sqlite3",
                    webhook_secrets=WebhookSecretRegistry(secrets={TENANT: SECRET}),
                    deployment_credentials=WebhookSecretRegistry(
                        secrets={TENANT: DEPLOY_SECRET}
                    ),
                )
            )
        )

    body = {
        "tenant_id": TENANT,
        "target": {
            "target_type": "git",
            "identity_digest": _digest("rollover-target"),
            "reference": "https://github.com/example/project@abc123",
        },
        "environment": {
            "identity_digest": _digest("rollover-env"),
            "runner_image_digest": "sha256:" + _digest("rollover-runner"),
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": "key-rollover-0001",
    }
    headers = {"X-Tenant-ID": TENANT}

    old_client = make_client(manifest)
    first = old_client.post("/v1/certifications", json=body, headers=headers)
    assert first.status_code == 201
    original_run = first.json()["run_id"]

    # same manifest digest -> replay still deduplicates
    replay = old_client.post("/v1/certifications", json=body, headers=headers)
    assert replay.status_code == 200
    assert replay.json()["run_id"] == original_run

    # content rollover: SAME manifest_id, NEW server-side digest
    rolled_manifest = dataclasses.replace(
        manifest, digest=_digest("rolled-over-manifest-content")
    )
    assert rolled_manifest.manifest_id == manifest.manifest_id
    new_client = make_client(rolled_manifest)

    # identical request + identical idempotency key -> a NEW recertification run
    recert = new_client.post("/v1/certifications", json=body, headers=headers)
    assert recert.status_code == 201, recert.text
    recert_run = recert.json()["run_id"]
    assert recert_run != original_run
    assert recert.json()["release_verdict"] == "NOT_READY"  # default-deny at intake

    # replays under the NEW digest deduplicate to the NEW run (deterministic)
    again = new_client.post("/v1/certifications", json=body, headers=headers)
    assert again.status_code == 200
    assert again.json()["run_id"] == recert_run

    # both runs exist: the stale one was never silently reused as the new certification
    run_ids = {row["run_id"] for row in store.list_runs(TENANT)}
    assert {original_run, recert_run} <= run_ids


# --------------------------------------------------------------------------------------
# deploy/enforce_admission.sh — outcome recording through the supplied integration
# --------------------------------------------------------------------------------------

_GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")


def _bash_executable() -> str | None:
    if os.name == "nt":
        return str(_GIT_BASH) if _GIT_BASH.exists() else None
    return shutil.which("bash")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(_bash_executable() is None, reason="no usable bash for the .sh integration")
def test_enforce_admission_sh_records_real_outcomes_end_to_end(
    context, certified_target, environment, manifest
):
    """The supplied pipeline integration closes the loop by itself: enforce_admission.sh
    obtains the admission, runs the REAL deploy command, and records the REAL outcome —
    a staging success recorded by the script is what unlocks production, and a failing
    deploy exits nonzero with a FAILED outcome in the audit ledger."""
    import urllib.request

    import uvicorn

    app = create_app(context)
    client = TestClient(app)
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=2) as live:
                if live.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError("live service never became healthy")

    bash = _bash_executable()
    script = str(Path(__file__).parents[1] / "deploy" / "enforce_admission.sh").replace("\\", "/")
    base_env = {
        **os.environ,
        "CERTFORGE_URL": base,
        "CERTFORGE_TENANT": TENANT,
        "CERTFORGE_ARTIFACT_DIGEST": certified_target.artifact_sha256,
        "CERTFORGE_ENV_IDENTITY_DIGEST": environment.identity_digest,
        "CERTFORGE_RULE_MANIFEST_DIGEST": manifest.digest,
        "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET,
        "CERTFORGE_PYTHON": sys.executable.replace("\\", "/"),
    }

    def run_wrapper(deploy_env: str, deployment_id: str, *deploy_cmd: str):
        return subprocess.run(
            [bash, script, *deploy_cmd],
            capture_output=True,
            text=True,
            timeout=120,
            env={**base_env, "CERTFORGE_ENVIRONMENT": deploy_env,
                 "CERTFORGE_DEPLOYMENT_ID": deployment_id},
        )

    try:
        # production FIRST is denied (exit 2) and no deploy command runs
        proc = run_wrapper("production", "deploy-sh-early", "true")
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert "staging_acceptance_missing" in proc.stdout

        # a missing deploy command is fail-closed BEFORE any admission is minted
        proc = run_wrapper("staging", "deploy-sh-noargs")
        assert proc.returncode == 3
        assert "no deploy command supplied" in proc.stderr

        # staging deploy through the wrapper succeeds and records SUCCEEDED
        staging_proc = run_wrapper("staging", "deploy-sh-stg", "true")
        assert staging_proc.returncode == 0, staging_proc.stdout + staging_proc.stderr
        assert "DEPLOYMENT SUCCEEDED" in staging_proc.stdout
        assert '"recorded": true' in staging_proc.stdout
        assert '"status": "SUCCEEDED"' in staging_proc.stdout

        # production is admissible ONLY because the wrapper recorded staging success
        prod_proc = run_wrapper("production", "deploy-sh-prd", "true")
        assert prod_proc.returncode == 0, prod_proc.stdout + prod_proc.stderr
        assert '"status": "SUCCEEDED"' in prod_proc.stdout

        # a FAILING production deploy exits with the deploy status and records FAILED
        fail_proc = run_wrapper("production", "deploy-sh-fail", "false")
        assert fail_proc.returncode == 1, fail_proc.stdout + fail_proc.stderr
        assert "recording FAILED outcome" in fail_proc.stderr
        assert '"status": "FAILED"' in fail_proc.stdout
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    audit = client.get("/v1/deployments/audit", headers={"X-Tenant-ID": TENANT}).json()
    assert audit["chain_valid"] is True
    outcomes = [row for row in audit["records"] if row["record_type"] == "OUTCOME"]
    # staging SUCCEEDED + production SUCCEEDED + production FAILED, all via the script
    assert len(outcomes) == 3
    assert all(row["admission_id"] for row in outcomes)
