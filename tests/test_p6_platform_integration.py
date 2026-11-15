"""P6 platform integration — HTTP admission surface + signed build/registry webhooks.

Exercises the REAL FastAPI app (create_app) end-to-end: certification binding over HTTP,
the deployment admission hook endpoint, outcome + rollback evidence, release status
checks for CI, the tenant-scoped audit trail, and HMAC-verified webhook intake with
run deduplication. Fail-closed on every negative path.
"""
from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import secrets as _secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge import run_worker
from echo_certification_forge.acquisition import AcquisitionError, acquire_target
from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.deployment_service import (
    DEPLOY_NONCE_HEADER,
    DEPLOY_SIGNATURE_HEADER,
    DEPLOY_TIMESTAMP_HEADER,
    sign_deployment_request,
)
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import (
    EnvironmentIdentity,
    RunState,
    TargetIdentity,
    declared_target_identity_digest,
)
from echo_certification_forge.release_hooks import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookSecretRegistry,
    sign_webhook,
)
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.sandbox import DockerSandbox
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


def test_reconciliation_rejects_mutable_or_different_git_identity_without_artifact(
    store, manifest, environment
):
    repository = "https://github.com/echo/example.git"
    mutable_reference = f"{repository}@main"
    mutable_run = "cert-git-mutable-ref"
    store.register_declared_run(
        run_id=mutable_run,
        tenant_id=TENANT,
        target_type="git",
        target_identity_digest=declared_target_identity_digest(
            TENANT, "git", None, "main", mutable_reference
        ),
        target_reference=mutable_reference,
        environment_identity_digest=environment.identity_digest,
        environment_json=environment.to_dict(),
        policy_version=manifest.manifest_id,
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        declared_source_commit="main",
    )
    mutable_target = TargetIdentity(
        tenant_id=TENANT,
        target_type="git",
        canonical_ref=mutable_reference,
        artifact_sha256=_digest("mutable-tree"),
        source_commit="a" * 40,
    )
    with pytest.raises(ValueError, match="target_declared_artifact_commitment_missing"):
        store.reconcile_declared_target(mutable_run, TENANT, mutable_target, environment)

    exact_commit = "b" * 40
    exact_reference = f"{repository}@{exact_commit}"
    exact_run = "cert-git-reference-drift"
    store.register_declared_run(
        run_id=exact_run,
        tenant_id=TENANT,
        target_type="git",
        target_identity_digest=declared_target_identity_digest(
            TENANT, "git", None, exact_commit, exact_reference
        ),
        target_reference=exact_reference,
        environment_identity_digest=environment.identity_digest,
        environment_json=environment.to_dict(),
        policy_version=manifest.manifest_id,
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        declared_source_commit=exact_commit,
    )
    drifted_target = TargetIdentity(
        tenant_id=TENANT,
        target_type="git",
        canonical_ref=f"{repository}@{'c' * 40}",
        artifact_sha256=_digest("different-tree"),
        source_commit="c" * 40,
    )
    with pytest.raises(ValueError, match="target_declared_reference_mismatch"):
        store.reconcile_declared_target(exact_run, TENANT, drifted_target, environment)


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
    context, certified_target, environment, manifest, tmp_path
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
        # a production deployment may never begin without a rollback mechanism
        "CERTFORGE_ROLLBACK_CMD": "true",
    }

    def run_wrapper(deploy_env: str, deployment_id: str, *deploy_cmd: str,
                    drop_rollback_cmd: bool = False):
        env = {**base_env, "CERTFORGE_ENVIRONMENT": deploy_env,
               "CERTFORGE_DEPLOYMENT_ID": deployment_id}
        if drop_rollback_cmd:
            env.pop("CERTFORGE_ROLLBACK_CMD", None)
        return subprocess.run(
            [bash, script, *deploy_cmd],
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )

    try:
        # production WITHOUT a rollback mechanism fails closed BEFORE any admission is
        # requested and BEFORE the deploy command can run
        marker = tmp_path / "no-rollback-deploy-ran.marker"
        proc = run_wrapper(
            "production", "deploy-sh-norollback", "touch", str(marker).replace("\\", "/"),
            drop_rollback_cmd=True,
        )
        assert proc.returncode == 3, proc.stdout + proc.stderr
        assert "CERTFORGE_ROLLBACK_CMD" in proc.stderr
        assert proc.stdout.strip() == ""  # no admission was minted
        assert not marker.exists()  # the deployment never began

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

        # a production admission that binds NO rollback target (no prior good production)
        # is REFUSED by the wrapper before the deploy command can run: the FIRST
        # production deployment must be provisioned out-of-band via the authenticated API
        marker = tmp_path / "no-bound-target-deploy-ran.marker"
        proc = run_wrapper(
            "production", "deploy-sh-nofirst", "touch", str(marker).replace("\\", "/")
        )
        assert proc.returncode == 3, proc.stdout + proc.stderr
        assert "no admission-bound rollback target" in proc.stderr
        assert not marker.exists()  # the deployment never began

        # bootstrap the first production deployment out-of-band via the authenticated API
        artifact = certified_target.artifact_sha256
        boot = _post_signed(
            client,
            "/v1/deployments/admissions",
            _admit_body(artifact, "production", environment, manifest, "deploy-sh-boot"),
        ).json()
        assert boot["allowed"] is True, boot["reasons"]
        response = _post_signed(
            client,
            f"/v1/deployments/admissions/{boot['admission_id']}/outcome",
            {"status": "SUCCEEDED", "detail": "bootstrap production"},
        )
        assert response.status_code == 201

        # production through the wrapper now carries the admission-bound rollback target
        prod_proc = run_wrapper("production", "deploy-sh-prd", "true")
        assert prod_proc.returncode == 0, prod_proc.stdout + prod_proc.stderr
        assert '"status": "SUCCEEDED"' in prod_proc.stdout
        assert f'"artifact_sha256": "{artifact}"' in prod_proc.stdout  # frozen candidate

        # a FAILING production deploy exits with the deploy status, records FAILED,
        # executes the mandatory rollback against the ADMISSION-BOUND target and records it
        fail_proc = run_wrapper("production", "deploy-sh-fail", "false")
        assert fail_proc.returncode == 1, fail_proc.stdout + fail_proc.stderr
        assert "recording FAILED outcome" in fail_proc.stderr
        assert '"status": "FAILED"' in fail_proc.stdout
        assert "EXECUTING ROLLBACK (admission-bound last-known-good" in fail_proc.stderr
        assert '"status": "ROLLED_BACK"' in fail_proc.stdout
        assert f'"rollback_to": "{artifact}"' in fail_proc.stdout
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    audit = client.get("/v1/deployments/audit", headers={"X-Tenant-ID": TENANT}).json()
    assert audit["chain_valid"] is True
    outcomes = [row for row in audit["records"] if row["record_type"] == "OUTCOME"]
    # staging SUCCEEDED (script) + bootstrap production SUCCEEDED (API) + production
    # SUCCEEDED (script) + production FAILED + ROLLED_BACK (script)
    assert len(outcomes) == 5
    assert all(row["admission_id"] for row in outcomes)


# --------------------------------------------------------------------------------------
# Terminal outcome transitions over HTTP — 409 fail-closed mapping
# --------------------------------------------------------------------------------------


def test_http_terminal_outcome_transitions_fail_closed(
    client, certified_target, environment, manifest
):
    """FAILED -> SUCCEEDED forgery and drifted rollback digests are rejected with 409
    through the real API surface."""
    artifact = certified_target.artifact_sha256
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    staging = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-term-s1"),
    ).json()
    assert staging["allowed"] is True, staging["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging green"},
    )
    assert response.status_code == 201

    # repeated / contradictory outcomes on the same admission are 409 outcome_already_terminal
    for body in ({"status": "SUCCEEDED", "detail": "again"}, {"status": "FAILED", "detail": "flip"}):
        response = _post_signed(
            client, f"/v1/deployments/admissions/{staging['admission_id']}/outcome", body
        )
        assert response.status_code == 409
        assert response.json()["detail"] == "outcome_already_terminal"

    production = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-term-p1"),
    ).json()
    assert production["allowed"] is True, production["reasons"]

    # rollback without a preceding production failure is refused
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{production['admission_id']}/outcome",
        {"status": "ROLLED_BACK", "detail": "premature", "rollback_to": artifact},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "rollback_requires_failed_production"

    # first production failure binds NO candidate (no prior good production)
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{production['admission_id']}/outcome",
        {"status": "FAILED", "detail": "prod red"},
    )
    assert response.status_code == 201
    assert response.json()["payload"]["rollback_candidate"] is None
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{production['admission_id']}/outcome",
        {"status": "ROLLED_BACK", "detail": "nothing bound", "rollback_to": artifact},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "rollback_candidate_missing"

    # and the forgery is impossible over HTTP too
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{production['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "forged"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "outcome_already_terminal"


# --------------------------------------------------------------------------------------
# enforce_admission.sh — rollback MUST run even when outcome recording is down
# --------------------------------------------------------------------------------------


class _OneShotProxy:
    """TCP proxy forwarding ONLY the first connection to the upstream service, then
    refusing every later one — simulating the outcome endpoint going down right after
    admission was granted (urllib opens one connection per request; no keep-alive)."""

    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._listener.listen(8)
        self.forwarded = 0
        self.refused = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _pump(source: socket.socket, sink: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _serve(self) -> None:
        self._listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.forwarded == 0:
                self.forwarded += 1
                upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=30)
                threading.Thread(target=self._pump, args=(connection, upstream), daemon=True).start()
                threading.Thread(target=self._pump, args=(upstream, connection), daemon=True).start()
            else:
                self.refused += 1
                connection.close()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.mark.skipif(_bash_executable() is None, reason="no usable bash for the .sh integration")
def test_enforce_admission_sh_rolls_back_even_when_outcome_recording_is_down(
    context, certified_target, environment, manifest, tmp_path
):
    """TOTAL outcome-reporting outage must NEVER prevent the actual production rollback:
    the wrapper retries FAILED recording, still executes CERTFORGE_ROLLBACK_CMD with the
    ADMISSION-BOUND target (frozen before the deployment began), attempts ROLLED_BACK
    reporting, and then fails closed (exit 3) because reporting is incomplete."""
    import urllib.request

    import uvicorn

    app = create_app(context)
    client = TestClient(app)
    artifact = certified_target.artifact_sha256
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    # staging accepted + a good production deployment establish the last-known-good
    # that the wrapper's admission will freeze as its rollback target
    staging = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-down-s1"),
    ).json()
    assert staging["allowed"] is True, staging["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging green"},
    )
    assert response.status_code == 201
    good_prod = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-down-p0"),
    ).json()
    assert good_prod["allowed"] is True, good_prod["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{good_prod['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "prod green"},
    )
    assert response.status_code == 201

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as live:
                if live.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError("live service never became healthy")

    proxy = _OneShotProxy(port)
    marker = tmp_path / "rollback-executed.marker"
    bash = _bash_executable()
    script = str(Path(__file__).parents[1] / "deploy" / "enforce_admission.sh").replace("\\", "/")
    marker_posix = str(marker).replace("\\", "/")
    try:
        proc = subprocess.run(
            [bash, script, "false"],
            capture_output=True,
            text=True,
            timeout=120,
            env={
                **os.environ,
                # admission goes through the proxy's ONE forwarded connection; every
                # outcome request afterwards is refused (endpoint down)
                "CERTFORGE_URL": f"http://127.0.0.1:{proxy.port}",
                "CERTFORGE_TENANT": TENANT,
                "CERTFORGE_ARTIFACT_DIGEST": artifact,
                "CERTFORGE_ENVIRONMENT": "production",
                "CERTFORGE_ENV_IDENTITY_DIGEST": environment.identity_digest,
                "CERTFORGE_RULE_MANIFEST_DIGEST": manifest.digest,
                "CERTFORGE_DEPLOYMENT_ID": "deploy-down-p1",
                "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET,
                "CERTFORGE_PYTHON": sys.executable.replace("\\", "/"),
                "CERTFORGE_ROLLBACK_CMD":
                    f"printf %s \"$CERTFORGE_ROLLBACK_TARGET\" > '{marker_posix}'",
            },
        )
    finally:
        proxy.stop()
        server.should_exit = True
        thread.join(timeout=10)

    # fail-closed: reporting is incomplete -> exit 3, NOT the raw deploy status
    assert proc.returncode == 3, proc.stdout + proc.stderr
    # the FAILED recording was retried and reported as not recorded
    assert "outcome recording attempt 3/3 failed" in proc.stderr
    assert "OUTCOME NOT RECORDED (FAILED)" in proc.stderr
    # ... and the ACTUAL rollback still executed with the EXACT admission-bound target,
    # even though every single reporting attempt failed
    assert marker.exists(), proc.stdout + proc.stderr
    assert marker.read_text(encoding="utf-8").strip() == artifact
    assert "EXECUTING ROLLBACK (admission-bound last-known-good" in proc.stderr
    # ROLLED_BACK reporting was ATTEMPTED after the rollback and also failed
    assert "ROLLED_BACK outcome NOT RECORDED" in proc.stderr
    assert "DEPLOYMENT REPORTING INCOMPLETE" in proc.stderr
    assert proxy.forwarded == 1
    # 3 FAILED attempts + 3 ROLLED_BACK attempts were all refused by the dead endpoint
    assert proxy.refused >= 6

    # the ledger holds the wrapper's admission but NO outcome rows for it (reporting was
    # down), and the chain is still valid
    audit = client.get("/v1/deployments/audit", headers={"X-Tenant-ID": TENANT}).json()
    assert audit["chain_valid"] is True
    sh_admissions = [
        row
        for row in audit["records"]
        if row["record_type"] == "ADMISSION"
        and row["deployment_environment"] == "production"
        and row["record_id"] != good_prod["admission_id"]
    ]
    assert len(sh_admissions) == 1
    admission_id = sh_admissions[0]["record_id"]
    outcomes = [
        row
        for row in audit["records"]
        if row["record_type"] == "OUTCOME" and row["admission_id"] == admission_id
    ]
    assert outcomes == []

# --------------------------------------------------------------------------------------
# Outcome submission is idempotent/recoverable across commit-then-response-loss
# --------------------------------------------------------------------------------------


def test_http_outcome_operation_id_idempotency(client, certified_target, environment, manifest):
    """A stable operation id turns an ambiguous lost response into an idempotent
    recovery: the exact retry returns the committed record (200, replayed), while
    conflicting payloads and nonce replays remain rejected."""
    artifact = certified_target.artifact_sha256
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    staging = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-opid-s1"),
    ).json()
    assert staging["allowed"] is True, staging["reasons"]
    outcome_path = f"/v1/deployments/admissions/{staging['admission_id']}/outcome"
    payload = {"status": "SUCCEEDED", "detail": "staging green", "operation_id": "op-http-0001"}

    first = _post_signed(client, outcome_path, payload)
    assert first.status_code == 201
    assert first.json()["replayed"] is False
    record_id = first.json()["record_id"]

    # the EXACT retry (fresh nonce, same operation) returns the committed outcome
    replay = _post_signed(client, outcome_path, payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["record_id"] == record_id

    # a reused operation id with a DIFFERENT payload is a conflict, never a dedupe
    conflict = _post_signed(
        client, outcome_path,
        {"status": "FAILED", "detail": "staging green", "operation_id": "op-http-0001"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "outcome_operation_conflict"
    conflict = _post_signed(
        client, outcome_path,
        {"status": "SUCCEEDED", "detail": "other detail", "operation_id": "op-http-0001"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "outcome_operation_conflict"

    # a NEW operation id (or none) against the terminal admission keeps the strict guard
    terminal = _post_signed(
        client, outcome_path,
        {"status": "SUCCEEDED", "detail": "staging green", "operation_id": "op-http-9999"},
    )
    assert terminal.status_code == 409
    assert terminal.json()["detail"] == "outcome_already_terminal"
    terminal = _post_signed(client, outcome_path, {"status": "SUCCEEDED", "detail": "staging green"})
    assert terminal.status_code == 409
    assert terminal.json()["detail"] == "outcome_already_terminal"

    # idempotent recovery does NOT weaken nonce replay protection: reusing the exact
    # nonce is still rejected even for the same committed operation
    pinned = "aa11bb22cc33dd44ee55ff6677889900"
    ok = _post_signed(client, outcome_path, payload, nonce=pinned)
    assert ok.status_code == 200
    assert ok.json()["replayed"] is True
    replayed_nonce = _post_signed(client, outcome_path, payload, nonce=pinned)
    assert replayed_nonce.status_code == 401
    assert replayed_nonce.json()["detail"] == "deployment_credential_nonce_reused"


class _DropResponseProxy:
    """TCP proxy that forwards every connection but DROPS the response of connection
    number ``drop`` (1-based) AFTER fully reading it from the upstream — the server
    commits, the client never learns (commit-then-response-loss)."""

    def __init__(self, upstream_port: int, drop: int) -> None:
        self.upstream_port = upstream_port
        self.drop = drop
        self.connections = 0
        self.dropped = 0
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._listener.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _pump_request(source: socket.socket, sink: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                sink.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle(self, connection: socket.socket, index: int) -> None:
        try:
            upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=30)
        except OSError:
            connection.close()
            return
        threading.Thread(
            target=self._pump_request, args=(connection, upstream), daemon=True
        ).start()
        drop_this = index == self.drop
        try:
            while True:
                data = upstream.recv(65536)
                if not data:
                    break
                if not drop_this:
                    connection.sendall(data)
                # when dropping, keep reading so the upstream finishes (and COMMITS)
        except OSError:
            pass
        finally:
            if drop_this:
                self.dropped += 1
            try:
                upstream.close()
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def _serve(self) -> None:
        self._listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            threading.Thread(
                target=self._handle, args=(connection, self.connections), daemon=True
            ).start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.mark.skipif(_bash_executable() is None, reason="no usable bash for the .sh integration")
def test_enforce_admission_sh_recovers_committed_outcome_when_response_is_dropped(
    context, certified_target, environment, manifest, tmp_path
):
    """Commit-then-response-loss on the FAILED outcome: the server commits the outcome
    (binding the rollback candidate) but the response never reaches the wrapper. The
    stable operation id lets the retry RECOVER the committed record, the rollback runs
    against the exact bound target, and ROLLED_BACK records successfully."""
    import urllib.request

    import uvicorn

    app = create_app(context)
    client = TestClient(app)
    artifact = certified_target.artifact_sha256
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    # staging accepted + a good production deployment establish the last-known-good
    staging = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-drop-s1"),
    ).json()
    assert staging["allowed"] is True, staging["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging green"},
    )
    assert response.status_code == 201
    good_prod = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-drop-p0"),
    ).json()
    assert good_prod["allowed"] is True, good_prod["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{good_prod['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "prod green"},
    )
    assert response.status_code == 201

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as live:
                if live.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError("live service never became healthy")

    # connection order through the proxy: 1=admit, 2=FAILED attempt 1 (COMMITTED but the
    # response is dropped), 3=FAILED retry (idempotent recovery), 4=ROLLED_BACK
    proxy = _DropResponseProxy(port, drop=2)
    marker = tmp_path / "rollback-target.marker"
    bash = _bash_executable()
    script = str(Path(__file__).parents[1] / "deploy" / "enforce_admission.sh").replace("\\", "/")
    marker_posix = str(marker).replace("\\", "/")
    try:
        proc = subprocess.run(
            [bash, script, "false"],
            capture_output=True,
            text=True,
            timeout=120,
            env={
                **os.environ,
                "CERTFORGE_URL": f"http://127.0.0.1:{proxy.port}",
                "CERTFORGE_TENANT": TENANT,
                "CERTFORGE_ARTIFACT_DIGEST": artifact,
                "CERTFORGE_ENVIRONMENT": "production",
                "CERTFORGE_ENV_IDENTITY_DIGEST": environment.identity_digest,
                "CERTFORGE_RULE_MANIFEST_DIGEST": manifest.digest,
                "CERTFORGE_DEPLOYMENT_ID": "deploy-drop-p1",
                "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET,
                "CERTFORGE_PYTHON": sys.executable.replace("\\", "/"),
                "CERTFORGE_ROLLBACK_CMD":
                    f"printf %s \"$CERTFORGE_ROLLBACK_TARGET\" > '{marker_posix}'",
            },
        )
    finally:
        proxy.stop()
        server.should_exit = True
        thread.join(timeout=10)

    # reporting completed via recovery -> exit is the DEPLOY status, not fail-closed 3
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proxy.dropped == 1
    # attempt 1 failed (dropped response) but the retry recovered the COMMITTED record
    assert "FAILED outcome recording attempt 1/3 failed" in proc.stderr
    assert "attempt 3/3 failed" not in proc.stderr
    assert '"replayed": true' in proc.stdout
    assert '"status": "FAILED"' in proc.stdout
    assert '"status": "ROLLED_BACK"' in proc.stdout
    # the rollback executed against the EXACT bound last-known-good digest
    assert marker.exists(), proc.stdout + proc.stderr
    assert marker.read_text(encoding="utf-8").strip() == artifact

    # the server committed the FAILED outcome exactly ONCE despite the retry, plus the
    # ROLLED_BACK naming the bound candidate; the chain stays valid
    audit = client.get("/v1/deployments/audit", headers={"X-Tenant-ID": TENANT}).json()
    assert audit["chain_valid"] is True
    sh_admissions = [
        row
        for row in audit["records"]
        if row["record_type"] == "ADMISSION"
        and row["deployment_environment"] == "production"
        and row["record_id"] != good_prod["admission_id"]
    ]
    assert len(sh_admissions) == 1
    from echo_certification_forge.deployment import DeploymentLedger

    ledger = DeploymentLedger(context.deployment_ledger_path)
    sh_outcomes = ledger.outcomes(sh_admissions[0]["record_id"], TENANT)
    payloads = [json.loads(row["payload_json"]) for row in sh_outcomes]
    statuses = [payload["status"] for payload in payloads]
    assert statuses == ["FAILED", "ROLLED_BACK"]
    assert payloads[0]["rollback_candidate"]["artifact_sha256"] == artifact
    assert payloads[1]["rollback_to"] == artifact

# --------------------------------------------------------------------------------------
# OCI acquisition — registry-image webhooks deploy end-to-end by IMMUTABLE digest
# --------------------------------------------------------------------------------------


class _LocalOciRegistry:
    """Minimal in-process OCI registry: serves pre-registered manifests/blobs by digest
    over the standard /v2/<name>/{manifests,blobs}/<digest> paths."""

    def __init__(self) -> None:
        objects: dict[str, bytes] = {}
        self.objects = objects

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = objects.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def put(self, path: str, body: bytes) -> None:
        self.objects[path] = body

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _tar_layer(
    entries: dict[str, bytes | None] | None = None,
    *,
    symlinks: tuple[tuple[str, str], ...] = (),
    hardlinks: tuple[tuple[str, str], ...] = (),
    devices: tuple[str, ...] = (),
) -> bytes:
    """Build a deterministic in-memory tar layer (real image-layer bytes, not opaque)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in (entries or {}).items():
            info = tarfile.TarInfo(name)
            info.mtime = 0
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        for name, target in symlinks:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
        for name, target in hardlinks:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.type = tarfile.LNKTYPE
            info.linkname = target
            tar.addfile(info)
        for name in devices:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 3
            tar.addfile(info)
    return buffer.getvalue()


_OCI_HELLO_SOURCE = b"print('hello from the certified image layer')\n"
_OCI_LAYER = _tar_layer({"app/hello.py": _OCI_HELLO_SOURCE})


def _push_image(
    registry: _LocalOciRegistry, layers: list[bytes], name: str = "testapp"
) -> str:
    """Register a single-arch OCI image built from REAL tar layers; returns its
    sha256:<hex> manifest digest."""
    config = json.dumps({"architecture": "amd64", "os": "linux"}).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    descriptors = []
    for layer in layers:
        layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
        registry.put(f"/v2/{name}/blobs/{layer_digest}", layer)
        descriptors.append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": len(layer),
            }
        )
    manifest_bytes = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": descriptors,
        },
        sort_keys=True,
    ).encode("utf-8")
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    registry.put(f"/v2/{name}/manifests/{manifest_digest}", manifest_bytes)
    registry.put(f"/v2/{name}/blobs/{config_digest}", config)
    return manifest_digest


def _push_test_image(registry: _LocalOciRegistry, name: str = "testapp") -> str:
    """Register the standard tiny single-arch OCI image; returns its manifest digest."""
    return _push_image(registry, [_OCI_LAYER], name)


def test_oci_acquisition_is_digest_pinned_and_fail_closed(tmp_path):
    """The OCI path NEVER trusts a mutable tag and hash-verifies every byte it pulls:
    tag specs and unverifiable manifests/blobs fail acquisition BEFORE any run state
    could be created, while the digest-pinned pull materializes the REAL image rootfs
    (scanned contents, not opaque blobs) whose artifact identity is the image's NATIVE
    manifest digest."""
    registry = _LocalOciRegistry()
    try:
        manifest_digest = _push_test_image(registry)
        repo = f"http://127.0.0.1:{registry.port}/testapp"

        # mutable tags are rejected outright — a registry could re-point them later
        with pytest.raises(AcquisitionError, match="never a tag"):
            acquire_target({"type": "oci", "repository": repo, "tag": "latest"}, tmp_path / "t1")
        with pytest.raises(AcquisitionError, match="requires 'digest'"):
            acquire_target({"type": "oci", "repository": repo}, tmp_path / "t2")

        # manifest bytes that do not hash to the requested digest are refused
        wrong = "sha256:" + hashlib.sha256(b"attacker manifest").hexdigest()
        registry.put(f"/v2/testapp/manifests/{wrong}", b'{"schemaVersion": 2}')
        with pytest.raises(AcquisitionError, match="digest mismatch"):
            acquire_target({"type": "oci", "repository": repo, "digest": wrong}, tmp_path / "t3")

        # a tampered layer blob is refused even when the manifest itself verifies
        layer_digest = "sha256:" + hashlib.sha256(_OCI_LAYER).hexdigest()
        registry.put(f"/v2/testapp/blobs/{layer_digest}", b"tampered layer bytes")
        with pytest.raises(AcquisitionError, match="digest mismatch"):
            acquire_target(
                {"type": "oci", "repository": repo, "digest": manifest_digest}, tmp_path / "t4"
            )
        registry.put(f"/v2/testapp/blobs/{layer_digest}", _OCI_LAYER)  # restore

        # the digest-pinned pull verifies everything and preserves native identity
        acquired = acquire_target(
            {"type": "oci", "repository": repo, "digest": manifest_digest}, tmp_path / "t5"
        )
        assert acquired.target_type == "oci"
        assert acquired.canonical_ref == f"{repo}@{manifest_digest}"
        assert acquired.artifact_sha256 == manifest_digest.split(":", 1)[1]
        # the scanned source root is the MATERIALIZED image rootfs (real contents) ...
        assert acquired.source_root.name == "rootfs"
        hello = acquired.source_root / "app" / "hello.py"
        assert hello.read_bytes() == _OCI_HELLO_SOURCE
        # ... with the verified OCI layout preserved beside it as evidence
        layout = acquired.source_root.parent
        assert (layout / "oci-layout").exists()
        assert (layout / "index.json").exists()
        assert (layout / "blobs" / "sha256" / acquired.artifact_sha256).exists()
    finally:
        registry.stop()


_DOCKER_STUB_SOURCE = r'''
import json, os, subprocess, sys

argv = sys.argv[1:]
if not argv or argv[0] != "run":
    sys.exit(64)
workdir = None
image = None
cmd = []
for index, arg in enumerate(argv):
    if arg == "-v" and argv[index + 1].endswith(":/work:ro"):
        workdir = argv[index + 1][: -len(":/work:ro")]
    if arg == "-w":
        cursor = index + 2
        while argv[cursor] == "--env":
            cursor += 2
        image = argv[cursor]
        cmd = argv[cursor + 1 :]
with open(os.environ["CERTFORGE_TEST_DOCKER_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"argv": argv, "image": image, "workdir": workdir}) + "\n")
if workdir is None or image is None or not cmd:
    sys.exit(64)
executable = sys.executable if cmd[0] in ("python", "python3") else cmd[0]
sys.exit(subprocess.run([executable, *cmd[1:]], cwd=workdir).returncode)
'''


def test_registry_webhook_oci_run_certifies_and_deploys_end_to_end(
    client, store, manifest, signer, tmp_path
):
    """A registry-image webhook is NOT a dead end: the worker acquires the image from
    the registry BY THE DECLARED IMMUTABLE DIGEST (no tag trust), materializes and scans
    the REAL image rootfs, executes the journey INSIDE the sandbox pinned to the exact
    image digest (the journey runs code shipped in the image layer — never on the host),
    reconciles exactly to the declared native identity, certifies, binds, and admits —
    end to end through the real surfaces."""
    registry = _LocalOciRegistry()
    stub = tmp_path / "docker_stub.py"
    stub.write_text(_DOCKER_STUB_SOURCE, encoding="utf-8")
    docker_log = tmp_path / "docker_invocations.jsonl"
    os.environ["CERTFORGE_TEST_DOCKER_LOG"] = str(docker_log)
    try:
        manifest_digest = _push_test_image(registry)
        repo = f"http://127.0.0.1:{registry.port}/testapp"
        exact_image = f"127.0.0.1:{registry.port}/testapp@{manifest_digest}"
        event = {
            "event_id": "evt-oci-0001",
            "event_type": "registry.image.pushed",
            "tenant_id": TENANT,
            "image_digest": manifest_digest,
            "image_repository": repo,
            "source_commit": "abc123def456",
            # the platform declares the WORKER's environment commitment for the run
            "environment_identity_digest": run_worker._worker_environment(
                sandbox=DockerSandbox(image=exact_image)
            ).identity_digest,
            "policy_version": manifest.manifest_id,
        }
        body = json.dumps(event).encode("utf-8")
        response = client.post("/v1/hooks/registry", content=body, headers=_signed_headers(body))
        assert response.status_code == 201, response.text
        run = response.json()["run"]
        run_id = run["run_id"]
        assert run["state"] == "QUEUED"
        assert run["release_verdict"] == "NOT_READY"  # default-deny until certified

        # the worker pulls the image BY DIGEST and reconciles the declared commitment;
        # the journey executes code FROM THE IMAGE LAYER inside the (stubbed) sandbox
        result = run_worker.run(
            run_id,
            TENANT,
            {"type": "oci", "repository": repo, "digest": manifest_digest},
            store=store,
            manifest=manifest,
            signer=signer,
            entitled=frozenset({TENANT}),
            journey=["python3", "app/hello.py"],
            sandbox=DockerSandbox(docker=(sys.executable, str(stub))),
        )
    finally:
        os.environ.pop("CERTFORGE_TEST_DOCKER_LOG", None)
        registry.stop()
    assert "error" not in result, result
    assert result["release_verdict"] == "PRODUCTION_READY", result["blocking_findings"]
    assert result["journey_isolation"] == "docker"

    # the sandbox ran EXACTLY ONE journey, pinned to the certified image digest (native
    # registry reference, scheme stripped) with networking disabled — never a host image
    invocations = [
        json.loads(line) for line in docker_log.read_text(encoding="utf-8").splitlines()
    ]
    assert len(invocations) == 1
    assert invocations[0]["image"] == f"127.0.0.1:{registry.port}/testapp@{manifest_digest}"
    assert "--network" in invocations[0]["argv"]
    assert invocations[0]["argv"][invocations[0]["argv"].index("--network") + 1] == "none"

    bare = manifest_digest.split(":", 1)[1]
    row = store.get_run(run_id, TENANT)
    identity = json.loads(str(row["target_identity_json"]))
    assert identity["artifact_sha256"] == bare  # native registry identity preserved
    assert identity["target_type"] == "oci"
    assert "declared_identity_digest" not in identity  # reconciled, no longer declared

    # binding + staging admission work against the image's NATIVE manifest digest
    response = _post_signed(client, f"/v1/certifications/{run_id}/bindings")
    assert response.status_code == 201, response.text
    assert response.json()["artifact_sha256"] == bare
    admit = _post_signed(
        client,
        "/v1/deployments/admissions",
        {
            "artifact_sha256": bare,
            "deployment_environment": "staging",
            "environment_identity_digest": result["environment_identity_digest"],
            "rule_manifest_digest": manifest.digest,
            "deployment_id": "deploy-oci-s1",
            "requested_by": "ci.pipeline",
        },
    ).json()
    assert admit["allowed"] is True, admit["reasons"]
    assert admit["run_id"] == run_id

def test_oci_rootfs_whiteouts_and_symlink_containment(tmp_path):
    """Materialization applies REAL layer semantics safely: whiteouts delete (and are
    never written into the rootfs), later layers overlay earlier ones, and symlink
    members are recorded as inert marker files — the control plane never creates a
    symlink on the host, so no member can traverse out of the destination tree."""
    registry = _LocalOciRegistry()
    try:
        base_layer = _tar_layer(
            {
                "app/hello.py": _OCI_HELLO_SOURCE,
                "app/secret.txt": b"to be whiteout-deleted\n",
            },
            symlinks=(("app/link", "../../../../outside"),),
        )
        top_layer = _tar_layer(
            {"app/.wh.secret.txt": b"", "app/extra.txt": b"added by layer 2\n"}
        )
        digest = _push_image(registry, [base_layer, top_layer], name="layered")
        repo = f"http://127.0.0.1:{registry.port}/layered"
        acquired = acquire_target(
            {"type": "oci", "repository": repo, "digest": digest}, tmp_path / "dst"
        )
    finally:
        registry.stop()
    rootfs = acquired.source_root
    assert (rootfs / "app" / "hello.py").read_bytes() == _OCI_HELLO_SOURCE
    # the whiteout deleted the base-layer file and was itself never materialized
    assert not (rootfs / "app" / "secret.txt").exists()
    assert not any(p.name.startswith(".wh.") for p in rootfs.rglob("*"))
    assert (rootfs / "app" / "extra.txt").read_bytes() == b"added by layer 2\n"
    # the symlink member became an inert REGULAR marker file, not a host symlink
    link = rootfs / "app" / "link"
    assert link.is_file()
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "@certforge-symlink:../../../../outside"
    # nothing escaped the destination tree
    assert not (tmp_path / "outside").exists()
    assert not (tmp_path.parent / "outside").exists()


def test_oci_malicious_layers_fail_closed(tmp_path):
    """Hostile layer archives are refused during acquisition — path traversal, absolute
    paths, separator smuggling, device nodes, unreadable archives, hardlink escapes and
    ambiguous multi-platform indexes all fail closed BEFORE any content is certified."""
    registry = _LocalOciRegistry()
    try:
        repo_base = f"http://127.0.0.1:{registry.port}"
        cases = [
            ("traversal", _tar_layer({"../evil.txt": b"x"}), "path traversal"),
            ("absolute", _tar_layer({"/evil.txt": b"x"}), "absolute path"),
            ("backslash", _tar_layer({"app\\evil.txt": b"x"}), "unsafe name"),
            ("device", _tar_layer(devices=("app/dev0",)), "device/fifo"),
            ("nottar", b"this is not a tar archive", "not a readable tar archive"),
            (
                "hardlink",
                _tar_layer(hardlinks=(("app/hl", "../../etc/passwd"),)),
                "hardlink target",
            ),
        ]
        for name, layer, pattern in cases:
            digest = _push_image(registry, [layer], name=name)
            with pytest.raises(AcquisitionError, match=pattern):
                acquire_target(
                    {"type": "oci", "repository": f"{repo_base}/{name}", "digest": digest},
                    tmp_path / name,
                )
            # fail-closed means no partially-materialized rootfs content survives use
            assert not (tmp_path / name / "rootfs" / "evil.txt").exists()

        # a multi-platform index is ambiguous — certification requires pinning the ONE
        # platform-specific image manifest digest
        child_a = _push_image(registry, [_tar_layer({"a.txt": b"a"})], name="multi")
        child_b = _push_image(registry, [_tar_layer({"b.txt": b"b"})], name="multi")
        index_bytes = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": child_a,
                        "size": 1,
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": child_b,
                        "size": 1,
                    },
                ],
            },
            sort_keys=True,
        ).encode("utf-8")
        index_digest = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
        registry.put(f"/v2/multi/manifests/{index_digest}", index_bytes)
        with pytest.raises(AcquisitionError, match="exactly ONE platform image"):
            acquire_target(
                {"type": "oci", "repository": f"{repo_base}/multi", "digest": index_digest},
                tmp_path / "multi",
            )
    finally:
        registry.stop()


def test_registry_webhook_oci_journey_without_sandbox_fails_closed(
    client, store, manifest, signer
):
    """An OCI journey with NO isolated runtime configured must not certify: image code
    never executes in the control plane, so the worker fails closed BEFORE any run-state
    mutation and the run stays uncertified and unbindable."""
    registry = _LocalOciRegistry()
    try:
        manifest_digest = _push_test_image(registry, name="nosandbox")
        repo = f"http://127.0.0.1:{registry.port}/nosandbox"
        event = {
            "event_id": "evt-oci-0002",
            "event_type": "registry.image.pushed",
            "tenant_id": TENANT,
            "image_digest": manifest_digest,
            "image_repository": repo,
            "source_commit": "abc123def456",
            "environment_identity_digest": run_worker._worker_environment().identity_digest,
            "policy_version": manifest.manifest_id,
        }
        body = json.dumps(event).encode("utf-8")
        response = client.post("/v1/hooks/registry", content=body, headers=_signed_headers(body))
        assert response.status_code == 201, response.text
        run_id = response.json()["run"]["run_id"]

        result = run_worker.run(
            run_id,
            TENANT,
            {"type": "oci", "repository": repo, "digest": manifest_digest},
            store=store,
            manifest=manifest,
            signer=signer,
            entitled=frozenset({TENANT}),
            journey=["python3", "app/hello.py"],
            sandbox=None,
        )
    finally:
        registry.stop()
    assert result["error"] == "oci_journey_requires_sandbox"
    worker_root = store.evidence_root / ".worker"
    assert not worker_root.exists() or not any(worker_root.iterdir())
    # the refusal happened BEFORE any run-state mutation — the run is still pending
    row = store.get_run(run_id, TENANT)
    assert row["state"] == RunState.QUEUED.value
    # an uncertified run has no signed verdict and cannot be bound
    response = _post_signed(client, f"/v1/certifications/{run_id}/bindings")
    assert response.status_code >= 400


@pytest.mark.skipif(_bash_executable() is None, reason="no usable bash for the .sh integration")
def test_enforce_admission_sh_rolls_back_when_success_cannot_be_ledgered(
    context, certified_target, environment, manifest, tmp_path
):
    """A production deploy that SUCCEEDS but whose SUCCEEDED outcome cannot be durably
    recorded must NOT stay live: the wrapper attempts a FAILED record, then executes the
    admission-bound rollback target, attempts ROLLED_BACK reporting, and exits fail-closed
    (exit 3) — no artifact the ledger cannot account for remains in production."""
    import urllib.request

    import uvicorn

    app = create_app(context)
    client = TestClient(app)
    artifact = certified_target.artifact_sha256
    response = _post_signed(client, "/v1/certifications/cert-http-v1/bindings")
    assert response.status_code == 201

    # staging accepted + a good production deployment establish the last-known-good
    # that the wrapper's admission will freeze as its rollback target
    staging = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "staging", environment, manifest, "deploy-unledgered-s1"),
    ).json()
    assert staging["allowed"] is True, staging["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{staging['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "staging green"},
    )
    assert response.status_code == 201
    good_prod = _post_signed(
        client,
        "/v1/deployments/admissions",
        _admit_body(artifact, "production", environment, manifest, "deploy-unledgered-p0"),
    ).json()
    assert good_prod["allowed"] is True, good_prod["reasons"]
    response = _post_signed(
        client,
        f"/v1/deployments/admissions/{good_prod['admission_id']}/outcome",
        {"status": "SUCCEEDED", "detail": "prod green"},
    )
    assert response.status_code == 201

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as live:
                if live.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError("live service never became healthy")

    proxy = _OneShotProxy(port)
    deploy_marker = tmp_path / "deploy-succeeded.marker"
    rollback_marker = tmp_path / "rollback-executed.marker"
    bash = _bash_executable()
    script = str(Path(__file__).parents[1] / "deploy" / "enforce_admission.sh").replace("\\", "/")
    deploy_marker_posix = str(deploy_marker).replace("\\", "/")
    rollback_marker_posix = str(rollback_marker).replace("\\", "/")
    try:
        proc = subprocess.run(
            [bash, script, "touch", deploy_marker_posix],
            capture_output=True,
            text=True,
            timeout=120,
            env={
                **os.environ,
                # admission goes through the proxy's ONE forwarded connection; every
                # outcome request afterwards is refused (acknowledgement outage)
                "CERTFORGE_URL": f"http://127.0.0.1:{proxy.port}",
                "CERTFORGE_TENANT": TENANT,
                "CERTFORGE_ARTIFACT_DIGEST": artifact,
                "CERTFORGE_ENVIRONMENT": "production",
                "CERTFORGE_ENV_IDENTITY_DIGEST": environment.identity_digest,
                "CERTFORGE_RULE_MANIFEST_DIGEST": manifest.digest,
                "CERTFORGE_DEPLOYMENT_ID": "deploy-unledgered-p1",
                "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET,
                "CERTFORGE_PYTHON": sys.executable.replace("\\", "/"),
                "CERTFORGE_ROLLBACK_CMD":
                    f"printf %s \"$CERTFORGE_ROLLBACK_TARGET\" > '{rollback_marker_posix}'",
            },
        )
    finally:
        proxy.stop()
        server.should_exit = True
        thread.join(timeout=10)

    # the deploy command itself SUCCEEDED ...
    assert deploy_marker.exists(), proc.stdout + proc.stderr
    # ... but the ledger could not record it, so the wrapper failed closed (exit 3)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "outcome recording attempt 3/3 failed" in proc.stderr
    assert "OUTCOME NOT RECORDED (SUCCEEDED)" in proc.stderr
    assert "UNLEDGERED PRODUCTION ARTIFACT" in proc.stderr
    # the ACTUAL rollback executed with the EXACT admission-bound target, restoring the
    # previous known-good release even though every reporting attempt failed
    assert rollback_marker.exists(), proc.stdout + proc.stderr
    assert rollback_marker.read_text(encoding="utf-8").strip() == artifact
    assert "EXECUTING ROLLBACK (admission-bound last-known-good" in proc.stderr
    assert "ROLLED_BACK outcome NOT RECORDED" in proc.stderr
    assert "DEPLOYMENT REPORTING INCOMPLETE" in proc.stderr
    assert proxy.forwarded == 1
    # 3 SUCCEEDED + 3 FAILED + 3 ROLLED_BACK attempts were all refused
    assert proxy.refused >= 9

    # the ledger holds the wrapper's admission with NO outcome rows (acknowledgement was
    # down) and the chain is still valid — nothing unledgered was left live
    audit = client.get("/v1/deployments/audit", headers={"X-Tenant-ID": TENANT}).json()
    assert audit["chain_valid"] is True
    sh_admissions = [
        row
        for row in audit["records"]
        if row["record_type"] == "ADMISSION"
        and row["deployment_environment"] == "production"
        and row["record_id"] != good_prod["admission_id"]
    ]
    assert len(sh_admissions) == 1
    admission_id = sh_admissions[0]["record_id"]
    outcomes = [
        row
        for row in audit["records"]
        if row["record_type"] == "OUTCOME" and row["admission_id"] == admission_id
    ]
    assert outcomes == []
