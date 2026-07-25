"""P6 acceptance: signed release events and exact production deployment enforcement."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import VerdictLifecycleEvent
from echo_certification_forge.platform import CertificationPlatform
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import (
    Ed25519VerdictSigner,
    TrustedPublicKeyRegistry,
)


def _certify(store, manifest, target, environment, root: Path):
    source = root / "p6-source"
    source.mkdir()
    (source / "journey.py").write_text("print('p6-ok')\n", encoding="utf-8")
    store.register_run(
        "cert-p6",
        target,
        environment,
        manifest.manifest_id,
        manifest.digest,
    )
    signer = Ed25519VerdictSigner.generate()
    result = RunExecutor(store, manifest, signer).execute(
        "cert-p6",
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
    verdict = store.latest_signed_verdict("cert-p6", target.tenant_id)
    return signer, trusted, json.loads(verdict["payload_json"])


def test_p6_release_event_dedup_and_exact_deployment_hook(
    store, manifest, target, environment, tmp_path
):
    signer, trusted, payload = _certify(
        store, manifest, target, environment, tmp_path
    )
    platform = CertificationPlatform(store.db_path)
    account = platform.bootstrap(
        organization_id="org-p6",
        tenant_id=target.tenant_id,
        organization_name="P6 Organization",
        project_id="project-p6",
        project_name="P6 Project",
        target_reference=target.canonical_ref,
        required_policy=manifest.manifest_id,
        owner_user_id="owner-p6",
        owner_email="p6@example.test",
        plan_id="professional",
        billing_status="active",
    )
    client = TestClient(
        create_app(ServiceContext(store, manifest, trusted, platform=platform))
    )
    headers = {"X-CertForge-API-Key": account["api_key"]}
    event = {
        "source": "git",
        "event_id": "evt-p6-001",
        "target_reference": target.canonical_ref,
        "target_digest": target.artifact_sha256,
        "environment_digest": environment.identity_digest,
        "policy_digest": manifest.digest,
        "priority": "P1",
        "payload": {"commit": target.source_commit, "artifact": target.artifact_sha256},
    }

    first = client.post(
        "/v1/integrations/release-events", headers=headers, json=event
    )
    replay = client.post(
        "/v1/integrations/release-events", headers=headers, json=event
    )
    assert first.status_code == 200 and first.json()["deduplicated"] is False
    assert replay.status_code == 200 and replay.json()["deduplicated"] is True
    conflict = client.post(
        "/v1/integrations/release-events",
        headers=headers,
        json={**event, "payload": {"commit": "different"}},
    )
    assert conflict.status_code == 409

    request = {
        "attempt_id": "deploy-p6-valid",
        "run_id": "cert-p6",
        "deployment_environment": "production",
        "target_identity_digest": target.identity_digest,
        "artifact_sha256": target.artifact_sha256,
        "environment_identity_digest": environment.identity_digest,
        "rule_manifest_digest": manifest.digest,
        "evidence_merkle_root": payload["evidence_merkle_root"],
        "signing_key_id": signer.key_id,
    }
    wrong = client.post(
        "/v1/deployments/authorize",
        headers=headers,
        json={
            **request,
            "attempt_id": "deploy-p6-wrong",
            "artifact_sha256": "f" * 64,
        },
    )
    assert wrong.status_code == 200
    assert wrong.json()["allowed"] is False
    assert "deployment_artifact_mismatch" in wrong.json()["reasons"]

    valid = client.post("/v1/deployments/authorize", headers=headers, json=request)
    assert valid.status_code == 200
    assert valid.json() == {
        "allowed": True,
        "release_verdict": "PRODUCTION_READY",
        "run_id": "cert-p6",
        "attempt_id": "deploy-p6-valid",
        "reasons": ["exact_certification_valid"],
    }

    store.append_lifecycle_event(
        "cert-p6",
        target.tenant_id,
        VerdictLifecycleEvent.REVOKED,
        "p6-test",
        "post-deployment vulnerability",
    )
    revoked = client.post(
        "/v1/deployments/authorize",
        headers=headers,
        json={**request, "attempt_id": "deploy-p6-revoked"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["allowed"] is False
    assert "verdict_revoked" in revoked.json()["reasons"]


def test_p6_deployment_hook_requires_subscriber_auth(
    store, manifest
):
    client = TestClient(create_app(ServiceContext(
        store,
        manifest,
        TrustedPublicKeyRegistry.empty(),
    )))
    response = client.post(
        "/v1/deployments/authorize",
        json={
            "attempt_id": "deploy-unauthorized",
            "run_id": "unknown",
            "deployment_environment": "production",
            "target_identity_digest": "a" * 64,
            "artifact_sha256": "b" * 64,
            "environment_identity_digest": "c" * 64,
            "rule_manifest_digest": "d" * 64,
            "evidence_merkle_root": "e" * 64,
            "signing_key_id": "key-unauthorized",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_api_key"
