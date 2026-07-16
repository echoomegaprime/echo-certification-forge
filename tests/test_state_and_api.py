from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from echo_certification_forge.models import RunState
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry


def test_state_machine_rejects_skipped_transition(store, manifest, target, environment):
    store.register_run("cert-state", target, environment, manifest.manifest_id, manifest.digest)
    with pytest.raises(ValueError, match="illegal run-state transition"):
        store.transition_state(
            "cert-state", target.tenant_id, RunState.EXECUTING_TESTS,
            "orchestrator", "skip", "workflow-v1",
        )


def test_state_machine_persists_legal_transition(store, manifest, target, environment):
    store.register_run("cert-state", target, environment, manifest.manifest_id, manifest.digest)
    store.transition_state(
        "cert-state", target.tenant_id, RunState.QUEUED,
        "orchestrator", "accepted", "workflow-v1",
    )
    assert store.get_run("cert-state", target.tenant_id)["state"] == "QUEUED"


def test_api_requires_tenant_and_hides_cross_tenant_run(store, manifest, target, environment):
    store.register_run("cert-api", target, environment, manifest.manifest_id, manifest.digest)
    app = create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty()))
    client = TestClient(app)
    assert client.get("/v1/certifications/cert-api").status_code == 401
    assert client.get(
        "/v1/certifications/cert-api", headers={"X-Tenant-ID": "tenant-other"}
    ).status_code == 404
    response = client.get(
        "/v1/certifications/cert-api", headers={"X-Tenant-ID": target.tenant_id}
    )
    assert response.status_code == 200
    assert response.json()["run_id"] == "cert-api"


def test_health_truthfully_reports_pending_gates(store, manifest):
    app = create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty()))
    client = TestClient(app)
    response = client.get("/v1/status")
    assert response.status_code == 200
    body = response.json()
    assert body["external_evidence_anchor"] == "PENDING"
    assert body["runner_isolation"] == "P2_FOUNDATION_VERIFIED"
    assert "PRODUCTION_READY" in body["release_verdicts"]
