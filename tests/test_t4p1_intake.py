"""T4.P1 acceptance — run intake: submit + status + idempotency-key binding.

Real FastAPI TestClient over a real on-disk sqlite EvidenceStore. No mocks.
"""
from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry

TENANT = "tenant-alpha"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _client(store: EvidenceStore, manifest) -> TestClient:
    return TestClient(create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty())))


def _submit_body(manifest, *, target_digest: str, key: str) -> dict:
    return {
        "tenant_id": TENANT,
        "target": {
            "target_type": "git",
            "identity_digest": target_digest,
            "reference": "https://github.com/example/project@abc123",
        },
        "environment": {
            "identity_digest": _digest("environment"),
            "runner_image_digest": "sha256:" + _digest("runner-image"),
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": key,
    }


def test_submit_creates_queued_run_bound_to_declared_target(store, manifest):
    client = _client(store, manifest)
    target_digest = _digest("artifact-A")
    body = _submit_body(manifest, target_digest=target_digest, key="key-aaaa1111")

    response = client.post("/v1/certifications", json=body, headers={"X-Tenant-ID": TENANT})

    assert response.status_code == 201, response.text
    run = response.json()
    assert run["state"] == "QUEUED"
    assert run["run_outcome"] == "INCONCLUSIVE"
    assert run["release_verdict"] == "NOT_READY"  # default-deny at intake
    assert run["target_identity_digest"] == target_digest  # immutable binding echoed back
    assert run["policy_version"] == manifest.manifest_id
    assert run["evidence_merkle_root"] is None


def test_idempotent_replay_returns_same_run(store, manifest):
    client = _client(store, manifest)
    body = _submit_body(manifest, target_digest=_digest("artifact-B"), key="key-bbbb2222")

    first = client.post("/v1/certifications", json=body, headers={"X-Tenant-ID": TENANT})
    second = client.post("/v1/certifications", json=body, headers={"X-Tenant-ID": TENANT})

    assert first.status_code == 201
    assert second.status_code == 200  # replay, not a new create
    assert first.json()["run_id"] == second.json()["run_id"]
    assert second.json()["state"] == "QUEUED"  # replay returns the durable run unchanged
    assert second.json()["target_identity_digest"] == first.json()["target_identity_digest"]
    # exactly one run persisted for this tenant
    assert len(store.list_runs(TENANT)) == 1


def test_shared_idempotency_key_is_isolated_across_tenants(store, manifest):
    """Tenant B reusing tenant A's idempotency key must get a DISTINCT run it owns,
    and must never observe tenant A's run (idempotency PK is (tenant_id, key))."""
    client = _client(store, manifest)
    shared_key = "key-shared-000"

    body_a = _submit_body(manifest, target_digest=_digest("tenantA-artifact"), key=shared_key)
    a = client.post("/v1/certifications", json=body_a, headers={"X-Tenant-ID": TENANT})
    assert a.status_code == 201
    run_a = a.json()["run_id"]

    body_b = {**_submit_body(manifest, target_digest=_digest("tenantB-artifact"), key=shared_key),
              "tenant_id": "tenant-beta"}
    b = client.post("/v1/certifications", json=body_b, headers={"X-Tenant-ID": "tenant-beta"})
    assert b.status_code == 201  # NOT a replay of A -> a fresh create
    run_b = b.json()["run_id"]

    assert run_a != run_b  # no collision, no hijack
    # tenant B cannot read tenant A's run (404-no-leak), and vice-versa
    assert client.get(f"/v1/certifications/{run_a}", headers={"X-Tenant-ID": "tenant-beta"}).status_code == 404
    assert client.get(f"/v1/certifications/{run_b}", headers={"X-Tenant-ID": TENANT}).status_code == 404
    # each tenant sees exactly its own single run
    assert [r["run_id"] for r in store.list_runs(TENANT)] == [run_a]
    assert [r["run_id"] for r in store.list_runs("tenant-beta")] == [run_b]


def test_idempotency_key_reuse_with_different_target_conflicts(store, manifest):
    client = _client(store, manifest)
    key = "key-cccc3333"
    first = client.post(
        "/v1/certifications",
        json=_submit_body(manifest, target_digest=_digest("artifact-C1"), key=key),
        headers={"X-Tenant-ID": TENANT},
    )
    conflict = client.post(
        "/v1/certifications",
        json=_submit_body(manifest, target_digest=_digest("artifact-C2"), key=key),
        headers={"X-Tenant-ID": TENANT},
    )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "idempotency_conflict"


def test_status_returns_durable_record_across_store_reopen(store, manifest):
    client = _client(store, manifest)
    body = _submit_body(manifest, target_digest=_digest("artifact-D"), key="key-dddd4444")
    created = client.post("/v1/certifications", json=body, headers={"X-Tenant-ID": TENANT})
    assert created.status_code == 201
    run_id = created.json()["run_id"]

    # Simulate a fresh process: reopen the store from the same paths, new app instance.
    reopened = EvidenceStore(store.db_path, store.evidence_root)
    fresh_client = _client(reopened, manifest)
    status = fresh_client.get(
        f"/v1/certifications/{run_id}", headers={"X-Tenant-ID": TENANT}
    )

    assert status.status_code == 200
    assert status.json()["run_id"] == run_id
    assert status.json()["state"] == "QUEUED"


def test_submit_rejects_tenant_mismatch_and_unknown_policy(store, manifest):
    client = _client(store, manifest)
    # header tenant disagrees with body tenant -> fail closed
    mismatch = client.post(
        "/v1/certifications",
        json=_submit_body(manifest, target_digest=_digest("artifact-E"), key="key-eeee5555"),
        headers={"X-Tenant-ID": "tenant-other"},
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"] == "tenant_mismatch"

    bad_policy = _submit_body(manifest, target_digest=_digest("artifact-F"), key="key-ffff6666")
    bad_policy["policy_version"] = "policy-does-not-exist"
    unknown = client.post(
        "/v1/certifications", json=bad_policy, headers={"X-Tenant-ID": TENANT}
    )
    assert unknown.status_code == 422
    assert unknown.json()["detail"] == "policy_unknown"
