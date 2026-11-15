"""Canonical identity export boundaries over real local tenant/store state."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import canonical_json, sha256_json
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.identity_export import (
    IdentityExportError,
    export_canonical_identities,
)
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    Permission,
    SubscriberGovernance,
    SubscriberPolicy,
)


@pytest.fixture
def export_stack(tmp_path, manifest, target, environment):
    store = EvidenceStore(tmp_path / "store.sqlite3", tmp_path / "evidence")
    policy = SubscriberPolicy.load(
        Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
    )
    governance = SubscriberGovernance(
        store.db_path, policy, b"synthetic-export-test-pepper-32-bytes-minimum"
    )
    org = governance.provision_organization(
        slug="export-alpha", display_name="Export Alpha",
        owner_email="owner@export-alpha.example", owner_display_name="Owner",
        plan_code="developer",
    )
    target = replace(target, tenant_id=org.organization_id, source_commit="a" * 40,
        canonical_ref="https://github.com/example/project@" + "a" * 40)
    store.register_run("run-export", target, environment, manifest.manifest_id, manifest.digest)
    client = TestClient(create_app(ServiceContext(
        store, manifest, TrustedPublicKeyRegistry.empty(), governance,
    )))
    headers = {"X-Tenant-ID": org.organization_id, "Authorization": f"Bearer {org.bootstrap_api_key}"}
    return store, governance, org, target, environment, client, headers


def test_export_preserves_exact_objects_and_checksums_without_run_changes(export_stack):
    store, governance, org, target, environment, client, headers = export_stack
    before = store.get_run("run-export", org.organization_id)
    first = client.get("/v1/certifications/run-export/identities", headers=headers)
    second = client.get("/v1/certifications/run-export/identities", headers=headers)
    assert first.status_code == second.status_code == 200
    exported = first.json()
    assert exported == second.json()
    assert exported["identities"] == {"target": target.to_dict(), "environment": environment.to_dict()}
    assert exported["identities_sha256"] == sha256_json(exported["identities"])
    assert exported["export_sha256"] == sha256_json({k: v for k, v in exported.items() if k != "export_sha256"})
    assert exported["target_identity_digest"] == target.identity_digest
    assert exported["environment_identity_digest"] == environment.identity_digest
    assert first.headers["cache-control"] == "no-store"
    assert store.get_run("run-export", org.organization_id) == before
    assert store.list_evidence("run-export", org.organization_id) == []
    principal = governance.authenticate(org.bootstrap_api_key, tenant_hint=org.organization_id,
        permission=Permission.AUDIT_READ, action="test.audit")
    events = [item for item in governance.list_audit_events(principal)
              if item["action"] == "certifications.identities.exported"]
    assert len(events) == 2
    assert set(events[0]["details"]) == {"export_sha256", "identities_sha256", "target_identity_digest", "environment_identity_digest"}
    assert target.canonical_ref not in json.dumps(events)
    assert governance.verify_audit(principal)["valid"] is True


def test_export_never_reads_evidence_artifacts(export_stack, monkeypatch):
    store, _, _, _, _, client, headers = export_stack
    def forbidden(*_args, **_kwargs):
        raise AssertionError("identity export must not read evidence bytes")
    monkeypatch.setattr(store, "read_evidence_artifact", forbidden)
    assert client.get("/v1/certifications/run-export/identities", headers=headers).status_code == 200
    assert client.get("/v1/subscriber/certifications/run-export/evidence/denied-artifact", headers=headers).status_code == 403


@pytest.mark.parametrize("headers", [{}, {"X-Tenant-ID": "export-alpha"}])
def test_identity_export_rejects_unauthenticated_headers(export_stack, headers):
    client = export_stack[5]
    response = client.get("/v1/certifications/run-export/identities", headers=headers)
    assert response.status_code == 401
    assert "identities" not in response.json()


def test_identity_export_requires_run_read_permission(export_stack):
    _, governance, org, _, _, client, _ = export_stack
    owner = governance.authenticate(org.bootstrap_api_key, tenant_hint=org.organization_id,
        permission=Permission.API_KEY_MANAGE, action="test.owner")
    token = governance.create_api_key(owner, name="projects-only", scopes={Permission.PROJECT_READ},
        expires_at=datetime.now(UTC) + timedelta(days=1))
    response = client.get("/v1/certifications/run-export/identities", headers={
        "X-Tenant-ID": org.organization_id, "Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert "identities" not in response.json()


def test_cross_tenant_export_is_indistinguishable_from_unknown_run(export_stack):
    _, governance, _, _, _, client, _ = export_stack
    other = governance.provision_organization(slug="export-beta", display_name="Beta",
        owner_email="owner@export-beta.example", owner_display_name="Owner", plan_code="developer")
    headers = {"X-Tenant-ID": other.organization_id, "Authorization": f"Bearer {other.bootstrap_api_key}"}
    foreign = client.get("/v1/certifications/run-export/identities", headers=headers)
    missing = client.get("/v1/certifications/absent-run/identities", headers=headers)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_governance_disabled_cannot_export_by_tenant_header(store, manifest, target, environment):
    store.register_run("run-export", target, environment, manifest.manifest_id, manifest.digest)
    client = TestClient(create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty())))
    response = client.get("/v1/certifications/run-export/identities", headers={"X-Tenant-ID": target.tenant_id})
    assert response.status_code == 503
    assert response.json()["detail"] == "subscriber_governance_disabled"


def test_audit_failure_prevents_export_response(export_stack, monkeypatch):
    _, governance, _, _, _, client, headers = export_stack
    def failed_audit(*_args, **_kwargs):
        raise sqlite3.OperationalError("synthetic audit outage")
    monkeypatch.setattr(governance, "audit_resource_event", failed_audit)
    response = client.get("/v1/certifications/run-export/identities", headers=headers)
    assert response.status_code == 503
    assert "identities" not in response.json()
    assert "synthetic audit outage" not in response.text


def test_key_revoked_after_initial_auth_is_rejected_before_export(export_stack, monkeypatch):
    store, governance, org, _, _, client, headers = export_stack
    owner = governance.authenticate(org.bootstrap_api_key, tenant_hint=org.organization_id,
        permission=Permission.API_KEY_MANAGE, action="test.owner")
    original = store.get_run
    def revoke_after_read(*args, **kwargs):
        row = original(*args, **kwargs)
        governance.revoke_api_key(owner, owner.key_id)
        return row
    monkeypatch.setattr(store, "get_run", revoke_after_read)
    response = client.get("/v1/certifications/run-export/identities", headers=headers)
    assert response.status_code == 401
    assert "identities" not in response.json()
    assert response.json()["detail"] == "api_key_inactive"


@pytest.mark.parametrize("field", ["target_identity_digest", "environment_identity_digest"])
def test_digest_mismatch_fails_without_data_disclosure(export_stack, field):
    store, _, org, _, _, client, headers = export_stack
    with sqlite3.connect(store.db_path) as connection:
        connection.execute(f"UPDATE runs SET {field} = ? WHERE run_id = ?", ("0" * 64, "run-export"))
    response = client.get("/v1/certifications/run-export/identities", headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"] == "identity_digest_mismatch"
    assert "identities" not in response.json()


@pytest.mark.parametrize("change,code", [
    ({"declared_identity_digest": "0" * 64}, "identity_not_reconciled"),
    ({"extra": "synthetic-secret-value"}, "identity_record_invalid"),
    ({"tenant_id": "wrong-tenant"}, "identity_tenant_mismatch"),
    ({"source_commit": "synthetic-secret-value"}, "identity_record_invalid"),
])
def test_invalid_stored_identity_fails_closed(export_stack, change, code):
    store, _, org, _, _, _, _ = export_stack
    row = store.get_run("run-export", org.organization_id)
    data = json.loads(row["target_identity_json"])
    data.update(change)
    row["target_identity_json"] = canonical_json(data)
    with pytest.raises(IdentityExportError, match=code):
        export_canonical_identities(row, org.organization_id)


@pytest.mark.parametrize("reference", [
    "https://user:synthetic-password@example.invalid/repo",
    "https://example.invalid/repo?access_token=synthetic-token",
    "https://example.invalid/repo#synthetic-token",
    "https://example.invalid/repo\nAuthorization: synthetic-token",
    "https://user%253Asynthetic-password%2540example.invalid/repo",
    "https://example.invalid/repo%253Faccess_token%253Dsynthetic-token",
    "https://example.invalid/repo%2523synthetic-token",
])
def test_sensitive_canonical_references_are_not_exported(export_stack, reference):
    store, _, org, _, _, _, _ = export_stack
    row = store.get_run("run-export", org.organization_id)
    data = json.loads(row["target_identity_json"])
    data["canonical_ref"] = reference
    row["target_identity_json"] = canonical_json(data)
    row["target_identity_digest"] = sha256_json(data)
    with pytest.raises(IdentityExportError, match="identity_reference_not_exportable"):
        export_canonical_identities(row, org.organization_id)


def test_duplicate_keys_and_unbounded_identity_records_are_rejected(export_stack):
    store, _, org, _, _, _, _ = export_stack
    row = store.get_run("run-export", org.organization_id)
    for raw in ('{"tenant_id":"first","tenant_id":"second"}', '{"oversized":"' + "x" * 20000 + '"}'):
        with pytest.raises(IdentityExportError, match="identity_record_invalid"):
            export_canonical_identities({**row, "target_identity_json": raw}, org.organization_id)


def test_openapi_declares_protected_complete_export_schema(export_stack):
    client = export_stack[5]
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/v1/certifications/{run_id}/identities"]["get"]
    assert operation["security"] == [{"BearerAuth": ["tenant"]}]
    assert "401" in operation["responses"] and "403" in operation["responses"]
    response = operation["responses"]["200"]["content"]["application/json"]["schema"]
    model = schema["components"]["schemas"][response["$ref"].split("/")[-1]]
    assert model["additionalProperties"] is False
    assert {"identities", "identities_sha256", "export_sha256"} <= set(model["required"])


def test_sdk_command_metadata_does_not_replace_bearer_or_tenant(export_stack):
    client, headers = export_stack[5:]
    response = client.get("/v1/certifications/run-export/identities",
        params={"command": "identities"}, headers=headers)
    assert response.status_code == 200
    denied = client.get("/v1/certifications/run-export/identities",
        params={"command": "identities", "tenant_id": export_stack[2].organization_id})
    assert denied.status_code == 401
