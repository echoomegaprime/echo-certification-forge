from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from echo_certification_forge.anchor import (
    AnchorStatement,
    IndependentFileAnchorProvider,
    privacy_preserving_tenant_ref,
)
from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.custody import (
    CustodyChunk,
    CustodyStore,
    EvidenceManifest,
    EvidenceVisibility,
)
from echo_certification_forge.p3_service import (
    AnchorServiceContext,
    CustodyServiceContext,
    create_anchor_app,
    create_custody_app,
)
from echo_certification_forge.runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerStore,
    TrustedTransportRegistry,
    create_transport_request,
)

NOW = datetime.now(UTC)


def _custody_context(tmp_path: Path):
    authority = ControlPlaneTransportAuthority.generate()
    registry = TrustedTransportRegistry.empty()
    registry.add_pem(authority.public_key_pem)
    runner = RunnerEphemeralIdentity.generate()
    credential = authority.issue(
        credential_id="credential.service",
        run_id="run.service",
        tenant_id="tenant.service",
        runner_id="runner.service",
        runner_public_key_pem=runner.public_key_pem,
        scopes=tuple(command.value for command in RunnerCommand),
        issued_at=NOW,
        ttl=timedelta(minutes=10),
    )
    runner_store = RunnerStore(tmp_path / "runner.sqlite3")
    runner_store.create_lease(credential, registry, now=NOW, lease_ttl=timedelta(minutes=5))
    custody = CustodyStore(
        tmp_path / "custody.sqlite3",
        tmp_path / "evidence",
        runner_store,
        registry,
    )
    custody.register_run(
        run_id="run.service",
        tenant_id="tenant.service",
        target_identity_digest="1" * 64,
        environment_identity_digest="2" * 64,
        policy_version="policy.v1",
        policy_digest="3" * 64,
        mandatory_rules_digest="4" * 64,
    )
    return custody, credential


def _request(credential, request_id: str, sequence: int, body: dict):
    return create_transport_request(
        request_id=request_id,
        credential=credential,
        nonce=f"nonce-{request_id}-0000000000000000",
        command=RunnerCommand.EVIDENCE_CHUNK,
        sequence=sequence,
        issued_at=NOW + timedelta(seconds=sequence),
        body=body,
    )


def test_custody_http_surface_real_contract(tmp_path: Path):
    custody, credential = _custody_context(tmp_path)
    client = TestClient(create_custody_app(CustodyServiceContext(custody)))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["private_verdict_signing_key_loaded"] is False

    content = b"service-evidence"
    manifest = EvidenceManifest(
        run_id="run.service",
        tenant_id="tenant.service",
        artifact_id="artifact.service",
        declared_size_bytes=len(content),
        declared_sha256=sha256_bytes(content),
        media_type="application/octet-stream",
        purpose="HTTP custody contract",
        visibility=EvidenceVisibility.RESTRICTED,
        total_chunks=1,
        retention_until=NOW + timedelta(days=30),
    )
    begin = _request(
        credential,
        "begin.service",
        1,
        {"operation": "begin_upload", "artifact_id": manifest.artifact_id, "manifest_sha256": manifest.identity_digest},
    )
    response = client.post(
        "/v1/uploads/begin",
        json={"request": begin.model_dump(mode="json"), "manifest": manifest.model_dump(mode="json")},
    )
    assert response.status_code == 200

    chunk = CustodyChunk(
        artifact_id=manifest.artifact_id,
        chunk_index=0,
        total_chunks=1,
        chunk_sha256=sha256_bytes(content),
        payload_b64=base64.b64encode(content).decode("ascii"),
    )
    append = _request(
        credential,
        "chunk.service",
        2,
        {"operation": "append_chunk", "artifact_id": chunk.artifact_id, "chunk_index": 0, "chunk_sha256": chunk.chunk_sha256},
    )
    assert client.post(
        "/v1/uploads/chunks",
        json={"request": append.model_dump(mode="json"), "chunk": chunk.model_dump(mode="json")},
    ).status_code == 200

    final = _request(
        credential,
        "final.service",
        3,
        {"operation": "finalize_upload", "artifact_id": manifest.artifact_id},
    )
    assert client.post(
        "/v1/uploads/finalize",
        json={"request": final.model_dump(mode="json"), "artifact_id": manifest.artifact_id},
    ).status_code == 200
    assert client.get(f"/v1/runs/run.service/verify", headers={"X-Tenant-ID": "tenant.service"}).json()["valid"] is True
    assert client.get(f"/v1/runs/run.service/verify", headers={"X-Tenant-ID": "tenant.other"}).status_code == 404
    assert client.get(f"/v1/evidence/run.service/{manifest.artifact_id}", headers={"X-Tenant-ID": "tenant.service"}).status_code == 403
    assert client.get(
        f"/v1/evidence/run.service/{manifest.artifact_id}",
        headers={"X-Tenant-ID": "tenant.service", "X-Restricted-Evidence-Authorized": "true"},
    ).status_code == 200


def test_anchor_http_surface_and_outage(tmp_path: Path):
    provider = IndependentFileAnchorProvider.generate(tmp_path / "anchor", "anchor.service")
    client = TestClient(create_anchor_app(AnchorServiceContext(provider)))
    assert client.get("/healthz").json()["status"] == "ok"
    statement = AnchorStatement(
        run_id="run.service",
        tenant_ref=privacy_preserving_tenant_ref("tenant.service", "namespace.service"),
        artifact_id="run.evidence.set",
        evidence_merkle_root="5" * 64,
        policy_version="policy.v1",
        anchored_at=NOW,
        anchor_provider_id=provider.provider_id,
    )
    response = client.post(
        "/v1/anchors",
        json={"statement": statement.model_dump(mode="json"), "idempotency_key": "anchor.service.1"},
    )
    assert response.status_code == 200
    receipt_id = response.json()["receipt_id"]
    assert client.get(f"/v1/anchors/{receipt_id}/verify").json() == {
        "valid": True,
        "reason": "verified",
        "receipt_id": receipt_id,
    }
    assert client.get(f"/v1/anchors/{receipt_id}/bundle").status_code == 200
    provider.available = False
    assert client.post(
        "/v1/anchors",
        json={"statement": statement.model_dump(mode="json"), "idempotency_key": "anchor.service.2"},
    ).status_code == 503
