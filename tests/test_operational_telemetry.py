from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.adapter_execution import sign_adapter_bundle
from echo_certification_forge.adapters import (
    AdapterExecutionRecord,
    AdapterIdentity,
    AdapterMaturity,
    AdapterQualityReport,
)
from echo_certification_forge.canonical import sha256_bytes, sha256_json, utc_now
from echo_certification_forge.operational_telemetry import (
    OperationalTelemetryError,
    OperationalTelemetryRegistry,
    SignedOperationalReport,
)
from echo_certification_forge.platform import CertificationPlatform
from echo_certification_forge.runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    TrustedTransportRegistry,
    create_transport_request,
)
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry


def _heartbeat_report(*, now=None, sequence: int = 1, response_id: str = "heartbeat-response-1"):
    issued_at = now or utc_now()
    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
    credential = authority.issue(
        credential_id="heartbeat-credential-1",
        run_id="cert-heartbeat-1",
        tenant_id="tenant-alpha",
        runner_id="runner-anvil-1",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=issued_at,
        ttl=timedelta(minutes=10),
    )
    request = create_transport_request(
        request_id=f"heartbeat-request-{sequence}",
        credential=credential,
        nonce=f"heartbeat-nonce-{sequence:032d}",
        command=RunnerCommand.HEARTBEAT,
        sequence=sequence,
        issued_at=issued_at,
        body={"action": "heartbeat"},
    )
    response = runner.sign_response(
        response_id=response_id,
        request=request,
        status="ACCEPTED",
        body={
            "kind": "worker_heartbeat",
            "health": "HEALTHY",
            "capacity_total": 4,
            "capacity_available": 3,
            "active_run_count": 1,
            "worker_image_sha256": sha256_bytes(b"runner-image"),
        },
        issued_at=issued_at,
    )
    trusted = TrustedTransportRegistry.empty()
    trusted.add_pem(authority.public_key_pem)
    return SignedOperationalReport(credential=credential, response=response), trusted


def _adapter_record() -> AdapterExecutionRecord:
    identity = AdapterIdentity(
        adapter_id="gs343",
        version="v2",
        artifact_sha256=sha256_bytes(b"adapter"),
        configuration_sha256=sha256_bytes(b"configuration"),
        runtime_sha256=sha256_bytes(b"runtime"),
        maturity=AdapterMaturity.STABLE,
        provenance="signed-anvil-r5",
    )
    quality = AdapterQualityReport(
        adapter_id="gs343",
        passed_cases=25,
        total_cases=25,
        critical_failures=(),
        suite_sha256=sha256_bytes(b"suite"),
        evidence_ids=("gs343-r5",),
    )
    payload = {
        "identity": identity.to_dict(),
        "observed_identity_digest": identity.identity_digest,
        "quality": {
            "adapter_id": quality.adapter_id,
            "passed_cases": quality.passed_cases,
            "total_cases": quality.total_cases,
            "critical_failures": list(quality.critical_failures),
            "suite_sha256": quality.suite_sha256,
            "evidence_ids": list(quality.evidence_ids),
        },
        "execution_node": "ANVIL",
    }
    return AdapterExecutionRecord(
        identity=identity,
        observed_identity_digest=identity.identity_digest,
        quality=quality,
        execution_node="ANVIL",
        result_sha256=sha256_json(payload),
    )


def test_authenticated_heartbeat_projects_fresh_truth_and_stales(tmp_path: Path) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    report, trusted = _heartbeat_report(now=current)

    accepted = registry.ingest_worker_heartbeat(report, trusted, now=current)
    replay = registry.ingest_worker_heartbeat(report, trusted, now=current)
    fresh = registry.snapshot("tenant-alpha", now=current + timedelta(minutes=1))
    stale = registry.snapshot("tenant-alpha", now=current + timedelta(minutes=6))

    assert accepted == {"accepted": True, "idempotent": False, "runner_id": "runner-anvil-1"}
    assert replay["idempotent"] is True
    assert fresh["runner"]["health"] == "HEALTHY"
    assert fresh["runner"]["source"] == "authenticated_ed25519_worker_reports"
    assert fresh["runner"]["capacity_available"] == 3
    assert stale["runner"]["health"] == "STALE"
    assert stale["runner"]["fresh"] == 0


def test_heartbeat_rejects_untrusted_and_tampered_reports(tmp_path: Path) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    first, trusted = _heartbeat_report(now=current)
    untrusted = TrustedTransportRegistry.empty()
    with pytest.raises(OperationalTelemetryError, match="untrusted_operational_credential"):
        registry.ingest_worker_heartbeat(first, untrusted, now=current)

    tampered = first.model_copy(
        update={
            "response": first.response.model_copy(
                update={"signature_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
            )
        }
    )
    with pytest.raises(OperationalTelemetryError, match="invalid_operational_runner_signature"):
        registry.ingest_worker_heartbeat(tampered, trusted, now=current)

def test_signed_adapter_bundle_populates_tenant_scoped_registry(tmp_path: Path) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    signed = sign_adapter_bundle(
        (_adapter_record(),), run_id="cert-adapter-1", tenant_id="tenant-alpha"
    )
    trusted = TrustedTransportRegistry.empty()
    trusted.add_pem(signed.control_plane_public_key_pem)
    accepted = registry.ingest_adapter_inventory(
        SignedOperationalReport(credential=signed.credential, response=signed.response),
        trusted,
        now=signed.response.issued_at,
    )
    snapshot = registry.snapshot("tenant-alpha", now=current)

    assert accepted["adapter_count"] == 1
    assert snapshot["adapters"]["inventory_status"] == "AVAILABLE"
    assert snapshot["adapters"]["maturity_status"] == "STABLE"
    assert snapshot["adapters"]["entries"][0]["adapter_id"] == "gs343"
    assert snapshot["adapters"]["entries"][0]["identity_digest"] == _adapter_record().identity.identity_digest


def test_empty_registry_is_explicitly_non_green(tmp_path: Path) -> None:
    snapshot = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3").snapshot(
        "tenant-empty"
    )
    assert snapshot["runner"]["health"] == "NO_AUTHENTICATED_HEARTBEATS"
    assert snapshot["adapters"]["inventory_status"] == "EMPTY"
    assert snapshot["adapters"]["maturity_status"] == "UNAVAILABLE"


def test_quarantine_excludes_runner_and_adapter_without_deleting_evidence(tmp_path: Path) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    heartbeat, heartbeat_trust = _heartbeat_report(now=current)
    registry.ingest_worker_heartbeat(heartbeat, heartbeat_trust, now=current)
    signed_adapter = sign_adapter_bundle(
        (_adapter_record(),), run_id="cert-adapter-quarantine", tenant_id="tenant-alpha"
    )
    adapter_trust = TrustedTransportRegistry.empty()
    adapter_trust.add_pem(signed_adapter.control_plane_public_key_pem)
    registry.ingest_adapter_inventory(
        SignedOperationalReport(
            credential=signed_adapter.credential,
            response=signed_adapter.response,
        ),
        adapter_trust,
        now=signed_adapter.response.issued_at,
    )

    runner = registry.quarantine(
        "tenant-alpha",
        subject_type="runner",
        subject_id="runner-anvil-1",
        reason="investigating an image-integrity mismatch",
        actor="api_key:owner",
        now=current,
    )
    replay = registry.quarantine(
        "tenant-alpha",
        subject_type="runner",
        subject_id="runner-anvil-1",
        reason="a conflicting replay must not replace the original reason",
        actor="api_key:other",
        now=current + timedelta(seconds=1),
    )
    adapter = registry.quarantine(
        "tenant-alpha",
        subject_type="adapter",
        subject_id="gs343",
        reason="quality regression requires isolation",
        actor="api_key:owner",
        now=current,
    )
    isolated = registry.snapshot("tenant-alpha", now=current + timedelta(minutes=1))

    assert runner["idempotent"] is False
    assert replay["idempotent"] is True
    assert replay["reason"] == "investigating an image-integrity mismatch"
    assert adapter["quarantined"] is True
    assert isolated["runner"]["health"] == "QUARANTINED"
    assert isolated["runner"]["capacity_total"] == 0
    assert isolated["runner"]["entries"][0]["quarantined"] is True
    assert isolated["adapters"]["inventory_status"] == "QUARANTINED"
    assert isolated["adapters"]["total"] == 1
    assert isolated["adapters"]["available"] == 0
    assert isolated["adapters"]["entries"][0]["quarantined"] is True

    registry.release_quarantine(
        "tenant-alpha",
        subject_type="runner",
        subject_id="runner-anvil-1",
        reason="runner image was independently reverified",
        actor="api_key:owner",
        now=current + timedelta(minutes=2),
    )
    registry.release_quarantine(
        "tenant-alpha",
        subject_type="adapter",
        subject_id="gs343",
        reason="adapter quality suite passed again",
        actor="api_key:owner",
        now=current + timedelta(minutes=2),
    )
    restored = registry.snapshot("tenant-alpha", now=current + timedelta(minutes=3))
    assert restored["runner"]["health"] == "HEALTHY"
    assert restored["adapters"]["inventory_status"] == "AVAILABLE"
    assert restored["adapters"]["maturity_status"] == "STABLE"


def test_quarantine_rejects_unknown_or_inactive_subject(tmp_path: Path) -> None:
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    with pytest.raises(OperationalTelemetryError, match="operational_subject_not_found"):
        registry.quarantine(
            "tenant-alpha",
            subject_type="runner",
            subject_id="missing-runner",
            reason="unknown runners cannot create phantom quarantine state",
            actor="api_key:owner",
        )
    with pytest.raises(OperationalTelemetryError, match="active_quarantine_not_found"):
        registry.release_quarantine(
            "tenant-alpha",
            subject_type="adapter",
            subject_id="missing-adapter",
            reason="there is no active quarantine to release",
            actor="api_key:owner",
        )


def test_service_ingests_signed_reports_and_projects_tenant_truth(store, manifest) -> None:
    platform = CertificationPlatform(store.db_path)
    account = platform.bootstrap(
        organization_id="org-operations",
        tenant_id="tenant-alpha",
        organization_name="Operations",
        project_id="project-operations",
        project_name="Operations",
        target_reference="https://example.test/operations",
        required_policy=manifest.manifest_id,
        owner_user_id="owner-operations",
        owner_email="operations@example.test",
        plan_id="professional",
        billing_status="active",
    )
    heartbeat, trusted = _heartbeat_report()
    signed_adapter = sign_adapter_bundle(
        (_adapter_record(),), run_id="cert-adapter-service", tenant_id="tenant-alpha"
    )
    trusted.add_pem(signed_adapter.control_plane_public_key_pem)
    client = TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                platform=platform,
                transport_registry=trusted,
            )
        )
    )

    heartbeat_response = client.post(
        "/v1/internal/worker-heartbeats",
        json=heartbeat.model_dump(mode="json"),
    )
    adapter_response = client.post(
        "/v1/internal/adapter-inventory",
        json=SignedOperationalReport(
            credential=signed_adapter.credential,
            response=signed_adapter.response,
        ).model_dump(mode="json"),
    )
    telemetry = client.get(
        "/v1/subscriber/telemetry",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )

    assert heartbeat_response.status_code == 200
    assert adapter_response.status_code == 200
    assert telemetry.status_code == 200
    body = telemetry.json()
    assert body["capacity"]["runner_health"] == "HEALTHY"
    assert body["capacity"]["authenticated_runner_source"]["fresh"] == 1
    assert body["adapters"]["inventory_status"] == "AVAILABLE"
    assert body["adapters"]["maturity_status"] == "STABLE"
    assert body["adapters"]["entries"][0]["adapter_id"] == "gs343"

    quarantined = client.post(
        "/v1/subscriber/operational-quarantines",
        headers={"X-CertForge-API-Key": account["api_key"]},
        json={
            "subject_type": "runner",
            "subject_id": "runner-anvil-1",
            "reason": "operator isolated the runner for verification",
        },
    )
    isolated = client.get(
        "/v1/subscriber/telemetry",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )
    released = client.post(
        "/v1/subscriber/operational-quarantines/runner/runner-anvil-1/release",
        headers={"X-CertForge-API-Key": account["api_key"]},
        json={"reason": "independent verification completed successfully"},
    )
    audit = client.get(
        "/v1/subscriber/audit?limit=10",
        headers={"X-CertForge-API-Key": account["api_key"]},
    )

    assert quarantined.status_code == 200
    assert isolated.json()["capacity"]["runner_health"] == "QUARANTINED"
    assert released.status_code == 200
    assert released.json()["quarantined"] is False
    assert {entry["action"] for entry in audit.json()} >= {
        "operations.quarantine",
        "operations.quarantine.release",
    }
