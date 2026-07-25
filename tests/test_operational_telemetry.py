from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.adapter_execution import (
    AdapterBundleTrustBinding,
    sign_adapter_bundle,
)
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
from echo_certification_forge.runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    TrustedTransportRegistry,
    create_transport_request,
)
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    OrganizationStatus,
    SubscriberGovernance,
    SubscriberPolicy,
)


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


def _signed_adapter_bundle(*, run_id: str, tenant_id: str):
    runner = RunnerEphemeralIdentity.generate()
    binding = AdapterBundleTrustBinding(
        registry_id="test-operational-registry",
        runner_key_id=runner.key_id,
        policy_id="test-operational-policy",
        policy_sha256=sha256_bytes(b"policy"),
        qualification_trust_pins_sha256=sha256_bytes(b"qualification-pins"),
        r5_trust_pins_sha256=sha256_bytes(b"r5-pins"),
        external_trust_pins_sha256=sha256_bytes(b"external-pins"),
    )
    return sign_adapter_bundle(
        (_adapter_record(),),
        run_id=run_id,
        tenant_id=tenant_id,
        trust_binding=binding,
        runner_identity=runner,
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
    signed = _signed_adapter_bundle(
        run_id="cert-adapter-1", tenant_id="tenant-alpha"
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


def test_service_ingests_signed_reports_and_projects_tenant_truth(store, manifest) -> None:
    subscribers = SubscriberGovernance(
        store.db_path,
        SubscriberPolicy.load(
            Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
        ),
        b"operational-telemetry-test-pepper-32-bytes-minimum",
    )
    account = subscribers.provision_organization(
        organization_id="tenant-alpha",
        owner_user_id="owner-operations",
        slug="operations",
        display_name="Operations",
        owner_email="operations@example.test",
        owner_display_name="Operations Owner",
        plan_code="professional",
        status=OrganizationStatus.ACTIVE,
    )
    heartbeat, trusted = _heartbeat_report()
    signed_adapter = _signed_adapter_bundle(
        run_id="cert-adapter-service", tenant_id="tenant-alpha"
    )
    trusted.add_pem(signed_adapter.control_plane_public_key_pem)
    client = TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                subscribers=subscribers,
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
        headers={
            "X-Tenant-ID": account.organization_id,
            "Authorization": f"Bearer {account.bootstrap_api_key}",
        },
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
