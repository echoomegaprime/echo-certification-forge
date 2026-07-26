from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import sha256_bytes, sha256_json, utc_now
from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.intake import SubmitTarget
from echo_certification_forge.models import declared_target_identity_digest
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
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    OrganizationStatus,
    Permission,
    SubscriberGovernance,
    SubscriberPolicy,
)
from echo_certification_forge.windows_package import (
    P8C_INSTALLER_NAME,
    P8C_INSTALLER_SHA256,
    P8C_SOURCE_COMMIT,
    WindowsPackageResultBody,
    sign_package_result,
    windows_package_environment,
)
from echo_certification_forge.windows_package_finalize import (
    finalize_windows_package_result,
)


def _body(worker_image_sha256: str) -> WindowsPackageResultBody:
    environment = windows_package_environment(worker_image_sha256)
    return WindowsPackageResultBody(
        kind="windows_package_result",
        target_type="package",
        artifact_sha256=P8C_INSTALLER_SHA256,
        source_commit=P8C_SOURCE_COMMIT,
        reference=f"C:\\release\\{P8C_INSTALLER_NAME}",
        package_size=185_087_693,
        worker_image_sha256=worker_image_sha256,
        environment=environment.to_dict(),
        checks={
            "artifact_digest": True,
            "source_commit": True,
            "regular_file": True,
            "no_reparse_point": True,
            "authenticode_valid": False,
            "authenticode_timestamped": False,
        },
        authenticode_status="NotSigned",
        ready_candidate=False,
    )


def _enrolled_report(registry: OperationalTelemetryRegistry, *, now=None):
    current = now or utc_now()
    authority = ControlPlaneTransportAuthority.generate()
    private_key = Ed25519PrivateKey.generate()
    runner = RunnerEphemeralIdentity(private_key)
    trusted = TrustedTransportRegistry.empty()
    trusted.add_pem(authority.public_key_pem)
    worker_image = sha256_bytes(b"p8c-windows-worker-v1")
    heartbeat_credential = authority.issue(
        credential_id="p8c-heartbeat-credential",
        run_id="cert-p8c-heartbeat",
        tenant_id="echo-sovereign",
        runner_id="wrk-p8c-windows",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=current,
        ttl=timedelta(minutes=10),
    )
    heartbeat_request = create_transport_request(
        request_id="p8c-heartbeat-request",
        credential=heartbeat_credential,
        nonce="p8c-heartbeat-nonce-0000000000000000",
        command=RunnerCommand.HEARTBEAT,
        sequence=1,
        issued_at=current,
        body={"action": "heartbeat"},
    )
    heartbeat = runner.sign_response(
        response_id="p8c-heartbeat-response",
        request=heartbeat_request,
        status="ACCEPTED",
        body={
            "kind": "worker_heartbeat",
            "health": "HEALTHY",
            "capacity_total": 1,
            "capacity_available": 1,
            "active_run_count": 0,
            "worker_image_sha256": worker_image,
        },
        issued_at=current,
    )
    registry.ingest_worker_heartbeat(
        SignedOperationalReport(credential=heartbeat_credential, response=heartbeat),
        trusted,
        now=current,
    )
    registry.enroll_runner(
        "echo-sovereign",
        runner_id="wrk-p8c-windows",
        actor="api_key:owner",
        now=current,
    )
    result_credential = authority.issue(
        credential_id="p8c-result-credential",
        run_id="cert-p8c-exact",
        tenant_id="echo-sovereign",
        runner_id="wrk-p8c-windows",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=current,
        ttl=timedelta(minutes=10),
    )
    body = _body(worker_image)
    response = sign_package_result(
        body, result_credential, private_key, issued_at=current
    )
    with sqlite3.connect(registry.database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS subscriber_run_reservations(
                run_id TEXT, organization_id TEXT, state TEXT, target_type TEXT,
                target_reference TEXT, target_identity_digest TEXT
            );
            CREATE TABLE IF NOT EXISTS subscriber_run_dispatches(
                run_id TEXT, organization_id TEXT, target_json TEXT
            );
            CREATE TABLE IF NOT EXISTS runs(
                run_id TEXT, tenant_id TEXT, state TEXT, environment_identity_digest TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO subscriber_run_reservations VALUES (?, ?, 'BOUND', 'package', ?, ?)",
            (
                result_credential.claims.run_id,
                result_credential.claims.tenant_id,
                body.reference,
                declared_target_identity_digest(
                    result_credential.claims.tenant_id,
                    "package",
                    body.artifact_sha256,
                    body.source_commit,
                    body.reference,
                ),
            ),
        )
        connection.execute(
            "INSERT INTO subscriber_run_dispatches VALUES (?, ?, ?)",
            (
                result_credential.claims.run_id,
                result_credential.claims.tenant_id,
                json.dumps(
                    {
                        "type": "package",
                        "path": body.reference,
                        "artifact_sha256": body.artifact_sha256,
                        "source_commit": body.source_commit,
                    }
                ),
            ),
        )
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, 'QUEUED', ?)",
            (
                result_credential.claims.run_id,
                result_credential.claims.tenant_id,
                body.environment_identity_digest,
            ),
        )
    return (
        SignedOperationalReport(credential=result_credential, response=response),
        trusted,
        body,
        runner,
        result_credential,
    )


def test_package_intake_dispatches_only_with_both_immutable_pins() -> None:
    target = SubmitTarget(
        target_type="package",
        identity_digest="a" * 64,
        reference=f"C:\\release\\{P8C_INSTALLER_NAME}",
        artifact_sha256=P8C_INSTALLER_SHA256,
        source_commit=P8C_SOURCE_COMMIT,
    )
    assert target.worker_spec() == {
        "type": "package",
        "path": f"C:\\release\\{P8C_INSTALLER_NAME}",
        "artifact_sha256": P8C_INSTALLER_SHA256,
        "source_commit": P8C_SOURCE_COMMIT,
    }
    with pytest.raises(ValueError, match="requires artifact_sha256 and source_commit"):
        target.model_copy(update={"source_commit": None}).worker_spec()


def test_enrolled_signed_windows_result_is_accepted_and_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    report, trusted, body, _runner, _credential = _enrolled_report(
        registry, now=current
    )
    accepted = registry.ingest_windows_package_result(report, trusted, now=current)
    replay = registry.ingest_windows_package_result(report, trusted, now=current)
    stored = registry.windows_package_result("cert-p8c-exact", "echo-sovereign")
    assert accepted["accepted"] is True
    assert accepted["ready_candidate"] is False
    assert replay["idempotent"] is True
    assert stored is not None
    assert stored["body"]["artifact_sha256"] == P8C_INSTALLER_SHA256
    assert stored["body"]["authenticode_status"] == "NotSigned"
    assert body.environment_identity_digest == windows_package_environment(
        body.worker_image_sha256
    ).identity_digest


def test_windows_result_rejects_tamper_expiry_wrong_digest_and_ready_override(
    tmp_path: Path,
) -> None:
    current = utc_now()
    registry = OperationalTelemetryRegistry(tmp_path / "telemetry.sqlite3")
    report, trusted, body, runner, credential = _enrolled_report(
        registry, now=current
    )
    tampered = report.model_copy(
        update={
            "response": report.response.model_copy(
                update={"signature_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
            )
        }
    )
    with pytest.raises(OperationalTelemetryError, match="invalid_operational_runner_signature"):
        registry.ingest_windows_package_result(tampered, trusted, now=current)
    with pytest.raises(OperationalTelemetryError, match="expired_or_future"):
        registry.ingest_windows_package_result(
            report, trusted, now=current + timedelta(minutes=11)
        )

    for mutation, error in (
        ({"artifact_sha256": "0" * 64}, "windows_package_result_binding_mismatch"),
        ({"ready_candidate": True}, "windows_package_result_body_invalid"),
        ({"llm_verdict": "PRODUCTION_READY"}, "windows_package_result_body_invalid"),
    ):
        malicious_body = {**body.model_dump(mode="json"), **mutation}
        request = create_transport_request(
            request_id=f"malicious-{sha256_json(mutation)[:16]}",
            credential=credential,
            nonce=f"malicious-nonce-{sha256_json(mutation)[:32]}",
            command=RunnerCommand.TRANSITION,
            sequence=2,
            issued_at=current,
            body={"action": "observe"},
        )
        response = runner.sign_response(
            response_id=f"malicious-response-{sha256_json(mutation)[:16]}",
            request=request,
            status="COMPLETED",
            body=malicious_body,
            issued_at=current,
        )
        with pytest.raises(OperationalTelemetryError, match=error):
            registry.ingest_windows_package_result(
                SignedOperationalReport(credential=credential, response=response),
                trusted,
                now=current,
            )


def test_exact_package_result_produces_signed_not_ready_and_gate_remains_closed(
    tmp_path: Path, manifest
) -> None:
    db_path = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db_path, tmp_path / "evidence")
    policy = SubscriberPolicy.load(
        Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
    )
    governance = SubscriberGovernance(
        db_path, policy, b"windows-package-test-pepper-32-bytes-minimum"
    )
    registry = OperationalTelemetryRegistry(db_path)
    api_keys = TrustedPublicKeyRegistry.empty()
    client = TestClient(
        create_app(ServiceContext(store, manifest, api_keys, governance))
    )
    organization = governance.provision_organization(
        slug="p8c-windows",
        display_name="P8C Windows",
        owner_email="owner@p8c-windows.example",
        owner_display_name="P8C Owner",
        plan_code="sovereign",
        status=OrganizationStatus.ACTIVE,
    )
    headers = {
        "X-Tenant-ID": organization.organization_id,
        "Authorization": f"Bearer {organization.bootstrap_api_key}",
    }
    project = client.post(
        "/v1/subscriber/projects",
        headers=headers,
        json={
            "slug": "echo-desktop",
            "name": "Echo Desktop",
            "target_reference": f"C:\\release\\{P8C_INSTALLER_NAME}",
        },
    )
    assert project.status_code == 201

    current = utc_now()
    authority = ControlPlaneTransportAuthority.generate()
    private_key = Ed25519PrivateKey.generate()
    runner = RunnerEphemeralIdentity(private_key)
    trusted_transport = TrustedTransportRegistry.empty()
    trusted_transport.add_pem(authority.public_key_pem)
    worker_image = sha256_bytes(b"p8c-windows-worker-v1")
    principal = governance.authenticate(
        organization.bootstrap_api_key,
        tenant_hint=organization.organization_id,
        permission=Permission.PRIVATE_WORKER_MANAGE,
        action="windows-package-test.register-worker",
    )
    private_worker = governance.register_private_worker(
        principal,
        display_name="P8C Windows Runner",
        attestation_sha256=worker_image,
    )
    runner_id = private_worker["worker_id"]
    heartbeat_credential = authority.issue(
        credential_id="p8c-integration-heartbeat",
        run_id="cert-p8c-integration-heartbeat",
        tenant_id=organization.organization_id,
        runner_id=runner_id,
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=current,
        ttl=timedelta(minutes=10),
    )
    heartbeat_request = create_transport_request(
        request_id="p8c-integration-heartbeat-request",
        credential=heartbeat_credential,
        nonce="p8c-integration-heartbeat-nonce-000000",
        command=RunnerCommand.HEARTBEAT,
        sequence=1,
        issued_at=current,
        body={"action": "heartbeat"},
    )
    heartbeat = runner.sign_response(
        response_id="p8c-integration-heartbeat-response",
        request=heartbeat_request,
        status="ACCEPTED",
        body={
            "kind": "worker_heartbeat",
            "health": "HEALTHY",
            "capacity_total": 1,
            "capacity_available": 1,
            "active_run_count": 0,
            "worker_image_sha256": worker_image,
        },
        issued_at=current,
    )
    registry.ingest_worker_heartbeat(
        SignedOperationalReport(credential=heartbeat_credential, response=heartbeat),
        trusted_transport,
        now=current,
    )
    registry.enroll_runner(
        organization.organization_id,
        runner_id=runner_id,
        actor="api_key:owner",
        now=current,
    )

    reference = f"C:\\release\\{P8C_INSTALLER_NAME}"
    environment = windows_package_environment(worker_image)
    declared_digest = declared_target_identity_digest(
        organization.organization_id,
        "package",
        P8C_INSTALLER_SHA256,
        P8C_SOURCE_COMMIT,
        reference,
    )
    submitted = client.post(
        "/v1/certifications",
        headers=headers,
        json={
            "tenant_id": organization.organization_id,
            "project_id": project.json()["project_id"],
            "target": {
                "target_type": "package",
                "identity_digest": declared_digest,
                "reference": reference,
                "artifact_sha256": P8C_INSTALLER_SHA256,
                "source_commit": P8C_SOURCE_COMMIT,
            },
            "environment": {
                "identity_digest": environment.identity_digest,
                "runner_image_digest": "sha256:" + worker_image,
            },
            "policy_version": manifest.manifest_id,
            "idempotency_key": "p8c-windows-exact-0001",
        },
    )
    assert submitted.status_code == 201
    run_id = submitted.json()["run_id"]
    result_credential = authority.issue(
        credential_id="p8c-integration-result",
        run_id=run_id,
        tenant_id=organization.organization_id,
        runner_id=runner_id,
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=current,
        ttl=timedelta(minutes=10),
    )
    body = _body(worker_image).model_copy(
        update={"reference": reference}
    )
    response = sign_package_result(body, result_credential, private_key, issued_at=current)
    registry.ingest_windows_package_result(
        SignedOperationalReport(credential=result_credential, response=response),
        trusted_transport,
        now=current,
    )
    signer = Ed25519VerdictSigner.generate()
    finalized = finalize_windows_package_result(
        run_id=run_id,
        tenant_id=organization.organization_id,
        store=store,
        registry=registry,
        governance=governance,
        manifest=manifest,
        signer=signer,
    )
    assert finalized["signed"] is True
    assert finalized["release_verdict"] == "NOT_READY"
    trusted_verdicts = TrustedPublicKeyRegistry.empty()
    trusted_verdicts.add_pem(signer.public_key_pem)
    final_run = store.get_run(run_id, organization.organization_id)
    decision = DeployGate(store, trusted_verdicts).evaluate(
        organization.organization_id,
        run_id,
        final_run["target_identity_digest"],
        final_run["environment_identity_digest"],
        manifest.digest,
    )
    assert decision.allowed is False
    assert "verdict_not_production_ready" in decision.reasons
