from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import json
import sqlite3
from urllib import request as urllib_request

import pytest
from cryptography.hazmat.primitives import serialization
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
    SignedRunCredential,
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
    file_sha256,
    inspect_windows_installer,
    sign_package_result,
    windows_package_environment,
)
from echo_certification_forge.windows_package_credential import (
    initialize_authority,
    issue_credential,
    main as credential_main,
)
from echo_certification_forge.windows_package_finalize import (
    finalize_windows_package_result,
    main as finalizer_main,
)
from echo_certification_forge.windows_package_worker import (
    initialize_identity,
    main as worker_main,
    run_once,
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


def test_static_windows_observer_checks_digest_commit_and_authenticode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    artifact = source / P8C_INSTALLER_NAME
    source.mkdir()
    artifact.write_bytes(b"exact installer bytes")
    digest = file_sha256(artifact)
    worker_image = sha256_bytes(b"worker-image")
    monkeypatch.setattr(
        "echo_certification_forge.windows_package._git_head",
        lambda _source: P8C_SOURCE_COMMIT,
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package._authenticode",
        lambda _path: {
            "Status": "NotSigned",
            "SignerSubject": None,
            "TimestamperSubject": None,
        },
    )

    body = inspect_windows_installer(
        artifact,
        source,
        worker_image_sha256=worker_image,
        expected_artifact_sha256=digest,
        expected_source_commit=P8C_SOURCE_COMMIT,
        expected_reference=str(artifact),
    )
    assert body.authenticode_status == "NotSigned"
    assert body.ready_candidate is False
    assert body.checks["artifact_digest"] is True

    with pytest.raises(ValueError, match="filename"):
        inspect_windows_installer(
            artifact,
            source,
            worker_image_sha256=worker_image,
            expected_artifact_sha256=digest,
            expected_source_commit=P8C_SOURCE_COMMIT,
            expected_reference=str(source / "different.exe"),
        )
    with pytest.raises(ValueError, match="digest"):
        inspect_windows_installer(
            artifact,
            source,
            worker_image_sha256=worker_image,
            expected_artifact_sha256="0" * 64,
            expected_source_commit=P8C_SOURCE_COMMIT,
            expected_reference=str(artifact),
        )
    with pytest.raises(ValueError, match="source HEAD"):
        inspect_windows_installer(
            artifact,
            source,
            worker_image_sha256=worker_image,
            expected_artifact_sha256=digest,
            expected_source_commit="0" * 40,
            expected_reference=str(artifact),
        )


def test_transport_and_runner_identity_clis_are_short_lived_and_non_overwriting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    authority_private = tmp_path / "authority.pem"
    authority_public = tmp_path / "authority-public.pem"
    runner_private = tmp_path / "runner.pem"
    runner_public = tmp_path / "runner-public.pem"
    credential_path = tmp_path / "credential.json"

    authority = initialize_authority(authority_private, authority_public)
    initialize_identity(runner_private, runner_public)
    issued = issue_credential(
        authority_key_path=authority_private,
        runner_public_key_path=runner_public,
        run_id="cert-live-package",
        tenant_id="echo-sovereign",
        runner_id="pwrk-live-package",
        output_path=credential_path,
        ttl_seconds=60,
    )
    assert authority["key_id"].startswith("ed25519:")
    assert issued["issued"] == "true"
    assert SignedRunCredential.model_validate_json(
        credential_path.read_text(encoding="utf-8")
    ).claims.scopes == (RunnerCommand.TRANSITION.value,)
    with pytest.raises(ValueError, match="TTL"):
        issue_credential(
            authority_key_path=authority_private,
            runner_public_key_path=runner_public,
            run_id="cert-too-long",
            tenant_id="echo-sovereign",
            runner_id="pwrk-live-package",
            output_path=tmp_path / "too-long.json",
            ttl_seconds=901,
        )
    with pytest.raises(FileExistsError):
        initialize_authority(authority_private, tmp_path / "unused-public.pem")

    assert credential_main(
        [
            "init",
            "--private-key",
            str(tmp_path / "cli-authority.pem"),
            "--public-key",
            str(tmp_path / "cli-authority-public.pem"),
        ]
    ) == 0
    assert credential_main(
        [
            "issue",
            "--authority-key",
            str(tmp_path / "cli-authority.pem"),
            "--runner-public-key",
            str(runner_public),
            "--run-id",
            "cert-cli-package",
            "--tenant",
            "echo-sovereign",
            "--runner-id",
            "pwrk-cli-package",
            "--out",
            str(tmp_path / "cli-credential.json"),
            "--ttl-seconds",
            "60",
        ]
    ) == 0
    assert worker_main(
        [
            "init",
            "--private-key",
            str(tmp_path / "cli-runner.pem"),
            "--public-key",
            str(tmp_path / "cli-runner-public.pem"),
        ]
    ) == 0
    assert '"initialized": "true"' in capsys.readouterr().out


def test_windows_worker_posts_only_the_signed_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_private = tmp_path / "runner.pem"
    runner_public = tmp_path / "runner-public.pem"
    initialize_identity(runner_private, runner_public)
    runner_key = serialization.load_pem_private_key(
        runner_private.read_bytes(), password=None
    )
    assert isinstance(runner_key, Ed25519PrivateKey)
    runner = RunnerEphemeralIdentity(runner_key)
    authority = ControlPlaneTransportAuthority.generate()
    credential = authority.issue(
        credential_id="live-result-credential",
        run_id="cert-live-package",
        tenant_id="echo-sovereign",
        runner_id="pwrk-live-package",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=utc_now(),
        ttl=timedelta(minutes=5),
    )
    credential_path = tmp_path / "credential.json"
    credential_path.write_text(credential.model_dump_json(), encoding="utf-8")
    artifact = tmp_path / P8C_INSTALLER_NAME
    artifact.write_bytes(b"package")
    body = _body(
        file_sha256(
            Path(__file__).parents[1]
            / "src"
            / "echo_certification_forge"
            / "windows_package.py"
        )
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_worker.inspect_windows_installer",
        lambda *args, **kwargs: body,
    )

    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self) -> bytes:
            return b'{"accepted":true}'

    def _urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(urllib_request, "urlopen", _urlopen)
    result = run_once(
        endpoint="http://127.0.0.1:8309",
        artifact_path=artifact,
        source_root=tmp_path,
        credential_path=credential_path,
        private_key_path=runner_private,
        expected_artifact_sha256=P8C_INSTALLER_SHA256,
        expected_source_commit=P8C_SOURCE_COMMIT,
        expected_reference=body.reference,
    )
    assert result["accepted"] is True
    assert result["authenticode_status"] == "NotSigned"
    posted = json.loads(captured["request"].data)
    assert posted["credential"]["claims"]["run_id"] == "cert-live-package"
    assert "command" not in posted["response"]["body"]
    with pytest.raises(ValueError, match="HTTPS"):
        run_once(
            endpoint="http://example.invalid",
            artifact_path=artifact,
            source_root=tmp_path,
            credential_path=credential_path,
            private_key_path=runner_private,
            expected_artifact_sha256=P8C_INSTALLER_SHA256,
            expected_source_commit=P8C_SOURCE_COMMIT,
            expected_reference=body.reference,
        )


def test_worker_and_finalizer_cli_paths_preserve_key_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_worker.run_once",
        lambda **kwargs: {"accepted": True, "run_id": "cert-cli-package"},
    )
    assert worker_main(
        [
            "run",
            "--endpoint",
            "http://127.0.0.1:8309",
            "--artifact",
            str(tmp_path / "package.exe"),
            "--source-root",
            str(tmp_path),
            "--credential",
            str(tmp_path / "credential.json"),
            "--private-key",
            str(tmp_path / "runner.pem"),
            "--artifact-sha256",
            "a" * 64,
            "--source-commit",
            "b" * 40,
            "--reference",
            str(tmp_path / "package.exe"),
        ]
    ) == 0
    assert "cert-cli-package" in capsys.readouterr().out

    monkeypatch.delenv("ECHO_CERTFORGE_API_KEY_PEPPER", raising=False)
    assert finalizer_main(
        [
            "--run-id",
            "cert-cli-package",
            "--tenant",
            "echo-sovereign",
        ]
    ) == 2
    assert "subscriber_governance_pepper_missing" in capsys.readouterr().out

    monkeypatch.setenv(
        "ECHO_CERTFORGE_API_KEY_PEPPER", "test-pepper-with-at-least-thirty-two-bytes"
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.EvidenceStore",
        lambda *args: "store",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.OperationalTelemetryRegistry",
        lambda *args: "registry",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.SubscriberPolicy.load",
        lambda *args: "subscriber-policy",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.SubscriberGovernance",
        lambda *args: "governance",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.RuleManifest.load",
        lambda *args: "manifest",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize._load_signer",
        lambda *args: "signer",
    )
    monkeypatch.setattr(
        "echo_certification_forge.windows_package_finalize.finalize_windows_package_result",
        lambda **kwargs: {
            "run_id": kwargs["run_id"],
            "signed": True,
            "release_verdict": "NOT_READY",
        },
    )
    assert finalizer_main(
        [
            "--run-id",
            "cert-cli-package",
            "--tenant",
            "echo-sovereign",
            "--db",
            str(tmp_path / "db.sqlite3"),
            "--evidence-root",
            str(tmp_path / "evidence"),
            "--policy",
            str(tmp_path / "policy.json"),
            "--subscriber-policy",
            str(tmp_path / "subscriber-policy.json"),
            "--signing-key",
            str(tmp_path / "signing.pem"),
        ]
    ) == 0
    assert '"release_verdict": "NOT_READY"' in capsys.readouterr().out


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
