from __future__ import annotations

import base64
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from echo_certification_forge.anchor import (
    AnchorConflict,
    AnchorStatement,
    AnchorUnavailable,
    AnchorVerificationBundle,
    IndependentFileAnchorProvider,
    privacy_preserving_tenant_ref,
    verify_anchor_bundle,
)
from echo_certification_forge.canonical import sha256_bytes, sha256_json
from echo_certification_forge.custody import (
    CustodyAuthenticationError,
    CustodyChunk,
    CustodyError,
    CustodyStore,
    EvidenceConflict,
    EvidenceIncomplete,
    EvidenceManifest,
    EvidenceVisibility,
    RetentionEventType,
)
from echo_certification_forge.models import ReleaseVerdict, RunOutcome
from echo_certification_forge.runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    RunnerLeaseState,
    RunnerStore,
    TrustedTransportRegistry,
    create_transport_request,
)
from echo_certification_forge import signer_cli
from echo_certification_forge.signing_service import (
    IsolatedVerdictSigningService,
    MandatoryRuleAttestation,
    OfflineVerificationBundle,
    ProductionSignedVerdict,
    ProductionSigningRequest,
    PublicKeyState,
    SigningActorType,
    SigningAuthorizationAuthority,
    SigningAuthorizationError,
    SigningConflict,
    SigningRunContext,
    SigningStore,
    SigningUnavailable,
    TrustedSigningAuthorizationRegistry,
    VerdictLifecycleState,
    public_key_record_from_private_key,
    verify_offline_bundle,
    verify_production_verdict,
)

NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
TARGET = "1" * 64
ENVIRONMENT = "2" * 64
POLICY = "3" * 64
RULES = "4" * 64


def setup_transport(tmp_path: Path, *, run_id: str = "run.p3", tenant_id: str = "tenant.p3"):
    authority = ControlPlaneTransportAuthority.generate()
    registry = TrustedTransportRegistry.empty()
    registry.add_pem(authority.public_key_pem)
    runner = RunnerEphemeralIdentity.generate()
    credential = authority.issue(
        credential_id=f"credential.{run_id}",
        run_id=run_id,
        tenant_id=tenant_id,
        runner_id=f"runner.{run_id}",
        runner_public_key_pem=runner.public_key_pem,
        scopes=tuple(command.value for command in RunnerCommand),
        issued_at=NOW,
        ttl=timedelta(minutes=10),
    )
    store = RunnerStore(tmp_path / f"{run_id}.runner.sqlite3")
    store.create_lease(credential, registry, now=NOW, lease_ttl=timedelta(minutes=5))
    return authority, registry, runner, credential, store


def transport_request(credential, *, request_id: str, sequence: int, body: dict, nonce: str | None = None):
    return create_transport_request(
        request_id=request_id,
        credential=credential,
        nonce=nonce or f"nonce-{request_id}-0000000000000000",
        command=RunnerCommand.EVIDENCE_CHUNK,
        sequence=sequence,
        issued_at=NOW + timedelta(seconds=sequence),
        body=body,
    )


def setup_custody(tmp_path: Path, *, run_id: str = "run.p3", tenant_id: str = "tenant.p3"):
    _authority, registry, _runner, credential, runner_store = setup_transport(
        tmp_path, run_id=run_id, tenant_id=tenant_id
    )
    custody = CustodyStore(
        tmp_path / f"{run_id}.custody.sqlite3",
        tmp_path / f"{run_id}.evidence",
        runner_store,
        registry,
    )
    custody.register_run(
        run_id=run_id,
        tenant_id=tenant_id,
        target_identity_digest=TARGET,
        environment_identity_digest=ENVIRONMENT,
        policy_version="policy.v1",
        policy_digest=POLICY,
        mandatory_rules_digest=RULES,
    )
    return custody, credential, runner_store


def upload_artifact(
    custody: CustodyStore,
    credential,
    *,
    content: bytes = b"verified-p3-evidence",
    artifact_id: str = "artifact.p3",
    start_sequence: int = 1,
    visibility: EvidenceVisibility = EvidenceVisibility.RAW,
    legal_hold: bool = False,
):
    chunks = [content[: len(content) // 2], content[len(content) // 2 :]]
    manifest = EvidenceManifest(
        run_id=credential.claims.run_id,
        tenant_id=credential.claims.tenant_id,
        artifact_id=artifact_id,
        declared_size_bytes=len(content),
        declared_sha256=sha256_bytes(content),
        media_type="application/octet-stream",
        purpose="P3 acceptance evidence",
        visibility=visibility,
        total_chunks=len(chunks),
        retention_until=NOW + timedelta(days=30),
        legal_hold=legal_hold,
    )
    begin = transport_request(
        credential,
        request_id=f"begin.{artifact_id}",
        sequence=start_sequence,
        body={
            "operation": "begin_upload",
            "artifact_id": artifact_id,
            "manifest_sha256": manifest.identity_digest,
        },
    )
    custody.begin_upload(begin, manifest, now=NOW + timedelta(seconds=start_sequence))
    for index, payload in enumerate(chunks):
        sequence = start_sequence + index + 1
        chunk = CustodyChunk(
            artifact_id=artifact_id,
            chunk_index=index,
            total_chunks=len(chunks),
            chunk_sha256=sha256_bytes(payload),
            payload_b64=base64.b64encode(payload).decode("ascii"),
        )
        request = transport_request(
            credential,
            request_id=f"chunk.{artifact_id}.{index}",
            sequence=sequence,
            body={
                "operation": "append_chunk",
                "artifact_id": artifact_id,
                "chunk_index": index,
                "chunk_sha256": chunk.chunk_sha256,
            },
        )
        custody.append_chunk(request, chunk, now=NOW + timedelta(seconds=sequence))
    final_sequence = start_sequence + len(chunks) + 1
    final_request = transport_request(
        credential,
        request_id=f"final.{artifact_id}",
        sequence=final_sequence,
        body={"operation": "finalize_upload", "artifact_id": artifact_id},
    )
    descriptor = custody.finalize_upload(
        final_request, artifact_id, now=NOW + timedelta(seconds=final_sequence)
    )
    return manifest, descriptor, final_sequence


def build_anchor(tmp_path: Path, *, merkle_root: str, run_id: str = "run.p3", tenant_id: str = "tenant.p3"):
    provider = IndependentFileAnchorProvider.generate(tmp_path / "independent-anchor", "anchor.p3")
    statement = AnchorStatement(
        run_id=run_id,
        tenant_ref=privacy_preserving_tenant_ref(tenant_id, "echoforge.p3"),
        artifact_id="run.evidence.set",
        evidence_merkle_root=merkle_root,
        policy_version="policy.v1",
        anchored_at=NOW + timedelta(minutes=1),
        anchor_provider_id=provider.provider_id,
    )
    receipt = provider.create_anchor(statement, idempotency_key="anchor.request.1")
    return provider, statement, receipt, provider.verification_bundle(receipt.receipt_id)


def build_signing_stack(tmp_path: Path):
    custody, credential, _runner_store = setup_custody(tmp_path)
    _manifest, descriptor, _sequence = upload_artifact(custody, credential)
    verification = custody.verify_run("run.p3", "tenant.p3")
    assert verification["valid"] is True
    provider, _statement, receipt, anchor_bundle = build_anchor(
        tmp_path, merkle_root=verification["merkle_root"]
    )

    signing_key = Ed25519PrivateKey.generate()
    key_record = public_key_record_from_private_key(
        signing_key,
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=365),
    )
    auth_authority = SigningAuthorizationAuthority.generate()
    auth_registry = TrustedSigningAuthorizationRegistry()
    auth_registry.add_pem(auth_authority.public_key_pem)
    authorization = auth_authority.issue(
        authorization_id="authorization.p3",
        run_id="run.p3",
        tenant_id="tenant.p3",
        actor_id="control.certforge",
        issued_at=NOW,
        ttl=timedelta(minutes=5),
    )
    rules = (
        MandatoryRuleAttestation(rule_id="rule.a", passed=True, evidence_ids=(descriptor["artifact_id"],)),
        MandatoryRuleAttestation(rule_id="rule.b", passed=True, evidence_ids=(descriptor["artifact_id"],)),
    )
    context = SigningRunContext(
        run_id="run.p3",
        tenant_id="tenant.p3",
        target_identity_digest=TARGET,
        environment_identity_digest=ENVIRONMENT,
        policy_version="policy.v1",
        policy_digest=POLICY,
        mandatory_rules_digest=RULES,
        mandatory_rule_ids=("rule.a", "rule.b"),
        evidence_merkle_root=verification["merkle_root"],
        anchor_artifact_id="run.evidence.set",
        tenant_anchor_namespace="echoforge.p3",
    )
    store = SigningStore(tmp_path / "signing.sqlite3")
    store.register_context(context)
    store.publish_key(key_record)
    service = IsolatedVerdictSigningService(
        store,
        {key_record.key_id: signing_key},
        auth_registry,
        {receipt.provider_key_id: provider.public_key_pem},
    )
    request = ProductionSigningRequest(
        request_id="sign.request.1",
        nonce="signing-nonce-0000000000000001",
        actor_type=SigningActorType.CONTROL_PLANE,
        actor_id="control.certforge",
        run_id="run.p3",
        tenant_id="tenant.p3",
        run_outcome=RunOutcome.COMPLETE,
        release_verdict=ReleaseVerdict.PRODUCTION_READY,
        target_identity_digest=TARGET,
        environment_identity_digest=ENVIRONMENT,
        policy_version="policy.v1",
        policy_digest=POLICY,
        mandatory_rules_digest=RULES,
        mandatory_rule_results=rules,
        evidence_merkle_root=verification["merkle_root"],
        anchor_bundle=anchor_bundle,
        lifecycle_state=VerdictLifecycleState.VALID,
        signing_key_id=key_record.key_id,
        issued_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(days=30),
        authorization=authorization,
    )
    return {
        "custody": custody,
        "provider": provider,
        "receipt": receipt,
        "anchor_bundle": anchor_bundle,
        "signing_key": signing_key,
        "key_record": key_record,
        "auth_authority": auth_authority,
        "auth_registry": auth_registry,
        "authorization": authorization,
        "context": context,
        "store": store,
        "service": service,
        "request": request,
    }


def replace_request(request: ProductionSigningRequest, **updates) -> ProductionSigningRequest:
    data = request.model_dump(mode="json")
    data.update(updates)
    return ProductionSigningRequest.model_validate(data)


def test_custody_happy_path_merkle_visibility_retention_and_restart(tmp_path: Path):
    custody, credential, runner_store = setup_custody(tmp_path)
    _manifest, descriptor, _ = upload_artifact(
        custody, credential, visibility=EvidenceVisibility.RESTRICTED, legal_hold=True
    )
    with pytest.raises(PermissionError):
        custody.get_artifact("run.p3", "tenant.p3", "artifact.p3")
    stored, content = custody.get_artifact(
        "run.p3", "tenant.p3", "artifact.p3", allow_restricted=True
    )
    assert content == b"verified-p3-evidence"
    assert stored["leaf_hash"] == descriptor["leaf_hash"]
    state = custody.retention_state("run.p3", "tenant.p3", "artifact.p3")
    assert state["legal_hold"] is True
    custody.append_retention_event(
        run_id="run.p3",
        tenant_id="tenant.p3",
        artifact_id="artifact.p3",
        event_type=RetentionEventType.LEGAL_HOLD_RELEASED,
        actor="operator.p3",
        reason="release after review",
    )
    assert custody.retention_state("run.p3", "tenant.p3", "artifact.p3")["legal_hold"] is False
    with pytest.raises(PermissionError):
        custody.delete_artifact("run.p3", "tenant.p3", "artifact.p3")
    report = custody.verify_run("run.p3", "tenant.p3")
    assert report["valid"] is True
    restarted = CustodyStore(custody.db_path, custody.evidence_root, runner_store, custody.transport_registry)
    assert restarted.verify_run("run.p3", "tenant.p3") == report


def test_partial_upload_resume_missing_chunk_and_duplicate_chunk(tmp_path: Path):
    custody, credential, _ = setup_custody(tmp_path)
    content = b"resume-evidence"
    manifest = EvidenceManifest(
        run_id="run.p3",
        tenant_id="tenant.p3",
        artifact_id="artifact.resume",
        declared_size_bytes=len(content),
        declared_sha256=sha256_bytes(content),
        media_type="application/octet-stream",
        purpose="resume test",
        visibility=EvidenceVisibility.RAW,
        total_chunks=2,
        retention_until=NOW + timedelta(days=1),
    )
    begin = transport_request(
        credential,
        request_id="begin.resume",
        sequence=1,
        body={"operation": "begin_upload", "artifact_id": manifest.artifact_id, "manifest_sha256": manifest.identity_digest},
    )
    custody.begin_upload(begin, manifest, now=NOW + timedelta(seconds=1))
    first = content[:6]
    chunk = CustodyChunk(
        artifact_id=manifest.artifact_id,
        chunk_index=0,
        total_chunks=2,
        chunk_sha256=sha256_bytes(first),
        payload_b64=base64.b64encode(first).decode(),
    )
    request = transport_request(
        credential,
        request_id="chunk.resume.0",
        sequence=2,
        body={"operation": "append_chunk", "artifact_id": manifest.artifact_id, "chunk_index": 0, "chunk_sha256": chunk.chunk_sha256},
    )
    custody.append_chunk(request, chunk, now=NOW + timedelta(seconds=2))
    with pytest.raises(EvidenceConflict, match="duplicate_chunk"):
        custody.append_chunk(
            transport_request(
                credential,
                request_id="chunk.resume.duplicate",
                sequence=3,
                body={"operation": "append_chunk", "artifact_id": manifest.artifact_id, "chunk_index": 0, "chunk_sha256": chunk.chunk_sha256},
            ),
            chunk,
            now=NOW + timedelta(seconds=3),
        )
    with pytest.raises(EvidenceIncomplete, match="missing_chunks"):
        custody.finalize_upload(
            transport_request(
                credential,
                request_id="final.resume.incomplete",
                sequence=4,
                body={"operation": "finalize_upload", "artifact_id": manifest.artifact_id},
            ),
            manifest.artifact_id,
            now=NOW + timedelta(seconds=4),
        )
    status = custody.upload_status("run.p3", "tenant.p3", manifest.artifact_id)
    assert status["missing_chunks"] == [1]
    second = content[6:]
    chunk2 = CustodyChunk(
        artifact_id=manifest.artifact_id,
        chunk_index=1,
        total_chunks=2,
        chunk_sha256=sha256_bytes(second),
        payload_b64=base64.b64encode(second).decode(),
    )
    custody.append_chunk(
        transport_request(
            credential,
            request_id="chunk.resume.1",
            sequence=5,
            body={"operation": "append_chunk", "artifact_id": manifest.artifact_id, "chunk_index": 1, "chunk_sha256": chunk2.chunk_sha256},
        ),
        chunk2,
        now=NOW + timedelta(seconds=5),
    )
    descriptor = custody.finalize_upload(
        transport_request(
            credential,
            request_id="final.resume",
            sequence=6,
            body={"operation": "finalize_upload", "artifact_id": manifest.artifact_id},
        ),
        manifest.artifact_id,
        now=NOW + timedelta(seconds=6),
    )
    assert descriptor["sha256"] == manifest.declared_sha256


def test_custody_rejects_sequence_rollback_cross_run_cross_tenant_and_expiry(tmp_path: Path):
    custody, credential, runner_store = setup_custody(tmp_path)
    manifest = EvidenceManifest(
        run_id="run.p3",
        tenant_id="tenant.p3",
        artifact_id="artifact.guard",
        declared_size_bytes=1,
        declared_sha256=sha256_bytes(b"x"),
        media_type="application/octet-stream",
        purpose="guard test",
        visibility=EvidenceVisibility.PUBLIC,
        total_chunks=1,
        retention_until=NOW + timedelta(days=1),
    )
    begin = transport_request(
        credential,
        request_id="begin.guard",
        sequence=5,
        body={"operation": "begin_upload", "artifact_id": manifest.artifact_id, "manifest_sha256": manifest.identity_digest},
    )
    custody.begin_upload(begin, manifest, now=NOW + timedelta(seconds=5))
    chunk = CustodyChunk(
        artifact_id=manifest.artifact_id,
        chunk_index=0,
        total_chunks=1,
        chunk_sha256=sha256_bytes(b"x"),
        payload_b64=base64.b64encode(b"x").decode(),
    )
    with pytest.raises(EvidenceConflict, match="sequence_rollback"):
        custody.append_chunk(
            transport_request(
                credential,
                request_id="chunk.rollback",
                sequence=4,
                body={"operation": "append_chunk", "artifact_id": manifest.artifact_id, "chunk_index": 0, "chunk_sha256": chunk.chunk_sha256},
            ),
            chunk,
            now=NOW + timedelta(seconds=6),
        )
    injected = manifest.model_copy(update={"run_id": "run.other"})
    with pytest.raises(CustodyAuthenticationError, match="identity_mismatch"):
        custody.begin_upload(
            transport_request(
                credential,
                request_id="begin.inject",
                sequence=6,
                body={"operation": "begin_upload", "artifact_id": injected.artifact_id, "manifest_sha256": injected.identity_digest},
            ),
            injected,
            now=NOW + timedelta(seconds=6),
        )
    with pytest.raises(KeyError):
        custody.get_run("run.p3", "tenant.other")
    connection = runner_store._connect()  # test-only direct expiry injection
    try:
        connection.execute(
            "UPDATE runner_leases SET lease_expires_at = ? WHERE run_id = ?",
            ((NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"), "run.p3"),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(CustodyAuthenticationError, match="lease_expired"):
        custody.append_chunk(
            transport_request(
                credential,
                request_id="chunk.expired",
                sequence=7,
                body={"operation": "append_chunk", "artifact_id": manifest.artifact_id, "chunk_index": 0, "chunk_sha256": chunk.chunk_sha256},
            ),
            chunk,
            now=NOW + timedelta(seconds=7),
        )


def test_custody_detects_modified_bytes_and_append_only_database(tmp_path: Path):
    custody, credential, _ = setup_custody(tmp_path)
    _manifest, descriptor, _ = upload_artifact(custody, credential)
    path = custody.evidence_root / descriptor["relative_path"]
    path.write_bytes(b"tampered")
    report = custody.verify_run("run.p3", "tenant.p3")
    assert report["valid"] is False
    assert "digest_mismatch" in report["invalid_artifacts"][0]["reason"]
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with custody._connection() as connection:
            connection.execute("DELETE FROM evidence_artifacts")


def test_anchor_real_file_receipt_idempotency_links_and_offline_verification(tmp_path: Path):
    provider, statement, receipt, bundle = build_anchor(tmp_path, merkle_root="5" * 64)
    assert provider.root.joinpath("anchor-log.jsonl").is_file()
    assert provider.verify_receipt(receipt) == (True, "verified")
    assert verify_anchor_bundle(bundle) == (True, "verified")
    assert provider.create_anchor(statement, idempotency_key="anchor.request.1") == receipt
    conflicting = statement.model_copy(update={"evidence_merkle_root": "6" * 64})
    with pytest.raises(AnchorConflict, match="idempotency_payload_conflict"):
        provider.create_anchor(conflicting, idempotency_key="anchor.request.1")
    superseding = AnchorStatement(
        **{
            **statement.model_dump(),
            "evidence_merkle_root": "7" * 64,
            "anchored_at": NOW + timedelta(minutes=2),
            "supersedes_receipt_id": receipt.receipt_id,
        }
    )
    second = provider.create_anchor(superseding, idempotency_key="anchor.request.2")
    invalidating = AnchorStatement(
        **{
            **statement.model_dump(),
            "anchored_at": NOW + timedelta(minutes=3),
            "invalidates_receipt_id": second.receipt_id,
        }
    )
    provider.create_anchor(invalidating, idempotency_key="anchor.request.3")
    assert provider.verify_log()["valid"] is True
    tampered_receipt = receipt.model_copy(update={"chain_hash": "0" * 64})
    tampered_bundle = bundle.model_copy(update={"receipt": tampered_receipt})
    assert verify_anchor_bundle(tampered_bundle)[0] is False
    provider.available = False
    with pytest.raises(AnchorUnavailable):
        provider.create_anchor(statement, idempotency_key="anchor.request.4")




def test_anchor_recovers_receipt_written_before_log_and_idempotency(tmp_path: Path, monkeypatch):
    provider = IndependentFileAnchorProvider.generate(tmp_path / "anchor-recovery", "anchor.recovery")
    statement = AnchorStatement(
        run_id="run.recovery",
        tenant_ref=privacy_preserving_tenant_ref("tenant.recovery", "namespace.recovery"),
        artifact_id="run.evidence.set",
        evidence_merkle_root="8" * 64,
        policy_version="policy.v1",
        anchored_at=NOW,
        anchor_provider_id=provider.provider_id,
    )
    original_append = IndependentFileAnchorProvider._append_log
    monkeypatch.setattr(
        IndependentFileAnchorProvider,
        "_append_log",
        lambda _self, _entry: (_ for _ in ()).throw(OSError("log interrupted")),
    )
    with pytest.raises(OSError, match="log interrupted"):
        provider.create_anchor(statement, idempotency_key="anchor.recovery.1")
    assert list((provider.root / "receipts").glob("*.json"))
    assert provider._read_log() == []
    monkeypatch.setattr(IndependentFileAnchorProvider, "_append_log", original_append)
    recovered = IndependentFileAnchorProvider(
        root=provider.root,
        provider_id=provider.provider_id,
        _private_key=provider._private_key,
    )
    receipt = recovered.create_anchor(statement, idempotency_key="anchor.recovery.1")
    assert recovered.verify_receipt(receipt) == (True, "verified")
    assert recovered.verify_log()["entry_count"] == 1

def test_signing_happy_path_idempotency_replay_and_offline_bundle(tmp_path: Path):
    stack = build_signing_stack(tmp_path)
    envelope = stack["service"].sign(stack["request"], now=NOW + timedelta(minutes=2))
    assert envelope.payload.anchor_receipt_id == stack["receipt"].receipt_id
    assert envelope.payload.release_verdict is ReleaseVerdict.PRODUCTION_READY
    public_bundle = stack["store"].public_bundle()
    assert verify_production_verdict(envelope, public_bundle, now=NOW + timedelta(days=1)) == (True, "verified")
    offline = OfflineVerificationBundle(
        verdict=envelope,
        anchor_bundle=stack["anchor_bundle"],
        public_key_bundle=public_bundle,
    )
    assert verify_offline_bundle(offline, now=NOW + timedelta(days=1)) == (True, "verified")
    retry = replace_request(stack["request"], nonce="signing-nonce-0000000000000002")
    assert stack["service"].sign(retry, now=NOW + timedelta(minutes=2)) == envelope
    with pytest.raises(SigningAuthorizationError, match="replay"):
        stack["service"].sign(retry, now=NOW + timedelta(minutes=2))
    conflict = replace_request(
        stack["request"],
        nonce="signing-nonce-0000000000000003",
        release_verdict=ReleaseVerdict.NOT_READY,
    )
    with pytest.raises(SigningConflict, match="conflicting_idempotent"):
        stack["service"].sign(conflict, now=NOW + timedelta(minutes=2))


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"actor_type": SigningActorType.RUNNER}, "only_control_plane"),
        ({"actor_type": SigningActorType.MODEL}, "only_control_plane"),
        ({"actor_type": SigningActorType.DESKTOP}, "only_control_plane"),
        ({"actor_type": SigningActorType.ORDINARY_WORKER}, "only_control_plane"),
        ({"tenant_id": "tenant.other"}, "identity_mismatch"),
        ({"target_identity_digest": "a" * 64}, "target_identity_digest"),
        ({"environment_identity_digest": "b" * 64}, "environment_identity_digest"),
        ({"policy_version": "policy.v2"}, "policy_version"),
        ({"policy_digest": "c" * 64}, "policy_digest"),
        ({"mandatory_rules_digest": "d" * 64}, "mandatory_rules_digest"),
        ({"evidence_merkle_root": "e" * 64}, "evidence_merkle_root"),
        ({"run_outcome": RunOutcome.INCONCLUSIVE}, "incomplete_run"),
        ({"lifecycle_state": VerdictLifecycleState.REVOKED}, "lifecycle"),
    ],
)
def test_signing_denial_matrix(tmp_path: Path, updates: dict, reason: str):
    stack = build_signing_stack(tmp_path)
    request = replace_request(stack["request"], **updates)
    with pytest.raises((SigningAuthorizationError, KeyError), match=reason):
        stack["service"].sign(request, now=NOW + timedelta(minutes=2))


def test_signing_rejects_missing_rule_tampered_anchor_unknown_key_revoked_key_and_outage(tmp_path: Path):
    stack = build_signing_stack(tmp_path)
    missing_rule = replace_request(
        stack["request"],
        mandatory_rule_results=[stack["request"].mandatory_rule_results[0].model_dump(mode="json")],
    )
    with pytest.raises(SigningAuthorizationError, match="mandatory_rule_set_mismatch"):
        stack["service"].sign(missing_rule, now=NOW + timedelta(minutes=2))
    tampered_receipt = stack["receipt"].model_copy(update={"signature_b64": base64.b64encode(b"x" * 64).decode()})
    tampered_bundle = stack["anchor_bundle"].model_copy(update={"receipt": tampered_receipt})
    with pytest.raises(SigningAuthorizationError, match="anchor_verification_failed"):
        stack["service"].sign(
            replace_request(stack["request"], anchor_bundle=tampered_bundle.model_dump(mode="json")),
            now=NOW + timedelta(minutes=2),
        )
    with pytest.raises(SigningAuthorizationError, match="outside_validity|not_usable|unknown"):
        stack["service"].sign(
            replace_request(stack["request"], signing_key_id="ed25519:" + "0" * 32),
            now=NOW + timedelta(minutes=2),
        )
    stack["store"].transition_key(
        stack["key_record"].key_id,
        PublicKeyState.REVOKED,
        reason="administrative revocation",
        effective_at=NOW + timedelta(minutes=1),
    )
    with pytest.raises(SigningAuthorizationError, match="not_usable"):
        stack["service"].sign(
            replace_request(stack["request"], nonce="signing-nonce-0000000000000099"),
            now=NOW + timedelta(minutes=2),
        )
    stack["service"].available = False
    with pytest.raises(SigningUnavailable):
        stack["service"].sign(stack["request"], now=NOW + timedelta(minutes=2))


def test_key_rotation_historical_verification_and_compromise_response(tmp_path: Path):
    stack = build_signing_stack(tmp_path)
    envelope = stack["service"].sign(stack["request"], now=NOW + timedelta(minutes=2))
    old_key_id = stack["key_record"].key_id
    stack["store"].transition_key(
        old_key_id,
        PublicKeyState.GRACE,
        reason="rotation overlap",
        effective_at=NOW + timedelta(minutes=3),
    )
    new_key = Ed25519PrivateKey.generate()
    new_record = public_key_record_from_private_key(
        new_key,
        not_before=NOW + timedelta(minutes=3),
        not_after=NOW + timedelta(days=365),
    )
    stack["store"].publish_key(new_record)
    stack["store"].transition_key(
        old_key_id,
        PublicKeyState.REVOKED,
        reason="rotated after overlap",
        effective_at=NOW + timedelta(days=1),
    )
    bundle = stack["store"].public_bundle()
    assert verify_production_verdict(envelope, bundle, now=NOW + timedelta(days=2)) == (True, "verified")
    stack["store"].transition_key(
        old_key_id,
        PublicKeyState.COMPROMISED,
        reason="compromise response",
        effective_at=NOW + timedelta(days=3),
    )
    assert verify_production_verdict(
        envelope, stack["store"].public_bundle(), now=NOW + timedelta(days=4)
    ) == (False, "signing_key_compromised")


def test_signing_authorization_expiry_database_lock_and_storage_interruption_fail_closed(tmp_path: Path):
    stack = build_signing_stack(tmp_path)
    expired_auth = stack["auth_authority"].issue(
        authorization_id="authorization.expired",
        run_id="run.p3",
        tenant_id="tenant.p3",
        actor_id="control.certforge",
        issued_at=NOW - timedelta(minutes=10),
        ttl=timedelta(minutes=1),
    )
    expired_request = replace_request(stack["request"], authorization=expired_auth.model_dump(mode="json"))
    with pytest.raises(SigningAuthorizationError, match="expired"):
        stack["service"].sign(expired_request, now=NOW + timedelta(minutes=2))

    blocker = sqlite3.connect(stack["store"].db_path, timeout=1)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(sqlite3.OperationalError):
            stack["service"].sign(
                replace_request(stack["request"], nonce="signing-nonce-0000000000000042"),
                now=NOW + timedelta(minutes=2),
            )
    finally:
        blocker.rollback()
        blocker.close()

    custody, credential, _ = setup_custody(tmp_path / "storage")
    custody.evidence_root.rmdir()
    custody.evidence_root.write_text("not-a-directory", encoding="utf-8")
    with pytest.raises((OSError, NotADirectoryError, CustodyError)):
        upload_artifact(custody, credential, content=b"xy", artifact_id="artifact.storage")




def test_isolated_signer_cli_real_entrypoint_and_failure_output(tmp_path: Path, monkeypatch, capsys):
    stack = build_signing_stack(tmp_path / "fixture")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    request_path = runtime / "request.json"
    context_path = runtime / "context.json"
    record_path = runtime / "key-record.json"
    private_path = runtime / "verdict-key.pem"
    auth_path = runtime / "authorization-public.pem"
    anchor_path = runtime / "anchor-public.pem"
    output_path = runtime / "verdict.json"
    public_bundle_path = runtime / "public-keys.json"
    db_path = runtime / "signer.sqlite3"

    request_path.write_text(json.dumps(stack["request"].model_dump(mode="json")), encoding="utf-8")
    context_path.write_text(json.dumps(stack["context"].model_dump(mode="json")), encoding="utf-8")
    record_path.write_text(json.dumps(stack["key_record"].model_dump(mode="json")), encoding="utf-8")
    private_path.write_bytes(
        stack["signing_key"].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    auth_path.write_text(stack["auth_authority"].public_key_pem, encoding="ascii")
    anchor_path.write_text(stack["provider"].public_key_pem, encoding="ascii")
    monkeypatch.setattr(
        "sys.argv",
        [
            "echo-certforge-signer",
            "--request", str(request_path),
            "--context", str(context_path),
            "--key-record", str(record_path),
            "--signing-key", str(private_path),
            "--authorization-public-key", str(auth_path),
            "--trusted-anchor-public-key", str(anchor_path),
            "--db", str(db_path),
            "--output", str(output_path),
            "--public-bundle", str(public_bundle_path),
        ],
    )
    assert signer_cli.main() == 0
    stdout = json.loads(capsys.readouterr().out)
    assert stdout["ok"] is True
    envelope = ProductionSignedVerdict.model_validate_json(output_path.read_text(encoding="utf-8"))
    bundle = json.loads(public_bundle_path.read_text(encoding="utf-8"))
    assert verify_production_verdict(envelope, bundle, now=NOW + timedelta(days=1)) == (True, "verified")
    assert "PRIVATE KEY" not in output_path.read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in public_bundle_path.read_text(encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        [
            "echo-certforge-signer",
            "--request", str(runtime / "missing.json"),
            "--context", str(context_path),
            "--key-record", str(record_path),
            "--signing-key", str(private_path),
            "--authorization-public-key", str(auth_path),
            "--trusted-anchor-public-key", str(anchor_path),
            "--db", str(runtime / "failure.sqlite3"),
            "--output", str(runtime / "failure-verdict.json"),
            "--public-bundle", str(runtime / "failure-public.json"),
        ],
    )
    assert signer_cli.main() == 1
    failure = json.loads(capsys.readouterr().err)
    assert failure["ok"] is False
    assert failure["error"] == "FileNotFoundError"
    assert "PRIVATE KEY" not in json.dumps(failure)

def test_schema_validation_rejects_unknown_fields_and_non_deterministic_shapes(tmp_path: Path):
    with pytest.raises(ValidationError):
        EvidenceManifest.model_validate(
            {
                "run_id": "run.p3",
                "tenant_id": "tenant.p3",
                "artifact_id": "artifact.p3",
                "declared_size_bytes": 1,
                "declared_sha256": sha256_bytes(b"x"),
                "media_type": "application/octet-stream",
                "purpose": "test",
                "visibility": "RAW",
                "total_chunks": 1,
                "retention_until": NOW.isoformat(),
                "unknown": True,
            }
        )
    with pytest.raises(ValidationError):
        MandatoryRuleAttestation(rule_id="rule.a", passed=True, evidence_ids=("b", "a"))
