"""T4.P2 acceptance — read/cancel surface + tenant isolation.

Covers echo.certforge.{cancel,findings,evidence,verify,verdict}. Real FastAPI TestClient over a
real on-disk sqlite EvidenceStore, real Ed25519 signing. No mocks.
"""
from __future__ import annotations

import json
from dataclasses import replace

from fastapi.testclient import TestClient

from echo_certification_forge.models import RedactionStatus, RunOutcome, RunState, RuleResult
from echo_certification_forge.production_e2e import RULE_ID as PRODUCTION_E2E_RULE_ID
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.verdict import DeterministicVerdictEngine
from production_e2e_support import trusted_generic_production_e2e


def _client(store, manifest, trusted=None) -> TestClient:
    return TestClient(create_app(ServiceContext(store, manifest, trusted or TrustedPublicKeyRegistry.empty())))


def _h(tenant: str) -> dict[str, str]:
    return {"X-Tenant-ID": tenant}


def _satisfy_all_rules(store, manifest, run_id, tenant_id):
    for index, rule in enumerate(manifest.rules, start=1):
        artifact_id = f"evidence-{index:02d}"
        store.append_artifact(
            run_id, tenant_id, artifact_id,
            json.dumps({"rule": rule.id, "passed": True}, sort_keys=True).encode(),
            "application/json", "deterministic-test-harness", RedactionStatus.COMPLETE,
        )
        store.record_rule_result(run_id, tenant_id, RuleResult(rule.id, True, (artifact_id,), {"src": "acc"}))


def test_cross_tenant_reads_and_cancel_are_404_no_leak(store, manifest, target, environment):
    store.register_run("cert-iso", target, environment, manifest.manifest_id, manifest.digest)
    client = _client(store, manifest)
    other = _h("tenant-intruder")
    for path, method in [
        ("/v1/certifications/cert-iso", "get"),
        ("/v1/certifications/cert-iso/findings", "get"),
        ("/v1/certifications/cert-iso/evidence", "get"),
        ("/v1/certifications/cert-iso/verdict", "get"),
        ("/v1/certifications/cert-iso/verify", "post"),
        ("/v1/certifications/cert-iso/cancel", "post"),
    ]:
        response = getattr(client, method)(path, headers=other)
        assert response.status_code == 404, f"{method} {path} leaked: {response.status_code}"


def test_cancel_transitions_then_fails_closed_on_second(store, manifest, target, environment):
    store.register_run("cert-cancel", target, environment, manifest.manifest_id, manifest.digest)
    store.transition_state("cert-cancel", target.tenant_id, RunState.QUEUED, "orch", "queued", "v1")
    client = _client(store, manifest)

    first = client.post("/v1/certifications/cert-cancel/cancel", headers=_h(target.tenant_id))
    assert first.status_code == 200
    assert first.json()["state"] == "CANCELLED"

    second = client.post("/v1/certifications/cert-cancel/cancel", headers=_h(target.tenant_id))
    assert second.status_code == 409  # never silently re-opens a terminal run
    assert second.json()["detail"] == "run_not_cancellable"


def test_findings_endpoint_lists_recorded_findings(store, manifest, target, environment):
    store.register_run("cert-find", target, environment, manifest.manifest_id, manifest.digest)
    store.record_finding("f-1", "cert-find", target.tenant_id, "CRITICAL", "auth bypass", True, ())
    store.record_finding("f-2", "cert-find", target.tenant_id, "LOW", "cosmetic", False, ())
    client = _client(store, manifest)

    response = client.get("/v1/certifications/cert-find/findings", headers=_h(target.tenant_id))
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert {f["finding_id"] for f in findings} == {"f-1", "f-2"}
    critical = next(f for f in findings if f["finding_id"] == "f-1")
    assert critical["severity"] == "CRITICAL" and critical["blocks_release"] is True


def test_evidence_index_is_redacted_metadata_only(store, manifest, target, environment):
    store.register_run("cert-ev", target, environment, manifest.manifest_id, manifest.digest)
    store.append_artifact(
        "cert-ev", target.tenant_id, "art-1", b"secret-bytes-not-in-index",
        "text/plain", "harness", RedactionStatus.COMPLETE,
    )
    client = _client(store, manifest)

    response = client.get("/v1/certifications/cert-ev/evidence", headers=_h(target.tenant_id))
    assert response.status_code == 200
    artifacts = response.json()["artifacts"]
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art["artifact_id"] == "art-1"
    assert set(art) == {"artifact_id", "sha256", "size_bytes", "media_type",
                        "source_component", "redaction_status", "ordinal", "created_at"}
    # never leak raw content, filesystem path, or chain-integrity internals
    assert "relative_path" not in art and "chain_hash" not in art
    assert "secret-bytes" not in json.dumps(response.json())


def test_verify_detects_tampered_artifact(store, manifest, target, environment):
    store.register_run("cert-tamper", target, environment, manifest.manifest_id, manifest.digest)
    store.append_artifact("cert-tamper", target.tenant_id, "art-x", b"original",
                          "text/plain", "harness", RedactionStatus.COMPLETE)
    client = _client(store, manifest)

    good = client.post("/v1/certifications/cert-tamper/verify", headers=_h(target.tenant_id))
    assert good.status_code == 200 and good.json()["valid"] is True

    # tamper the on-disk artifact content out from under the recorded hash
    art_file = store.evidence_root / f"{target.tenant_id}/cert-tamper/artifacts/art-x.bin"
    art_file.write_bytes(b"tampered-content")

    bad = client.post("/v1/certifications/cert-tamper/verify", headers=_h(target.tenant_id))
    assert bad.status_code == 200
    body = bad.json()
    assert body["valid"] is False
    assert any(item.get("artifact_id") == "art-x" for item in body["invalid_artifacts"])


def test_verdict_endpoint_404_until_signed_then_returns_envelope(store, manifest, target, environment):
    store.register_run("cert-verdict", target, environment, manifest.manifest_id, manifest.digest)
    _satisfy_all_rules(store, manifest, "cert-verdict", target.tenant_id)
    store.set_run_outcome("cert-verdict", target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    client = _client(store, manifest, trusted)

    before = client.get("/v1/certifications/cert-verdict/verdict", headers=_h(target.tenant_id))
    assert before.status_code == 404 and before.json()["detail"] == "verdict_not_available"

    decision = DeterministicVerdictEngine().evaluate(
        store, "cert-verdict", target.tenant_id, manifest, signer.key_id
    )
    store.save_signed_verdict("cert-verdict", target.tenant_id, signer.sign(decision))

    after = client.get("/v1/certifications/cert-verdict/verdict", headers=_h(target.tenant_id))
    assert after.status_code == 200
    body = after.json()
    assert body["run_id"] == "cert-verdict"
    assert body["key_id"] == signer.key_id
    assert body["payload"]["release_verdict"] in {"PRODUCTION_READY", "CONDITIONALLY_READY", "NOT_READY"}
    # the returned envelope independently verifies against the trusted key
    from echo_certification_forge.models import SignedVerdictEnvelope
    envelope = SignedVerdictEnvelope(
        payload=body["payload"], signature_b64=body["signature_b64"],
        key_id=body["key_id"], public_key_pem=body["public_key_pem"],
    )
    verified, reason = trusted.verify(envelope)
    assert verified, reason


def test_list_preserves_signed_verdict_and_production_e2e_in_one_read(
    store, manifest, target, environment, monkeypatch
):
    client = _client(store, manifest)
    tenant = target.tenant_id
    other = replace(target, tenant_id="tenant-other")
    for run_id, run_target in (
        ("cert-unsigned", target), ("cert-valid", target),
        ("cert-mismatch", target), ("cert-other", other),
    ):
        store.register_run(run_id, run_target, environment, manifest.manifest_id, manifest.digest)

    details = trusted_generic_production_e2e(target, environment).result_details()
    for run_id, rule_details in (
        ("cert-valid", details),
        ("cert-mismatch", {**details, "environment_identity_digest": "0" * 64}),
    ):
        artifact_id = f"evidence-{run_id}"
        store.append_artifact(
            run_id, tenant, artifact_id, b"attestation fixture",
            "text/plain", "test", RedactionStatus.COMPLETE,
        )
        store.record_rule_result(
            run_id, tenant, RuleResult(PRODUCTION_E2E_RULE_ID, True, (artifact_id,), rule_details)
        )

    signer = Ed25519VerdictSigner.generate()
    engine = DeterministicVerdictEngine()
    roots = []
    for revision in (1, 2):
        store.append_artifact(
            "cert-valid", tenant, f"evidence-revision-{revision}", str(revision).encode(),
            "text/plain", "test", RedactionStatus.COMPLETE,
        )
        decision = engine.evaluate(store, "cert-valid", tenant, manifest, signer.key_id)
        store.save_signed_verdict("cert-valid", tenant, signer.sign(decision))
        roots.append(decision.evidence_merkle_root)
    assert roots[0] != roots[1]

    expected = []
    for row in store.list_runs(tenant):
        response = client.get(f"/v1/certifications/{row['run_id']}", headers=_h(tenant))
        assert response.status_code == 200
        expected.append(response.json())
    select_statements = []
    connect = store._connect

    def record_select(sql):
        if sql.lstrip().upper().startswith("SELECT"):
            select_statements.append(sql)

    def traced_connect():
        connection = connect()
        connection.set_trace_callback(record_select)
        return connection

    monkeypatch.setattr(store, "_connect", traced_connect)
    response = client.get("/v1/certifications", headers=_h(tenant))
    assert response.status_code == 200
    assert response.json() == expected
    assert len(select_statements) == 1
    by_id = {row["run_id"]: row for row in response.json()}
    assert set(by_id) == {"cert-unsigned", "cert-valid", "cert-mismatch"}
    assert by_id["cert-valid"]["evidence_merkle_root"] == roots[1]
    assert by_id["cert-valid"]["production_e2e"]["verified"] is True
    assert by_id["cert-valid"]["production_e2e"]["attestation_id"] == details["attestation_id"]
    assert by_id["cert-unsigned"]["release_verdict"] == "NOT_READY"
    assert by_id["cert-unsigned"]["evidence_merkle_root"] is None
    assert by_id["cert-mismatch"]["production_e2e"] == by_id["cert-unsigned"]["production_e2e"]
    assert by_id["cert-mismatch"]["production_e2e"]["verified"] is False
    assert client.get("/v1/certifications", headers=_h("tenant-empty")).json() == []
