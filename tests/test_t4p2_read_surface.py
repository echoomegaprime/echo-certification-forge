"""T4.P2 acceptance — read/cancel surface + tenant isolation.

Covers echo.certforge.{cancel,findings,evidence,verify,verdict}. Real FastAPI TestClient over a
real on-disk sqlite EvidenceStore, real Ed25519 signing. No mocks.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from echo_certification_forge.models import RedactionStatus, RunOutcome, RunState, RuleResult
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.verdict import DeterministicVerdictEngine


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
