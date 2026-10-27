from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import contained_path, parse_utc_iso, require_identifier, require_sha256
from echo_certification_forge.cli import main as cli_main
from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.models import (
    RedactionStatus,
    RuleResult,
    RunOutcome,
    SignedVerdictEnvelope,
)
from echo_certification_forge.policy import RuleManifest
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.verdict import DeterministicVerdictEngine
from production_e2e_support import trusted_generic_production_e2e


def complete_run(store, manifest, target, environment, run_id="cert-extra"):
    store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    production_e2e = trusted_generic_production_e2e(target, environment).result_details()
    for index, rule in enumerate(manifest.rules, start=1):
        artifact_id = f"extra-{index:02d}"
        store.append_artifact(
            run_id, target.tenant_id, artifact_id,
            json.dumps({"rule": rule.id}).encode(), "application/json", "extra-test",
        )
        store.record_rule_result(
            run_id, target.tenant_id,
            RuleResult(
                rule.id,
                True,
                (artifact_id,),
                production_e2e if rule.id == "production_e2e" else {"verified": True},
            ),
        )
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    return run_id


def issue(store, manifest, target, environment, run_id="cert-extra"):
    complete_run(store, manifest, target, environment, run_id)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    envelope = signer.sign(decision)
    store.save_signed_verdict(run_id, target.tenant_id, envelope)
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    return signer, envelope, trusted


def test_canonical_validation_and_path_guards(tmp_path: Path):
    assert require_identifier("tenant:one", "tenant") == "tenant:one"
    assert require_sha256("a" * 64, "digest") == "a" * 64
    with pytest.raises(ValueError):
        require_identifier("bad tenant", "tenant")
    with pytest.raises(ValueError):
        require_sha256("abc", "digest")
    assert contained_path(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    with pytest.raises(ValueError):
        contained_path(tmp_path, "../escape")
    with pytest.raises(ValueError):
        parse_utc_iso("2026-07-16T00:00:00")


def test_policy_rejects_duplicate_and_zero_evidence(tmp_path: Path):
    base = {
        "schema_version": "1.0.0", "manifest_id": "m", "release_policy": "p",
        "verdict_ttl_seconds": 10,
        "rules": [{"id": "r", "severity": "BLOCKER", "mandatory": True,
                   "conditional_allowed": False, "minimum_evidence": 1, "description": "x"}],
    }
    path = tmp_path / "policy.json"
    duplicate = dict(base)
    duplicate["rules"] = base["rules"] * 2
    path.write_text(json.dumps(duplicate))
    with pytest.raises(ValueError, match="duplicate"):
        RuleManifest.load(path)
    base["rules"][0]["minimum_evidence"] = 0
    path.write_text(json.dumps(base))
    with pytest.raises(ValueError, match="at least one"):
        RuleManifest.load(path)


def test_signer_loads_private_pem_and_registry_directory(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    signer = Ed25519VerdictSigner.from_private_pem(pem)
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "trusted.pem").write_text(signer.public_key_pem)
    registry = TrustedPublicKeyRegistry.from_directory(key_dir)
    assert signer.key_id in registry.keys
    other = Ed25519VerdictSigner.generate()
    with pytest.raises(ValueError):
        Ed25519VerdictSigner.from_private_pem(
            serialization.load_pem_private_key(pem, password=None).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ) if False else b"not a key"
        )
    assert other.key_id not in registry.keys


def test_api_verification_and_deploy_gate(store, manifest, target, environment):
    signer, envelope, trusted = issue(store, manifest, target, environment, "cert-api-full")
    app = create_app(ServiceContext(store, manifest, trusted))
    client = TestClient(app)
    headers = {"X-Tenant-ID": target.tenant_id}
    evidence = client.get("/v1/certifications/cert-api-full/evidence/verify", headers=headers)
    assert evidence.status_code == 200 and evidence.json()["valid"] is True
    verdict = client.get("/v1/certifications/cert-api-full/verdict/verify", headers=headers)
    assert verdict.status_code == 200 and verdict.json()["valid"] is True
    response = client.post(
        "/v1/release-gates/evaluate",
        headers=headers,
        json={
            "run_id": "cert-api-full",
            "target_identity_digest": target.identity_digest,
            "environment_identity_digest": environment.identity_digest,
            "rule_manifest_digest": manifest.digest,
        },
    )
    assert response.status_code == 200 and response.json()["allowed"] is True
    assert signer.key_id == envelope.key_id


def test_api_missing_verdict_and_unknown_run(store, manifest, target, environment):
    store.register_run("cert-api-empty", target, environment, manifest.manifest_id, manifest.digest)
    client = TestClient(create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty())))
    headers = {"X-Tenant-ID": target.tenant_id}
    missing = client.get("/v1/certifications/cert-api-empty/verdict/verify", headers=headers)
    assert missing.json() == {"valid": False, "reason": "signed_verdict_missing"}
    assert client.get("/v1/certifications/nope/evidence/verify", headers=headers).status_code == 404
    assert client.post(
        "/v1/release-gates/evaluate", headers=headers,
        json={"run_id": "nope", "target_identity_digest": "a"*64,
              "environment_identity_digest": "b"*64, "rule_manifest_digest": "c"*64},
    ).status_code == 404


def test_blocking_finding_and_failed_rule_keep_not_ready(store, manifest, target, environment):
    run_id = complete_run(store, manifest, target, environment, "cert-blocking")
    store.record_finding(
        "finding-critical", run_id, target.tenant_id, "CRITICAL", "authorization bypass", True,
        ("extra-01",),
    )
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(
        store, run_id, target.tenant_id, manifest, signer.key_id
    )
    assert decision.release_verdict.value == "NOT_READY"
    assert "blocking_findings_present" in decision.reasons


def test_redaction_failure_invalidates_evidence(store, manifest, target, environment):
    store.register_run("cert-redaction", target, environment, manifest.manifest_id, manifest.digest)
    store.append_artifact(
        "cert-redaction", target.tenant_id, "unsafe", b"secret", "text/plain", "scanner",
        RedactionStatus.FAILED,
    )
    report = store.verify_evidence("cert-redaction", target.tenant_id)
    assert not report.valid
    assert report.invalid_artifacts[0]["reason"] == "redaction_incomplete"


def test_gate_rejects_expired_environment_policy_and_tampered_payload(store, manifest, target, environment):
    signer, envelope, trusted = issue(store, manifest, target, environment, "cert-gate-branches")
    gate = DeployGate(store, trusted)
    expired = gate.evaluate(
        target.tenant_id, "cert-gate-branches", target.identity_digest,
        environment.identity_digest, manifest.digest,
        at=parse_utc_iso(envelope.payload["expires_at"]) + timedelta(seconds=1),
    )
    assert "verdict_expired" in expired.reasons
    mismatched = gate.evaluate(
        target.tenant_id, "cert-gate-branches", target.identity_digest,
        "f" * 64, "e" * 64,
    )
    assert "environment_identity_mismatch" in mismatched.reasons
    assert "rule_manifest_mismatch" in mismatched.reasons
    bad = SignedVerdictEnvelope(dict(envelope.payload), envelope.signature_b64, envelope.key_id, envelope.public_key_pem)
    bad.payload["run_id"] = "forged"
    valid, reason = trusted.verify(bad)
    assert not valid and reason == "invalid_signature"


def test_cli_evidence_verification(store, manifest, target, environment, tmp_path: Path, capsys):
    run_id = complete_run(store, manifest, target, environment, "cert-cli")
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    code = cli_main([
        "--db", str(store.db_path), "--evidence-root", str(store.evidence_root),
        "--trusted-keys", str(key_dir), "verify-evidence",
        "--tenant", target.tenant_id, "--run", run_id,
    ])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
