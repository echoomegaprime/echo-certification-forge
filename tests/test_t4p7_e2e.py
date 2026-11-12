"""T4.P7 (= Task 6) acceptance — real end-to-end certification run.

A benign target is certified through the full executor path to a signed, independently-verifiable
verdict + evidence bundle that the deploy gate ALLOWS; a hostile variant is refused (BLOCK) with a
blocking finding and the deploy gate DENIES it. Real EvidenceStore, real Ed25519 signing, real
subprocess journey, real deploy-gate evaluation. No mocks.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import SignedVerdictEnvelope
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from production_e2e_support import trusted_generic_production_e2e

RUN = "cert-e2e"


def _benign(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "hello.py").write_text("print('service ok')\n", encoding="utf-8")
    return root


def _envelope(store, run_id, tenant_id) -> SignedVerdictEnvelope:
    row = store.latest_signed_verdict(run_id, tenant_id)
    return SignedVerdictEnvelope(
        payload=json.loads(row["payload_json"]), signature_b64=row["signature_b64"],
        key_id=row["key_id"], public_key_pem=row["public_key_pem"],
    )


def test_e2e_benign_target_certified_and_deploy_gate_allows(store, manifest, target, environment, tmp_path):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    signer = Ed25519VerdictSigner.generate()
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    executor = RunExecutor(store, manifest, signer)

    result = executor.execute(
        RUN, target.tenant_id, _benign(tmp_path),
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "hello.py"],
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
        production_e2e_attestation=trusted_generic_production_e2e(target, environment),
    )

    # certified through the full path
    assert result.final_state == "COMPLETED"
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings
    assert result.blocking_findings == ()

    # independently verifiable evidence bundle
    report = store.verify_evidence(RUN, target.tenant_id)
    assert report.valid

    # independently verifiable signed verdict, bound to this exact target + evidence root
    envelope = _envelope(store, RUN, target.tenant_id)
    ok, reason = trusted.verify(envelope)
    assert ok, reason
    assert envelope.payload["release_verdict"] == "PRODUCTION_READY"
    assert envelope.payload["target_identity_digest"] == target.identity_digest
    assert envelope.payload["evidence_merkle_root"] == report.merkle_root

    # the whole chain: the deploy gate ALLOWS release of this certified run
    decision = DeployGate(store, trusted).evaluate(
        target.tenant_id, RUN, target.identity_digest,
        environment.identity_digest, manifest.digest,
    )
    assert decision.allowed is True
    assert decision.release_verdict.value == "PRODUCTION_READY"


def test_e2e_hostile_variant_blocked_and_deploy_gate_denies(store, manifest, target, environment, tmp_path):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    signer = Ed25519VerdictSigner.generate()
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    executor = RunExecutor(store, manifest, signer)

    root = tmp_path / "evil"
    root.mkdir()
    (root / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    (root / ".gitmodules").write_text('[submodule "x"]\n  url = git@evil:x.git\n', encoding="utf-8")

    result = executor.execute(
        RUN, target.tenant_id, root,
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "hello.py"],
    )

    assert result.final_state == "COMPLETED"
    assert result.release_verdict == "NOT_READY"
    assert result.blocking_findings  # non-empty
    findings = store.blocking_findings(RUN, target.tenant_id)
    assert any("hostile_source" in f["title"] for f in findings)

    # the signed refusal still verifies (honest, tamper-evident BLOCK)
    envelope = _envelope(store, RUN, target.tenant_id)
    ok, _ = trusted.verify(envelope)
    assert ok
    assert envelope.payload["release_verdict"] == "NOT_READY"

    # the deploy gate DENIES release of the hostile run
    decision = DeployGate(store, trusted).evaluate(
        target.tenant_id, RUN, target.identity_digest,
        environment.identity_digest, manifest.digest,
    )
    assert decision.allowed is False
    assert "verdict_not_production_ready" in decision.reasons
