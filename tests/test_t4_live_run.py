"""Live-run completion — target acquisition + the key-holding run-worker path.

Proves the worker (which holds the run-signer, separate from the key-less read API) acquires a real
target, registers a full-identity run, executes, signs, and finalizes to a deploy-gate-allowable
verdict. Real store, real Ed25519, real subprocess journey, real deploy-gate. No mocks.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from echo_certification_forge.acquisition import AcquiredTarget, AcquisitionError, acquire_target
from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.models import SignedVerdictEnvelope
from echo_certification_forge.run_worker import run
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry


def _benign(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "hello.py").write_text("print('service ok')\n", encoding="utf-8")
    return root


# --- acquisition -------------------------------------------------------------------------------
def test_acquire_local_computes_stable_identity(tmp_path):
    src = _benign(tmp_path)
    a = acquire_target({"type": "local", "path": str(src)}, tmp_path / "dest")
    assert isinstance(a, AcquiredTarget)
    assert a.target_type == "local"
    assert len(a.artifact_sha256) == 64
    # deterministic: same tree -> same digest
    b = acquire_target({"type": "local", "path": str(src)}, tmp_path / "dest2")
    assert a.artifact_sha256 == b.artifact_sha256


def test_acquire_rejects_unknown_type_and_bad_git(tmp_path):
    with pytest.raises(AcquisitionError, match="unsupported target type"):
        acquire_target({"type": "smtp"}, tmp_path / "d")
    with pytest.raises(AcquisitionError):
        acquire_target({"type": "git", "url": "https://invalid.invalid/nope.git"},
                       tmp_path / "d", clone_timeout_s=15.0)


# --- run-worker --------------------------------------------------------------------------------
def _run_worker(store, manifest, tenant, source, journey):
    signer = Ed25519VerdictSigner.generate()
    result = run("cert-live", tenant, {"type": "local", "path": str(source)},
                 store=store, manifest=manifest, signer=signer,
                 entitled=frozenset({tenant}), journey=journey)
    return result, signer


def test_worker_benign_target_certified_and_deploy_gate_allows(store, manifest, tmp_path):
    tenant = "tenant-live"
    result, signer = _run_worker(store, manifest, tenant, _benign(tmp_path),
                                 [sys.executable, "hello.py"])

    assert result["state"] == "COMPLETED"
    assert result["release_verdict"] == "PRODUCTION_READY", result["blocking_findings"]
    assert result["signed"] is True

    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    row = store.latest_signed_verdict("cert-live", tenant)
    envelope = SignedVerdictEnvelope(payload=json.loads(row["payload_json"]),
                                     signature_b64=row["signature_b64"], key_id=row["key_id"],
                                     public_key_pem=row["public_key_pem"])
    ok, reason = trusted.verify(envelope)
    assert ok, reason
    # the acquired identity is what the worker registered + signed
    assert envelope.payload["target_identity_digest"] == result["target_identity_digest"]

    gate = DeployGate(store, trusted).evaluate(
        tenant, "cert-live", result["target_identity_digest"],
        result["environment_identity_digest"], manifest.digest,
    )
    assert gate.allowed is True


def test_worker_hostile_target_blocked(store, manifest, tmp_path):
    tenant = "tenant-live"
    root = tmp_path / "evil"
    root.mkdir()
    (root / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "setup.py").write_text("import os; os.system('rm -rf /')\n", encoding="utf-8")

    result, _ = _run_worker(store, manifest, tenant, root, [sys.executable, "hello.py"])
    assert result["release_verdict"] == "NOT_READY"
    assert result["blocking_findings"]


def test_worker_unentitled_tenant_halts_no_signature(store, manifest, tmp_path):
    signer = Ed25519VerdictSigner.generate()
    result = run("cert-live", "tenant-live", {"type": "local", "path": str(_benign(tmp_path))},
                 store=store, manifest=manifest, signer=signer,
                 entitled=frozenset(), journey=None)  # not entitled
    assert result["state"] == "INFRASTRUCTURE_FAILURE"
    assert result["signed"] is False
    assert store.latest_signed_verdict("cert-live", "tenant-live") is None
