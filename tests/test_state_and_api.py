from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import pytest

from echo_certification_forge.canonical import sha256_bytes, to_utc_iso
from echo_certification_forge.models import RunState
from echo_certification_forge.product_readiness import create_product_readiness_envelope
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry



def _adapter_report(tmp_path, *, passing: bool):
    """Adapter acceptance evidence for the status tests.

    passing=True RAISES the evidence to policy (STABLE, all cases passed, no critical
    failures). passing=False mirrors what is actually committed in
    artifacts/p5-adapter-bundle-20260723: EXPERIMENTAL maturity, partial cases, gate BLOCK.
    Thresholds are never lowered in either direction.
    """
    import json as _json

    maturity = "STABLE" if passing else "EXPERIMENTAL"
    report = {
        "schema_version": "1.0.0",
        "adapter_gate": "GO" if passing else "BLOCK",
        "adapter_gate_eligible": bool(passing),
        "release_verdict": "READY" if passing else "NOT_READY",
        "policy": {
            "required_maturity": "STABLE",
            "minimum_cases": 3,
            "required_adapters": [{"adapter_id": "gs343"}, {"adapter_id": "r2d2"}],
        },
        "records": [
            {
                "identity": {"adapter_id": a, "maturity": maturity},
                "quality": {
                    "adapter_id": a,
                    "passed_cases": 240 if passing else 7,
                    "total_cases": 240,
                    "critical_failures": [] if passing else ["probe_failed:3"],
                },
            }
            for a in ("gs343", "r2d2")
        ],
    }
    path = tmp_path / ("adapter-pass.json" if passing else "adapter-block.json")
    path.write_text(_json.dumps(report), encoding="utf-8")
    return path


def test_state_machine_rejects_skipped_transition(store, manifest, target, environment):
    store.register_run("cert-state", target, environment, manifest.manifest_id, manifest.digest)
    with pytest.raises(ValueError, match="illegal run-state transition"):
        store.transition_state(
            "cert-state", target.tenant_id, RunState.EXECUTING_TESTS,
            "orchestrator", "skip", "workflow-v1",
        )


def test_state_machine_persists_legal_transition(store, manifest, target, environment):
    store.register_run("cert-state", target, environment, manifest.manifest_id, manifest.digest)
    store.transition_state(
        "cert-state", target.tenant_id, RunState.QUEUED,
        "orchestrator", "accepted", "workflow-v1",
    )
    assert store.get_run("cert-state", target.tenant_id)["state"] == "QUEUED"


def test_api_requires_tenant_and_hides_cross_tenant_run(store, manifest, target, environment):
    store.register_run("cert-api", target, environment, manifest.manifest_id, manifest.digest)
    app = create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty()))
    client = TestClient(app)
    assert client.get("/v1/certifications/cert-api").status_code == 401
    assert client.get(
        "/v1/certifications/cert-api", headers={"X-Tenant-ID": "tenant-other"}
    ).status_code == 404
    response = client.get(
        "/v1/certifications/cert-api", headers={"X-Tenant-ID": target.tenant_id}
    )
    assert response.status_code == 200
    assert response.json()["run_id"] == "cert-api"


def test_health_truthfully_reports_completed_p8c_and_remaining_product_gate(store, manifest):
    app = create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty()))
    client = TestClient(app)
    response = client.get("/v1/status")
    assert response.status_code == 200
    body = response.json()
    assert body["completed_phase_gate"] == "P8C"
    assert body["release_verdict"] == "NOT_READY"
    assert body["evidence_custody"] == "P3_APPEND_ONLY_VERIFIED"
    assert body["external_evidence_anchor"] == "P3_INDEPENDENT_PROVIDER_VERIFIED"
    assert body["verdict_signing"] == "P3_ISOLATED_SIGNER_VERIFIED"
    assert body["public_key_lifecycle"] == "P3_ROTATION_REVOCATION_VERIFIED"
    assert body["runner_isolation"] == "P2_FOUNDATION_VERIFIED"
    assert "PRODUCTION_READY" in body["release_verdicts"]


def test_required_adapter_status_publishes_customer_environment(store, manifest):
    environment = {
        "certification_environment_identity_digest": "a" * 64,
        "runner_image_digest": "sha256:" + "b" * 64,
        "adapter_set_sha256": "c" * 64,
        "adapter_execution_profile_sha256": "d" * 64,
    }
    app = create_app(
        ServiceContext(
            store,
            manifest,
            TrustedPublicKeyRegistry.empty(),
            adapter_mode="required",
            certification_environment=environment,
        )
    )

    body = TestClient(app).get("/v1/status").json()

    assert body["adapter_qualification"] == "REQUIRED"
    assert {key: body[key] for key in environment} == environment


def test_status_promotes_only_from_signed_exact_source_product_report(
    store, manifest, tmp_path
):
    signer = Ed25519VerdictSigner.generate()
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    now = datetime.now(UTC)
    gates = {
        name: {"state": "COMPLETE", "evidence_sha256": sha256_bytes(name.encode())}
        for name in (
            "P1", "P2", "P3", "P4", "P5", "P6", "P7", "SDK", "CI", "MASTER"
        )
    }
    master_run = {
        "run_id": "master-status",
        "run_outcome": "COMPLETE",
        "target_release_verdict": "NOT_READY",
        "signed_verdict_verified": True,
        "evidence_chain_verified": True,
        "sandbox_isolation": "docker",
        "requirements_passed": True,
        "rerun_command": "python scripts/master_acceptance.py --verify",
    }
    envelope = create_product_readiness_envelope(
        signer=signer,
        source_commit="a" * 40,
        source_tree_sha256="b" * 64,
        generated_at=to_utc_iso(now),
        expires_at=to_utc_iso(now + timedelta(days=30)),
        gates=gates,
        master_run=master_run,
    )
    report = tmp_path / "product-readiness.json"
    report.write_text(json.dumps(asdict(envelope)), encoding="utf-8")
    app = create_app(
        ServiceContext(
            store,
            manifest,
            trusted,
            product_readiness_report_path=report,
            source_commit="a" * 40,
            adapter_acceptance_report_path=_adapter_report(tmp_path, passing=True),
        )
    )

    body = TestClient(app).get("/v1/status").json()

    assert body["release_verdict"] == "PRODUCTION_READY"
    assert body["product_readiness_reason"] == "signed_exact_source_acceptance_verified"
    assert body["source_commit"] == "a" * 40

    # NEGATIVE CONTROL (P0 #26804 acceptance): identical signed report, identical source commit,
    # only the adapter evidence degraded to what is actually committed today (EXPERIMENTAL /
    # partial cases). /v1/status MUST refuse to promote. Before this gate existed the endpoint
    # returned PRODUCTION_READY here, because the verdict was read out of the signed payload
    # rather than derived from evidence.
    blocked_app = create_app(
        ServiceContext(
            store,
            manifest,
            trusted,
            product_readiness_report_path=report,
            source_commit="a" * 40,
            adapter_acceptance_report_path=_adapter_report(tmp_path, passing=False),
        )
    )
    blocked = TestClient(blocked_app).get("/v1/status").json()
    assert blocked["release_verdict"] == "NOT_READY", (
        "status promoted despite EXPERIMENTAL adapter evidence -- the adapter gate is not wired "
        "into the live verdict path"
    )
    assert blocked["product_readiness_reason"].startswith("adapter_qualification_failed:")

    # Unconfigured adapter evidence must also block: a deployment that forgets to point at the
    # report must not publish PRODUCTION_READY over evidence nobody read.
    unset_app = create_app(
        ServiceContext(
            store,
            manifest,
            trusted,
            product_readiness_report_path=report,
            source_commit="a" * 40,
        )
    )
    unset = TestClient(unset_app).get("/v1/status").json()
    assert unset["release_verdict"] == "NOT_READY"
