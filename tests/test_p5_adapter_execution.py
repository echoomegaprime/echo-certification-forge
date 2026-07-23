from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.adapter_execution import (
    AdapterEvidenceSource,
    AdapterExecutionError,
    adapter_bundle_body,
    build_acceptance_report,
    build_records_from_evidence,
    default_p5_policy,
    load_json,
    sign_adapter_bundle,
    write_adapter_execution_artifacts,
)
from echo_certification_forge.adapter_transport import parse_verified_adapter_bundle
from echo_certification_forge.adapters import AdapterMaturity, adapter_set_digest
from echo_certification_forge.canonical import canonical_json, sha256_bytes, sha256_json


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def key_id(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return f"ed25519:{sha256_bytes(raw)[:32]}"


def public_key_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def make_r5_evidence(
    root: Path,
    *,
    model: str,
    adapter_digest: str,
    maturity: str = "STABLE",
    private_key: Ed25519PrivateKey | None = None,
) -> Path:
    private_key = private_key or Ed25519PrivateKey.generate()
    key = key_id(private_key)
    root.mkdir(parents=True)
    payload = {
        "schema": "echo.family-routing-receipt/v1",
        "request_id": f"request-{model}",
        "challenge_nonce": f"challenge-{model}",
        "request_sha256": sha256_bytes(canonical_json({"model": model}).encode()),
        "requested_model": model,
        "requested_persona": model.removeprefix("echo-"),
        "registry_adapter_id": model,
        "selected_adapter_id": model,
        "selected_adapter_digest": adapter_digest,
        "adapter_version": "v-test",
        "maturity_state": maturity,
        "persona_enabled": True,
        "routing_mode": "lora_adapter",
        "adapter_applied": True,
        "persona_applied": True,
        "active_adapter_ids": [model],
        "active_adapter_ids_before": [model],
        "active_adapter_ids_after": [model],
        "server_build_digest": sha256_bytes(f"{model}:server".encode()),
        "registry_snapshot_digest": sha256_bytes(f"{model}:registry".encode()),
        "registry_revision": f"registry-{model}",
        "fallback_used": False,
        "fallback_reason": None,
        "base_model_id": "echo-prime",
        "base_model_revision": "base-r5",
        "base_model_digest": sha256_bytes(b"base"),
        "slot_lease_id": f"slot-{model}",
        "started_at": "2026-07-23T00:00:00Z",
        "completed_at": "2026-07-23T00:00:01Z",
        "signature_key_id": key,
        "response_sha256": sha256_bytes(f"positive-{model}".encode()),
        "response_size_bytes": len(f"positive-{model}".encode()),
    }
    signature = private_key.sign(canonical_json(payload).encode("utf-8"))
    receipt = {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_id": key,
    }
    write_json(
        root / "r5-report.json",
        {
            "r5_gate": "PASS",
            "run_outcome": "COMPLETE",
            "expected_identity": {"target_model": model},
            "forge_verification_bundle": {
                "public_key_pem": public_key_pem(private_key),
                "attested_key_id": key,
            },
        },
    )
    write_json(root / "positive-target.json", {"status_code": 200, "body": {"routing_receipt": receipt}})
    write_json(root / "evidence-manifest.json", {"entries": [], "merkle_root": sha256_bytes(b"")})
    return root


def qualification_report(*, gs_go: bool = True, r2_go: bool = True) -> dict[str, Any]:
    def mode(mode_name: str, go: bool, count: int) -> tuple[dict[str, Any], dict[str, Any]]:
        probes = [{"probe": f"{mode_name}-{index}", "passed": go} for index in range(count)]
        return (
            {
                "content_gate_passed": go,
                "routing_gate_passed": go,
                "integration_verdict": "GO" if go else "NEEDS_RETRAIN_OR_ROUTING_PROOF",
            },
            {"probe_results": probes},
        )

    gs_qualification, gs_score = mode("gs", gs_go, 25)
    r2_qualification, r2_score = mode("r2", r2_go, 25)
    return {
        "schema_version": "1.0.0",
        "qualification": {
            "gs_adapter_v2_context": gs_qualification,
            "r2_adapter_context": r2_qualification,
        },
        "mode_scores": {
            "gs_adapter_v2_context": gs_score,
            "r2_adapter_context": r2_score,
        },
    }


def sources(tmp_path: Path, *, gs_maturity: str = "STABLE", r2_maturity: str = "STABLE"):
    gs = make_r5_evidence(
        tmp_path / "gs-r5",
        model="echo-gs343",
        adapter_digest=sha256_bytes(b"gs343-adapter"),
        maturity=gs_maturity,
    )
    r2 = make_r5_evidence(
        tmp_path / "r2-r5",
        model="echo-r2d2",
        adapter_digest=sha256_bytes(b"r2d2-adapter"),
        maturity=r2_maturity,
    )
    return (
        AdapterEvidenceSource("gs343", "echo-gs343", gs, "gs_adapter_v2_context"),
        AdapterEvidenceSource("r2d2", "echo-r2d2", r2, "r2_adapter_context"),
    )


def test_builds_signed_gs343_r2d2_bundle_and_acceptance_report(tmp_path: Path) -> None:
    records = build_records_from_evidence(sources(tmp_path), qualification_report=qualification_report())

    signed = sign_adapter_bundle(records, run_id="cert-p5-live", tenant_id="echo-sovereign")
    parsed = parse_verified_adapter_bundle(
        signed.response,
        signed.runner_public_key_pem,
        expected_run_id="cert-p5-live",
        expected_tenant_id="echo-sovereign",
    )
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-live",
        tenant_id="echo-sovereign",
        policy=default_p5_policy(records),
        expected_adapter_set_sha256=signed.adapter_set_sha256,
    )

    assert tuple(record.identity.adapter_id for record in parsed) == ("gs343", "r2d2")
    assert {record.identity.maturity for record in parsed} == {AdapterMaturity.STABLE}
    assert report["adapter_gate"] == "GO"
    assert report["release_verdict"] == "NOT_READY"
    assert report["adapter_set_sha256"] == adapter_set_digest(records)


def test_missing_routing_receipt_fails_closed(tmp_path: Path) -> None:
    selected = sources(tmp_path)
    write_json(selected[0].r5_evidence_directory / "positive-target.json", {"status_code": 200, "body": {}})

    with pytest.raises(AdapterExecutionError, match="routing_receipt"):
        build_records_from_evidence(selected, qualification_report=qualification_report())


def test_failed_quality_is_emitted_and_acceptance_blocks(tmp_path: Path) -> None:
    records = build_records_from_evidence(
        sources(tmp_path),
        qualification_report=qualification_report(gs_go=False),
    )
    signed = sign_adapter_bundle(records, run_id="cert-p5-quality-block", tenant_id="echo-sovereign")
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-quality-block",
        tenant_id="echo-sovereign",
        policy=default_p5_policy(records),
        expected_adapter_set_sha256=signed.adapter_set_sha256,
    )

    assert records[0].quality.score == 0.0
    assert records[0].quality.critical_failures
    assert report["adapter_gate"] == "BLOCK"
    assert "critical_quality_failure:gs343" in report["reasons"]
    assert "quality_below_threshold:gs343" in report["reasons"]


def test_non_stable_adapter_signs_but_acceptance_blocks(tmp_path: Path) -> None:
    records = build_records_from_evidence(
        sources(tmp_path, gs_maturity="CONFORMANCE_PENDING"),
        qualification_report=qualification_report(),
    )
    signed = sign_adapter_bundle(records, run_id="cert-p5-block", tenant_id="echo-sovereign")
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-block",
        tenant_id="echo-sovereign",
        policy=default_p5_policy(records),
        expected_adapter_set_sha256=signed.adapter_set_sha256,
    )

    assert report["adapter_gate"] == "BLOCK"
    assert "maturity_not_stable:gs343" in report["reasons"]


def test_writes_complete_verifiable_artifact_set(tmp_path: Path) -> None:
    records = build_records_from_evidence(sources(tmp_path), qualification_report=qualification_report())
    signed = sign_adapter_bundle(records, run_id="cert-p5-artifacts", tenant_id="echo-sovereign")
    policy = default_p5_policy(records)
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-artifacts",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
    )
    output = tmp_path / "bundle"

    write_adapter_execution_artifacts(
        output,
        signed_bundle=signed,
        acceptance_report=report,
        policy=policy,
    )

    assert json.loads((output / "adapter-acceptance-report.json").read_text())["adapter_gate"] == "GO"
    assert json.loads((output / "adapter-policy.json").read_text())["required_maturity"] == "STABLE"
    assert json.loads((output / "adapter-bundle-response.json").read_text())["status"] == "COMPLETED"
    assert (output / "adapter-runner-public-key.pem").read_text() == signed.runner_public_key_pem


def test_input_container_validation_fails_closed(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")

    for path in (tmp_path / "missing.json", invalid):
        with pytest.raises(AdapterExecutionError, match="unreadable JSON evidence"):
            load_json(path)
    with pytest.raises(AdapterExecutionError, match="must be an object"):
        load_json(array)
    with pytest.raises(AdapterExecutionError, match="at least one record"):
        adapter_bundle_body(())
    with pytest.raises(AdapterExecutionError, match="without records"):
        default_p5_policy(())
    with pytest.raises(AdapterExecutionError, match="at least one adapter"):
        build_records_from_evidence((), qualification_report={})

    selected = sources(tmp_path / "sources")
    with pytest.raises(AdapterExecutionError, match="duplicate adapter source"):
        build_records_from_evidence((selected[0], selected[0]), qualification_report=qualification_report())


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("blocked_r5", "R5 gate is not PASS"),
        ("target_mismatch", "R5 target model mismatch"),
        ("missing_public_key", "lacks attested public key"),
        ("missing_signature", "lacks signature_b64"),
        ("key_mismatch", "key does not match attestation"),
        ("invalid_signature", "signature is invalid"),
    ),
)
def test_r5_evidence_tampering_fails_closed(tmp_path: Path, mutation: str, message: str) -> None:
    root = tmp_path / mutation
    root.mkdir()
    selected = sources(root)
    report_path = selected[0].r5_evidence_directory / "r5-report.json"
    positive_path = selected[0].r5_evidence_directory / "positive-target.json"
    report = load_json(report_path)
    positive = load_json(positive_path)

    if mutation == "blocked_r5":
        report["r5_gate"] = "BLOCK"
    elif mutation == "target_mismatch":
        report["expected_identity"]["target_model"] = "echo-r2d2"
    elif mutation == "missing_public_key":
        report["forge_verification_bundle"]["public_key_pem"] = None
    elif mutation == "missing_signature":
        positive["body"]["routing_receipt"]["signature_b64"] = None
    elif mutation == "key_mismatch":
        positive["body"]["routing_receipt"]["key_id"] = "ed25519:" + "0" * 32
    elif mutation == "invalid_signature":
        positive["body"]["routing_receipt"]["signature_b64"] = base64.b64encode(b"bad").decode()
    write_json(report_path, report)
    write_json(positive_path, positive)

    with pytest.raises(AdapterExecutionError, match=message):
        build_records_from_evidence(selected, qualification_report=qualification_report())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("integration_verdict", "UNKNOWN", "invalid integration verdict"),
        ("content_gate_passed", None, "must be boolean"),
    ),
)
def test_malformed_qualification_fails_closed(
    tmp_path: Path,
    field: str,
    value: Any,
    message: str,
) -> None:
    report = qualification_report()
    report["qualification"]["gs_adapter_v2_context"][field] = value

    with pytest.raises(AdapterExecutionError, match=message):
        build_records_from_evidence(sources(tmp_path), qualification_report=report)


def test_empty_probe_evidence_and_unknown_maturity_fail_closed(tmp_path: Path) -> None:
    report = qualification_report()
    report["mode_scores"]["gs_adapter_v2_context"]["probe_results"] = []
    with pytest.raises(AdapterExecutionError, match="must be non-empty"):
        build_records_from_evidence(sources(tmp_path / "empty-probes"), qualification_report=report)

    records = build_records_from_evidence(
        sources(tmp_path / "unknown-maturity", gs_maturity="UNRECOGNIZED"),
        qualification_report=qualification_report(),
    )
    assert records[0].identity.maturity is AdapterMaturity.EXPERIMENTAL
