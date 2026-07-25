from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.adapter_execution import (
    AdapterBundleTrustBinding,
    AdapterEvidenceSource,
    AdapterExecutionError,
    adapter_bundle_body,
    build_acceptance_report,
    build_records_from_evidence,
    default_p5_policy,
    external_trust_pins_digest,
    load_json,
    policy_to_json,
    r5_trust_pins_digest,
    sign_adapter_bundle,
    write_adapter_execution_artifacts,
)
from echo_certification_forge.adapter_transport import parse_verified_adapter_bundle
from echo_certification_forge.adapters import AdapterMaturity, adapter_set_digest
from echo_certification_forge.canonical import sha256_bytes, sha256_json
from echo_certification_forge.p5_qualification import (
    QualificationArtifactDigests,
    QualificationEvidenceTrustPins,
    TrustedRoutingKey,
    run_qualification,
)
from echo_certification_forge.family_r5 import execute as execute_r5
from echo_certification_forge.evidence import merkle_root
from echo_certification_forge.runner import RunnerEphemeralIdentity
from echo_certification_forge.run_worker import _load_adapter_inputs
from test_family_r5 import FakeFamilyTransport, expected as expected_r5
from test_p5_qualification import (
    FakeQualificationTransport,
    GS_CANDIDATE,
    R2_CANDIDATE,
    _artifact_digest,
    _config,
    _qualification_trust,
)

GS_ARTIFACT_DIGEST = _artifact_digest(GS_CANDIDATE)
R2_ARTIFACT_DIGEST = _artifact_digest(R2_CANDIDATE)


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
    wrong_model: str,
    wrong_digest: str,
    maturity: str = "STABLE",
    private_key: Ed25519PrivateKey | None = None,
) -> Path:
    private_key = private_key or Ed25519PrivateKey.generate()
    transport = FakeFamilyTransport(
        private_key=private_key,
        target=model,
        wrong=wrong_model,
        target_digest=adapter_digest,
        wrong_digest=wrong_digest,
        maturity=maturity,
    )
    report = execute_r5(
        expected_r5(transport),
        transport=transport,
        evidence_directory=root,
    )
    assert report["r5_gate"] == "PASS"
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
    gs_key = Ed25519PrivateKey.generate()
    r2_key = Ed25519PrivateKey.generate()
    gs = make_r5_evidence(
        tmp_path / "gs-r5",
        model=GS_CANDIDATE,
        adapter_digest=GS_ARTIFACT_DIGEST,
        wrong_model=R2_CANDIDATE,
        wrong_digest=R2_ARTIFACT_DIGEST,
        maturity=gs_maturity,
        private_key=gs_key,
    )
    r2 = make_r5_evidence(
        tmp_path / "r2-r5",
        model=R2_CANDIDATE,
        adapter_digest=R2_ARTIFACT_DIGEST,
        wrong_model=GS_CANDIDATE,
        wrong_digest=GS_ARTIFACT_DIGEST,
        maturity=r2_maturity,
        private_key=r2_key,
    )
    return (
        AdapterEvidenceSource(
            "gs343",
            GS_CANDIDATE,
            gs,
            "gs_adapter_v2_context",
            TrustedRoutingKey(public_key_pem(gs_key), key_id(gs_key)),
        ),
        AdapterEvidenceSource(
            "r2d2",
            R2_CANDIDATE,
            r2,
            "r2_adapter_context",
            TrustedRoutingKey(public_key_pem(r2_key), key_id(r2_key)),
        ),
    )


@pytest.fixture(scope="module")
def complete_qualification(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("adapter-execution-qualification")
    transport = FakeQualificationTransport(request_prefix="adapter-execution")
    config = _config(root, transport)
    report = run_qualification(config, transport=transport)
    assert report["promotion_decision"] == "PROMOTE"
    return report, _qualification_trust(config, transport)


def build_records(
    selected: tuple[AdapterEvidenceSource, ...],
    report: dict[str, Any],
    trust: QualificationEvidenceTrustPins,
):
    return build_records_from_evidence(
        selected,
        qualification_report=report,
        qualification_trust_pins=trust,
    )


def trust_binding(
    selected: tuple[AdapterEvidenceSource, ...],
    trust: QualificationEvidenceTrustPins,
    policy,
    runner: RunnerEphemeralIdentity,
) -> AdapterBundleTrustBinding:
    return AdapterBundleTrustBinding(
        registry_id="test-adapter-registry",
        runner_key_id=runner.key_id,
        policy_id="test-adapter-policy",
        policy_sha256=sha256_json(policy_to_json(policy)),
        qualification_trust_pins_sha256=trust.digest,
        r5_trust_pins_sha256=r5_trust_pins_digest(selected),
        external_trust_pins_sha256=external_trust_pins_digest(trust, selected),
    )


def dummy_binding() -> AdapterBundleTrustBinding:
    return AdapterBundleTrustBinding(
        registry_id="test-adapter-registry",
        runner_key_id="ed25519:" + "0" * 32,
        policy_id="test-adapter-policy",
        policy_sha256="1" * 64,
        qualification_trust_pins_sha256="2" * 64,
        r5_trust_pins_sha256="3" * 64,
        external_trust_pins_sha256="4" * 64,
    )


def reseal_r5_manifest(directory: Path) -> None:
    path = directory / "evidence-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    leaves: list[str] = []
    for entry in manifest["entries"]:
        content = (directory / entry["name"]).read_bytes()
        entry["sha256"] = sha256_bytes(content)
        entry["size_bytes"] = len(content)
        leaves.append(entry["sha256"])
    manifest["merkle_root"] = merkle_root(leaves)
    write_json(path, manifest)


def write_registry(
    path: Path,
    binding: AdapterBundleTrustBinding,
    runner_public_key_pem: str,
) -> None:
    write_json(
        path,
        {
            "schema_version": "1.0.0",
            "registry_id": binding.registry_id,
            "runner": {
                "runner_id": "anvil-adapter-runner",
                "key_id": binding.runner_key_id,
                "public_key_pem": runner_public_key_pem,
            },
            "policy": {
                "policy_id": binding.policy_id,
                "sha256": binding.policy_sha256,
            },
            "qualification_trust_pins_sha256": (
                binding.qualification_trust_pins_sha256
            ),
            "r5_trust_pins_sha256": binding.r5_trust_pins_sha256,
            "external_trust_pins_sha256": binding.external_trust_pins_sha256,
        },
    )


def test_builds_signed_gs343_r2d2_bundle_and_acceptance_report(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path)
    records = build_records(selected, qualification, trust)
    policy = default_p5_policy(records)
    runner = RunnerEphemeralIdentity.generate()
    binding = trust_binding(selected, trust, policy, runner)
    signed = sign_adapter_bundle(
        records,
        run_id="cert-p5-live",
        tenant_id="echo-sovereign",
        trust_binding=binding,
        runner_identity=runner,
    )
    parsed = parse_verified_adapter_bundle(
        signed.response,
        signed.runner_public_key_pem,
        expected_run_id="cert-p5-live",
        expected_tenant_id="echo-sovereign",
        expected_trust_roots=binding.to_dict(),
    )
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-live",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
        trust_binding=binding,
    )

    assert tuple(record.identity.adapter_id for record in parsed) == ("gs343", "r2d2")
    assert {record.identity.maturity for record in parsed} == {AdapterMaturity.STABLE}
    assert report["adapter_gate"] == "GO"
    assert report["release_verdict"] == "NOT_READY"
    assert report["adapter_set_sha256"] == adapter_set_digest(records)


def test_missing_routing_receipt_fails_closed(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path)
    write_json(selected[0].r5_evidence_directory / "positive-target.json", {"status_code": 200, "body": {}})

    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(selected, qualification, trust)


def test_r5_package_key_must_match_external_operator_pin(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path)
    operator_key = Ed25519PrivateKey.generate()
    selected = (
        replace(
            selected[0],
            trusted_routing_key=TrustedRoutingKey(
                public_key_pem(operator_key),
                key_id(operator_key),
            ),
        ),
        selected[1],
    )
    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(selected, qualification, trust)


def test_legacy_qualification_report_is_rejected(
    tmp_path: Path, complete_qualification
) -> None:
    _, trust = complete_qualification
    selected = sources(tmp_path)
    with pytest.raises(AdapterExecutionError, match="legacy qualification reports"):
        build_records(selected, qualification_report(), trust)


def test_non_stable_adapter_signs_but_acceptance_blocks(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path, gs_maturity="CONFORMANCE_PENDING")
    records = build_records(selected, qualification, trust)
    policy = default_p5_policy(records)
    runner = RunnerEphemeralIdentity.generate()
    binding = trust_binding(selected, trust, policy, runner)
    signed = sign_adapter_bundle(
        records,
        run_id="cert-p5-block",
        tenant_id="echo-sovereign",
        trust_binding=binding,
        runner_identity=runner,
    )
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-block",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
        trust_binding=binding,
    )

    assert report["adapter_gate"] == "BLOCK"
    assert "maturity_not_stable:gs343" in report["reasons"]


def test_writes_complete_verifiable_artifact_set(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path)
    records = build_records(selected, qualification, trust)
    policy = default_p5_policy(records)
    runner = RunnerEphemeralIdentity.generate()
    binding = trust_binding(selected, trust, policy, runner)
    signed = sign_adapter_bundle(
        records,
        run_id="cert-p5-artifacts",
        tenant_id="echo-sovereign",
        trust_binding=binding,
        runner_identity=runner,
    )
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-artifacts",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
        trust_binding=binding,
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


def test_worker_uses_independent_registry_and_rejects_self_keyed_bundle(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path / "sources")
    records = build_records(selected, qualification, trust)
    policy = default_p5_policy(records)
    trusted_runner = RunnerEphemeralIdentity.generate()
    binding = trust_binding(selected, trust, policy, trusted_runner)
    signed = sign_adapter_bundle(
        records,
        run_id="cert-p5-worker-registry",
        tenant_id="echo-sovereign",
        trust_binding=binding,
        runner_identity=trusted_runner,
    )
    output = tmp_path / "bundle"
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id="cert-p5-worker-registry",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
        trust_binding=binding,
    )
    write_adapter_execution_artifacts(
        output,
        signed_bundle=signed,
        acceptance_report=report,
        policy=policy,
    )
    registry = tmp_path / "trusted-adapter-registry.json"
    write_registry(registry, binding, trusted_runner.public_key_pem)

    loaded_records, loaded_policy = _load_adapter_inputs(
        response_path=output / "adapter-bundle-response.json",
        policy_path=output / "adapter-policy.json",
        registry_path=registry,
        run_id="cert-p5-worker-registry",
        tenant="echo-sovereign",
    )
    assert len(loaded_records) == 2
    assert loaded_policy == policy

    policy_path = output / "adapter-policy.json"
    original_policy = policy_path.read_text(encoding="utf-8")
    tampered_policy = json.loads(original_policy)
    tampered_policy["minimum_score"] = 0.0
    write_json(policy_path, tampered_policy)
    with pytest.raises(ValueError, match="policy differs from independent registry"):
        _load_adapter_inputs(
            response_path=output / "adapter-bundle-response.json",
            policy_path=policy_path,
            registry_path=registry,
            run_id="cert-p5-worker-registry",
            tenant="echo-sovereign",
        )
    policy_path.write_text(original_policy, encoding="utf-8")

    attacker = RunnerEphemeralIdentity.generate()
    attacker_binding = replace(binding, runner_key_id=attacker.key_id)
    attacker_bundle = sign_adapter_bundle(
        records,
        run_id="cert-p5-worker-registry",
        tenant_id="echo-sovereign",
        trust_binding=attacker_binding,
        runner_identity=attacker,
    )
    (output / "adapter-bundle-response.json").write_text(
        attacker_bundle.response.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "adapter-runner-public-key.pem").write_text(
        attacker.public_key_pem,
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="adapter_input_rejected"):
        _load_adapter_inputs(
            response_path=output / "adapter-bundle-response.json",
            policy_path=output / "adapter-policy.json",
            registry_path=registry,
            run_id="cert-p5-worker-registry",
            tenant="echo-sovereign",
        )


def test_input_container_validation_fails_closed(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
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
        adapter_bundle_body((), dummy_binding())
    with pytest.raises(AdapterExecutionError, match="without records"):
        default_p5_policy(())
    with pytest.raises(AdapterExecutionError, match="at least one adapter"):
        build_records_from_evidence(
            (),
            qualification_report=qualification,
            qualification_trust_pins=trust,
        )

    selected = sources(tmp_path / "sources")
    with pytest.raises(AdapterExecutionError, match="duplicate adapter source"):
        build_records_from_evidence(
            (selected[0], selected[0]),
            qualification_report=qualification,
            qualification_trust_pins=trust,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("blocked_r5", "R5 gate is not PASS"),
        ("target_mismatch", "R5 target model mismatch"),
        ("missing_public_key", "lacks attested public key"),
        ("missing_signature", "lacks signature_b64"),
        ("key_mismatch", "differs from external trusted key"),
        ("invalid_signature", "signature is invalid"),
    ),
)
def test_r5_evidence_tampering_fails_closed(
    tmp_path: Path,
    mutation: str,
    message: str,
    complete_qualification,
) -> None:
    qualification, trust = complete_qualification
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
        report["expected_identity"]["target_model"] = R2_CANDIDATE
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
    reseal_r5_manifest(selected[0].r5_evidence_directory)

    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(selected, qualification, trust)


def test_empty_and_replayed_r5_packages_fail_closed(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    empty = sources(tmp_path / "empty")
    write_json(
        empty[0].r5_evidence_directory / "evidence-manifest.json",
        {
            "schema": "echo.certification-forge.evidence-manifest/v1",
            "entries": [],
            "merkle_root": sha256_bytes(b""),
        },
    )
    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(empty, qualification, trust)

    replayed = sources(tmp_path / "replayed")
    target = (
        replayed[0].r5_evidence_directory / "positive-target.json"
    ).read_bytes()
    (replayed[0].r5_evidence_directory / "positive-wrong.json").write_bytes(target)
    reseal_r5_manifest(replayed[0].r5_evidence_directory)
    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(replayed, qualification, trust)


def test_unknown_maturity_fails_closed(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    records = build_records(
        sources(tmp_path / "unknown-maturity", gs_maturity="UNRECOGNIZED"),
        qualification,
        trust,
    )
    assert records[0].identity.maturity is AdapterMaturity.EXPERIMENTAL
