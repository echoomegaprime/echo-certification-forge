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
from echo_certification_forge.adapter_transport import (
    AdapterBundleError,
    parse_verified_adapter_bundle,
)
from echo_certification_forge.adapters import AdapterMaturity, adapter_set_digest
from echo_certification_forge.canonical import sha256_bytes, sha256_json
from echo_certification_forge.p5_qualification import (
    QualificationEvidenceTrustPins,
    TrustedRoutingKey,
    run_qualification,
)
from echo_certification_forge.family_r5 import execute as execute_r5
from echo_certification_forge.evidence import merkle_root
from echo_certification_forge.runner import RunnerEphemeralIdentity
from echo_certification_forge.run_worker import (
    _load_adapter_inputs,
    load_adapter_execution_profile,
    main as run_worker_main,
)
from echo_certification_forge.run_worker import _worker_environment
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.production_launch import production_worker_args
from test_family_r5 import FakeFamilyTransport, expected as expected_r5
from test_p5_qualification import (
    FakeQualificationTransport,
    GS_CANDIDATE,
    GS_INCUMBENT,
    R2_CANDIDATE,
    R2_INCUMBENT,
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
    evidence_run_id: str,
    evidence_run_nonce: str,
) -> Path:
    private_key = private_key or Ed25519PrivateKey.generate()
    transport = FakeFamilyTransport(
        private_key=private_key,
        target=model,
        wrong=wrong_model,
        target_digest=adapter_digest,
        wrong_digest=wrong_digest,
        maturity=maturity,
        requested_models=[
            GS_CANDIDATE,
            GS_INCUMBENT,
            R2_CANDIDATE,
            R2_INCUMBENT,
        ],
    )
    report = execute_r5(
        expected_r5(transport),
        evidence_run_id=evidence_run_id,
        evidence_run_nonce=evidence_run_nonce,
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
        evidence_run_id="test-gs343-r5-run",
        evidence_run_nonce="test-gs343-r5-run-nonce-01",
    )
    r2 = make_r5_evidence(
        tmp_path / "r2-r5",
        model=R2_CANDIDATE,
        adapter_digest=R2_ARTIFACT_DIGEST,
        wrong_model=GS_CANDIDATE,
        wrong_digest=GS_ARTIFACT_DIGEST,
        maturity=r2_maturity,
        private_key=r2_key,
        evidence_run_id="test-r2d2-r5-run",
        evidence_run_nonce="test-r2d2-r5-run-nonce-01",
    )
    return (
        AdapterEvidenceSource(
            "gs343",
            GS_CANDIDATE,
            gs,
            "gs_adapter_v2_context",
            TrustedRoutingKey(public_key_pem(gs_key), key_id(gs_key)),
            "test-gs343-r5-run",
            "test-gs343-r5-run-nonce-01",
        ),
        AdapterEvidenceSource(
            "r2d2",
            R2_CANDIDATE,
            r2,
            "r2_adapter_context",
            TrustedRoutingKey(public_key_pem(r2_key), key_id(r2_key)),
            "test-r2d2-r5-run",
            "test-r2d2-r5-run-nonce-01",
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
        r5_trust_pins_sha256=r5_trust_pins_digest(
            selected,
            trust.deployment_identity.to_dict(),
        ),
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
    reusable_response,
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
            "reusable_bundle": {
                "run_id": reusable_response.run_id,
                "tenant_id": reusable_response.tenant_id,
                "sha256": sha256_json(
                    reusable_response.model_dump(mode="json")
                ),
            },
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
    trusted_private_key = Ed25519PrivateKey.generate()
    trusted_runner = RunnerEphemeralIdentity(trusted_private_key)
    signing_key_path = tmp_path / "adapter-runner-signing-key.pem"
    signing_key_path.write_bytes(
        trusted_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
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
    write_registry(
        registry,
        binding,
        trusted_runner.public_key_pem,
        signed.response,
    )

    loaded_records, loaded_policy, rebound = _load_adapter_inputs(
        response_path=output / "adapter-bundle-response.json",
        policy_path=output / "adapter-policy.json",
        registry_path=registry,
        runner_signing_key_path=signing_key_path,
        run_id="cert-p5-production-new",
        tenant="echo-sovereign",
    )
    assert len(loaded_records) == 2
    assert loaded_policy == policy
    assert rebound.run_id == "cert-p5-production-new"
    assert rebound.request_id == "cert-p5-production-new-adapter-request"
    public_records, public_policy, public_response, profile_sha256 = (
        load_adapter_execution_profile(
            response_path=output / "adapter-bundle-response.json",
            policy_path=output / "adapter-policy.json",
            registry_path=registry,
        )
    )
    assert public_records == loaded_records
    assert public_policy == loaded_policy
    assert public_response.run_id == "cert-p5-worker-registry"
    assert profile_sha256 == sha256_json(rebound.body)
    _, _, repeated = _load_adapter_inputs(
        response_path=output / "adapter-bundle-response.json",
        policy_path=output / "adapter-policy.json",
        registry_path=registry,
        runner_signing_key_path=signing_key_path,
        run_id="cert-p5-production-new",
        tenant="echo-sovereign",
    )
    assert repeated.model_dump(mode="json") == rebound.model_dump(mode="json")
    _, _, second_rebound = _load_adapter_inputs(
        response_path=output / "adapter-bundle-response.json",
        policy_path=output / "adapter-policy.json",
        registry_path=registry,
        runner_signing_key_path=signing_key_path,
        run_id="cert-p5-production-second",
        tenant="echo-sovereign",
    )
    assert second_rebound.run_id == "cert-p5-production-second"
    with pytest.raises(AdapterBundleError, match="run or tenant mismatch"):
        parse_verified_adapter_bundle(
            rebound,
            trusted_runner.public_key_pem,
            expected_run_id="cert-p5-production-second",
            expected_tenant_id="echo-sovereign",
            expected_trust_roots=binding.to_dict(),
        )

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
            runner_signing_key_path=signing_key_path,
            run_id="cert-p5-production-new",
            tenant="echo-sovereign",
        )
    policy_path.write_text(original_policy, encoding="utf-8")

    attacker = RunnerEphemeralIdentity.generate()
    attacker_private = Ed25519PrivateKey.generate()
    signing_key_path.write_bytes(
        attacker_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="signing key differs"):
        _load_adapter_inputs(
            response_path=output / "adapter-bundle-response.json",
            policy_path=output / "adapter-policy.json",
            registry_path=registry,
            runner_signing_key_path=signing_key_path,
            run_id="cert-p5-production-new",
            tenant="echo-sovereign",
        )
    signing_key_path.write_bytes(
        trusted_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

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
            runner_signing_key_path=signing_key_path,
            run_id="cert-p5-production-new",
            tenant="echo-sovereign",
        )


def test_production_router_arguments_rebind_bundle_and_reach_worker_execution(
    tmp_path: Path,
    complete_qualification,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    qualification, trust = complete_qualification
    selected = sources(tmp_path / "sources")
    records = build_records(selected, qualification, trust)
    policy = default_p5_policy(records)
    adapter_private_key = Ed25519PrivateKey.generate()
    adapter_runner = RunnerEphemeralIdentity(adapter_private_key)
    adapter_key_path = tmp_path / "adapter-runner-signing-key.pem"
    adapter_key_path.write_bytes(
        adapter_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    binding = trust_binding(selected, trust, policy, adapter_runner)
    reusable = sign_adapter_bundle(
        records,
        run_id="reusable-qualified-adapter-set",
        tenant_id="echo-sovereign",
        trust_binding=binding,
        runner_identity=adapter_runner,
    )
    artifacts = tmp_path / "p5"
    acceptance = build_acceptance_report(
        reusable.response,
        reusable.runner_public_key_pem,
        run_id="reusable-qualified-adapter-set",
        tenant_id="echo-sovereign",
        policy=policy,
        expected_adapter_set_sha256=reusable.adapter_set_sha256,
        trust_binding=binding,
    )
    write_adapter_execution_artifacts(
        artifacts,
        signed_bundle=reusable,
        acceptance_report=acceptance,
        policy=policy,
    )
    registry = artifacts / "trusted-adapter-registry.json"
    write_registry(
        registry,
        binding,
        adapter_runner.public_key_pem,
        reusable.response,
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.txt").write_text("certification target", encoding="utf-8")
    run_id = "production-router-worker-e2e"
    args = production_worker_args(
        run_id=run_id,
        tenant="echo-sovereign",
        target={"type": "local", "path": str(target)},
        journey=None,
        policy_id="certforge.release-strict.v2",
        adapter_response=artifacts / "adapter-bundle-response.json",
        adapter_policy=artifacts / "adapter-policy.json",
        adapter_registry=registry,
        adapter_runner_signing_key=adapter_key_path,
    )
    db_path = tmp_path / "certforge.sqlite3"
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("ECHO_CERTFORGE_DB", str(db_path))
    monkeypatch.setenv("ECHO_CERTFORGE_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv(
        "ECHO_CERTFORGE_POLICY",
        str(Path(__file__).parents[1] / "policies" / "mandatory-rules.v2.json"),
    )
    monkeypatch.setenv(
        "ECHO_CERTFORGE_RUN_SIGNING_KEY",
        str(tmp_path / "run-signing-key.pem"),
    )
    monkeypatch.setenv("ECHO_CERTFORGE_ENTITLED_TENANTS", "echo-sovereign")
    monkeypatch.setenv("ECHO_CERTFORGE_WORK_ROOT", str(tmp_path / "workspaces"))
    assert run_worker_main(args) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["adapter_bundle_response_sha256"]
    assert result["signed"] is True
    expected_environment = _worker_environment(
        adapter_set_digest(records),
        result["adapter_execution_profile_sha256"],
    )
    assert result["environment_identity_digest"] == expected_environment.identity_digest
    store = EvidenceStore(db_path, evidence_root)
    adapter_artifact = next(
        item
        for item in store.list_evidence(run_id, "echo-sovereign")
        if item["artifact_id"]
        == "adapter-response-" + sha256_bytes(run_id.encode("utf-8"))[:32]
    )
    assert adapter_artifact["sha256"] == result["adapter_bundle_response_sha256"]
    assert store.verify_evidence(run_id, "echo-sovereign").valid is True

    second_run_id = "production-router-worker-e2e-second"
    second_args = production_worker_args(
        run_id=second_run_id,
        tenant="echo-sovereign",
        target={"type": "local", "path": str(target)},
        journey=None,
        policy_id="certforge.release-strict.v2",
        adapter_response=artifacts / "adapter-bundle-response.json",
        adapter_policy=artifacts / "adapter-policy.json",
        adapter_registry=registry,
        adapter_runner_signing_key=adapter_key_path,
    )
    assert run_worker_main(second_args) == 0
    second_result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    second_artifact = next(
        item
        for item in store.list_evidence(second_run_id, "echo-sovereign")
        if item["source_component"] == "run-worker"
    )
    assert second_artifact["sha256"] == second_result["adapter_bundle_response_sha256"]
    assert second_artifact["artifact_id"] != adapter_artifact["artifact_id"]
    assert (
        second_result["adapter_execution_profile_sha256"]
        == result["adapter_execution_profile_sha256"]
    )
    assert second_result["environment_identity_digest"] == result["environment_identity_digest"]
    assert second_result["adapter_bundle_response_sha256"] != result["adapter_bundle_response_sha256"]
    assert store.verify_evidence(second_run_id, "echo-sovereign").valid is True


def test_production_worker_rejects_v1_manifest_without_adapters(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "hello.txt").write_text("hello", encoding="utf-8")
    result = run_worker_main(
        [
            "--run-id",
            "production-v1-bypass",
            "--tenant",
            "echo-sovereign",
            "--target-json",
            json.dumps({"type": "local", "path": str(target)}),
            "--policy",
            str(Path(__file__).parents[1] / "policies" / "mandatory-rules.v1.json"),
        ]
    )
    assert result == 2


def test_production_worker_rejects_copied_v2_rule_in_unpinned_manifest(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "policies" / "mandatory-rules.v2.json"
    manifest = json.loads(source.read_text(encoding="utf-8"))
    adapter_rule = next(
        rule for rule in manifest["rules"] if rule["id"] == "adapter_identity_and_quality"
    )
    adapter_rule["description"] = "attacker copied the rule but changed the manifest"
    attacker_manifest = tmp_path / "attacker-v2.json"
    write_json(attacker_manifest, manifest)
    target = tmp_path / "target"
    target.mkdir()
    result = run_worker_main(
        [
            "--run-id",
            "production-manifest-copy",
            "--tenant",
            "echo-sovereign",
            "--target-json",
            json.dumps({"type": "local", "path": str(target)}),
            "--policy",
            str(attacker_manifest),
        ]
    )
    assert result == 2


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

    fifth = sources(tmp_path / "fifth-alias")
    attestation_path = fifth[0].r5_evidence_directory / "attestation.json"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["requested_models"].append("echo-unapproved-fifth")
    write_json(attestation_path, attestation)
    reseal_r5_manifest(fifth[0].r5_evidence_directory)
    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(fifth, qualification, trust)


def test_mixed_r5_run_receipt_splice_fails_closed(
    tmp_path: Path, complete_qualification
) -> None:
    qualification, trust = complete_qualification
    key = Ed25519PrivateKey.generate()
    first = make_r5_evidence(
        tmp_path / "first-run",
        model=GS_CANDIDATE,
        adapter_digest=GS_ARTIFACT_DIGEST,
        wrong_model=R2_CANDIDATE,
        wrong_digest=R2_ARTIFACT_DIGEST,
        private_key=key,
        evidence_run_id="external-r5-run-one",
        evidence_run_nonce="external-r5-run-one-nonce",
    )
    second = make_r5_evidence(
        tmp_path / "second-run",
        model=GS_CANDIDATE,
        adapter_digest=GS_ARTIFACT_DIGEST,
        wrong_model=R2_CANDIDATE,
        wrong_digest=R2_ARTIFACT_DIGEST,
        private_key=key,
        evidence_run_id="external-r5-run-two",
        evidence_run_nonce="external-r5-run-two-nonce",
    )
    (first / "wrong-active-response.json").write_bytes(
        (second / "wrong-active-response.json").read_bytes()
    )
    reseal_r5_manifest(first)
    r2_source = sources(tmp_path / "r2-source")[1]
    selected = (
        AdapterEvidenceSource(
            "gs343",
            GS_CANDIDATE,
            first,
            "gs_adapter_context",
            TrustedRoutingKey(public_key_pem(key), key_id(key)),
            "external-r5-run-one",
            "external-r5-run-one-nonce",
        ),
        r2_source,
    )
    with pytest.raises(AdapterExecutionError, match="R5 full evidence rejected"):
        build_records(selected, qualification, trust)


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
