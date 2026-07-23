"""Whole-product P5 executor acceptance for the strict adapter rule."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from echo_certification_forge.adapters import (
    AdapterAcceptancePolicy,
    AdapterExecutionRecord,
    AdapterIdentity,
    AdapterMaturity,
    AdapterQualityReport,
    adapter_set_digest,
)
from echo_certification_forge.executor import RunExecutor, StaticEntitlement
from echo_certification_forge.models import EnvironmentIdentity
from echo_certification_forge.policy import RuleManifest
from echo_certification_forge.signing import Ed25519VerdictSigner

RUN = "cert-p5-executor"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def record(adapter_id: str, maturity: AdapterMaturity = AdapterMaturity.STABLE) -> AdapterExecutionRecord:
    identity = AdapterIdentity(
        adapter_id=adapter_id,
        version="1.0.0",
        artifact_sha256=digest(f"{adapter_id}:artifact"),
        configuration_sha256=digest(f"{adapter_id}:configuration"),
        runtime_sha256=digest(f"{adapter_id}:runtime"),
        maturity=maturity,
        provenance=f"repo:ECHO-OMEGA-PRIME/adapters/{adapter_id}@1.0.0",
    )
    return AdapterExecutionRecord(
        identity=identity,
        observed_identity_digest=identity.identity_digest,
        quality=AdapterQualityReport(
            adapter_id=adapter_id,
            passed_cases=40,
            total_cases=40,
            critical_failures=(),
            suite_sha256=digest(f"{adapter_id}:suite"),
            evidence_ids=(f"{adapter_id}-identity", f"{adapter_id}-quality"),
        ),
        execution_node="ANVIL",
        result_sha256=digest(f"{adapter_id}:result"),
    )


def policy(*records: AdapterExecutionRecord) -> AdapterAcceptancePolicy:
    return AdapterAcceptancePolicy(
        required_adapter_digests=tuple(
            (item.identity.adapter_id, item.identity.identity_digest) for item in records
        ),
        minimum_score=0.95,
        minimum_cases=20,
        required_execution_nodes=("ANVIL",),
    )


def environment(adapter_digest: str) -> EnvironmentIdentity:
    return EnvironmentIdentity(
        runner_image_sha256=digest("runner"),
        adapter_set_sha256=adapter_digest,
        test_plan_sha256=digest("test-plan"),
        policy_sha256=digest("policy-v2"),
        harness_sha256=digest("harness"),
        prompt_set_sha256=digest("prompts"),
        model_route_sha256=digest("models"),
        os_runtime_sha256=digest("os-runtime"),
        egress_policy_sha256=digest("egress"),
    )


def source(tmp_path: Path) -> Path:
    root = tmp_path / "benign"
    root.mkdir()
    (root / "hello.py").write_text("print('ok')\n", encoding="utf-8")
    return root


def manifest_v2() -> RuleManifest:
    return RuleManifest.load(Path(__file__).parents[1] / "policies" / "mandatory-rules.v2.json")


def execute(store, target, tmp_path: Path, *, records, adapter_policy, adapter_digest: str):
    manifest = manifest_v2()
    store.register_run(RUN, target, environment(adapter_digest), manifest.manifest_id, manifest.digest)
    executor = RunExecutor(store, manifest, Ed25519VerdictSigner.generate())
    return executor.execute(
        RUN,
        target.tenant_id,
        source(tmp_path),
        entitlement=StaticEntitlement(frozenset({target.tenant_id})),
        journey=[sys.executable, "hello.py"],
        control_attestations={
            "runner_control_channel": True,
            "signing_authority_separation": True,
        },
        adapter_records=records,
        adapter_policy=adapter_policy,
    )


def test_verified_stable_gs343_and_r2d2_reach_production_ready(store, target, tmp_path) -> None:
    records = (record("gs343"), record("r2d2"))

    result = execute(
        store,
        target,
        tmp_path,
        records=records,
        adapter_policy=policy(*records),
        adapter_digest=adapter_set_digest(records),
    )

    assert result.release_verdict == "PRODUCTION_READY"
    rules = store.list_rule_results(RUN, target.tenant_id)
    assert rules["adapter_identity_and_quality"].passed is True
    artifact_ids = {item["artifact_id"] for item in store.list_evidence(RUN, target.tenant_id)}
    assert f"{RUN}-adapter-gs343" in artifact_ids
    assert f"{RUN}-adapter-r2d2" in artifact_ids
    assert f"{RUN}-adapter-assessment" in artifact_ids


def test_v2_without_adapter_bundle_fails_closed(store, target, tmp_path) -> None:
    result = execute(
        store,
        target,
        tmp_path,
        records=None,
        adapter_policy=None,
        adapter_digest=digest("missing-adapters"),
    )

    assert result.release_verdict == "NOT_READY"
    rules = store.list_rule_results(RUN, target.tenant_id)
    assert rules["adapter_identity_and_quality"].passed is False


def test_non_stable_adapter_fails_closed(store, target, tmp_path) -> None:
    records = (record("gs343", AdapterMaturity.DEGRADED), record("r2d2"))

    result = execute(
        store,
        target,
        tmp_path,
        records=records,
        adapter_policy=policy(*records),
        adapter_digest=adapter_set_digest(records),
    )

    assert result.release_verdict == "NOT_READY"
    rules = store.list_rule_results(RUN, target.tenant_id)
    assert rules["adapter_identity_and_quality"].passed is False


def test_environment_adapter_set_mismatch_fails_closed(store, target, tmp_path) -> None:
    records = (record("gs343"), record("r2d2"))

    result = execute(
        store,
        target,
        tmp_path,
        records=records,
        adapter_policy=policy(*records),
        adapter_digest=digest("wrong-adapter-set"),
    )

    assert result.release_verdict == "NOT_READY"
    rules = store.list_rule_results(RUN, target.tenant_id)
    assert rules["adapter_identity_and_quality"].passed is False


def test_partial_adapter_contract_fails_closed(store, target, tmp_path) -> None:
    records = (record("gs343"), record("r2d2"))

    result = execute(
        store,
        target,
        tmp_path,
        records=records,
        adapter_policy=None,
        adapter_digest=adapter_set_digest(records),
    )

    assert result.release_verdict == "NOT_READY"
    rules = store.list_rule_results(RUN, target.tenant_id)
    assert rules["adapter_identity_and_quality"].passed is False
