from __future__ import annotations

from dataclasses import replace

import pytest

from echo_certification_forge.adapters import (
    AdapterAcceptancePolicy,
    AdapterExecutionRecord,
    AdapterIdentity,
    AdapterMaturity,
    AdapterQualityReport,
    adapter_set_digest,
    evaluate_adapter_acceptance,
)


def digest(ch: str) -> str:
    return ch * 64


def identity(
    adapter_id: str,
    *,
    artifact: str,
    configuration: str,
    runtime: str,
    maturity: AdapterMaturity = AdapterMaturity.STABLE,
) -> AdapterIdentity:
    return AdapterIdentity(
        adapter_id=adapter_id,
        version="1.0.0",
        artifact_sha256=digest(artifact),
        configuration_sha256=digest(configuration),
        runtime_sha256=digest(runtime),
        maturity=maturity,
        provenance=f"repo:ECHO-OMEGA-PRIME/adapters/{adapter_id}@1.0.0",
    )


def record(
    adapter_identity: AdapterIdentity,
    *,
    passed: int = 40,
    total: int = 40,
    critical_failures: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] | None = None,
) -> AdapterExecutionRecord:
    evidence = evidence_ids if evidence_ids is not None else (
        f"{adapter_identity.adapter_id}-identity",
        f"{adapter_identity.adapter_id}-quality",
    )
    return AdapterExecutionRecord(
        identity=adapter_identity,
        observed_identity_digest=adapter_identity.identity_digest,
        quality=AdapterQualityReport(
            adapter_id=adapter_identity.adapter_id,
            passed_cases=passed,
            total_cases=total,
            critical_failures=critical_failures,
            suite_sha256=digest("d"),
            evidence_ids=evidence,
        ),
        execution_node="ANVIL",
        result_sha256=digest("e"),
    )


def fixtures() -> tuple[AdapterExecutionRecord, AdapterExecutionRecord]:
    gs343 = record(identity("gs343", artifact="a", configuration="b", runtime="c"))
    r2d2 = record(identity("r2d2", artifact="b", configuration="c", runtime="d"))
    return gs343, r2d2


def policy_for(
    *records: AdapterExecutionRecord,
    minimum_score: float = 0.95,
    minimum_cases: int = 20,
) -> AdapterAcceptancePolicy:
    return AdapterAcceptancePolicy(
        required_adapter_digests=tuple(
            (item.identity.adapter_id, item.identity.identity_digest) for item in records
        ),
        minimum_score=minimum_score,
        minimum_cases=minimum_cases,
    )


def evaluate(
    records: tuple[AdapterExecutionRecord, ...],
    policy: AdapterAcceptancePolicy | None = None,
):
    selected_policy = policy or policy_for(*records)
    return evaluate_adapter_acceptance(
        records,
        selected_policy,
        adapter_set_digest(records),
    )


def test_stable_gs343_and_r2d2_are_accepted() -> None:
    records = fixtures()

    result = evaluate(records)

    assert result.eligible is True
    assert result.reasons == ()
    assert result.accepted_adapters == ("gs343", "r2d2")
    assert result.adapter_set_sha256 == adapter_set_digest(records)


def test_adapter_set_digest_is_order_invariant() -> None:
    gs343, r2d2 = fixtures()

    assert adapter_set_digest((gs343, r2d2)) == adapter_set_digest((r2d2, gs343))


def test_missing_required_adapter_fails_closed() -> None:
    gs343, r2d2 = fixtures()
    result = evaluate((gs343,), policy_for(gs343, r2d2))

    assert result.eligible is False
    assert "missing_adapter:r2d2" in result.reasons


def test_unexpected_adapter_fails_closed() -> None:
    gs343, r2d2 = fixtures()
    bree = record(identity("bree", artifact="c", configuration="d", runtime="e"))
    result = evaluate((gs343, r2d2, bree), policy_for(gs343, r2d2))

    assert result.eligible is False
    assert "unexpected_adapter:bree" in result.reasons


def test_duplicate_adapter_fails_closed() -> None:
    gs343, r2d2 = fixtures()
    records = (gs343, r2d2, gs343)
    result = evaluate(records, policy_for(gs343, r2d2))

    assert result.eligible is False
    assert "duplicate_adapter:gs343" in result.reasons


@pytest.mark.parametrize(
    "maturity",
    [
        AdapterMaturity.EXPERIMENTAL,
        AdapterMaturity.DEGRADED,
        AdapterMaturity.RETIRED,
    ],
)
def test_non_stable_maturity_fails_closed(maturity: AdapterMaturity) -> None:
    adapter_identity = identity(
        "gs343",
        artifact="a",
        configuration="b",
        runtime="c",
        maturity=maturity,
    )
    gs343 = record(adapter_identity)
    result = evaluate((gs343,), policy_for(gs343))

    assert result.eligible is False
    assert "maturity_not_stable:gs343" in result.reasons


def test_unapproved_execution_node_fails_closed() -> None:
    gs343, _ = fixtures()
    altered = replace(gs343, execution_node="FORGE")
    result = evaluate((altered,), policy_for(gs343))

    assert result.eligible is False
    assert "unapproved_execution_node:gs343" in result.reasons


def test_observed_identity_mismatch_fails_closed() -> None:
    gs343, _ = fixtures()
    altered = replace(gs343, observed_identity_digest=digest("f"))
    result = evaluate((altered,), policy_for(gs343))

    assert result.eligible is False
    assert "observed_identity_mismatch:gs343" in result.reasons


def test_unapproved_identity_fails_closed() -> None:
    gs343, _ = fixtures()
    policy = AdapterAcceptancePolicy(
        required_adapter_digests=(("gs343", digest("f")),),
        minimum_score=0.95,
        minimum_cases=20,
    )
    result = evaluate((gs343,), policy)

    assert result.eligible is False
    assert "unapproved_identity:gs343" in result.reasons


def test_low_quality_score_fails_closed() -> None:
    adapter_identity = identity("gs343", artifact="a", configuration="b", runtime="c")
    gs343 = record(adapter_identity, passed=18, total=20)
    result = evaluate((gs343,), policy_for(gs343))

    assert result.eligible is False
    assert "quality_below_threshold:gs343" in result.reasons


def test_insufficient_quality_cases_fails_closed() -> None:
    adapter_identity = identity("gs343", artifact="a", configuration="b", runtime="c")
    gs343 = record(adapter_identity, passed=10, total=10)
    result = evaluate((gs343,), policy_for(gs343))

    assert result.eligible is False
    assert "insufficient_quality_cases:gs343" in result.reasons


def test_critical_failure_fails_closed() -> None:
    adapter_identity = identity("gs343", artifact="a", configuration="b", runtime="c")
    gs343 = record(adapter_identity, critical_failures=("identity_rebind",))
    result = evaluate((gs343,), policy_for(gs343))

    assert result.eligible is False
    assert "critical_quality_failure:gs343" in result.reasons


def test_missing_quality_evidence_fails_closed() -> None:
    adapter_identity = identity("gs343", artifact="a", configuration="b", runtime="c")
    gs343 = record(adapter_identity, evidence_ids=())
    result = evaluate((gs343,), policy_for(gs343))

    assert result.eligible is False
    assert "quality_evidence_missing:gs343" in result.reasons


def test_adapter_set_commitment_mismatch_fails_closed() -> None:
    records = fixtures()
    result = evaluate_adapter_acceptance(records, policy_for(*records), digest("f"))

    assert result.eligible is False
    assert "adapter_set_identity_mismatch" in result.reasons


def test_invalid_quality_shape_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="total_cases must be positive"):
        AdapterQualityReport(
            adapter_id="gs343",
            passed_cases=0,
            total_cases=0,
            critical_failures=(),
            suite_sha256=digest("a"),
            evidence_ids=("proof",),
        )

    with pytest.raises(ValueError, match="evidence_ids must be unique"):
        AdapterQualityReport(
            adapter_id="gs343",
            passed_cases=1,
            total_cases=1,
            critical_failures=(),
            suite_sha256=digest("a"),
            evidence_ids=("proof", "proof"),
        )
