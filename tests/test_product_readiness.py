from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from echo_certification_forge.canonical import sha256_bytes, to_utc_iso
from echo_certification_forge.product_readiness import (
    create_product_readiness_envelope,
    verify_product_readiness,
)
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry


SOURCE_COMMIT = "a" * 40


def _gates() -> dict[str, dict[str, str]]:
    return {
        name: {"state": "COMPLETE", "evidence_sha256": sha256_bytes(name.encode())}
        for name in (
            "P1", "P2", "P3", "P4", "P5", "P6", "P7", "SDK", "CI", "MASTER"
        )
    }


def _master() -> dict[str, object]:
    return {
        "run_id": "master-acceptance-1",
        "run_outcome": "COMPLETE",
        "target_release_verdict": "NOT_READY",
        "signed_verdict_verified": True,
        "evidence_chain_verified": True,
        "sandbox_isolation": "docker",
        "requirements_passed": True,
        "rerun_command": "python scripts/master_acceptance.py --verify",
    }


def _write_report(path: Path, signer: Ed25519VerdictSigner) -> TrustedPublicKeyRegistry:
    now = datetime(2026, 7, 26, tzinfo=UTC)
    envelope = create_product_readiness_envelope(
        signer=signer,
        source_commit=SOURCE_COMMIT,
        source_tree_sha256="b" * 64,
        generated_at=to_utc_iso(now),
        expires_at=to_utc_iso(now + timedelta(days=30)),
        gates=_gates(),
        master_run=_master(),
    )
    path.write_text(json.dumps(asdict(envelope), sort_keys=True), encoding="utf-8")
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    return trusted


def _passing_adapter_report(tmp_path: Path) -> Path:
    """Adapter evidence that genuinely qualifies.

    Built by RAISING the evidence to policy (maturity STABLE, no critical failures, all cases
    passed) -- never by lowering a threshold. This is the positive control required by P0 #26804:
    without it, a gate that blocked unconditionally would pass every negative test while making
    the product unshippable.
    """
    report = {
        "schema_version": "1.0.0",
        "adapter_gate": "GO",
        "adapter_gate_eligible": True,
        "release_verdict": "READY",
        "policy": {
            "required_maturity": "STABLE",
            "minimum_cases": 3,
            "required_adapters": [{"adapter_id": "gs343"}, {"adapter_id": "r2d2"}],
        },
        "records": [
            {
                "identity": {"adapter_id": a, "maturity": "STABLE"},
                "quality": {
                    "adapter_id": a,
                    "passed_cases": 240,
                    "total_cases": 240,
                    "critical_failures": [],
                },
            }
            for a in ("gs343", "r2d2")
        ],
    }
    path = tmp_path / "adapter-acceptance-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_missing_report_fails_closed(tmp_path: Path) -> None:
    status = verify_product_readiness(
        None,
        TrustedPublicKeyRegistry.empty(),
        expected_source_commit=SOURCE_COMMIT,
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert status.release_verdict == "NOT_READY"
    assert status.reason == "product_readiness_report_missing"


def test_signed_exact_source_report_promotes_status(tmp_path: Path) -> None:
    path = tmp_path / "product-readiness.json"
    trusted = _write_report(path, Ed25519VerdictSigner.generate())
    status = verify_product_readiness(
        path,
        trusted,
        expected_source_commit=SOURCE_COMMIT,
        now=datetime(2026, 7, 27, tzinfo=UTC),
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert status.ready
    assert status.reason == "signed_exact_source_acceptance_verified"
    assert status.report_sha256 == sha256_bytes(path.read_bytes())


def test_wrong_commit_tamper_and_untrusted_key_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "product-readiness.json"
    signer = Ed25519VerdictSigner.generate()
    trusted = _write_report(path, signer)

    wrong_commit = verify_product_readiness(
        path,
        trusted,
        expected_source_commit="c" * 40,
        now=datetime(2026, 7, 27, tzinfo=UTC),
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert wrong_commit.release_verdict == "NOT_READY"

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["payload"]["required_gates"]["P7"]["state"] = "PENDING"
    path.write_text(json.dumps(raw), encoding="utf-8")
    tampered = verify_product_readiness(
        path,
        trusted,
        expected_source_commit=SOURCE_COMMIT,
        now=datetime(2026, 7, 27, tzinfo=UTC),
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert tampered.reason == "product_readiness_invalid_signature"

    _write_report(path, signer)
    untrusted = verify_product_readiness(
        path,
        TrustedPublicKeyRegistry.empty(),
        expected_source_commit=SOURCE_COMMIT,
        now=datetime(2026, 7, 27, tzinfo=UTC),
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert untrusted.reason == "product_readiness_untrusted_signing_key"


def test_expired_or_incomplete_gate_report_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "product-readiness.json"
    signer = Ed25519VerdictSigner.generate()
    trusted = _write_report(path, signer)
    expired = verify_product_readiness(
        path,
        trusted,
        expected_source_commit=SOURCE_COMMIT,
        now=datetime(2026, 9, 1, tzinfo=UTC),
        adapter_report_path=_passing_adapter_report(tmp_path),
    )
    assert expired.release_verdict == "NOT_READY"
    assert expired.reason == "product_readiness_contract_invalid"

    gates = _gates()
    gates["SDK"]["state"] = "PENDING"
    now = datetime(2026, 7, 26, tzinfo=UTC)
    try:
        create_product_readiness_envelope(
            signer=signer,
            source_commit=SOURCE_COMMIT,
            source_tree_sha256="b" * 64,
            generated_at=to_utc_iso(now),
            expires_at=to_utc_iso(now + timedelta(days=1)),
            gates=gates,
            master_run=_master(),
        )
    except ValueError as error:
        assert "SDK" in str(error)
    else:
        raise AssertionError("incomplete release gate was signed")
