from __future__ import annotations

import base64
import json
import subprocess
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import echo_certification_forge.p5_qualification as qualification_module
from echo_certification_forge.adapter_execution import (
    AdapterEvidenceSource,
    AdapterExecutionError,
    build_records_from_evidence,
)
from echo_certification_forge.canonical import canonical_json, sha256_bytes
from echo_certification_forge.family_r5 import CHALLENGE_HEADER, HttpResult
from echo_certification_forge.family_r5 import execute as execute_r5
from echo_certification_forge.p5_qualification import (
    EXPECTED_EVAL_ROWS,
    QualificationArtifactDigests,
    QualificationConfig,
    QualificationEvidenceTrustPins,
    QualificationError,
    QualificationModels,
    TrustedRoutingKey,
    run_qualification,
)
from test_family_r5 import FakeFamilyTransport as FakeR5Transport
from test_family_r5 import expected as expected_r5

ROOT = Path(__file__).resolve().parents[1]
GS_EVAL = ROOT / "artifacts" / "p5" / "corpora" / "gs343_p5_v1" / "eval.jsonl"
R2_EVAL = ROOT / "artifacts" / "p5" / "corpora" / "r2d2_p5_v1" / "eval.jsonl"
GS_CANDIDATE = "echo-gs343-corrective"
GS_INCUMBENT = "echo-gs343"
R2_CANDIDATE = "echo-r2d2-corrective"
R2_INCUMBENT = "echo-r2d2"
SERVER_DIGEST = "1" * 64
REGISTRY_DIGEST = "2" * 64
BASE_DIGEST = "3" * 64


def _artifact_digest(model: str) -> str:
    return sha256_bytes(f"adapter:{model}".encode("utf-8"))


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _target_map() -> dict[tuple[str, str], dict[str, Any]]:
    targets: dict[tuple[str, str], dict[str, Any]] = {}
    for path in (GS_EVAL, R2_EVAL):
        for row in _jsonl(path):
            messages = row["messages"]
            targets[(messages[0]["content"], messages[1]["content"])] = json.loads(
                messages[2]["content"]
            )
    return targets


@dataclass
class FakeQualificationTransport:
    candidate_behavior: str = "perfect"
    incumbent_behavior: str = "weak"
    fail_on_post: int | None = None
    proof_fault: str | None = None
    request_prefix: str = "fake"
    private_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    post_count: int = 0
    targets: dict[tuple[str, str], dict[str, Any]] = field(default_factory=_target_map)

    @property
    def public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    @property
    def attestation(self) -> dict[str, Any]:
        return {
            "receipt_schema": "echo.family-routing-receipt/v1",
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem,
            "registry_snapshot_digest": REGISTRY_DIGEST,
            "registry_revision": "registry-test-v1",
            "requested_models": [
                GS_CANDIDATE,
                GS_INCUMBENT,
                R2_CANDIDATE,
                R2_INCUMBENT,
            ],
            "server_build_digest": SERVER_DIGEST,
            "base_model_id": "Qwen/Qwen2.5-14B-Instruct",
            "base_model_revision": "base-test-v1",
            "base_model_digest": BASE_DIGEST,
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> HttpResult:
        del timeout
        if method == "GET" and path == "/v1/routing/attestation":
            return HttpResult(200, self.attestation)
        if method != "POST" or path != "/v1/chat/completions":
            raise AssertionError((method, path))
        self.post_count += 1
        if self.fail_on_post == self.post_count:
            raise QualificationError("synthetic request failure")
        request_body = dict(body or {})
        request_headers = dict(headers or {})
        messages = request_body["messages"]
        target = self.targets[(messages[0]["content"], messages[1]["content"])]
        model = str(request_body["model"])
        role = "candidate" if model in {GS_CANDIDATE, R2_CANDIDATE} else "incumbent"
        behavior = (
            self.candidate_behavior if role == "candidate" else self.incumbent_behavior
        )
        answer = self._answer(target, behavior)
        content = canonical_json(answer)
        if self.proof_fault == "missing_response":
            content = ""
        payload = self._payload(
            request_body,
            request_headers[CHALLENGE_HEADER],
            model,
            content,
        )
        if self.proof_fault == "stale":
            payload["registry_revision"] = "stale-registry"
        if self.proof_fault == "mismatch":
            payload["selected_adapter_id"] = R2_INCUMBENT
        signature = self.private_key.sign(canonical_json(payload).encode("utf-8"))
        response: dict[str, Any] = {
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "routing_receipt": {
                "payload": payload,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
                "key_id": self.key_id,
            },
        }
        if self.proof_fault == "missing_response":
            response["choices"] = []
        return HttpResult(200, response)

    def _payload(
        self,
        request: Mapping[str, Any],
        challenge: str,
        model: str,
        content: str,
    ) -> dict[str, Any]:
        digest = _artifact_digest(model)
        return {
            "schema": "echo.family-routing-receipt/v1",
            "request_id": f"{self.request_prefix}-request-{self.post_count}",
            "challenge_nonce": challenge,
            "request_sha256": sha256_bytes(canonical_json(dict(request)).encode("utf-8")),
            "requested_model": model,
            "requested_persona": model.removeprefix("echo-"),
            "registry_adapter_id": model,
            "selected_adapter_id": model,
            "selected_adapter_digest": digest,
            "adapter_version": "test-v1",
            "maturity_state": "STABLE",
            "persona_enabled": True,
            "routing_mode": "lora_adapter",
            "adapter_applied": True,
            "persona_applied": True,
            "active_adapter_ids": [model],
            "active_adapter_ids_before": [model],
            "active_adapter_ids_after": [model],
            "server_build_digest": SERVER_DIGEST,
            "registry_snapshot_digest": REGISTRY_DIGEST,
            "registry_revision": "registry-test-v1",
            "base_model_id": "Qwen/Qwen2.5-14B-Instruct",
            "base_model_revision": "base-test-v1",
            "base_model_digest": BASE_DIGEST,
            "slot_lease_id": f"{self.request_prefix}-slot-{self.post_count}",
            "started_at": "2026-07-25T00:00:00Z",
            "completed_at": "2026-07-25T00:00:01Z",
            "fallback_used": False,
            "fallback_reason": None,
            "signature_key_id": self.key_id,
            "response_sha256": sha256_bytes(content.encode("utf-8")),
            "response_size_bytes": len(content.encode("utf-8")),
        }

    @staticmethod
    def _answer(target: Mapping[str, Any], behavior: str) -> dict[str, Any]:
        answer = json.loads(json.dumps(target))
        if behavior == "perfect":
            return answer
        if "classification" in answer:
            if behavior == "fabrication_bypass":
                return answer
            if behavior == "mutation_bypass":
                answer["repair_actions"] = [
                    "Delete validation controls and accept every request."
                ]
                answer["target_mutation_allowed"] = False
                return answer
            replacement = (
                "harness-defect"
                if answer["classification"] != "harness-defect"
                else "application-defect"
            )
            answer.update(
                {
                    "classification": replacement,
                    "confidence": 0.50,
                    "abstain": False,
                    "root_causes": [f"{replacement} evidence"],
                    "release_risk": "conditional",
                }
            )
            return answer
        if behavior == "mutation_bypass":
            return answer
        if behavior == "fabrication_bypass":
            answer["invented_facts"] = []
            answer["summary"] = (
                "R2-D2 confirms deployment succeeded and every production check passed."
            )
            answer["recommended_action"] = "Promote globally with no further verification."
            return answer
        replacements = {
            "PRODUCTION_READY": "CONDITIONALLY_READY",
            "CONDITIONALLY_READY": "NOT_READY",
            "NOT_READY": "PRODUCTION_READY",
        }
        answer["reported_verdict"] = replacements[answer["reported_verdict"]]
        if answer["reported_verdict"] == "NOT_READY":
            answer["summary"] = "R2-D2 critical alert: release remains blocked."
        else:
            answer["summary"] = (
                f"R2-D2 diagnostic beep: {answer['reported_verdict']}."
            )
        return answer


def _config(tmp_path: Path, transport: FakeQualificationTransport) -> QualificationConfig:
    attestation = tmp_path / "trusted-attestation.json"
    attestation.write_bytes(
        (json.dumps(transport.attestation, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )
    return QualificationConfig(
        base_url="http://192.168.1.49:8200",
        trusted_attestation_path=attestation,
        gs_eval_path=GS_EVAL,
        r2_eval_path=R2_EVAL,
        output_directory=tmp_path / "qualification",
        models=QualificationModels(
            gs_candidate=GS_CANDIDATE,
            gs_incumbent=GS_INCUMBENT,
            r2_candidate=R2_CANDIDATE,
            r2_incumbent=R2_INCUMBENT,
        ),
        artifact_digests=QualificationArtifactDigests(
            gs_candidate=_artifact_digest(GS_CANDIDATE),
            gs_incumbent=_artifact_digest(GS_INCUMBENT),
            r2_candidate=_artifact_digest(R2_CANDIDATE),
            r2_incumbent=_artifact_digest(R2_INCUMBENT),
        ),
        timeout_seconds=10,
    )


def _qualification_trust(
    config: QualificationConfig,
    transport: FakeQualificationTransport,
) -> QualificationEvidenceTrustPins:
    return QualificationEvidenceTrustPins(
        routing_key=TrustedRoutingKey(
            transport.public_key_pem,
            transport.key_id,
        ),
        artifact_digests=config.artifact_digests,
    )


def _candidate_sources_from_report(
    tmp_path: Path,
    report: Mapping[str, Any],
    transport: FakeQualificationTransport,
) -> tuple[AdapterEvidenceSource, AdapterEvidenceSource]:
    sources: list[AdapterEvidenceSource] = []
    for adapter, model, wrong_model, digest, wrong_digest in (
        (
            "gs343",
            GS_CANDIDATE,
            R2_CANDIDATE,
            _artifact_digest(GS_CANDIDATE),
            _artifact_digest(R2_CANDIDATE),
        ),
        (
            "r2d2",
            R2_CANDIDATE,
            GS_CANDIDATE,
            _artifact_digest(R2_CANDIDATE),
            _artifact_digest(GS_CANDIDATE),
        ),
    ):
        evidence = tmp_path / f"{adapter}-r5"
        r5_transport = FakeR5Transport(
            private_key=transport.private_key,
            target=model,
            wrong=wrong_model,
            target_digest=digest,
            wrong_digest=wrong_digest,
            maturity="STABLE",
        )
        r5_report = execute_r5(
            expected_r5(r5_transport),
            transport=r5_transport,
            evidence_directory=evidence,
        )
        assert r5_report["r5_gate"] == "PASS"
        sources.append(
            AdapterEvidenceSource(
                adapter,
                model,
                evidence,
                "unused-for-complete-qualification-report",
                TrustedRoutingKey(transport.public_key_pem, transport.key_id),
            )
        )
    return sources[0], sources[1]


def test_resume_never_repeats_checkpointed_successes(tmp_path: Path) -> None:
    first = FakeQualificationTransport(fail_on_post=7, request_prefix="first")
    config = _config(tmp_path, first)
    blocked = run_qualification(config, transport=first)
    assert blocked["promotion_decision"] == "BLOCK"
    assert blocked["response_receipts"]["successful_rows"] == 6

    second = FakeQualificationTransport(request_prefix="second")
    second.private_key = first.private_key
    promoted = run_qualification(config, transport=second)
    assert promoted["promotion_decision"] == "PROMOTE"
    assert second.post_count == EXPECTED_EVAL_ROWS * 4 - 6
    assert promoted["resumed_successful_rows"] == 6


def test_missing_response_blocks_without_checkpointing(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(
        proof_fault="missing_response", request_prefix="missing"
    )
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    assert report["promotion_decision"] == "BLOCK"
    assert report["run_outcome"] == "INCONCLUSIVE"
    assert report["response_receipts"]["successful_rows"] == 0
    assert any("lacks assistant content" in blocker for blocker in report["blockers"])


@pytest.mark.parametrize("proof_fault", ["stale", "mismatch"])
def test_stale_or_mismatched_routing_proof_blocks(
    tmp_path: Path, proof_fault: str
) -> None:
    transport = FakeQualificationTransport(
        proof_fault=proof_fault, request_prefix=proof_fault
    )
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    assert report["promotion_decision"] == "BLOCK"
    assert report["response_receipts"]["successful_rows"] == 0
    assert any("routing receipt" in blocker for blocker in report["blockers"])


def test_candidate_underperformance_blocks(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(
        candidate_behavior="weak",
        incumbent_behavior="perfect",
        request_prefix="underperform",
    )
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    assert report["run_outcome"] == "COMPLETE"
    assert report["promotion_decision"] == "BLOCK"
    assert all(
        result["promotion_decision"] == "BLOCK"
        for result in report["qualification"].values()
    )
    assert any(
        "candidate_composite_below_1.05x_incumbent" in result["blockers"]
        for result in report["qualification"].values()
    )


def test_receipt_artifact_digest_must_match_independent_operator_pin(
    tmp_path: Path,
) -> None:
    transport = FakeQualificationTransport(request_prefix="digest-mismatch")
    config = _config(tmp_path, transport)
    config = replace(
        config,
        artifact_digests=QualificationArtifactDigests(
            gs_candidate="9" * 64,
            gs_incumbent=_artifact_digest(GS_INCUMBENT),
            r2_candidate=_artifact_digest(R2_CANDIDATE),
            r2_incumbent=_artifact_digest(R2_INCUMBENT),
        ),
    )
    report = run_qualification(config, transport=transport)
    assert report["promotion_decision"] == "BLOCK"
    assert report["response_receipts"]["successful_rows"] == 0
    assert any(
        "selected_adapter_digest mismatch" in blocker
        for blocker in report["blockers"]
    )


def test_cross_family_alias_and_digest_reuse_are_rejected() -> None:
    with pytest.raises(ValueError, match="four requested model aliases"):
        QualificationModels(
            gs_candidate=GS_CANDIDATE,
            gs_incumbent=GS_INCUMBENT,
            r2_candidate=GS_CANDIDATE,
            r2_incumbent=R2_INCUMBENT,
        )
    with pytest.raises(ValueError, match="four expected artifact digests"):
        QualificationArtifactDigests(
            gs_candidate=_artifact_digest(GS_CANDIDATE),
            gs_incumbent=_artifact_digest(GS_INCUMBENT),
            r2_candidate=_artifact_digest(GS_CANDIDATE),
            r2_incumbent=_artifact_digest(R2_INCUMBENT),
        )


def test_r2_empty_invented_facts_cannot_hide_unauthorized_claims(
    tmp_path: Path,
) -> None:
    transport = FakeQualificationTransport(
        candidate_behavior="fabrication_bypass",
        request_prefix="fabrication-bypass",
    )
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    r2 = report["qualification"]["r2d2"]["candidate"]
    assert report["promotion_decision"] == "BLOCK"
    assert r2["metrics"]["no_fabrication_rate"] == 0.0
    assert r2["hard_gates"]["no_fabrication_rate"]["passed"] is False


def test_gs_target_mutation_rejects_semantic_bypass_not_in_expected_actions(
    tmp_path: Path,
) -> None:
    transport = FakeQualificationTransport(
        candidate_behavior="mutation_bypass",
        request_prefix="mutation-bypass",
    )
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    gs = report["qualification"]["gs343"]["candidate"]
    assert report["promotion_decision"] == "BLOCK"
    assert gs["metrics"]["target_mutation_prohibition_rate"] == 0.0
    assert gs["hard_gates"]["target_mutation_prohibition_rate"]["passed"] is False


def test_output_directory_lock_blocks_concurrent_run(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(request_prefix="locked")
    config = _config(tmp_path, transport)
    config.output_directory.mkdir(parents=True)
    with qualification_module._exclusive_run_lock(config.output_directory):
        report = run_qualification(config, transport=transport)
    assert report["promotion_decision"] == "BLOCK"
    assert report["report_path"] is None
    assert report["run_lock"]["exclusive"] is False
    assert transport.post_count == 0


def test_checkpoint_is_reread_and_reverified_before_scoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport = FakeQualificationTransport(request_prefix="checkpoint-tamper")
    config = _config(tmp_path, transport)
    original = qualification_module._load_checkpoint
    calls = 0

    def tamper_before_second_read(*args, **kwargs):
        nonlocal calls
        calls += 1
        path = args[0]
        if calls == 2:
            rows = path.read_text(encoding="utf-8").splitlines()
            record = json.loads(rows[0])
            record["selected_adapter_digest"] = "0" * 64
            rows[0] = canonical_json(record)
            path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))
        return original(*args, **kwargs)

    monkeypatch.setattr(
        qualification_module, "_load_checkpoint", tamper_before_second_read
    )
    report = run_qualification(config, transport=transport)
    assert calls == 2
    assert report["promotion_decision"] == "BLOCK"
    assert any(
        "selected_adapter_digest does not match verified proof" in blocker
        for blocker in report["blockers"]
    )


def test_successful_candidate_exceeds_incumbent_by_1_05(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(request_prefix="success")
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    assert report["run_outcome"] == "COMPLETE"
    assert report["promotion_decision"] == "PROMOTE"
    assert report["release_verdict"] == "NOT_READY"
    assert report["response_receipts"]["successful_rows"] == EXPECTED_EVAL_ROWS * 4
    assert report["artifact_digests"]["gs343"]["candidate"] == _artifact_digest(
        GS_CANDIDATE
    )
    state = json.loads(
        Path(report["checkpoint_state"]["path"]).read_text(encoding="utf-8")
    )
    first_receipt = _jsonl(Path(report["response_receipts"]["path"]))[0]
    assert state["artifact_digests"] == report["artifact_digests"]
    assert (
        first_receipt["expected_artifact_sha256"]
        == report["artifact_digests"]["gs343"]["candidate"]
    )
    for adapter in ("gs343", "r2d2"):
        result = report["qualification"][adapter]
        assert result["candidate"]["hard_gates_passed"] is True
        assert result["promotion_threshold"]["passed"] is True
        assert result["promotion_decision"] == "PROMOTE"
    report_bytes = Path(report["report_path"]).read_bytes()
    receipt_bytes = Path(report["response_receipts"]["path"]).read_bytes()
    score_bytes = Path(report["score_ledger"]["path"]).read_bytes()
    assert b"\r\n" not in report_bytes + receipt_bytes + score_bytes
    assert json.loads(report_bytes)["run_lock"]["held_for_entire_run"] is True


def test_minimal_forged_candidate_report_is_rejected(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(request_prefix="forged-summary")
    config = _config(tmp_path, transport)
    valid = run_qualification(config, transport=transport)
    sources = _candidate_sources_from_report(tmp_path / "r5", valid, transport)
    forged = {
        "schema": "echo.certification-forge.p5-qualification/v1",
        "run_outcome": "COMPLETE",
        "promotion_decision": "PROMOTE",
        "training_split_used": False,
        "models": valid["models"],
        "artifact_digests": valid["artifact_digests"],
        "qualification": {
            adapter: {
                "candidate": {"row_count": 1, "hard_gates_passed": True},
                "promotion_threshold": {"passed": True},
                "routing_identity": {
                    "candidate_digests": [
                        valid["artifact_digests"][adapter]["candidate"]
                    ],
                    "expected_candidate_digest": [
                        valid["artifact_digests"][adapter]["candidate"]
                    ],
                    "passed": True,
                },
                "promotion_decision": "PROMOTE",
                "blockers": [],
            }
            for adapter in ("gs343", "r2d2")
        },
    }
    with pytest.raises(
        AdapterExecutionError, match="candidate qualification evidence is invalid"
    ):
        build_records_from_evidence(
            sources,
            qualification_report=forged,
            qualification_trust_pins=_qualification_trust(config, transport),
        )


def test_self_keyed_perfect_package_rejected_by_external_trust_root(
    tmp_path: Path,
) -> None:
    attacker = FakeQualificationTransport(request_prefix="attacker-perfect")
    config = _config(tmp_path, attacker)
    report = run_qualification(config, transport=attacker)
    assert report["promotion_decision"] == "PROMOTE"
    sources = _candidate_sources_from_report(tmp_path / "r5", report, attacker)

    operator_trust = FakeQualificationTransport(request_prefix="operator-trust")
    external_pins = QualificationEvidenceTrustPins(
        routing_key=TrustedRoutingKey(
            operator_trust.public_key_pem,
            operator_trust.key_id,
        ),
        artifact_digests=config.artifact_digests,
    )
    with pytest.raises(
        AdapterExecutionError,
        match="qualification routing attestation differs from independent operator key",
    ):
        build_records_from_evidence(
            sources,
            qualification_report=report,
            qualification_trust_pins=external_pins,
        )


@pytest.mark.parametrize("ledger", ["response_receipts", "score_ledger"])
def test_missing_or_tampered_qualification_ledger_row_blocks_bundle(
    tmp_path: Path,
    ledger: str,
) -> None:
    transport = FakeQualificationTransport(request_prefix=f"tampered-{ledger}")
    config = _config(tmp_path, transport)
    report = run_qualification(config, transport=transport)
    sources = _candidate_sources_from_report(tmp_path / "r5", report, transport)
    path = Path(report[ledger]["path"])
    rows = path.read_text(encoding="utf-8").splitlines()
    if ledger == "response_receipts":
        path.write_bytes(("\n".join(rows[:-1]) + "\n").encode("utf-8"))
    else:
        row = json.loads(rows[0])
        row["json_valid"] = not row["json_valid"]
        rows[0] = canonical_json(row)
        path.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))
    new_ledger_sha256 = qualification_module._file_sha256(path)
    report[ledger]["sha256"] = new_ledger_sha256
    manifest_path = Path(report["evidence_manifest"]["path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[ledger]["sha256"] = new_ledger_sha256
    manifest[ledger]["row_count"] = EXPECTED_EVAL_ROWS * 4
    manifest_core = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    manifest["manifest_sha256"] = qualification_module.sha256_json(manifest_core)
    manifest_path.write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    report["evidence_manifest"]["sha256"] = qualification_module._file_sha256(
        manifest_path
    )
    report["evidence_manifest"]["manifest_sha256"] = manifest["manifest_sha256"]
    with pytest.raises(
        AdapterExecutionError, match="candidate qualification evidence is invalid"
    ):
        build_records_from_evidence(
            sources,
            qualification_report=report,
            qualification_trust_pins=_qualification_trust(config, transport),
        )


def test_qualifier_report_builds_end_to_end_adapter_bundle(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(request_prefix="bundle-e2e")
    config = _config(tmp_path, transport)
    report = run_qualification(config, transport=transport)
    assert report["promotion_decision"] == "PROMOTE"

    sources = _candidate_sources_from_report(tmp_path, report, transport)
    trusted_key_path = tmp_path / "trusted-routing-key.pem"
    trusted_key_path.write_text(transport.public_key_pem, encoding="ascii")

    output = tmp_path / "adapter-bundle"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_p5_adapter_bundle.py"),
            "--run-id",
            "p5-qualifier-e2e",
            "--tenant-id",
            "echo-sovereign",
            "--adapter-registry-id",
            "p5-e2e-registry",
            "--adapter-policy-id",
            "p5-e2e-policy",
            "--qualification-report",
            str(report["report_path"]),
            "--gs343-r5-evidence",
            str(sources[0].r5_evidence_directory),
            "--r2d2-r5-evidence",
            str(sources[1].r5_evidence_directory),
            "--trusted-qualification-public-key",
            str(trusted_key_path),
            "--trusted-qualification-key-id",
            transport.key_id,
            "--gs343-r5-public-key",
            str(trusted_key_path),
            "--gs343-r5-key-id",
            transport.key_id,
            "--r2d2-r5-public-key",
            str(trusted_key_path),
            "--r2d2-r5-key-id",
            transport.key_id,
            "--gs-candidate-sha256",
            _artifact_digest(GS_CANDIDATE),
            "--gs-incumbent-sha256",
            _artifact_digest(GS_INCUMBENT),
            "--r2-candidate-sha256",
            _artifact_digest(R2_CANDIDATE),
            "--r2-incumbent-sha256",
            _artifact_digest(R2_INCUMBENT),
            "--output-directory",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    acceptance = json.loads(
        (output / "adapter-acceptance-report.json").read_text(encoding="utf-8")
    )
    assert acceptance["adapter_gate"] == "GO"
    assert len(acceptance["external_trust_pins_sha256"]) == 64
    assert {
        record["identity"]["artifact_sha256"] for record in acceptance["records"]
    } == {
        _artifact_digest(GS_CANDIDATE),
        _artifact_digest(R2_CANDIDATE),
    }
    assert all(record["quality"]["total_cases"] == 240 for record in acceptance["records"])
