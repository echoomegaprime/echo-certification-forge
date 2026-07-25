from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.canonical import canonical_json, sha256_bytes
from echo_certification_forge.family_r5 import CHALLENGE_HEADER, HttpResult
from echo_certification_forge.p5_qualification import (
    EXPECTED_EVAL_ROWS,
    QualificationConfig,
    QualificationError,
    QualificationModels,
    run_qualification,
)

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
        digest = sha256_bytes(f"adapter:{model}".encode("utf-8"))
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
            "maturity_state": "CONFORMANCE_PENDING",
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
        timeout_seconds=10,
    )


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


def test_successful_candidate_exceeds_incumbent_by_1_05(tmp_path: Path) -> None:
    transport = FakeQualificationTransport(request_prefix="success")
    report = run_qualification(_config(tmp_path, transport), transport=transport)
    assert report["run_outcome"] == "COMPLETE"
    assert report["promotion_decision"] == "PROMOTE"
    assert report["release_verdict"] == "NOT_READY"
    assert report["response_receipts"]["successful_rows"] == EXPECTED_EVAL_ROWS * 4
    for adapter in ("gs343", "r2d2"):
        result = report["qualification"][adapter]
        assert result["candidate"]["hard_gates_passed"] is True
        assert result["promotion_threshold"]["passed"] is True
        assert result["promotion_decision"] == "PROMOTE"
    report_bytes = Path(report["report_path"]).read_bytes()
    receipt_bytes = Path(report["response_receipts"]["path"]).read_bytes()
    score_bytes = Path(report["score_ledger"]["path"]).read_bytes()
    assert b"\r\n" not in report_bytes + receipt_bytes + score_bytes
