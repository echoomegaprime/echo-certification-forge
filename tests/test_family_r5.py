from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.canonical import canonical_json, sha256_bytes
from echo_certification_forge.family_r5 import HttpResult, ExpectedIdentity, execute

TARGET = "echo-gs343"
WRONG = "echo-r2d2"
SERVER_DIGEST = "1" * 64
REGISTRY_DIGEST = "2" * 64
BASE_DIGEST = "3" * 64
TARGET_DIGEST = "4" * 64
WRONG_DIGEST = "5" * 64
REGISTRY_REVISION = "registry-r5"
BASE_REVISION = "base-r5"


@dataclass
class FakeFamilyTransport:
    tamper_error_signature: bool = False
    attestation_server_digest: str = SERVER_DIGEST
    private_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    target: str = TARGET
    wrong: str = WRONG
    target_digest: str = TARGET_DIGEST
    wrong_digest: str = WRONG_DIGEST
    maturity: str = "CONFORMANCE_PENDING"
    loaded: list[str] = field(default_factory=list)
    lease_token: str | None = None
    fault_target: str | None = None
    request_counter: int = 0

    def __post_init__(self) -> None:
        if not self.loaded:
            self.loaded = [self.target, self.wrong]

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
        headers = dict(headers or {})
        body = dict(body or {})
        if method == "GET" and path == "/health":
            return self._result(200, {
                "status": "ok",
                "loaded": list(self.loaded),
                "routing_maintenance": {
                    "active": self.lease_token is not None,
                    "drain_requested": False,
                    "lease_id": "lease-1" if self.lease_token else None,
                    "ttl_remaining_seconds": 60 if self.lease_token else 0,
                    "unloaded": [self.target] if self.target not in self.loaded else [],
                    "fault_targets": [self.target] if self.fault_target else [],
                },
            })
        if method == "GET" and path == "/v1/routing/attestation":
            return self._result(200, {
                "receipt_schema": "echo.family-routing-receipt/v1",
                "key_id": self.key_id,
                "public_key_pem": self.public_key_pem,
                "registry_snapshot_digest": REGISTRY_DIGEST,
                "registry_revision": REGISTRY_REVISION,
                "requested_models": [self.target, self.wrong],
                "server_build_digest": self.attestation_server_digest,
                "base_model_id": "base",
                "base_model_revision": BASE_REVISION,
                "base_model_digest": BASE_DIGEST,
            })
        if method == "POST" and path == "/admin/adapter-routing/lease":
            assert self.lease_token is None
            self.lease_token = "t" * 43
            return self._result(200, {
                "lease_token": self.lease_token,
                "lease_id": "lease-1",
                "ttl_seconds": 60,
            })
        if method == "POST" and path == "/admin/adapter-routing/fault/wrong-active":
            self._require_lease(headers)
            assert body == {
                "target_adapter_id": self.target,
                "wrong_adapter_id": self.wrong,
            }
            self.fault_target = self.wrong
            self.lease_token = None
            return self._result(200, {
                "armed": {
                    "target_adapter_id": self.target,
                    "wrong_adapter_id": self.wrong,
                    "armed": True,
                },
                "released": {
                    "released": True,
                    "lease_id": "lease-1",
                    "fault_preserved": True,
                    "unloaded_preserved": False,
                },
            })
        if method == "POST" and path == f"/admin/adapters/{self.target}/unload":
            self._require_lease(headers)
            self.loaded.remove(self.target)
            return self._result(200, {"adapter_id": self.target, "loaded": False})
        if method == "POST" and path == "/admin/adapter-routing/release":
            self._require_lease(headers)
            preserve_unloaded = body.get("preserve_unloaded") is True
            if not preserve_unloaded and self.target not in self.loaded:
                self.loaded.append(self.target)
            self.lease_token = None
            if not body.get("preserve_faults"):
                self.fault_target = None
            return self._result(200, {
                "released": True,
                "lease_id": "lease-1",
                "fault_preserved": body.get("preserve_faults") is True,
                "unloaded_preserved": preserve_unloaded,
            })
        if method == "POST" and path == "/v1/chat/completions":
            self.request_counter += 1
            challenge = headers["x-echo-routing-challenge"]
            model = body["model"]
            if model == self.target and self.target not in self.loaded:
                receipt = self._failure_receipt(
                    body, challenge, "ADAPTER_NOT_ACTIVE", None, [self.wrong]
                )
                self.loaded.append(self.target)
                return self._result(503, {
                    "error_code": "ADAPTER_NOT_ACTIVE",
                    "message": "adapter not active",
                    "routing_receipt": receipt,
                })
            if model == self.target and self.fault_target:
                selected = self.fault_target
                self.fault_target = None
                receipt = self._failure_receipt(
                    body, challenge, "ADAPTER_IDENTITY_MISMATCH", selected, [selected]
                )
                return self._result(409, {
                    "error_code": "ADAPTER_IDENTITY_MISMATCH",
                    "message": "identity mismatch",
                    "routing_receipt": receipt,
                })
            content = f"positive-{model}"
            digest = (
                self.target_digest if model == self.target else self.wrong_digest
            )
            receipt = self._positive_receipt(body, challenge, model, digest, content)
            return self._result(200, {
                "model": model,
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }],
                "routing_receipt": receipt,
            })
        raise AssertionError((method, path, body, headers))

    def _require_lease(self, headers: Mapping[str, str]) -> None:
        assert self.lease_token is not None
        assert headers["x-echo-maintenance-lease"] == self.lease_token

    def _common(self, body: Mapping[str, Any], challenge: str, model: str) -> dict[str, Any]:
        return {
            "schema": "echo.family-routing-receipt/v1",
            "request_id": f"request-{self.request_counter}",
            "challenge_nonce": challenge,
            "request_sha256": sha256_bytes(canonical_json(dict(body)).encode()),
            "requested_model": model,
            "server_build_digest": SERVER_DIGEST,
            "registry_snapshot_digest": REGISTRY_DIGEST,
            "base_model_id": "base",
            "base_model_revision": BASE_REVISION,
            "base_model_digest": BASE_DIGEST,
            "slot_lease_id": "slot-1",
            "started_at": "2026-07-19T00:00:00Z",
            "completed_at": "2026-07-19T00:00:01Z",
            "registry_revision": REGISTRY_REVISION,
            "fallback_used": False,
            "fallback_reason": None,
            "signature_key_id": self.key_id,
        }

    def _positive_receipt(
        self, body: Mapping[str, Any], challenge: str, model: str, digest: str, content: str
    ) -> dict[str, Any]:
        payload = self._common(body, challenge, model)
        payload.update({
            "requested_persona": model.removeprefix("echo-"),
            "registry_adapter_id": model,
            "selected_adapter_id": model,
            "selected_adapter_digest": digest,
            "adapter_version": "v-test",
            "maturity_state": self.maturity,
            "persona_enabled": True,
            "routing_mode": "lora_adapter",
            "adapter_applied": True,
            "persona_applied": True,
            "active_adapter_ids": [model],
            "active_adapter_ids_before": [model],
            "active_adapter_ids_after": [model],
            "response_sha256": sha256_bytes(content.encode()),
            "response_size_bytes": len(content.encode()),
        })
        return self._sign(payload, tamper=False)

    def _failure_receipt(
        self,
        body: Mapping[str, Any],
        challenge: str,
        code: str,
        selected: str | None,
        active: list[str],
    ) -> dict[str, Any]:
        payload = self._common(body, challenge, self.target)
        payload.update({
            "requested_persona": "gs343",
            "registry_adapter_id": self.target,
            "selected_adapter_id": selected,
            "selected_adapter_digest": None,
            "adapter_version": "v-test",
            "maturity_state": "CONFORMANCE_PENDING",
            "persona_enabled": True,
            "routing_mode": "failure",
            "adapter_applied": False,
            "persona_applied": False,
            "active_adapter_ids": active,
            "error_code": code,
            "error_reason": "expected negative control",
            "response_sha256": None,
            "response_size_bytes": None,
        })
        return self._sign(payload, tamper=self.tamper_error_signature)

    def _sign(self, payload: dict[str, Any], *, tamper: bool) -> dict[str, Any]:
        signature = self.private_key.sign(canonical_json(payload).encode())
        if tamper:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return {
            "payload": payload,
            "signature_b64": base64.b64encode(signature).decode(),
            "key_id": self.key_id,
        }

    @staticmethod
    def _result(status: int, body: dict[str, Any]) -> HttpResult:
        return HttpResult(status, body)


def expected(transport: FakeFamilyTransport) -> ExpectedIdentity:
    return ExpectedIdentity(
        server_build_digest=SERVER_DIGEST,
        registry_snapshot_digest=REGISTRY_DIGEST,
        registry_revision=REGISTRY_REVISION,
        signature_key_id=transport.key_id,
        base_model_digest=BASE_DIGEST,
        base_model_revision=BASE_REVISION,
        target_adapter_digest=transport.target_digest,
        wrong_adapter_digest=transport.wrong_digest,
        target_model=transport.target,
        wrong_model=transport.wrong,
    )


def test_r5_controls_pass_and_restore() -> None:
    transport = FakeFamilyTransport()
    report = execute(expected(transport), transport=transport)
    assert report["r5_gate"] == "PASS"
    assert report["run_outcome"] == "COMPLETE"
    assert report["release_verdict"] == "NOT_READY"
    assert report["deployment_authorized"] is False
    assert report["completion_marker"] == "[R5 COMPLETE]"
    assert transport.loaded == [transport.wrong, transport.target]
    assert transport.lease_token is None
    assert transport.fault_target is None


def test_wrong_server_identity_blocks_before_mutation() -> None:
    transport = FakeFamilyTransport(attestation_server_digest="9" * 64)
    report = execute(expected(transport), transport=transport)
    assert report["r5_gate"] == "BLOCK"
    assert report["run_outcome"] == "INCONCLUSIVE"
    assert "server_build_digest mismatch" in report["blocker"]
    assert transport.lease_token is None
    assert transport.loaded == [transport.target, transport.wrong]


def test_tampered_negative_receipt_blocks_and_leaves_clean_state() -> None:
    transport = FakeFamilyTransport(tamper_error_signature=True)
    report = execute(expected(transport), transport=transport)
    assert report["r5_gate"] == "BLOCK"
    assert "signature is invalid" in report["blocker"]
    assert transport.lease_token is None
    assert transport.fault_target is None
    assert transport.target in transport.loaded


def test_evidence_manifest_redacts_lease_token(tmp_path: Path) -> None:
    transport = FakeFamilyTransport()
    output = tmp_path / "r5"
    report = execute(expected(transport), transport=transport, evidence_directory=output)
    assert report["r5_gate"] == "PASS"
    manifest = report["evidence_manifest"]
    assert len(manifest["merkle_root"]) == 64
    lease_evidence = (output / "wrong-active-lease.json").read_text()
    assert "[REDACTED]" in lease_evidence
    assert "t" * 43 not in lease_evidence
