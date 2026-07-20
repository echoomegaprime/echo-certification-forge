"""Deterministic, loopback-only Family 14B R5 routing controls."""
from __future__ import annotations

import argparse
import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, require_sha256, sha256_bytes
from .evidence import merkle_root

SCHEMA = "echo.certification-forge.family-r5-negative-controls/v1"
RECEIPT_SCHEMA = "echo.family-routing-receipt/v1"
LEASE_HEADER = "x-echo-maintenance-lease"
CHALLENGE_HEADER = "x-echo-routing-challenge"


class R5Error(RuntimeError):
    """A deterministic R5 gate requirement failed."""


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: dict[str, Any]


class Transport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30,
    ) -> HttpResult: ...


@dataclass(slots=True)
class LoopbackTransport:
    base_url: str = "http://127.0.0.1:8200"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}:
            raise ValueError("R5 maintenance requires a loopback HTTP URL")
        self.base_url = self.base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30,
    ) -> HttpResult:
        data = None if body is None else canonical_json(dict(body)).encode()
        request_headers = {"accept": "application/json", **dict(headers or {})}
        if data is not None:
            request_headers["content-type"] = "application/json"
        request = Request(
            self.base_url + path,
            data=data,
            method=method.upper(),
            headers=request_headers,
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                return HttpResult(response.status, _json(response.read()))
        except HTTPError as error:
            return HttpResult(error.code, _json(error.read()))
        except (URLError, TimeoutError, OSError) as error:
            raise R5Error(f"transport failure: {type(error).__name__}: {error}") from error


@dataclass(frozen=True, slots=True)
class ExpectedIdentity:
    server_build_digest: str
    registry_snapshot_digest: str
    registry_revision: str
    signature_key_id: str
    base_model_digest: str
    base_model_revision: str
    target_adapter_digest: str
    wrong_adapter_digest: str
    target_model: str = "echo-gs343"
    wrong_model: str = "echo-r2d2"

    def __post_init__(self) -> None:
        for name in (
            "server_build_digest",
            "registry_snapshot_digest",
            "base_model_digest",
            "target_adapter_digest",
            "wrong_adapter_digest",
        ):
            require_sha256(str(getattr(self, name)), name)
        if not self.registry_revision or not self.base_model_revision:
            raise ValueError("registry and base-model revisions are required")
        if not self.signature_key_id.startswith("ed25519:"):
            raise ValueError("signature_key_id must identify an Ed25519 key")
        if self.target_model == self.wrong_model:
            raise ValueError("target and wrong models must differ")


@dataclass(slots=True)
class Operator:
    transport: Transport
    expected: ExpectedIdentity
    evidence: dict[str, Any] = field(default_factory=dict)
    trusted_public_key_pem: str | None = None

    def run(self) -> dict[str, Any]:
        controls: list[dict[str, Any]] = []
        blocker: str | None = None
        try:
            attestation = self._preflight()
            self._positive(self.expected.target_model, self.expected.target_adapter_digest, "positive-target")
            self._positive(self.expected.wrong_model, self.expected.wrong_adapter_digest, "positive-wrong")
            controls.append(self._wrong_active(attestation))
            controls.append(self._unloaded(attestation))
            self._restored("final-health")
        except Exception as error:
            blocker = f"{type(error).__name__}: {error}"
            try:
                self._restored(f"failure-cleanup-{uuid.uuid4().hex[:8]}")
            except Exception as cleanup:
                blocker += f"; cleanup={type(cleanup).__name__}: {cleanup}"
        passed = blocker is None and len(controls) == 2 and all(x["passed"] for x in controls)
        return {
            "schema": SCHEMA,
            "run_outcome": "COMPLETE" if passed else "INCONCLUSIVE",
            "release_verdict": "NOT_READY",
            "r5_gate": "PASS" if passed else "BLOCK",
            "deployment_authorized": False,
            "completion_marker": "[R5 COMPLETE]" if passed else None,
            "controls": controls,
            "blocker": blocker,
            "expected_identity": self.expected.__dict__ if hasattr(self.expected, "__dict__") else {
                name: getattr(self.expected, name)
                for name in self.expected.__dataclass_fields__
            },
        }

    def _add(self, name: str, value: Any) -> None:
        if name in self.evidence:
            raise R5Error(f"duplicate evidence: {name}")
        self.evidence[name] = _redact(value)

    def _preflight(self) -> dict[str, Any]:
        health = self.transport.request("GET", "/health", timeout=10)
        _status(health, 200, "initial health")
        self._add("initial-health", health.body)
        _clean(health.body, self.expected.target_model, self.expected.wrong_model)
        result = self.transport.request("GET", "/v1/routing/attestation", timeout=10)
        _status(result, 200, "attestation")
        attestation = result.body
        self._add("attestation", attestation)
        required = {
            "receipt_schema": RECEIPT_SCHEMA,
            "key_id": self.expected.signature_key_id,
            "server_build_digest": self.expected.server_build_digest,
            "registry_snapshot_digest": self.expected.registry_snapshot_digest,
            "registry_revision": self.expected.registry_revision,
            "base_model_digest": self.expected.base_model_digest,
            "base_model_revision": self.expected.base_model_revision,
        }
        _fields(attestation, required, "attestation")
        pem = attestation.get("public_key_pem")
        if not isinstance(pem, str):
            raise R5Error("attestation lacks public_key_pem")
        key = _public_key(pem)
        if _key_id(key) != self.expected.signature_key_id:
            raise R5Error("attested public key identifier mismatch")
        self.trusted_public_key_pem = pem
        return attestation

    def _positive(self, model: str, digest: str, name: str) -> None:
        challenge = f"certforge-r5-positive-{model}-{uuid.uuid4()}"
        request = _chat(model, f"R5 provenance probe for {model}")
        result = self.transport.request(
            "POST", "/v1/chat/completions", body=request,
            headers={CHALLENGE_HEADER: challenge}, timeout=95,
        )
        self._add(name, {"status_code": result.status, "body": result.body})
        _status(result, 200, name)
        payload = self._receipt(result.body)
        self._common(payload, request, challenge, model)
        _fields(payload, {
            "selected_adapter_id": model,
            "selected_adapter_digest": digest,
            "active_adapter_ids_before": [model],
            "active_adapter_ids_after": [model],
            "adapter_applied": True,
            "persona_applied": True,
            "fallback_used": False,
        }, name)
        content = _content(result.body).encode()
        _fields(payload, {
            "response_sha256": sha256_bytes(content),
            "response_size_bytes": len(content),
        }, name)

    def _wrong_active(self, attestation: Mapping[str, Any]) -> dict[str, Any]:
        token = self._lease("wrong-active-lease")
        released = False
        try:
            arm = self.transport.request(
                "POST", "/admin/adapter-routing/fault/wrong-active",
                body={"target_adapter_id": self.expected.target_model,
                      "wrong_adapter_id": self.expected.wrong_model},
                headers={LEASE_HEADER: token}, timeout=20,
            )
            self._add("wrong-active-arm", {"status_code": arm.status, "body": arm.body})
            _status(arm, 200, "arm wrong-active")
            released = arm.body.get("released", {}).get("released") is True
            if not released:
                raise R5Error("wrong-active route did not release its lease")
        finally:
            if not released:
                self._release(token)
        challenge = f"certforge-r5-wrong-active-{uuid.uuid4()}"
        request = _chat(self.expected.target_model, "R5 wrong-active control")
        result = self.transport.request(
            "POST", "/v1/chat/completions", body=request,
            headers={CHALLENGE_HEADER: challenge}, timeout=95,
        )
        self._add("wrong-active-response", {"status_code": result.status, "body": result.body})
        _status(result, 409, "wrong-active inference")
        if result.body.get("error_code") != "ADAPTER_IDENTITY_MISMATCH":
            raise R5Error("wrong-active returned the wrong error code")
        payload = self._receipt(result.body)
        self._common(payload, request, challenge, self.expected.target_model)
        _failure(payload, "ADAPTER_IDENTITY_MISMATCH")
        _fields(payload, {
            "selected_adapter_id": self.expected.wrong_model,
            "active_adapter_ids": [self.expected.wrong_model],
        }, "wrong-active receipt")
        self._restored("wrong-active-restored-health")
        return {"control": "wrong_active_adapter", "passed": True,
                "http_status": 409, "error_code": payload["error_code"],
                "receipt_key_id": attestation["key_id"]}

    def _unloaded(self, attestation: Mapping[str, Any]) -> dict[str, Any]:
        token = self._lease("unloaded-lease")
        released = False
        try:
            result = self.transport.request(
                "POST", f"/admin/adapters/{self.expected.target_model}/unload",
                headers={LEASE_HEADER: token}, timeout=20,
            )
            self._add("adapter-unload", {"status_code": result.status, "body": result.body})
            _status(result, 200, "unload adapter")
            if result.body.get("loaded") is not False:
                raise R5Error("adapter did not enter unloaded state")
            result = self.transport.request(
                "POST", "/admin/adapter-routing/release",
                body={"preserve_faults": False, "preserve_unloaded": True},
                headers={LEASE_HEADER: token}, timeout=20,
            )
            self._add("unloaded-release", {"status_code": result.status, "body": result.body})
            _status(result, 200, "release unloaded lease")
            released = result.body.get("released") is True
            if not released or result.body.get("unloaded_preserved") is not True:
                raise R5Error("release did not preserve unloaded state")
        finally:
            if not released:
                self._release(token)
        challenge = f"certforge-r5-unloaded-{uuid.uuid4()}"
        request = _chat(self.expected.target_model, "R5 unloaded-adapter control")
        result = self.transport.request(
            "POST", "/v1/chat/completions", body=request,
            headers={CHALLENGE_HEADER: challenge}, timeout=30,
        )
        self._add("unloaded-response", {"status_code": result.status, "body": result.body})
        _status(result, 503, "unloaded inference")
        if result.body.get("error_code") != "ADAPTER_NOT_ACTIVE":
            raise R5Error("unloaded inference returned the wrong error code")
        payload = self._receipt(result.body)
        self._common(payload, request, challenge, self.expected.target_model)
        _failure(payload, "ADAPTER_NOT_ACTIVE")
        if payload.get("selected_adapter_id") is not None:
            raise R5Error("unloaded receipt selected an adapter")
        if self.expected.target_model in list(payload.get("active_adapter_ids") or []):
            raise R5Error("unloaded receipt falsely reports the target active")
        self._restored("unloaded-restored-health")
        return {"control": "unloaded_adapter", "passed": True,
                "http_status": 503, "error_code": payload["error_code"],
                "receipt_key_id": attestation["key_id"]}

    def _lease(self, name: str) -> str:
        result = self.transport.request(
            "POST", "/admin/adapter-routing/lease",
            body={"ttl_seconds": 60}, timeout=190,
        )
        _status(result, 200, "acquire lease")
        token = result.body.get("lease_token")
        if not isinstance(token, str) or len(token) < 32:
            raise R5Error("lease response lacks a valid token")
        self._add(name, result.body)
        return token

    def _release(self, token: str) -> None:
        name = f"cleanup-release-{uuid.uuid4().hex[:8]}"
        try:
            result = self.transport.request(
                "POST", "/admin/adapter-routing/release",
                body={"preserve_faults": False, "preserve_unloaded": False},
                headers={LEASE_HEADER: token}, timeout=20,
            )
            self._add(name, {"status_code": result.status, "body": result.body})
        except Exception as error:
            self._add(name, {"cleanup_error": f"{type(error).__name__}: {error}"})

    def _restored(self, name: str) -> None:
        deadline = time.monotonic() + 35
        latest: HttpResult | None = None
        while time.monotonic() <= deadline:
            latest = self.transport.request("GET", "/health", timeout=10)
            try:
                _status(latest, 200, "restoration health")
                _clean(latest.body, self.expected.target_model, self.expected.wrong_model)
                self._add(name, latest.body)
                return
            except R5Error:
                time.sleep(0.25)
        if latest:
            self._add(name, {"status_code": latest.status, "body": latest.body})
        raise R5Error("Family server did not restore clean routing state")

    def _receipt(self, body: Mapping[str, Any]) -> dict[str, Any]:
        receipt = body.get("routing_receipt")
        if not isinstance(receipt, dict) or not self.trusted_public_key_pem:
            raise R5Error("response lacks a verifiable routing receipt")
        payload = receipt.get("payload")
        signature = receipt.get("signature_b64")
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise R5Error("routing receipt structure is invalid")
        if receipt.get("key_id") != self.expected.signature_key_id:
            raise R5Error("routing receipt key identifier mismatch")
        if payload.get("signature_key_id") != self.expected.signature_key_id:
            raise R5Error("routing payload key identifier mismatch")
        if "public_key_pem" in receipt:
            raise R5Error("receipt embedded a self-selected public key")
        try:
            key = _public_key(self.trusted_public_key_pem)
            key.verify(base64.b64decode(signature, validate=True), canonical_json(payload).encode())
        except (InvalidSignature, ValueError, TypeError) as error:
            raise R5Error("routing receipt signature is invalid") from error
        return payload

    def _common(
        self, payload: Mapping[str, Any], request: Mapping[str, Any],
        challenge: str, model: str,
    ) -> None:
        _fields(payload, {
            "schema": RECEIPT_SCHEMA,
            "challenge_nonce": challenge,
            "request_sha256": sha256_bytes(canonical_json(dict(request)).encode()),
            "requested_model": model,
            "registry_adapter_id": model,
            "server_build_digest": self.expected.server_build_digest,
            "registry_snapshot_digest": self.expected.registry_snapshot_digest,
            "registry_revision": self.expected.registry_revision,
            "base_model_digest": self.expected.base_model_digest,
            "base_model_revision": self.expected.base_model_revision,
            "signature_key_id": self.expected.signature_key_id,
            "fallback_used": False,
        }, "receipt")


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode()) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R5Error(f"invalid JSON response: {error}") from error
    if not isinstance(value, dict):
        raise R5Error("JSON response must be an object")
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): "[REDACTED]" if str(k).lower() in
                {"lease_token", "token", "authorization"} else _redact(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _status(result: HttpResult, status: int, operation: str) -> None:
    if result.status != status:
        raise R5Error(f"{operation} expected HTTP {status}, observed {result.status}: "
                      f"{canonical_json(result.body)[:800]}")


def _fields(value: Mapping[str, Any], expected: Mapping[str, Any], label: str) -> None:
    for name, wanted in expected.items():
        if value.get(name) != wanted:
            raise R5Error(f"{label} {name} mismatch: expected {wanted!r}, "
                          f"observed {value.get(name)!r}")


def _chat(model: str, prompt: str) -> dict[str, Any]:
    return {"model": model, "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 16, "temperature": 0.0, "top_p": 1.0, "ground": False}


def _content(body: Mapping[str, Any]) -> str:
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise R5Error("completion lacks assistant content") from error
    if not isinstance(content, str):
        raise R5Error("assistant content is not text")
    return content


def _public_key(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        raise R5Error("invalid attestation public key") from error
    if not isinstance(key, Ed25519PublicKey):
        raise R5Error("attestation key is not Ed25519")
    return key


def _key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{sha256_bytes(raw)[:32]}"


def _failure(payload: Mapping[str, Any], code: str) -> None:
    _fields(payload, {"routing_mode": "failure", "adapter_applied": False,
                      "persona_applied": False, "fallback_used": False,
                      "error_code": code, "selected_adapter_digest": None,
                      "persona_enabled": True, "response_sha256": None,
                      "response_size_bytes": None}, "failure receipt")
    if not isinstance(payload.get("error_reason"), str) or not payload["error_reason"].strip():
        raise R5Error("failure receipt lacks an error reason")


def _clean(body: Mapping[str, Any], target: str, wrong: str) -> None:
    if body.get("status") != "ok":
        raise R5Error("Family health is not ok")
    loaded = body.get("loaded")
    if not isinstance(loaded, list) or target not in loaded or wrong not in loaded:
        raise R5Error("required R5 adapters are not loaded")
    state = body.get("routing_maintenance")
    if not isinstance(state, dict):
        raise R5Error("health lacks routing_maintenance")
    if state.get("active") is not False or state.get("drain_requested") is not False:
        raise R5Error("maintenance is active or draining")
    if list(state.get("unloaded") or []) or list(state.get("fault_targets") or []):
        raise R5Error("maintenance state is not clean")


def write_evidence(directory: Path, evidence: Mapping[str, Any], report: Mapping[str, Any]) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=False)
    entries: list[dict[str, Any]] = []
    values = {**dict(evidence), "r5-report": dict(report)}
    for ordinal, (name, value) in enumerate(sorted(values.items()), 1):
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        path = directory / f"{name}.json"
        path.write_bytes(content)
        entries.append({"name": path.name, "ordinal": ordinal,
                        "sha256": sha256_bytes(content), "size_bytes": len(content)})
    manifest = {"schema": "echo.certification-forge.evidence-manifest/v1",
                "entries": entries,
                "merkle_root": merkle_root(x["sha256"] for x in entries)}
    (directory / "evidence-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def execute(expected: ExpectedIdentity, *, transport: Transport | None = None,
            evidence_directory: Path | None = None) -> dict[str, Any]:
    operator = Operator(transport or LoopbackTransport(), expected)
    report = operator.run()
    if evidence_directory is not None:
        report["evidence_manifest"] = write_evidence(
            evidence_directory, operator.evidence, report)
    return report


def _args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Family 14B R5 controls")
    for option in ("server-build-digest", "registry-snapshot-digest",
                   "registry-revision", "signature-key-id", "base-model-digest",
                   "base-model-revision", "target-adapter-digest",
                   "wrong-adapter-digest"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--target-model", default="echo-gs343")
    parser.add_argument("--wrong-model", default="echo-r2d2")
    parser.add_argument("--evidence-directory", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _args(argv)
    expected = ExpectedIdentity(
        server_build_digest=args.server_build_digest,
        registry_snapshot_digest=args.registry_snapshot_digest,
        registry_revision=args.registry_revision,
        signature_key_id=args.signature_key_id,
        base_model_digest=args.base_model_digest,
        base_model_revision=args.base_model_revision,
        target_adapter_digest=args.target_adapter_digest,
        wrong_adapter_digest=args.wrong_adapter_digest,
        target_model=args.target_model,
        wrong_model=args.wrong_model,
    )
    report = execute(expected, evidence_directory=args.evidence_directory)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["r5_gate"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
