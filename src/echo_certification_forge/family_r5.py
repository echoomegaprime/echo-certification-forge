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
FULL_EVIDENCE_NAMES = frozenset(
    {
        "adapter-unload.json",
        "attestation.json",
        "final-health.json",
        "initial-health.json",
        "positive-target.json",
        "positive-wrong.json",
        "r5-report.json",
        "unloaded-lease.json",
        "unloaded-release.json",
        "unloaded-response.json",
        "unloaded-restored-health.json",
        "wrong-active-arm.json",
        "wrong-active-lease.json",
        "wrong-active-response.json",
        "wrong-active-restored-health.json",
    }
)


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

    def run_preflight(self) -> dict[str, Any]:
        """Read-only preflight: health + attestation + identity/key verification.

        Fires NO lease, fault, unload, or inference — it does not mutate routing
        state. Used as the dry-run that proves the whole path (grant -> SSH ->
        loopback -> attestation) without touching the live family server.
        """
        blocker: str | None = None
        try:
            self._preflight()
        except Exception as error:  # noqa: BLE001 - deterministic gate boundary
            blocker = f"{type(error).__name__}: {error}"
        passed = blocker is None
        return {
            "schema": SCHEMA,
            "mode": "preflight",
            "run_outcome": "PREFLIGHT_OK" if passed else "INCONCLUSIVE",
            "release_verdict": "NOT_READY",
            "r5_gate": "BLOCK",  # preflight NEVER passes the gate; live controls do
            "deployment_authorized": False,
            "completion_marker": None,
            "controls": [],
            "blocker": blocker,
            "expected_identity": {
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
            headers={CHALLENGE_HEADER: challenge}, timeout=190,
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
            headers={CHALLENGE_HEADER: challenge}, timeout=190,
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


def _load_evidence_json(directory: Path, name: str) -> dict[str, Any]:
    path = directory / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise R5Error(f"invalid R5 evidence {name}: {error}") from error
    if not isinstance(value, dict):
        raise R5Error(f"R5 evidence {name} must be an object")
    return value


def _verify_evidence_manifest(directory: Path) -> dict[str, Any]:
    manifest = _load_evidence_json(directory, "evidence-manifest.json")
    if manifest.get("schema") != "echo.certification-forge.evidence-manifest/v1":
        raise R5Error("R5 evidence manifest schema is invalid")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(FULL_EVIDENCE_NAMES):
        raise R5Error("R5 full evidence manifest has the wrong entry count")
    names: set[str] = set()
    leaves: list[str] = []
    for ordinal, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise R5Error("R5 evidence manifest entry must be an object")
        name = entry.get("name")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or name in names
            or entry.get("ordinal") != ordinal
        ):
            raise R5Error("R5 evidence manifest name or ordinal is invalid")
        path = directory / name
        try:
            content = path.read_bytes()
        except OSError as error:
            raise R5Error(f"R5 evidence manifest file is missing: {name}") from error
        digest = sha256_bytes(content)
        if entry.get("sha256") != digest or entry.get("size_bytes") != len(content):
            raise R5Error(f"R5 evidence manifest binding failed for {name}")
        names.add(name)
        leaves.append(digest)
    if names != FULL_EVIDENCE_NAMES:
        raise R5Error("R5 evidence manifest is not the canonical full-run file set")
    if manifest.get("merkle_root") != merkle_root(leaves):
        raise R5Error("R5 evidence manifest Merkle root is invalid")
    disk_json = {
        path.name
        for path in directory.glob("*.json")
        if path.name != "evidence-manifest.json"
    }
    if disk_json != FULL_EVIDENCE_NAMES:
        raise R5Error("R5 evidence directory contains missing or unexpected JSON files")
    return manifest


def _verify_signed_receipt(
    receipt: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise R5Error("R5 response lacks a routing receipt")
    payload = receipt.get("payload")
    signature = receipt.get("signature_b64")
    if (
        not isinstance(payload, dict)
        or not isinstance(signature, str)
        or receipt.get("key_id") != key_id
        or payload.get("signature_key_id") != key_id
    ):
        raise R5Error("R5 routing receipt structure or key is invalid")
    try:
        key.verify(
            base64.b64decode(signature, validate=True),
            canonical_json(payload).encode("utf-8"),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise R5Error("R5 routing receipt signature is invalid") from error
    return payload


def _verify_completion_receipt(
    evidence: Mapping[str, Any],
    *,
    key: Ed25519PublicKey,
    key_id: str,
    model: str,
    adapter_digest: str,
    identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if evidence.get("status_code") != 200:
        raise R5Error(f"R5 positive evidence for {model} is not HTTP 200")
    body = evidence.get("body")
    if not isinstance(body, dict):
        raise R5Error(f"R5 positive evidence for {model} lacks a response body")
    payload = _verify_signed_receipt(
        body.get("routing_receipt"),
        key=key,
        key_id=key_id,
    )
    content = _content(body)
    required = {
        "schema": RECEIPT_SCHEMA,
        "requested_model": model,
        "registry_adapter_id": model,
        "selected_adapter_id": model,
        "selected_adapter_digest": adapter_digest,
        "adapter_applied": True,
        "persona_applied": True,
        "fallback_used": False,
        "routing_mode": "lora_adapter",
        "server_build_digest": identity["server_build_digest"],
        "registry_snapshot_digest": identity["registry_snapshot_digest"],
        "registry_revision": identity["registry_revision"],
        "base_model_digest": identity["base_model_digest"],
        "base_model_revision": identity["base_model_revision"],
        "response_sha256": sha256_bytes(content.encode("utf-8")),
        "response_size_bytes": len(content.encode("utf-8")),
    }
    _fields(payload, required, f"positive receipt {model}")
    challenge = payload.get("challenge_nonce")
    if not isinstance(challenge, str) or not challenge.startswith(
        f"certforge-r5-positive-{model}-"
    ):
        raise R5Error(f"R5 positive receipt challenge is invalid for {model}")
    return payload, body["routing_receipt"]


def _verify_negative_receipt(
    evidence: Mapping[str, Any],
    *,
    key: Ed25519PublicKey,
    key_id: str,
    target_model: str,
    wrong_model: str,
    identity: Mapping[str, Any],
    control: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if control == "wrong_active_adapter":
        status, code, selected = 409, "ADAPTER_IDENTITY_MISMATCH", wrong_model
        challenge_prefix = "certforge-r5-wrong-active-"
    else:
        status, code, selected = 503, "ADAPTER_NOT_ACTIVE", None
        challenge_prefix = "certforge-r5-unloaded-"
    if evidence.get("status_code") != status:
        raise R5Error(f"R5 {control} evidence has the wrong HTTP status")
    body = evidence.get("body")
    if not isinstance(body, dict) or body.get("error_code") != code:
        raise R5Error(f"R5 {control} evidence has the wrong error code")
    payload = _verify_signed_receipt(
        body.get("routing_receipt"),
        key=key,
        key_id=key_id,
    )
    _failure(payload, code)
    required = {
        "schema": RECEIPT_SCHEMA,
        "requested_model": target_model,
        "registry_adapter_id": target_model,
        "selected_adapter_id": selected,
        "server_build_digest": identity["server_build_digest"],
        "registry_snapshot_digest": identity["registry_snapshot_digest"],
        "registry_revision": identity["registry_revision"],
        "base_model_digest": identity["base_model_digest"],
        "base_model_revision": identity["base_model_revision"],
    }
    _fields(payload, required, f"negative receipt {control}")
    challenge = payload.get("challenge_nonce")
    if not isinstance(challenge, str) or not challenge.startswith(challenge_prefix):
        raise R5Error(f"R5 {control} receipt challenge is invalid")
    return payload, body["routing_receipt"]


def verify_full_r5_evidence(
    directory: Path,
    *,
    trusted_public_key_pem: str,
    trusted_key_id: str,
    target_model: str,
    target_adapter_digest: str,
    wrong_model: str,
    wrong_adapter_digest: str,
) -> dict[str, Any]:
    """Verify the complete canonical R5 full-run evidence package."""
    require_sha256(target_adapter_digest, "target_adapter_digest")
    require_sha256(wrong_adapter_digest, "wrong_adapter_digest")
    if target_model == wrong_model or target_adapter_digest == wrong_adapter_digest:
        raise R5Error("R5 target and wrong identities must differ")
    key = _public_key(trusted_public_key_pem)
    if _key_id(key) != trusted_key_id:
        raise R5Error("R5 trusted key id does not match its public key")
    manifest = _verify_evidence_manifest(directory)
    report = _load_evidence_json(directory, "r5-report.json")
    if (
        report.get("schema") != SCHEMA
        or report.get("run_outcome") != "COMPLETE"
        or report.get("r5_gate") != "PASS"
        or report.get("completion_marker") != "[R5 COMPLETE]"
        or report.get("blocker") is not None
        or report.get("deployment_authorized") is not False
    ):
        raise R5Error("R5 report is not a completed full-run PASS")
    expected = report.get("expected_identity")
    if not isinstance(expected, dict):
        raise R5Error("R5 report lacks expected identity")
    required_identity = {
        "target_model": target_model,
        "wrong_model": wrong_model,
        "target_adapter_digest": target_adapter_digest,
        "wrong_adapter_digest": wrong_adapter_digest,
        "signature_key_id": trusted_key_id,
    }
    _fields(expected, required_identity, "R5 expected identity")
    for field in (
        "server_build_digest",
        "registry_snapshot_digest",
        "base_model_digest",
    ):
        require_sha256(str(expected.get(field)), field)
    for field in ("registry_revision", "base_model_revision"):
        if not isinstance(expected.get(field), str) or not expected[field]:
            raise R5Error(f"R5 expected identity lacks {field}")

    bundle = report.get("forge_verification_bundle")
    if not isinstance(bundle, dict) or bundle.get("mode") != "full":
        raise R5Error("R5 forge verification bundle is not full mode")
    if (
        bundle.get("public_key_pem") != trusted_public_key_pem
        or bundle.get("attested_key_id") != trusted_key_id
    ):
        raise R5Error("R5 forge bundle differs from the external trusted key")
    bundle_identity = {
        "attested_server_build_digest": expected["server_build_digest"],
        "attested_registry_snapshot_digest": expected["registry_snapshot_digest"],
        "attested_registry_revision": expected["registry_revision"],
        "attested_base_model_digest": expected["base_model_digest"],
        "attested_base_model_revision": expected["base_model_revision"],
    }
    _fields(bundle, bundle_identity, "R5 forge bundle")

    attestation = _load_evidence_json(directory, "attestation.json")
    _fields(
        attestation,
        {
            "receipt_schema": RECEIPT_SCHEMA,
            "key_id": trusted_key_id,
            "public_key_pem": trusted_public_key_pem,
            "server_build_digest": expected["server_build_digest"],
            "registry_snapshot_digest": expected["registry_snapshot_digest"],
            "registry_revision": expected["registry_revision"],
            "base_model_digest": expected["base_model_digest"],
            "base_model_revision": expected["base_model_revision"],
        },
        "R5 attestation",
    )
    requested_models = attestation.get("requested_models")
    if not isinstance(requested_models, list) or not {
        target_model,
        wrong_model,
    }.issubset(set(requested_models)):
        raise R5Error("R5 attestation does not cover both models")

    for name in (
        "initial-health.json",
        "wrong-active-restored-health.json",
        "unloaded-restored-health.json",
        "final-health.json",
    ):
        health = _load_evidence_json(directory, name)
        _clean(health, target_model, wrong_model)
    wrong_active_arm = _load_evidence_json(directory, "wrong-active-arm.json")
    if wrong_active_arm.get("status_code") != 200 or not isinstance(
        wrong_active_arm.get("body"), dict
    ):
        raise R5Error("R5 wrong-active arm response is invalid")
    wrong_active_arm = wrong_active_arm["body"]
    if (
        wrong_active_arm.get("armed")
        != {
            "target_adapter_id": target_model,
            "wrong_adapter_id": wrong_model,
            "armed": True,
        }
        or wrong_active_arm.get("released", {}).get("released") is not True
        or wrong_active_arm.get("released", {}).get("fault_preserved") is not True
    ):
        raise R5Error("R5 wrong-active control was not canonically armed and released")
    adapter_unload = _load_evidence_json(directory, "adapter-unload.json")
    if adapter_unload.get("status_code") != 200 or not isinstance(
        adapter_unload.get("body"), dict
    ):
        raise R5Error("R5 unload response is invalid")
    adapter_unload = adapter_unload["body"]
    if adapter_unload != {"adapter_id": target_model, "loaded": False}:
        raise R5Error("R5 unload control does not bind the target adapter")
    unloaded_release = _load_evidence_json(directory, "unloaded-release.json")
    if unloaded_release.get("status_code") != 200 or not isinstance(
        unloaded_release.get("body"), dict
    ):
        raise R5Error("R5 unloaded release response is invalid")
    unloaded_release = unloaded_release["body"]
    if (
        unloaded_release.get("released") is not True
        or unloaded_release.get("unloaded_preserved") is not True
        or unloaded_release.get("fault_preserved") is not False
    ):
        raise R5Error("R5 unloaded control was not canonically preserved")

    target_payload, target_receipt = _verify_completion_receipt(
        _load_evidence_json(directory, "positive-target.json"),
        key=key,
        key_id=trusted_key_id,
        model=target_model,
        adapter_digest=target_adapter_digest,
        identity=expected,
    )
    wrong_payload, _ = _verify_completion_receipt(
        _load_evidence_json(directory, "positive-wrong.json"),
        key=key,
        key_id=trusted_key_id,
        model=wrong_model,
        adapter_digest=wrong_adapter_digest,
        identity=expected,
    )
    wrong_active_payload, wrong_active_receipt = _verify_negative_receipt(
        _load_evidence_json(directory, "wrong-active-response.json"),
        key=key,
        key_id=trusted_key_id,
        target_model=target_model,
        wrong_model=wrong_model,
        identity=expected,
        control="wrong_active_adapter",
    )
    unloaded_payload, unloaded_receipt = _verify_negative_receipt(
        _load_evidence_json(directory, "unloaded-response.json"),
        key=key,
        key_id=trusted_key_id,
        target_model=target_model,
        wrong_model=wrong_model,
        identity=expected,
        control="unloaded_adapter",
    )
    request_ids = [
        target_payload.get("request_id"),
        wrong_payload.get("request_id"),
        wrong_active_payload.get("request_id"),
        unloaded_payload.get("request_id"),
    ]
    challenges = [
        target_payload.get("challenge_nonce"),
        wrong_payload.get("challenge_nonce"),
        wrong_active_payload.get("challenge_nonce"),
        unloaded_payload.get("challenge_nonce"),
    ]
    if (
        any(not isinstance(item, str) or not item for item in request_ids + challenges)
        or len(set(request_ids)) != 4
        or len(set(challenges)) != 4
    ):
        raise R5Error("R5 evidence reuses or omits request identity")

    controls = report.get("controls")
    expected_controls = {
        "wrong_active_adapter": (409, "ADAPTER_IDENTITY_MISMATCH"),
        "unloaded_adapter": (503, "ADAPTER_NOT_ACTIVE"),
    }
    if not isinstance(controls, list) or len(controls) != 2:
        raise R5Error("R5 report must contain exactly two negative controls")
    observed_controls: dict[str, tuple[Any, Any]] = {}
    for control in controls:
        if not isinstance(control, dict) or control.get("passed") is not True:
            raise R5Error("R5 report contains a failed negative control")
        observed_controls[str(control.get("control"))] = (
            control.get("http_status"),
            control.get("error_code"),
        )
        if control.get("receipt_key_id") != trusted_key_id:
            raise R5Error("R5 control receipt key id mismatch")
    if observed_controls != expected_controls:
        raise R5Error("R5 report negative controls are incomplete or incorrect")

    bundle_receipts = bundle.get("receipts")
    if not isinstance(bundle_receipts, list) or len(bundle_receipts) != 2:
        raise R5Error("R5 forge bundle must contain exactly two control receipts")
    expected_receipts = {
        "wrong_active_adapter": wrong_active_receipt,
        "unloaded_adapter": unloaded_receipt,
    }
    for entry in bundle_receipts:
        if not isinstance(entry, dict):
            raise R5Error("R5 forge bundle receipt entry is invalid")
        control = entry.get("control")
        receipt = expected_receipts.get(str(control))
        if receipt is None or entry != {
            "control": control,
            "key_id": receipt.get("key_id"),
            "payload": receipt.get("payload"),
            "signature_b64": receipt.get("signature_b64"),
        }:
            raise R5Error("R5 forge bundle receipt does not match evidence")
    return {
        "report": report,
        "manifest": manifest,
        "target_receipt": target_receipt,
        "target_payload": target_payload,
    }


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


def _build_bundle(operator: "Operator", mode: str) -> dict[str, Any]:
    """Assemble the material FORGE independently re-verifies: the attested public
    key + key_id + (for the full run) each negative-control routing receipt with
    its signature. No tokens or private material — receipts are public evidence."""
    pem = operator.trusted_public_key_pem
    attestation = operator.evidence.get("attestation") or {}
    receipts: list[dict[str, Any]] = []
    if mode == "full":
        for control, key in (("wrong_active_adapter", "wrong-active-response"),
                             ("unloaded_adapter", "unloaded-response")):
            body = (operator.evidence.get(key) or {}).get("body") or {}
            receipt = body.get("routing_receipt")
            if isinstance(receipt, dict):
                receipts.append({
                    "control": control,
                    "key_id": receipt.get("key_id"),
                    "payload": receipt.get("payload"),
                    "signature_b64": receipt.get("signature_b64"),
                })
    return {
        "schema": "echo.certification-forge.forge-verification-bundle/v1",
        "mode": mode,
        "public_key_pem": pem,
        "attested_key_id": attestation.get("key_id"),
        "attested_server_build_digest": attestation.get("server_build_digest"),
        "attested_registry_snapshot_digest": attestation.get("registry_snapshot_digest"),
        "attested_registry_revision": attestation.get("registry_revision"),
        "attested_base_model_digest": attestation.get("base_model_digest"),
        "attested_base_model_revision": attestation.get("base_model_revision"),
        "receipts": receipts,
    }


def execute(expected: ExpectedIdentity, *, mode: str = "full",
            transport: Transport | None = None,
            evidence_directory: Path | None = None) -> dict[str, Any]:
    if mode not in {"full", "preflight"}:
        raise ValueError("mode must be 'full' or 'preflight'")
    operator = Operator(transport or LoopbackTransport(), expected)
    report = operator.run_preflight() if mode == "preflight" else operator.run()
    report["forge_verification_bundle"] = _build_bundle(operator, mode)
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
    parser.add_argument("--mode", choices=("full", "preflight"), default="full")
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
    report = execute(expected, mode=args.mode,
                     evidence_directory=args.evidence_directory)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.mode == "preflight":
        return 0 if report["run_outcome"] == "PREFLIGHT_OK" else 2
    return 0 if report["r5_gate"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
