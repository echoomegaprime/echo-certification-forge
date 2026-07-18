"""Fail-closed Family 14B adapter-routing receipt verification."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, sha256_bytes, sha256_json

RECEIPT_SCHEMA = "echo.family-routing-receipt/v1"
MARKER_SCHEMA = "echo.release-phase-marker/v1"
CERTIFIED_MATURITY = "CERTIFIED"


class RoutingProofError(ValueError):
    """Raised when routing provenance is absent, malformed, or contradictory."""


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    persona_id: str
    requested_model: str
    adapter_id: str
    adapter_digest: str
    adapter_version: str
    maturity_state: str
    enabled: bool
    registry_revision: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AdapterIdentity":
        required = (
            "persona_id",
            "requested_model",
            "adapter_id",
            "adapter_version",
            "maturity_state",
            "enabled",
            "registry_revision",
        )
        missing = [field for field in required if not value.get(field)]
        if missing:
            raise RoutingProofError(f"adapter identity missing fields: {missing}")
        digest_value = value.get("adapter_artifact_digest", value.get("adapter_digest"))
        if not digest_value:
            raise RoutingProofError("adapter identity missing adapter_artifact_digest")
        digest = str(digest_value).removeprefix("sha256:")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise RoutingProofError("adapter_digest must be a lowercase SHA-256 digest")
        return cls(
            persona_id=str(value["persona_id"]),
            requested_model=str(value["requested_model"]),
            adapter_id=str(value["adapter_id"]),
            adapter_digest=digest,
            adapter_version=str(value["adapter_version"]),
            maturity_state=str(value["maturity_state"]).upper(),
            enabled=value["enabled"] is True,
            registry_revision=str(value["registry_revision"]),
        )


@dataclass(frozen=True, slots=True)
class RoutingReceipt:
    payload: dict[str, Any]
    signature_b64: str
    key_id: str

    @classmethod
    def from_envelope(cls, envelope: Mapping[str, Any]) -> "RoutingReceipt":
        if set(envelope) - {"payload", "signature_b64", "key_id"}:
            raise RoutingProofError("routing receipt envelope contains unsupported fields")
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise RoutingProofError("routing receipt payload must be an object")
        signature_b64 = envelope.get("signature_b64")
        key_id = envelope.get("key_id")
        if not isinstance(signature_b64, str) or not signature_b64:
            raise RoutingProofError("routing receipt signature_b64 is required")
        if not isinstance(key_id, str) or not key_id:
            raise RoutingProofError("routing receipt key_id is required")
        return cls(payload=dict(payload), signature_b64=signature_b64, key_id=key_id)


@dataclass(frozen=True, slots=True)
class RoutingProofResult:
    ok: bool
    status: str
    checks: tuple[dict[str, Any], ...]
    receipt_payload: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "checks": [dict(item) for item in self.checks],
            "receipt_payload": self.receipt_payload,
        }


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise RoutingProofError(f"{field} must be an RFC3339 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RoutingProofError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _trusted_key(key_id: str, trusted_public_keys: Mapping[str, str]) -> Ed25519PublicKey:
    pem = trusted_public_keys.get(key_id)
    if pem is None:
        raise RoutingProofError("untrusted routing receipt signing key")
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise RoutingProofError("routing receipt public key must be Ed25519")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    derived_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    if derived_key_id != key_id:
        raise RoutingProofError("routing receipt key_id does not match trusted public key")
    return key


def _verify_signature(receipt: RoutingReceipt, trusted_public_keys: Mapping[str, str]) -> None:
    key = _trusted_key(receipt.key_id, trusted_public_keys)
    try:
        signature = base64.b64decode(receipt.signature_b64, validate=True)
        key.verify(signature, canonical_json(receipt.payload).encode("utf-8"))
    except (InvalidSignature, ValueError) as error:
        raise RoutingProofError("invalid routing receipt signature") from error


def _check(checks: list[dict[str, Any]], name: str, passed: bool, actual: Any, expected: Any) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "actual": actual,
            "expected": expected,
        }
    )


def verify_persona_routing(
    *,
    response: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    expected: AdapterIdentity,
    trusted_public_keys: Mapping[str, str],
) -> RoutingProofResult:
    """Verify that a persona response used the exact certified LoRA adapter."""
    envelope = response.get("routing_receipt")
    if not isinstance(envelope, Mapping):
        return RoutingProofResult(
            ok=False,
            status="BLOCK",
            checks=(
                {
                    "name": "routing_receipt_present",
                    "passed": False,
                    "actual": type(envelope).__name__,
                    "expected": "signed routing_receipt object",
                },
            ),
            receipt_payload=None,
        )

    try:
        receipt = RoutingReceipt.from_envelope(envelope)
        _verify_signature(receipt, trusted_public_keys)
        payload = receipt.payload
        started = _parse_utc(payload.get("started_at"), "started_at")
        completed = _parse_utc(payload.get("completed_at"), "completed_at")
    except (RoutingProofError, TypeError, ValueError) as error:
        return RoutingProofResult(
            ok=False,
            status="BLOCK",
            checks=(
                {
                    "name": "routing_receipt_valid",
                    "passed": False,
                    "actual": str(error),
                    "expected": "valid trusted Ed25519 receipt",
                },
            ),
            receipt_payload=dict(envelope.get("payload", {})) if isinstance(envelope.get("payload"), dict) else None,
        )

    checks: list[dict[str, Any]] = []
    _check(checks, "receipt_schema", payload.get("schema") == RECEIPT_SCHEMA, payload.get("schema"), RECEIPT_SCHEMA)
    _check(checks, "receipt_key_id", payload.get("signature_key_id") == receipt.key_id, payload.get("signature_key_id"), receipt.key_id)
    _check(checks, "challenge_nonce", payload.get("challenge_nonce") == challenge_nonce, payload.get("challenge_nonce"), challenge_nonce)
    expected_request_hash = sha256_json(dict(request_payload))
    _check(checks, "request_sha256", payload.get("request_sha256") == expected_request_hash, payload.get("request_sha256"), expected_request_hash)
    _check(checks, "requested_model", payload.get("requested_model") == expected.requested_model, payload.get("requested_model"), expected.requested_model)
    _check(checks, "response_model", response.get("model") == expected.requested_model, response.get("model"), expected.requested_model)
    _check(checks, "requested_persona", payload.get("requested_persona") == expected.persona_id, payload.get("requested_persona"), expected.persona_id)
    _check(checks, "registry_adapter_id", payload.get("registry_adapter_id") == expected.adapter_id, payload.get("registry_adapter_id"), expected.adapter_id)
    _check(checks, "selected_adapter_id", payload.get("selected_adapter_id") == expected.adapter_id, payload.get("selected_adapter_id"), expected.adapter_id)
    selected_digest = str(payload.get("selected_adapter_digest", "")).removeprefix("sha256:")
    _check(checks, "selected_adapter_digest", selected_digest == expected.adapter_digest, selected_digest, expected.adapter_digest)
    _check(checks, "adapter_version", payload.get("adapter_version") == expected.adapter_version, payload.get("adapter_version"), expected.adapter_version)
    _check(checks, "registry_revision", payload.get("registry_revision") == expected.registry_revision, payload.get("registry_revision"), expected.registry_revision)
    _check(checks, "persona_enabled", expected.enabled is True, expected.enabled, True)
    _check(checks, "maturity_certified", expected.maturity_state == CERTIFIED_MATURITY, expected.maturity_state, CERTIFIED_MATURITY)
    _check(checks, "routing_mode", payload.get("routing_mode") == "lora_adapter", payload.get("routing_mode"), "lora_adapter")
    _check(checks, "adapter_applied", payload.get("adapter_applied") is True, payload.get("adapter_applied"), True)
    _check(checks, "persona_applied", payload.get("persona_applied") is True, payload.get("persona_applied"), True)
    _check(checks, "fallback_used", payload.get("fallback_used") is False, payload.get("fallback_used"), False)
    active = payload.get("active_adapter_ids")
    _check(checks, "active_adapter_ids", active == [expected.adapter_id], active, [expected.adapter_id])
    _check(checks, "slot_lease_id", isinstance(payload.get("slot_lease_id"), str) and bool(payload.get("slot_lease_id")), payload.get("slot_lease_id"), "non-empty string")
    _check(checks, "request_id", isinstance(payload.get("request_id"), str) and bool(payload.get("request_id")), payload.get("request_id"), "non-empty string")
    _check(checks, "server_build_digest", isinstance(payload.get("server_build_digest"), str) and len(str(payload.get("server_build_digest")).removeprefix("sha256:")) == 64, payload.get("server_build_digest"), "sha256 digest")
    _check(checks, "base_model_digest", isinstance(payload.get("base_model_digest"), str) and len(str(payload.get("base_model_digest")).removeprefix("sha256:")) == 64, payload.get("base_model_digest"), "sha256 digest")
    _check(checks, "completion_order", completed >= started, payload.get("completed_at"), ">= started_at")
    _check(checks, "fallback_reason_empty", payload.get("fallback_reason") in (None, ""), payload.get("fallback_reason"), None)

    ok = all(item["passed"] for item in checks)
    return RoutingProofResult(
        ok=ok,
        status="PASS" if ok else "BLOCK",
        checks=tuple(checks),
        receipt_payload=payload,
    )


def verify_base_routing(
    *,
    response: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    trusted_public_keys: Mapping[str, str],
) -> RoutingProofResult:
    """Verify an explicit base request cannot be mislabeled as a persona route."""
    envelope = response.get("routing_receipt")
    if not isinstance(envelope, Mapping):
        return RoutingProofResult(False, "BLOCK", ({"name": "routing_receipt_present", "passed": False},), None)
    try:
        receipt = RoutingReceipt.from_envelope(envelope)
        _verify_signature(receipt, trusted_public_keys)
    except (RoutingProofError, TypeError, ValueError) as error:
        return RoutingProofResult(False, "BLOCK", ({"name": "routing_receipt_valid", "passed": False, "actual": str(error)},), None)

    payload = receipt.payload
    checks: list[dict[str, Any]] = []
    _check(checks, "receipt_schema", payload.get("schema") == RECEIPT_SCHEMA, payload.get("schema"), RECEIPT_SCHEMA)
    _check(checks, "challenge_nonce", payload.get("challenge_nonce") == challenge_nonce, payload.get("challenge_nonce"), challenge_nonce)
    expected_hash = sha256_json(dict(request_payload))
    _check(checks, "request_sha256", payload.get("request_sha256") == expected_hash, payload.get("request_sha256"), expected_hash)
    _check(checks, "requested_model", payload.get("requested_model") == "echo-prime", payload.get("requested_model"), "echo-prime")
    _check(checks, "response_model", response.get("model") == "echo-prime", response.get("model"), "echo-prime")
    _check(checks, "routing_mode", payload.get("routing_mode") == "base", payload.get("routing_mode"), "base")
    _check(checks, "adapter_applied", payload.get("adapter_applied") is False, payload.get("adapter_applied"), False)
    _check(checks, "persona_applied", payload.get("persona_applied") is False, payload.get("persona_applied"), False)
    _check(checks, "fallback_used", payload.get("fallback_used") is False, payload.get("fallback_used"), False)
    _check(checks, "selected_adapter_id", payload.get("selected_adapter_id") in (None, ""), payload.get("selected_adapter_id"), None)
    _check(checks, "active_adapter_ids", payload.get("active_adapter_ids") == [], payload.get("active_adapter_ids"), [])
    ok = all(item["passed"] for item in checks)
    return RoutingProofResult(ok, "PASS" if ok else "BLOCK", tuple(checks), payload)


def verify_unloaded_adapter_failure(
    *,
    error_response: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    expected: AdapterIdentity,
    trusted_public_keys: Mapping[str, str],
) -> RoutingProofResult:
    """Verify the negative control fails visibly rather than silently serving base."""
    envelope = error_response.get("routing_receipt")
    if not isinstance(envelope, Mapping):
        return RoutingProofResult(False, "BLOCK", ({"name": "failure_receipt_present", "passed": False},), None)
    try:
        receipt = RoutingReceipt.from_envelope(envelope)
        _verify_signature(receipt, trusted_public_keys)
    except (RoutingProofError, TypeError, ValueError) as error:
        return RoutingProofResult(False, "BLOCK", ({"name": "failure_receipt_valid", "passed": False, "actual": str(error)},), None)

    payload = receipt.payload
    checks: list[dict[str, Any]] = []
    _check(checks, "error_code", error_response.get("error_code") == "ADAPTER_NOT_ACTIVE", error_response.get("error_code"), "ADAPTER_NOT_ACTIVE")
    _check(checks, "challenge_nonce", payload.get("challenge_nonce") == challenge_nonce, payload.get("challenge_nonce"), challenge_nonce)
    _check(checks, "request_sha256", payload.get("request_sha256") == sha256_json(dict(request_payload)), payload.get("request_sha256"), sha256_json(dict(request_payload)))
    _check(checks, "requested_model", payload.get("requested_model") == expected.requested_model, payload.get("requested_model"), expected.requested_model)
    _check(checks, "registry_adapter_id", payload.get("registry_adapter_id") == expected.adapter_id, payload.get("registry_adapter_id"), expected.adapter_id)
    _check(checks, "adapter_version", payload.get("adapter_version") == expected.adapter_version, payload.get("adapter_version"), expected.adapter_version)
    _check(checks, "registry_revision", payload.get("registry_revision") == expected.registry_revision, payload.get("registry_revision"), expected.registry_revision)
    _check(checks, "persona_enabled", expected.enabled is True, expected.enabled, True)
    _check(checks, "routing_mode", payload.get("routing_mode") == "failure", payload.get("routing_mode"), "failure")
    _check(checks, "adapter_applied", payload.get("adapter_applied") is False, payload.get("adapter_applied"), False)
    _check(checks, "persona_applied", payload.get("persona_applied") is False, payload.get("persona_applied"), False)
    _check(checks, "fallback_used", payload.get("fallback_used") is False, payload.get("fallback_used"), False)
    _check(checks, "selected_adapter_id", payload.get("selected_adapter_id") in (None, ""), payload.get("selected_adapter_id"), None)
    ok = all(item["passed"] for item in checks)
    return RoutingProofResult(ok, "PASS" if ok else "BLOCK", tuple(checks), payload)
