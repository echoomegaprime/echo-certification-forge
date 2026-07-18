"""Standalone signed routing receipts for the ANVIL Family 14B server.

This module is designed to be imported by ``serve_echo_family.py``.  The caller
must supply route state obtained from the live PEFT/model objects immediately
before and after generation.  A request label or routing-table lookup is not
accepted as proof that an adapter was applied.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RECEIPT_SCHEMA = "echo.family-routing-receipt/v1"


class AdapterRouteMismatch(RuntimeError):
    """Raised before generation when actual model state contradicts the route."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def utc_iso(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("routing receipt timestamps must be timezone-aware")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_digest(value: str, field: str) -> str:
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return digest


@dataclass(frozen=True, slots=True)
class ExpectedAdapter:
    persona_id: str
    requested_model: str
    adapter_id: str
    adapter_digest: str
    adapter_version: str
    registry_revision: str

    def __post_init__(self) -> None:
        normalize_digest(self.adapter_digest, "adapter_digest")


@dataclass(frozen=True, slots=True)
class ActualRouteState:
    """State read from the live model/PEFT objects, never from request labels."""

    selected_adapter_id: str | None
    selected_adapter_digest: str | None
    active_adapter_ids: tuple[str, ...]
    adapter_applied: bool

    @classmethod
    def from_runtime(
        cls,
        *,
        selected_adapter_id: str | None,
        selected_adapter_digest: str | None,
        active_adapter_ids: Sequence[str],
        adapter_applied: bool,
    ) -> "ActualRouteState":
        active = tuple(str(item) for item in active_adapter_ids)
        if len(set(active)) != len(active):
            raise AdapterRouteMismatch("runtime reported duplicate active adapters")
        if len(active) > 1:
            raise AdapterRouteMismatch("Family server supports exactly one active adapter per generation")
        if selected_adapter_digest is not None:
            normalize_digest(selected_adapter_digest, "selected_adapter_digest")
        return cls(
            selected_adapter_id=selected_adapter_id,
            selected_adapter_digest=selected_adapter_digest,
            active_adapter_ids=active,
            adapter_applied=bool(adapter_applied),
        )


class RoutingReceiptSigner:
    """Ed25519 routing-attestation signer; private material stays on ANVIL."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def from_private_pem(cls, pem: bytes, password: bytes | None = None) -> "RoutingReceiptSigner":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("routing receipt private key must be Ed25519")
        return cls(key)

    @property
    def key_id(self) -> str:
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        material = dict(payload)
        if material.get("signature_key_id") != self.key_id:
            raise ValueError("payload signature_key_id does not match routing signer")
        signature = self._private_key.sign(canonical_json(material).encode("utf-8"))
        return {
            "payload": material,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "key_id": self.key_id,
        }


def assert_persona_route(expected: ExpectedAdapter, actual: ActualRouteState) -> None:
    expected_digest = normalize_digest(expected.adapter_digest, "adapter_digest")
    actual_digest = (
        normalize_digest(actual.selected_adapter_digest, "selected_adapter_digest")
        if actual.selected_adapter_digest is not None
        else None
    )
    failures: list[str] = []
    if not actual.adapter_applied:
        failures.append("adapter_applied_false")
    if actual.selected_adapter_id != expected.adapter_id:
        failures.append("selected_adapter_id_mismatch")
    if actual_digest != expected_digest:
        failures.append("selected_adapter_digest_mismatch")
    if actual.active_adapter_ids != (expected.adapter_id,):
        failures.append("active_adapter_ids_mismatch")
    if failures:
        raise AdapterRouteMismatch(",".join(failures))


def assert_base_route(actual: ActualRouteState) -> None:
    failures: list[str] = []
    if actual.adapter_applied:
        failures.append("base_route_adapter_applied")
    if actual.selected_adapter_id is not None:
        failures.append("base_route_selected_adapter_present")
    if actual.selected_adapter_digest is not None:
        failures.append("base_route_adapter_digest_present")
    if actual.active_adapter_ids:
        failures.append("base_route_active_adapter_present")
    if failures:
        raise AdapterRouteMismatch(",".join(failures))


def _common_payload(
    *,
    signer: RoutingReceiptSigner,
    request_id: str,
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    server_build_digest: str,
    base_model_id: str,
    base_model_digest: str,
    requested_model: str,
    started_at: datetime,
    completed_at: datetime,
    slot_lease_id: str | None,
) -> dict[str, Any]:
    if not challenge_nonce or len(challenge_nonce) < 16:
        raise ValueError("routing challenge nonce must contain at least 16 characters")
    if not request_id:
        raise ValueError("request_id is required")
    if completed_at < started_at:
        raise ValueError("completed_at cannot precede started_at")
    return {
        "schema": RECEIPT_SCHEMA,
        "request_id": request_id,
        "request_sha256": sha256_json(dict(request_payload)),
        "challenge_nonce": challenge_nonce,
        "server_build_digest": normalize_digest(server_build_digest, "server_build_digest"),
        "base_model_id": base_model_id,
        "base_model_digest": normalize_digest(base_model_digest, "base_model_digest"),
        "requested_model": requested_model,
        "slot_lease_id": slot_lease_id,
        "started_at": utc_iso(started_at),
        "completed_at": utc_iso(completed_at),
        "signature_key_id": signer.key_id,
    }


def persona_receipt(
    *,
    signer: RoutingReceiptSigner,
    expected: ExpectedAdapter,
    actual: ActualRouteState,
    request_id: str,
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    server_build_digest: str,
    base_model_id: str,
    base_model_digest: str,
    slot_lease_id: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    """Create a receipt only after the exact expected adapter is active."""
    assert_persona_route(expected, actual)
    payload = _common_payload(
        signer=signer,
        request_id=request_id,
        request_payload=request_payload,
        challenge_nonce=challenge_nonce,
        server_build_digest=server_build_digest,
        base_model_id=base_model_id,
        base_model_digest=base_model_digest,
        requested_model=expected.requested_model,
        slot_lease_id=slot_lease_id,
        started_at=started_at,
        completed_at=completed_at,
    )
    payload.update(
        {
            "requested_persona": expected.persona_id,
            "registry_adapter_id": expected.adapter_id,
            "selected_adapter_id": actual.selected_adapter_id,
            "selected_adapter_digest": normalize_digest(
                str(actual.selected_adapter_digest), "selected_adapter_digest"
            ),
            "adapter_version": expected.adapter_version,
            "registry_revision": expected.registry_revision,
            "active_adapter_ids": list(actual.active_adapter_ids),
            "routing_mode": "lora_adapter",
            "adapter_applied": True,
            "persona_applied": True,
            "fallback_used": False,
            "fallback_reason": None,
        }
    )
    return signer.sign(payload)


def base_receipt(
    *,
    signer: RoutingReceiptSigner,
    actual: ActualRouteState,
    request_id: str,
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    server_build_digest: str,
    base_model_id: str,
    base_model_digest: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    assert_base_route(actual)
    payload = _common_payload(
        signer=signer,
        request_id=request_id,
        request_payload=request_payload,
        challenge_nonce=challenge_nonce,
        server_build_digest=server_build_digest,
        base_model_id=base_model_id,
        base_model_digest=base_model_digest,
        requested_model="echo-prime",
        slot_lease_id=None,
        started_at=started_at,
        completed_at=completed_at,
    )
    payload.update(
        {
            "requested_persona": None,
            "registry_adapter_id": None,
            "selected_adapter_id": None,
            "selected_adapter_digest": None,
            "active_adapter_ids": [],
            "routing_mode": "base",
            "adapter_applied": False,
            "persona_applied": False,
            "fallback_used": False,
            "fallback_reason": None,
        }
    )
    return signer.sign(payload)


def adapter_not_active_receipt(
    *,
    signer: RoutingReceiptSigner,
    expected: ExpectedAdapter,
    request_id: str,
    request_payload: Mapping[str, Any],
    challenge_nonce: str,
    server_build_digest: str,
    base_model_id: str,
    base_model_digest: str,
    slot_lease_id: str | None,
    started_at: datetime,
    completed_at: datetime,
    reason: str = "adapter_not_active",
) -> dict[str, Any]:
    payload = _common_payload(
        signer=signer,
        request_id=request_id,
        request_payload=request_payload,
        challenge_nonce=challenge_nonce,
        server_build_digest=server_build_digest,
        base_model_id=base_model_id,
        base_model_digest=base_model_digest,
        requested_model=expected.requested_model,
        slot_lease_id=slot_lease_id,
        started_at=started_at,
        completed_at=completed_at,
    )
    payload.update(
        {
            "requested_persona": expected.persona_id,
            "registry_adapter_id": expected.adapter_id,
            "selected_adapter_id": None,
            "selected_adapter_digest": None,
            "adapter_version": expected.adapter_version,
            "registry_revision": expected.registry_revision,
            "active_adapter_ids": [],
            "routing_mode": "failure",
            "adapter_applied": False,
            "persona_applied": False,
            "fallback_used": False,
            "fallback_reason": reason,
        }
    )
    return signer.sign(payload)


def adapter_not_active_response(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "error_code": "ADAPTER_NOT_ACTIVE",
        "detail": "requested persona adapter is not active; base fallback is prohibited",
        "routing_receipt": dict(receipt),
    }
