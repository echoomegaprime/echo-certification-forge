from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.adapter_routing import (
    AdapterIdentity,
    RECEIPT_SCHEMA,
    RoutingProofError,
    verify_base_routing,
    verify_persona_routing,
    verify_unloaded_adapter_failure,
)
from echo_certification_forge.canonical import canonical_json, sha256_bytes, sha256_json


def key_material():
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private, key_id, {key_id: pem}


def identity():
    return AdapterIdentity.from_mapping(
        {
            "persona_id": "gs343",
            "requested_model": "echo-gs343",
            "adapter_id": "echo-gs343",
            "adapter_artifact_digest": "a" * 64,
            "adapter_version": "1.0.0",
            "maturity_state": "CERTIFIED",
            "enabled": True,
            "registry_revision": "42",
        }
    )


def signed_envelope(private, key_id, payload):
    signature = private.sign(canonical_json(payload).encode("utf-8"))
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_id": key_id,
    }


def persona_payload(request, nonce, key_id):
    now = datetime.now(UTC)
    return {
        "schema": RECEIPT_SCHEMA,
        "request_id": "req-1",
        "request_sha256": sha256_json(request),
        "challenge_nonce": nonce,
        "server_build_digest": "b" * 64,
        "base_model_id": "family-14b",
        "base_model_digest": "c" * 64,
        "requested_model": "echo-gs343",
        "requested_persona": "gs343",
        "registry_adapter_id": "echo-gs343",
        "selected_adapter_id": "echo-gs343",
        "selected_adapter_digest": "a" * 64,
        "adapter_version": "1.0.0",
        "registry_revision": "42",
        "active_adapter_ids": ["echo-gs343"],
        "routing_mode": "lora_adapter",
        "adapter_applied": True,
        "persona_applied": True,
        "fallback_used": False,
        "fallback_reason": None,
        "slot_lease_id": "lease-1",
        "started_at": now.isoformat().replace("+00:00", "Z"),
        "completed_at": (now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "signature_key_id": key_id,
    }


def test_identity_rejects_missing_and_bad_digest():
    try:
        AdapterIdentity.from_mapping({})
    except RoutingProofError:
        pass
    else:
        raise AssertionError("missing identity must fail")

    bad = {
        "persona_id": "x",
        "requested_model": "x",
        "adapter_id": "x",
        "adapter_digest": "not-a-digest",
        "maturity_state": "CERTIFIED",
        "registry_revision": "1",
    }
    try:
        AdapterIdentity.from_mapping(bad)
    except RoutingProofError:
        pass
    else:
        raise AssertionError("bad digest must fail")


def test_persona_receipt_passes_only_exact_route():
    private, key_id, trust = key_material()
    request = {"model": "echo-gs343", "messages": [{"role": "user", "content": "probe"}]}
    nonce = "nonce-1"
    payload = persona_payload(request, nonce, key_id)
    response = {
        "model": "echo-gs343",
        "choices": [{"message": {"content": "{}"}}],
        "routing_receipt": signed_envelope(private, key_id, payload),
    }
    result = verify_persona_routing(
        response=response,
        request_payload=request,
        challenge_nonce=nonce,
        expected=identity(),
        trusted_public_keys=trust,
    )
    assert result.ok is True
    assert result.status == "PASS"
    assert all(item["passed"] for item in result.checks)


def test_persona_missing_receipt_blocks():
    result = verify_persona_routing(
        response={"model": "echo-gs343"},
        request_payload={"model": "echo-gs343"},
        challenge_nonce="n",
        expected=identity(),
        trusted_public_keys={},
    )
    assert result.ok is False
    assert result.status == "BLOCK"


def test_persona_tamper_wrong_adapter_and_fallback_block():
    private, key_id, trust = key_material()
    request = {"model": "echo-gs343", "messages": []}
    payload = persona_payload(request, "n", key_id)
    payload["selected_adapter_id"] = "echo-prime"
    payload["fallback_used"] = True
    response = {
        "model": "echo-gs343",
        "routing_receipt": signed_envelope(private, key_id, payload),
    }
    result = verify_persona_routing(
        response=response,
        request_payload=request,
        challenge_nonce="n",
        expected=identity(),
        trusted_public_keys=trust,
    )
    assert result.ok is False
    failed = {item["name"] for item in result.checks if not item["passed"]}
    assert {"selected_adapter_id", "fallback_used"} <= failed


def test_persona_invalid_signature_blocks():
    private, key_id, trust = key_material()
    request = {"model": "echo-gs343"}
    payload = persona_payload(request, "n", key_id)
    envelope = signed_envelope(private, key_id, payload)
    envelope["signature_b64"] = base64.b64encode(b"x" * 64).decode("ascii")
    result = verify_persona_routing(
        response={"model": "echo-gs343", "routing_receipt": envelope},
        request_payload=request,
        challenge_nonce="n",
        expected=identity(),
        trusted_public_keys=trust,
    )
    assert result.ok is False
    assert result.checks[0]["name"] == "routing_receipt_valid"


def test_explicit_base_control_passes():
    private, key_id, trust = key_material()
    request = {"model": "echo-prime", "messages": []}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload = {
        "schema": RECEIPT_SCHEMA,
        "request_sha256": sha256_json(request),
        "challenge_nonce": "base-nonce",
        "requested_model": "echo-prime",
        "routing_mode": "base",
        "adapter_applied": False,
        "persona_applied": False,
        "fallback_used": False,
        "selected_adapter_id": None,
        "active_adapter_ids": [],
        "started_at": now,
        "completed_at": now,
        "signature_key_id": key_id,
    }
    response = {
        "model": "echo-prime",
        "routing_receipt": signed_envelope(private, key_id, payload),
    }
    result = verify_base_routing(
        response=response,
        request_payload=request,
        challenge_nonce="base-nonce",
        trusted_public_keys=trust,
    )
    assert result.ok is True


def test_unloaded_adapter_must_fail_visibly_without_fallback():
    private, key_id, trust = key_material()
    request = {"model": "echo-gs343", "messages": []}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload = {
        "schema": RECEIPT_SCHEMA,
        "request_sha256": sha256_json(request),
        "challenge_nonce": "neg",
        "requested_model": "echo-gs343",
        "registry_adapter_id": "echo-gs343",
        "routing_mode": "failure",
        "adapter_applied": False,
        "persona_applied": False,
        "fallback_used": False,
        "selected_adapter_id": None,
        "adapter_version": "1.0.0",
        "registry_revision": "42",
        "started_at": now,
        "completed_at": now,
        "signature_key_id": key_id,
    }
    response = {
        "error_code": "ADAPTER_NOT_ACTIVE",
        "routing_receipt": signed_envelope(private, key_id, payload),
    }
    result = verify_unloaded_adapter_failure(
        error_response=response,
        request_payload=request,
        challenge_nonce="neg",
        expected=identity(),
        trusted_public_keys=trust,
    )
    assert result.ok is True

    response["error_code"] = "OK"
    bad = verify_unloaded_adapter_failure(
        error_response=response,
        request_payload=request,
        challenge_nonce="neg",
        expected=identity(),
        trusted_public_keys=trust,
    )
    assert bad.ok is False
