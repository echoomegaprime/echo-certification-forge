from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrations.anvil.family_routing_receipts import (
    ActualRouteState,
    AdapterRouteMismatch,
    ExpectedAdapter,
    RoutingReceiptSigner,
    adapter_not_active_receipt,
    adapter_not_active_response,
    base_receipt,
    persona_receipt,
)
from echo_certification_forge.adapter_routing import (
    AdapterIdentity,
    verify_base_routing,
    verify_persona_routing,
    verify_unloaded_adapter_failure,
)


def signer() -> RoutingReceiptSigner:
    return RoutingReceiptSigner(Ed25519PrivateKey.generate())


def expected() -> ExpectedAdapter:
    return ExpectedAdapter(
        persona_id="gs343",
        requested_model="echo-gs343",
        adapter_id="echo-gs343",
        adapter_digest="a" * 64,
    )


def request() -> dict:
    return {"model": "echo-gs343", "messages": [{"role": "user", "content": "probe"}]}


def times():
    started = datetime.now(UTC)
    return started, started + timedelta(seconds=1)


def receipt_args(route_signer: RoutingReceiptSigner) -> dict:
    started, completed = times()
    return {
        "signer": route_signer,
        "request_id": "req-1",
        "request_payload": request(),
        "challenge_nonce": "nonce-at-least-16",
        "server_build_digest": "b" * 64,
        "base_model_id": "family-14b",
        "base_model_digest": "c" * 64,
        "started_at": started,
        "completed_at": completed,
    }


def trust(route_signer: RoutingReceiptSigner) -> dict[str, str]:
    return {route_signer.key_id: route_signer.public_key_pem}


def client_identity() -> AdapterIdentity:
    return AdapterIdentity.from_mapping(
        {
            "persona_id": "gs343",
            "requested_model": "echo-gs343",
            "adapter_id": "echo-gs343",
            "adapter_digest": "a" * 64,
            "maturity_state": "CERTIFIED",
            "registry_revision": "1",
        }
    )


def test_persona_receipt_round_trips_through_independent_verifier():
    route_signer = signer()
    actual = ActualRouteState.from_runtime(
        selected_adapter_id="echo-gs343",
        selected_adapter_digest="a" * 64,
        active_adapter_ids=["echo-gs343"],
        adapter_applied=True,
    )
    envelope = persona_receipt(
        expected=expected(),
        actual=actual,
        slot_lease_id="lease-1",
        **receipt_args(route_signer),
    )
    result = verify_persona_routing(
        response={"model": "echo-gs343", "routing_receipt": envelope},
        request_payload=request(),
        challenge_nonce="nonce-at-least-16",
        expected=client_identity(),
        trusted_public_keys=trust(route_signer),
    )
    assert result.ok is True


@pytest.mark.parametrize(
    ("actual", "fragment"),
    [
        (
            ActualRouteState.from_runtime(
                selected_adapter_id="echo-prime",
                selected_adapter_digest="a" * 64,
                active_adapter_ids=["echo-prime"],
                adapter_applied=True,
            ),
            "selected_adapter_id_mismatch",
        ),
        (
            ActualRouteState.from_runtime(
                selected_adapter_id="echo-gs343",
                selected_adapter_digest="d" * 64,
                active_adapter_ids=["echo-gs343"],
                adapter_applied=True,
            ),
            "selected_adapter_digest_mismatch",
        ),
        (
            ActualRouteState.from_runtime(
                selected_adapter_id="echo-gs343",
                selected_adapter_digest="a" * 64,
                active_adapter_ids=["echo-gs343"],
                adapter_applied=False,
            ),
            "adapter_applied_false",
        ),
    ],
)
def test_persona_receipt_refuses_false_route(actual, fragment):
    route_signer = signer()
    with pytest.raises(AdapterRouteMismatch, match=fragment):
        persona_receipt(
            expected=expected(),
            actual=actual,
            slot_lease_id="lease-1",
            **receipt_args(route_signer),
        )


def test_base_receipt_refuses_active_adapter_and_valid_base_round_trips():
    route_signer = signer()
    active = ActualRouteState.from_runtime(
        selected_adapter_id="echo-gs343",
        selected_adapter_digest="a" * 64,
        active_adapter_ids=["echo-gs343"],
        adapter_applied=True,
    )
    args = receipt_args(route_signer)
    args["request_payload"] = {"model": "echo-prime", "messages": []}
    with pytest.raises(AdapterRouteMismatch):
        base_receipt(actual=active, **args)

    clear = ActualRouteState.from_runtime(
        selected_adapter_id=None,
        selected_adapter_digest=None,
        active_adapter_ids=[],
        adapter_applied=False,
    )
    envelope = base_receipt(actual=clear, **args)
    result = verify_base_routing(
        response={"model": "echo-prime", "routing_receipt": envelope},
        request_payload=args["request_payload"],
        challenge_nonce="nonce-at-least-16",
        trusted_public_keys=trust(route_signer),
    )
    assert result.ok is True


def test_unloaded_receipt_proves_visible_failure_without_base_fallback():
    route_signer = signer()
    envelope = adapter_not_active_receipt(
        expected=expected(),
        slot_lease_id="lease-1",
        **receipt_args(route_signer),
    )
    response = adapter_not_active_response(envelope)
    result = verify_unloaded_adapter_failure(
        error_response=response,
        request_payload=request(),
        challenge_nonce="nonce-at-least-16",
        expected=client_identity(),
        trusted_public_keys=trust(route_signer),
    )
    assert result.ok is True
    assert response["error_code"] == "ADAPTER_NOT_ACTIVE"
    assert response["routing_receipt"]["payload"]["fallback_used"] is False


def test_runtime_rejects_multiple_active_adapters():
    with pytest.raises(AdapterRouteMismatch, match="exactly one"):
        ActualRouteState.from_runtime(
            selected_adapter_id="echo-gs343",
            selected_adapter_digest="a" * 64,
            active_adapter_ids=["echo-gs343", "echo-r2d2"],
            adapter_applied=True,
        )
