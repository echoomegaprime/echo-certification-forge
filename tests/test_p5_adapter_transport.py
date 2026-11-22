from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from echo_certification_forge.adapter_transport import (
    AdapterBundleError,
    parse_verified_adapter_bundle,
)
from echo_certification_forge.adapters import AdapterIdentity, AdapterMaturity
from echo_certification_forge.canonical import sha256_json
from echo_certification_forge.runner import (
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    TransportRequest,
)


def digest(ch: str) -> str:
    return ch * 64


def adapter_record(adapter_id: str = "gs343") -> dict:
    identity = AdapterIdentity(
        adapter_id=adapter_id,
        version="1.0.0",
        artifact_sha256=digest("a"),
        configuration_sha256=digest("b"),
        runtime_sha256=digest("c"),
        maturity=AdapterMaturity.STABLE,
        provenance=f"repo:ECHO-OMEGA-PRIME/adapters/{adapter_id}@1.0.0",
    )
    quality = {
        "adapter_id": adapter_id,
        "passed_cases": 40,
        "total_cases": 40,
        "critical_failures": [],
        "suite_sha256": digest("d"),
        "evidence_ids": [f"{adapter_id}-identity", f"{adapter_id}-quality"],
    }
    payload = {
        "identity": identity.to_dict(),
        "observed_identity_digest": identity.identity_digest,
        "quality": quality,
        "execution_node": "ANVIL",
    }
    return {**payload, "result_sha256": sha256_json(payload)}


def bundle(*records: dict) -> dict:
    return {
        "schema_version": "1.0.0",
        "kind": "adapter_execution_bundle",
        "records": list(records),
    }


def signed_response(
    body: dict,
    *,
    status: str = "COMPLETED",
    run_id: str = "cert-p5-001",
    tenant_id: str = "echo-sovereign",
    runner_id: str = "anvil-adapter-runner",
):
    now = datetime(2026, 7, 23, 19, 0, tzinfo=UTC)
    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
    credential = authority.issue(
        credential_id="credential-p5-001",
        run_id=run_id,
        tenant_id=tenant_id,
        runner_id=runner_id,
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.TRANSITION.value,),
        issued_at=now,
        ttl=timedelta(minutes=5),
    )
    request_body = {"action": "execute_adapters"}
    request = TransportRequest(
        request_id="request-p5-001",
        run_id=run_id,
        tenant_id=tenant_id,
        runner_id=runner_id,
        nonce="0123456789abcdef",
        command=RunnerCommand.TRANSITION,
        sequence=1,
        issued_at=now,
        credential=credential,
        body=request_body,
        body_sha256=sha256_json(request_body),
    )
    response = runner.sign_response(
        response_id="response-p5-001",
        request=request,
        status=status,
        body=body,
        issued_at=now,
    )
    return response, runner.public_key_pem


def parse(response, public_key: str):
    return parse_verified_adapter_bundle(
        response,
        public_key,
        expected_run_id="cert-p5-001",
        expected_tenant_id="echo-sovereign",
    )


def test_valid_signed_anvil_bundle_is_accepted() -> None:
    response, public_key = signed_response(bundle(adapter_record("gs343"), adapter_record("r2d2")))

    records = parse(response, public_key)

    assert tuple(item.identity.adapter_id for item in records) == ("gs343", "r2d2")
    assert all(item.execution_node == "ANVIL" for item in records)
    assert all(item.result_sha256 for item in records)


def test_invalid_runner_signature_is_rejected() -> None:
    response, public_key = signed_response(bundle(adapter_record()))
    tampered = response.model_copy(update={"signature_b64": "AAAA"})

    with pytest.raises(AdapterBundleError, match="invalid_runner_signature"):
        parse(tampered, public_key)


def test_signed_result_hash_mismatch_is_rejected() -> None:
    raw = adapter_record()
    raw["result_sha256"] = digest("f")
    response, public_key = signed_response(bundle(raw))

    with pytest.raises(AdapterBundleError, match="result_sha256 mismatch"):
        parse(response, public_key)


def test_signed_extra_body_field_is_rejected() -> None:
    body = bundle(adapter_record())
    body["command"] = "run-anything"
    response, public_key = signed_response(body)

    with pytest.raises(AdapterBundleError, match="body schema mismatch"):
        parse(response, public_key)


def test_wrong_run_binding_is_rejected() -> None:
    response, public_key = signed_response(bundle(adapter_record()), run_id="cert-p5-other")

    with pytest.raises(AdapterBundleError, match="run or tenant mismatch"):
        parse(response, public_key)


def test_unapproved_runner_is_rejected() -> None:
    response, public_key = signed_response(
        bundle(adapter_record()),
        runner_id="untrusted-adapter-runner",
    )

    with pytest.raises(AdapterBundleError, match="runner is not approved"):
        parse(response, public_key)


def test_nonterminal_response_is_rejected() -> None:
    response, public_key = signed_response(bundle(adapter_record()), status="ACCEPTED")

    with pytest.raises(AdapterBundleError, match="not complete"):
        parse(response, public_key)


def test_empty_and_oversized_bundles_are_rejected() -> None:
    response, public_key = signed_response(bundle())
    with pytest.raises(AdapterBundleError, match="may not be empty"):
        parse(response, public_key)

    response, public_key = signed_response(bundle(adapter_record(), adapter_record("r2d2")))
    with pytest.raises(AdapterBundleError, match="exceeds max_records"):
        parse_verified_adapter_bundle(
            response,
            public_key,
            expected_run_id="cert-p5-001",
            expected_tenant_id="echo-sovereign",
            max_records=1,
        )
