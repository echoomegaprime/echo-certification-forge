"""Optional exact-consumer qualification; synthetic proofs are never release evidence.

Set ECHO_CERTFORGE_CONSUMER_SOURCE to certificate_chat.py exported from the
consumer commit below. The exact byte digest is required before executing any
consumer definition. No consumer implementation or trust configuration is copied
into the producer, and no network or live signing key is used.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.canonical import utc_now
from echo_certification_forge.models import RunOutcome, VerdictLifecycleEvent
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import SubscriberGovernance
from echo_certification_forge.verdict import DeterministicVerdictEngine
from test_evidence_and_verdict import register, satisfy_all_rules
from test_p7_subscriber_governance import PEPPER, _headers, _policy, _provision

CONSUMER_COMMIT = "bf8471df40b7bf5eb3460e2364dddf38dd0e7ae0"
CONSUMER_SHA256 = "c23e46579662e755638519e0d5854b8146ddc91758b7d549f1f2e7d378d9ba6d"


@pytest.fixture(scope="module")
def consumer():
    source_path = os.environ.get("ECHO_CERTFORGE_CONSUMER_SOURCE")
    if not source_path:
        pytest.skip("exact consumer snapshot not supplied; interop qualification not executed")
    raw = Path(source_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONSUMER_SHA256:
        pytest.fail("consumer snapshot does not match the pinned exact source")
    parsed = ast.parse(raw)
    # The proof verifier has no GitHub API dependency. Omit only its unused
    # relative import; all verifier/helper definitions remain byte-source bound.
    relative = [node for node in parsed.body if isinstance(node, ast.ImportFrom) and node.level]
    if len(relative) != 1 or [alias.name for alias in relative[0].names] != ["github_ops"]:
        pytest.fail("unexpected consumer dependency layout")
    parsed.body = [node for node in parsed.body if node not in relative]
    namespace: dict[str, Any] = {"__name__": "exact_consumer_qualification"}
    exec(compile(parsed, "pinned_consumer_certificate_chat.py", "exec"), namespace)
    assert namespace["CERTIFICATE_SCHEMA"] == "2.1.0"
    return namespace


@dataclass(repr=False)
class ProofFixture:
    client: TestClient
    url: str
    proof: dict[str, Any]
    target: Any
    store: Any
    run_id: str


@pytest.fixture
def published(tmp_path, store, manifest, target, environment, monkeypatch):
    governance = SubscriberGovernance(tmp_path / "certforge.sqlite3", _policy(), PEPPER)
    owner = _provision(governance, "consumer-qualification", plan_code="professional")
    target = replace(target, tenant_id=owner.organization_id)
    run_id = register(store, manifest, target, environment, run_id="qualification-proof")
    satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)
    signer = Ed25519VerdictSigner.generate()
    decision = DeterministicVerdictEngine().evaluate(store, run_id, target.tenant_id, manifest, signer.key_id)
    store.save_signed_verdict(run_id, target.tenant_id, signer.sign(decision))
    trusted = TrustedPublicKeyRegistry.empty()
    trusted.add_pem(signer.public_key_pem)
    # Ephemeral test keys only; the installed consumer and all live trust remain untouched.
    monkeypatch.setenv("ECHO_CERTFORGE_TRUSTED_KEY_IDS", signer.key_id)
    monkeypatch.setenv("ECHO_CERTFORGE_TRUSTED_RULE_MANIFEST_DIGESTS", manifest.digest)
    with TestClient(create_app(ServiceContext(store, manifest, trusted, governance))) as client:
        response = client.post(
            f"/v1/subscriber/certifications/{run_id}/publish",
            headers=_headers(owner.organization_id, owner.bootstrap_api_key),
        )
        assert response.status_code == 200
        url = response.json()["verification_url"]
        public = client.get(url)
        assert public.status_code == 200
        proof = public.json()
        assert proof.get("valid") is True
        yield ProofFixture(client, url, proof, target, store, run_id)


def verify(consumer, published, proof=None, *, repository="example/project", sha=None):
    return consumer["_verify_certforge_receipt"](
        published.proof if proof is None else proof,
        repository,
        published.target.source_commit if sha is None else sha,
    )


def test_real_producer_json_roundtrip_is_accepted_by_exact_consumer(consumer, published):
    proof = json.loads(json.dumps(published.proof))
    payload, target, environment, e2e = verify(consumer, published, proof)
    assert payload["run_id"] == published.run_id
    assert target["source_commit"] == published.target.source_commit
    assert bool(environment) and bool(e2e)


@pytest.mark.parametrize("field", ["payload", "target_identity", "environment_identity", "production_e2e"])
def test_missing_producer_identity_is_rejected(consumer, published, field):
    proof = copy.deepcopy(published.proof)
    proof.pop(field)
    with pytest.raises(consumer["CertificateChatError"], match="identity is missing"):
        verify(consumer, published, proof)


@pytest.mark.parametrize("field", ["target_identity", "environment_identity", "production_e2e"])
def test_changed_identity_cannot_reuse_the_signed_verdict(consumer, published, field):
    proof = copy.deepcopy(published.proof)
    proof[field]["qualification_tamper"] = True
    with pytest.raises(consumer["CertificateChatError"], match="digest does not match"):
        verify(consumer, published, proof)


def test_changed_signed_payload_is_rejected(consumer, published):
    proof = copy.deepcopy(published.proof)
    proof["payload"]["qualification_tamper"] = True
    with pytest.raises(consumer["CertificateChatError"], match="signature is invalid"):
        verify(consumer, published, proof)


@pytest.mark.parametrize("variable", ["ECHO_CERTFORGE_TRUSTED_KEY_IDS", "ECHO_CERTFORGE_TRUSTED_RULE_MANIFEST_DIGESTS"])
def test_response_cannot_select_its_own_trust(consumer, published, monkeypatch, variable):
    monkeypatch.delenv(variable)
    with pytest.raises(consumer["CertificateChatError"]):
        verify(consumer, published)


@pytest.mark.parametrize("arguments", [{"repository": "example/another"}, {"sha": "b" * 40}])
def test_proof_cannot_be_reused_for_a_different_target(consumer, published, arguments):
    with pytest.raises(consumer["CertificateChatError"], match="does not match"):
        verify(consumer, published, **arguments)


def test_every_public_read_rechecks_revocation(published):
    published.store.append_lifecycle_event(
        published.run_id, published.target.tenant_id, VerdictLifecycleEvent.REVOKED,
        actor="synthetic-qualification", reason="synthetic revocation",
    )
    response = published.client.get(published.url)
    assert response.status_code == 200
    assert response.json().get("valid") is False
    assert "verdict_revoked" in response.json()["reasons"]


def test_every_public_read_rechecks_expiry(published, monkeypatch):
    import echo_certification_forge.deploy_gate as gate
    future = utc_now() + timedelta(days=8)
    monkeypatch.setattr(gate, "utc_now", lambda: future)
    response = published.client.get(published.url)
    assert response.status_code == 200
    assert response.json().get("valid") is False
    assert "verdict_expired" in response.json()["reasons"]
