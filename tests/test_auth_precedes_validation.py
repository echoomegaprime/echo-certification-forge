"""Auth must be decided BEFORE the request body is validated (#25476).

`submit_certification` takes `request: SubmitRequest` as a body parameter.
FastAPI validates body parameters *before* it ever calls the endpoint, so an
in-handler `authorize(...)` never runs on a malformed body and the caller gets
422 instead of 401.

That hands an unauthenticated caller a **schema oracle**: 422 means "your body
was wrong", any other status means "your body was right, now prove who you are".
The opaque `request_validation_error` detail hides *which* field failed, but the
status code alone is enough to brute-force the request shape without ever
presenting a credential. Nothing about the request schema is owed to an
anonymous caller.

The fix moves `authorize` into a FastAPI dependency. Dependencies are solved --
and called -- before accumulated body-validation errors are raised, so a 401
propagates first. The same pattern is applied to every other body-validated
endpoint that previously authorized only inside the handler.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import SubscriberGovernance, SubscriberPolicy

DIGEST = "0" * 64
PEPPER = b"auth-before-validation-pepper-material-32b"


@pytest.fixture
def client(tmp_path: Path, manifest) -> TestClient:
    store = EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")
    return TestClient(
        create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty(), None))
    )


@pytest.fixture
def governed(tmp_path: Path, manifest) -> tuple[TestClient, str, str, str]:
    db = tmp_path / "governed.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    policy = SubscriberPolicy.load(
        Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
    )
    governance = SubscriberGovernance(db, policy, PEPPER)
    client = TestClient(
        create_app(
            ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty(), governance)
        )
    )
    org = governance.provision_organization(
        slug="auth-probe",
        display_name="Auth Probe Inc",
        owner_email="owner@auth-probe.example",
        owner_display_name="Auth Probe Owner",
        plan_code="developer",
    )
    return client, org.organization_id, org.bootstrap_api_key, org.organization_id


def _valid_body() -> dict:
    return {
        "tenant_id": "probe",
        "target": {
            "target_type": "git",
            "identity_digest": DIGEST,
            "reference": "probe",
        },
        "environment": {"identity_digest": DIGEST},
        "policy_version": "v1",
        "idempotency_key": "probe-key-1",
    }


@pytest.mark.parametrize(
    "body,label",
    [
        ({}, "empty body"),
        ({"tenant_id": "probe"}, "partial body"),
        ({**_valid_body(), "target": {"target_type": "NOT_A_REAL_TYPE"}}, "bad target_type"),
    ],
)
def test_malformed_body_without_credentials_is_401_not_422(
    client: TestClient, body: dict, label: str
) -> None:
    """A malformed body must not be *diagnosed* for an anonymous caller."""
    resp = client.post("/v1/certifications", json=body)
    assert resp.status_code == 401, (
        f"{label}: got {resp.status_code}. 422 here means the body was validated "
        "before the credential was checked, which tells an anonymous caller "
        "their request shape was wrong."
    )


def test_wellformed_body_without_credentials_is_also_401(client: TestClient) -> None:
    """The other half of the oracle.

    This one already returned 401 before the fix. It is here so the pair is
    asserted together: if malformed and well-formed bodies ever diverge again,
    the oracle is back regardless of which side moved.
    """
    resp = client.post("/v1/certifications", json=_valid_body())
    assert resp.status_code == 401


def test_anonymous_responses_are_indistinguishable(client: TestClient) -> None:
    """Status AND body must match, or the oracle survives in the payload.

    Asserting only the status code would let a future change reintroduce the
    leak through `detail` (e.g. 401 + "request_validation_error").
    """
    malformed = client.post("/v1/certifications", json={})
    wellformed = client.post("/v1/certifications", json=_valid_body())
    assert malformed.status_code == wellformed.status_code
    assert malformed.json() == wellformed.json(), (
        "anonymous callers can still tell the two apart from the response body"
    )


def test_invalid_sdk_command_without_credentials_is_not_a_schema_oracle(
    client: TestClient,
) -> None:
    """Middleware must not diagnose an invalid SDK command for anonymous callers."""
    invalid_command = client.post("/v1/certifications", json={"command": ""})
    wellformed = client.post("/v1/certifications", json=_valid_body())
    assert invalid_command.status_code == 401
    assert invalid_command.status_code == wellformed.status_code
    assert invalid_command.json() == wellformed.json()


@pytest.mark.parametrize(
    "method,path,malformed,wellformed",
    [
        ("POST", "/v1/release-gates/evaluate", {}, {
            "run_id": "run-1",
            "target_identity_digest": DIGEST,
            "environment_identity_digest": DIGEST,
            "rule_manifest_digest": DIGEST,
        }),
        ("POST", "/v1/subscriber/projects", {}, {
            "slug": "app",
            "name": "App Project",
            "target_reference": "https://github.com/example/app",
        }),
        ("POST", "/v1/subscriber/legal-holds", {}, {
            "hold_id": "hold-1",
            "reason": "legal hold for investigation",
        }),
        ("POST", "/v1/subscriber/members", {}, {
            "email": "member@example.test",
            "display_name": "Member",
            "role": "VIEWER",
        }),
        ("PUT", "/v1/subscriber/governance", {}, {
            "expected_version": 1,
            "config": {
                "allowed_policy_ids": ["mandatory-rules.v1"],
                "retention_days": 30,
                "private_worker_only": False,
                "report_brand_name": None,
                "report_logo_url": None,
                "customer_managed_signing": False,
                "local_only_execution": False,
            },
        }),
        ("POST", "/v1/subscriber/policy-packs", {}, {
            "name": "pack",
            "version": "v1",
            "manifest": {"rules": []},
        }),
        ("POST", "/v1/subscriber/private-workers", {}, {
            "display_name": "worker",
            "attestation_sha256": DIGEST,
        }),
        ("POST", "/v1/subscriber/operational-quarantines", {}, {
            "subject_type": "runner",
            "subject_id": "runner-1",
            "reason": "quarantine for review",
        }),
        ("POST", "/v1/subscriber/runner-enrollments", {}, {
            "runner_id": "runner-1",
        }),
        ("POST", "/v1/subscriber/adapter-maturity/remediate", {}, {
            "reason": "remediate adapters",
        }),
    ],
)
def test_other_body_validated_endpoints_auth_before_schema(
    client: TestClient,
    method: str,
    path: str,
    malformed: dict,
    wellformed: dict,
) -> None:
    """Every body-validated mutation must hide schema from anonymous callers.

    Ungoverned apps reject subscriber mutations with 503 (governance disabled)
    after the credential dependency runs. That is still fail-closed and must
    not become a 422 schema oracle.
    """
    bad = client.request(method, path, json=malformed)
    good = client.request(method, path, json=wellformed)
    assert bad.status_code != 422, f"{method} {path} malformed -> {bad.status_code}"
    assert good.status_code != 422, f"{method} {path} well-formed -> {good.status_code}"
    assert bad.status_code == good.status_code, (
        f"{method} {path}: {bad.status_code} vs {good.status_code}"
    )
    assert bad.json() == good.json()


def test_governed_anonymous_submit_is_indistinguishable(governed) -> None:
    client, _org_id, _token, _ = governed
    malformed = client.post("/v1/certifications", json={})
    wellformed = client.post("/v1/certifications", json=_valid_body())
    assert malformed.status_code == 401
    assert wellformed.status_code == 401
    assert malformed.json() == wellformed.json()


def test_body_tenant_cannot_override_authorized_tenant(governed, manifest) -> None:
    """A credential for tenant A plus a body naming tenant B must fail closed."""
    client, org_id, token, _ = governed
    headers = {"X-Tenant-ID": org_id, "Authorization": f"Bearer {token}"}
    project = client.post(
        "/v1/subscriber/projects",
        headers=headers,
        json={
            "slug": "bound",
            "name": "Bound Project",
            "target_reference": "https://github.com/example/bound",
        },
    )
    assert project.status_code == 201, project.text
    body = {
        "tenant_id": "tenant-other",
        "project_id": project.json()["project_id"],
        "target": {
            "target_type": "git",
            "identity_digest": DIGEST,
            "reference": "https://github.com/example/bound@abc",
        },
        "environment": {
            "identity_digest": DIGEST,
            "runner_image_digest": "sha256:" + DIGEST,
        },
        "policy_version": manifest.manifest_id,
        "idempotency_key": "cross-tenant-body-1",
    }
    response = client.post("/v1/certifications", headers=headers, json=body)
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"
    listed = client.get("/v1/certifications", headers=headers)
    assert listed.status_code == 200
    assert listed.json() == []
