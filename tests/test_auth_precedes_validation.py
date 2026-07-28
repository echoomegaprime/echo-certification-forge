"""Auth must be decided BEFORE the request body is validated (#25476).

`submit_certification` takes `request: SubmitRequest` as a body parameter and
calls `authorize(...)` in its first line. FastAPI validates body parameters
*before* it ever calls the endpoint, so on a malformed body `authorize` never
runs and the caller gets 422 instead of 401.

That hands an unauthenticated caller a **schema oracle**: 422 means "your body
was wrong", any other status means "your body was right, now prove who you are".
The opaque `request_validation_error` detail hides *which* field failed, but the
status code alone is enough to brute-force the request shape without ever
presenting a credential. Nothing about the request schema is owed to an
anonymous caller.

Reproduced against the deployed build (sha 3423029, certforge :8309): POST with
`{}` and POST with a fully-formed body both return 422 with no credential.

The fix moves `authorize` into a FastAPI dependency. Dependencies are solved --
and called -- before accumulated body-validation errors are raised, so a 401
propagates first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry

DIGEST = "0" * 64


@pytest.fixture
def client(tmp_path: Path, manifest) -> TestClient:
    store = EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")
    return TestClient(
        create_app(ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty(), None))
    )


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
