"""P0.5 regression: P6 deployment READ endpoints must not trust X-Tenant-ID alone.

Before this test existed, GET /v1/deployments/rollback-target, GET /v1/deployments/audit
and GET /v1/releases/{sha}/status resolved the tenant with `tenant(x_tenant_id)` — a bare,
unauthenticated, caller-supplied header. Sending any tenant string returned HTTP 200 with
that tenant's deployment audit chain, rollback target and release-gate status; only a
*missing* header was rejected. The OpenAPI contract meanwhile advertised these operations
as BearerAuth-protected, so the published contract did not describe the running service —
the worst possible gap in a product whose entire proposition is verifiable claims.

Governance is deliberately ENABLED here. With `subscribers=None` the whole API documents a
header-only fallback for offline/dev use, so a fixture without governance cannot express
this requirement at all — which is precisely why the hole survived the existing P6 suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.subscriber import (
    OrganizationStatus,
    SubscriberGovernance,
    SubscriberPolicy,
)
from echo_certification_forge.signing import TrustedPublicKeyRegistry

TENANT = "tenant-alpha"
VICTIM = "tenant-victim"
SHA = "a" * 64

DEPLOYMENT_READS = [
    "/v1/deployments/rollback-target",
    "/v1/deployments/audit",
    f"/v1/releases/{SHA}/status",
]


@pytest.fixture
def governed_client(store, manifest, tmp_path) -> TestClient:
    subscribers = SubscriberGovernance(
        store.db_path,
        SubscriberPolicy.load(
            Path(__file__).parents[1] / "policies" / "subscriber-governance.v1.json"
        ),
        b"p6-deployment-read-auth-test-pepper-32-bytes-min",
    )
    subscribers.provision_organization(
        organization_id=TENANT,
        owner_user_id="owner-deploy",
        slug="deploy",
        display_name="Deploy",
        owner_email="deploy@example.test",
        owner_display_name="Deploy Owner",
        plan_code="professional",
        status=OrganizationStatus.ACTIVE,
    )
    return TestClient(
        create_app(
            ServiceContext(
                store,
                manifest,
                TrustedPublicKeyRegistry.empty(),
                subscribers=subscribers,
                deployment_ledger_path=tmp_path / "deployments.sqlite3",
            )
        )
    )


@pytest.mark.parametrize("path", DEPLOYMENT_READS)
def test_read_rejects_bare_tenant_header(governed_client: TestClient, path: str) -> None:
    """Naming a tenant is not the same as being one."""
    response = governed_client.get(path, headers={"X-Tenant-ID": VICTIM})
    assert response.status_code == 401, (
        f"{path} returned {response.status_code} to an unauthenticated caller who simply "
        f"asserted tenant {VICTIM!r}: {response.text[:200]}"
    )


@pytest.mark.parametrize("path", DEPLOYMENT_READS)
def test_read_rejects_no_credentials(governed_client: TestClient, path: str) -> None:
    assert governed_client.get(path).status_code == 401


@pytest.mark.parametrize("path", DEPLOYMENT_READS)
def test_read_rejects_bogus_bearer(governed_client: TestClient, path: str) -> None:
    response = governed_client.get(
        path, headers={"Authorization": "Bearer ecf_live_not.a_real_key"}
    )
    assert response.status_code == 401, f"{path} -> {response.status_code}"


def test_public_and_health_surfaces_stay_open(governed_client: TestClient) -> None:
    """The fix must not close anything the contract declares public."""
    assert governed_client.get("/healthz").status_code == 200
    # /health is an alias introduced after this commit; assert it only where present.
    alias = governed_client.get("/health")
    assert alias.status_code in (200, 404), alias.status_code
