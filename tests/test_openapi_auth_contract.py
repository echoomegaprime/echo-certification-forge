"""Unit + acceptance tests for Certification Forge OpenAPI auth contract (P0.5).

ACCEPTANCE:
- OpenAPI exposes securitySchemes (BearerAuth + TenantScope) and per-op security
- Unauthenticated call to a protected endpoint returns 401
- Public exceptions (health, seal-verify) remain open
- Client X-Tenant-ID alone is never authoritative
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.openapi_auth import (
    ALTERNATE_SECURITY,
    PROTECTED_SECURITY,
    PUBLIC_PATH_METHODS,
    SECURITY_SCHEMES,
    apply_openapi_auth_contract,
    build_minimal_auth_demo_app,
    install_openapi_auth,
    is_alternate_auth_path,
    is_public_operation,
)


def test_security_schemes_declare_bearer_and_tenant_scope() -> None:
    assert "BearerAuth" in SECURITY_SCHEMES
    assert SECURITY_SCHEMES["BearerAuth"]["type"] == "http"
    assert SECURITY_SCHEMES["BearerAuth"]["scheme"] == "bearer"
    assert "TenantScope" in SECURITY_SCHEMES
    assert SECURITY_SCHEMES["TenantScope"]["name"] == "X-Tenant-ID"
    assert "never authoritative" in SECURITY_SCHEMES["TenantScope"]["description"].lower()
    assert PROTECTED_SECURITY == [{"BearerAuth": ["tenant"]}]


def test_public_exceptions_are_exactly_health_and_seal_surfaces() -> None:
    paths = {p for p, _ in PUBLIC_PATH_METHODS}
    assert "/healthz" in paths
    assert "/health" in paths
    assert "/v1/seal-verify" in paths
    assert any(p.startswith("/v1/seal-verify") for p in paths)
    assert is_public_operation("/healthz", "GET")
    assert is_public_operation("/v1/seal-verify", "post")
    assert not is_public_operation("/v1/status", "get")
    assert not is_public_operation("/v1/certifications", "get")


def test_apply_contract_strips_legacy_optional_headers_and_marks_security() -> None:
    schema = {
        "paths": {
            "/healthz": {
                "get": {
                    "parameters": [
                        {
                            "name": "authorization",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/v1/status": {
                "get": {
                    "parameters": [
                        {
                            "name": "authorization",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "x-tenant-id",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "X-Request-ID",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/v1/deployments/admissions": {
                "post": {
                    "parameters": [],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        }
    }
    apply_openapi_auth_contract(schema)

    schemes = schema["components"]["securitySchemes"]
    assert set(schemes) >= {"BearerAuth", "TenantScope", "DeploymentHMAC"}
    assert schema["security"] == PROTECTED_SECURITY

    health = schema["paths"]["/healthz"]["get"]
    assert health["security"] == []
    assert health["parameters"] == []

    status = schema["paths"]["/v1/status"]["get"]
    assert status["security"] == PROTECTED_SECURITY
    param_names = {p["name"].lower() for p in status["parameters"]}
    assert "authorization" not in param_names
    assert "x-tenant-id" not in param_names
    assert "x-request-id" in param_names
    assert "401" in status["responses"]
    assert "403" in status["responses"]
    assert status["responses"]["401"]["$ref"] == "#/components/responses/Unauthorized"
    assert status["responses"]["403"]["$ref"] == "#/components/responses/Forbidden"

    admissions = schema["paths"]["/v1/deployments/admissions"]["post"]
    assert admissions["security"] == ALTERNATE_SECURITY
    assert is_alternate_auth_path("/v1/deployments/admissions")


def test_demo_app_openapi_exposes_security_schemes_and_per_op_security() -> None:
    app = build_minimal_auth_demo_app()
    schema = app.openapi()

    schemes = schema["components"]["securitySchemes"]
    assert "BearerAuth" in schemes
    assert "TenantScope" in schemes
    assert schema["security"] == [{"BearerAuth": ["tenant"]}]

    assert schema["paths"]["/healthz"]["get"]["security"] == []
    assert schema["paths"]["/v1/seal-verify"]["post"]["security"] == []
    assert schema["paths"]["/v1/status"]["get"]["security"] == [
        {"BearerAuth": ["tenant"]}
    ]
    assert schema["paths"]["/v1/certifications"]["get"]["security"] == [
        {"BearerAuth": ["tenant"]}
    ]

    # Legacy optional header identity params must not appear
    for path, methods in schema["paths"].items():
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            for param in op.get("parameters") or []:
                name = str(param.get("name", "")).lower()
                assert not (
                    param.get("in") == "header"
                    and name in {"authorization", "x-tenant-id"}
                ), f"legacy header param on {method.upper()} {path}"


def test_unauthenticated_protected_endpoint_returns_401() -> None:
    client = TestClient(build_minimal_auth_demo_app())
    r = client.get("/v1/status")
    assert r.status_code == 401
    assert "bearer" in r.json()["detail"].lower()

    r2 = client.get("/v1/certifications")
    assert r2.status_code == 401


def test_public_exceptions_remain_open_without_auth() -> None:
    client = TestClient(build_minimal_auth_demo_app())
    assert client.get("/healthz").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.post("/v1/seal-verify").status_code == 200
    assert client.get("/v1/seal-verify/vid-1").status_code == 200
    assert client.get("/v1/public/verifications/vid-1").status_code == 200


def test_tenant_identity_comes_from_principal_not_header_alone() -> None:
    client = TestClient(build_minimal_auth_demo_app())

    # X-Tenant-ID alone is never enough
    alone = client.get("/v1/status", headers={"X-Tenant-ID": "org-demo-tenant"})
    assert alone.status_code == 401

    # Valid bearer -> principal tenant
    ok = client.get(
        "/v1/status",
        headers={"Authorization": "Bearer ecf_live_key_demo.secret"},
    )
    assert ok.status_code == 200
    assert ok.json()["tenant_id"] == "org-demo-tenant"

    # Matching hint accepted
    match = client.get(
        "/v1/status",
        headers={
            "Authorization": "Bearer ecf_live_key_demo.secret",
            "X-Tenant-ID": "org-demo-tenant",
        },
    )
    assert match.status_code == 200
    assert match.json()["tenant_id"] == "org-demo-tenant"

    # Mismatching hint rejected — header cannot override principal
    mismatch = client.get(
        "/v1/status",
        headers={
            "Authorization": "Bearer ecf_live_key_demo.secret",
            "X-Tenant-ID": "some-other-org",
        },
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"] == "tenant_mismatch"


def test_install_openapi_auth_is_idempotent_cache() -> None:
    from fastapi import FastAPI

    app = FastAPI()
    install_openapi_auth(app, title="t", version="1")
    s1 = app.openapi()
    s2 = app.openapi()
    assert s1 is s2
    assert "BearerAuth" in s1["components"]["securitySchemes"]


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/v1/internal/worker-heartbeats", True),
        ("/v1/hooks/build", True),
        ("/v1/deployments/admissions", True),
        ("/v1/releases/abc/status", True),
        ("/v1/certifications/{run_id}/bindings", True),
        ("/v1/certifications", False),
        ("/v1/status", False),
    ],
)
def test_alternate_auth_path_detection(path: str, expected: bool) -> None:
    assert is_alternate_auth_path(path) is expected
