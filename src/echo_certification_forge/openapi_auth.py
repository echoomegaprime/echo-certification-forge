"""OpenAPI security contract for Certification Forge.

Design rules (echosforge P0.5 / OpenAPI auth correctness):

1. ``securitySchemes`` declare Bearer (subscriber API key) and tenant scope
   documentation. Tenant identity is bound to the authenticated principal at
   key issuance — never taken authoritatively from a client header alone.
2. Protected operations declare ``security`` requirements; public exceptions
   (health, seal-verify, public verification) declare empty security.
3. Standard 401 / 403 response components are attached to protected ops.
4. Legacy optional ``authorization`` / ``x-tenant-id`` header parameters are
   stripped from the generated schema so clients do not treat them as optional
   free-form identity.
5. Non-Bearer control surfaces (deployments / hooks / internal workers) declare
   their own credential schemes — they are not silent public endpoints.
"""

from __future__ import annotations

from typing import Any, Iterable

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

# Public routes: no credentials required (path templates as in OpenAPI).
PUBLIC_PATH_METHODS: frozenset[tuple[str, str]] = frozenset(
    {
        ("/healthz", "get"),
        ("/health", "get"),
        ("/v1/seal-verify", "post"),
        ("/v1/seal-verify/{verification_id}", "get"),
        ("/v1/public/verifications/{verification_id}", "get"),
    }
)

# Paths that use non-Bearer transport/HMAC credentials.
ALTERNATE_AUTH_PREFIXES: tuple[str, ...] = (
    "/v1/internal/",
    "/v1/hooks/",
    "/v1/deployments/",
    "/v1/releases/",
    "/v1/certifications/{run_id}/bindings",
)

_LEGACY_HEADER_NAMES = frozenset({"authorization", "x-tenant-id"})

SECURITY_SCHEMES: dict[str, dict[str, Any]] = {
    "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "APIKey",
        "description": (
            "Subscriber API key (`Authorization: Bearer ecf_live_key_...`). "
            "The authenticated principal carries a fixed tenant scope "
            "(`organization_id`) derived at key issuance. That principal-bound "
            "tenant is authoritative for every protected call."
        ),
    },
    "TenantScope": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Tenant-ID",
        "description": (
            "Optional non-authoritative tenant consistency hint only. "
            "Tenant identity MUST be derived from the Bearer principal; "
            "a client-supplied X-Tenant-ID is never authoritative alone. "
            "If supplied and it disagrees with the principal's organization_id, "
            "the request is rejected (tenant isolation). "
            "This scheme is documented for clarity — it is NOT a standalone "
            "credential and MUST NOT be used without BearerAuth."
        ),
    },
    "DeploymentHMAC": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Certforge-Signature",
        "description": (
            "HMAC / deployment-plane credential for admissions, hooks, release "
            "status, and internal worker surfaces. Not a subscriber Bearer key. "
            "Tenant binding is established by the registered deployment "
            "credential — never by a client-supplied X-Tenant-ID alone."
        ),
    },
}

# Bearer required; tenant scope is principal-bound (documented as OAuth-style
# scope name on the Bearer scheme, not as a second required credential).
PROTECTED_SECURITY: list[dict[str, list[str]]] = [{"BearerAuth": ["tenant"]}]
ALTERNATE_SECURITY: list[dict[str, list[str]]] = [{"DeploymentHMAC": []}]

STANDARD_RESPONSES: dict[str, dict[str, Any]] = {
    "Unauthorized": {
        "description": (
            "Missing or invalid credentials. Protected endpoints always require "
            "a valid subscriber API key (Bearer) or the surface-specific "
            "deployment credential."
        ),
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "examples": [
                                "bearer API key is required",
                                "api_key_invalid",
                                "api_key_revoked",
                                "api_key_expired",
                            ],
                        }
                    },
                    "required": ["detail"],
                }
            }
        },
    },
    "Forbidden": {
        "description": (
            "Authenticated principal lacks permission, membership is inactive, "
            "or optional X-Tenant-ID consistency hint conflicts with the "
            "principal-bound tenant scope."
        ),
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "string",
                            "examples": [
                                "permission_denied",
                                "member_inactive",
                                "tenant_mismatch",
                            ],
                        }
                    },
                    "required": ["detail"],
                }
            }
        },
    },
}


def is_public_operation(path: str, method: str) -> bool:
    return (path, method.lower()) in PUBLIC_PATH_METHODS


def is_alternate_auth_path(path: str) -> bool:
    if path in ALTERNATE_AUTH_PREFIXES:
        return True
    return any(path.startswith(prefix) for prefix in ALTERNATE_AUTH_PREFIXES)


def _strip_legacy_auth_headers(
    parameters: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not parameters:
        return []
    kept: list[dict[str, Any]] = []
    for param in parameters:
        name = str(param.get("name", "")).lower()
        if param.get("in") == "header" and name in _LEGACY_HEADER_NAMES:
            continue
        kept.append(param)
    return kept


def _attach_auth_error_responses(operation: dict[str, Any]) -> None:
    op_responses = operation.setdefault("responses", {})
    op_responses.setdefault("401", {"$ref": "#/components/responses/Unauthorized"})
    op_responses.setdefault("403", {"$ref": "#/components/responses/Forbidden"})


def apply_openapi_auth_contract(
    schema: dict[str, Any],
    *,
    public_ops: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Mutate an OpenAPI schema in place to enforce the auth contract."""
    public = frozenset((p, m.lower()) for p, m in (public_ops or PUBLIC_PATH_METHODS))

    components = schema.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes.update(SECURITY_SCHEMES)
    responses = components.setdefault("responses", {})
    responses.update(STANDARD_RESPONSES)

    # Document global default; per-op overrides still win.
    schema["security"] = list(PROTECTED_SECURITY)

    for path, methods in (schema.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.startswith("x-") or method in {
                "parameters",
                "summary",
                "description",
                "servers",
            }:
                continue
            if not isinstance(operation, dict):
                continue

            operation["parameters"] = _strip_legacy_auth_headers(
                operation.get("parameters")
            )

            method_l = method.lower()
            if (path, method_l) in public:
                operation["security"] = []
                continue

            if is_alternate_auth_path(path):
                # Not public — declare deployment-plane credentials instead of
                # implying subscriber Bearer keys or no auth at all.
                operation["security"] = list(ALTERNATE_SECURITY)
                _attach_auth_error_responses(operation)
                continue

            operation["security"] = list(PROTECTED_SECURITY)
            _attach_auth_error_responses(operation)

    return schema


def install_openapi_auth(app: FastAPI, *, title: str, version: str) -> None:
    """Replace app.openapi with a contract-aware generator."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(
            title=title,
            version=version,
            routes=app.routes,
            description=(
                "Echo Certification Forge control plane. "
                "Protected endpoints require BearerAuth; tenant scope is bound "
                "to the authenticated principal (never X-Tenant-ID alone). "
                "Public exceptions: health, seal-verify, and public verification "
                "lookup."
            ),
        )
        apply_openapi_auth_contract(schema)
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


def build_minimal_auth_demo_app() -> FastAPI:
    """Minimal FastAPI app used by acceptance tests (no full certforge stack).

    Mirrors production rules:
    - health / seal-verify public
    - protected route requires Authorization Bearer
    - tenant comes from principal, not X-Tenant-ID alone
    """
    from fastapi import Header, HTTPException

    app = FastAPI(title="Echo Certification Forge", version="1.0.0")
    install_openapi_auth(app, title="Echo Certification Forge", version="1.0.0")

    # Simulated principal store: token -> organization_id
    _PRINCIPALS = {
        "ecf_live_key_demo.secret": "org-demo-tenant",
    }

    def resolve_tenant(
        authorization: str | None,
        x_tenant_id: str | None,
    ) -> str:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="bearer API key is required")
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="bearer API key is required")
        org = _PRINCIPALS.get(token)
        if org is None:
            raise HTTPException(status_code=401, detail="api_key_invalid")
        hint = x_tenant_id.strip() if x_tenant_id and x_tenant_id.strip() else None
        if hint is not None and hint != org:
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        return org

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/seal-verify")
    def seal_verify() -> dict[str, object]:
        return {"valid": False, "reasons": ["demo"]}

    @app.get("/v1/seal-verify/{verification_id}")
    def seal_verify_get(verification_id: str) -> dict[str, object]:
        return {"verification_id": verification_id, "valid": False}

    @app.get("/v1/public/verifications/{verification_id}")
    def public_verification(verification_id: str) -> dict[str, object]:
        return {"verification_id": verification_id, "valid": False}

    @app.get("/v1/status")
    def status(
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant = resolve_tenant(authorization, x_tenant_id)
        return {"service": "echo-certification-forge", "tenant_id": tenant}

    @app.get("/v1/certifications")
    def list_certifications(
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        tenant = resolve_tenant(authorization, x_tenant_id)
        return [{"tenant_id": tenant, "runs": []}]

    @app.post("/v1/deployments/admissions")
    def deployments_admissions(
        x_certforge_signature: str | None = Header(default=None),
    ) -> dict[str, bool]:
        if not x_certforge_signature:
            raise HTTPException(status_code=401, detail="deployment_signature_required")
        return {"ok": True}

    return app
