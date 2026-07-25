"""Tenant-scoped read and deploy-gate API surface."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .deploy_gate import DeployGate
from .evidence import EvidenceStore
from .intake import SubmitError, SubmitRequest, project_run, submit
from .models import RunState, SignedVerdictEnvelope
from .policy import RuleManifest
from .signing import TrustedPublicKeyRegistry
from .subscriber import (
    MemberRole,
    Permission,
    SubscriberError,
    SubscriberGovernance,
    SubscriberPrincipal,
)


@dataclass(slots=True)
class ServiceContext:
    store: EvidenceStore
    manifest: RuleManifest
    trusted_keys: TrustedPublicKeyRegistry
    subscribers: SubscriberGovernance | None = None


class DeployGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(min_length=1, max_length=128)
    target_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    name: str = Field(min_length=1, max_length=160)
    target_reference: str = Field(min_length=1, max_length=2048)


class ApiKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    user_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    )
    scopes: list[Permission] = Field(min_length=1)
    expires_at: datetime


class GovernanceConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_policy_ids: list[str]
    retention_days: int
    private_worker_only: bool
    report_brand_name: str | None
    report_logo_url: str | None
    customer_managed_signing: bool
    customer_signing_key_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    )
    local_only_execution: bool


class GovernanceUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    config: GovernanceConfigRequest


class PolicyPackCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    manifest: dict[str, Any]


class PrivateWorkerCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(min_length=1, max_length=160)
    attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MemberInviteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=160)
    role: MemberRole


class MemberRoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: MemberRole


def create_app(context: ServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge", version="0.4.0")

    @app.middleware("http")
    async def audit_final_request_outcome(request: Request, call_next):
        audit_actor = None
        if context.subscribers is not None:
            authorization = request.headers.get("Authorization")
            if authorization is not None and authorization.startswith("Bearer "):
                token = authorization.removeprefix("Bearer ").strip()
                if token:
                    try:
                        audit_actor = context.subscribers.resolve_request_audit_actor(token)
                    except sqlite3.Error:
                        return JSONResponse(
                            status_code=503,
                            content={"detail": "subscriber_governance_unavailable"},
                        )
        try:
            response = await call_next(request)
        except Exception:
            if context.subscribers is not None and audit_actor is not None:
                try:
                    context.subscribers.audit_request_outcome(
                        organization_id=audit_actor["organization_id"],
                        actor_ref=audit_actor["actor_ref"],
                        key_id=audit_actor["key_id"],
                        method=request.method,
                        path=request.url.path,
                        status_code=500,
                        tenant_hint=request.headers.get("X-Tenant-ID"),
                        reason="unhandled_exception",
                    )
                except sqlite3.Error:
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "subscriber_governance_unavailable"},
                    )
            return JSONResponse(
                status_code=500,
                content={"detail": "internal_server_error"},
            )
        audit_reason = response.headers.get("X-Certforge-Audit-Code")
        if audit_reason is not None:
            del response.headers["X-Certforge-Audit-Code"]
        if context.subscribers is not None and audit_actor is not None:
            try:
                context.subscribers.audit_request_outcome(
                    organization_id=audit_actor["organization_id"],
                    actor_ref=audit_actor["actor_ref"],
                    key_id=audit_actor["key_id"],
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    tenant_hint=request.headers.get("X-Tenant-ID"),
                    reason=audit_reason,
                )
            except sqlite3.Error:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "subscriber_governance_unavailable"},
                )
        return response

    @app.exception_handler(SubscriberError)
    async def handle_subscriber_error(
        _request: Request, exc: SubscriberError
    ) -> JSONResponse:
        headers = {"X-Certforge-Audit-Code": exc.code}
        if exc.retry_after is not None:
            headers["Retry-After"] = str(exc.retry_after)
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.code},
            headers=headers,
        )

    @app.exception_handler(sqlite3.Error)
    async def handle_subscriber_storage_error(
        _request: Request, _exc: sqlite3.Error
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "subscriber_governance_unavailable"
                    if context.subscribers is not None
                    else "certification_store_unavailable"
                )
            },
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": "request_validation_error"},
            headers={"X-Certforge-Audit-Code": "request_validation_error"},
        )

    def tenant(value: str | None) -> str:
        if value is None or not value.strip():
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        return value

    def subscriber_error(exc: SubscriberError) -> HTTPException:
        headers = {"X-Certforge-Audit-Code": exc.code}
        if exc.retry_after is not None:
            headers["Retry-After"] = str(exc.retry_after)
        return HTTPException(status_code=exc.status_code, detail=exc.code, headers=headers)

    def authorize(
        tenant_header: str | None,
        authorization: str | None,
        permission: Permission,
        action: str,
    ) -> tuple[str, SubscriberPrincipal | None]:
        tenant_id = tenant(tenant_header)
        if context.subscribers is None:
            return tenant_id, None
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="bearer API key is required")
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="bearer API key is required")
        try:
            principal = context.subscribers.authenticate(
                token,
                tenant_hint=tenant_id,
                permission=permission,
                action=action,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="subscriber_governance_unavailable") from exc
        return principal.organization_id, principal

    def subscriber_principal(
        tenant_header: str | None,
        authorization: str | None,
        permission: Permission,
        action: str,
    ) -> SubscriberPrincipal:
        if context.subscribers is None:
            raise HTTPException(status_code=503, detail="subscriber_governance_disabled")
        _tenant_id, principal = authorize(tenant_header, authorization, permission, action)
        if principal is None:
            raise HTTPException(status_code=503, detail="subscriber_governance_disabled")
        return principal

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        # Shape matches the echo.certforge.health output_schema
        # (contracts/certforge-capabilities.v1.json): status, version, custody, anchor, signing.
        return {
            "status": "ok",
            "version": "0.4.0",
            "custody": "append_only_merkle_verified",
            "anchor": "independent_provider_required",
            "signing": "isolated_out_of_process",
            "control_plane_executes_customer_code": False,
            "private_signing_key_loaded": False,
            "subscriber_governance": (
                "configured" if context.subscribers is not None else "disabled"
            ),
        }

    @app.get("/v1/status")
    def status() -> dict[str, object]:
        return {
            "service": "echo-certification-forge",
            "release_verdicts": ["NOT_READY", "CONDITIONALLY_READY", "PRODUCTION_READY"],
            "run_outcomes": ["COMPLETE", "INCONCLUSIVE", "CANCELLED", "INFRA_FAILED"],
            "rule_manifest_id": context.manifest.manifest_id,
            "rule_manifest_digest": context.manifest.digest,
            "trusted_signing_keys": sorted(context.trusted_keys.keys),
            "completed_phase_gate": "P3",
            "release_verdict": "NOT_READY",
            "evidence_custody": "P3_APPEND_ONLY_VERIFIED",
            "external_evidence_anchor": "P3_INDEPENDENT_PROVIDER_VERIFIED",
            "verdict_signing": "P3_ISOLATED_SIGNER_VERIFIED",
            "public_key_lifecycle": "P3_ROTATION_REVOCATION_VERIFIED",
            "runner_isolation": "P2_FOUNDATION_VERIFIED",
        }

    @app.post("/v1/certifications", status_code=201)
    def submit_certification(
        request: SubmitRequest,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, principal = authorize(
            x_tenant_id, authorization, Permission.RUN_CREATE, "certifications.submit"
        )
        reservation = None
        try:
            if context.subscribers is not None:
                if principal is None or request.project_id is None:
                    raise SubscriberError(422, "project_id_required")
                try:
                    target_spec = request.target.worker_spec()
                except ValueError as exc:
                    raise SubscriberError(422, "target_not_dispatchable") from exc
                reservation = context.subscribers.reserve_certification_run(
                    principal,
                    project_id=request.project_id,
                    idempotency_key=request.idempotency_key,
                    request_digest=request.request_digest(),
                    policy_version=request.policy_version,
                    target_type=request.target.target_type,
                    target_reference=request.target.reference,
                    target_identity_digest=request.target.identity_digest,
                    dispatch_target_spec=target_spec,
                    journey=request.journey,
                    submit_request=request.model_dump(exclude_none=True),
                )
            status_code, body = submit(context.store, context.manifest, request, tenant_id)
            if context.subscribers is not None and reservation is not None:
                context.subscribers.bind_run(
                    reservation,
                    str(body["run_id"]),
                    target_spec=target_spec,
                    journey=request.journey,
                )
        except SubmitError as exc:
            if reservation is not None and reservation.created:
                context.subscribers.release_reservation(
                    reservation, reason="submit_rejected", compensate_meter=True
                )
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except SubscriberError as exc:
            if reservation is not None and reservation.created:
                context.subscribers.release_reservation(
                    reservation, reason="governance_rejected", compensate_meter=True
                )
            raise subscriber_error(exc) from exc
        except sqlite3.Error as exc:
            if reservation is not None and reservation.created:
                try:
                    context.subscribers.release_reservation(
                        reservation,
                        reason="subscriber_storage_failure",
                        compensate_meter=True,
                    )
                except sqlite3.Error:
                    pass
            raise HTTPException(status_code=503, detail="subscriber_governance_unavailable") from exc
        response.status_code = status_code
        return body

    @app.get("/v1/certifications")
    def list_runs(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.list"
        )
        return [project_run(context.store, row) for row in context.store.list_runs(tenant_id)]

    @app.get("/v1/certifications/{run_id}")
    def get_run(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.read"
        )
        try:
            row = context.store.get_run(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return project_run(context.store, row)

    @app.post("/v1/certifications/{run_id}/cancel")
    def cancel_certification(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_CANCEL, "certifications.cancel"
        )
        try:
            context.store.transition_state(
                run_id=run_id,
                tenant_id=tenant_id,
                next_state=RunState.CANCELLED,
                actor="certforge.api",
                reason="cancel_requested",
                workflow_version="t4.p2",
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except ValueError as exc:
            # already terminal / past the cancellable window — fail closed, never re-open
            raise HTTPException(status_code=409, detail="run_not_cancellable") from exc
        return project_run(context.store, context.store.get_run(run_id, tenant_id))

    @app.get("/v1/certifications/{run_id}/findings")
    def get_findings(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.findings"
        )
        try:
            findings = context.store.list_findings(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run_id": run_id, "findings": findings}

    @app.get("/v1/certifications/{run_id}/evidence")
    def get_evidence_index(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.evidence"
        )
        try:
            artifacts = context.store.list_evidence(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run_id": run_id, "artifacts": artifacts}  # redacted index, never raw content

    @app.post("/v1/certifications/{run_id}/verify")
    def verify_run(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.verify"
        )
        try:
            report = context.store.verify_evidence(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {
            "run_id": report.run_id,
            "valid": report.valid,
            "artifact_count": report.artifact_count,
            "invalid_artifacts": list(report.invalid_artifacts),
            "merkle_root": report.merkle_root,
            "chain_tip": report.chain_tip,
        }

    @app.get("/v1/certifications/{run_id}/verdict")
    def get_verdict(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "certifications.verdict"
        )
        try:
            row = context.store.latest_signed_verdict(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        if row is None:
            raise HTTPException(status_code=404, detail="verdict_not_available")
        return {
            "run_id": run_id,
            "payload": json.loads(row["payload_json"]),
            "signature_b64": row["signature_b64"],
            "key_id": row["key_id"],
            "public_key_pem": row["public_key_pem"],
        }

    @app.get("/v1/certifications/{run_id}/evidence/verify")
    def verify_evidence(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "evidence.verify"
        )
        try:
            report = context.store.verify_evidence(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {
            "run_id": report.run_id,
            "valid": report.valid,
            "artifact_count": report.artifact_count,
            "invalid_artifacts": list(report.invalid_artifacts),
            "merkle_root": report.merkle_root,
            "chain_tip": report.chain_tip,
        }

    @app.get("/v1/certifications/{run_id}/verdict/verify")
    def verify_verdict(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, _principal = authorize(
            x_tenant_id, authorization, Permission.RUN_READ, "verdict.verify"
        )
        try:
            row = context.store.latest_signed_verdict(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        if row is None:
            return {"valid": False, "reason": "signed_verdict_missing"}
        envelope = SignedVerdictEnvelope(
            payload=json.loads(row["payload_json"]),
            signature_b64=row["signature_b64"],
            key_id=row["key_id"],
            public_key_pem=row["public_key_pem"],
        )
        valid, reason = context.trusted_keys.verify(envelope)
        return {"valid": valid, "reason": reason, "key_id": envelope.key_id, "payload": envelope.payload}

    @app.post("/v1/release-gates/evaluate")
    def evaluate_gate(
        request: DeployGateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id, principal = authorize(
            x_tenant_id, authorization, Permission.RELEASE_GATE, "release_gate.evaluate"
        )
        try:
            if context.subscribers is not None:
                if principal is None:
                    raise SubscriberError(503, "subscriber_governance_disabled")
                context.subscribers.require_plan_feature(principal, "release_gates")
            result = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=tenant_id,
                run_id=request.run_id,
                target_identity_digest=request.target_identity_digest,
                environment_identity_digest=request.environment_identity_digest,
                rule_manifest_digest=request.rule_manifest_digest,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        return result.to_dict()

    @app.get("/v1/subscriber/me")
    def subscriber_me(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.PROJECT_READ, "subscriber.me"
        )
        return {
            "organization_id": principal.organization_id,
            "user_id": principal.user_id,
            "role": principal.role.value,
            "key_id": principal.key_id,
            "scopes": sorted(scope.value for scope in principal.scopes),
            "organization_status": principal.organization_status.value,
            "plan_code": principal.plan_code,
        }

    @app.post("/v1/subscriber/projects", status_code=201)
    def create_project(
        request: ProjectCreateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.PROJECT_MANAGE, "projects.create"
        )
        try:
            return context.subscribers.create_project(
                principal,
                slug=request.slug,
                name=request.name,
                target_reference=request.target_reference,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        except sqlite3.Error as exc:
            raise HTTPException(status_code=503, detail="subscriber_governance_unavailable") from exc

    @app.get("/v1/subscriber/projects")
    def list_projects(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.PROJECT_READ, "projects.list"
        )
        try:
            return context.subscribers.list_projects(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.delete("/v1/subscriber/projects/{project_id}", status_code=204)
    def archive_project(
        project_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.PROJECT_MANAGE, "projects.archive"
        )
        context.subscribers.archive_project(principal, project_id)
        return Response(status_code=204)

    @app.post("/v1/subscriber/api-keys", status_code=201)
    def create_api_key(
        request: ApiKeyCreateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.API_KEY_MANAGE, "api_keys.create"
        )
        try:
            token = context.subscribers.create_api_key(
                principal,
                name=request.name,
                scopes=request.scopes,
                expires_at=request.expires_at,
                user_id=request.user_id,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        return {"api_key": token, "returned_once": True}

    @app.get("/v1/subscriber/api-keys")
    def list_api_keys(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.API_KEY_MANAGE, "api_keys.list"
        )
        try:
            return context.subscribers.list_api_keys(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.delete("/v1/subscriber/api-keys/{key_id}", status_code=204)
    def revoke_api_key(
        key_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.API_KEY_MANAGE, "api_keys.revoke"
        )
        try:
            context.subscribers.revoke_api_key(principal, key_id)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        return Response(status_code=204)

    @app.post("/v1/subscriber/members", status_code=201)
    def invite_member(
        request: MemberInviteRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.MEMBER_MANAGE, "members.invite"
        )
        try:
            user_id = context.subscribers.invite_member(
                principal,
                email=request.email,
                display_name=request.display_name,
                role=request.role,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc
        return {"user_id": user_id, "status": "INVITED"}

    @app.get("/v1/subscriber/members")
    def list_members(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.MEMBER_MANAGE, "members.list"
        )
        return context.subscribers.list_members(principal)

    @app.post("/v1/subscriber/members/{user_id}/activate", status_code=204)
    def activate_member(
        user_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.MEMBER_MANAGE, "members.activate"
        )
        context.subscribers.activate_member(principal, user_id)
        return Response(status_code=204)

    @app.patch("/v1/subscriber/members/{user_id}/role", status_code=204)
    def update_member_role(
        user_id: str,
        request: MemberRoleUpdateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.MEMBER_MANAGE, "members.role_update"
        )
        context.subscribers.update_member_role(principal, user_id, request.role)
        return Response(status_code=204)

    @app.delete("/v1/subscriber/members/{user_id}", status_code=204)
    def deactivate_member(
        user_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.MEMBER_MANAGE, "members.deactivate"
        )
        context.subscribers.deactivate_member(principal, user_id)
        return Response(status_code=204)

    @app.get("/v1/subscriber/subscription")
    def get_subscription(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.GOVERNANCE_READ, "subscription.read"
        )
        try:
            return context.subscribers.subscription(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.post("/v1/subscriber/subscription/cancel")
    def cancel_subscription(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.BILLING_MANAGE, "subscription.cancel"
        )
        try:
            return context.subscribers.request_subscription_cancellation(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/subscriber/governance")
    def get_governance(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.GOVERNANCE_READ, "governance.read"
        )
        try:
            return context.subscribers.governance_config(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.put("/v1/subscriber/governance")
    def update_governance(
        request: GovernanceUpdateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.GOVERNANCE_MANAGE, "governance.update"
        )
        try:
            return context.subscribers.update_governance(
                principal,
                request.config.model_dump(mode="json"),
                expected_version=request.expected_version,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.post("/v1/subscriber/policy-packs", status_code=201)
    def create_policy_pack(
        request: PolicyPackCreateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.POLICY_PACK_MANAGE, "policy_packs.create"
        )
        try:
            return context.subscribers.create_policy_pack(
                principal,
                name=request.name,
                version=request.version,
                manifest=request.manifest,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/subscriber/policy-packs")
    def list_policy_packs(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_READ,
            "policy_packs.list",
        )
        return context.subscribers.list_policy_packs(principal)

    @app.post("/v1/subscriber/private-workers", status_code=201)
    def create_private_worker(
        request: PrivateWorkerCreateRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.PRIVATE_WORKER_MANAGE,
            "private_workers.create",
        )
        try:
            return context.subscribers.register_private_worker(
                principal,
                display_name=request.display_name,
                attestation_sha256=request.attestation_sha256,
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/subscriber/private-workers")
    def list_private_workers(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.PRIVATE_WORKER_MANAGE,
            "private_workers.list",
        )
        return context.subscribers.list_private_workers(principal)

    @app.delete("/v1/subscriber/private-workers/{worker_id}", status_code=204)
    def revoke_private_worker(
        worker_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Response:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.PRIVATE_WORKER_MANAGE,
            "private_workers.revoke",
        )
        context.subscribers.revoke_private_worker(principal, worker_id)
        return Response(status_code=204)

    @app.get("/v1/subscriber/usage")
    def get_usage(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.USAGE_READ, "usage.read"
        )
        try:
            return context.subscribers.usage_summary(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/subscriber/audit")
    def get_audit(
        limit: int = Query(default=100, ge=1, le=1000),
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.AUDIT_READ, "audit.list"
        )
        try:
            return context.subscribers.list_audit_events(principal, limit=limit)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/subscriber/audit/verify")
    def verify_audit(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id, authorization, Permission.AUDIT_READ, "audit.verify"
        )
        try:
            return context.subscribers.verify_audit(principal)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    return app
