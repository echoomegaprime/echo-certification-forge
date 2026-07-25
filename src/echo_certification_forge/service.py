"""Tenant-scoped read and deploy-gate API surface."""
from __future__ import annotations

import base64
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .canonical import sha256_json, to_utc_iso, utc_now
from .deploy_gate import DeployGate
from .deployment import DeploymentAdmissionController, DeploymentLedger
from .deployment_service import install_deployment_api
from .evidence import (
    EvidenceArtifactIntegrityError,
    EvidenceArtifactRestricted,
    EvidenceArtifactTooLarge,
    EvidenceArtifactUnavailable,
    EvidenceStore,
)
from .intake import (
    SubmitEnvironment,
    SubmitError,
    SubmitRequest,
    SubmitTarget,
    project_run,
    submit,
)
from .models import RunState, SignedVerdictEnvelope, VerdictLifecycleEvent
from .policy import RuleManifest
from .release_hooks import WebhookSecretRegistry
from .operational_telemetry import (
    OperationalTelemetryError,
    OperationalTelemetryRegistry,
    SignedOperationalReport,
)
from .runner import TrustedTransportRegistry
from .signing import TrustedPublicKeyRegistry
from .subscriber import (
    MemberRole,
    Permission,
    SubscriberError,
    SubscriberGovernance,
    SubscriberPrincipal,
)


_MAX_ADMIN_ARTIFACT_BYTES = 5 * 1024 * 1024
_LOGGER = logging.getLogger(__name__)
_SERVICE_VERSION = "0.8.0"
_TELEMETRY_RUN_LIMIT = 25
_TELEMETRY_EVENT_LIMIT = 64
_TERMINAL_STATES = {
    RunState.COMPLETED.value,
    RunState.CANCELLED.value,
    RunState.INFRASTRUCTURE_FAILURE.value,
}


@dataclass(slots=True)
class ServiceContext:
    store: EvidenceStore
    manifest: RuleManifest
    trusted_keys: TrustedPublicKeyRegistry
    subscribers: SubscriberGovernance | None = None
    deployment_ledger_path: Path | None = None
    webhook_secrets: WebhookSecretRegistry = field(
        default_factory=lambda: WebhookSecretRegistry(secrets={})
    )
    deployment_credentials: WebhookSecretRegistry = field(
        default_factory=lambda: WebhookSecretRegistry(secrets={})
    )
    transport_registry: TrustedTransportRegistry | None = None
    operational_registry: OperationalTelemetryRegistry | None = None
    adapter_mode: str = "pending"
    certification_environment: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.transport_registry is None:
            self.transport_registry = TrustedTransportRegistry.empty()
        if self.operational_registry is None:
            self.operational_registry = OperationalTelemetryRegistry(self.store.db_path)


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


class RerunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=8, max_length=128)


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


class LegalHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hold_id: str = Field(min_length=1, max_length=128)
    run_id: str | None = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2048)


class LifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: VerdictLifecycleEvent
    reason: str = Field(min_length=1, max_length=2048)
    replacement_run_id: str | None = Field(default=None, min_length=1, max_length=128)


class OperationalQuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_type: Literal["runner", "adapter"]
    subject_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=8, max_length=2048)


class OperationalQuarantineReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=8, max_length=2048)


def create_app(context: ServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge", version=_SERVICE_VERSION)

    @app.middleware("http")
    async def production_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

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
            _LOGGER.exception(
                "unhandled request exception method=%s path=%s",
                request.method,
                request.url.path,
            )
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
    assert context.transport_registry is not None
    assert context.operational_registry is not None

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
            "version": _SERVICE_VERSION,
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
        result: dict[str, object] = {
            "service": "echo-certification-forge",
            "release_verdicts": ["NOT_READY", "CONDITIONALLY_READY", "PRODUCTION_READY"],
            "run_outcomes": ["COMPLETE", "INCONCLUSIVE", "CANCELLED", "INFRA_FAILED"],
            "rule_manifest_id": context.manifest.manifest_id,
            "rule_manifest_digest": context.manifest.digest,
            "trusted_signing_keys": sorted(context.trusted_keys.keys),
            "completed_phase_gate": "P8C",
            "customer_surface": "LIVE",
            "adapter_qualification": context.adapter_mode.upper(),
            "release_verdict": "NOT_READY",
            "evidence_custody": "P3_APPEND_ONLY_VERIFIED",
            "external_evidence_anchor": "P3_INDEPENDENT_PROVIDER_VERIFIED",
            "verdict_signing": "P3_ISOLATED_SIGNER_VERIFIED",
            "public_key_lifecycle": "P3_ROTATION_REVOCATION_VERIFIED",
            "runner_isolation": "P2_FOUNDATION_VERIFIED",
            "deployment_enforcement": "P6_FAIL_CLOSED",
            "subscriber_governance": (
                "P7_FAIL_CLOSED" if context.subscribers is not None else "DISABLED"
            ),
        }
        if context.certification_environment is not None:
            result.update(context.certification_environment)
        return result

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
        run_id = request.run_id(context.manifest.digest)
        manifest_request_digest = sha256_json(
            {
                "request": request.request_digest(),
                "active_rule_manifest_digest": context.manifest.digest,
            }
        )
        manifest_idempotency_key = (
            f"{request.idempotency_key}@{context.manifest.digest[:16]}"
        )
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
                    idempotency_key=manifest_idempotency_key,
                    request_digest=manifest_request_digest,
                    policy_version=request.policy_version,
                    target_type=request.target.target_type,
                    target_reference=request.target.reference,
                    target_identity_digest=request.target.identity_digest,
                    dispatch_target_spec=target_spec,
                    journey=request.journey,
                    submit_request=request.model_dump(exclude_none=True),
                )
            if context.subscribers is not None and reservation is not None:
                created = context.subscribers.materialize_reserved_run(
                    reservation,
                    run_id=run_id,
                    target_type=request.target.target_type,
                    target_reference=request.target.reference,
                    target_identity_digest=request.target.identity_digest,
                    environment_identity_digest=request.environment.identity_digest,
                    environment_json=request.environment.model_dump(exclude_none=True),
                    manifest_id=context.manifest.manifest_id,
                    manifest_digest=context.manifest.digest,
                    target_spec=target_spec,
                    journey=request.journey,
                )
                status_code = 201 if created else 200
                body = project_run(
                    context.store,
                    context.store.get_run(run_id, tenant_id),
                )
            else:
                status_code, body = submit(
                    context.store, context.manifest, request, tenant_id
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

    @app.get("/v1/subscriber/certifications/{run_id}/evidence/{artifact_id}")
    def get_evidence_artifact(
        run_id: str,
        artifact_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.RUN_READ,
            "certifications.evidence.download",
        )
        try:
            context.subscribers.require_plan_feature(principal, "audit_exports")
            descriptor, content = context.store.read_evidence_artifact(
                run_id,
                principal.organization_id,
                artifact_id,
                max_bytes=_MAX_ADMIN_ARTIFACT_BYTES,
            )
            context.subscribers.audit_resource_event(
                principal,
                action="evidence.download",
                resource_type="evidence_artifact",
                resource_id=artifact_id,
                details={
                    "run_id": run_id,
                    "sha256": descriptor["sha256"],
                    "size_bytes": descriptor["size_bytes"],
                },
            )
            return {
                "run_id": run_id,
                "artifact_id": artifact_id,
                "sha256": descriptor["sha256"],
                "size_bytes": descriptor["size_bytes"],
                "media_type": descriptor["media_type"],
                "redaction_status": descriptor["redaction_status"],
                "encoding": "base64",
                "payload_base64": base64.b64encode(content).decode("ascii"),
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="artifact_not_found") from exc
        except EvidenceArtifactRestricted as exc:
            raise HTTPException(status_code=403, detail="artifact_redaction_incomplete") from exc
        except EvidenceArtifactTooLarge as exc:
            raise HTTPException(status_code=413, detail="artifact_too_large") from exc
        except EvidenceArtifactUnavailable as exc:
            raise HTTPException(status_code=410, detail="artifact_content_unavailable") from exc
        except EvidenceArtifactIntegrityError as exc:
            raise HTTPException(status_code=409, detail="artifact_integrity_failed") from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

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

    @app.post("/v1/subscriber/certifications/{run_id}/rerun", status_code=201)
    def subscriber_rerun(
        run_id: str,
        request: RerunRequest,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        """Create a governed queued run with immutable lineage to a terminal source."""
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.RUN_CREATE,
            "certifications.rerun",
        )
        reservation = None
        try:
            source = context.store.get_run(run_id, principal.organization_id)
            if source["state"] not in _TERMINAL_STATES:
                raise SubscriberError(409, "source_run_not_terminal")
            if (
                source.get("policy_version") != context.manifest.manifest_id
                or source["rule_manifest_digest"] != context.manifest.digest
            ):
                raise SubscriberError(409, "source_policy_not_active")
            target = json.loads(source["target_identity_json"])
            environment = json.loads(source["environment_identity_json"])
            target_type = str(target.get("target_type", ""))
            target_reference = str(
                source.get("target_reference")
                or target.get("reference")
                or target.get("canonical_ref")
                or ""
            )
            project_id = source.get("project_id")
            if not target_type or not target_reference or not project_id:
                raise SubscriberError(409, "source_run_not_rerunnable")

            internal_key = "rerun-" + sha256_json(
                {
                    "source_run_id": run_id,
                    "idempotency_key": request.idempotency_key,
                }
            )
            runner_image_digest = environment.get("runner_image_digest")
            if runner_image_digest is None and environment.get("runner_image_sha256"):
                runner_image_digest = "sha256:" + str(environment["runner_image_sha256"])
            rerun_request = SubmitRequest(
                tenant_id=principal.organization_id,
                project_id=str(project_id),
                target=SubmitTarget(
                    target_type=target_type,
                    identity_digest=source["target_identity_digest"],
                    reference=target_reference,
                ),
                environment=SubmitEnvironment(
                    identity_digest=source["environment_identity_digest"],
                    runner_image_digest=runner_image_digest,
                ),
                policy_version=context.manifest.manifest_id,
                idempotency_key=internal_key,
            )
            target_spec, journey = context.subscribers.rerun_dispatch_template(
                principal, run_id
            )
            request_digest = sha256_json(
                {
                    "request": rerun_request.request_digest(),
                    "active_rule_manifest_digest": context.manifest.digest,
                }
            )
            scoped_key = f"{internal_key}@{context.manifest.digest[:16]}"
            reservation = context.subscribers.reserve_certification_run(
                principal,
                project_id=str(project_id),
                idempotency_key=scoped_key,
                request_digest=request_digest,
                policy_version=rerun_request.policy_version,
                target_type=rerun_request.target.target_type,
                target_reference=rerun_request.target.reference,
                target_identity_digest=rerun_request.target.identity_digest,
                dispatch_target_spec=target_spec,
                journey=journey,
                submit_request=rerun_request.model_dump(exclude_none=True),
            )
            rerun_id = rerun_request.run_id(context.manifest.digest)
            created = context.subscribers.materialize_reserved_run(
                reservation,
                run_id=rerun_id,
                target_type=rerun_request.target.target_type,
                target_reference=rerun_request.target.reference,
                target_identity_digest=rerun_request.target.identity_digest,
                environment_identity_digest=rerun_request.environment.identity_digest,
                environment_json=rerun_request.environment.model_dump(exclude_none=True),
                manifest_id=context.manifest.manifest_id,
                manifest_digest=context.manifest.digest,
                target_spec=target_spec,
                journey=journey,
                source_run_id=run_id,
            )
            response.status_code = 201 if created else 200
            body = project_run(
                context.store,
                context.store.get_run(rerun_id, principal.organization_id),
            )
            context.subscribers.audit_resource_event(
                principal,
                action="certification.rerun",
                resource_type="certification",
                resource_id=rerun_id,
                details={"source_run_id": run_id, "status_code": response.status_code},
            )
            return body
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except SubscriberError as exc:
            if reservation is not None and reservation.created:
                context.subscribers.release_reservation(
                    reservation, reason="rerun_rejected", compensate_meter=True
                )
            raise subscriber_error(exc) from exc

    @app.post("/v1/subscriber/legal-holds", status_code=201)
    def create_legal_hold(
        request: LegalHoldRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_MANAGE,
            "legal_holds.create",
        )
        try:
            if request.run_id is not None:
                context.store.get_run(request.run_id, principal.organization_id)
            return context.subscribers.create_legal_hold(
                principal,
                hold_id=request.hold_id,
                run_id=request.run_id,
                reason=request.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.delete("/v1/subscriber/legal-holds/{hold_id}")
    def release_legal_hold(
        hold_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_MANAGE,
            "legal_holds.release",
        )
        try:
            return context.subscribers.release_legal_hold(principal, hold_id)
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.post("/v1/subscriber/certifications/{run_id}/lifecycle")
    def append_lifecycle(
        run_id: str,
        request: LifecycleRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_MANAGE,
            "certifications.lifecycle",
        )
        try:
            context.store.get_run(run_id, principal.organization_id)
            if request.event_type is VerdictLifecycleEvent.SUPERSEDED:
                if request.replacement_run_id is None:
                    raise SubscriberError(422, "replacement_run_id_required")
                context.store.get_run(
                    request.replacement_run_id, principal.organization_id
                )
            context.store.append_lifecycle_event(
                run_id,
                principal.organization_id,
                request.event_type,
                actor=f"api_key:{principal.key_id}",
                reason=request.reason,
                replacement_run_id=request.replacement_run_id,
            )
            context.subscribers.audit_resource_event(
                principal,
                action="verdict.lifecycle",
                resource_type="certification",
                resource_id=run_id,
                details=request.model_dump(mode="json"),
            )
            return {
                "run_id": run_id,
                "event_type": request.event_type.value,
                "replacement_run_id": request.replacement_run_id,
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.post("/v1/subscriber/certifications/{run_id}/publish")
    def publish_verification(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.RUN_READ,
            "certifications.publish",
        )
        try:
            row = context.store.latest_signed_verdict(
                run_id, principal.organization_id
            )
            if row is None:
                raise SubscriberError(409, "signed_verdict_missing")
            payload = json.loads(row["payload_json"])
            gate = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=principal.organization_id,
                run_id=run_id,
                target_identity_digest=payload["target_identity_digest"],
                environment_identity_digest=payload["environment_identity_digest"],
                rule_manifest_digest=payload["rule_manifest_digest"],
                evidence_merkle_root=payload["evidence_merkle_root"],
                signing_key_id=payload["signing_key_id"],
            )
            if not gate.allowed:
                raise SubscriberError(409, "certification_not_current")
            verification_id = context.subscribers.publish_verification(
                principal, run_id
            )
            return {
                "verification_id": verification_id,
                "verification_url": f"/v1/public/verifications/{verification_id}",
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.get("/v1/public/verifications/{verification_id}")
    def public_verification(verification_id: str) -> dict[str, Any]:
        try:
            published = context.subscribers.public_verification(verification_id)
            row = context.store.latest_signed_verdict(
                published["run_id"], published["organization_id"]
            )
            if row is None:
                raise SubscriberError(404, "verification_not_found")
            payload = json.loads(row["payload_json"])
            gate = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=published["organization_id"],
                run_id=published["run_id"],
                target_identity_digest=payload["target_identity_digest"],
                environment_identity_digest=payload["environment_identity_digest"],
                rule_manifest_digest=payload["rule_manifest_digest"],
                evidence_merkle_root=payload["evidence_merkle_root"],
                signing_key_id=payload["signing_key_id"],
            )
            return {
                "verification_id": verification_id,
                "valid": gate.allowed,
                "reasons": list(gate.reasons),
                "payload": payload,
                "signature_b64": row["signature_b64"],
                "key_id": row["key_id"],
                "public_key_pem": row["public_key_pem"],
            }
        except (KeyError, ValueError, SubscriberError) as exc:
            raise HTTPException(
                status_code=404, detail="verification_not_found"
            ) from exc

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

    @app.post("/v1/internal/worker-heartbeats")
    def ingest_worker_heartbeat(report: SignedOperationalReport) -> dict[str, Any]:
        try:
            return context.operational_registry.ingest_worker_heartbeat(
                report, context.transport_registry
            )
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc

    @app.post("/v1/internal/adapter-inventory")
    def ingest_adapter_inventory(report: SignedOperationalReport) -> dict[str, Any]:
        try:
            return context.operational_registry.ingest_adapter_inventory(
                report, context.transport_registry
            )
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc

    @app.get("/v1/subscriber/telemetry")
    def subscriber_telemetry(
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Project bounded operational truth without implying worker health we cannot prove."""
        principal = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.USAGE_READ,
            "telemetry.read",
        )
        try:
            usage = context.subscribers.usage_summary(principal)
            raw_state_counts = context.store.count_runs_by_state(
                principal.organization_id
            )
            recent_run_rows = context.store.list_runs(
                principal.organization_id, limit=_TELEMETRY_RUN_LIMIT
            )
            authenticated = context.operational_registry.snapshot(
                principal.organization_id
            )
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

        state_counts = {state.value: 0 for state in RunState}
        for state, count in raw_state_counts.items():
            state_counts[state] = count
        active_runs = sum(
            count for state, count in state_counts.items() if state not in _TERMINAL_STATES
        )
        concurrent_limit = int(usage["limits"]["concurrent_runs"])
        run_limit = int(usage["limits"]["monthly_certification_runs"])
        run_usage = int(usage["meters"].get("certification_runs", 0))
        budgets = {
            "certification_runs": {
                "used": run_usage,
                "limit": run_limit,
                "remaining": max(run_limit - run_usage, 0),
            }
        }

        recent_runs = []
        for row in recent_run_rows:
            events = context.store.list_state_events(
                str(row["run_id"]),
                principal.organization_id,
                limit=_TELEMETRY_EVENT_LIMIT,
            )
            recent_runs.append(
                {
                    "run_id": row["run_id"],
                    "state": row["state"],
                    "run_outcome": row["run_outcome"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "timeline": events,
                    "timeline_truncated": len(events) >= _TELEMETRY_EVENT_LIMIT,
                }
            )

        return {
            "generated_at": to_utc_iso(utc_now()),
            "queue": {
                "queued": state_counts[RunState.QUEUED.value],
                "active": active_runs,
                "terminal": sum(state_counts[state] for state in _TERMINAL_STATES),
                "total": sum(state_counts.values()),
                "state_counts": state_counts,
            },
            "capacity": {
                "concurrent_run_limit": concurrent_limit,
                "active_runs": active_runs,
                "quota_slots_remaining": max(concurrent_limit - active_runs, 0),
                "runner_health": authenticated["runner"]["health"],
                "runner_health_reason": authenticated["runner"]["reason"],
                "capacity_basis": "subscription_quota_only",
                "authenticated_runner_source": authenticated["runner"],
            },
            "subscription": {
                "plan_code": principal.plan_code,
                "period_start": usage["period_started_at"],
                "period_end": usage["period_ended_at"],
                "certification_runs_limit": run_limit,
            },
            "budgets": budgets,
            "state_machine": {
                "ordered_states": [state.value for state in RunState],
                "terminal_states": sorted(_TERMINAL_STATES),
                "recent_runs": recent_runs,
                "recent_runs_limit": _TELEMETRY_RUN_LIMIT,
            },
            "adapters": authenticated["adapters"],
            "authenticated_source_snapshot_sha256": authenticated["snapshot_sha256"],
        }

    @app.post("/v1/subscriber/operational-quarantines")
    def quarantine_operational_subject(
        request: OperationalQuarantineRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_MANAGE,
            "operations.quarantine",
        )
        try:
            result = context.operational_registry.quarantine(
                actor.organization_id,
                subject_type=request.subject_type,
                subject_id=request.subject_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.subscribers.audit_resource_event(
                actor,
                action="operations.quarantine",
                resource_type=request.subject_type,
                resource_id=request.subject_id,
                details={
                    "reason": request.reason,
                    "idempotent": bool(result["idempotent"]),
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except SubscriberError as exc:
            raise subscriber_error(exc) from exc

    @app.post(
        "/v1/subscriber/operational-quarantines/{subject_type}/{subject_id}/release"
    )
    def release_operational_quarantine(
        subject_type: Literal["runner", "adapter"],
        subject_id: str,
        request: OperationalQuarantineReleaseRequest,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = subscriber_principal(
            x_tenant_id,
            authorization,
            Permission.GOVERNANCE_MANAGE,
            "operations.quarantine.release",
        )
        try:
            result = context.operational_registry.release_quarantine(
                actor.organization_id,
                subject_type=subject_type,
                subject_id=subject_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.subscribers.audit_resource_event(
                actor,
                action="operations.quarantine.release",
                resource_type=subject_type,
                resource_id=subject_id,
                details={"reason": request.reason},
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
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

    app.state.certforge_manifest = context.manifest
    ledger_path = context.deployment_ledger_path or context.store.db_path.with_name(
        context.store.db_path.stem + "-deployments.sqlite3"
    )
    controller = DeploymentAdmissionController(
        store=context.store,
        trusted_keys=context.trusted_keys,
        ledger=DeploymentLedger(ledger_path),
        active_rule_manifest_digest=context.manifest.digest,
    )
    install_deployment_api(
        app,
        controller,
        context.webhook_secrets,
        context.deployment_credentials,
    )

    return app
