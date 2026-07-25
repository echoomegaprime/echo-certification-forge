"""P6 HTTP surface — deployment admission, outcomes, rollback, release status, webhooks.

Installed additively onto the existing tenant-scoped API by ``install_deployment_api``.
Every endpoint is fail-closed: a missing tenant header, unknown artifact, or unverifiable
certification denies. Mutation endpoints (binding, admission, outcome) additionally require
an authenticated tenant-bound deployment credential — an HMAC signature over the exact
request body proving possession of the tenant's deployment secret; the ``X-Tenant-ID``
header alone never authorizes a mutation. Admission decisions are RECORDED (append-only,
hash-chained) whether allowed or denied, so the deployment audit trail is complete by
construction.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .deployment import (
    PRODUCTION,
    AdmissionRequest,
    BindingError,
    DeploymentAdmissionController,
    DeploymentOutcomeStatus,
    OutcomeError,
)
from .release_hooks import (
    BUILD_EVENT,
    REGISTRY_EVENT,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookError,
    WebhookSecretRegistry,
    ingest_webhook,
    verify_webhook_signature,
)

_ACTOR = "certforge.deployment_api"

DEPLOY_SIGNATURE_HEADER = "X-Certforge-Deploy-Signature"
DEPLOY_TIMESTAMP_HEADER = "X-Certforge-Deploy-Timestamp"


class AdmitBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artifact_sha256: str = Field(pattern=r"^(sha256:)?[0-9a-f]{64}$")
    deployment_environment: str = Field(pattern=r"^(staging|production)$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_id: str = Field(min_length=1, max_length=128)
    requested_by: str = Field(min_length=1, max_length=128)


class OutcomeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(pattern=r"^(SUCCEEDED|FAILED|ROLLED_BACK)$")
    detail: str = Field(min_length=1, max_length=4096)
    rollback_to: str | None = Field(default=None, pattern=r"^(sha256:)?[0-9a-f]{64}$")


def install_deployment_api(
    app: FastAPI,
    controller: DeploymentAdmissionController,
    webhook_secrets: WebhookSecretRegistry,
    deployment_credentials: WebhookSecretRegistry,
) -> None:
    store = controller.store

    def tenant(value: str | None) -> str:
        if value is None or not value.strip():
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        return value

    def authorize_mutation(tenant_id: str, request: Request, body: bytes) -> None:
        """Require the tenant-bound deployment credential for any mutation.

        The caller must prove possession of the tenant's deployment secret with an HMAC
        signature over ``{timestamp}.{body}`` (same verified scheme as release webhooks).
        Fail-closed on every path: unregistered tenant, missing/invalid headers, stale
        timestamp, or a signature made with a different tenant's secret all yield 401.
        """
        try:
            verify_webhook_signature(
                deployment_credentials,
                tenant_id,
                request.headers.get(DEPLOY_SIGNATURE_HEADER),
                request.headers.get(DEPLOY_TIMESTAMP_HEADER),
                body,
            )
        except WebhookError as exc:
            code = exc.code.replace("webhook_", "deployment_credential_", 1)
            raise HTTPException(status_code=exc.status_code, detail=code) from exc

    @app.post("/v1/certifications/{run_id}/bindings", status_code=201)
    async def bind_certification(
        run_id: str,
        request: Request,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        authorize_mutation(tenant_id, request, await request.body())
        try:
            record = controller.bind_certification(run_id, tenant_id, _ACTOR)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except BindingError as exc:
            raise HTTPException(status_code=409, detail=exc.code) from exc
        if not record.get("created", True):
            response.status_code = 200
        return {
            "run_id": run_id,
            "artifact_sha256": record["artifact_sha256"],
            "record_id": record["record_id"],
            "chain_hash": record["chain_hash"],
            "created": bool(record.get("created", True)),
        }

    @app.post("/v1/deployments/admissions")
    async def admit_deployment(
        request: Request,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        raw = await request.body()
        # The deployment credential is verified BEFORE the body is parsed.
        authorize_mutation(tenant_id, request, raw)
        try:
            body = AdmitBody.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="admission_body_invalid") from exc
        try:
            admission = AdmissionRequest(
                tenant_id=tenant_id,
                artifact_sha256=body.artifact_sha256,
                deployment_environment=body.deployment_environment,
                environment_identity_digest=body.environment_identity_digest,
                rule_manifest_digest=body.rule_manifest_digest,
                deployment_id=body.deployment_id,
                requested_by=body.requested_by,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        decision = controller.admit(admission, _ACTOR)
        return decision.to_dict()

    @app.post("/v1/deployments/admissions/{admission_id}/outcome", status_code=201)
    async def report_outcome(
        admission_id: str,
        request: Request,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        raw = await request.body()
        authorize_mutation(tenant_id, request, raw)
        try:
            body = OutcomeBody.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="outcome_body_invalid") from exc
        try:
            record = controller.report_outcome(
                admission_id=admission_id,
                tenant_id=tenant_id,
                status=DeploymentOutcomeStatus(body.status),
                detail=body.detail,
                actor=_ACTOR,
                rollback_to=body.rollback_to,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="admission not found") from exc
        except OutcomeError as exc:
            raise HTTPException(status_code=409, detail=exc.code) from exc
        return {
            "admission_id": admission_id,
            "record_id": record["record_id"],
            "status": body.status,
            "chain_hash": record["chain_hash"],
            "payload": record["payload"],
        }

    @app.get("/v1/deployments/rollback-target")
    def rollback_target(
        environment: str = PRODUCTION,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        if environment != PRODUCTION:
            raise HTTPException(status_code=422, detail="only production rollback targets exist")
        target = controller.rollback_target(tenant_id)
        return {"environment": environment, "rollback_target": target}

    @app.get("/v1/releases/{artifact_sha256}/status")
    def release_status(
        artifact_sha256: str,
        environment_identity_digest: str | None = None,
        rule_manifest_digest: str | None = None,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            return controller.release_status(
                tenant_id,
                artifact_sha256,
                environment_identity_digest,
                rule_manifest_digest,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/v1/deployments/audit")
    def deployment_audit(
        artifact_sha256: str | None = None,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        chain_valid, broken_ordinal = controller.ledger.verify_chain()
        records = controller.ledger.trail(tenant_id, artifact_sha256)
        return {
            "chain_valid": chain_valid,
            "broken_ordinal": broken_ordinal,
            "records": [
                {
                    "record_id": row["record_id"],
                    "record_type": row["record_type"],
                    "admission_id": row["admission_id"],
                    "run_id": row["run_id"],
                    "artifact_sha256": row["artifact_sha256"],
                    "deployment_environment": row["deployment_environment"],
                    "allowed": None if row["allowed"] is None else bool(row["allowed"]),
                    "actor": row["actor"],
                    "created_at": row["created_at"],
                    "chain_hash": row["chain_hash"],
                }
                for row in records
            ],
        }

    @app.post("/v1/hooks/build")
    async def build_hook(
        request: Request,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        return await _ingest(request, response, x_tenant_id, BUILD_EVENT)

    @app.post("/v1/hooks/registry")
    async def registry_hook(
        request: Request,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        return await _ingest(request, response, x_tenant_id, REGISTRY_EVENT)

    async def _ingest(
        request: Request,
        response: Response,
        x_tenant_id: str | None,
        event_kind: str,
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        body = await request.body()
        # Read the run context lazily: signature is verified BEFORE the body is parsed.
        try:
            status_code, result = ingest_webhook(
                store=store,
                manifest=app.state.certforge_manifest,
                registry=webhook_secrets,
                tenant_header=tenant_id,
                event_kind=event_kind,
                body=body,
                signature_header=request.headers.get(SIGNATURE_HEADER),
                timestamp_header=request.headers.get(TIMESTAMP_HEADER),
            )
        except WebhookError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        response.status_code = status_code
        return result
