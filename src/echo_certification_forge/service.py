"""Tenant-scoped read and deploy-gate API surface."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .canonical import sha256_json, to_utc_iso, utc_now
from .deploy_gate import DeployGate
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
from .models import (
    RunState,
    SignedVerdictEnvelope,
    VerdictLifecycleEvent,
)
from .operational_telemetry import (
    OperationalTelemetryError,
    OperationalTelemetryRegistry,
    SignedOperationalReport,
)
from .platform import ApiPrincipal, CertificationPlatform, PlatformError
from .policy import RuleManifest
from .runner import TrustedTransportRegistry
from .signing import TrustedPublicKeyRegistry


_MAX_ADMIN_ARTIFACT_BYTES = 5 * 1024 * 1024
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
    platform: CertificationPlatform | None = None
    billing_webhook_secret: str = ""
    transport_registry: TrustedTransportRegistry | None = None
    operational_registry: OperationalTelemetryRegistry | None = None

    def __post_init__(self) -> None:
        if self.platform is None:
            self.platform = CertificationPlatform(self.store.db_path)
        if self.transport_registry is None:
            self.transport_registry = TrustedTransportRegistry.empty()
        if self.operational_registry is None:
            self.operational_registry = OperationalTelemetryRegistry(self.store.db_path)
        self.operational_registry.hydrate_transport_registry(self.transport_registry)


class DeployGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=128)
    target_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_merkle_root: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signing_key_id: str | None = Field(default=None, min_length=1, max_length=128)


class SubscriberSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    target: SubmitTarget
    environment: SubmitEnvironment
    policy_version: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128)


class RerunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=8, max_length=128)


class UsageMeterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    unit: Literal["worker_minutes", "model_tokens", "evidence_storage_bytes"]
    amount: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=128)


class ReleaseEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    source: Literal["git", "build", "registry", "staging"]
    event_id: str = Field(min_length=1, max_length=128)
    target_reference: str = Field(min_length=1, max_length=2048)
    target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    priority: Literal["P0", "P1", "P2", "P3", "P4"]
    payload: dict[str, Any]


class ProductionDeploymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    attempt_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    deployment_environment: Literal["production"]
    target_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_merkle_root: str = Field(pattern=r"^[0-9a-f]{64}$")
    signing_key_id: str = Field(min_length=1, max_length=128)


class LegalHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    hold_id: str = Field(min_length=1, max_length=128)
    run_id: str | None = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2048)


class LifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    event_type: VerdictLifecycleEvent
    reason: str = Field(min_length=1, max_length=2048)
    replacement_run_id: str | None = Field(default=None, min_length=1, max_length=128)


class OperationalQuarantineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    subject_type: Literal["runner", "adapter"]
    subject_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=8, max_length=2048)


class OperationalQuarantineReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    reason: str = Field(min_length=8, max_length=2048)


class OperationalKeyRotationStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    old_key_id: str = Field(min_length=1, max_length=128)
    new_public_key_pem: str = Field(min_length=80, max_length=8192)
    overlap_seconds: int = Field(default=3600, ge=60, le=86_400)
    reason: str = Field(min_length=8, max_length=2048)


class RunnerEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    runner_id: str = Field(min_length=1, max_length=128)


class OperationalReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str | None = Field(default=None, min_length=1, max_length=64)
    reason: str = Field(min_length=8, max_length=2048)


def create_app(context: ServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge", version="0.7.0")
    assert context.platform is not None
    assert context.transport_registry is not None
    assert context.operational_registry is not None

    def tenant(value: str | None) -> str:
        if value is None or not value.strip():
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        return value

    def platform_error(exc: PlatformError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.code)

    def principal(value: str | None) -> ApiPrincipal:
        try:
            return context.platform.authenticate(value or "")
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        # Shape matches the echo.certforge.health output_schema
        # (contracts/certforge-capabilities.v1.json): status, version, custody, anchor, signing.
        return {
            "status": "ok",
            "version": "0.7.0",
            "custody": "append_only_merkle_verified",
            "anchor": "independent_provider_required",
            "signing": "isolated_out_of_process",
            "control_plane_executes_customer_code": False,
            "private_signing_key_loaded": False,
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
            "deployment_enforcement": "P6_FAIL_CLOSED",
            "subscriber_governance": "P7_FAIL_CLOSED",
        }

    @app.post("/v1/certifications", status_code=201)
    def submit_certification(
        request: SubmitRequest,
        response: Response,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            status_code, body = submit(context.store, context.manifest, request, tenant_id)
        except SubmitError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        response.status_code = status_code
        return body

    @app.get("/v1/certifications")
    def list_runs(x_tenant_id: str | None = Header(default=None)) -> list[dict[str, object]]:
        tenant_id = tenant(x_tenant_id)
        return [project_run(context.store, row) for row in context.store.list_runs(tenant_id)]

    @app.get("/v1/certifications/{run_id}")
    def get_run(run_id: str, x_tenant_id: str | None = Header(default=None)) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            row = context.store.get_run(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return project_run(context.store, row)

    @app.post("/v1/certifications/{run_id}/cancel")
    def cancel_certification(
        run_id: str, x_tenant_id: str | None = Header(default=None)
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
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
        run_id: str, x_tenant_id: str | None = Header(default=None)
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            findings = context.store.list_findings(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run_id": run_id, "findings": findings}

    @app.get("/v1/certifications/{run_id}/evidence")
    def get_evidence_index(
        run_id: str, x_tenant_id: str | None = Header(default=None)
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            artifacts = context.store.list_evidence(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run_id": run_id, "artifacts": artifacts}  # redacted index, never raw content

    @app.get("/v1/subscriber/certifications/{run_id}/evidence/{artifact_id}")
    def get_evidence_artifact(
        run_id: str,
        artifact_id: str,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, object]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            subscription = context.platform.subscription(actor.organization_id)
            if "full_evidence" not in subscription["limits"]["entitlements"]:
                raise PlatformError("full_evidence_entitlement_required", 403)
            descriptor, content = context.store.read_evidence_artifact(
                run_id,
                actor.tenant_id,
                artifact_id,
                max_bytes=_MAX_ADMIN_ARTIFACT_BYTES,
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "evidence.download",
                "evidence_artifact",
                artifact_id,
                {
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
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/certifications/{run_id}/verify")
    def verify_run(
        run_id: str, x_tenant_id: str | None = Header(default=None)
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
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
        run_id: str, x_tenant_id: str | None = Header(default=None)
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
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
    def verify_evidence(run_id: str, x_tenant_id: str | None = Header(default=None)) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
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
    def verify_verdict(run_id: str, x_tenant_id: str | None = Header(default=None)) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
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
    ) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            result = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=tenant_id,
                run_id=request.run_id,
                target_identity_digest=request.target_identity_digest,
                environment_identity_digest=request.environment_identity_digest,
                rule_manifest_digest=request.rule_manifest_digest,
                evidence_merkle_root=request.evidence_merkle_root,
                signing_key_id=request.signing_key_id,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return result.to_dict()

    @app.post("/v1/subscriber/certifications", status_code=201)
    def subscriber_submit(
        request: SubscriberSubmitRequest,
        response: Response,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, object]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator")
            context.platform.reserve_run(actor, request.idempotency_key)
            status_code, body = submit(
                context.store,
                context.manifest,
                SubmitRequest(
                    tenant_id=actor.tenant_id,
                    target=request.target,
                    environment=request.environment,
                    policy_version=request.policy_version,
                    idempotency_key=request.idempotency_key,
                ),
                actor.tenant_id,
            )
        except PlatformError as exc:
            raise platform_error(exc) from exc
        except SubmitError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        response.status_code = status_code
        context.platform.audit(
            actor.organization_id,
            actor.project_id,
            f"api_key:{actor.key_id}",
            "certification.submit",
            "certification",
            str(body["run_id"]),
            {"status_code": status_code},
        )
        return body

    @app.get("/v1/subscriber/certifications")
    def subscriber_runs(
        x_certforge_api_key: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        actor = principal(x_certforge_api_key)
        return [
            project_run(context.store, row)
            for row in context.store.list_runs(actor.tenant_id)
        ]

    @app.post("/v1/subscriber/certifications/{run_id}/rerun", status_code=201)
    def subscriber_rerun(
        run_id: str,
        request: RerunRequest,
        response: Response,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, object]:
        """Create a new queued run with immutable lineage to one terminal source run."""
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator")
            source = context.store.get_run(run_id, actor.tenant_id)
            if source["state"] not in _TERMINAL_STATES:
                raise PlatformError("source_run_not_terminal", 409)
            if (
                source.get("policy_version") != context.manifest.manifest_id
                or source["rule_manifest_digest"] != context.manifest.digest
            ):
                raise PlatformError("source_policy_not_active", 409)
            target = json.loads(source["target_identity_json"])
            environment = json.loads(source["environment_identity_json"])
            target_type = str(target.get("target_type", ""))
            target_reference = str(source.get("target_reference") or target.get("reference") or "")
            if not target_type or not target_reference:
                raise PlatformError("source_run_not_rerunnable", 409)
            internal_key = "rerun-" + sha256_json(
                {
                    "source_run_id": run_id,
                    "idempotency_key": request.idempotency_key,
                }
            )
            context.platform.reserve_run(actor, internal_key)
            status_code, body = submit(
                context.store,
                context.manifest,
                SubmitRequest(
                    tenant_id=actor.tenant_id,
                    target=SubmitTarget(
                        target_type=target_type,
                        identity_digest=source["target_identity_digest"],
                        reference=target_reference,
                    ),
                    environment=SubmitEnvironment(
                        identity_digest=source["environment_identity_digest"],
                        runner_image_digest=environment.get("runner_image_digest"),
                    ),
                    policy_version=context.manifest.manifest_id,
                    idempotency_key=internal_key,
                ),
                actor.tenant_id,
                source_run_id=run_id,
            )
            response.status_code = status_code
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "certification.rerun",
                "certification",
                str(body["run_id"]),
                {"source_run_id": run_id, "status_code": status_code},
            )
            return body
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc
        except SubmitError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc

    @app.post("/v1/subscriber/usage")
    def meter_usage(
        request: UsageMeterRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, int]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator")
            return context.platform.meter(
                actor,
                unit=request.unit,
                amount=request.amount,
                idempotency_key=request.idempotency_key,
            )
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.get("/v1/subscriber/usage")
    def usage_summary(
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        return context.platform.usage_summary(actor)

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
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Project bounded operational truth without implying worker health we cannot prove."""
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator", "viewer")
            usage = context.platform.usage_summary(actor)
            raw_state_counts = context.store.count_runs_by_state(actor.tenant_id)
            recent_run_rows = context.store.list_runs(
                actor.tenant_id, limit=_TELEMETRY_RUN_LIMIT
            )
            authenticated = context.operational_registry.snapshot(actor.tenant_id)
        except PlatformError as exc:
            raise platform_error(exc) from exc

        state_counts = {state.value: 0 for state in RunState}
        for state, count in raw_state_counts.items():
            state_counts[state] = count
        active_runs = sum(
            count for state, count in state_counts.items() if state not in _TERMINAL_STATES
        )
        concurrent_limit = int(usage["limits"]["concurrent_runs"])
        budgets = {}
        for unit in ("worker_minutes", "model_tokens", "evidence_storage_bytes"):
            limit = int(usage["limits"][unit])
            used = int(usage["used"].get(unit, 0))
            budgets[unit] = {"used": used, "limit": limit, "remaining": max(limit - used, 0)}

        recent_runs = []
        for row in recent_run_rows:
            events = context.store.list_state_events(
                str(row["run_id"]), actor.tenant_id, limit=_TELEMETRY_EVENT_LIMIT
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
                "plan_id": usage["plan_id"],
                "billing_status": usage["billing_status"],
                "period_start": usage["period_start"],
                "period_end": usage["period_end"],
                "certification_runs_limit": int(usage["limits"]["certification_runs"]),
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
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.quarantine(
                actor.tenant_id,
                subject_type=request.subject_type,
                subject_id=request.subject_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.quarantine",
                request.subject_type,
                request.subject_id,
                {
                    "reason": request.reason,
                    "idempotent": bool(result["idempotent"]),
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post(
        "/v1/subscriber/operational-quarantines/{subject_type}/{subject_id}/release"
    )
    def release_operational_quarantine(
        subject_type: Literal["runner", "adapter"],
        subject_id: str,
        request: OperationalQuarantineReleaseRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.release_quarantine(
                actor.tenant_id,
                subject_type=subject_type,
                subject_id=subject_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.quarantine.release",
                subject_type,
                subject_id,
                {"reason": request.reason},
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.get("/v1/subscriber/operational-key-rotations")
    def operational_key_rotations(
        x_certforge_api_key: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            context.operational_registry.reconcile_key_rotations(
                context.transport_registry, now=utc_now()
            )
            return context.operational_registry.key_rotation_status(actor.tenant_id)
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/operational-key-rotations")
    def begin_operational_key_rotation(
        request: OperationalKeyRotationStartRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.begin_key_rotation(
                actor.tenant_id,
                old_key_id=request.old_key_id,
                new_public_key_pem=request.new_public_key_pem,
                overlap_seconds=request.overlap_seconds,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
                trusted=context.transport_registry,
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.key_rotation.begin",
                "operational_key_rotation",
                str(result["rotation_id"]),
                {
                    "old_key_id": result["old_key_id"],
                    "new_key_id": result["new_key_id"],
                    "overlap_expires_at": result["overlap_expires_at"],
                    "reason": request.reason,
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/operational-key-rotations/{rotation_id}/finalize")
    def finalize_operational_key_rotation(
        rotation_id: str,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.finalize_key_rotation(
                actor.tenant_id,
                rotation_id=rotation_id,
                actor=f"api_key:{actor.key_id}",
                trusted=context.transport_registry,
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.key_rotation.finalize",
                "operational_key_rotation",
                rotation_id,
                {
                    "old_key_id": result["old_key_id"],
                    "new_key_id": result["new_key_id"],
                    "proof_received": result["proof_received"],
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/runner-enrollments")
    def enroll_operational_runner(
        request: RunnerEnrollmentRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.enroll_runner(
                actor.tenant_id,
                runner_id=request.runner_id,
                actor=f"api_key:{actor.key_id}",
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.runner_enrollment.activate",
                "runner",
                request.runner_id,
                {
                    "runner_key_id": result["runner_key_id"],
                    "worker_image_sha256": result["worker_image_sha256"],
                    "enrollment_enforced": True,
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/runner-enrollments/{runner_id}/revoke")
    def revoke_operational_runner_enrollment(
        runner_id: str,
        request: OperationalReasonRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.revoke_runner_enrollment(
                actor.tenant_id,
                runner_id=runner_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.runner_enrollment.revoke",
                "runner",
                runner_id,
                {"reason": request.reason},
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/adapter-maturity/remediate")
    def remediate_operational_adapter_maturity(
        request: OperationalReasonRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            result = context.operational_registry.remediate_adapter_maturity(
                actor.tenant_id,
                reason=request.reason,
                actor=f"api_key:{actor.key_id}",
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "operations.adapter_maturity.remediate",
                "adapter_inventory",
                actor.tenant_id,
                {
                    "remediated": result["remediated"],
                    "quarantined_adapter_ids": result["quarantined_adapter_ids"],
                    "maturity_status": result["maturity_status"],
                    "reason": request.reason,
                },
            )
            return result
        except OperationalTelemetryError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.code) from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.get("/v1/subscriber/audit")
    def subscriber_audit(
        limit: int = 100,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        actor = principal(x_certforge_api_key)
        try:
            return context.platform.audit_log(actor, limit)
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/integrations/release-events")
    def release_event(
        request: ReleaseEventRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator")
            return context.platform.ingest_release_event(
                actor,
                source=request.source,
                event_id=request.event_id,
                target_reference=request.target_reference,
                target_digest=request.target_digest,
                environment_digest=request.environment_digest,
                policy_digest=request.policy_digest,
                priority=request.priority,
                payload=request.payload,
            )
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/deployments/authorize")
    def authorize_production_deployment(
        request: ProductionDeploymentRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin", "operator")
            subscription = context.platform.subscription(actor.organization_id)
            if "release_gates" not in subscription["limits"]["entitlements"]:
                raise PlatformError("release_gates_not_entitled", 403)
            run = context.store.get_run(request.run_id, actor.tenant_id)
            target = json.loads(run["target_identity_json"])
            reasons: set[str] = set()
            if target.get("artifact_sha256") != request.artifact_sha256:
                reasons.add("deployment_artifact_mismatch")
            result = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=actor.tenant_id,
                run_id=request.run_id,
                target_identity_digest=request.target_identity_digest,
                environment_identity_digest=request.environment_identity_digest,
                rule_manifest_digest=request.rule_manifest_digest,
                evidence_merkle_root=request.evidence_merkle_root,
                signing_key_id=request.signing_key_id,
            )
            reasons.update(result.reasons if not result.allowed else ())
            allowed = result.allowed and not reasons
            ordered_reasons = (
                ("exact_certification_valid",)
                if allowed
                else tuple(sorted(reasons))
            )
            context.platform.record_deployment(
                actor,
                attempt_id=request.attempt_id,
                run_id=request.run_id,
                deployment_environment=request.deployment_environment,
                target_identity_digest=request.target_identity_digest,
                artifact_sha256=request.artifact_sha256,
                environment_identity_digest=request.environment_identity_digest,
                rule_manifest_digest=request.rule_manifest_digest,
                evidence_merkle_root=request.evidence_merkle_root,
                signing_key_id=request.signing_key_id,
                allowed=allowed,
                reasons=ordered_reasons,
            )
            return {
                "allowed": allowed,
                "release_verdict": (
                    "PRODUCTION_READY" if allowed else "NOT_READY"
                ),
                "run_id": request.run_id,
                "attempt_id": request.attempt_id,
                "reasons": list(ordered_reasons),
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/legal-holds")
    def create_legal_hold(
        request: LegalHoldRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            if request.run_id is not None:
                context.store.get_run(request.run_id, actor.tenant_id)
            return context.platform.create_legal_hold(
                actor,
                hold_id=request.hold_id,
                run_id=request.run_id,
                reason=request.reason,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.delete("/v1/subscriber/legal-holds/{hold_id}")
    def release_legal_hold(
        hold_id: str,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            return context.platform.release_legal_hold(actor, hold_id)
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/certifications/{run_id}/lifecycle")
    def lifecycle(
        run_id: str,
        request: LifecycleRequest,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        actor = principal(x_certforge_api_key)
        try:
            context.platform.require_role(actor, "owner", "admin")
            if request.event_type is VerdictLifecycleEvent.SUPERSEDED:
                if request.replacement_run_id is None:
                    raise PlatformError("replacement_run_id_required", 422)
                context.store.get_run(request.replacement_run_id, actor.tenant_id)
            context.store.append_lifecycle_event(
                run_id,
                actor.tenant_id,
                request.event_type,
                actor=f"api_key:{actor.key_id}",
                reason=request.reason,
                replacement_run_id=request.replacement_run_id,
            )
            context.platform.audit(
                actor.organization_id,
                actor.project_id,
                f"api_key:{actor.key_id}",
                "verdict.lifecycle",
                "certification",
                run_id,
                request.model_dump(mode="json", exclude={"command"}),
            )
            return {
                "run_id": run_id,
                "event_type": request.event_type.value,
                "replacement_run_id": request.replacement_run_id,
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.post("/v1/subscriber/certifications/{run_id}/publish")
    def publish_verification(
        run_id: str,
        x_certforge_api_key: str | None = Header(default=None),
    ) -> dict[str, str]:
        actor = principal(x_certforge_api_key)
        try:
            row = context.store.latest_signed_verdict(run_id, actor.tenant_id)
            if row is None:
                raise PlatformError("signed_verdict_missing", 409)
            payload = json.loads(row["payload_json"])
            gate = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=actor.tenant_id,
                run_id=run_id,
                target_identity_digest=payload["target_identity_digest"],
                environment_identity_digest=payload["environment_identity_digest"],
                rule_manifest_digest=payload["rule_manifest_digest"],
                evidence_merkle_root=payload["evidence_merkle_root"],
                signing_key_id=payload["signing_key_id"],
            )
            if not gate.allowed:
                raise PlatformError("certification_not_current", 409)
            verification_id = context.platform.publish_verification(actor, run_id)
            return {
                "verification_id": verification_id,
                "verification_url": f"/v1/public/verifications/{verification_id}",
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        except PlatformError as exc:
            raise platform_error(exc) from exc

    @app.get("/v1/public/verifications/{verification_id}")
    def public_verification(verification_id: str) -> dict[str, Any]:
        try:
            published = context.platform.public_verification(verification_id)
            row = context.store.latest_signed_verdict(
                published["run_id"], published["tenant_id"]
            )
            if row is None:
                raise PlatformError("verification_not_found", 404)
            payload = json.loads(row["payload_json"])
            gate = DeployGate(context.store, context.trusted_keys).evaluate(
                tenant_id=published["tenant_id"],
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
        except (KeyError, PlatformError) as exc:
            raise HTTPException(status_code=404, detail="verification_not_found") from exc

    @app.post("/v1/billing/webhook")
    async def billing_webhook(
        request: Request,
        x_billing_signature: str | None = Header(default=None),
        x_billing_timestamp: int | None = Header(default=None),
    ) -> dict[str, Any]:
        if (
            not context.billing_webhook_secret
            or x_billing_signature is None
            or x_billing_timestamp is None
        ):
            raise HTTPException(status_code=401, detail="billing_signature_required")
        raw_body = await request.body()
        try:
            return context.platform.apply_billing_event(
                raw_body=raw_body,
                signature=x_billing_signature,
                timestamp=x_billing_timestamp,
                secret=context.billing_webhook_secret,
            )
        except PlatformError as exc:
            raise platform_error(exc) from exc

    return app
