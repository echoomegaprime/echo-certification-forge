"""Tenant-scoped read and deploy-gate API surface."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

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
from .platform import ApiPrincipal, CertificationPlatform, PlatformError
from .policy import RuleManifest
from .signing import TrustedPublicKeyRegistry


_MAX_ADMIN_ARTIFACT_BYTES = 5 * 1024 * 1024


@dataclass(slots=True)
class ServiceContext:
    store: EvidenceStore
    manifest: RuleManifest
    trusted_keys: TrustedPublicKeyRegistry
    platform: CertificationPlatform | None = None
    billing_webhook_secret: str = ""

    def __post_init__(self) -> None:
        if self.platform is None:
            self.platform = CertificationPlatform(self.store.db_path)


class DeployGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(min_length=1, max_length=128)
    target_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_merkle_root: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signing_key_id: str | None = Field(default=None, min_length=1, max_length=128)


class SubscriberSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: SubmitTarget
    environment: SubmitEnvironment
    policy_version: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128)


class UsageMeterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    unit: Literal["worker_minutes", "model_tokens", "evidence_storage_bytes"]
    amount: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=128)


class ReleaseEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
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
    hold_id: str = Field(min_length=1, max_length=128)
    run_id: str | None = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2048)


class LifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: VerdictLifecycleEvent
    reason: str = Field(min_length=1, max_length=2048)
    replacement_run_id: str | None = Field(default=None, min_length=1, max_length=128)


def create_app(context: ServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge", version="0.7.0")
    assert context.platform is not None

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
                request.model_dump(mode="json"),
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
