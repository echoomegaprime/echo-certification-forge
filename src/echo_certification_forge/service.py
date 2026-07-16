"""Tenant-scoped read and deploy-gate API surface."""
from __future__ import annotations

import json
from dataclasses import dataclass

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .deploy_gate import DeployGate
from .evidence import EvidenceStore
from .models import SignedVerdictEnvelope
from .policy import RuleManifest
from .signing import TrustedPublicKeyRegistry


@dataclass(slots=True)
class ServiceContext:
    store: EvidenceStore
    manifest: RuleManifest
    trusted_keys: TrustedPublicKeyRegistry


class DeployGateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(min_length=1, max_length=128)
    target_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def create_app(context: ServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge", version="0.2.0")

    def tenant(value: str | None) -> str:
        if value is None or not value.strip():
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        return value

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        return {
            "status": "ok",
            "version": "0.1.0",
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
            "external_evidence_anchor": "PENDING",
            "runner_isolation": "P2_FOUNDATION_VERIFIED",
        }

    @app.get("/v1/certifications")
    def list_runs(x_tenant_id: str | None = Header(default=None)) -> list[dict[str, object]]:
        tenant_id = tenant(x_tenant_id)
        return context.store.list_runs(tenant_id)

    @app.get("/v1/certifications/{run_id}")
    def get_run(run_id: str, x_tenant_id: str | None = Header(default=None)) -> dict[str, object]:
        tenant_id = tenant(x_tenant_id)
        try:
            return context.store.get_run(run_id, tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc

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
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return result.to_dict()

    return app
