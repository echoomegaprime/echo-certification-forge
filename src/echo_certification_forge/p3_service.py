"""Typed HTTP surfaces for evidence custody and independent anchoring."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .anchor import (
    AnchorConflict,
    AnchorStatement,
    AnchorUnavailable,
    IndependentFileAnchorProvider,
)
from .custody import (
    CustodyAuthenticationError,
    CustodyChunk,
    CustodyError,
    CustodyStore,
    EvidenceConflict,
    EvidenceIncomplete,
    EvidenceManifest,
)
from .runner import AuthenticationFailure, LeaseFailure, TransportRequest


@dataclass(slots=True)
class CustodyServiceContext:
    custody: CustodyStore


@dataclass(slots=True)
class AnchorServiceContext:
    provider: IndependentFileAnchorProvider


class BeginUploadBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: TransportRequest
    manifest: EvidenceManifest


class AppendChunkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: TransportRequest
    chunk: CustodyChunk


class FinalizeUploadBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: TransportRequest
    artifact_id: str = Field(min_length=1, max_length=128)


class CreateAnchorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: AnchorStatement
    idempotency_key: str = Field(min_length=1, max_length=128)


def _custody_error(exc: Exception) -> HTTPException:
    if isinstance(exc, (CustodyAuthenticationError, AuthenticationFailure)):
        return HTTPException(status_code=401, detail=str(exc))
    if isinstance(exc, LeaseFailure):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail="not found")
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, EvidenceIncomplete):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (EvidenceConflict, CustodyError)):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=503, detail="custody unavailable")


def create_custody_app(context: CustodyServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge Evidence Custody", version="0.3.0")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        try:
            with context.custody._connection() as connection:
                schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            root_ready = context.custody.evidence_root.is_dir()
        except (OSError, Exception) as exc:  # fail closed; no secret material returned
            return {
                "status": "unavailable",
                "schema_version": None,
                "evidence_root_ready": False,
                "private_verdict_signing_key_loaded": False,
                "error_type": type(exc).__name__,
            }
        return {
            "status": "ok" if root_ready else "unavailable",
            "version": "0.3.0",
            "schema_version": schema_version,
            "evidence_root_ready": root_ready,
            "append_only": True,
            "private_verdict_signing_key_loaded": False,
            "executes_customer_code": False,
        }

    @app.post("/v1/uploads/begin")
    def begin_upload(body: BeginUploadBody) -> dict[str, Any]:
        try:
            return context.custody.begin_upload(body.request, body.manifest)
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    @app.post("/v1/uploads/chunks")
    def append_chunk(body: AppendChunkBody) -> dict[str, Any]:
        try:
            return context.custody.append_chunk(body.request, body.chunk)
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    @app.post("/v1/uploads/finalize")
    def finalize_upload(body: FinalizeUploadBody) -> dict[str, Any]:
        try:
            return context.custody.finalize_upload(body.request, body.artifact_id)
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    @app.get("/v1/uploads/{run_id}/{artifact_id}")
    def upload_status(
        run_id: str,
        artifact_id: str,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if not x_tenant_id:
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        try:
            return context.custody.upload_status(run_id, x_tenant_id, artifact_id)
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    @app.get("/v1/runs/{run_id}/verify")
    def verify_run(
        run_id: str,
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if not x_tenant_id:
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        try:
            return context.custody.verify_run(run_id, x_tenant_id)
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    @app.get("/v1/evidence/{run_id}/{artifact_id}")
    def evidence_metadata(
        run_id: str,
        artifact_id: str,
        x_tenant_id: str | None = Header(default=None),
        x_restricted_evidence_authorized: str | None = Header(default=None),
    ) -> dict[str, Any]:
        if not x_tenant_id:
            raise HTTPException(status_code=401, detail="X-Tenant-ID is required")
        try:
            descriptor, _content = context.custody.get_artifact(
                run_id,
                x_tenant_id,
                artifact_id,
                allow_restricted=x_restricted_evidence_authorized == "true",
            )
            return descriptor
        except Exception as exc:  # noqa: BLE001
            raise _custody_error(exc) from exc

    return app


def create_anchor_app(context: AnchorServiceContext) -> FastAPI:
    app = FastAPI(title="Echo Certification Forge External Anchor", version="0.3.0")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return context.provider.health()

    @app.post("/v1/anchors")
    def create_anchor(body: CreateAnchorBody) -> dict[str, Any]:
        try:
            receipt = context.provider.create_anchor(
                body.statement, idempotency_key=body.idempotency_key
            )
            return receipt.model_dump(mode="json")
        except AnchorUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except AnchorConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/anchors/{receipt_id}/verify")
    def verify_anchor(receipt_id: str) -> dict[str, Any]:
        try:
            receipt = context.provider.get_receipt(receipt_id)
            valid, reason = context.provider.verify_receipt(receipt)
            return {"valid": valid, "reason": reason, "receipt_id": receipt_id}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="anchor receipt not found") from exc

    @app.get("/v1/anchors/{receipt_id}/bundle")
    def anchor_bundle(receipt_id: str) -> dict[str, Any]:
        try:
            return context.provider.verification_bundle(receipt_id).model_dump(mode="json")
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="anchor receipt not found") from exc

    return app
