"""Run intake: submit request models, public-state projection, idempotent submission.

Backs `echo.certforge.submit` (POST /v1/certifications) and the schema-conforming projection
used by `echo.certforge.status`. Default-deny: a fresh run carries release_verdict NOT_READY
until a signed verdict is issued.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .canonical import sha256_json
from .evidence import EvidenceStore
from .models import ReleaseVerdict, RunState, declared_target_identity_digest
from .policy import RuleManifest

# Internal fine-grained RunState -> coarse public state (contracts/schemas/certification-run.v1.json).
_PUBLIC_STATE: dict[RunState, str] = {
    RunState.CREATED: "CREATED",
    RunState.QUEUED: "QUEUED",
    RunState.ACQUIRING_TARGET: "DISCOVERING",
    RunState.DISCOVERING: "DISCOVERING",
    RunState.PLANNING: "BUILDING",
    RunState.PROVISIONING: "BUILDING",
    RunState.BUILDING: "BUILDING",
    RunState.STARTING_APPLICATION: "EXECUTING_TESTS",
    RunState.VERIFYING_READINESS: "EXECUTING_TESTS",
    RunState.EXECUTING_TESTS: "EXECUTING_TESTS",
    RunState.COLLECTING_EVIDENCE: "VERIFYING_EVIDENCE",
    RunState.CLASSIFYING_FINDINGS: "ISSUING_VERDICT",
    RunState.CALCULATING_VERDICT: "ISSUING_VERDICT",
    RunState.FINALIZING_REPORT: "ISSUING_VERDICT",
    RunState.REGISTERING_RESULT: "ISSUING_VERDICT",
    RunState.COMPLETED: "COMPLETE",
    RunState.CANCELLED: "CANCELLED",
    RunState.INFRASTRUCTURE_FAILURE: "FAILED",
}


class SubmitTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_type: str = Field(
        pattern=r"^(local|git|archive|container|package|deployment|mcp|sdk|cli)$"
    )
    identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reference: str = Field(min_length=1, max_length=2048)
    artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_commit: str | None = Field(default=None, min_length=7, max_length=64)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    path: str | None = Field(default=None, min_length=1, max_length=2048)
    ref: str | None = Field(default=None, min_length=1, max_length=256)

    def worker_spec(self) -> dict[str, str]:
        if self.target_type == "local":
            return {"type": "local", "path": self.path or self.reference}
        if self.target_type == "git":
            if self.url is not None:
                spec = {"type": "git", "url": self.url}
                if self.ref is not None:
                    spec["ref"] = self.ref
                if self.artifact_sha256 is not None:
                    spec["artifact_sha256"] = self.artifact_sha256
                if self.source_commit is not None:
                    spec["source_commit"] = self.source_commit
                return spec
            reference = self.reference
            separator = reference.rfind("@")
            if separator > reference.rfind("/") and not (
                reference.startswith("git@") and reference.count("@") == 1
            ):
                spec = {
                    "type": "git",
                    "url": reference[:separator],
                    "ref": reference[separator + 1 :],
                }
            else:
                spec = {"type": "git", "url": reference}
            if self.artifact_sha256 is not None:
                spec["artifact_sha256"] = self.artifact_sha256
            if self.source_commit is not None:
                spec["source_commit"] = self.source_commit
            return spec
        if self.target_type == "package":
            if self.artifact_sha256 is None or self.source_commit is None:
                raise ValueError("package target requires artifact_sha256 and source_commit")
            return {
                "type": "package",
                "path": self.path or self.reference,
                "artifact_sha256": self.artifact_sha256,
                "source_commit": self.source_commit,
            }
        raise ValueError("target type is not dispatchable")


class SubmitEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runner_image_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class SubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(min_length=1, max_length=128)
    project_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    )
    target: SubmitTarget
    environment: SubmitEnvironment
    policy_version: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128)
    journey: list[str] | None = Field(default=None, max_length=32)

    def request_digest(self) -> str:
        """Semantic identity of the request (excludes the idempotency key itself)."""
        return sha256_json(
            {
                "tenant_id": self.tenant_id,
                **({"project_id": self.project_id} if self.project_id is not None else {}),
                "target": self.target.model_dump(exclude_none=True),
                "environment": self.environment.model_dump(),
                "policy_version": self.policy_version,
                **({"journey": self.journey} if self.journey is not None else {}),
            }
        )

    def run_id(self, active_rule_manifest_digest: str) -> str:
        """Return an identity bound to the request, idempotency key, and active rules."""
        return "cert_" + sha256_json(
            {
                "d": self.request_digest(),
                "k": self.idempotency_key,
                "m": active_rule_manifest_digest,
            }
        )[:40]


def to_public_state(internal: str) -> str:
    return _PUBLIC_STATE[RunState(internal)]


def project_run(store: EvidenceStore, row: dict[str, Any]) -> dict[str, Any]:
    """Project an internal run row into a certification-run.v1.json-conforming object."""
    run_id = row["run_id"]
    tenant_id = row["tenant_id"]
    release_verdict = ReleaseVerdict.NOT_READY.value
    evidence_merkle_root: str | None = None
    verdict_row = store.latest_signed_verdict(run_id, tenant_id)
    if verdict_row is not None:
        payload = json.loads(verdict_row["payload_json"])
        release_verdict = payload.get("release_verdict", release_verdict)
        evidence_merkle_root = payload.get("evidence_merkle_root")
    projected = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "state": to_public_state(row["state"]),
        "run_outcome": row["run_outcome"],
        "release_verdict": release_verdict,
        "target_identity_digest": row["target_identity_digest"],
        "environment_identity_digest": row["environment_identity_digest"],
        "policy_version": row["policy_version"] or row["rule_manifest_id"],
        "evidence_merkle_root": evidence_merkle_root,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if row.get("source_run_id") is not None:
        projected["source_run_id"] = row["source_run_id"]
        projected["rerun_sequence"] = int(row["rerun_sequence"])
    return projected


class SubmitError(Exception):
    """Raised on a fail-closed intake rejection. Carries HTTP status + machine code."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


def submit(
    store: EvidenceStore,
    manifest: RuleManifest,
    request: SubmitRequest,
    tenant_header: str,
    *,
    source_run_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Idempotent, tenant-fail-closed run submission.

    Returns (201, run) for a new run; (200, run) for an idempotent replay of the same request;
    raises SubmitError(409, "idempotency_conflict") when a key is reused for a different request,
    SubmitError(403, "tenant_mismatch") when the header and body tenants disagree,
    SubmitError(422, "policy_unknown") when the requested policy is not the active manifest.
    """
    if request.tenant_id != tenant_header:
        raise SubmitError(403, "tenant_mismatch")
    if request.policy_version != manifest.manifest_id:
        raise SubmitError(422, "policy_unknown")
    if request.target.artifact_sha256 is not None:
        expected = declared_target_identity_digest(
            request.tenant_id,
            request.target.target_type,
            request.target.artifact_sha256,
            request.target.source_commit,
            request.target.reference,
        )
        if expected != request.target.identity_digest:
            raise SubmitError(422, "target_commitment_mismatch")

    request_digest = sha256_json(
        {
            "request": request.request_digest(),
            "active_rule_manifest_digest": manifest.digest,
        }
    )
    scoped_key = f"{request.idempotency_key}@{manifest.digest[:16]}"
    existing = store.find_idempotent(request.tenant_id, scoped_key)
    if existing is not None:
        if existing["request_digest"] != request_digest:
            raise SubmitError(409, "idempotency_conflict")
        row = store.get_run(existing["run_id"], request.tenant_id)
        return 200, project_run(store, row)

    run_id = request.run_id(manifest.digest)
    environment_json = request.environment.model_dump(exclude_none=True)
    try:
        store.register_declared_run(
            run_id=run_id,
            tenant_id=request.tenant_id,
            target_type=request.target.target_type,
            target_identity_digest=request.target.identity_digest,
            target_reference=request.target.reference,
            project_id=request.project_id,
            environment_identity_digest=request.environment.identity_digest,
            environment_json=environment_json,
            policy_version=request.policy_version,
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.digest,
            declared_artifact_sha256=request.target.artifact_sha256,
            declared_source_commit=request.target.source_commit,
            source_run_id=source_run_id,
        )
    except sqlite3.IntegrityError:
        # A concurrent or recovered submit already created this deterministic run. Finish any
        # interrupted CREATED -> QUEUED/idempotency steps before returning the replay.
        row = store.get_run(run_id, request.tenant_id)
        if row["state"] == RunState.CREATED.value:
            try:
                store.transition_state(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    next_state=RunState.QUEUED,
                    actor="certforge.intake-recovery",
                    reason="recover_interrupted_submission",
                    workflow_version="p7.subscriber",
                )
            except ValueError:
                if (
                    store.get_run(run_id, request.tenant_id)["state"]
                    != RunState.QUEUED.value
                ):
                    raise
        existing = store.find_idempotent(
            request.tenant_id, scoped_key
        )
        if existing is None:
            try:
                store.bind_idempotent(
                    request.tenant_id,
                    scoped_key,
                    request_digest,
                    run_id,
                )
            except sqlite3.IntegrityError:
                existing = store.find_idempotent(
                    request.tenant_id, scoped_key
                )
        if existing is not None and (
            existing["request_digest"] != request_digest
            or existing["run_id"] != run_id
        ):
            raise SubmitError(409, "idempotency_conflict")
        return 200, project_run(store, store.get_run(run_id, request.tenant_id))
    store.transition_state(
        run_id=run_id,
        tenant_id=request.tenant_id,
        next_state=RunState.QUEUED,
        actor="certforge.intake",
        reason="submitted",
        workflow_version="t4.p1",
    )
    store.bind_idempotent(request.tenant_id, scoped_key, request_digest, run_id)
    row = store.get_run(run_id, request.tenant_id)
    return 201, project_run(store, row)
