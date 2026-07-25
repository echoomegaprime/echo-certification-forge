"""P6 platform integration — signed build/registry webhooks mapped to certification targets.

Receives source-control/build/container-registry events, verifies an HMAC-SHA256 signature
per tenant (fail-closed: unknown tenant, missing/invalid signature, or stale timestamp is
rejected before the body is trusted), maps the event to a certification target, and submits
it through the existing idempotent intake so duplicate events for the same artifact
deduplicate to ONE certification run (SPEC section 37: receive events, verify webhook
signatures, deduplicate runs).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .canonical import parse_utc_iso, sha256_json, utc_now
from .evidence import EvidenceStore
from .models import declared_target_identity_digest
from .intake import (
    SubmitEnvironment,
    SubmitError,
    SubmitRequest,
    SubmitTarget,
    submit,
)
from .policy import RuleManifest

SIGNATURE_HEADER = "X-Certforge-Signature"
TIMESTAMP_HEADER = "X-Certforge-Timestamp"
MAX_CLOCK_SKEW_SECONDS = 300

BUILD_EVENT = "build.artifact.published"
REGISTRY_EVENT = "registry.image.pushed"


class WebhookError(Exception):
    """Fail-closed webhook rejection with an HTTP status and machine code."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


@dataclass(frozen=True, slots=True)
class WebhookSecretRegistry:
    """Per-tenant webhook signing secrets. No secret registered => the tenant cannot
    deliver webhooks (fail-closed)."""

    secrets: dict[str, str]

    @classmethod
    def from_file(cls, path: Path) -> "WebhookSecretRegistry":
        if not path.exists():
            return cls(secrets={})
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and v for k, v in raw.items()
        ):
            raise ValueError("webhook secret registry must map tenant_id -> non-empty secret")
        return cls(secrets=dict(raw))

    def secret_for(self, tenant_id: str) -> str | None:
        return self.secrets.get(tenant_id)


def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    """Produce the signature a sender must set: HMAC-SHA256 over ``timestamp . body``."""
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_webhook_signature(
    registry: WebhookSecretRegistry,
    tenant_id: str,
    signature_header: str | None,
    timestamp_header: str | None,
    body: bytes,
) -> None:
    """Raise WebhookError unless the delivery is authentically signed and fresh."""
    secret = registry.secret_for(tenant_id)
    if secret is None:
        raise WebhookError(401, "webhook_tenant_not_registered")
    if not signature_header:
        raise WebhookError(401, "webhook_signature_missing")
    if not timestamp_header:
        raise WebhookError(401, "webhook_timestamp_missing")
    try:
        sent_at = parse_utc_iso(timestamp_header)
    except ValueError as exc:
        raise WebhookError(401, "webhook_timestamp_invalid") from exc
    skew = abs((utc_now() - sent_at).total_seconds())
    if skew > MAX_CLOCK_SKEW_SECONDS:
        raise WebhookError(401, "webhook_timestamp_stale")
    expected = sign_webhook(secret, timestamp_header, body)
    if not hmac.compare_digest(expected, signature_header):
        raise WebhookError(401, "webhook_signature_invalid")


class BuildWebhookEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=8, max_length=128)
    event_type: str = Field(pattern=r"^build\.artifact\.published$")
    tenant_id: str = Field(min_length=1, max_length=128)
    artifact_sha256: str = Field(pattern=r"^(sha256:)?[0-9a-f]{64}$")
    source_commit: str = Field(min_length=7, max_length=64)
    repository: str = Field(min_length=1, max_length=2048)
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: str = Field(min_length=1, max_length=128)


class RegistryWebhookEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=8, max_length=128)
    event_type: str = Field(pattern=r"^registry\.image\.pushed$")
    tenant_id: str = Field(min_length=1, max_length=128)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_repository: str = Field(min_length=1, max_length=2048)
    source_commit: str = Field(min_length=7, max_length=64)
    environment_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: str = Field(min_length=1, max_length=128)


def _bare_digest(value: str) -> str:
    return value[len("sha256:"):] if value.startswith("sha256:") else value


def _map_event(event: BuildWebhookEvent | RegistryWebhookEvent) -> SubmitRequest:
    """Deterministically map a verified platform event to a certification target.

    The idempotency key derives from the SEMANTIC identity of the release candidate
    (tenant + artifact digest + commit + policy) — not the event id — so re-deliveries
    AND distinct events describing the same artifact deduplicate to one run.
    """
    if isinstance(event, BuildWebhookEvent):
        target_type = "package"
        artifact = _bare_digest(event.artifact_sha256)
        reference = f"{event.repository}@{event.source_commit}"
    else:
        target_type = "container"
        artifact = _bare_digest(event.image_digest)
        reference = f"{event.image_repository}@{event.source_commit}"
    identity_digest = declared_target_identity_digest(
        event.tenant_id, target_type, artifact, event.source_commit, reference
    )
    idempotency_key = "hook-" + sha256_json(
        {
            "tenant_id": event.tenant_id,
            "artifact_sha256": artifact,
            "source_commit": event.source_commit,
            "policy_version": event.policy_version,
        }
    )[:40]
    return SubmitRequest(
        tenant_id=event.tenant_id,
        target=SubmitTarget(
            target_type=target_type,
            identity_digest=identity_digest,
            reference=reference,
            # Declared artifact commitment: lets the queued run reconcile to the acquired
            # exact TargetIdentity before execution and become deployable.
            artifact_sha256=artifact,
            source_commit=event.source_commit,
        ),
        environment=SubmitEnvironment(identity_digest=event.environment_identity_digest),
        policy_version=event.policy_version,
        idempotency_key=idempotency_key,
    )


def ingest_webhook(
    store: EvidenceStore,
    manifest: RuleManifest,
    registry: WebhookSecretRegistry,
    tenant_header: str,
    event_kind: str,
    body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
) -> tuple[int, dict[str, Any]]:
    """Verify, map, and idempotently submit a platform webhook event.

    Returns (201, run) for a new certification run or (200, run) for a deduplicated one.
    Every failure raises WebhookError (fail-closed; the body is never acted on unless the
    signature verified first).
    """
    verify_webhook_signature(registry, tenant_header, signature_header, timestamp_header, body)
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookError(400, "webhook_body_invalid") from exc
    model: type[BuildWebhookEvent] | type[RegistryWebhookEvent]
    if event_kind == BUILD_EVENT:
        model = BuildWebhookEvent
    elif event_kind == REGISTRY_EVENT:
        model = RegistryWebhookEvent
    else:
        raise WebhookError(404, "webhook_event_unknown")
    try:
        event = model.model_validate(parsed)
    except ValidationError as exc:
        raise WebhookError(422, "webhook_event_invalid") from exc
    if event.tenant_id != tenant_header:
        raise WebhookError(403, "tenant_mismatch")
    request = _map_event(event)
    try:
        status_code, run = submit(store, manifest, request, tenant_header)
    except SubmitError as exc:
        raise WebhookError(exc.status_code, exc.code) from exc
    return status_code, {
        "event_id": event.event_id,
        "deduplicated": status_code == 200,
        "run": run,
    }
