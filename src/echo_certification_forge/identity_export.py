"""Export reconciled stored identities without reading evidence or changing runs."""
from __future__ import annotations

import json
from dataclasses import fields
from typing import Annotated, Any, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .canonical import require_identifier, sha256_json
from .models import EnvironmentIdentity, TargetIdentity

_MAX_IDENTITY_BYTES = 16 * 1024
_SCHEMA_VERSION = "certforge.canonical-identities.v1"
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
GitCommit = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")]


class IdentityExportError(ValueError):
    """A fixed public error code that never includes stored identity contents."""


class ExportTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tenant_id: Identifier
    target_type: Identifier
    canonical_ref: str = Field(min_length=1, max_length=2048)
    artifact_sha256: Digest
    source_commit: GitCommit | None
    dependency_sha256: Digest | None
    configuration_sha256: Digest | None


class ExportEnvironment(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    runner_image_sha256: Digest
    adapter_set_sha256: Digest
    test_plan_sha256: Digest
    policy_sha256: Digest
    harness_sha256: Digest
    prompt_set_sha256: Digest
    model_route_sha256: Digest
    os_runtime_sha256: Digest
    egress_policy_sha256: Digest


class ExportIdentities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target: ExportTarget
    environment: ExportEnvironment


class CanonicalIdentityExport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["certforge.canonical-identities.v1"]
    run_id: Identifier
    tenant_id: Identifier
    target_identity_digest: Digest
    environment_identity_digest: Digest
    rule_manifest_id: Identifier
    rule_manifest_digest: Digest
    identities: ExportIdentities
    identities_sha256: Digest
    export_sha256: Digest


def _identity_json(raw: Any) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise IdentityExportError("identity_record_invalid")
            result[key] = value
        return result

    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_IDENTITY_BYTES:
        raise IdentityExportError("identity_record_invalid")
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise IdentityExportError("identity_record_invalid")
    return value


def _reference_is_exportable(reference: str) -> None:
    # Never redact and re-hash a canonical identity. Refuse credentials, query
    # material, fragments, or controls instead of returning a changed identity.
    decoded = reference
    try:
        for _ in range(4):
            unquoted = unquote(decoded, errors="strict")
            if unquoted == decoded:
                break
            decoded = unquoted
        if unquote(decoded, errors="strict") != decoded:
            raise IdentityExportError("identity_reference_not_exportable")
        parsed = urlsplit(decoded)
    except (ValueError, UnicodeError) as error:
        raise IdentityExportError("identity_reference_not_exportable") from error
    if (
        any(ord(character) < 32 or ord(character) == 127 for character in decoded)
        or "?" in decoded
        or "#" in decoded
        or parsed.username is not None
        or parsed.password is not None
        or "%" in parsed.netloc
    ):
        raise IdentityExportError("identity_reference_not_exportable")


def export_canonical_identities(row: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    """Validate the stored objects and their commitments; do not infer any fields.

    The caller must first authenticate RUN_READ and obtain this row through the
    tenant-scoped store. This pure projection neither authorizes access nor reads
    artifact bytes. Successful HTTP export also requires an audited authorization
    recheck in the service before any identities are returned.
    """
    try:
        target_data = _identity_json(row["target_identity_json"])
        environment_data = _identity_json(row["environment_identity_json"])
        if "declared_identity_digest" in target_data or "declared_identity_digest" in environment_data:
            raise IdentityExportError("identity_not_reconciled")
        if (
            set(target_data) != {field.name for field in fields(TargetIdentity)}
            or set(environment_data) != {field.name for field in fields(EnvironmentIdentity)}
        ):
            raise IdentityExportError("identity_record_invalid")
        if row["tenant_id"] != tenant_id or target_data["tenant_id"] != tenant_id:
            raise IdentityExportError("identity_tenant_mismatch")
        identities = ExportIdentities.model_validate({
            "target": target_data, "environment": environment_data,
        }).model_dump(mode="json")
        _reference_is_exportable(identities["target"]["canonical_ref"])
        target = TargetIdentity(**target_data)
        environment = EnvironmentIdentity(**environment_data)
        if (
            target.to_dict() != target_data or environment.to_dict() != environment_data
            or target.identity_digest != row["target_identity_digest"]
            or environment.identity_digest != row["environment_identity_digest"]
        ):
            raise IdentityExportError("identity_digest_mismatch")
        require_identifier(row["run_id"], "run_id")
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "run_id": row["run_id"],
            "tenant_id": tenant_id,
            "target_identity_digest": target.identity_digest,
            "environment_identity_digest": environment.identity_digest,
            "rule_manifest_id": row["rule_manifest_id"],
            "rule_manifest_digest": row["rule_manifest_digest"],
            "identities": identities,
            "identities_sha256": sha256_json(identities),
        }
        return CanonicalIdentityExport.model_validate({
            **payload, "export_sha256": sha256_json(payload),
        }).model_dump(mode="json")
    except IdentityExportError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, ValidationError) as error:
        raise IdentityExportError("identity_record_invalid") from error
