"""Deterministic P4 twelve-image manifest contracts and offline verification."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import parse_utc_iso, require_sha256, sha256_bytes, to_utc_iso
from .supply_chain import (
    ImageAdmissionPolicy,
    ImageAttestation,
    ImageRole,
    evaluate_image_admission,
    verify_image_attestation,
    verify_spdx_document,
)

P4_ROLES = tuple(role.value for role in ImageRole)
P4_VARIANTS = ("a", "b")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class P4ArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    sha256: str

    @model_validator(mode="after")
    def validate_digest(self) -> "P4ArtifactRef":
        require_sha256(self.sha256, "sha256")
        return self


class P4ImageRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    role: ImageRole
    variant: Literal["a", "b"]
    repository: str = Field(min_length=1)
    tag: str = Field(min_length=1)
    reference: str = Field(min_length=1)
    image_id: str
    repo_digest: str = Field(min_length=1)
    config_digest: str
    manifest_digest: str
    platform: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    operating_system: str = Field(min_length=1)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    base_image_reference: str = Field(min_length=1)
    base_digest: str
    dockerfile_path: str = Field(min_length=1)
    dockerfile_sha256: str
    lockfile_path: str = Field(min_length=1)
    lockfile_sha256: str
    sbom: P4ArtifactRef
    provenance: P4ArtifactRef
    attestation: P4ArtifactRef
    admission_policy: P4ArtifactRef
    vulnerability_scan: P4ArtifactRef
    runtime_scan: P4ArtifactRef
    attestation_identity: str
    attestation_public_key_fingerprint: str
    attestation_created_at: datetime
    attestation_expiration_time: datetime
    runtime_uid: int = 65532
    runtime_gid: int = 65532
    entrypoint: tuple[str, ...] = ()
    command: tuple[str, ...] = ()
    health_command: tuple[str, ...]
    admission_policy_identity: str = Field(min_length=1)
    build_timestamp: datetime
    build_host_identity: str = Field(min_length=1)
    normalized_manifest_sha256: str
    source_file_count: int = Field(ge=1)
    package_count: int = Field(ge=1)
    labels: dict[str, str]

    @model_validator(mode="after")
    def validate_record(self) -> "P4ImageRecord":
        for name in (
            "image_id",
            "config_digest",
            "manifest_digest",
            "base_digest",
        ):
            value = getattr(self, name)
            if not value.startswith("sha256:") or len(value) != 71:
                raise ValueError(f"{name} must be sha256:<64 hex>")
        for name in (
            "dockerfile_sha256",
            "lockfile_sha256",
            "normalized_manifest_sha256",
        ):
            require_sha256(getattr(self, name), name)
        if self.attestation_created_at.tzinfo is None or self.attestation_expiration_time.tzinfo is None:
            raise ValueError("attestation timestamps must be timezone-aware")
        if self.build_timestamp.tzinfo is None:
            raise ValueError("build_timestamp must be timezone-aware")
        if self.attestation_expiration_time <= self.attestation_created_at:
            raise ValueError("attestation expiration must follow creation")
        if self.runtime_uid != 65532 or self.runtime_gid != 65532:
            raise ValueError("runtime identity must remain 65532:65532")
        if not self.health_command:
            raise ValueError("health_command is required")
        return self


class P4ImageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    phase: Literal["P4"] = "P4"
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    base_image_reference: str = Field(min_length=1)
    base_digest: str
    created_at_utc: datetime
    build_host_identity: str = Field(min_length=1)
    attestation_public_key: P4ArtifactRef
    attestation_key_id: str = Field(min_length=1)
    records: tuple[P4ImageRecord, ...]

    @model_validator(mode="after")
    def validate_manifest(self) -> "P4ImageManifest":
        if not self.base_digest.startswith("sha256:") or len(self.base_digest) != 71:
            raise ValueError("base_digest must be sha256:<64 hex>")
        if self.created_at_utc.tzinfo is None:
            raise ValueError("created_at_utc must be timezone-aware")
        expected = {(role, variant) for role in P4_ROLES for variant in P4_VARIANTS}
        actual = {(item.role.value, item.variant) for item in self.records}
        if actual != expected or len(self.records) != 12:
            raise ValueError("manifest must contain exactly one record for every P4 role/variant pair")
        for field_name in ("reference", "image_id", "repo_digest", "config_digest", "manifest_digest"):
            values = [getattr(item, field_name) for item in self.records]
            if len(values) != len(set(values)):
                raise ValueError(f"unexpected duplicate {field_name}")
        if any(item.source_commit != self.source_commit for item in self.records):
            raise ValueError("record source commit mismatch")
        if any(item.base_digest != self.base_digest for item in self.records):
            raise ValueError("record base digest mismatch")
        if any(item.build_host_identity != self.build_host_identity for item in self.records):
            raise ValueError("record build-host identity mismatch")
        if any(item.attestation_identity != self.attestation_key_id for item in self.records):
            raise ValueError("record attestation identity mismatch")
        return self


def _resolve_artifact(manifest_path: Path, artifact: P4ArtifactRef) -> Path:
    candidate = Path(artifact.path)
    if not candidate.is_absolute():
        candidate = (manifest_path.parent / candidate).resolve()
    return candidate


def _artifact_ok(manifest_path: Path, artifact: P4ArtifactRef) -> tuple[bool, str, Path]:
    path = _resolve_artifact(manifest_path, artifact)
    if not path.is_file():
        return False, "missing", path
    if sha256_file(path) != artifact.sha256:
        return False, "sha256_mismatch", path
    return True, "verified", path


def verify_p4_image_manifest(
    manifest_path: Path,
    *,
    expected_source_commit: str,
    expected_base_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a sealed P4 image manifest without trusting mutable image tags."""

    manifest_path = manifest_path.resolve(strict=True)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = P4ImageManifest.model_validate(document)
    current = now or datetime.now(UTC)
    failures: list[str] = []
    if manifest.source_commit != expected_source_commit:
        failures.append("source_commit_mismatch")
    if manifest.base_digest != expected_base_digest:
        failures.append("base_digest_mismatch")

    public_ok, public_reason, public_path = _artifact_ok(manifest_path, manifest.attestation_public_key)
    if not public_ok:
        failures.append(f"attestation_public_key:{public_reason}")

    record_results: list[dict[str, Any]] = []
    for record in manifest.records:
        prefix = f"{record.role.value}.{record.variant}"
        artifact_results: dict[str, Any] = {}
        paths: dict[str, Path] = {}
        for name in (
            "sbom",
            "provenance",
            "attestation",
            "admission_policy",
            "vulnerability_scan",
            "runtime_scan",
        ):
            ok, reason, path = _artifact_ok(manifest_path, getattr(record, name))
            artifact_results[name] = {"ok": ok, "reason": reason, "path": str(path)}
            paths[name] = path
            if not ok:
                failures.append(f"{prefix}:{name}:{reason}")
        if not all(item["ok"] for item in artifact_results.values()):
            record_results.append({"record": prefix, "artifacts": artifact_results, "passed": False})
            continue

        attestation = ImageAttestation.model_validate_json(paths["attestation"].read_text(encoding="utf-8"))
        policy = ImageAdmissionPolicy.model_validate_json(paths["admission_policy"].read_text(encoding="utf-8"))
        valid_attestation, attestation_reason = verify_image_attestation(attestation, now=current)
        admission = evaluate_image_admission(attestation, policy, now=current)
        if not valid_attestation:
            failures.append(f"{prefix}:attestation:{attestation_reason}")
        if not admission.allowed:
            failures.append(f"{prefix}:admission:{','.join(admission.reasons)}")
        identity = attestation.identity
        expected = {
            "role": record.role,
            "image_digest": record.manifest_digest,
            "base_image_digest": record.base_digest,
            "source_commit": record.source_commit,
            "dockerfile_sha256": record.dockerfile_sha256,
            "lockfile_sha256": record.lockfile_sha256,
            "sbom_sha256": record.sbom.sha256,
            "provenance_sha256": record.provenance.sha256,
        }
        for name, value in expected.items():
            if getattr(identity, name) != value:
                failures.append(f"{prefix}:identity_{name}_mismatch")
        if attestation.key_id != manifest.attestation_key_id:
            failures.append(f"{prefix}:attestation_key_id_mismatch")
        if policy.policy_id != record.admission_policy_identity:
            failures.append(f"{prefix}:policy_id_mismatch")

        sbom = json.loads(paths["sbom"].read_text(encoding="utf-8"))
        sbom_valid, sbom_reason = verify_spdx_document(sbom, image_digest=record.manifest_digest)
        if not sbom_valid:
            failures.append(f"{prefix}:sbom:{sbom_reason}")
        provenance = json.loads(paths["provenance"].read_text(encoding="utf-8"))
        subject = ((provenance.get("subject") or [{}])[0].get("digest") or {}).get("sha256")
        if subject != record.manifest_digest.split(":", 1)[1]:
            failures.append(f"{prefix}:provenance_subject_mismatch")
        external = (((provenance.get("predicate") or {}).get("buildDefinition") or {}).get("externalParameters") or {})
        if external.get("source_commit") != record.source_commit:
            failures.append(f"{prefix}:provenance_source_mismatch")
        if external.get("dockerfile_sha256") != record.dockerfile_sha256:
            failures.append(f"{prefix}:provenance_dockerfile_mismatch")
        if external.get("lockfile_sha256") != record.lockfile_sha256:
            failures.append(f"{prefix}:provenance_lockfile_mismatch")

        vulnerability = json.loads(paths["vulnerability_scan"].read_text(encoding="utf-8"))
        if not vulnerability.get("passed"):
            failures.append(f"{prefix}:vulnerability_policy_failed")
        if any(int(vulnerability.get(key, -1)) != 0 for key in ("critical_count", "fixed_high_or_critical_count", "secret_finding_count")):
            failures.append(f"{prefix}:vulnerability_counts_nonzero")
        runtime_scan = json.loads(paths["runtime_scan"].read_text(encoding="utf-8"))
        if not runtime_scan.get("passed"):
            failures.append(f"{prefix}:runtime_scan_failed")

        expected_labels = {
            "echo.certforge.image.role": record.role.value,
            "echo.certforge.image.variant": record.variant,
            "echo.certforge.admission.policy": record.admission_policy_identity,
            "echo.certforge.attestation.key_id": manifest.attestation_key_id,
            "org.opencontainers.image.revision": record.source_commit,
            "org.opencontainers.image.base.digest": record.base_digest,
        }
        for name, value in expected_labels.items():
            if record.labels.get(name) != value:
                failures.append(f"{prefix}:label_{name}_mismatch")
        record_results.append(
            {
                "record": prefix,
                "artifacts": artifact_results,
                "attestation": {"valid": valid_attestation, "reason": attestation_reason},
                "admission": admission.model_dump(mode="json"),
                "sbom": {"valid": sbom_valid, "reason": sbom_reason},
                "passed": not any(item.startswith(prefix + ":") for item in failures),
            }
        )

    return {
        "schema_version": "1.0.0",
        "verified_at_utc": to_utc_iso(current),
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "source_commit": manifest.source_commit,
        "base_digest": manifest.base_digest,
        "record_count": len(manifest.records),
        "attestation_key_id": manifest.attestation_key_id,
        "attestation_public_key": {"path": str(public_path), "verified": public_ok, "reason": public_reason},
        "records": record_results,
        "failures": sorted(set(failures)),
        "passed": not failures,
    }


def write_manifest(path: Path, manifest: P4ImageManifest) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.model_dump_json(indent=2) + "\n"
    path.write_text(payload, encoding="utf-8")
    digest = sha256_bytes(payload.encode("utf-8"))
    path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def manifest_timestamp(value: str) -> datetime:
    return parse_utc_iso(value)
