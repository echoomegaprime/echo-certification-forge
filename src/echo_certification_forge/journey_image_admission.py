"""Bounded journey-image sealing through an existing, independently admitted authority.

Preparation is unsigned evidence, not authorization. This module never loads keys,
changes a live policy, executes Docker, or changes the twelve-image P4 manifest.
An admitted control-plane owner may inject its existing signing authority only
after independently reviewing the exact request digest.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json, require_sha256, sha256_bytes
from .supply_chain import (
    ImageAdmissionDenied,
    ImageAdmissionPolicy,
    ImageAttestation,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    evaluate_image_admission,
    scan_dockerfile,
    verify_spdx_document,
)


class JourneyQualification(BaseModel):
    """Public evidence commitments; authenticity remains an independent review gate."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    identity_digest: str
    archive_sha256: str
    independent_archive_sha256: str
    normalized_first_sha256: str
    normalized_second_sha256: str
    scanner_report_sha256: str
    node_core_report_sha256: str
    runtime_probe_sha256: str
    critical_count: int = Field(ge=0)
    fixed_high_or_critical_count: int = Field(ge=0)
    secret_count: int = Field(ge=0)
    node_core_finding_count: int = Field(ge=0)
    node_version: Literal["24.19.0"]
    python_version: str = Field(pattern=r"^3\.11\.[0-9]+$")
    uid: int = Field(gt=0)
    read_only_root: bool
    network_disabled: bool
    utf8: bool
    observed_at: datetime

    @model_validator(mode="after")
    def check_qualification(self) -> JourneyQualification:
        for name in (
            "identity_digest", "archive_sha256", "independent_archive_sha256",
            "normalized_first_sha256", "normalized_second_sha256",
            "scanner_report_sha256", "node_core_report_sha256", "runtime_probe_sha256",
        ):
            require_sha256(getattr(self, name), name)
        if self.archive_sha256 == self.independent_archive_sha256:
            raise ValueError("independent_build_evidence_required")
        if self.normalized_first_sha256 != self.normalized_second_sha256:
            raise ValueError("normalized_build_mismatch")
        if any((self.critical_count, self.fixed_high_or_critical_count,
                self.secret_count, self.node_core_finding_count)):
            raise ValueError("image_security_policy_failed")
        if self.observed_at.tzinfo is None:
            raise ValueError("qualification_time_requires_timezone")
        if not all((self.read_only_root, self.network_disabled, self.utf8)):
            raise ValueError("runtime_isolation_or_encoding_failed")
        return self


class JourneyAdmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["certforge.journey-image-admission.v1"] = "certforge.journey-image-admission.v1"
    state: Literal["UNSIGNED_NOT_ADMITTED"] = "UNSIGNED_NOT_ADMITTED"
    identity: ImageIdentity
    qualification: JourneyQualification
    prior_policy: ImageAdmissionPolicy
    prior_attestation: ImageAttestation

    @model_validator(mode="after")
    def check_binding(self) -> JourneyAdmissionRequest:
        if self.identity.role != ImageRole.RUNNER or self.prior_policy.required_role != ImageRole.RUNNER:
            raise ValueError("runner_role_required")
        if self.identity.architecture != "amd64" or self.identity.operating_system != "linux":
            raise ValueError("unsupported_journey_platform")
        if self.qualification.identity_digest != self.identity.digest:
            raise ValueError("qualification_identity_mismatch")
        if self.identity.image_digest in self.prior_policy.revoked_image_digests:
            raise ValueError("candidate_image_revoked")
        return self

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.model_dump(mode="json")).encode("utf-8"))


def proposed_policy(request: JourneyAdmissionRequest, *, now: datetime | None = None) -> ImageAdmissionPolicy:
    """Derive a separate exact-image proposal, preserving every public trust constraint."""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ImageAdmissionDenied("verification_time_requires_timezone")
    age = current - request.qualification.observed_at
    if age < timedelta(seconds=-30) or age > timedelta(hours=24):
        raise ImageAdmissionDenied("qualification_stale_or_future")
    if request.identity.created_at > current + timedelta(seconds=30):
        raise ImageAdmissionDenied("identity_time_in_future")
    admission = evaluate_image_admission(request.prior_attestation, request.prior_policy, now=current)
    if not admission.allowed:
        raise ImageAdmissionDenied("existing_authority_not_admitted")
    identity = request.identity
    # A new policy ID avoids overwriting the existing P4 runner or its other roles.
    proposal = request.prior_policy.model_dump(mode="json")
    proposal.update(
        policy_id="journey.runner." + identity.digest[:32],
        expected_image_digest=identity.image_digest,
        approved_base_digests=[identity.base_image_digest],
        approved_source_commits=[identity.source_commit],
        approved_dockerfile_sha256=identity.dockerfile_sha256,
        approved_lockfile_sha256=identity.lockfile_sha256,
    )
    return ImageAdmissionPolicy.model_validate(proposal)


def prepare_admission_request(
    *, identity: ImageIdentity, qualification: JourneyQualification,
    prior_policy: ImageAdmissionPolicy, prior_attestation: ImageAttestation,
    dockerfile: bytes, lockfile: bytes, sbom: bytes, provenance: bytes,
    now: datetime | None = None,
) -> JourneyAdmissionRequest:
    """Bind exact material bytes before producing any unsigned policy proposal."""
    qualification = JourneyQualification.model_validate_json(qualification.model_dump_json())
    for name, raw in (("dockerfile", dockerfile), ("lockfile", lockfile),
                      ("sbom", sbom), ("provenance", provenance)):
        if len(raw) > 4 * 1024 * 1024:
            raise ImageAdmissionDenied("material_size_limit")
        if hashlib.sha256(raw).hexdigest() != getattr(identity, name + "_sha256"):
            raise ImageAdmissionDenied(name + "_hash_mismatch")
    scan = scan_dockerfile(dockerfile.decode("utf-8"))
    if not scan.valid:
        raise ImageAdmissionDenied("dockerfile_policy_failed")
    bases = [line.split()[1].split("@", 1)[1] for line in dockerfile.decode("utf-8").splitlines()
             if line.strip().upper().startswith("FROM ")]
    if identity.base_image_digest != bases[-1]:
        raise ImageAdmissionDenied("final_base_mismatch")
    lock = json.loads(lockfile)
    provenance_record = json.loads(provenance)
    if not isinstance(lock, dict) or not isinstance(provenance_record, dict):
        raise ImageAdmissionDenied("material_object_required")
    if lock.get("source_commit") != identity.source_commit or provenance_record.get("source_commit") != identity.source_commit:
        raise ImageAdmissionDenied("material_source_mismatch")
    sbom_record = json.loads(sbom)
    if (not isinstance(sbom_record, dict) or not isinstance(sbom_record.get("packages"), list)
            or not all(isinstance(row, dict) for row in sbom_record["packages"])):
        raise ImageAdmissionDenied("sbom_invalid")
    valid, _ = verify_spdx_document(sbom_record, image_digest=identity.image_digest)
    if not valid:
        raise ImageAdmissionDenied("sbom_invalid")
    packages = {(row.get("name"), row.get("versionInfo")) for row in sbom_record["packages"]
                if isinstance(row.get("name"), str) and isinstance(row.get("versionInfo"), str)}
    if ("nodejs", qualification.node_version) not in packages or ("CPython", qualification.python_version) not in packages:
        raise ImageAdmissionDenied("runtime_packages_missing_from_sbom")
    request = JourneyAdmissionRequest(identity=identity, qualification=qualification,
                                      prior_policy=prior_policy, prior_attestation=prior_attestation)
    proposed_policy(request, now=now)
    return request


def seal_admission_request(
    request: JourneyAdmissionRequest, *, authority: ImageAttestationAuthority,
    approved_request_sha256: str, now: datetime | None = None,
    valid_for: timedelta = timedelta(days=7),
) -> tuple[ImageAttestation, ImageAdmissionPolicy]:
    """Owner-controlled signing adapter, with no key loader or trust bootstrap.

    The approval digest is an integrity check, never an authorization claim. The
    caller must be the admitted control-plane owner. Existing authority lifetime
    bounds the result; stale evidence, changed inputs and untrusted keys fail
    before the signing method is called.
    """
    request = JourneyAdmissionRequest.model_validate_json(request.model_dump_json())
    require_sha256(approved_request_sha256, "approved_request_sha256")
    if request.digest != approved_request_sha256:
        raise ImageAdmissionDenied("reviewed_request_mismatch")
    current = now or datetime.now(UTC)
    policy = proposed_policy(request, now=current)
    previous = request.prior_attestation
    if authority.key_id != previous.key_id or authority.public_key_pem != previous.public_key_pem:
        raise ImageAdmissionDenied("existing_authority_required")
    remaining = previous.expires_at - current
    if valid_for <= timedelta(0) or valid_for > timedelta(days=30) or valid_for > remaining:
        raise ImageAdmissionDenied("authority_lifetime_exceeded")
    attestation = authority.sign(request.identity, issued_at=current, valid_for=valid_for)
    if not evaluate_image_admission(attestation, policy, now=current).allowed:
        raise ImageAdmissionDenied("signed_candidate_not_admitted")
    return attestation, policy
