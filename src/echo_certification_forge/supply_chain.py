"""P4 image supply-chain identity, attestation, admission, and build-context policy."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json, require_sha256, sha256_bytes, to_utc_iso

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PINNED_FROM = re.compile(r"^FROM\s+[^\s]+@sha256:[0-9a-f]{64}(?:\s+AS\s+[A-Za-z0-9_.-]+)?$", re.IGNORECASE)


class ImageRole(StrEnum):
    RUNNER = "runner"
    CUSTODY = "custody"
    ANCHOR = "anchor"
    SIGNER = "signer"
    WORKER = "worker"
    VERIFIER = "verifier"


class ImageSupplyChainError(RuntimeError):
    """Base failure for image supply-chain verification."""


class ImageAdmissionDenied(ImageSupplyChainError):
    """An image did not satisfy the exact admission policy."""


class ImageIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    role: ImageRole
    image_digest: str
    base_image_digest: str
    source_commit: str
    dockerfile_sha256: str
    lockfile_sha256: str
    sbom_sha256: str
    provenance_sha256: str
    architecture: str = Field(min_length=1, max_length=32)
    operating_system: str = Field(min_length=1, max_length=32)
    created_at: datetime

    @model_validator(mode="after")
    def validate_identity(self) -> "ImageIdentity":
        if not _IMAGE_DIGEST.fullmatch(self.image_digest):
            raise ValueError("image_digest must be sha256:<64 hex>")
        if not _IMAGE_DIGEST.fullmatch(self.base_image_digest):
            raise ValueError("base_image_digest must be sha256:<64 hex>")
        if not _COMMIT.fullmatch(self.source_commit):
            raise ValueError("source_commit must be an exact 40-character Git SHA")
        for field_name in ("dockerfile_sha256", "lockfile_sha256", "sbom_sha256", "provenance_sha256"):
            require_sha256(getattr(self, field_name), field_name)
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return self

    @property
    def digest(self) -> str:
        return sha256_bytes(canonical_json(self.model_dump(mode="json")).encode("utf-8"))


class ImageAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.1.0"
    identity: ImageIdentity
    key_id: str = Field(min_length=1, max_length=128)
    algorithm: str = "Ed25519"
    public_key_pem: str
    issued_at: datetime
    expires_at: datetime
    signature_b64: str

    @model_validator(mode="after")
    def validate_lifetime(self) -> "ImageAttestation":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("attestation timestamps must be timezone-aware")
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(days=90):
            raise ValueError("attestation lifetime must be greater than zero and no more than 90 days")
        return self


class ImageAttestationAuthority:
    """Ephemeral or HSM-backed attestation authority. Private keys are not serialised."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        public_key = private_key.public_key()
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        self.public_key_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @classmethod
    def generate(cls) -> "ImageAttestationAuthority":
        return cls(Ed25519PrivateKey.generate())

    def sign(
        self,
        identity: ImageIdentity,
        *,
        issued_at: datetime | None = None,
        valid_for: timedelta = timedelta(days=30),
    ) -> ImageAttestation:
        issued = issued_at or datetime.now(UTC)
        if issued.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")
        expires = issued + valid_for
        signed_payload = {
            "identity": identity.model_dump(mode="json"),
            "issued_at": to_utc_iso(issued),
            "expires_at": to_utc_iso(expires),
        }
        signature = self._private_key.sign(canonical_json(signed_payload).encode("utf-8"))
        return ImageAttestation(
            identity=identity,
            key_id=self.key_id,
            public_key_pem=self.public_key_pem,
            issued_at=issued,
            expires_at=expires,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


class ImageAdmissionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.1.0"
    policy_id: str = Field(min_length=1, max_length=128)
    required_role: ImageRole
    expected_image_digest: str
    approved_base_digests: tuple[str, ...]
    approved_source_commits: tuple[str, ...]
    approved_dockerfile_sha256: str
    approved_lockfile_sha256: str
    trusted_attestation_keys: dict[str, str]
    revoked_image_digests: tuple[str, ...] = ()
    compromised_key_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_policy(self) -> "ImageAdmissionPolicy":
        if not _IMAGE_DIGEST.fullmatch(self.expected_image_digest):
            raise ValueError("expected_image_digest must be sha256:<64 hex>")
        if not self.approved_base_digests or not all(_IMAGE_DIGEST.fullmatch(item) for item in self.approved_base_digests):
            raise ValueError("approved_base_digests must contain exact image digests")
        if not self.approved_source_commits or not all(_COMMIT.fullmatch(item) for item in self.approved_source_commits):
            raise ValueError("approved_source_commits must contain exact Git SHAs")
        require_sha256(self.approved_dockerfile_sha256, "approved_dockerfile_sha256")
        require_sha256(self.approved_lockfile_sha256, "approved_lockfile_sha256")
        return self


class AdmissionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reasons: tuple[str, ...]
    image_digest: str
    role: ImageRole
    attestation_key_id: str


def _attestation_payload(attestation: ImageAttestation) -> dict[str, Any]:
    return {
        "identity": attestation.identity.model_dump(mode="json"),
        "issued_at": to_utc_iso(attestation.issued_at),
        "expires_at": to_utc_iso(attestation.expires_at),
    }


def verify_image_attestation(
    attestation: ImageAttestation,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    if attestation.algorithm != "Ed25519":
        return False, "unsupported_attestation_algorithm"
    try:
        key = serialization.load_pem_public_key(attestation.public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return False, "attestation_key_not_ed25519"
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if attestation.key_id != f"ed25519:{sha256_bytes(raw)[:32]}":
            return False, "attestation_key_id_mismatch"
        key.verify(
            base64.b64decode(attestation.signature_b64, validate=True),
            canonical_json(_attestation_payload(attestation)).encode("utf-8"),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False, "invalid_image_attestation"
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        return False, "verification_time_not_timezone_aware"
    if current < attestation.issued_at:
        return False, "image_attestation_not_yet_valid"
    if current >= attestation.expires_at:
        return False, "image_attestation_expired"
    return True, "verified"


def evaluate_image_admission(
    attestation: ImageAttestation,
    policy: ImageAdmissionPolicy,
    *,
    now: datetime | None = None,
) -> AdmissionResult:
    identity = attestation.identity
    reasons: list[str] = []
    valid, reason = verify_image_attestation(attestation, now=now)
    if not valid:
        reasons.append(reason)
    trusted = policy.trusted_attestation_keys.get(attestation.key_id)
    if trusted is None:
        reasons.append("unknown_attestation_key")
    elif trusted != attestation.public_key_pem:
        reasons.append("attestation_public_key_mismatch")
    if attestation.key_id in policy.compromised_key_ids:
        reasons.append("attestation_key_compromised")
    if identity.role is not policy.required_role:
        reasons.append("image_role_mismatch")
    if identity.image_digest != policy.expected_image_digest:
        reasons.append("image_digest_drift")
    if identity.image_digest in policy.revoked_image_digests:
        reasons.append("image_digest_revoked")
    if identity.base_image_digest not in policy.approved_base_digests:
        reasons.append("base_image_not_approved")
    if identity.source_commit not in policy.approved_source_commits:
        reasons.append("source_commit_not_approved")
    if identity.dockerfile_sha256 != policy.approved_dockerfile_sha256:
        reasons.append("dockerfile_digest_mismatch")
    if identity.lockfile_sha256 != policy.approved_lockfile_sha256:
        reasons.append("lockfile_digest_mismatch")
    return AdmissionResult(
        allowed=not reasons,
        reasons=tuple(reasons),
        image_digest=identity.image_digest,
        role=identity.role,
        attestation_key_id=attestation.key_id,
    )


class DockerfileFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    line: int
    rule: str
    detail: str


class DockerfileScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    findings: tuple[DockerfileFinding, ...]
    sha256: str


def scan_dockerfile(text: str) -> DockerfileScanResult:
    findings: list[DockerfileFinding] = []
    logical_lines: list[tuple[int, str]] = []
    pending = ""
    pending_line = 0
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not pending:
            pending_line = line_number
        pending += stripped[:-1].rstrip() + " " if stripped.endswith("\\") else stripped
        if not stripped.endswith("\\"):
            logical_lines.append((pending_line, pending.strip()))
            pending = ""
    if pending:
        logical_lines.append((pending_line, pending.strip()))

    from_count = 0
    for line_number, line in logical_lines:
        upper = line.upper()
        if upper.startswith("FROM "):
            from_count += 1
            if not _PINNED_FROM.fullmatch(line):
                findings.append(DockerfileFinding(line=line_number, rule="unpinned_base", detail=line))
        if upper.startswith("ADD "):
            findings.append(DockerfileFinding(line=line_number, rule="add_forbidden", detail=line))
        if "DOCKER.SOCK" in upper:
            findings.append(DockerfileFinding(line=line_number, rule="docker_socket_forbidden", detail=line))
        if "--PRIVILEGED" in upper or "CAP_SYS_ADMIN" in upper:
            findings.append(DockerfileFinding(line=line_number, rule="privilege_request_forbidden", detail=line))
        if re.search(r"(?:curl|wget)[^|;&]*(?:\||&&)\s*(?:sh|bash)\b", line, re.IGNORECASE):
            findings.append(DockerfileFinding(line=line_number, rule="remote_script_execution", detail=line))
        if upper.startswith("USER ") and line.split(maxsplit=1)[1].strip() in {"0", "root", "0:0"}:
            findings.append(DockerfileFinding(line=line_number, rule="root_runtime_user", detail=line))
    if from_count == 0:
        findings.append(DockerfileFinding(line=0, rule="base_missing", detail="Dockerfile has no FROM instruction"))
    return DockerfileScanResult(
        valid=not findings,
        findings=tuple(findings),
        sha256=sha256_bytes(text.encode("utf-8")),
    )


class BuildContextScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    file_count: int
    total_bytes: int
    manifest_sha256: str
    findings: tuple[str, ...]


def scan_build_context(root: Path, *, max_files: int = 10_000, max_bytes: int = 512 * 1024 * 1024) -> BuildContextScanResult:
    root = root.resolve(strict=True)
    findings: list[str] = []
    manifest: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        posix = PurePosixPath(relative.as_posix())
        if posix.is_absolute() or ".." in posix.parts:
            findings.append(f"path_escape:{relative.as_posix()}")
            continue
        if path.is_symlink():
            findings.append(f"symlink_forbidden:{relative.as_posix()}")
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        total_bytes += size
        manifest.append(
            {
                "path": relative.as_posix(),
                "bytes": size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        if len(manifest) > max_files:
            findings.append("file_count_limit_exceeded")
            break
        if total_bytes > max_bytes:
            findings.append("context_size_limit_exceeded")
            break
    manifest_sha256 = sha256_bytes(canonical_json(manifest).encode("utf-8"))
    return BuildContextScanResult(
        valid=not findings,
        file_count=len(manifest),
        total_bytes=total_bytes,
        manifest_sha256=manifest_sha256,
        findings=tuple(findings),
    )


def build_spdx_document(
    *,
    image_name: str,
    image_digest: str,
    packages: list[dict[str, str]],
    created_at: datetime,
) -> dict[str, Any]:
    if not _IMAGE_DIGEST.fullmatch(image_digest):
        raise ValueError("image_digest must be exact")
    namespace = f"https://cert.echoforge.com/spdx/{image_digest.split(':', 1)[1]}"
    normalized_packages = sorted(packages, key=lambda item: (item["name"].lower(), item["version"]))
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{image_name}-sbom",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": to_utc_iso(created_at.astimezone(UTC)),
            "creators": ["Tool: echo-certification-forge-p4"],
        },
        "packages": [
            {
                "name": item["name"],
                "SPDXID": f"SPDXRef-Package-{index}",
                "versionInfo": item["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
            for index, item in enumerate(normalized_packages, start=1)
        ],
    }


def verify_spdx_document(document: dict[str, Any], *, image_digest: str) -> tuple[bool, str]:
    if document.get("spdxVersion") != "SPDX-2.3":
        return False, "spdx_version_invalid"
    expected_suffix = image_digest.split(":", 1)[1]
    if not str(document.get("documentNamespace", "")).endswith(expected_suffix):
        return False, "sbom_image_binding_mismatch"
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        return False, "sbom_packages_missing"
    ids = [item.get("SPDXID") for item in packages]
    if len(ids) != len(set(ids)):
        return False, "sbom_duplicate_package_id"
    return True, "verified"


def sha256_json_document(document: dict[str, Any]) -> str:
    return sha256_bytes((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))


_PRIVATE_KEY_BLOCK_RE = re.compile(
    b"-----BEGIN "
    + b"(?P<label>(?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)"
    + b"-----[\\r\\n]+"
    + b"(?:[A-Za-z0-9+/=]{16,}[\\r\\n]+){2,}"
    + b"-----END (?P=label)-----"
)


def contains_private_key_material(payload: bytes) -> bool:
    """Return true only for a complete plausible PEM private-key block."""
    return _PRIVATE_KEY_BLOCK_RE.search(payload) is not None


def container_link_escapes(member_path: str, target: str) -> bool:
    """Check whether an image-root symlink lexically escapes the container root.

    Absolute links remain inside the container mount namespace. Relative links are
    resolved from the link's parent and denied only if ``..`` traverses above root.
    """
    member = PurePosixPath(member_path.lstrip("./"))
    target_path = PurePosixPath(target)
    stack: list[str] = [] if target_path.is_absolute() else list(member.parent.parts)
    for part in target_path.parts:
        if part in {"", "/", "."}:
            continue
        if part == "..":
            if not stack:
                return True
            stack.pop()
            continue
        stack.append(part)
    return False
