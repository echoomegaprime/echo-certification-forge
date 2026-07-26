"""Digest-pinned Windows package certification transport for Echo Desktop.

This lane is intentionally single-purpose. It never launches the installer, accepts
arbitrary commands, or carries a verdict-signing key. The Windows runner observes the
exact artifact declared by a run and sends an Ed25519-authenticated result to the control plane;
only the isolated platform signer may turn that evidence into a release verdict.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonical_json, sha256_bytes, sha256_json, utc_now
from .models import EnvironmentIdentity
from .runner import RunnerResponse, SignedRunCredential

# Historical P8C candidate retained only as an acceptance fixture. Production bindings
# are read from each submitted reservation and are never hardcoded in the execution lane.
P8C_SOURCE_COMMIT = "6a7a8da448d86cfaab7a29bde6d3354b45785f81"
P8C_INSTALLER_SHA256 = "1bdef4f842593f3a03cb547899a08c11f60c51edcf03fa4673de6e6a1dface55"
P8C_INSTALLER_NAME = "EchoDesktop-Setup-0.4.0.exe"

_CHECK_NAMES = frozenset(
    {
        "artifact_digest",
        "source_commit",
        "regular_file",
        "no_reparse_point",
        "authenticode_valid",
        "authenticode_timestamped",
    }
)
_AUTHENTICODE_STATUSES = frozenset(
    {
        "Valid",
        "UnknownError",
        "NotSigned",
        "HashMismatch",
        "NotTrusted",
        "NotSupportedFileFormat",
        "Incompatible",
    }
)


def _component_digest(name: str) -> str:
    return sha256_bytes(f"certforge:p8c-windows:{name}:v1".encode("utf-8"))


def windows_package_environment(worker_image_sha256: str) -> EnvironmentIdentity:
    """Return the exact environment commitment submitted with this runner's package run."""
    return EnvironmentIdentity(
        runner_image_sha256=worker_image_sha256,
        adapter_set_sha256=_component_digest("no-adapters"),
        test_plan_sha256=_component_digest("static-installer-authenticode"),
        policy_sha256=_component_digest("release-strict-v2"),
        harness_sha256=_component_digest("windows-package-worker"),
        prompt_set_sha256=_component_digest("no-llm"),
        model_route_sha256=_component_digest("deterministic-only"),
        os_runtime_sha256=_component_digest("windows-powershell-authenticode"),
        egress_policy_sha256=_component_digest("certforge-only"),
    )


class WindowsPackageResultBody(BaseModel):
    """Strict authenticated observation produced by the pinned Windows runner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["windows_package_result"]
    target_type: Literal["package"]
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    reference: str = Field(min_length=1, max_length=2048)
    package_size: int = Field(gt=0, le=2_147_483_648)
    worker_image_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: dict[str, str]
    checks: dict[str, bool]
    authenticode_status: str = Field(min_length=1, max_length=80)
    signer_subject: str | None = Field(default=None, max_length=512)
    timestamper_subject: str | None = Field(default=None, max_length=512)
    ready_candidate: bool

    @model_validator(mode="after")
    def exact_p8c_binding(self) -> "WindowsPackageResultBody":
        if Path(self.reference).suffix.lower() != ".exe":
            raise ValueError("Windows package reference must be an .exe installer")
        if frozenset(self.checks) != _CHECK_NAMES:
            raise ValueError("Windows package checks are not the exact contract set")
        environment = EnvironmentIdentity(**self.environment)
        expected = windows_package_environment(self.worker_image_sha256)
        if environment != expected:
            raise ValueError("Windows package environment identity mismatch")
        expected_ready = all(self.checks.values()) and self.authenticode_status == "Valid"
        if self.ready_candidate != expected_ready:
            raise ValueError("ready_candidate does not match deterministic checks")
        return self

    @property
    def environment_identity_digest(self) -> str:
        return EnvironmentIdentity(**self.environment).identity_digest


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _git_head(source_root: Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        shell=False,
    )
    if process.returncode != 0:
        raise ValueError("source root is not a readable git worktree")
    return process.stdout.strip().lower()


def _authenticode(path: Path) -> dict[str, Any]:
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:ECHO_CERTFORGE_PACKAGE_PATH;"
        "[pscustomobject]@{Status=[string]$s.Status;"
        "SignerSubject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};"
        "TimestamperSubject=if($s.TimeStamperCertificate){$s.TimeStamperCertificate.Subject}else{$null}}"
        "|ConvertTo-Json -Compress"
    )
    child_environment = os.environ.copy()
    child_environment["ECHO_CERTFORGE_PACKAGE_PATH"] = str(path)
    process = subprocess.run(
        ["pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        env=child_environment,
        text=True,
        timeout=30,
        shell=False,
    )
    if process.returncode != 0 or process.stderr.strip():
        raise RuntimeError("Authenticode inspection failed")
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Authenticode inspection returned invalid JSON") from exc
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("Status"), str)
        or result["Status"] not in _AUTHENTICODE_STATUSES
    ):
        raise RuntimeError("Authenticode inspection returned an invalid result")
    return result


def inspect_windows_installer(
    artifact_path: Path,
    source_root: Path,
    *,
    worker_image_sha256: str,
    expected_artifact_sha256: str,
    expected_source_commit: str,
    expected_reference: str,
) -> WindowsPackageResultBody:
    """Inspect the exact submitted installer without executing it."""
    artifact = artifact_path.resolve(strict=True)
    source = source_root.resolve(strict=True)
    if artifact.name != Path(expected_reference).name or artifact.suffix.lower() != ".exe":
        raise ValueError("installer filename does not match the submitted reference")
    try:
        artifact.relative_to(source)
    except ValueError as exc:
        raise ValueError("installer is outside the pinned source worktree") from exc
    info = artifact.lstat()
    regular_file = stat.S_ISREG(info.st_mode) and not artifact.is_symlink()
    no_reparse = not _is_reparse_point(artifact)
    if not regular_file or not no_reparse:
        raise ValueError("installer path is not a regular non-reparse file")
    digest = file_sha256(artifact)
    head = _git_head(source)
    if digest != expected_artifact_sha256.lower():
        raise ValueError("installer digest does not match the submitted artifact")
    if head != expected_source_commit.lower():
        raise ValueError("source HEAD does not match the submitted source commit")
    signature = _authenticode(artifact)
    status = str(signature["Status"])
    signer = signature.get("SignerSubject")
    timestamper = signature.get("TimestamperSubject")
    checks = {
        "artifact_digest": True,
        "source_commit": True,
        "regular_file": regular_file,
        "no_reparse_point": no_reparse,
        "authenticode_valid": status == "Valid",
        "authenticode_timestamped": bool(timestamper),
    }
    environment = windows_package_environment(worker_image_sha256)
    return WindowsPackageResultBody(
        kind="windows_package_result",
        target_type="package",
        artifact_sha256=digest,
        source_commit=head,
        reference=str(artifact),
        package_size=info.st_size,
        worker_image_sha256=worker_image_sha256,
        environment=environment.to_dict(),
        checks=checks,
        authenticode_status=status,
        signer_subject=signer if isinstance(signer, str) else None,
        timestamper_subject=timestamper if isinstance(timestamper, str) else None,
        ready_candidate=all(checks.values()) and status == "Valid",
    )


def load_runner_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("runner private key must be Ed25519")
    return key


def sign_package_result(
    body: WindowsPackageResultBody,
    credential: SignedRunCredential,
    private_key: Ed25519PrivateKey,
    *,
    sequence: int = 1,
    issued_at: datetime | None = None,
) -> RunnerResponse:
    claims = credential.claims
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = f"ed25519:{sha256_bytes(public)[:32]}"
    if key_id != claims.runner_key_id:
        raise ValueError("runner private key does not match credential")
    current = issued_at or utc_now()
    unsigned = RunnerResponse(
        response_id=f"p8c-result-{sha256_json(body.model_dump(mode='json'))[:24]}",
        request_id=f"p8c-observe-{claims.credential_id}",
        run_id=claims.run_id,
        tenant_id=claims.tenant_id,
        runner_id=claims.runner_id,
        sequence=sequence,
        issued_at=current,
        status="COMPLETED",
        body=body.model_dump(mode="json"),
        body_sha256=sha256_json(body.model_dump(mode="json")),
        runner_key_id=key_id,
        signature_b64="pending",
    )
    signature = private_key.sign(canonical_json(unsigned.signed_payload()).encode("utf-8"))
    return unsigned.model_copy(
        update={"signature_b64": base64.b64encode(signature).decode("ascii")}
    )
