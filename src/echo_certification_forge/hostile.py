"""Deterministic P4 hostile-runtime observation and evidence contracts."""
from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import require_sha256

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class HostileCaseKind(StrEnum):
    BASELINE = "baseline"
    NETWORK_EXFILTRATION = "network_exfiltration"
    DNS_EXFILTRATION = "dns_exfiltration"
    METADATA_ACCESS = "metadata_access"
    DOCKER_SOCKET_ACCESS = "docker_socket_access"
    ENVIRONMENT_THEFT = "environment_theft"
    SECRET_FILE_READ = "secret_file_read"
    PROCFS_INSPECTION = "procfs_inspection"
    MOUNT_PROBING = "mount_probing"
    PID_EXHAUSTION = "pid_exhaustion"
    CPU_EXHAUSTION = "cpu_exhaustion"
    MEMORY_EXHAUSTION = "memory_exhaustion"
    DISK_EXHAUSTION = "disk_exhaustion"
    FILE_SIZE_EXHAUSTION = "file_size_exhaustion"
    DESCRIPTOR_EXHAUSTION = "descriptor_exhaustion"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    RUNNER_CRASH = "runner_crash"
    SIGNER_CRASH = "signer_crash"
    WORKER_CRASH = "worker_crash"
    CUSTODY_CRASH = "custody_crash"
    ANCHOR_CRASH = "anchor_crash"
    EVIDENCE_CORRUPTION = "evidence_corruption"
    LOG_INJECTION = "log_injection"
    CROSS_TENANT = "cross_tenant"
    CROSS_RUN_INJECTION = "cross_run_injection"
    ORPHAN_REAP = "orphan_reap"


class HostileDisposition(StrEnum):
    CONTAINED = "CONTAINED"
    DENIED = "DENIED"
    TERMINATED = "TERMINATED"
    DETECTED = "DETECTED"
    CLEAN = "CLEAN"
    FAILED = "FAILED"


class HostileCaseObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0.0"
    case_id: str = Field(min_length=1, max_length=128)
    kind: HostileCaseKind
    started_at: datetime
    completed_at: datetime
    container_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{12,64}$")
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    oom_killed: bool = False
    host_impact: bool = False
    unrelated_resources_changed: bool = False
    logs_sha256: str
    evidence: dict[str, Any]

    @model_validator(mode="after")
    def validate_observation(self) -> "HostileCaseObservation":
        if self.started_at.tzinfo is None or self.completed_at.tzinfo is None:
            raise ValueError("observation timestamps must be timezone-aware")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        require_sha256(self.logs_sha256, "logs_sha256")
        return self


class HostileCaseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    kind: HostileCaseKind
    disposition: HostileDisposition
    passed: bool
    reasons: tuple[str, ...]


def sanitize_runner_log(value: str, *, max_bytes: int = 1024 * 1024) -> str:
    """Normalize hostile logs without interpreting control sequences or fake status lines."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    encoded = value.encode("utf-8", errors="replace")[:max_bytes]
    text = encoded.decode("utf-8", errors="replace")
    text = _ANSI_ESCAPE.sub("", text)
    text = _CONTROL.sub("�", text)
    lines = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        # Prefix every line so a target cannot forge a control-plane log record.
        lines.append(f"TARGET|{line}")
    return "\n".join(lines)


def decide_hostile_case(observation: HostileCaseObservation) -> HostileCaseDecision:
    reasons: list[str] = []
    if observation.host_impact:
        reasons.append("host_impact_detected")
    if observation.unrelated_resources_changed:
        reasons.append("unrelated_resource_changed")

    disposition = HostileDisposition.CONTAINED
    kind = observation.kind
    if kind is HostileCaseKind.BASELINE:
        if observation.exit_code != 0 or observation.timed_out or observation.cancelled or observation.oom_killed:
            reasons.append("baseline_did_not_complete_cleanly")
        disposition = HostileDisposition.CLEAN
    elif kind in {
        HostileCaseKind.NETWORK_EXFILTRATION,
        HostileCaseKind.DNS_EXFILTRATION,
        HostileCaseKind.METADATA_ACCESS,
        HostileCaseKind.DOCKER_SOCKET_ACCESS,
        HostileCaseKind.ENVIRONMENT_THEFT,
        HostileCaseKind.SECRET_FILE_READ,
        HostileCaseKind.CROSS_TENANT,
        HostileCaseKind.CROSS_RUN_INJECTION,
    }:
        if not bool(observation.evidence.get("denied")):
            reasons.append("forbidden_operation_not_denied")
        disposition = HostileDisposition.DENIED
    elif kind in {
        HostileCaseKind.PID_EXHAUSTION,
        HostileCaseKind.MEMORY_EXHAUSTION,
        HostileCaseKind.DISK_EXHAUSTION,
        HostileCaseKind.FILE_SIZE_EXHAUSTION,
        HostileCaseKind.DESCRIPTOR_EXHAUSTION,
    }:
        if not bool(observation.evidence.get("limit_enforced")):
            reasons.append("resource_limit_not_enforced")
        disposition = HostileDisposition.CONTAINED
    elif kind in {HostileCaseKind.CPU_EXHAUSTION, HostileCaseKind.TIMEOUT}:
        if not observation.timed_out:
            reasons.append("wall_clock_timeout_not_enforced")
        disposition = HostileDisposition.TERMINATED
    elif kind is HostileCaseKind.CANCELLATION:
        if not observation.cancelled:
            reasons.append("cancellation_not_observed")
        disposition = HostileDisposition.TERMINATED
    elif kind in {
        HostileCaseKind.RUNNER_CRASH,
        HostileCaseKind.SIGNER_CRASH,
        HostileCaseKind.WORKER_CRASH,
        HostileCaseKind.CUSTODY_CRASH,
        HostileCaseKind.ANCHOR_CRASH,
    }:
        if observation.exit_code in {None, 0}:
            reasons.append("crash_not_observed")
        disposition = HostileDisposition.CONTAINED
    elif kind in {
        HostileCaseKind.EVIDENCE_CORRUPTION,
        HostileCaseKind.LOG_INJECTION,
        HostileCaseKind.ORPHAN_REAP,
    }:
        if not bool(observation.evidence.get("detected")):
            reasons.append("adversarial_condition_not_detected")
        disposition = HostileDisposition.DETECTED
    elif kind in {HostileCaseKind.PROCFS_INSPECTION, HostileCaseKind.MOUNT_PROBING}:
        if not bool(observation.evidence.get("sensitive_data_absent")):
            reasons.append("sensitive_data_visible")
        disposition = HostileDisposition.CONTAINED

    return HostileCaseDecision(
        case_id=observation.case_id,
        kind=observation.kind,
        disposition=HostileDisposition.FAILED if reasons else disposition,
        passed=not reasons,
        reasons=tuple(reasons),
    )


class TargetSourceFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    rule: str
    detail: str


class TargetSourceScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    file_count: int
    total_bytes: int
    findings: tuple[TargetSourceFinding, ...]


def scan_target_source(
    root: "Path",
    *,
    max_files: int = 50_000,
    max_bytes: int = 2 * 1024 * 1024 * 1024,
) -> TargetSourceScanResult:
    """Detect source features that require explicit isolated handling.

    The scan does not execute package managers, Git hooks, build scripts, or nested
    archives. Findings are fail-closed until a versioned adapter policy explicitly
    allows and isolates the feature.
    """
    import json
    from pathlib import Path

    resolved = Path(root).resolve(strict=True)
    findings: list[TargetSourceFinding] = []
    file_count = 0
    total_bytes = 0
    for path in sorted(resolved.rglob("*")):
        if path.is_symlink():
            findings.append(TargetSourceFinding(path=path.relative_to(resolved).as_posix(), rule="symlink", detail="source symlink"))
            continue
        if not path.is_file():
            continue
        file_count += 1
        size = path.stat().st_size
        total_bytes += size
        relative = path.relative_to(resolved).as_posix()
        if file_count > max_files:
            findings.append(TargetSourceFinding(path=".", rule="file_count_limit", detail=str(file_count)))
            break
        if total_bytes > max_bytes:
            findings.append(TargetSourceFinding(path=".", rule="source_size_limit", detail=str(total_bytes)))
            break
        lower = path.name.lower()
        if relative == ".gitmodules":
            findings.append(TargetSourceFinding(path=relative, rule="git_submodule", detail="submodule configuration requires explicit policy"))
        if relative.startswith(".git/"):
            findings.append(TargetSourceFinding(path=relative, rule="git_metadata", detail="Git metadata is not accepted in submitted build context"))
        if lower in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"} and size <= 4 * 1024 * 1024:
            text = path.read_text(encoding="utf-8", errors="replace")
            if "file:../" in text or "file:/" in text or "git+ssh://" in text:
                findings.append(TargetSourceFinding(path=relative, rule="poisoned_lockfile", detail="local or SSH dependency reference"))
        if lower == "package.json" and size <= 1024 * 1024:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                findings.append(TargetSourceFinding(path=relative, rule="invalid_package_manifest", detail="package.json is not valid JSON"))
            else:
                scripts = document.get("scripts") if isinstance(document, dict) else None
                if isinstance(scripts, dict):
                    for name in ("preinstall", "install", "postinstall", "prepare"):
                        value = scripts.get(name)
                        if isinstance(value, str) and value.strip():
                            findings.append(TargetSourceFinding(path=relative, rule="package_install_script", detail=f"{name}:{value[:160]}"))
        if lower in {"setup.py", "setup.cfg"}:
            findings.append(TargetSourceFinding(path=relative, rule="python_build_script", detail="legacy Python build script requires isolated execution policy"))
        if size <= 1024:
            payload = path.read_bytes()
            if payload.startswith(b"version https://git-lfs.github.com/spec/v1"):
                findings.append(TargetSourceFinding(path=relative, rule="git_lfs_pointer", detail="unresolved Git LFS pointer"))
    return TargetSourceScanResult(
        valid=not findings,
        file_count=file_count,
        total_bytes=total_bytes,
        findings=tuple(findings),
    )
