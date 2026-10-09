"""Measure public execution inputs; never inspect environment values or signing material.

The optional operator-owned profile selects one advertised journey and sandbox. Its
identity is derived again from the actual execution inputs at the worker boundary.
This module does not attest that an image was launched or that a journey passed.
"""
from __future__ import annotations

import dataclasses
import importlib.metadata
import json
import logging
import math
import os
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_bytes, sha256_json
from .models import EnvironmentIdentity
from .policy import RuleManifest
from .sandbox import DEFAULT_IMAGE, DockerSandbox

_ROOT = Path(__file__).resolve().parents[2]
_LOG = logging.getLogger(__name__)
_SCHEMA = "certforge.runtime.v1"
_IMAGE = re.compile(r"(?:[^@\s]+@)?sha256:([0-9a-f]{64})\Z")
_FIELDS = frozenset({"image", "memory", "cpus", "pids_limit", "tmpfs_size", "timeout_s", "user"})


def _sandbox_inputs(sandbox: DockerSandbox | None) -> dict:
    if sandbox is None:
        return {"isolation": "none", "network": "host", "production": False}
    if sandbox.extra_env:
        raise ValueError("runtime_extra_env_not_supported")
    if not isinstance(sandbox.image, str) or not _IMAGE.fullmatch(sandbox.image):
        raise ValueError("runtime_image_requires_exact_digest")
    for value in (sandbox.memory, sandbox.tmpfs_size):
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*[kmg]?", value):
            raise ValueError("runtime_resource_limit_invalid")
    for value in (sandbox.cpus, sandbox.timeout_s):
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("runtime_resource_limit_invalid") from exc
        if isinstance(value, bool) or not math.isfinite(number) or number <= 0:
            raise ValueError("runtime_resource_limit_invalid")
    if type(sandbox.pids_limit) is not int or sandbox.pids_limit < 1:
        raise ValueError("runtime_resource_limit_invalid")
    if not isinstance(sandbox.user, str) or not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", sandbox.user):
        raise ValueError("runtime_nonroot_user_required")
    return {
        "isolation": "docker", "image": sandbox.image,
        "image_identifier_kind": (
            "docker_content_id" if sandbox.image.startswith("sha256:") else "repository_digest"
        ),
        "memory": sandbox.memory, "memory_swap": sandbox.memory,
        "cpus": str(sandbox.cpus), "pids_limit": sandbox.pids_limit,
        "tmpfs_size": sandbox.tmpfs_size, "timeout_s": float(sandbox.timeout_s),
        "user": sandbox.user, "docker": list(sandbox.docker),
        "network": "none", "read_only": True, "source_mount": "/work:ro",
        "tmpfs_options": ["rw", "noexec", "nosuid"],
        "cap_drop": "ALL", "no_new_privileges": True,
    }


def _journey(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= 32:
        raise ValueError("runtime_journey_invalid")
    if any(not isinstance(item, str) or not item or "\x00" in item for item in value):
        raise ValueError("runtime_journey_invalid")
    return tuple(value)


@dataclass(frozen=True)
class RuntimeProfile:
    sandbox: DockerSandbox
    journey: tuple[str, ...] | None = None

    def check_execution(self, sandbox: DockerSandbox | None, journey: list[str] | None) -> None:
        if _sandbox_inputs(sandbox) != _sandbox_inputs(self.sandbox) or _journey(journey) != self.journey:
            raise ValueError("runtime_profile_mismatch")


def load_runtime_profile(
    path: Path | None = None, *, image: str | None = None, docker: tuple[str, ...] | None = None,
) -> RuntimeProfile:
    """Read only an explicitly selected public profile; unknown fields fail closed."""
    selected = path or os.environ.get("ECHO_CERTFORGE_RUNTIME_PROFILE")
    raw = {}
    if selected:
        try:
            raw = json.loads(Path(selected).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("runtime_profile_unreadable") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != _SCHEMA:
            raise ValueError("runtime_profile_schema_invalid")
        if set(raw) - {"schema_version", "sandbox", "journey"}:
            raise ValueError("runtime_profile_fields_invalid")
    config = raw.get("sandbox", {})
    if not isinstance(config, dict) or set(config) - _FIELDS:
        raise ValueError("runtime_profile_sandbox_fields_invalid")
    config = dict(config)
    configured_image = image or os.environ.get("ECHO_CERTFORGE_SANDBOX_IMAGE")
    if configured_image and "image" in config and config["image"] != configured_image:
        raise ValueError("runtime_profile_image_mismatch")
    config.setdefault("image", configured_image or DEFAULT_IMAGE)
    command = docker or tuple(os.environ.get("ECHO_CERTFORGE_SANDBOX_DOCKER", "docker").split())
    sandbox = DockerSandbox(**config, docker=command)
    _sandbox_inputs(sandbox)
    return RuntimeProfile(sandbox, _journey(raw.get("journey")))


def _harness_digest(source_root: Path) -> str:
    """Hash the explicit executable package and dependency declarations, never var/ or keys."""
    package = source_root / "src/echo_certification_forge"
    paths = sorted(package.rglob("*.py"))
    if not paths or not (package / "executor.py").is_file():
        raise ValueError("runtime_harness_source_missing")
    paths += [source_root / "pyproject.toml", source_root / "images/requirements.lock"]
    try:
        return sha256_json({
            path.relative_to(source_root).as_posix(): sha256_bytes(path.read_bytes())
            for path in paths
        })
    except OSError as exc:
        raise ValueError("runtime_harness_source_unreadable") from exc


def measured_environment(
    *, manifest: RuleManifest, sandbox: DockerSandbox | None = None,
    journey: list[str] | tuple[str, ...] | None = None,
    adapter_set_sha256: str | None = None,
    adapter_execution_profile_sha256: str | None = None,
    source_root: Path = _ROOT,
) -> EnvironmentIdentity:
    config = _sandbox_inputs(sandbox)
    plan = _journey(journey)
    try:
        executable_sha256 = sha256_bytes(Path(sys.executable).read_bytes())
        packages = {
            name: importlib.metadata.version(name)
            for name in ("cryptography", "fastapi", "pydantic", "uvicorn")
        }
    except (OSError, importlib.metadata.PackageNotFoundError) as exc:
        raise ValueError("runtime_metadata_unavailable") from exc
    runtime = {
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(), "os": platform.system(),
        "kernel": platform.release(), "machine": platform.machine(),
        "python_executable_sha256": executable_sha256,
        "packages": packages,
        "sandbox": config,
    }
    adapters = {
        "adapter_set_sha256": adapter_set_sha256,
        "verified_execution_profile_sha256": adapter_execution_profile_sha256,
        "mode": "verified_adapter_bundle" if adapter_execution_profile_sha256 else "no_verified_adapter_bundle",
    }
    environment = EnvironmentIdentity(
        runner_image_sha256=(
            _IMAGE.fullmatch(sandbox.image).group(1) if sandbox else sha256_json(runtime)
        ),
        adapter_set_sha256=adapter_set_sha256 or sha256_json([]),
        test_plan_sha256=sha256_json({
            "schema_version": _SCHEMA, "journey": list(plan) if plan else None,
            "mandatory_rules": [dataclasses.asdict(rule) for rule in manifest.rules],
        }),
        policy_sha256=manifest.digest,
        harness_sha256=_harness_digest(source_root),
        prompt_set_sha256=sha256_json({"component": "adapter_prompts", **adapters}),
        model_route_sha256=sha256_json({"component": "adapter_model_routes", **adapters}),
        os_runtime_sha256=sha256_json(runtime),
        egress_policy_sha256=sha256_json(config),
    )
    _LOG.debug("runtime_identity_measured", extra={
        "environment_identity_digest": environment.identity_digest,
        "runner_image_sha256": environment.runner_image_sha256,
        "runtime_schema": _SCHEMA, "isolation": config["isolation"],
    })
    return environment
