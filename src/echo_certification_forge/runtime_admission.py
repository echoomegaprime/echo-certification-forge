"""Public operator bindings for dependency-complete, source-specific sandboxes.

This is configuration selection, not image qualification or a signing authority.
Only an independently admitted operator release may install this configuration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .canonical import sha256_bytes, sha256_json
from .sandbox import DockerSandbox


@dataclass(frozen=True)
class RuntimeBinding:
    binding_id: str
    tenant_id: str
    project_id: str
    repository: str
    source_commit: str
    dependencies: tuple[tuple[str, str], ...]
    sandbox: DockerSandbox
    journey: tuple[str, ...]
    digest: str

    def check_target(self, target: dict) -> None:
        if (target.get("type") != "git" or target.get("url") != self.repository
                or target.get("ref") != self.source_commit
                or target.get("source_commit", self.source_commit) != self.source_commit):
            raise ValueError("runtime_binding_target_mismatch")

    def check_source(self, root: Path, source_commit: str | None) -> None:
        if source_commit != self.source_commit:
            raise ValueError("runtime_binding_source_mismatch")
        root = root.resolve(strict=True)
        for name, expected in self.dependencies:
            path = root.joinpath(*PurePosixPath(name).parts)
            # Reject links even when they resolve within the acquired tree.
            if any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents):
                raise ValueError("runtime_binding_dependency_mismatch")
            try:
                if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
                    raise ValueError("runtime_binding_dependency_mismatch")
                with path.open("rb") as stream:
                    content = stream.read(2 * 1024 * 1024 + 1)
                if len(content) > 2 * 1024 * 1024 or sha256_bytes(content) != expected:
                    raise ValueError("runtime_binding_dependency_mismatch")
            except OSError as exc:
                raise ValueError("runtime_binding_dependency_mismatch") from exc


def parse_bindings(raw: object, *, docker: tuple[str, ...], sandbox_fields: frozenset[str],
                   validate_sandbox, validate_journey) -> tuple[RuntimeBinding, ...]:
    if not isinstance(raw, list) or len(raw) > 128:
        raise ValueError("runtime_bindings_invalid")
    result = []
    identities = set()
    names = set()
    fields = {"binding_id", "tenant_id", "project_id", "repository", "source_commit",
              "dependencies", "sandbox", "journey"}
    for item in raw:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("runtime_binding_fields_invalid")
        for key in ("binding_id", "tenant_id", "project_id"):
            if not isinstance(item[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item[key]):
                raise ValueError("runtime_binding_identity_invalid")
        repo = item["repository"]
        if not isinstance(repo, str) or len(repo) > 2048:
            raise ValueError("runtime_binding_repository_invalid")
        uri = urlsplit(repo)
        if uri.scheme != "https" or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment:
            raise ValueError("runtime_binding_repository_invalid")
        if not isinstance(item["source_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", item["source_commit"]):
            raise ValueError("runtime_binding_commit_invalid")
        deps = item["dependencies"]
        if not isinstance(deps, dict) or not 1 <= len(deps) <= 32:
            raise ValueError("runtime_binding_dependencies_invalid")
        for name, digest in deps.items():
            if (not isinstance(name, str) or not name or len(name) > 256 or "\\" in name or ":" in name
                    or any(ord(c) < 32 for c in name)
                    or PurePosixPath(name).is_absolute() or any(p in {"", ".", ".."} for p in name.split("/"))
                    or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("runtime_binding_dependencies_invalid")
        config = item["sandbox"]
        if not isinstance(config, dict) or "image" not in config or set(config) - sandbox_fields:
            raise ValueError("runtime_binding_sandbox_invalid")
        sandbox = DockerSandbox(**config, docker=docker)
        validate_sandbox(sandbox)
        journey = validate_journey(item["journey"])
        if journey is None:
            raise ValueError("runtime_binding_journey_required")
        identity = (item["tenant_id"], item["project_id"], repo, item["source_commit"])
        if identity in identities or item["binding_id"] in names:
            raise ValueError("runtime_binding_duplicate")
        identities.add(identity)
        names.add(item["binding_id"])
        result.append(RuntimeBinding(item["binding_id"], item["tenant_id"], item["project_id"], repo,
                                     item["source_commit"], tuple(sorted(deps.items())), sandbox, journey,
                                     sha256_json(item)))
    return tuple(result)
