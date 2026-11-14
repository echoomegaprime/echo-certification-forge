"""Public operator bindings for dependency-complete, source-specific sandboxes.

This is configuration selection, not image qualification or a signing authority.
Only an independently admitted operator release may install this configuration.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .canonical import sha256_bytes, sha256_json
from .sandbox import DockerSandbox


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _dependency_sha256(root: Path, name: str) -> str:
    """Bounded regular-file read through stable, no-follow POSIX directory handles."""
    if (
        any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ValueError("runtime_binding_dependency_mismatch")
    root = Path(root)
    if ".." in root.parts:
        raise ValueError("runtime_binding_dependency_mismatch")
    if not root.is_absolute():
        root = Path.cwd() / root
    relative = PurePosixPath(name)
    if (not name or "\\" in name or ":" in name or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ValueError("runtime_binding_dependency_mismatch")
    descriptors: list[int] = []
    directories: list[tuple[int | None, str, int, tuple[int, ...]]] = []
    nofollow = os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
    try:
        anchor = root.anchor
        before = os.stat(anchor, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("runtime_binding_dependency_mismatch")
        current = os.open(anchor, directory_flags)
        descriptors.append(current)
        actual = os.fstat(current)
        if _directory_identity(actual) != _directory_identity(before):
            raise ValueError("runtime_binding_dependency_mismatch")
        directories.append((None, anchor, current, _directory_identity(actual)))
        for component in (*root.parts[1:], *relative.parts[:-1]):
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError("runtime_binding_dependency_mismatch")
            parent = current
            current = os.open(component, directory_flags, dir_fd=parent)
            descriptors.append(current)
            actual = os.fstat(current)
            if _directory_identity(actual) != _directory_identity(before):
                raise ValueError("runtime_binding_dependency_mismatch")
            directories.append((parent, component, current, _directory_identity(actual)))
        leaf = relative.parts[-1]
        before = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("runtime_binding_dependency_mismatch")
        descriptor = os.open(leaf, os.O_RDONLY | nofollow, dir_fd=current)
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_size > 2 * 1024 * 1024
                or _file_identity(opened) != _file_identity(before)):
            raise ValueError("runtime_binding_dependency_mismatch")
        content = bytearray()
        while len(content) <= 2 * 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 2 * 1024 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        current_path = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if (len(content) > 2 * 1024 * 1024 or len(content) != opened.st_size
                or _file_identity(after) != _file_identity(opened)
                or _file_identity(current_path) != _file_identity(opened)):
            raise ValueError("runtime_binding_dependency_mismatch")
        for parent, component, descriptor, identity in directories:
            path_stat = (os.stat(component, follow_symlinks=False) if parent is None
                         else os.stat(component, dir_fd=parent, follow_symlinks=False))
            if (_directory_identity(os.fstat(descriptor)) != identity
                    or _directory_identity(path_stat) != identity):
                raise ValueError("runtime_binding_dependency_mismatch")
        return sha256_bytes(bytes(content))
    except (OSError, TypeError, NotImplementedError, OverflowError) as exc:
        raise ValueError("runtime_binding_dependency_mismatch") from exc
    finally:
        close_error = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as exc:
                close_error = exc
        if close_error is not None:
            raise ValueError("runtime_binding_dependency_mismatch") from close_error


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
        for name, expected in self.dependencies:
            if _dependency_sha256(root, name) != expected:
                raise ValueError("runtime_binding_dependency_mismatch")


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
