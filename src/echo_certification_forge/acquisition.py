"""Target acquisition — normalize a target spec into an isolated on-disk source tree.

Targets are hostile until proven otherwise (SPEC 2.x). Acquisition therefore executes NOTHING from
the target: git clone runs with hooks disabled and the file:// protocol denied (blocks malicious
submodule/hook execution and local-path exfiltration), and no build/install/lifecycle scripts run.
The acquired tree is then handed to the RunExecutor whose hostile/supply-chain gates scan it before
any journey execution.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_bytes


class AcquisitionError(RuntimeError):
    """Fail-closed acquisition failure."""


@dataclass(frozen=True, slots=True)
class AcquiredTarget:
    source_root: Path
    target_type: str
    canonical_ref: str
    artifact_sha256: str


def _tree_digest(root: Path) -> str:
    """Deterministic content digest of a source tree: sha256 over sorted (relpath, sha256(bytes))."""
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        entries.append(f"{rel}:{sha256_bytes(path.read_bytes())}")
    return sha256_bytes("\n".join(entries).encode("utf-8"))


def acquire_target(spec: dict, dest: Path, *, clone_timeout_s: float = 120.0) -> AcquiredTarget:
    """Acquire a target into (or referencing) an isolated tree and compute its immutable identity.

    spec:
      {"type": "local", "path": "<abs dir>"}     -> scans the directory in place (read-only use)
      {"type": "git", "url": "<url>", "ref"?: "<branch/tag/sha>"}  -> shallow clone, hooks disabled
    """
    target_type = str(spec.get("type", "")).strip()

    if target_type == "local":
        raw = spec.get("path")
        if not raw:
            raise AcquisitionError("local target requires 'path'")
        root = Path(raw).resolve(strict=False)
        if not root.is_dir():
            raise AcquisitionError(f"local target path is not a directory: {root}")
        return AcquiredTarget(root, "local", root.as_posix(), _tree_digest(root))

    if target_type == "git":
        url = str(spec.get("url", "")).strip()
        if not url:
            raise AcquisitionError("git target requires 'url'")
        ref = str(spec.get("ref", "")).strip()
        dest = dest.resolve(strict=False)
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "git",
            "-c", "core.hooksPath=/dev/null",     # never run target-supplied hooks
            "-c", "protocol.file.allow=never",    # block file:// submodule/exfil tricks
            "-c", "advice.detachedHead=false",
            "clone", "--depth", "1", "--no-tags", "--single-branch",
        ]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", url, str(dest)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=clone_timeout_s, shell=False, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AcquisitionError(f"git clone failed: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise AcquisitionError(f"git clone exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        # remove the .git dir so no repo metadata/hooks enter the scanned build context
        git_dir = dest / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir, ignore_errors=True)
        canonical = f"{url}@{ref}" if ref else url
        return AcquiredTarget(dest, "git", canonical, _tree_digest(dest))

    raise AcquisitionError(f"unsupported target type: {target_type!r}")
