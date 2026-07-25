"""Target acquisition — normalize a target spec into an isolated on-disk source tree.

Targets are hostile until proven otherwise (SPEC 2.x). Acquisition therefore executes NOTHING from
the target: git clone runs with hooks disabled and the file:// protocol denied (blocks malicious
submodule/hook execution and local-path exfiltration), no build/install/lifecycle scripts run, and
OCI images are pulled by IMMUTABLE DIGEST ONLY over the registry HTTP API (mutable tags are
rejected outright; every manifest and blob byte is hash-verified against its declared digest and
nothing is extracted or executed). The acquired tree is then handed to the RunExecutor whose
hostile/supply-chain gates scan it before any journey execution.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
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


_OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OCI_NAME_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
_OCI_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
_OCI_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_OCI_MAX_BLOB_BYTES = 512 * 1024 * 1024
_OCI_INDEX_MEDIA_TYPES = frozenset(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)


def _tree_digest(root: Path) -> str:
    """Deterministic content digest of a source tree: sha256 over sorted (relpath, sha256(bytes))."""
    entries: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        entries.append(f"{rel}:{sha256_bytes(path.read_bytes())}")
    return sha256_bytes("\n".join(entries).encode("utf-8"))


def _oci_registry_base(repository: str) -> tuple[str, str]:
    """Split ``[http(s)://]host[:port]/name...`` into (base_url, name) — fail-closed on junk."""
    raw = repository.strip()
    scheme = "https"
    if raw.startswith("https://"):
        raw = raw[len("https://") :]
    elif raw.startswith("http://"):
        # Explicit opt-in only (hermetic test registries); the default is always TLS.
        scheme = "http"
        raw = raw[len("http://") :]
    host, sep, name = raw.partition("/")
    if not host or not sep or not name:
        raise AcquisitionError("oci repository must be '[scheme://]host[:port]/name'")
    if not _OCI_NAME_RE.match(name):
        raise AcquisitionError(f"oci repository name is not a valid OCI name: {name!r}")
    return f"{scheme}://{host}", name


def _oci_fetch(url: str, accept: str, expected_digest: str, limit: int, timeout_s: float) -> bytes:
    """Fetch a registry object and verify its bytes hash EXACTLY to the expected digest."""
    request = urllib.request.Request(url, headers={"Accept": accept}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:  # noqa: S310
            body = response.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise AcquisitionError(f"oci fetch failed: {type(exc).__name__}") from exc
    if len(body) > limit:
        raise AcquisitionError("oci object exceeds size limit")
    actual = f"sha256:{sha256_bytes(body)}"
    if actual != expected_digest:
        raise AcquisitionError(
            f"oci digest mismatch: expected {expected_digest}, got {actual}"
        )
    return body


def _oci_write_blob(blobs_dir: Path, digest: str, body: bytes) -> None:
    path = blobs_dir / digest.split(":", 1)[1]
    path.write_bytes(body)


def _acquire_oci(spec: dict, dest: Path, timeout_s: float) -> AcquiredTarget:
    """Pull an OCI image by immutable digest into an OCI image layout — verify everything.

    * The spec MUST pin a ``sha256:...`` manifest digest; a mutable ``tag`` key (or a
      missing/malformed digest) is rejected outright — the control plane never trusts a
      tag that a registry could re-point after certification.
    * The manifest bytes, every referenced child manifest (image index), the config blob
      and every layer blob are fetched by digest and hash-verified before being written.
    * Nothing is extracted, decompressed, or executed — the layout is inert evidence for
      the executor's scanning gates.
    * ``artifact_sha256`` is the BARE manifest digest hex, preserving the image's native
      registry identity so a webhook-declared image digest reconciles exactly.
    """
    if "tag" in spec:
        raise AcquisitionError("oci target must be pinned by immutable digest, never a tag")
    raw_digest = str(spec.get("digest", "")).strip()
    if not _OCI_DIGEST_RE.match(raw_digest):
        raise AcquisitionError("oci target requires 'digest' of the form sha256:<64 hex>")
    repository = str(spec.get("repository", "")).strip()
    if not repository:
        raise AcquisitionError("oci target requires 'repository'")
    base, name = _oci_registry_base(repository)

    dest = dest.resolve(strict=False)
    if dest.exists():
        shutil.rmtree(dest)
    blobs_dir = dest / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True, exist_ok=True)

    manifest_bytes = _oci_fetch(
        f"{base}/v2/{name}/manifests/{raw_digest}",
        _OCI_MANIFEST_ACCEPT,
        raw_digest,
        _OCI_MAX_MANIFEST_BYTES,
        timeout_s,
    )
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise AcquisitionError("oci manifest is not valid JSON") from exc
    _oci_write_blob(blobs_dir, raw_digest, manifest_bytes)

    image_manifests: list[dict] = []
    if manifest.get("mediaType") in _OCI_INDEX_MEDIA_TYPES or "manifests" in manifest:
        for entry in manifest.get("manifests", []):
            child_digest = str(entry.get("digest", ""))
            if not _OCI_DIGEST_RE.match(child_digest):
                raise AcquisitionError("oci index references a non-sha256 child manifest")
            child_bytes = _oci_fetch(
                f"{base}/v2/{name}/manifests/{child_digest}",
                _OCI_MANIFEST_ACCEPT,
                child_digest,
                _OCI_MAX_MANIFEST_BYTES,
                timeout_s,
            )
            try:
                child = json.loads(child_bytes)
            except ValueError as exc:
                raise AcquisitionError("oci child manifest is not valid JSON") from exc
            _oci_write_blob(blobs_dir, child_digest, child_bytes)
            image_manifests.append(child)
    else:
        image_manifests.append(manifest)

    for image in image_manifests:
        descriptors = [image.get("config", {})] + list(image.get("layers", []))
        for descriptor in descriptors:
            blob_digest = str(descriptor.get("digest", ""))
            if not _OCI_DIGEST_RE.match(blob_digest):
                raise AcquisitionError("oci manifest references a non-sha256 blob digest")
            blob_bytes = _oci_fetch(
                f"{base}/v2/{name}/blobs/{blob_digest}",
                "application/octet-stream",
                blob_digest,
                _OCI_MAX_BLOB_BYTES,
                timeout_s,
            )
            _oci_write_blob(blobs_dir, blob_digest, blob_bytes)

    (dest / "oci-layout").write_text(
        json.dumps({"imageLayoutVersion": "1.0.0"}, sort_keys=True) + "\n", encoding="utf-8"
    )
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": str(
                    manifest.get("mediaType", "application/vnd.oci.image.manifest.v1+json")
                ),
                "digest": raw_digest,
                "size": len(manifest_bytes),
            }
        ],
    }
    (dest / "index.json").write_text(
        json.dumps(index, sort_keys=True) + "\n", encoding="utf-8"
    )
    canonical = f"{repository}@{raw_digest}"
    # The image's NATIVE identity — the bare manifest digest — is the artifact identity,
    # exactly matching the digest a registry webhook declares.
    return AcquiredTarget(dest, "oci", canonical, raw_digest.split(":", 1)[1])


def acquire_target(spec: dict, dest: Path, *, clone_timeout_s: float = 120.0) -> AcquiredTarget:
    """Acquire a target into (or referencing) an isolated tree and compute its immutable identity.

    spec:
      {"type": "local", "path": "<abs dir>"}     -> scans the directory in place (read-only use)
      {"type": "git", "url": "<url>", "ref"?: "<branch/tag/sha>"}  -> shallow clone, hooks disabled
      {"type": "oci", "repository": "[scheme://]host[:port]/name", "digest": "sha256:<64 hex>"}
          -> digest-pinned registry pull into an inert OCI image layout (tags rejected)
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

    if target_type == "oci":
        return _acquire_oci(spec, dest, clone_timeout_s)

    raise AcquisitionError(f"unsupported target type: {target_type!r}")
