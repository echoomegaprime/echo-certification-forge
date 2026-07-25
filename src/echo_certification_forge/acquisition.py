"""Target acquisition — normalize a target spec into an isolated on-disk source tree.

Targets are hostile until proven otherwise (SPEC 2.x). Acquisition therefore executes NOTHING from
the target: git clone runs with hooks disabled and the file:// protocol denied (blocks malicious
submodule/hook execution and local-path exfiltration), no build/install/lifecycle scripts run, and
OCI images are pulled by IMMUTABLE DIGEST ONLY over the registry HTTP API (mutable tags are
rejected outright; every manifest and blob byte is hash-verified against its declared digest).
The image rootfs is then materialized with a hardened extractor (whiteouts honored; traversal,
device nodes and unsafe names rejected; symlinks never created on the host) so scanning gates
see REAL image contents — but nothing from any target is ever executed in the control plane.
The acquired tree is handed to the RunExecutor whose hostile/supply-chain gates scan it before
any journey execution, and OCI journeys run only inside a sandbox pinned to the exact digest.
"""
from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

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
_OCI_MAX_EXTRACT_BYTES = 1024 * 1024 * 1024  # expanded-rootfs budget (decompression-bomb guard)
_OCI_SYMLINK_PLACEHOLDER = "@certforge-symlink:"
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


def _oci_safe_rel(name: str, *, kind: str) -> PurePosixPath | None:
    """Normalize a layer tar member path — fail closed on ANY escape vector.

    Backslashes and colons are rejected outright (on Windows they act as separators /
    drive designators and would let a hostile member path escape the rootfs), absolute
    paths are rejected, and any ``..`` component is rejected as traversal.
    """
    raw = name.strip()
    if "\\" in raw or ":" in raw:
        raise AcquisitionError(f"oci layer {kind} has an unsafe name: {raw!r}")
    if raw.startswith("/"):
        raise AcquisitionError(f"oci layer {kind} has an absolute path: {raw!r}")
    parts = [part for part in PurePosixPath(raw).parts if part != "."]
    if any(part == ".." for part in parts):
        raise AcquisitionError(f"oci layer {kind} escapes the rootfs (path traversal): {raw!r}")
    if not parts:
        return None
    return PurePosixPath(*parts)


def _oci_dest(rootfs: Path, rel: PurePosixPath) -> Path:
    """Resolve a verified-relative member path under the rootfs, defending in depth:
    even though this extractor NEVER materializes symlinks, the resolved parent must
    still real-path inside the rootfs before anything is written through it."""
    dest = rootfs.joinpath(*rel.parts)
    dest.parent.mkdir(parents=True, exist_ok=True)
    root_real = rootfs.resolve(strict=False)
    parent_real = dest.parent.resolve(strict=False)
    if root_real != parent_real and root_real not in parent_real.parents:
        raise AcquisitionError(f"oci layer member resolves outside the rootfs: {rel}")
    return dest


def _oci_remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def _oci_apply_layer(blob: bytes, rootfs: Path, budget: list[int]) -> None:
    """Apply ONE image layer diff onto the rootfs — safely.

    * whiteouts (``.wh.<name>`` / ``.wh..wh..opq``) are applied as deletions, never
      written into the rootfs;
    * device/char/block/fifo members are rejected (never materialized on the host);
    * symlink members are recorded as inert ``@certforge-symlink:<target>`` marker
      files — the control plane NEVER creates a real symlink, so no later member can
      traverse through one, and journeys run against the REAL image in the sandbox;
    * hardlink members are copied from their (rootfs-internal, traversal-checked)
      target;
    * a total extraction budget rejects decompression bombs.
    """
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise AcquisitionError("oci layer is not a readable tar archive") from exc
    with archive:
        for member in archive:
            rel = _oci_safe_rel(member.name, kind="member")
            if rel is None:
                continue
            base = rel.name
            if base == ".wh..wh..opq":
                target_dir = rootfs.joinpath(*rel.parent.parts)
                if target_dir.is_dir():
                    for child in target_dir.iterdir():
                        _oci_remove(child)
                continue
            if base.startswith(".wh."):
                victim = rel.parent / base[len(".wh."):]
                _oci_remove(rootfs.joinpath(*victim.parts))
                continue
            if member.ischr() or member.isblk() or member.isfifo():
                raise AcquisitionError(
                    f"oci layer contains a device/fifo node (refused): {member.name!r}"
                )
            dest = _oci_dest(rootfs, rel)
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                data = (_OCI_SYMLINK_PLACEHOLDER + member.linkname).encode("utf-8")
            elif member.islnk():
                link_rel = _oci_safe_rel(member.linkname, kind="hardlink target")
                source = rootfs.joinpath(*link_rel.parts) if link_rel is not None else None
                if source is None or not source.is_file():
                    raise AcquisitionError(
                        f"oci layer hardlink target missing or unsafe: {member.linkname!r}"
                    )
                data = source.read_bytes()
            elif member.isreg():
                handle = archive.extractfile(member)
                if handle is None:
                    raise AcquisitionError(f"oci layer member is unreadable: {member.name!r}")
                data = handle.read(_OCI_MAX_EXTRACT_BYTES + 1)
            else:
                raise AcquisitionError(
                    f"oci layer member has an unsupported type: {member.name!r}"
                )
            budget[0] -= len(data)
            if budget[0] < 0:
                raise AcquisitionError("oci rootfs exceeds the extraction size budget")
            _oci_remove(dest)
            dest.write_bytes(data)


def _acquire_oci(spec: dict, dest: Path, timeout_s: float) -> AcquiredTarget:
    """Pull an OCI image by immutable digest into an OCI image layout — verify everything.

    * The spec MUST pin a ``sha256:...`` manifest digest; a mutable ``tag`` key (or a
      missing/malformed digest) is rejected outright — the control plane never trusts a
      tag that a registry could re-point after certification.
    * The manifest bytes, every referenced child manifest (image index), the config blob
      and every layer blob are fetched by digest and hash-verified before being written.
    * The image rootfs is materialized SAFELY (whiteout semantics honored; path
      traversal, unsafe names, and device nodes rejected; symlinks never created on the
      host — recorded as inert markers; extraction budget enforced) so scanning gates
      see real image contents. Nothing from the image is executed in the control plane —
      journeys run only inside an isolated sandbox pinned to this exact digest.
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

    if len(image_manifests) != 1:
        raise AcquisitionError(
            "oci index must resolve to exactly ONE platform image for certification; "
            "pin the platform-specific image manifest digest"
        )

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

    # Materialize the REAL image rootfs (safely) so the executor's hostile/supply-chain
    # gates scan actual image contents — never opaque layer blobs. Nothing is executed;
    # journeys run only inside the sandbox against the digest-pinned image itself.
    rootfs = dest / "rootfs"
    rootfs.mkdir(parents=True, exist_ok=True)
    budget = [_OCI_MAX_EXTRACT_BYTES]
    image = image_manifests[0]
    for descriptor in image.get("layers", []):
        blob_digest = str(descriptor.get("digest", ""))
        blob_path = blobs_dir / blob_digest.split(":", 1)[1]
        _oci_apply_layer(blob_path.read_bytes(), rootfs, budget)

    canonical = f"{repository}@{raw_digest}"
    # The image's NATIVE identity — the bare manifest digest — is the artifact identity,
    # exactly matching the digest a registry webhook declares. The scanned source root is
    # the materialized rootfs; the verified OCI layout lives beside it as evidence.
    return AcquiredTarget(rootfs, "oci", canonical, raw_digest.split(":", 1)[1])


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
