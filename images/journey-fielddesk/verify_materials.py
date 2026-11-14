"""Validate only hash-bound public dependency material before offline installation."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import sys
import tarfile

EXPECTED_INPUTS = frozenset({
    "frontend/package.json", "frontend/pnpm-lock.yaml", "frontend/pnpm-workspace.yaml",
    "frontend/.npmrc", "backend/requirements.txt", "deploy/certification/requirements.lock",
})
TARGET = "290658c4be634af6dd308021d1946f737032c3cf"

def verify_and_extract(inputs: Path, output: Path) -> dict:
    material_bytes = (inputs / "materials.json").read_bytes()
    if len(material_bytes) > 65536:
        raise ValueError("materials_size")
    materials = json.loads(material_bytes)
    if (materials.get("schema_version") != "fielddesk.journey-materials.v1"
            or materials.get("dependency_source_commit") != TARGET
            or not isinstance(materials.get("inputs"), dict)
            or set(materials["inputs"]) != EXPECTED_INPUTS
            or any(not isinstance(v, str) or re.fullmatch("[0-9a-f]{64}", v) is None
                   for v in materials["inputs"].values())):
        raise ValueError("materials_identity")
    lock = (inputs / "requirements.lock").read_bytes()
    if len(lock) > 65536 or hashlib.sha256(lock).hexdigest() != materials["python_requirements_sha256"]:
        raise ValueError("python_lock_identity")
    archive = materials["frontend_archive"]
    if archive.get("path") != "frontend-dependencies.tar.gz":
        raise ValueError("archive_name")
    path = inputs / archive["path"]
    if (path.is_symlink() or not path.is_file()
            or type(archive.get("size_bytes")) is not int
            or not 0 < path.stat().st_size == archive["size_bytes"] <= 1024 * 1024 * 1024):
        raise ValueError("archive_size")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != archive["sha256"]:
        raise ValueError("archive_identity")
    output.mkdir(exist_ok=False)
    count = total = 0
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            count += 1
            name = member.name.rstrip("/")
            relative = PurePosixPath(name)
            if (count > 200000 or len(name) > 4096 or not name
                    or relative.is_absolute() or "\\" in name or ":" in name
                    or any(p in {"", ".", ".."} for p in name.split("/"))
                    or not (name == "dependencies.json" or name == "frontend"
                            or name == "frontend/node_modules"
                            or name.startswith("frontend/node_modules/"))
                    or member.islnk() or not (member.isdir() or member.isfile() or member.issym())):
                raise ValueError("archive_member")
            if name in seen:
                raise ValueError("archive_duplicate")
            seen.add(name)
            if member.issym():
                destination = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                if (not member.linkname or member.linkname.startswith("/")
                        or "\\" in member.linkname or ":" in member.linkname
                        or destination.startswith("../") or destination == ".."):
                    raise ValueError("archive_link")
            if member.isfile():
                total += member.size
                if member.size < 0 or total > 2 * 1024 * 1024 * 1024:
                    raise ValueError("archive_expansion")
            tar.extract(member, output, filter="data")
    raw = (output / "dependencies.json").read_bytes()
    if (len(raw) > 65536 or hashlib.sha256(raw).hexdigest()
            != materials["dependencies_manifest_sha256"]
            or json.loads(raw) != {"version": 1, "inputs": materials["inputs"]}):
        raise ValueError("dependency_manifest")
    modules = output / "frontend/node_modules"
    if not (modules / "typescript/bin/tsc").is_file():
        raise ValueError("dependency_layout")
    # Check all link resolutions after extraction; no package code is imported.
    for base, dirs, files in os.walk(output, followlinks=False):
        for name in (*dirs, *files):
            item = Path(base) / name
            if item.is_symlink() and not item.resolve(strict=True).is_relative_to(output.resolve()):
                raise ValueError("dependency_link_escape")
    return {"members": count, "regular_bytes": total, "materials_sha256": hashlib.sha256(material_bytes).hexdigest()}

if __name__ == "__main__":
    print(json.dumps(verify_and_extract(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
