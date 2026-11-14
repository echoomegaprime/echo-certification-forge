"""Synthetic public dependency bundles are parsed without executing package code."""
import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def verifier():
    spec = importlib.util.spec_from_file_location(
        "fielddesk_material_verifier", ROOT / "images/journey-fielddesk/verify_materials.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bundle(verifier, tmp_path, extras=(), manifest_change=False):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    pins = {name: _sha(name.encode()) for name in verifier.EXPECTED_INPUTS}
    manifest = json.dumps({"version": 1, "inputs": pins}, sort_keys=True).encode()
    actual_manifest = manifest + b" " if manifest_change else manifest
    archive = inputs / "frontend-dependencies.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for name, raw in [
            ("dependencies.json", actual_manifest),
            ("frontend/node_modules/typescript/bin/tsc", b"public inert fixture\n"),
        ]:
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            out.addfile(item, io.BytesIO(raw))
        for name, kind, link in extras:
            item = tarfile.TarInfo(name)
            if kind == "file":
                item.size = 4
                out.addfile(item, io.BytesIO(b"data"))
            else:
                item.type = {"hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE,
                             "symlink": tarfile.SYMTYPE}[kind]
                item.linkname = link
                out.addfile(item)
    lock = b"public locked dependency fixture\n"
    (inputs / "requirements.lock").write_bytes(lock)
    material = {
        "schema_version": "fielddesk.journey-materials.v1",
        "dependency_source_commit": verifier.TARGET,
        "inputs": pins,
        "python_requirements_sha256": _sha(lock),
        "dependencies_manifest_sha256": _sha(manifest),
        "frontend_archive": {"path": archive.name, "size_bytes": archive.stat().st_size,
                             "sha256": _sha(archive.read_bytes())},
    }
    (inputs / "materials.json").write_text(json.dumps(material), encoding="utf-8")
    return inputs, material


def test_valid_tiny_sealed_bundle_materializes_only_public_files(verifier, tmp_path):
    inputs, material = _bundle(verifier, tmp_path)
    output = tmp_path / "output"
    result = verifier.verify_and_extract(inputs, output)
    assert result["members"] == 2
    assert result["regular_bytes"] > 0
    assert result["materials_sha256"] == _sha((inputs / "materials.json").read_bytes())
    assert (output / "frontend/node_modules/typescript/bin/tsc").read_bytes() == b"public inert fixture\n"
    assert json.loads((output / "dependencies.json").read_bytes())["inputs"] == material["inputs"]


@pytest.mark.parametrize("change", ["archive", "archive_size", "lock", "manifest", "source", "input_set"])
def test_dependency_bundle_rejects_wrong_bound_material(verifier, tmp_path, change):
    inputs, material = _bundle(verifier, tmp_path, manifest_change=change == "manifest")
    if change == "archive":
        material["frontend_archive"]["sha256"] = "0" * 64
    elif change == "archive_size":
        material["frontend_archive"]["size_bytes"] += 1
    elif change == "lock":
        (inputs / "requirements.lock").write_bytes(b"changed lock")
    elif change == "source":
        material["dependency_source_commit"] = "f" * 40
    elif change == "input_set":
        material["inputs"]["unreviewed.lock"] = "a" * 64
    (inputs / "materials.json").write_text(json.dumps(material), encoding="utf-8")
    with pytest.raises(ValueError):
        verifier.verify_and_extract(inputs, tmp_path / "output")


@pytest.mark.parametrize(("name", "kind", "link"), [
    ("../outside", "file", ""),
    ("/absolute", "file", ""),
    ("unreviewed/extra", "file", ""),
    ("frontend/node_modules_spoof/extra", "file", ""),
    ("dependencies.json", "file", ""),
    ("frontend/node_modules/typescript/bin/tsc", "file", ""),
    ("frontend/node_modules/hard", "hardlink", "frontend/node_modules/typescript/bin/tsc"),
    ("frontend/node_modules/fifo", "fifo", ""),
    ("frontend/node_modules/escape", "symlink", "../../../../outside"),
])
def test_dependency_archive_refuses_unsafe_or_duplicate_members(
    verifier, tmp_path, name, kind, link
):
    sentinel = tmp_path / "outside"
    sentinel.write_bytes(b"outside sentinel must not change")
    inputs, _ = _bundle(verifier, tmp_path, extras=[(name, kind, link)])
    with pytest.raises(ValueError):
        verifier.verify_and_extract(inputs, tmp_path / "output")
    assert sentinel.read_bytes() == b"outside sentinel must not change"
