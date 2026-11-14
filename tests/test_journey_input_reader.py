"""Public preparation input custody and literal build-platform parsing."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from echo_certification_forge.supply_chain import ImageAdmissionDenied, pinned_dockerfile_base_digests

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def preparer():
    spec = importlib.util.spec_from_file_location(
        "bounded_journey_preparer", ROOT / "scripts/prepare_journey_image_admission.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("payload", [b"", b"public\r\nbytes\x1a", b"x" * (4 * 1024 * 1024)])
def test_preparation_reads_exact_regular_bytes(preparer, tmp_path, payload):
    path = tmp_path / "public-input"
    path.write_bytes(payload)
    assert preparer.read_bounded(path) == payload


@pytest.mark.parametrize("kind", ["directory", "oversize", "hardlink"])
def test_preparation_denies_noncanonical_input_before_read(preparer, tmp_path, kind):
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"x" * (4 * 1024 * 1024 + 1) if kind == "oversize" else b"public")
        if kind == "hardlink":
            try:
                os.link(path, tmp_path / "alias")
            except OSError:
                pytest.skip("filesystem does not support hardlink fixture")
    with pytest.raises(ImageAdmissionDenied):
        preparer.read_bounded(path)


def test_preparation_checks_descriptor_nlink_after_open(preparer, tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"public")
    real_open = preparer.os.open
    alias = tmp_path / "alias"
    def open_then_link(selected, flags, *args, **kwargs):
        descriptor = real_open(selected, flags, *args, **kwargs)
        os.link(path, alias)
        return descriptor
    monkeypatch.setattr(preparer.os, "open", open_then_link)
    with pytest.raises(ImageAdmissionDenied):
        preparer.read_bounded(path)
    assert alias.exists()


def test_preparation_detects_mutation_during_read(preparer, tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"public")
    before = path.stat()
    real_fstat = preparer.os.fstat
    calls = 0
    def changing_fstat(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_bytes(b"changed public input")
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        return real_fstat(descriptor)
    monkeypatch.setattr(preparer.os, "fstat", changing_fstat)
    with pytest.raises(ImageAdmissionDenied):
        preparer.read_bounded(path)
    assert calls >= 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX open-file replacement semantics")
def test_preparation_denies_replaced_path_before_read(preparer, tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"public")
    real_open = preparer.os.open
    def replacing_open(selected, flags, *args, **kwargs):
        descriptor = real_open(selected, flags, *args, **kwargs)
        path.rename(tmp_path / "original")
        path.write_bytes(b"replacement")
        return descriptor
    monkeypatch.setattr(preparer.os, "open", replacing_open)
    with pytest.raises(ImageAdmissionDenied):
        preparer.read_bounded(path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="host lacks POSIX FIFO fixtures")
@pytest.mark.parametrize("swap_after_precheck", [False, True])
def test_preparation_fifo_cannot_block_reader(tmp_path, swap_after_precheck):
    path = tmp_path / "input"
    if swap_after_precheck:
        path.write_bytes(b"public")
    else:
        os.mkfifo(path)
    code = (
        "import importlib.util,os,sys\nfrom pathlib import Path\n"
        "from echo_certification_forge.supply_chain import ImageAdmissionDenied\n"
        "spec=importlib.util.spec_from_file_location('reader',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n"
        "p=Path(sys.argv[2]);real_open=module.os.open\n"
        "def swapped(selected,flags,*args,**kwargs):\n"
        " if sys.argv[3]=='1':\n"
        "  p.unlink();os.mkfifo(p)\n"
        " assert flags & os.O_NONBLOCK\n"
        " assert flags & os.O_NOFOLLOW\n"
        " return real_open(selected,flags,*args,**kwargs)\n"
        "module.os.open=swapped\n"
        "try:module.read_bounded(p)\n"
        "except (ImageAdmissionDenied,OSError):sys.exit(0)\n"
        "sys.exit(9)\n"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", code, str(ROOT / "scripts/prepare_journey_image_admission.py"),
         str(path), "1" if swap_after_precheck else "0"],
        capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("platform", [
    "--platform=linux/arm64", "--platform=$BUILDPLATFORM",
    "--platform=" + chr(36) + "{TARGETPLATFORM}", "--platform=linux/amd64 --privileged",
])
def test_dockerfile_parser_denies_nonliteral_or_extra_platform_options(platform):
    with pytest.raises(ImageAdmissionDenied, match="dockerfile_base_not_pinned"):
        pinned_dockerfile_base_digests(f"FROM {platform} python@sha256:" + "a" * 64)


def test_dockerfile_parser_accepts_only_the_actual_literal_amd64_pin():
    digest = "sha256:" + "a" * 64
    assert pinned_dockerfile_base_digests(
        "FROM --platform=linux/amd64 python@" + digest + " AS runtime\n") == (digest,)
