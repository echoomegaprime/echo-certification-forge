"""OCI extraction must not allocate the entire expanded-rootfs allowance."""
from __future__ import annotations

import io
from pathlib import Path
import tarfile

import pytest

from echo_certification_forge.acquisition import AcquisitionError, _oci_apply_layer


def layer(entries: dict[str, bytes], *, hardlinks=()) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        for name, target in hardlinks:
            member = tarfile.TarInfo(name)
            member.type = tarfile.LNKTYPE
            member.linkname = target
            archive.addfile(member)
    return buffer.getvalue()


def test_tiny_member_uses_bounded_reads_and_closes_input(tmp_path, monkeypatch):
    original_read = tarfile.ExFileObject.read
    opened = []
    sizes = []

    def bounded_read(handle, size=-1):
        opened.append(handle)
        sizes.append(size)
        assert 0 < size <= 1024 * 1024, "read exceeds the bounded copy buffer"
        return original_read(handle, size)

    monkeypatch.setattr(tarfile.ExFileObject, "read", bounded_read)
    budget = [1024 * 1024 * 1024]
    _oci_apply_layer(layer({"app/tiny.txt": b"tiny"}), tmp_path, budget)
    assert (tmp_path / "app/tiny.txt").read_bytes() == b"tiny"
    assert budget == [1024 * 1024 * 1024 - 4]
    assert sizes and all(handle.closed for handle in opened)


@pytest.mark.parametrize("remaining", [0, 3])
def test_declared_oversize_rejected_before_read_or_replacement(tmp_path, monkeypatch, remaining):
    destination = tmp_path / "existing.txt"
    destination.write_bytes(b"original")

    def no_read(*args, **kwargs):
        raise AssertionError("oversize member was read")

    monkeypatch.setattr(tarfile.ExFileObject, "read", no_read)
    budget = [remaining]
    with pytest.raises(AcquisitionError, match="extraction size budget"):
        _oci_apply_layer(layer({"existing.txt": b"four"}), tmp_path, budget)
    assert destination.read_bytes() == b"original"
    assert budget == [remaining]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["existing.txt"]


def test_exact_remaining_budget_allows_member_and_empty_file(tmp_path):
    budget = [4]
    _oci_apply_layer(layer({"four.txt": b"four", "empty.txt": b""}), tmp_path, budget)
    assert (tmp_path / "four.txt").read_bytes() == b"four"
    assert (tmp_path / "empty.txt").read_bytes() == b""
    assert budget == [0]


def test_budget_is_cumulative_across_members(tmp_path):
    budget = [7]
    with pytest.raises(AcquisitionError, match="extraction size budget"):
        _oci_apply_layer(layer({"first": b"four", "second": b"four"}), tmp_path, budget)
    assert (tmp_path / "first").read_bytes() == b"four"
    assert not (tmp_path / "second").exists()
    assert budget == [3]


def test_midstream_failure_preserves_prior_destination_and_removes_partial(tmp_path, monkeypatch):
    original_read = tarfile.ExFileObject.read
    calls = 0

    def failed_read(handle, size=-1):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic input failure")
        return original_read(handle, size)

    destination = tmp_path / "existing"
    destination.write_bytes(b"original")
    monkeypatch.setattr(tarfile.ExFileObject, "read", failed_read)
    budget = [2 * 1024 * 1024]
    with pytest.raises(AcquisitionError, match="extraction failed"):
        _oci_apply_layer(layer({"existing": b"x" * (1024 * 1024 + 1)}), tmp_path, budget)
    assert calls == 2
    assert destination.read_bytes() == b"original"
    assert budget == [2 * 1024 * 1024]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["existing"]


def test_hardlinks_stream_without_whole_source_read_and_support_self_target(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.write_bytes(b"content")
    original_read_bytes = Path.read_bytes

    def forbid_source_read_bytes(path):
        if path == source:
            raise AssertionError("hardlink source must stream")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_source_read_bytes)
    budget = [14]
    _oci_apply_layer(layer({}, hardlinks=(("copy", "source"), ("source", "source"))), tmp_path, budget)
    with source.open("rb") as handle:
        assert handle.read() == b"content"
    assert (tmp_path / "copy").read_bytes() == b"content"
    assert budget == [0]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["copy", "source"]


def test_hardlink_oversize_preserves_destination(tmp_path):
    (tmp_path / "source").write_bytes(b"four")
    (tmp_path / "copy").write_bytes(b"original")
    budget = [3]
    with pytest.raises(AcquisitionError, match="extraction size budget"):
        _oci_apply_layer(layer({}, hardlinks=(("copy", "source"),)), tmp_path, budget)
    assert (tmp_path / "copy").read_bytes() == b"original"
    assert budget == [3]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["copy", "source"]


def test_truncated_member_preserves_destination_and_cleans_temp(tmp_path, monkeypatch):
    destination = tmp_path / "existing"
    destination.write_bytes(b"original")
    monkeypatch.setattr(tarfile.ExFileObject, "read", lambda *args: b"")
    budget = [4]
    with pytest.raises(AcquisitionError, match="size does not match"):
        _oci_apply_layer(layer({"existing": b"four"}), tmp_path, budget)
    assert destination.read_bytes() == b"original"
    assert budget == [4]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["existing"]


def test_failed_replace_preserves_prior_regular_file(tmp_path, monkeypatch):
    destination = tmp_path / "existing"
    destination.write_bytes(b"original")

    def failed_replace(*args):
        raise OSError("synthetic replacement failure")

    monkeypatch.setattr(Path, "replace", failed_replace)
    budget = [4]
    with pytest.raises(AcquisitionError, match="extraction failed"):
        _oci_apply_layer(layer({"existing": b"four"}), tmp_path, budget)
    assert destination.read_bytes() == b"original"
    assert budget == [4]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["existing"]
