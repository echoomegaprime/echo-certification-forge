"""Structural checks use synthetic bytes, never vendor qualification evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from echo_certification_forge import clamav_database as database

ENGINE = "clamav/clamav@sha256:" + "a" * 64


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _header(epoch: int, version: int, *, signatures: int = 10, level: int = 90) -> bytes:
    text = f"ClamAV-VDB:synthetic UTC:{version}:{signatures}:{level}:md5:dsig:synthetic:{epoch}"
    return text.encode("ascii").ljust(512, b" ")


def _write_manifest(root: Path, document: dict) -> str:
    value = json.dumps(document, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    (root / "manifest.json").write_bytes(value)
    return _sha(value)


def _file_record(root: Path, name: str) -> dict:
    value = (root / name).read_bytes()
    return {"path": name, "size_bytes": len(value), "sha256": _sha(value)}


def _database_record(root: Path, name: str) -> dict:
    return {"path": name, **database.parse_database_header((root / name).read_bytes()[:512])}


def _make_profile(tmp_path: Path) -> dict:
    root = tmp_path / "synthetic-definitions"
    root.mkdir()
    now = datetime.fromtimestamp(int(datetime.now(UTC).timestamp()), UTC)
    epochs = {"main.cvd": int(now.timestamp()) - 400 * 86400,
              "daily.cld": int(now.timestamp()) - 3600,
              "bytecode.cvd": int(now.timestamp()) - 800 * 86400}
    versions = {"main.cvd": 63, "daily.cld": 28182, "bytecode.cvd": 339}
    for name, epoch in epochs.items():
        (root / name).write_bytes(_header(epoch, versions[name]) + b"SYNTHETIC, NOT SIGNED VENDOR DATA\n")
    for name in ("main-63.cvd.sign", "bytecode-339.cvd.sign"):
        (root / name).write_bytes(b"SYNTHETIC SIDE CAR, NOT A VENDOR SIGNATURE\n")
    names = [*epochs, "main-63.cvd.sign", "bytecode-339.cvd.sign"]
    document = {
        "schema_version": "1.0.0", "kind": "clamav-definition-profile",
        "official_updater_reference": ENGINE,
        "daily_policy_max_age_hours": 48, "future_clock_skew_seconds": 300,
        "files": [_file_record(root, name) for name in names],
        "databases": [_database_record(root, name) for name in epochs],
    }
    return {"root": root, "document": document, "sha": _write_manifest(root, document), "now": now}


@pytest.fixture
def profile(tmp_path):
    value = _make_profile(tmp_path)
    yield value
    # Windows marks copied files read-only, so release only this test's temporary files.
    for path in sorted(tmp_path.rglob("*"), key=lambda entry: len(entry.parts), reverse=True):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


def _validate(profile, *, document=None, now=None, engine=ENGINE):
    digest = profile["sha"]
    if document is not None:
        digest = _write_manifest(profile["root"], document)
    return database.validate_database_snapshot(
        profile["root"], digest, engine, now=profile["now"] if now is None else now)


def _replace_database(profile, name: str, *, epoch=None, version=None):
    root, document = profile["root"], profile["document"]
    old = next(item for item in document["databases"] if item["path"] == name)
    (root / name).write_bytes(_header(old["build_epoch"] if epoch is None else epoch,
                                     old["version"] if version is None else version)
                              + b"SYNTHETIC, NOT SIGNED VENDOR DATA\n")
    for index, item in enumerate(document["files"]):
        if item["path"] == name:
            document["files"][index] = _file_record(root, name)
    for index, item in enumerate(document["databases"]):
        if item["path"] == name:
            document["databases"][index] = _database_record(root, name)


def test_clean_profile_binds_actual_bytes_and_allows_old_main_and_bytecode(profile):
    result = _validate(profile)
    assert set(result["databases"]) == {"main", "daily", "bytecode"}
    assert set(result["files"]) == {"main.cvd", "daily.cld", "bytecode.cvd",
                                    "main-63.cvd.sign", "bytecode-339.cvd.sign"}
    assert result["manifest_sha256"] == profile["sha"]
    assert result["daily_max_age_seconds"] == 48 * 3600
    assert result["future_clock_skew_seconds"] == 300
    assert result["databases"]["main"]["build_epoch"] < profile["now"].timestamp() - 48 * 3600


def test_header_parses_and_binds_exact_header_bytes(profile):
    value = (profile["root"] / "daily.cld").read_bytes()[:512]
    result = database.parse_database_header(value)
    assert result["version"] == 28182
    assert result["signatures"] == 10
    assert result["required_functionality_level"] == 90
    assert result["header_sha256"] == _sha(value)


@pytest.mark.parametrize("value", [b"", b"x" * 511, b"x" * 513,
    b"\xff".ljust(512, b" "),
    b"Custom-VDB:time:1:2:3:x:x:x:1".ljust(512, b" "),
    b"ClamAV-VDB:time:no:2:3:x:x:x:1".ljust(512, b" "),
    b"ClamAV-VDB:time:1:2:3:x:x:1".ljust(512, b" "),
    _header(1, 0), _header(1, 1, signatures=0), _header(1, 1, level=-1), _header(0, 1)])
def test_malformed_headers_are_rejected(value):
    with pytest.raises(ValueError):
        database.parse_database_header(value)


@pytest.mark.parametrize("digest", ["a" * 63, "A" * 64, "sha256:" + "a" * 64, "g" * 64])
def test_manifest_digest_requires_full_lowercase_sha256(profile, digest):
    with pytest.raises(ValueError, match="manifest digest"):
        database.validate_database_snapshot(profile["root"], digest, ENGINE, now=profile["now"])


def test_manifest_hash_is_checked(profile):
    with pytest.raises(ValueError, match="manifest hash mismatch"):
        database.validate_database_snapshot(profile["root"], "0" * 64, ENGINE, now=profile["now"])


def test_missing_manifest_fails_closed(profile):
    (profile["root"] / "manifest.json").unlink()
    with pytest.raises(FileNotFoundError):
        _validate(profile)


@pytest.mark.parametrize("value", [b"{", b"\xff", b"[]", b"null"])
def test_malformed_or_nonobject_manifest_fails(profile, value):
    (profile["root"] / "manifest.json").write_bytes(value)
    with pytest.raises(ValueError):
        database.validate_database_snapshot(profile["root"], _sha(value), ENGINE, now=profile["now"])


@pytest.mark.parametrize(("key", "value"), [
    ("schema_version", "0.0.0"), ("kind", "custom-profile"),
    ("files", None), ("databases", None),
    ("official_updater_reference", "clamav/clamav@sha256:" + "b" * 64),
    ("daily_policy_max_age_hours", 49), ("future_clock_skew_seconds", 301),
])
def test_manifest_cannot_weaken_schema_engine_or_freshness_policy(profile, key, value):
    document = copy.deepcopy(profile["document"])
    document[key] = value
    with pytest.raises(ValueError):
        _validate(profile, document=document)


@pytest.mark.parametrize("engine", ["clamav/clamav:stable",
    "other/clamav@sha256:" + "a" * 64, "clamav/clamav@sha256:" + "A" * 64])
def test_mutable_or_unofficial_engine_is_rejected(profile, engine):
    with pytest.raises(ValueError, match="official pinned"):
        _validate(profile, engine=engine)


@pytest.mark.parametrize(("record_set", "name"), [
    ("files", "../main.cvd"), ("files", "/main.cvd"), ("files", "sub/main.cvd"),
    ("files", r"..\main.cvd"), ("databases", "../daily.cld")])
def test_manifest_paths_cannot_escape_snapshot(profile, record_set, name):
    document = copy.deepcopy(profile["document"])
    document[record_set][0]["path"] = name
    with pytest.raises(ValueError):
        _validate(profile, document=document)


@pytest.mark.parametrize("field", ["version", "signatures", "required_functionality_level",
                                  "build_epoch", "header_sha256"])
def test_claimed_database_header_must_match_real_header(profile, field):
    document = copy.deepcopy(profile["document"])
    document["databases"][1][field] = "0" * 64 if field == "header_sha256" else 123
    with pytest.raises(ValueError, match="header identity mismatch"):
        _validate(profile, document=document)


@pytest.mark.parametrize("field", ["version", "signatures", "required_functionality_level", "build_epoch"])
def test_header_identity_numeric_claims_do_not_accept_bools_or_strings(profile, field):
    document = copy.deepcopy(profile["document"])
    document["databases"][1][field] = str(document["databases"][1][field])
    with pytest.raises(ValueError, match="header identity mismatch"):
        _validate(profile, document=document)


@pytest.mark.parametrize(("key", "value"), [("size_bytes", True), ("size_bytes", 0),
    ("size_bytes", 123), ("sha256", "f" * 64), ("sha256", "bad")])
def test_file_record_size_and_hash_are_enforced(profile, key, value):
    document = copy.deepcopy(profile["document"])
    document["files"][0][key] = value
    with pytest.raises(ValueError):
        _validate(profile, document=document)


@pytest.mark.parametrize("change", ["append", "replace", "remove"])
def test_actual_data_drift_is_rejected(profile, change):
    path = profile["root"] / "daily.cld"
    if change == "remove":
        path.unlink()
    elif change == "append":
        path.write_bytes(path.read_bytes() + b"changed")
    else:
        data = path.read_bytes()
        path.write_bytes(data[:-1] + b"x")
    with pytest.raises((ValueError, FileNotFoundError)):
        _validate(profile)


@pytest.mark.parametrize("kind", ["file", "subdir", "unlisted-known-db"])
def test_extra_snapshot_contents_are_rejected(profile, kind):
    root = profile["root"]
    if kind == "subdir":
        (root / "extra").mkdir()
    else:
        (root / ("daily.cvd" if kind == "unlisted-known-db" else "custom.ndb")).write_bytes(b"custom")
    with pytest.raises(ValueError, match="unexpected"):
        _validate(profile)


def test_declared_custom_database_is_rejected(profile):
    root, document = profile["root"], copy.deepcopy(profile["document"])
    (root / "custom.ndb").write_bytes(b"unsigned synthetic database")
    document["files"].append(_file_record(root, "custom.ndb"))
    with pytest.raises(ValueError, match="unknown or custom"):
        _validate(profile, document=document)


def test_duplicate_file_record_is_rejected(profile):
    document = copy.deepcopy(profile["document"])
    document["files"].append(copy.deepcopy(document["files"][0]))
    with pytest.raises(ValueError, match="duplicate definition file"):
        _validate(profile, document=document)


def test_duplicate_database_identity_is_rejected(profile):
    document = copy.deepcopy(profile["document"])
    document["databases"][2] = copy.deepcopy(document["databases"][0])
    with pytest.raises(ValueError, match="duplicate database identity"):
        _validate(profile, document=document)


def test_ambiguous_cvd_and_cld_variants_are_rejected(profile):
    root, document = profile["root"], copy.deepcopy(profile["document"])
    (root / "daily.cvd").write_bytes((root / "daily.cld").read_bytes())
    document["files"].append(_file_record(root, "daily.cvd"))
    with pytest.raises(ValueError, match="ambiguous CVD/CLD"):
        _validate(profile, document=document)


def test_missing_required_cvd_sidecar_is_rejected(profile):
    root, document = profile["root"], copy.deepcopy(profile["document"])
    name = "main-63.cvd.sign"
    (root / name).unlink()
    document["files"] = [item for item in document["files"] if item["path"] != name]
    with pytest.raises(ValueError, match="sidecar missing"):
        _validate(profile, document=document)


def test_sidecar_must_match_current_database_version(profile):
    root, document = profile["root"], copy.deepcopy(profile["document"])
    (root / "main-63.cvd.sign").rename(root / "main-64.cvd.sign")
    document["files"] = [_file_record(root, "main-64.cvd.sign") if item["path"] == "main-63.cvd.sign"
                         else item for item in document["files"]]
    with pytest.raises(ValueError, match="mismatched sidecar"):
        _validate(profile, document=document)


def test_unused_cvd_sidecar_for_selected_cld_is_rejected(profile):
    root, document = profile["root"], copy.deepcopy(profile["document"])
    (root / "daily-28182.cvd.sign").write_bytes(b"unused synthetic signature")
    document["files"].append(_file_record(root, "daily-28182.cvd.sign"))
    with pytest.raises(ValueError, match="unused or mismatched sidecar"):
        _validate(profile, document=document)


@pytest.mark.parametrize(("offset", "accepted"), [
    (-48 * 3600, True), (-48 * 3600 - 1, False), (300, True), (301, False)])
def test_daily_freshness_enforces_exact_policy_boundaries(profile, offset, accepted):
    _replace_database(profile, "daily.cld", epoch=int(profile["now"].timestamp()) + offset)
    if accepted:
        assert _validate(profile, document=profile["document"])["databases"]["daily"]["build_epoch"] == int(profile["now"].timestamp()) + offset
    else:
        with pytest.raises(ValueError, match="stale|future"):
            _validate(profile, document=profile["document"])


@pytest.mark.parametrize("name", ["main.cvd", "bytecode.cvd"])
def test_future_clock_guard_applies_to_all_databases(profile, name):
    _replace_database(profile, name, epoch=int(profile["now"].timestamp()) + 301)
    with pytest.raises(ValueError, match="future"):
        _validate(profile, document=profile["document"])


def test_naive_freshness_clock_is_rejected(profile):
    with pytest.raises(ValueError, match="timezone aware"):
        _validate(profile, now=profile["now"].replace(tzinfo=None))


def test_file_and_total_snapshot_bounds_need_no_large_allocations(profile, monkeypatch):
    monkeypatch.setattr(database, "MAX_FILE_BYTES", 512)
    with pytest.raises(ValueError, match="file identity"):
        _validate(profile)
    monkeypatch.setattr(database, "MAX_FILE_BYTES", 512 * 1024 * 1024)
    total = sum(item["size_bytes"] for item in profile["document"]["files"])
    monkeypatch.setattr(database, "MAX_SNAPSHOT_BYTES", total - 1)
    with pytest.raises(ValueError, match="definition snapshot byte budget exceeded"):
        _validate(profile)


def test_manifest_read_is_bounded_before_json_parsing(profile):
    value = b" " * (128 * 1024 + 1)
    (profile["root"] / "manifest.json").write_bytes(value)
    with pytest.raises(ValueError, match="file size invalid"):
        database.validate_database_snapshot(profile["root"], _sha(value), ENGINE, now=profile["now"])


def test_hardlinked_file_is_rejected(profile, tmp_path):
    os.link(profile["root"] / "daily.cld", tmp_path / "hardlink")
    with pytest.raises(ValueError, match="hard-linked"):
        _validate(profile)


def test_symlink_file_is_rejected_if_platform_permits(profile, tmp_path):
    path = profile["root"] / "daily.cld"
    target = tmp_path / "real-daily"
    path.rename(target)
    try:
        path.symlink_to(target)
    except OSError as exc:
        target.rename(path)
        pytest.skip(f"platform does not permit unprivileged symlinks: {exc}")
    with pytest.raises(ValueError, match="nonsymlink"):
        _validate(profile)


def test_private_stage_is_independent_readonly_and_leaves_source_unchanged(profile, tmp_path):
    snapshot = _validate(profile)
    before = {path.name: _sha(path.read_bytes()) for path in profile["root"].iterdir()}
    destination = tmp_path / "private-copy"
    staged = database.stage_database_snapshot(snapshot, destination)
    assert staged["directory"] == destination.resolve()
    assert staged["manifest_sha256"] == snapshot["manifest_sha256"]
    assert {path.name: _sha(path.read_bytes()) for path in profile["root"].iterdir()} == before
    assert {path.name: _sha(path.read_bytes()) for path in destination.iterdir()} == before
    assert not any(path.stat().st_mode & stat.S_IWUSR for path in destination.iterdir())
    source = profile["root"] / "daily.cld"
    source.write_bytes(source.read_bytes() + b"later caller mutation")
    assert database.validate_database_snapshot(destination, profile["sha"], ENGINE)["databases"]["daily"]["version"] == 28182


def test_stage_revalidates_source_drift_and_removes_only_failed_private_copy(profile, tmp_path):
    snapshot = _validate(profile)
    source = profile["root"] / "daily.cld"
    source.write_bytes(source.read_bytes() + b"changed after qualification")
    destination = tmp_path / "failed-private-copy"
    with pytest.raises(ValueError, match="bytes changed"):
        database.stage_database_snapshot(snapshot, destination)
    assert not destination.exists()
    assert source.exists()
    assert source.read_bytes().endswith(b"changed after qualification")


def test_existing_stage_directory_is_never_removed(profile, tmp_path):
    destination = tmp_path / "already-owned-by-someone"
    destination.mkdir()
    marker = destination / "keep"
    marker.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="already exists"):
        database.stage_database_snapshot(_validate(profile), destination)
    assert marker.read_bytes() == b"preserve"


class _SyntheticRead:
    """Safe stream shim for growth/truncation; never opens a FIFO or allocates large data."""
    def __init__(self, stream, change):
        self.stream = stream
        self.change = change
        self.done = False

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def fileno(self):
        return self.stream.fileno()

    def read(self, count):
        if self.done:
            return b""
        self.done = True
        value = self.stream.read(count)
        return value + b"x" if self.change == "grow" else value[:-1]


def test_read_detects_growth_before_collecting_unbounded_content(profile, monkeypatch):
    real_fdopen = database.os.fdopen
    monkeypatch.setattr(database.os, "fdopen",
                        lambda fd, mode: _SyntheticRead(real_fdopen(fd, mode), "grow"))
    path = profile["root"] / "daily.cld"
    with pytest.raises(ValueError, match="grew during reading"):
        database._read_file(path, limit=path.stat().st_size, collect=True)


@pytest.mark.parametrize("change", ["grow", "truncate"])
def test_stage_copy_is_bounded_and_detects_truncation(profile, tmp_path, monkeypatch, change):
    snapshot = _validate(profile)
    target = profile["root"] / "main.cvd"
    real_open, real_fdopen = database.os.open, database.os.fdopen
    descriptors = {}
    target_opens = 0

    def open_file(path, flags, *args, **kwargs):
        nonlocal target_opens
        fd = real_open(path, flags, *args, **kwargs)
        if Path(path) == target:
            target_opens += 1
            descriptors[fd] = target_opens
        else:
            descriptors.pop(fd, None)
        return fd

    def wrap_stream(fd, mode):
        stream = real_fdopen(fd, mode)
        return _SyntheticRead(stream, change) if descriptors.get(fd) == 2 else stream

    monkeypatch.setattr(database.os, "open", open_file)
    monkeypatch.setattr(database.os, "fdopen", wrap_stream)
    destination = tmp_path / "bounded-failed-copy"
    with pytest.raises(ValueError, match="grew while copying|truncated while copying"):
        database.stage_database_snapshot(snapshot, destination)
    assert not destination.exists()
    assert _sha(target.read_bytes()) == snapshot["files"]["main.cvd"]["sha256"]


def test_open_guard_sets_nonblocking_flag_before_any_simulated_fifo_swap(profile, monkeypatch):
    observed = []

    def safe_open(path, flags):
        observed.append(flags)
        raise OSError("simulated file swap; no FIFO was opened")

    monkeypatch.setattr(database.os, "open", safe_open)
    with pytest.raises(OSError, match="simulated file swap"):
        database._read_file(profile["root"] / "daily.cld", limit=4096)
    assert len(observed) == 1
    assert observed[0] & os.O_RDONLY == os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        assert observed[0] & os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        assert observed[0] & os.O_NOFOLLOW


def test_evidence_omits_local_paths_and_manifest_bytes(profile):
    evidence = database.snapshot_evidence(_validate(profile))
    assert "directory" not in evidence
    assert "manifest_bytes" not in evidence
    assert evidence["manifest_sha256"] == profile["sha"]
    assert set(evidence["databases"]) == {"main", "daily", "bytecode"}


def test_opened_file_identity_must_match_path_before_reading(profile, tmp_path, monkeypatch):
    target = profile["root"] / "daily.cld"
    substitute = tmp_path / "different-inode-same-bytes"
    substitute.write_bytes(target.read_bytes())
    real_open = database.os.open

    def substitute_open(path, flags, *args, **kwargs):
        return real_open(substitute if Path(path) == target else path, flags, *args, **kwargs)

    monkeypatch.setattr(database.os, "open", substitute_open)
    with pytest.raises(ValueError, match="changed before opening"):
        database._read_file(target, limit=4096)


def test_same_size_write_during_read_is_detected(profile, monkeypatch):
    target = profile["root"] / "daily.cld"
    original = target.read_bytes()
    initial_mtime = target.stat().st_mtime_ns
    real_fdopen = database.os.fdopen

    class ChangingStream:
        def __init__(self, stream):
            self.stream = stream
            self.changed = False

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, count):
            value = self.stream.read(count)
            if value and not self.changed:
                self.changed = True
                target.write_bytes(original[:-1] + b"X")
                os.utime(target, ns=(target.stat().st_atime_ns, initial_mtime + 1_000_000_000))
            return value

    monkeypatch.setattr(database.os, "fdopen", lambda fd, mode: ChangingStream(real_fdopen(fd, mode)))
    with pytest.raises(ValueError, match="changed while reading|changed after reading"):
        database._read_file(target, limit=4096)


def test_link_added_before_descriptor_check_is_rejected(monkeypatch, tmp_path):
    """Descriptor identity must retain the validated link count on every platform."""
    from types import SimpleNamespace
    import echo_certification_forge.clamav_database as db
    path = tmp_path / "vendor-profile"
    path.write_bytes(b"regular public vendor input")
    original_fstat = db.os.fstat
    def linked_descriptor(fd):
        value = original_fstat(fd)
        return SimpleNamespace(**{
            key: (2 if key == "st_nlink" else getattr(value, key))
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
        })
    monkeypatch.setattr(db.os, "fstat", linked_descriptor)
    with pytest.raises(ValueError, match="before opening"):
        db._read_file(path, limit=1024)
