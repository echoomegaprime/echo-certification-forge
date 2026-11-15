"""Immutable public ClamAV definition snapshots; vendor authentication is separate."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DAILY_MAX_AGE_SECONDS = 48 * 3600
MAX_FUTURE_SECONDS = 300
DATABASE_NAMES = frozenset({"main", "daily", "bytecode"})
DB_NAME = re.compile(r"(main|daily|bytecode)\.(cvd|cld)")
SIGN_NAME = re.compile(r"(main|daily|bytecode)-([0-9]+)\.cvd\.sign")
ENGINE_REFERENCE = re.compile(r"clamav/clamav@sha256:[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)


def _full_identity(value: os.stat_result) -> tuple[int, ...]:
    # Windows lstat exposes birth time as ctime, whereas fstat exposes change time.
    # Compare each API's change time against its own before/after observation.
    return (*_identity(value), value.st_ctime_ns)


def _read_file(path: Path, *, limit: int, collect: bool = False) -> tuple[str, bytes, bytes]:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), f"not a regular nonsymlink file: {path.name}")
    require(before.st_nlink == 1, f"hard-linked profile file rejected: {path.name}")
    require(0 < before.st_size <= limit, f"profile file size invalid: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    header = b""
    content = bytearray()
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and _identity(opened) == _identity(before),
                "profile file changed before opening")
        consumed = 0
        while chunk := stream.read(1024 * 1024):
            consumed += len(chunk)
            require(consumed <= before.st_size and consumed <= limit, "profile file grew during reading")
            digest.update(chunk)
            if len(header) < 512:
                header += chunk[:512 - len(header)]
            if collect:
                content.extend(chunk)
        require(_full_identity(os.fstat(stream.fileno())) == _full_identity(opened), "profile file changed while reading")
    require(_full_identity(path.lstat()) == _full_identity(before), "profile file changed after reading")
    return digest.hexdigest(), header, bytes(content)


def parse_database_header(header: bytes) -> dict[str, Any]:
    require(len(header) == 512, "database header must contain 512 bytes")
    try:
        fields = header.rstrip(b" \x00\r\n").decode("ascii").split(":")
        require(len(fields) == 9 and fields[0] == "ClamAV-VDB", "invalid official database header")
        values = [int(fields[index]) for index in (2, 3, 4, 8)]
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("malformed database header") from exc
    version, signatures, level, epoch = values
    require(version > 0 and signatures > 0 and level >= 0 and epoch > 0, "invalid database header numbers")
    return {"version": version, "signatures": signatures, "required_functionality_level": level,
            "build_epoch": epoch, "header_sha256": hashlib.sha256(header).hexdigest()}


def validate_database_snapshot(directory: Path, manifest_sha256: str, engine_reference: str,
                               *, now: datetime | None = None) -> dict[str, Any]:
    """Validate inventory, bytes and daily age; this does not claim vendor authentication."""
    require(SHA256.fullmatch(manifest_sha256) is not None, "definition manifest digest invalid")
    require(ENGINE_REFERENCE.fullmatch(engine_reference) is not None, "official pinned ClamAV engine required")
    require(directory.is_dir() and not directory.is_symlink(), "definition directory missing or symlinked")
    directory = directory.resolve(strict=True)
    manifest_hash, _, manifest_bytes = _read_file(directory / "manifest.json", limit=128 * 1024, collect=True)
    require(manifest_hash == manifest_sha256, "definition manifest hash mismatch")
    try:
        document = json.loads(manifest_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("definition manifest malformed") from exc
    require(isinstance(document, dict) and document.get("schema_version") == "1.0.0"
            and document.get("kind") == "clamav-definition-profile", "definition manifest schema invalid")
    require(document.get("official_updater_reference") == engine_reference, "definition engine identity mismatch")
    require(document.get("daily_policy_max_age_hours", 48) == 48
            and document.get("future_clock_skew_seconds", 300) == 300, "definition freshness policy cannot be overridden")
    records = document.get("files")
    declared_databases = document.get("databases")
    require(isinstance(records, list) and 3 <= len(records) <= 6, "definition inventory invalid")
    require(isinstance(declared_databases, list) and len(declared_databases) == 3, "three database identities required")
    identities = {}
    for item in declared_databases:
        require(isinstance(item, dict) and isinstance(item.get("path"), str)
                and DB_NAME.fullmatch(item["path"]) is not None, "database identity path invalid")
        require(item["path"] not in identities, "duplicate database identity")
        identities[item["path"]] = item
    files = {}
    databases = {}
    total = 0
    for item in records:
        require(isinstance(item, dict), "definition file record invalid")
        name = item.get("path")
        require(isinstance(name, str) and (DB_NAME.fullmatch(name) or SIGN_NAME.fullmatch(name)),
                "unknown or custom definition file")
        require(name not in files, "duplicate definition file")
        size = item.get("size_bytes")
        expected = item.get("sha256")
        require(type(size) is int and 0 < size <= MAX_FILE_BYTES and isinstance(expected, str)
                and SHA256.fullmatch(expected) is not None, "definition file identity invalid")
        require(total + size <= MAX_SNAPSHOT_BYTES, "definition snapshot byte budget exceeded")
        path = directory / name
        actual, header, _ = _read_file(path, limit=MAX_FILE_BYTES)
        require(path.stat().st_size == size and actual == expected, f"definition bytes changed: {name}")
        total += size
        files[name] = {"path": name, "size_bytes": size, "sha256": expected}
        match = DB_NAME.fullmatch(name)
        if match:
            database = match.group(1)
            require(database not in databases, "ambiguous CVD/CLD database variants")
            parsed = parse_database_header(header)
            claim = identities.get(name)
            require(claim is not None and all(type(claim.get(key)) is int and claim[key] == parsed[key]
                    for key in ("version", "signatures", "required_functionality_level", "build_epoch"))
                    and claim.get("header_sha256") == parsed["header_sha256"], "database header identity mismatch")
            databases[database] = {"path": name, **parsed}
    require(total <= MAX_SNAPSHOT_BYTES and set(databases) == DATABASE_NAMES, "definition database set incomplete")
    require(set(identities) == {entry["path"] for entry in databases.values()}, "database identity inventory mismatch")
    require({entry.name for entry in directory.iterdir()} == set(files) | {"manifest.json"},
            "unexpected file, directory, or custom definitions in snapshot")
    for name in files:
        match = SIGN_NAME.fullmatch(name)
        if match:
            database, version = match.groups()
            require(databases[database]["path"].endswith(".cvd")
                    and databases[database]["version"] == int(version), "unused or mismatched sidecar")
    # Current official CVD containers require their real versioned detached signatures.
    # Patched CLD containers authenticate their internal signed INFO, not an invented sidecar.
    for name, identity in databases.items():
        if identity["path"].endswith(".cvd"):
            require(f'{name}-{identity["version"]}.cvd.sign' in files, "required vendor CVD sidecar missing")
    current = now or datetime.now(UTC)
    require(current.tzinfo is not None, "definition freshness clock must be timezone aware")
    current_epoch = current.timestamp()
    require(all(entry["build_epoch"] <= current_epoch + MAX_FUTURE_SECONDS for entry in databases.values()),
            "definition timestamp is in the future")
    require(current_epoch - databases["daily"]["build_epoch"] <= DAILY_MAX_AGE_SECONDS,
            "daily definitions are stale")
    return {"directory": directory, "manifest_sha256": manifest_sha256, "engine_reference": engine_reference,
            "files": files, "databases": databases, "manifest_bytes": manifest_bytes,
            "daily_max_age_seconds": DAILY_MAX_AGE_SECONDS, "future_clock_skew_seconds": MAX_FUTURE_SECONDS}


def stage_database_snapshot(snapshot: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Copy into a private owned run directory; hostile targets never see a mutable caller directory."""
    require(not destination.exists() and not destination.is_symlink(), "staged definition directory already exists")
    destination.mkdir(mode=0o700)
    try:
        # Revalidate before copying, then validate copied bytes independently.
        validate_database_snapshot(snapshot["directory"], snapshot["manifest_sha256"], snapshot["engine_reference"])
        for name in [*snapshot["files"], "manifest.json"]:
            source = snapshot["directory"] / name
            before = source.lstat()
            require(stat.S_ISREG(before.st_mode) and not source.is_symlink(), "source definitions changed before copy")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(source, flags), "rb") as incoming, (destination / name).open("xb") as outgoing:
                opened = os.fstat(incoming.fileno())
                require(stat.S_ISREG(opened.st_mode) and _identity(opened) == _identity(before),
                        "source identity changed before copy")
                expected_size = len(snapshot["manifest_bytes"]) if name == "manifest.json" else snapshot["files"][name]["size_bytes"]
                consumed = 0
                while chunk := incoming.read(min(1024 * 1024, expected_size - consumed + 1)):
                    consumed += len(chunk)
                    require(consumed <= expected_size, "source profile grew while copying")
                    outgoing.write(chunk)
                require(consumed == expected_size, "source profile truncated while copying")
                outgoing.flush()
                os.fsync(outgoing.fileno())
                require(_full_identity(os.fstat(incoming.fileno())) == _full_identity(opened),
                        "source definitions changed during copy")
                require(_full_identity(source.lstat()) == _full_identity(before),
                        "source path changed during copy")
            (destination / name).chmod(0o444)
        destination.chmod(0o555)
        return validate_database_snapshot(destination, snapshot["manifest_sha256"], snapshot["engine_reference"])
    except BaseException:
        destination.chmod(0o700)
        for child in destination.iterdir():
            child.chmod(0o600)
        shutil.rmtree(destination)
        raise


def snapshot_evidence(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in snapshot.items() if key not in {"directory", "manifest_bytes"}}
