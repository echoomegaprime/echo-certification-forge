"""Owner-operated, verified atomic intake for the existing production E2E provider.

This module has no signing, key generation, trust enrollment or release-verdict
operation. A separate admitted collector must produce the envelope. The owner
selects the roots and canonical run identities independently of that envelope.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import stat
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .canonical import require_sha256, sha256_bytes, utc_now
from .echo_workspace_probe import MAX_BODY, ObservationError, bounded_json
from .models import EnvironmentIdentity, SignedVerdictEnvelope, TargetIdentity
from .production_e2e import (
    VerifiedProductionE2E, validate_production_e2e, verify_signed_attestation,
)
from .signing import TrustedPublicKeyRegistry


class IntakeError(RuntimeError):
    """A fixed diagnostic code, without envelope, credential or key content."""


class IntakeOutcomeUnknown(IntakeError):
    """Publication was attempted; reconcile by readback before any new write."""


def _require(condition: Any, code: str) -> None:
    if not condition:
        raise IntakeError(code)


def verify_intake_document(
    raw: bytes, trusted_keys: TrustedPublicKeyRegistry, target: TargetIdentity,
    environment: EnvironmentIdentity, *, now: datetime, expected_content_sha256: str,
) -> VerifiedProductionE2E:
    """Verify reviewed bytes using the SAME contract consumed by the dispatcher."""
    try:
        require_sha256(expected_content_sha256, "expected_content_sha256")
        _require(sha256_bytes(raw) == expected_content_sha256, "content_digest_mismatch")
        document = bounded_json(raw)
        _require(set(document) in (
            {"payload", "signature_b64", "key_id"},
            {"payload", "signature_b64", "key_id", "public_key_pem"},
        ), "envelope_fields_invalid")
        _require(isinstance(document["payload"], dict) and
                 all(isinstance(document.get(key), str) for key in ("signature_b64", "key_id")) and
                 isinstance(document.get("public_key_pem", ""), str), "envelope_fields_invalid")
        envelope = SignedVerdictEnvelope(
            payload=document["payload"], signature_b64=document["signature_b64"],
            key_id=document["key_id"], public_key_pem=document.get("public_key_pem", ""),
        )
        verified = verify_signed_attestation(envelope, trusted_keys)
        eligible, reason = validate_production_e2e(verified.payload, target, environment, now=now)
        _require(eligible, reason)
        return verified
    except ObservationError as error:
        raise IntakeError("envelope_json_invalid") from error
    except (ValueError, TypeError, KeyError) as error:
        # The existing signature verifier returns fixed reasons, never material.
        text = str(error)
        reason = next((code for code in ("untrusted_signing_key", "invalid_signature", "payload_key_id_mismatch")
                       if text.endswith(code)), "envelope_invalid")
        raise IntakeError(reason) from error


def _no_symlinks(path: Path) -> None:
    _require(path.is_absolute() and ".." not in path.parts, "absolute_path_required")
    for component in (path, *path.parents):
        _require(not component.is_symlink(), "symlink_refused")


def _protected_directory(path: Path, owner_uid: int) -> None:
    _require(os.name == "posix", "posix_owner_required")
    _no_symlinks(path)
    for component in (path, *path.parents):
        info = component.stat()
        _require(stat.S_ISDIR(info.st_mode), "directory_required")
        if component == path:
            _require(info.st_uid == owner_uid, "directory_owner_mismatch")
            _require(not info.st_mode & 0o022, "unprotected_directory")
        else:
            _require(info.st_uid in (0, owner_uid), "parent_owner_mismatch")
            # A sticky system temporary parent cannot rename another owner's child.
            _require(not info.st_mode & 0o022 or
                     (info.st_uid == 0 and info.st_mode & stat.S_ISVTX), "unprotected_parent")


def _read_fd(fd: int, *, maximum: int = MAX_BODY, owner_uid: int | None = None) -> bytes:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "file_bound")
    if owner_uid is not None:
        _require(before.st_uid == owner_uid and not before.st_mode & 0o022, "unprotected_file")
    chunks, size = [], 0
    while chunk := os.read(fd, min(65536, maximum + 1 - size)):
        chunks.append(chunk)
        size += len(chunk)
        _require(size <= maximum, "file_bound")
    after = os.fstat(fd)
    _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "file_changed_during_read")
    return b"".join(chunks)


def _read_file(path: Path) -> bytes:
    _no_symlinks(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            return _read_fd(fd)
        finally:
            os.close(fd)
    except OSError as error:
        raise IntakeError("source_unavailable") from error


class ProductionE2EIntake:
    """Configured by the intake owner, never constructed from a target request.

    FORGE's production directories are root owned, so the operational default
    is UID 0. A nonzero owner is useful only for a separately isolated test root.
    """

    def __init__(self, attestation_directory: Path, trusted_key_directory: Path, *,
                 owner_uid: int = 0, clock: Callable[[], datetime] = utc_now) -> None:
        _require(type(owner_uid) is int and owner_uid >= 0, "owner_uid_invalid")
        self.root, self.trust, self.owner_uid, self.clock = (
            attestation_directory, trusted_key_directory, owner_uid, clock,
        )
        _protected_directory(self.root, self.owner_uid)
        _protected_directory(self.trust, self.owner_uid)

    def _registry(self) -> TrustedPublicKeyRegistry:
        _protected_directory(self.trust, self.owner_uid)
        registry = TrustedPublicKeyRegistry.empty()
        directory = os.open(self.trust, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = sorted(name for name in os.listdir(directory) if name.endswith(".pem"))
            _require(0 < len(names) <= 128, "trust_registry_bound")
            for name in names:
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        raw = _read_fd(fd, maximum=65536, owner_uid=self.owner_uid)
                    finally:
                        os.close(fd)
                    registry.add_pem(raw.decode("ascii"))
                except (OSError, UnicodeError, ValueError, TypeError) as error:
                    raise IntakeError("trust_registry_invalid") from error
        finally:
            os.close(directory)
        return registry

    def _verify(self, raw: bytes, target: TargetIdentity, environment: EnvironmentIdentity,
                expected_content_sha256: str) -> VerifiedProductionE2E:
        return verify_intake_document(raw, self._registry(), target, environment,
                                      now=self.clock(), expected_content_sha256=expected_content_sha256)

    @staticmethod
    def _name(target: TargetIdentity, environment: EnvironmentIdentity) -> str:
        return f"{target.identity_digest}.{environment.identity_digest}.json"

    def _receipt(self, state: str, raw: bytes, verified: VerifiedProductionE2E,
                 target: TargetIdentity, environment: EnvironmentIdentity) -> dict[str, Any]:
        return {
            "schema_version": "certforge.production-e2e-intake.v1", "state": state,
            "target_identity_digest": target.identity_digest,
            "environment_identity_digest": environment.identity_digest,
            "file_name": self._name(target, environment), "content_sha256": sha256_bytes(raw),
            "envelope_sha256": verified.envelope_sha256, "collector_key_id": verified.collector_key_id,
            "signature_verified": True, "release_verdict": "NOT_ISSUED",
        }

    def preview(self, source: Path, target: TargetIdentity, environment: EnvironmentIdentity, *,
                expected_content_sha256: str) -> dict[str, Any]:
        raw = _read_file(source)
        verified = self._verify(raw, target, environment, expected_content_sha256)
        return self._receipt("verified_not_installed", raw, verified, target, environment)

    @contextmanager
    def _locked_directory(self) -> Iterator[int]:
        import fcntl  # POSIX owner entrypoint, not an import-time Windows dependency.

        _protected_directory(self.root, self.owner_uid)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock = None
        try:
            lock = os.open(".production-e2e-intake.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
            info = os.fstat(lock)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner_uid and
                     not info.st_mode & 0o022, "intake_lock_invalid")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise IntakeError("intake_busy") from error
            yield directory
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)

    def _existing(self, directory: int, name: str) -> bytes | None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise IntakeError("symlink_refused" if error.errno == errno.ELOOP else "intake_read_failed") from error
        try:
            return _read_fd(fd, owner_uid=self.owner_uid)
        finally:
            os.close(fd)

    def install(self, source: Path, target: TargetIdentity, environment: EnvironmentIdentity, *,
                expected_content_sha256: str, replace_content_sha256: str | None = None) -> dict[str, Any]:
        raw = _read_file(source)
        # Reject unsigned/ineligible input before acquiring a write lock.
        self._verify(raw, target, environment, expected_content_sha256)
        name = self._name(target, environment)
        with self._locked_directory() as directory:
            # Reload independent trust and recheck expiry AFTER the lock acquisition.
            verified = self._verify(raw, target, environment, expected_content_sha256)
            old = self._existing(directory, name)
            if old == raw:
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.fsync(directory)
                    _require(self._existing(directory, name) == raw, "installed_readback_mismatch")
                except (OSError, IntakeError) as error:
                    raise IntakeOutcomeUnknown("installation_outcome_unknown") from error
                return self._receipt("already_present", raw, verified, target, environment)
            _require((old is None and replace_content_sha256 is None) or
                     (old is not None and sha256_bytes(old) == replace_content_sha256), "replacement_conflict")
            temporary = f".production-e2e-{uuid4().hex}.tmp"
            publication_attempted = False
            try:
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                # A verified document must still be current immediately before publication.
                verified = self._verify(raw, target, environment, expected_content_sha256)
                publication_attempted = True
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                _require(self._existing(directory, name) == raw, "installed_readback_mismatch")
            except (OSError, IntakeError) as error:
                if publication_attempted:
                    raise IntakeOutcomeUnknown("installation_outcome_unknown") from error
                raise
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    if publication_attempted:
                        raise IntakeOutcomeUnknown("installation_outcome_unknown") from error
                    raise IntakeError("temporary_cleanup_failed") from error
        return self._receipt("installed" if old is None else "replaced", raw, verified, target, environment)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--envelope-sha256", required=True)
    parser.add_argument("--identities", type=Path, required=True,
                        help="Owner-selected canonical target and environment from the exact certification run")
    parser.add_argument("--identities-sha256", required=True)
    parser.add_argument("--attestation-directory", type=Path, required=True)
    parser.add_argument("--trusted-key-directory", type=Path, required=True)
    parser.add_argument("--replace-content-sha256")
    parser.add_argument("--install", action="store_true", help="Atomically install the verified envelope")
    args = parser.parse_args(argv)
    try:
        raw = _read_file(args.identities)
        _require(sha256_bytes(raw) == args.identities_sha256, "identities_digest_mismatch")
        identities = bounded_json(raw)
        _require(set(identities) == {"target", "environment"}, "identities_fields_invalid")
        target, environment = TargetIdentity(**identities["target"]), EnvironmentIdentity(**identities["environment"])
        intake = ProductionE2EIntake(args.attestation_directory, args.trusted_key_directory)
        if args.install:
            result = intake.install(args.envelope, target, environment,
                                    expected_content_sha256=args.envelope_sha256,
                                    replace_content_sha256=args.replace_content_sha256)
        else:
            _require(args.replace_content_sha256 is None, "replacement_requires_install")
            result = intake.preview(args.envelope, target, environment, expected_content_sha256=args.envelope_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (IntakeError, ObservationError, OSError, TypeError, ValueError) as error:
        print(json.dumps({"state": "unknown" if isinstance(error, IntakeOutcomeUnknown) else "refused",
                          "release_verdict": "NOT_ISSUED",
                          "reason": str(error) if isinstance(error, IntakeError) else "intake_input_invalid"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
