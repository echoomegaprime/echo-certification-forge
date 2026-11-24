"""SQLite I/O resilience (incident #9676 unit_flapping on echo-certforge-dispatcher).

Retries transient disk I/O / lock errors that previously exited the dispatcher
process under root-filesystem pressure (Restart=always → restart storm).
"""
from __future__ import annotations

import logging
import random
import shutil
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger("echo_certification_forge.sqlite_io")

# Primary SQLite result codes for conditions that can clear by themselves:
# BUSY 5, LOCKED 6, IOERR 10, FULL 13, CANTOPEN 14, PROTOCOL 15. Extended codes
# keep the primary code in their low byte.
_TRANSIENT_CODES = frozenset({5, 6, 10, 13, 14, 15})

# Message fallback for errors that carry no result code. SQLite reports a full
# disk as "database or disk is full".
_TRANSIENT = (
    "disk i/o error",
    "disk is full",
    "disk full",
    "database is locked",
    "database is busy",
    "unable to open database file",
    "cannot commit",
    "locking protocol",
)


def is_transient_sqlite_error(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in _TRANSIENT_CODES:
        return True
    msg = str(exc).lower()
    return any(m in msg for m in _TRANSIENT)


def free_space_bytes(path: Path | str) -> int | None:
    try:
        p = Path(path)
        target = p if p.exists() else p.parent
        return int(shutil.disk_usage(str(target)).free)
    except OSError:
        return None


def connect_sqlite(
    db_path: Path | str,
    *,
    timeout: float = 10.0,
    wal: bool = True,
    synchronous: str = "FULL",
    busy_timeout_ms: int = 10000,
    foreign_keys: bool = True,
    max_attempts: int = 4,
    label: str = "sqlite_connect",
) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    attempts = min(max(int(max_attempts), 1), 8)
    last: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            free = free_space_bytes(path)
            if free is not None and free < 64 * 1024 * 1024:
                logger.warning(
                    "%s low free space free_mb=%.1f path=%s",
                    label,
                    free / (1024 * 1024),
                    path,
                )
            connection = sqlite3.connect(str(path), timeout=timeout)
            connection.row_factory = sqlite3.Row
            try:
                if foreign_keys:
                    connection.execute("PRAGMA foreign_keys = ON")
                if wal:
                    connection.execute("PRAGMA journal_mode = WAL")
                if synchronous:
                    connection.execute(f"PRAGMA synchronous = {synchronous}")
                if busy_timeout_ms > 0:
                    connection.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
            except Exception:
                connection.close()
                raise
            return connection
        except (sqlite3.OperationalError, OSError) as exc:
            last = exc
            if attempt >= attempts or not (
                is_transient_sqlite_error(exc) or isinstance(exc, OSError)
            ):
                break
            # Full-jitter exponential backoff (never zero sleep).
            base = min(8.0, 0.25 * (2 ** (attempt - 1)))
            delay = base * 0.5 + random.uniform(0, base * 0.5)
            logger.warning(
                "retry %s attempt=%s/%s sleep=%.3fs err=%s detail=%s",
                label,
                attempt,
                attempts,
                delay,
                type(exc).__name__,
                str(exc)[:120],
            )
            time.sleep(delay)
    assert last is not None
    raise last


__all__ = [
    "connect_sqlite",
    "free_space_bytes",
    "is_transient_sqlite_error",
]
