"""Legacy-table migration must not mask its real failure (Echo fleet #46912).

On 2026-10-19 echo-certforge-dispatcher flapped at start-up with
``sqlite3.OperationalError: cannot rollback - no transaction is active``. When ``BEGIN IMMEDIATE``
itself fails (for example ``database is locked`` once the busy timeout expires while another
process holds the write lock), ``_migrate_legacy_platform_tables`` ran ``ROLLBACK`` with no
transaction open. That raised a second error which hid the real cause.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from echo_certification_forge.subscriber import SubscriberGovernance


class _LockedOnBegin:
    """A real sqlite3 connection whose ``BEGIN IMMEDIATE`` fails the way a held write lock does."""

    def __init__(self, inner: sqlite3.Connection) -> None:
        object.__setattr__(self, "_inner", inner)

    def execute(self, sql, *args):
        if str(sql).strip().upper().startswith("BEGIN IMMEDIATE"):
            raise sqlite3.OperationalError("database is locked")
        return self._inner.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)


def _governance_without_init(db: Path) -> SubscriberGovernance:
    gov = object.__new__(SubscriberGovernance)
    gov.db_path = db
    return gov


def test_a_failed_begin_surfaces_the_real_error_not_cannot_rollback(tmp_path, monkeypatch) -> None:
    db = tmp_path / "certforge.sqlite3"
    gov = _governance_without_init(db)
    real_connect = SubscriberGovernance._connect
    monkeypatch.setattr(SubscriberGovernance, "_connect", lambda self: _LockedOnBegin(real_connect(self)))
    with pytest.raises(sqlite3.OperationalError) as exc:
        gov._migrate_legacy_platform_tables()
    assert "database is locked" in str(exc.value)
    assert "cannot rollback" not in str(exc.value)


def test_an_error_inside_the_transaction_still_rolls_back(tmp_path) -> None:
    db = tmp_path / "certforge.sqlite3"
    with sqlite3.connect(db) as c:
        # A legacy-looking subscriber_users table that matches neither layout: the migration must
        # refuse it and leave the database exactly as it was.
        c.execute("CREATE TABLE subscriber_users (user_id TEXT, unexpected TEXT)")
    gov = _governance_without_init(db)
    with pytest.raises(RuntimeError, match="incompatible subscriber schema"):
        gov._migrate_legacy_platform_tables()
    with sqlite3.connect(db) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        in_tx = c.in_transaction
    assert tables == {"subscriber_users"} and not in_tx


def test_a_needed_rename_is_committed(tmp_path) -> None:
    db = tmp_path / "certforge.sqlite3"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE subscriber_users (user_id TEXT, email TEXT, created_at TEXT)")
    _governance_without_init(db)._migrate_legacy_platform_tables()
    with sqlite3.connect(db) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"legacy_platform_subscriber_users"}
