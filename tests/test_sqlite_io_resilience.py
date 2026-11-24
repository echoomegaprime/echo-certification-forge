"""Transient-error classification and startup retry for the dispatcher (incident #9676)."""
from __future__ import annotations

import errno
import json
import sqlite3
from typing import Any

import pytest

from echo_certification_forge import dispatch_worker
from echo_certification_forge.sqlite_io import is_transient_sqlite_error


def _coded(message: str, code: int) -> sqlite3.OperationalError:
    error = sqlite3.OperationalError(message)
    error.sqlite_errorcode = code
    return error


@pytest.mark.parametrize(
    "message",
    [
        "database or disk is full",
        "disk I/O error",
        "database is locked",
        "database is busy",
        "unable to open database file",
        "locking protocol",
    ],
)
def test_real_sqlite_messages_are_transient(message: str) -> None:
    assert is_transient_sqlite_error(sqlite3.OperationalError(message))


@pytest.mark.parametrize("code", [5, 6, 10, 13, 14, 15, 778, 266, 517])
def test_result_codes_decide_even_with_an_unknown_message(code: int) -> None:
    # 778, 266 and 517 are extended codes of IOERR, IOERR and BUSY.
    assert is_transient_sqlite_error(_coded("message this code path has never seen", code))


@pytest.mark.parametrize(
    "error",
    [
        sqlite3.OperationalError("no such table: dispatch_outbox"),
        _coded("SQL logic error", 1),
        sqlite3.IntegrityError("database is locked"),
        ValueError("database is locked"),
        OSError(errno.ENOSPC, "No space left on device"),
    ],
)
def test_other_errors_are_not_classified_transient(error: BaseException) -> None:
    assert not is_transient_sqlite_error(error)


def test_a_full_disk_from_sqlite_itself_is_transient(tmp_path: Any) -> None:
    connection = sqlite3.connect(tmp_path / "full.sqlite3")
    try:
        connection.execute("PRAGMA page_size = 512")
        connection.execute("PRAGMA max_page_count = 4")
        connection.execute("CREATE TABLE filler (body TEXT)")
        with pytest.raises(sqlite3.OperationalError) as raised:
            for _ in range(200):
                connection.execute("INSERT INTO filler VALUES (?)", ("x" * 400,))
    finally:
        connection.close()
    assert "full" in str(raised.value).lower()
    assert is_transient_sqlite_error(raised.value)


def _step(action: Any, *, once: bool = False) -> Any:
    return dispatch_worker._startup_db_step(
        "subscriber_governance",
        action,
        db_path="/nonexistent/certforge.sqlite3",
        dispatcher_id="dispatcher-test",
        once=once,
    )


def test_startup_step_waits_out_transient_errors(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(dispatch_worker.time, "sleep", sleeps.append)
    failures: list[BaseException] = [
        sqlite3.OperationalError("database or disk is full"),
        OSError(errno.EIO, "Input/output error"),
        sqlite3.OperationalError("database is locked"),
    ]

    def action() -> str:
        if failures:
            raise failures.pop(0)
        return "ready"

    assert _step(action) == "ready"
    assert len(sleeps) == 3 and all(delay > 0 for delay in sleeps)
    assert sleeps == sorted(sleeps)
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["event"] for event in events] == ["dispatcher_startup_db_transient_error"] * 3
    assert [event["streak"] for event in events] == [1, 2, 3]
    assert {event["step"] for event in events} == {"subscriber_governance"}


@pytest.mark.parametrize(
    "error",
    [
        sqlite3.OperationalError("no such table: dispatch_outbox"),
        PermissionError(errno.EACCES, "Permission denied"),
        FileNotFoundError(errno.ENOENT, "No such file or directory"),
    ],
)
def test_startup_step_raises_errors_that_will_not_clear(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(dispatch_worker.time, "sleep", sleeps.append)

    def action() -> None:
        raise error

    with pytest.raises(type(error)):
        _step(action)
    assert sleeps == []


def test_once_mode_reports_a_transient_startup_error_without_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(dispatch_worker.time, "sleep", sleeps.append)

    def action() -> None:
        raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(dispatch_worker._StartupUnavailable):
        _step(action, once=True)
    assert sleeps == []
