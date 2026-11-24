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


def test_a_logic_error_from_sqlite_itself_is_not_transient(tmp_path: Any) -> None:
    connection = sqlite3.connect(tmp_path / "logic.sqlite3", isolation_level=None)
    try:
        with pytest.raises(sqlite3.OperationalError) as raised:
            connection.execute("COMMIT")
    finally:
        connection.close()
    assert "cannot commit" in str(raised.value).lower()
    assert raised.value.sqlite_errorcode == 1
    assert not is_transient_sqlite_error(raised.value)


@pytest.mark.parametrize(
    "message",
    ["database is locked", "disk I/O error", "database or disk is full", "cannot commit transaction"],
)
def test_a_non_transient_result_code_overrides_a_transient_looking_message(message: str) -> None:
    assert not is_transient_sqlite_error(_coded(message, 1))
    assert not is_transient_sqlite_error(_coded(message, 19))


def test_fallback_without_a_code_stays_narrow() -> None:
    assert not is_transient_sqlite_error(sqlite3.OperationalError("cannot commit - no transaction is active"))
    assert is_transient_sqlite_error(
        sqlite3.OperationalError("cannot commit transaction - SQL statements in progress")
    )
    for message in ("database or disk is full", "database is locked", "disk I/O error"):
        assert is_transient_sqlite_error(sqlite3.OperationalError(message))


def _run_main(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, dispatch: Any, *extra: str
) -> tuple[Any, list[float]]:
    """Drive the real dispatcher entry point with only the claim call replaced."""
    from echo_certification_forge.signing import Ed25519VerdictSigner

    sleeps: list[float] = []
    monkeypatch.setenv("ECHO_CERTFORGE_API_KEY_PEPPER", "synthetic-retry-classification-test-pepper")
    monkeypatch.setattr(dispatch_worker, "_load_signer", lambda _: Ed25519VerdictSigner.generate())
    monkeypatch.setattr(dispatch_worker, "dispatch_once", dispatch)
    monkeypatch.setattr(dispatch_worker.time, "sleep", sleeps.append)
    arguments = [
        "--non-production-compat",
        "--db",
        str(tmp_path / "loop.sqlite3"),
        "--evidence-root",
        str(tmp_path / "evidence"),
        *extra,
    ]
    return (lambda: dispatch_worker.main(arguments)), sleeps


PERMANENT_OS_ERRORS = [
    FileExistsError(errno.EEXIST, "File exists"),
    PermissionError(errno.EACCES, "Permission denied"),
    FileNotFoundError(errno.ENOENT, "No such file or directory"),
]


@pytest.mark.parametrize("error", PERMANENT_OS_ERRORS)
def test_claim_loop_stops_on_a_permanent_os_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: Any, error: OSError
) -> None:
    calls: list[int] = []

    def dispatch(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        assert len(calls) <= 8, "a permanent error must not be retried without end"
        raise error

    run_main, sleeps = _run_main(monkeypatch, tmp_path, dispatch)
    with pytest.raises(type(error)):
        run_main()
    assert len(calls) == 8
    assert len(sleeps) == 7
    events = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if "dispatcher_db_transient_error" in line
    ]
    assert len(events) == 8
    assert all(event["transient"] is False for event in events)


@pytest.mark.parametrize("error", PERMANENT_OS_ERRORS)
def test_once_mode_reports_a_permanent_os_error_as_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: OSError
) -> None:
    def dispatch(*args: Any, **kwargs: Any) -> Any:
        raise error

    run_main, sleeps = _run_main(monkeypatch, tmp_path, dispatch, "--once")
    assert run_main() == 1
    assert sleeps == []


TRANSIENT_LOOP_ERRORS = [
    OSError(errno.EIO, "Input/output error"),
    OSError(errno.ENOSPC, "No space left on device"),
    sqlite3.OperationalError("database is locked"),
    _coded("database or disk is full", 13),
]


@pytest.mark.parametrize("error", TRANSIENT_LOOP_ERRORS)
def test_claim_loop_keeps_waiting_through_a_transient_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: BaseException
) -> None:
    calls: list[int] = []

    def dispatch(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if len(calls) <= 12:
            raise error
        return object(), {"dispatcher_halted": True}

    run_main, sleeps = _run_main(monkeypatch, tmp_path, dispatch)
    assert run_main() == 2
    assert len(calls) == 13
    assert len(sleeps) == 12 and all(delay > 0 for delay in sleeps)


@pytest.mark.parametrize("error", TRANSIENT_LOOP_ERRORS)
def test_once_mode_reports_a_transient_error_as_retryable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, error: BaseException
) -> None:
    def dispatch(*args: Any, **kwargs: Any) -> Any:
        raise error

    run_main, sleeps = _run_main(monkeypatch, tmp_path, dispatch, "--once")
    assert run_main() == 4
    assert sleeps == []


def test_claim_loop_stops_on_a_sqlite_logic_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    calls: list[int] = []

    def dispatch(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        assert len(calls) <= 8
        raise _coded("cannot commit - no transaction is active", 1)

    run_main, sleeps = _run_main(monkeypatch, tmp_path, dispatch)
    with pytest.raises(sqlite3.OperationalError):
        run_main()
    assert len(calls) == 8 and len(sleeps) == 7
