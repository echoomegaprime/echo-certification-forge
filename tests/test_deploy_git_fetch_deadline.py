"""Isolated, no-network regression checks for deploy source-fetch deadlines."""
from pathlib import Path
import os
import subprocess

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] / "deploy" / "deploy_forge.sh").read_text()
START = '[[ "$GIT_ACQUISITION_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]]'
END = 'NEW_SHA="$(git rev-parse'
FETCH_BLOCK = SCRIPT[SCRIPT.index(START) : SCRIPT.index(END)]


def exercise(tmp_path: Path, seconds: str, code: int) -> subprocess.CompletedProcess[str]:
    mock = 'timeout() { printf "%s\n" "$@" > "$FETCH_ARGS_LOG"; return ' + str(code) + '; }'
    source = (
        'set -euo pipefail\n'
        f'GIT_ACQUISITION_TIMEOUT_SECONDS={seconds}\n'
        'SOURCE_REPO="$PWD"\n'
        'BRANCH=main\n'
        'GITC=()\n'
        + mock + '\n' + FETCH_BLOCK
    )
    return subprocess.run(
        ["bash", "-c", source],
        cwd=tmp_path,
        env={**os.environ, "FETCH_ARGS_LOG": str(tmp_path / "timeout-args.txt")},
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


def test_bounded_fetch_happens_after_validation_before_sha_resolution(tmp_path: Path) -> None:
    assert SCRIPT.index(START) < SCRIPT.index('fetch --quiet origin "$BRANCH"') < SCRIPT.index(END)
    result = exercise(tmp_path, "30", 0)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "timeout-args.txt").read_text().splitlines() == [
        "--signal=TERM", "--kill-after=5s", "30s", "git",
        "fetch", "--quiet", "origin", "main",
    ]


@pytest.mark.parametrize("status", [124, 137])
def test_deadline_failure_is_fail_closed(tmp_path: Path, status: int) -> None:
    result = exercise(tmp_path, "30", status)
    assert result.returncode == status
    assert "exceeded the configured acquisition deadline" in result.stdout


def test_other_fetch_failure_is_fail_closed(tmp_path: Path) -> None:
    result = exercise(tmp_path, "30", 23)
    assert result.returncode == 23
    assert "source fetch failed (status 23)" in result.stdout


@pytest.mark.parametrize("seconds", ["invalid", "0", "29", "1801"])
def test_invalid_deadlines_reject_before_fetch(tmp_path: Path, seconds: str) -> None:
    result = exercise(tmp_path, seconds, 0)
    assert result.returncode != 0
    assert not (tmp_path / "timeout-args.txt").exists()
