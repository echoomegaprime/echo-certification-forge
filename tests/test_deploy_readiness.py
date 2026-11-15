from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest


HELPER = Path(__file__).resolve().parents[1] / "deploy" / "readiness.sh"


def test_deploy_validates_before_side_effects_and_bounds_all_health_waits() -> None:
    script = HELPER.with_name("deploy_forge.sh").read_text(encoding="utf-8")
    source = script.index('/readiness.sh"')
    configure = script.index('configure_readiness_timeout "${CERTFORGE_READY_TIMEOUT_S:-90}"')
    lock = script.index('exec 9>"$LOCK_FILE"')
    fetch = script.index('git "${GITC[@]}" fetch')
    assert source < configure < lock < fetch
    waits = re.findall(
        r"^[ \t]*readiness_start\n[ \t]*while readiness_pending; do\n(.*?)^[ \t]*done$",
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert len(waits) == 3
    assert sum('readiness_probe "$STAGING_PORT"' in wait for wait in waits) == 1
    assert sum('readiness_probe "$PROD_PORT"' in wait for wait in waits) == 2
    assert all("readiness_pause" in wait for wait in waits)
    assert "READY_POLLS" not in script


def _bash() -> str:
    # Windows' System32/bash.exe may only be an unconfigured WSL launcher.
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        if git_bash.is_file():
            return str(git_bash)
    executable = shutil.which("bash")
    if executable is None:
        pytest.skip("Bash is required for deploy readiness behavior tests")
    return executable


def _run(body: str, *args: str, timeout: float = 5) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            _bash(), "--noprofile", "--norc", "-c",
            'set -euo pipefail\nsource "$1"\nshift\n' + body,
            "readiness-test", HELPER.as_posix(), *args,
        ],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


@pytest.mark.parametrize("value", ["1", "90", "1800"])
def test_readiness_accepts_supported_timeout(value: str) -> None:
    result = _run('configure_readiness_timeout "$1"\nprintf "%s" "$READY_TIMEOUT_S"', value)
    assert result.returncode == 0, result.stderr
    assert result.stdout == value


@pytest.mark.parametrize(
    "value",
    ["", "0", "-1", "1801", "090", "08", "1.5", "1+2", " 90", "90 ", "x", "9" * 40],
)
def test_readiness_rejects_invalid_configuration_before_continuing(value: str) -> None:
    result = _run(
        'configure_readiness_timeout "$1"\nprintf "UNEXPECTED SIDE EFFECT"', value
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "must be an integer between 1 and 1800" in result.stderr


def test_readiness_returns_on_first_success_without_polling_delay() -> None:
    result = _run(
        """
configure_readiness_timeout 90
curl() { printf 'healthy'; }
sleep() { printf 'UNEXPECTED DELAY'; return 1; }
readiness_start
while readiness_pending; do
  if readiness_probe 8311; then
    exit 0
  fi
  readiness_pause
done
exit 1
"""
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "healthy"


def test_readiness_allows_cold_start_beyond_old_twenty_second_budget() -> None:
    result = _run(
        """
configure_readiness_timeout 90
SECONDS=100
attempts=0
curl() {
  attempts=$(( attempts + 1 ))
  SECONDS=$(( SECONDS + 1 ))
  (( attempts == 25 ))
}
sleep() { :; }
readiness_start
while readiness_pending; do
  if readiness_probe 8311; then
    printf '%s' "$attempts"
    exit 0
  fi
  readiness_pause
done
exit 1
"""
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "25"


def test_failed_probe_time_consumes_total_deadline() -> None:
    result = _run(
        """
configure_readiness_timeout 3
SECONDS=100
attempts=0
curl() {
  attempts=$(( attempts + 1 ))
  SECONDS=$(( SECONDS + 1 ))
  return 22
}
sleep() { :; }
readiness_start
while readiness_pending; do
  if readiness_probe 8311; then
    exit 1
  fi
  readiness_pause
done
printf '%s' "$attempts"
"""
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "3"


@pytest.mark.parametrize("remaining, expected", [(90, "2"), (2, "2"), (1, "1")])
def test_probe_bounds_connection_and_response_to_remaining_budget(
    remaining: int, expected: str
) -> None:
    result = _run(
        """
configure_readiness_timeout "$1"
SECONDS=100
curl() { printf '%s\n' "$@"; }
readiness_start
readiness_probe 8311
""",
        str(remaining),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "-sf", "http://127.0.0.1:8311/healthz",
        "--connect-timeout", expected, "--max-time", expected,
    ]


def test_expired_budget_neither_probes_nor_sleeps() -> None:
    result = _run(
        """
configure_readiness_timeout 1
SECONDS=100
curl() { printf 'UNEXPECTED PROBE'; }
sleep() { printf 'UNEXPECTED DELAY'; }
readiness_start
SECONDS=$(( SECONDS + 1 ))
if readiness_pending || readiness_probe 8311; then
  exit 1
fi
readiness_pause
"""
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_stalled_probe_uses_finite_response_timeout() -> None:
    started = time.monotonic()
    result = _run(
        """
configure_readiness_timeout 1
curl() {
  local max_time=''
  while (( $# )); do
    if [[ "$1" == --max-time ]]; then
      max_time="$2"
      shift
    fi
    shift
  done
  [[ "$max_time" == 1 ]] || return 99
  # Simulate curl accepting a connection but receiving no response. No network.
  sleep "$max_time"
  return 28
}
readiness_start
if readiness_probe 8311; then
  exit 1
else
  status=$?
fi
printf '%s' "$status"
"""
    )
    elapsed = time.monotonic() - started
    assert result.returncode == 0, result.stderr
    assert result.stdout == "28"
    assert 0.8 <= elapsed < 5
