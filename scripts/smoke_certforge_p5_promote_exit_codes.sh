#!/usr/bin/env bash
# Acceptance smoke for certforge-p5-promote.sh soft-stop exit contract.
#
# Three required states:
#   1) hosted CI green + stub pipeline → promotes, exit 0
#   2) hosted CI not green → promotion=pending-hosted-ci, exit 75; && does not advance
#   3) hard failure (bad SHA / missing artefact) → exit 1
#
# Also verifies status lines appear on stderr as well as stdout.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROMOTE="${CERTFORGE_PROMOTE_SCRIPT:-$SCRIPT_DIR/certforge-p5-promote.sh}"
if [ ! -x "$PROMOTE" ]; then
  chmod +x "$PROMOTE" 2>/dev/null || true
fi
if [ ! -f "$PROMOTE" ]; then
  echo "FAIL: promote script not found: $PROMOTE" >&2
  exit 2
fi

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/certforge-p5-promote-smoke.XXXXXX")
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
EVAL="$WORKDIR/eval"
PROMO_DIR="$EVAL/promotion-run"
QUAL_DIR="$EVAL/qualification"
mkdir -p "$ROOT" "$QUAL_DIR" "$PROMO_DIR" "$WORKDIR/logs"
printf 'deadbeefcafebabe0123456789abcdef01234567\n' >"$ROOT/SOURCE_COMMIT"
EXPECTED_COMMIT=$(tr -d '\n' <"$ROOT/SOURCE_COMMIT")

# Minimal qualification report that satisfies qualification_promotes().
python3 - "$QUAL_DIR/qualification-report.json" <<'PY'
import json, sys
from pathlib import Path

def adapter_block():
    return {
        "candidate": {"hard_gates_passed": True},
        "promotion_threshold": {"passed": True},
        "promotion_decision": "PROMOTE",
    }

report = {
    "schema": "echo.certification-forge.p5-qualification/v2",
    "scoring_contract": {"schema": "echo.certification-forge.p5-semantic-scoring/v2"},
    "run_outcome": "COMPLETE",
    "promotion_decision": "PROMOTE",
    "release_verdict": "NOT_READY",
    "training_split_used": False,
    "response_receipts": {"successful_rows": 960},
    "qualification": {"gs343": adapter_block(), "r2d2": adapter_block()},
}
Path(sys.argv[1]).write_text(json.dumps(report), encoding="utf-8")
PY

base_env=(
  "CERTFORGE_PROMOTE_ROOT=$ROOT"
  "CERTFORGE_PROMOTE_EXPECTED_COMMIT=$EXPECTED_COMMIT"
  "CERTFORGE_PROMOTE_SOURCE_COMMIT_FILE=$ROOT/SOURCE_COMMIT"
  "CERTFORGE_PROMOTE_SKIP_SOURCE_CHECK=0"
  "CERTFORGE_PROMOTE_PYTHON=${CERTFORGE_PROMOTE_PYTHON:-python3}"
  "CERTFORGE_PROMOTE_EVAL_ROOT=$EVAL"
  "CERTFORGE_PROMOTE_QUALIFICATION=$QUAL_DIR/qualification-report.json"
  "CERTFORGE_PROMOTE_RUN_ID=smoke-promotion-run"
  "CERTFORGE_PROMOTE_PROMOTION_DIR=$PROMO_DIR"
  "CERTFORGE_PROMOTE_LOG=$WORKDIR/logs/promote.log"
  "CERTFORGE_PROMOTE_PIDFILE=$WORKDIR/logs/promote.pid"
  "CERTFORGE_PROMOTE_LOCK=$WORKDIR/logs/promote.lock"
  "CERTFORGE_PROMOTE_EVALUATOR_PIDFILE=$WORKDIR/logs/evaluator.pid"
)

# Static contract target: prefer co-located .canonical.sh when PROMOTE is a thin wrapper.
STATIC_SCRIPT="$PROMOTE"
if [ -f "$(dirname "$PROMOTE")/certforge-p5-promote.canonical.sh" ]; then
  STATIC_SCRIPT="$(dirname "$PROMOTE")/certforge-p5-promote.canonical.sh"
fi

run_case() {
  local name="$1"
  shift
  local out="$WORKDIR/out-$name.txt"
  local err="$WORKDIR/err-$name.txt"
  local rc=0
  env "${base_env[@]}" "$@" "$PROMOTE" run >"$out" 2>"$err" || rc=$?
  # Single result line: out|err|rc
  printf '%s|%s|%s\n' "$out" "$err" "$rc"
}

pass=0
fail=0
note() { printf '  %s\n' "$*"; }
ok() { pass=$((pass + 1)); note "PASS: $*"; }
bad() { fail=$((fail + 1)); note "FAIL: $*"; }

echo "=== certforge-p5-promote exit-code acceptance ==="
echo "script=$PROMOTE"
echo "workdir=$WORKDIR"

# ---------------------------------------------------------------------------
# Case 1: hosted CI green → promotes (stub pipeline), exit 0
# ---------------------------------------------------------------------------
result=$(run_case green \
  CERTFORGE_HOSTED_CI_MOCK=green:abcdef0123456789abcdef0123456789abcdef01 \
  CERTFORGE_PROMOTE_STUB_PIPELINE=1)
out=${result%%|*}; rest=${result#*|}; err=${rest%%|*}; rc=${rest##*|}
body_out=$(cat "$out"); body_err=$(cat "$err")
note "case1 green: rc=$rc stdout=$(printf '%s' "$body_out" | tr '\n' ' ') stderr=$(printf '%s' "$body_err" | tr '\n' ' ')"
if [ "$rc" = "0" ] && printf '%s' "$body_out" | grep -q 'promotion=deployed:' \
   && printf '%s' "$body_err" | grep -q 'promotion=deployed:' \
   && [ -f "$PROMO_DIR/FORGE_DEPLOYED" ]; then
  ok "hosted CI green promotes and exits 0 (stdout+stderr)"
else
  bad "hosted CI green expected exit 0 + promotion=deployed on both streams (rc=$rc)"
fi
rm -f "$PROMO_DIR/FORGE_DEPLOYED"

# ---------------------------------------------------------------------------
# Case 2: hosted CI not green → pending-hosted-ci, exit 75; && does not advance
# ---------------------------------------------------------------------------
result=$(run_case pending CERTFORGE_HOSTED_CI_MOCK=pending)
out=${result%%|*}; rest=${result#*|}; err=${rest%%|*}; rc=${rest##*|}
body_out=$(cat "$out"); body_err=$(cat "$err")
note "case2 pending: rc=$rc stdout=$(printf '%s' "$body_out" | tr '\n' ' ') stderr=$(printf '%s' "$body_err" | tr '\n' ' ')"
if [ "$rc" = "75" ] \
   && printf '%s' "$body_out" | grep -qx 'promotion=pending-hosted-ci' \
   && printf '%s' "$body_err" | grep -qx 'promotion=pending-hosted-ci'; then
  ok "pending-hosted-ci exits 75 and prints reason on stdout+stderr"
else
  bad "pending-hosted-ci expected exit 75 + dual-stream reason (rc=$rc)"
fi

# && chain must NOT advance
advanced=0
if env "${base_env[@]}" CERTFORGE_HOSTED_CI_MOCK=pending "$PROMOTE" run \
    && advanced=1; then
  :
fi
if [ "$advanced" = "0" ]; then
  ok "caller chained with && does NOT advance on pending-hosted-ci"
else
  bad "&& chain advanced after pending-hosted-ci (soft stop leaked as success)"
fi

# ---------------------------------------------------------------------------
# Case 3: hard failure — bad source SHA → exit 1
# ---------------------------------------------------------------------------
printf '0000000000000000000000000000000000000000\n' >"$ROOT/SOURCE_COMMIT"
result=$(run_case hardsha \
  CERTFORGE_HOSTED_CI_MOCK=green:abcdef0123456789abcdef0123456789abcdef01 \
  CERTFORGE_PROMOTE_STUB_PIPELINE=1)
out=${result%%|*}; rest=${result#*|}; err=${rest%%|*}; rc=${rest##*|}
body_out=$(cat "$out"); body_err=$(cat "$err")
note "case3 bad-sha: rc=$rc stdout=$(printf '%s' "$body_out" | tr '\n' ' ') stderr=$(printf '%s' "$body_err" | tr '\n' ' ')"
if [ "$rc" = "1" ] \
   && printf '%s' "$body_out" | grep -q 'promotion=blocked-source-commit-mismatch' \
   && printf '%s' "$body_err" | grep -q 'promotion=blocked-source-commit-mismatch'; then
  ok "bad source SHA hard-fails with exit 1 (stdout+stderr)"
else
  bad "bad source SHA expected exit 1 (rc=$rc)"
fi
# restore pin for missing-artefact case
printf '%s\n' "$EXPECTED_COMMIT" >"$ROOT/SOURCE_COMMIT"

# ---------------------------------------------------------------------------
# Case 3b: hard failure — missing qualification artefact → exit 1
# ---------------------------------------------------------------------------
rm -f "$QUAL_DIR/qualification-report.json"
result=$(run_case missing \
  CERTFORGE_HOSTED_CI_MOCK=green:abcdef0123456789abcdef0123456789abcdef01 \
  CERTFORGE_PROMOTE_STUB_PIPELINE=1)
out=${result%%|*}; rest=${result#*|}; err=${rest%%|*}; rc=${rest##*|}
body_out=$(cat "$out"); body_err=$(cat "$err")
note "case3b missing-artefact: rc=$rc stdout=$(printf '%s' "$body_out" | tr '\n' ' ') stderr=$(printf '%s' "$body_err" | tr '\n' ' ')"
if [ "$rc" = "1" ]; then
  ok "missing qualification artefact hard-fails with exit 1"
else
  bad "missing artefact expected exit 1 (rc=$rc)"
fi

# ---------------------------------------------------------------------------
# Static contract: no soft-stop exit 0 for pending-hosted-ci remains in script
# ---------------------------------------------------------------------------
if grep -n "pending-hosted-ci" "$STATIC_SCRIPT" | grep -E 'exit 0' >/dev/null; then
  bad "script still contains exit 0 near pending-hosted-ci"
else
  ok "no exit 0 adjacent to pending-hosted-ci in script source"
fi
if grep -q 'EXIT_PENDING=75' "$STATIC_SCRIPT" && grep -q 'soft_stop' "$STATIC_SCRIPT"; then
  ok "script defines EXIT_PENDING=75 and soft_stop helper"
else
  bad "script missing EXIT_PENDING/soft_stop contract helpers"
fi

echo
echo "=== summary: pass=$pass fail=$fail ==="
if [ "$fail" -ne 0 ]; then
  exit 1
fi
exit 0
