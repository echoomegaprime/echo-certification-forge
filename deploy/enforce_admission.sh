#!/usr/bin/env bash
# P6 deployment enforcement wrapper — makes certification MANDATORY around promotion.
#
# Deployment pipelines call this with the REAL deploy command as arguments:
#
#     deploy/enforce_admission.sh <deploy command...>
#
# It (1) obtains a recorded admission decision from the forge (fail-closed), (2) runs the
# supplied deploy command ONLY if admission was allowed, and (3) records the REAL outcome
# (SUCCEEDED / FAILED / ROLLED_BACK) against the exact admission_id — which is what unlocks
# production after a successful staging deployment and what produces rollback evidence
# after a failed production one. A missing deploy command is a fail-closed error: an
# admission without a recorded outcome must never be minted by this integration.
#
# Required environment:
#   CERTFORGE_URL                     e.g. http://127.0.0.1:8309
#   CERTFORGE_TENANT                  tenant id
#   CERTFORGE_ARTIFACT_DIGEST         sha256:<64-hex> (or bare hex) of the EXACT artifact
#   CERTFORGE_ENVIRONMENT             staging | production
#   CERTFORGE_ENV_IDENTITY_DIGEST     64-hex environment identity digest
#   CERTFORGE_RULE_MANIFEST_DIGEST    64-hex active mandatory-rule manifest digest
#   CERTFORGE_DEPLOYMENT_ID           unique id for this deployment attempt
#   CERTFORGE_DEPLOY_SECRET           tenant deployment credential (HMAC secret) — the
#                                     hook signs every admission/outcome request with it
#   CERTFORGE_ROLLBACK_CMD            REQUIRED for production deployments: the command
#                                     that rolls production back. A production deployment
#                                     may NEVER begin without a rollback path, so a
#                                     missing rollback command fails closed (exit 3)
#                                     BEFORE any admission is requested. It is ALWAYS run
#                                     after a FAILED production deployment (even when
#                                     outcome recording is completely down); it receives
#                                     the exact rollback target BOUND INTO THE ADMISSION
#                                     RECORD in CERTFORGE_ROLLBACK_TARGET and, when it
#                                     succeeds, a ROLLED_BACK outcome naming that exact
#                                     bound digest is recorded. Incomplete outcome
#                                     reporting fails the pipeline closed (exit 3) AFTER
#                                     the rollback has executed.
# Optional environment:
#   CERTFORGE_REQUESTED_BY            actor recorded on the admission (default deployment.pipeline)
#   CERTFORGE_PYTHON                  python interpreter to use (default python3)
#
# Outcome recording is idempotent/recoverable: every logical outcome gets ONE stable
# operation id reused (with a fresh signature nonce) across up to 3 attempts, so if the
# forge COMMITTED an outcome but the response was lost, the retry recovers the committed
# record instead of tripping the terminal-transition guard.
#
# Production rollback binding: the forge FREEZES the exact rollback target into the
# admission record BEFORE the deployment begins. This script refuses to start a
# production deployment whose admission carries no bound rollback target (exit 3) —
# the FIRST production deployment of a tenant must be provisioned out-of-band through
# the authenticated API, never through a wrapper that could not roll it back. On
# failure the rollback ALWAYS runs with the admission-bound target, even when every
# outcome-recording attempt fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${CERTFORGE_PYTHON:-python3}"
HOOK="$SCRIPT_DIR/scripts/deployment_admission_hook.py"

for var in CERTFORGE_URL CERTFORGE_TENANT CERTFORGE_ARTIFACT_DIGEST CERTFORGE_ENVIRONMENT \
           CERTFORGE_ENV_IDENTITY_DIGEST CERTFORGE_RULE_MANIFEST_DIGEST CERTFORGE_DEPLOYMENT_ID \
           CERTFORGE_DEPLOY_SECRET; do
  if [ -z "${!var:-}" ]; then
    echo "!! ADMISSION BLOCKED — $var is not set (fail-closed)" >&2
    exit 3
  fi
done

if [ "$#" -eq 0 ]; then
  echo "!! ADMISSION BLOCKED — no deploy command supplied (fail-closed)" >&2
  echo "   usage: enforce_admission.sh <deploy command...>" >&2
  exit 3
fi

# A production deployment must NEVER begin without a rollback mechanism in place.
# This is checked BEFORE any admission is requested, so no admission is ever minted
# for a production deployment that could not be rolled back.
if [ "$CERTFORGE_ENVIRONMENT" = "production" ] && [ -z "${CERTFORGE_ROLLBACK_CMD:-}" ]; then
  echo "!! ADMISSION BLOCKED — production deployments require CERTFORGE_ROLLBACK_CMD;" >&2
  echo "   no rollback mechanism means the deployment must not begin (fail-closed)" >&2
  exit 3
fi

new_operation_id() {
  # One stable operation id per LOGICAL outcome, reused across retries so a committed
  # outcome whose response was lost is recovered idempotently on the next attempt.
  "$PYTHON_BIN" -c 'import secrets; print("op-" + secrets.token_hex(16))'
}

record_outcome_retry() {
  # record_outcome_retry OUTVAR STATUS DETAIL [ROLLBACK_TO]
  # Up to 3 attempts under ONE stable operation id (fresh signature/nonce each — the hook
  # signs per invocation), so a commit-then-response-loss is RECOVERED: the retry returns
  # the committed record instead of tripping the terminal-transition guard. Captures the
  # hook's stdout JSON into OUTVAR and echoes it; returns nonzero when every attempt
  # failed. NEVER exits the script — the caller decides what failure of REPORTING means
  # (it must not prevent the actual rollback).
  local __outvar="$1" status="$2" detail="$3" rollback_to="${4:-}"
  local extra=() out="" rc=1 attempt operation_id
  operation_id="$(new_operation_id)"
  if [ -n "$rollback_to" ]; then
    extra=(--rollback-to "$rollback_to")
  fi
  for attempt in 1 2 3; do
    set +e
    out="$("$PYTHON_BIN" "$HOOK" outcome \
        --forge-url "$CERTFORGE_URL" \
        --tenant "$CERTFORGE_TENANT" \
        --admission-id "$ADMISSION_ID" \
        --status "$status" \
        --detail "$detail" \
        --operation-id "$operation_id" \
        "${extra[@]}")"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      break
    fi
    echo "!! $status outcome recording attempt $attempt/3 failed (exit $rc)" >&2
    if [ "$attempt" -lt 3 ]; then
      sleep 1
    fi
  done
  printf -v "$__outvar" '%s' "$out"
  if [ -n "$out" ]; then
    printf '%s\n' "$out"
  fi
  return "$rc"
}

set +e
ADMIT_OUT="$("$PYTHON_BIN" "$HOOK" admit \
  --forge-url "$CERTFORGE_URL" \
  --tenant "$CERTFORGE_TENANT" \
  --artifact-digest "$CERTFORGE_ARTIFACT_DIGEST" \
  --environment "$CERTFORGE_ENVIRONMENT" \
  --environment-identity-digest "$CERTFORGE_ENV_IDENTITY_DIGEST" \
  --rule-manifest-digest "$CERTFORGE_RULE_MANIFEST_DIGEST" \
  --deployment-id "$CERTFORGE_DEPLOYMENT_ID" \
  --requested-by "${CERTFORGE_REQUESTED_BY:-deployment.pipeline}")"
ADMIT_STATUS=$?
set -e
printf '%s\n' "$ADMIT_OUT"

if [ "$ADMIT_STATUS" -ne 0 ]; then
  echo "!! ADMISSION BLOCKED (exit $ADMIT_STATUS) — deployment must not proceed" >&2
  exit "$ADMIT_STATUS"
fi

ADMISSION_ID="$(printf '%s' "$ADMIT_OUT" | "$PYTHON_BIN" -c \
  'import json,sys; print(json.loads(sys.stdin.read().strip().splitlines()[-1])["admission_id"])')"
if [ -z "$ADMISSION_ID" ]; then
  echo "!! ADMISSION BLOCKED — admission_id missing from allowed decision (fail-closed)" >&2
  exit 3
fi

# The exact rollback target is FROZEN into the admission record before any deployment
# begins — extract it now. A production deployment with no bound rollback target must
# never start: there would be nothing to roll back to if it failed.
ROLLBACK_TARGET=""
if [ "$CERTFORGE_ENVIRONMENT" = "production" ]; then
  ROLLBACK_TARGET="$(printf '%s' "$ADMIT_OUT" | "$PYTHON_BIN" -c '
import json, sys
lines = [line for line in sys.stdin.read().strip().splitlines() if line.strip()]
decision = json.loads(lines[-1]) if lines else {}
candidate = decision.get("rollback_candidate") or {}
print(candidate.get("artifact_sha256") or "")
' 2>/dev/null || true)"
  if [ -z "$ROLLBACK_TARGET" ]; then
    echo "!! ADMISSION BLOCKED — no admission-bound rollback target; refusing to deploy" >&2
    echo "   (the first production deployment must be provisioned out-of-band via the" >&2
    echo "    authenticated API — this wrapper never deploys what it cannot roll back)" >&2
    exit 3
  fi
fi
echo "== ADMISSION ALLOWED ($ADMISSION_ID) — running $CERTFORGE_ENVIRONMENT deployment =="

set +e
"$@"
DEPLOY_STATUS=$?
set -e

if [ "$DEPLOY_STATUS" -eq 0 ]; then
  SUCCESS_OUT=""
  if ! record_outcome_retry SUCCESS_OUT SUCCEEDED "deployment command succeeded: $*"; then
    echo "!! OUTCOME NOT RECORDED (SUCCEEDED) — the ledger has no record of this deployment result" >&2
    exit 3
  fi
  echo "== DEPLOYMENT SUCCEEDED — outcome recorded against $ADMISSION_ID =="
  exit 0
fi

# ---------------------------------------------------------------------------------------
# Failure path. Reporting failures are captured — they must NEVER prevent the actual
# production rollback from executing. Any incomplete reporting fails the pipeline
# closed (exit 3) AFTER the rollback has run.
# ---------------------------------------------------------------------------------------
echo "!! DEPLOYMENT FAILED (exit $DEPLOY_STATUS) — recording FAILED outcome" >&2
REPORTING_OK=1
FAILED_OUT=""
if ! record_outcome_retry FAILED_OUT FAILED "deployment command failed with exit $DEPLOY_STATUS: $*"; then
  echo "!! OUTCOME NOT RECORDED (FAILED) — continuing to rollback; will fail closed after" >&2
  REPORTING_OK=0
fi

if [ "$CERTFORGE_ENVIRONMENT" = "production" ] && [ -n "${CERTFORGE_ROLLBACK_CMD:-}" ]; then
  # The rollback target was FROZEN into the admission record before the deployment began
  # and extracted before the deploy command ran — it is available even when every
  # outcome-recording attempt fails. Never re-read the live rollback target here:
  # concurrent deployments could have drifted it, and the ledger only accepts a
  # ROLLED_BACK outcome naming the admission-bound digest.
  echo "== EXECUTING ROLLBACK (admission-bound last-known-good: $ROLLBACK_TARGET) ==" >&2
  set +e
  CERTFORGE_ROLLBACK_TARGET="$ROLLBACK_TARGET" bash -c "$CERTFORGE_ROLLBACK_CMD"
  ROLLBACK_STATUS=$?
  set -e
  if [ "$ROLLBACK_STATUS" -ne 0 ]; then
    echo "!! ROLLBACK COMMAND FAILED (exit $ROLLBACK_STATUS) — FAILED outcome stands" >&2
  else
    # ALWAYS attempt to record the rollback against the admission-bound target — even if
    # the FAILED report above appeared to fail, its commit may simply have had its
    # response lost; a successfully recorded ROLLED_BACK proves the ledger holds the
    # complete FAILED -> ROLLED_BACK sequence.
    ROLLED_BACK_OUT=""
    if record_outcome_retry ROLLED_BACK_OUT ROLLED_BACK \
        "rolled back to admission-bound last-known-good after failed deployment" "$ROLLBACK_TARGET"; then
      echo "== ROLLBACK RECORDED against $ADMISSION_ID ==" >&2
      # ROLLED_BACK is only accepted after a committed FAILED production outcome, so a
      # successful record here proves reporting is complete end-to-end.
      REPORTING_OK=1
    else
      echo "!! ROLLBACK EXECUTED but ROLLED_BACK outcome NOT RECORDED — failing closed" >&2
      REPORTING_OK=0
    fi
  fi
fi

if [ "$REPORTING_OK" -ne 1 ]; then
  echo "!! DEPLOYMENT REPORTING INCOMPLETE — the ledger does not reflect reality (fail-closed)" >&2
  exit 3
fi
exit "$DEPLOY_STATUS"
