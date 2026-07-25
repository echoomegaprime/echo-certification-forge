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
# Optional environment:
#   CERTFORGE_REQUESTED_BY            actor recorded on the admission (default deployment.pipeline)
#   CERTFORGE_PYTHON                  python interpreter to use (default python3)
#   CERTFORGE_ROLLBACK_CMD            command run after a FAILED production deployment; it
#                                     receives the last-known-good digest in
#                                     CERTFORGE_ROLLBACK_TARGET and, when it succeeds, a
#                                     ROLLED_BACK outcome is recorded with that digest
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

record_outcome() {
  # record_outcome STATUS DETAIL [ROLLBACK_TO]
  local status="$1" detail="$2" rollback_to="${3:-}"
  local extra=()
  if [ -n "$rollback_to" ]; then
    extra=(--rollback-to "$rollback_to")
  fi
  if ! "$PYTHON_BIN" "$HOOK" outcome \
      --forge-url "$CERTFORGE_URL" \
      --tenant "$CERTFORGE_TENANT" \
      --admission-id "$ADMISSION_ID" \
      --status "$status" \
      --detail "$detail" \
      "${extra[@]}"; then
    echo "!! OUTCOME NOT RECORDED ($status) — the ledger has no record of this deployment result" >&2
    return 3
  fi
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
echo "== ADMISSION ALLOWED ($ADMISSION_ID) — running $CERTFORGE_ENVIRONMENT deployment =="

set +e
"$@"
DEPLOY_STATUS=$?
set -e

if [ "$DEPLOY_STATUS" -eq 0 ]; then
  record_outcome SUCCEEDED "deployment command succeeded: $*"
  echo "== DEPLOYMENT SUCCEEDED — outcome recorded against $ADMISSION_ID =="
  exit 0
fi

echo "!! DEPLOYMENT FAILED (exit $DEPLOY_STATUS) — recording FAILED outcome" >&2
record_outcome FAILED "deployment command failed with exit $DEPLOY_STATUS: $*"

if [ "$CERTFORGE_ENVIRONMENT" = "production" ] && [ -n "${CERTFORGE_ROLLBACK_CMD:-}" ]; then
  ROLLBACK_TARGET="$("$PYTHON_BIN" -c '
import json, os, urllib.request
url = os.environ["CERTFORGE_URL"].rstrip("/") + "/v1/deployments/rollback-target"
request = urllib.request.Request(url, headers={"X-Tenant-ID": os.environ["CERTFORGE_TENANT"]})
with urllib.request.urlopen(request, timeout=30) as response:
    target = json.loads(response.read().decode("utf-8")).get("rollback_target") or {}
print(target.get("artifact_sha256", ""))
')"
  if [ -n "$ROLLBACK_TARGET" ]; then
    echo "== ROLLING BACK to last-known-good $ROLLBACK_TARGET ==" >&2
    set +e
    CERTFORGE_ROLLBACK_TARGET="$ROLLBACK_TARGET" bash -c "$CERTFORGE_ROLLBACK_CMD"
    ROLLBACK_STATUS=$?
    set -e
    if [ "$ROLLBACK_STATUS" -eq 0 ]; then
      record_outcome ROLLED_BACK "rolled back to last-known-good after failed deployment" "$ROLLBACK_TARGET"
      echo "== ROLLBACK RECORDED against $ADMISSION_ID ==" >&2
    else
      echo "!! ROLLBACK COMMAND FAILED (exit $ROLLBACK_STATUS) — FAILED outcome stands" >&2
    fi
  else
    echo "!! NO ROLLBACK TARGET AVAILABLE — FAILED outcome stands" >&2
  fi
fi

exit "$DEPLOY_STATUS"
