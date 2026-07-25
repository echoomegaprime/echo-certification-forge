#!/usr/bin/env bash
# P6 deployment enforcement wrapper — makes certification MANDATORY before promotion.
#
# Deployment pipelines source-or-call this immediately before promoting an artifact.
# It resolves the forge admission API, invokes the fail-closed admission hook, and
# refuses the deployment on ANY non-zero outcome (denied OR forge unreachable).
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
#                                     hook signs every admission request with it
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for var in CERTFORGE_URL CERTFORGE_TENANT CERTFORGE_ARTIFACT_DIGEST CERTFORGE_ENVIRONMENT \
           CERTFORGE_ENV_IDENTITY_DIGEST CERTFORGE_RULE_MANIFEST_DIGEST CERTFORGE_DEPLOYMENT_ID \
           CERTFORGE_DEPLOY_SECRET; do
  if [ -z "${!var:-}" ]; then
    echo "!! ADMISSION BLOCKED — $var is not set (fail-closed)" >&2
    exit 3
  fi
done

if python3 "$SCRIPT_DIR/scripts/deployment_admission_hook.py" \
  --forge-url "$CERTFORGE_URL" \
  --tenant "$CERTFORGE_TENANT" \
  --artifact-digest "$CERTFORGE_ARTIFACT_DIGEST" \
  --environment "$CERTFORGE_ENVIRONMENT" \
  --environment-identity-digest "$CERTFORGE_ENV_IDENTITY_DIGEST" \
  --rule-manifest-digest "$CERTFORGE_RULE_MANIFEST_DIGEST" \
  --deployment-id "$CERTFORGE_DEPLOYMENT_ID" \
  --requested-by "${CERTFORGE_REQUESTED_BY:-deployment.pipeline}"; then
  echo "== ADMISSION ALLOWED — proceeding with $CERTFORGE_ENVIRONMENT deployment =="
else
  status=$?
  echo "!! ADMISSION BLOCKED (exit $status) — deployment must not proceed" >&2
  exit "$status"
fi
