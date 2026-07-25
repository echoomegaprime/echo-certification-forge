#!/usr/bin/env bash
# Production-grade, staging-gated deploy for echo-certification-forge on FORGE.
# Runs ON FORGE from within a repo clone:  bash deploy/deploy_forge.sh
# Gate: sync -> venv -> staging boot -> staging live-smoke -> promote (systemd) -> prod health+smoke
#       -> auto-rollback to previous commit on prod red.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"
STAGING_PORT="${CERTFORGE_STAGING_PORT:-8311}"
PROD_PORT="${CERTFORGE_PROD_PORT:-8309}"
SERVICE="echo-certforge"
DISPATCH_SERVICE="echo-certforge-dispatcher"
BRANCH="${CERTFORGE_BRANCH:-feat/certforge-r5-negative-controls}"
ENV_FILE="${CERTFORGE_ENV_FILE:-/home/forge/.config/echo/certforge.env}"
GITC=(-c credential.helper= -c credential.helper="store --file=/home/forge/.config/echo/omega_git_creds")

PREV_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo none)"
echo "== [1/7] sync repo ($BRANCH), prev=$PREV_COMMIT =="
git "${GITC[@]}" fetch --quiet origin "$BRANCH"
git checkout --quiet "$BRANCH"
git reset --hard --quiet "origin/$BRANCH"
NEW_COMMIT="$(git rev-parse --short HEAD)"
echo "   now at $NEW_COMMIT"

echo "== [2/7] venv + install =="
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip >/dev/null
./.venv/bin/pip install --quiet . >/dev/null
echo "   installed"

echo "== [3/7] runtime dirs =="
mkdir -p var/evidence var/trusted-public-keys var/dispatch-output
test -f policies/mandatory-rules.v1.json || { echo "!! policy manifest missing"; exit 1; }
test -f policies/subscriber-governance.v1.json || { echo "!! subscriber policy missing"; exit 1; }
test -f "$ENV_FILE" || {
  echo "!! $ENV_FILE missing"; exit 1;
}
ENV_MODE="$(stat -c '%a' "$ENV_FILE")"
if (( (8#$ENV_MODE & 077) != 0 )); then
  echo "!! $ENV_FILE must not be group/world accessible (mode=$ENV_MODE)"; exit 1
fi
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
PROD_PEPPER="${ECHO_CERTFORGE_API_KEY_PEPPER:-}"
STAGING_PEPPER="${ECHO_CERTFORGE_STAGING_API_KEY_PEPPER:-}"
test "${#PROD_PEPPER}" -ge 32 || {
  echo "!! production ECHO_CERTFORGE_API_KEY_PEPPER must be at least 32 bytes"; exit 1;
}
test "${#STAGING_PEPPER}" -ge 32 || {
  echo "!! ECHO_CERTFORGE_STAGING_API_KEY_PEPPER must be at least 32 bytes"; exit 1;
}

echo "== [4/7] staging boot on 127.0.0.1:$STAGING_PORT =="
STAGING_DB="$REPO_DIR/var/staging.sqlite3"
STAGING_EVIDENCE="$REPO_DIR/var/staging-evidence"
ECHO_CERTFORGE_DB="$STAGING_DB" \
ECHO_CERTFORGE_EVIDENCE_ROOT="$STAGING_EVIDENCE" \
ECHO_CERTFORGE_POLICY="$REPO_DIR/policies/mandatory-rules.v1.json" \
ECHO_CERTFORGE_SUBSCRIBER_POLICY="$REPO_DIR/policies/subscriber-governance.v1.json" \
ECHO_CERTFORGE_TRUSTED_KEYS="$REPO_DIR/var/trusted-public-keys" \
ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1 \
ECHO_CERTFORGE_API_KEY_PEPPER="$STAGING_PEPPER" \
./.venv/bin/python -m uvicorn echo_certification_forge.app:app --host 127.0.0.1 --port "$STAGING_PORT" --log-level warning >var/certforge_staging.log 2>&1 &
STAGING_PID=$!
trap 'kill $STAGING_PID 2>/dev/null || true' EXIT
ready=0
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$STAGING_PORT/healthz" >/dev/null 2>&1 && { ready=1; break; }; sleep 0.5; done
[ "$ready" = 1 ] || { echo "!! staging never became healthy"; tail -20 var/certforge_staging.log; exit 1; }

echo "== [5/7] staging live-smoke =="
if ! ECHO_CERTFORGE_DB="$STAGING_DB" \
  ECHO_CERTFORGE_SUBSCRIBER_POLICY="$REPO_DIR/policies/subscriber-governance.v1.json" \
  ECHO_CERTFORGE_API_KEY_PEPPER="$STAGING_PEPPER" \
  ./.venv/bin/python deploy/smoke_live.py "http://127.0.0.1:$STAGING_PORT"; then
  echo "!! STAGING SMOKE RED — production untouched, aborting"; exit 1
fi
kill $STAGING_PID 2>/dev/null || true; trap - EXIT

echo "== [6/7] promote -> systemd unit on 0.0.0.0:$PROD_PORT =="
sudo tee /etc/systemd/system/$SERVICE.service >/dev/null <<UNIT
[Unit]
Description=echo-certification-forge — autonomous release-certification control plane (read + deploy-gate API)
After=network.target

[Service]
Type=simple
User=forge
WorkingDirectory=$REPO_DIR
Environment=PYTHONUNBUFFERED=1
Environment=ECHO_CERTFORGE_DB=$REPO_DIR/var/certforge.sqlite3
Environment=ECHO_CERTFORGE_EVIDENCE_ROOT=$REPO_DIR/var/evidence
Environment=ECHO_CERTFORGE_POLICY=$REPO_DIR/policies/mandatory-rules.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBER_POLICY=$REPO_DIR/policies/subscriber-governance.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1
Environment=ECHO_CERTFORGE_TRUSTED_KEYS=$REPO_DIR/var/trusted-public-keys
EnvironmentFile=$ENV_FILE
ExecStart=$REPO_DIR/.venv/bin/python -m uvicorn echo_certification_forge.app:app --host 0.0.0.0 --port $PROD_PORT --log-level info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo tee /etc/systemd/system/$DISPATCH_SERVICE.service >/dev/null <<UNIT
[Unit]
Description=echo-certification-forge — durable subscriber run dispatcher
After=network.target $SERVICE.service
Requires=$SERVICE.service

[Service]
Type=simple
User=forge
WorkingDirectory=$REPO_DIR
Environment=PYTHONUNBUFFERED=1
Environment=ECHO_CERTFORGE_DB=$REPO_DIR/var/certforge.sqlite3
Environment=ECHO_CERTFORGE_EVIDENCE_ROOT=$REPO_DIR/var/evidence
Environment=ECHO_CERTFORGE_POLICY=$REPO_DIR/policies/mandatory-rules.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBER_POLICY=$REPO_DIR/policies/subscriber-governance.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1
Environment=ECHO_CERTFORGE_TRUSTED_KEYS=$REPO_DIR/var/trusted-public-keys
Environment=ECHO_CERTFORGE_RUN_SIGNING_KEY=$REPO_DIR/var/run-signing-key.pem
EnvironmentFile=$ENV_FILE
ExecStart=$REPO_DIR/.venv/bin/python -m echo_certification_forge.dispatch_worker --sandbox
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now $SERVICE.service
sudo systemctl restart $SERVICE.service
sudo systemctl enable --now $DISPATCH_SERVICE.service
sudo systemctl restart $DISPATCH_SERVICE.service

echo "== [7/7] production health + live-smoke =="
ready=0
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PROD_PORT/healthz" >/dev/null 2>&1 && { ready=1; break; }; sleep 0.5; done
if [ "$ready" != 1 ] \
  || ! systemctl is-active --quiet $DISPATCH_SERVICE.service \
  || ! ECHO_CERTFORGE_DB="$REPO_DIR/var/certforge.sqlite3" \
    ECHO_CERTFORGE_SUBSCRIBER_POLICY="$REPO_DIR/policies/subscriber-governance.v1.json" \
    ECHO_CERTFORGE_API_KEY_PEPPER="$PROD_PEPPER" \
    ./.venv/bin/python deploy/smoke_live.py "http://127.0.0.1:$PROD_PORT"; then
  echo "!! PROD RED — rolling back to $PREV_COMMIT"
  if [ "$PREV_COMMIT" != none ]; then
    git reset --hard --quiet "$PREV_COMMIT"
    ./.venv/bin/pip install --quiet . >/dev/null
    sudo systemctl restart $SERVICE.service || true
    sudo systemctl restart $DISPATCH_SERVICE.service || true
  else
    sudo systemctl stop $SERVICE.service || true
    sudo systemctl stop $DISPATCH_SERVICE.service || true
  fi
  echo "ROLLBACK COMPLETE — investigate before retrying"; exit 1
fi

echo "DEPLOY GREEN — $SERVICE live on :$PROD_PORT @ $NEW_COMMIT"
sudo systemctl status $SERVICE.service --no-pager -l | head -6 || true
sudo systemctl status $DISPATCH_SERVICE.service --no-pager -l | head -6 || true
