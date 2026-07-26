#!/usr/bin/env bash
# Immutable, staging-gated deploy for echo-certification-forge on FORGE.
# Fetches without changing the source checkout, builds a content-addressed release,
# promotes through an atomic symlink, and restores the prior unit/link on red.
set -euo pipefail

SOURCE_REPO="${CERTFORGE_SOURCE_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
STAGING_PORT="${CERTFORGE_STAGING_PORT:-8311}"
PROD_PORT="${CERTFORGE_PROD_PORT:-8309}"
SERVICE="echo-certforge"
DISPATCH_SERVICE="echo-certforge-dispatcher"
BRANCH="${CERTFORGE_BRANCH:-main}"
EXPECTED_COMMIT_SHA="${CERTFORGE_EXPECTED_COMMIT_SHA:-}"
RELEASE_ROOT="${CERTFORGE_RELEASE_ROOT:-/home/forge/echo-certification-forge-releases}"
CURRENT_LINK="${CERTFORGE_CURRENT_LINK:-/home/forge/echo-certification-forge-current}"
STATE_ROOT="${CERTFORGE_STATE_ROOT:-/home/forge/echo-certification-forge/var}"
ADAPTER_DIR="${ECHO_CERTFORGE_PROD_ADAPTER_DIR:-$STATE_ROOT/p5}"
ADAPTER_MODE="${CERTFORGE_ADAPTER_MODE:-required}"
TRUSTED_MANIFEST_SHA256="${ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256:-7dc98e0e95e6dd2c000ec069a8c46c4d1d49a4fe869ad4eae25e059d103644f4}"
UNIT_PATH="/etc/systemd/system/$SERVICE.service"
DISPATCH_UNIT_PATH="/etc/systemd/system/$DISPATCH_SERVICE.service"
ENV_FILE="${CERTFORGE_ENV_FILE:-/home/forge/.config/echo/certforge.env}"
GITC=(-c credential.helper= -c credential.helper="store --file=/home/forge/.config/echo/omega_git_creds")
LOCK_FILE="${CERTFORGE_DEPLOY_LOCK:-/run/lock/echo-certforge-deploy.lock}"

exec 9>"$LOCK_FILE"
flock -n 9 || {
  echo "!! another Certification Forge deployment is already running"
  exit 1
}

service_owns_port() {
  local service_pid
  local port="$1"
  service_pid="$(systemctl show "$SERVICE.service" --property MainPID --value 2>/dev/null)"
  [ "${service_pid:-0}" -gt 1 ] 2>/dev/null &&
    kill -0 "$service_pid" 2>/dev/null &&
    ss -H -ltnp "sport = :$port" | grep -q "pid=$service_pid,"
}

cd "$SOURCE_REPO"
echo "== [1/9] fetch immutable source ($BRANCH) =="
git "${GITC[@]}" fetch --quiet origin "$BRANCH"
NEW_SHA="$(git rev-parse "origin/$BRANCH^{commit}")"
if [ -n "$EXPECTED_COMMIT_SHA" ] && [ "$NEW_SHA" != "$EXPECTED_COMMIT_SHA" ]; then
  echo "!! fetched commit does not match the hosted-CI-approved commit"
  exit 1
fi
RELEASE_ID="$NEW_SHA-$(date -u +%Y%m%dT%H%M%SZ)-$$"
RELEASE_DIR="$RELEASE_ROOT/$RELEASE_ID"
RELEASE_TMP="$RELEASE_DIR.tmp.$$"
echo "   candidate=$NEW_SHA"

mkdir -p \
  "$RELEASE_ROOT" \
  "$STATE_ROOT/evidence" \
  "$STATE_ROOT/trusted-public-keys" \
  "$STATE_ROOT/trusted-transport-keys" \
  "$STATE_ROOT/run-output" \
  "$STATE_ROOT/dispatch-output" \
  "$STATE_ROOT/deploy-scratch"
trap 'rm -rf "$RELEASE_TMP"' EXIT
mkdir "$RELEASE_TMP"
git archive "$NEW_SHA" | tar -x -C "$RELEASE_TMP"
mv "$RELEASE_TMP" "$RELEASE_DIR"
trap 'test -f "$RELEASE_DIR/.certforge-release-sha" || rm -rf "$RELEASE_DIR"' EXIT

echo "== [2/9] isolated venv + install =="
python3 -m venv "$RELEASE_DIR/.venv"
"$RELEASE_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$RELEASE_DIR/.venv/bin/pip" install --quiet "$RELEASE_DIR"
"$RELEASE_DIR/.venv/bin/python" -m compileall -q \
  "$RELEASE_DIR/src" "$RELEASE_DIR/tests" "$RELEASE_DIR/deploy"
printf '%s\n' "$NEW_SHA" >"$RELEASE_DIR/.certforge-release-sha"
trap - EXIT

echo "== [3/9] verify release inputs =="
test -f "$RELEASE_DIR/policies/mandatory-rules.v2.json" || {
  echo "!! v2 policy manifest missing"
  exit 1
}
test -x "$RELEASE_DIR/.venv/bin/python" || {
  echo "!! release venv missing"
  exit 1
}
case "$ADAPTER_MODE" in
  required|pending) ;;
  *) echo "!! CERTFORGE_ADAPTER_MODE must be required or pending"; exit 1 ;;
esac
ADAPTER_RESPONSE=""
ADAPTER_POLICY=""
ADAPTER_REGISTRY=""
ADAPTER_SIGNING_KEY=""
DISPATCH_COMPAT_FLAG="--non-production-compat"
if [ "$ADAPTER_MODE" = required ]; then
  ADAPTER_RESPONSE="$ADAPTER_DIR/adapter-bundle-response.json"
  ADAPTER_POLICY="$ADAPTER_DIR/adapter-policy.json"
  ADAPTER_REGISTRY="$ADAPTER_DIR/trusted-adapter-registry.json"
  ADAPTER_SIGNING_KEY="$ADAPTER_DIR/adapter-runner-signing-key.pem"
  for required_adapter_input in \
    "$ADAPTER_RESPONSE" "$ADAPTER_POLICY" "$ADAPTER_REGISTRY" "$ADAPTER_SIGNING_KEY"; do
    test -f "$required_adapter_input" || {
      echo "!! required adapter input missing: $(basename "$required_adapter_input")"
      exit 1
    }
  done
  DISPATCH_COMPAT_FLAG=""
else
  echo "   adapter qualification pending: dispatcher remains fail-closed"
fi
RUN_SIGNING_KEY="$STATE_ROOT/run-signing-key.pem"
RUN_SIGNING_PUBLIC_KEY="$STATE_ROOT/trusted-public-keys/run-signing-key.pem"
"$RELEASE_DIR/.venv/bin/python" - "$RUN_SIGNING_KEY" "$RUN_SIGNING_PUBLIC_KEY" <<'PY'
from pathlib import Path
import sys

from echo_certification_forge.run_worker import _load_signer

private_path = Path(sys.argv[1])
public_path = Path(sys.argv[2])
signer = _load_signer(private_path)
public_path.write_text(signer.public_key_pem, encoding="ascii")
public_path.chmod(0o644)
PY
test -f "$RELEASE_DIR/policies/subscriber-governance.v1.json" || {
  echo "!! subscriber governance policy missing"
  exit 1
}
test -f "$ENV_FILE" || {
  echo "!! subscriber environment file missing: $ENV_FILE"
  exit 1
}
ENV_MODE="$(stat -c '%a' "$ENV_FILE")"
if (( (8#$ENV_MODE & 077) != 0 )); then
  echo "!! $ENV_FILE must not be group/world accessible (mode=$ENV_MODE)"
  exit 1
fi
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
PROD_PEPPER="${ECHO_CERTFORGE_API_KEY_PEPPER:-}"
STAGING_PEPPER="${ECHO_CERTFORGE_STAGING_API_KEY_PEPPER:-}"
test "${#PROD_PEPPER}" -ge 32 || {
  echo "!! production ECHO_CERTFORGE_API_KEY_PEPPER must be at least 32 bytes"
  exit 1
}
test "${#STAGING_PEPPER}" -ge 32 || {
  echo "!! ECHO_CERTFORGE_STAGING_API_KEY_PEPPER must be at least 32 bytes"
  exit 1
}

echo "== [4/9] staging boot on 127.0.0.1:$STAGING_PORT =="
STAGING_ROOT="$STATE_ROOT/deploy-scratch/staging.$RELEASE_ID"
rm -rf "$STAGING_ROOT"
mkdir -p "$STAGING_ROOT"
STAGING_PID=""
cleanup_staging() {
  if [ -n "$STAGING_PID" ]; then
    kill "$STAGING_PID" 2>/dev/null || true
    wait "$STAGING_PID" 2>/dev/null || true
  fi
  rm -rf "$STAGING_ROOT"
}
trap cleanup_staging EXIT
if ss -H -ltn "sport = :$STAGING_PORT" | grep -q .; then
  echo "!! staging port $STAGING_PORT is already occupied"
  exit 1
fi
ECHO_CERTFORGE_DB="$STAGING_ROOT/staging.sqlite3" \
ECHO_CERTFORGE_EVIDENCE_ROOT="$STAGING_ROOT/evidence" \
ECHO_CERTFORGE_POLICY="$RELEASE_DIR/policies/mandatory-rules.v2.json" \
ECHO_CERTFORGE_TRUSTED_KEYS="$STATE_ROOT/trusted-public-keys" \
ECHO_CERTFORGE_TRANSPORT_KEYS="$STATE_ROOT/trusted-transport-keys" \
ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE="$ADAPTER_RESPONSE" \
ECHO_CERTFORGE_PROD_ADAPTER_POLICY="$ADAPTER_POLICY" \
ECHO_CERTFORGE_ADAPTER_REGISTRY="$ADAPTER_REGISTRY" \
ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY="$ADAPTER_SIGNING_KEY" \
ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256="$TRUSTED_MANIFEST_SHA256" \
ECHO_CERTFORGE_SUBSCRIBER_POLICY="$RELEASE_DIR/policies/subscriber-governance.v1.json" \
ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1 \
ECHO_CERTFORGE_API_KEY_PEPPER="$STAGING_PEPPER" \
"$RELEASE_DIR/.venv/bin/python" -m uvicorn echo_certification_forge.app:app \
  --host 127.0.0.1 --port "$STAGING_PORT" --log-level warning \
  >"$STAGING_ROOT/service.log" 2>&1 &
STAGING_PID=$!

ready=0
for _ in $(seq 1 40); do
  kill -0 "$STAGING_PID" 2>/dev/null || {
    echo "!! staging process exited before readiness"
    tail -20 "$STAGING_ROOT/service.log"
    exit 1
  }
  curl -sf "http://127.0.0.1:$STAGING_PORT/healthz" >/dev/null 2>&1 && {
    if ss -H -ltnp "sport = :$STAGING_PORT" | grep -q "pid=$STAGING_PID,"; then
      ready=1
    else
      echo "!! staging health came from a process other than candidate $STAGING_PID"
      exit 1
    fi
    break
  }
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  echo "!! staging never became healthy"
  tail -20 "$STAGING_ROOT/service.log"
  exit 1
fi

echo "== [5/9] staging live-smoke =="
ECHO_CERTFORGE_DB="$STAGING_ROOT/staging.sqlite3" \
ECHO_CERTFORGE_SUBSCRIBER_POLICY="$RELEASE_DIR/policies/subscriber-governance.v1.json" \
ECHO_CERTFORGE_API_KEY_PEPPER="$STAGING_PEPPER" \
"$RELEASE_DIR/.venv/bin/python" "$RELEASE_DIR/deploy/smoke_live.py" \
  "http://127.0.0.1:$STAGING_PORT" || {
  echo "!! STAGING SMOKE RED - production untouched"
  exit 1
}
cleanup_staging
trap - EXIT
STAGING_PID=""

echo "== [6/9] capture rollback state =="
PREV_LINK=""
if [ -L "$CURRENT_LINK" ]; then
  PREV_LINK="$(readlink -f "$CURRENT_LINK")"
fi
PREV_ENABLED="$(systemctl is-enabled "$SERVICE.service" 2>/dev/null || true)"
PREV_ACTIVE="$(systemctl is-active "$SERVICE.service" 2>/dev/null || true)"
PREV_DISPATCH_ENABLED="$(systemctl is-enabled "$DISPATCH_SERVICE.service" 2>/dev/null || true)"
PREV_DISPATCH_ACTIVE="$(systemctl is-active "$DISPATCH_SERVICE.service" 2>/dev/null || true)"
UNIT_BACKUP="$STATE_ROOT/deploy-scratch/echo-certforge.service.$RELEASE_ID"
DISPATCH_UNIT_BACKUP="$STATE_ROOT/deploy-scratch/echo-certforge-dispatcher.service.$RELEASE_ID"
HAD_UNIT=0
HAD_DISPATCH_UNIT=0
UNIT_KIND="missing"
DISPATCH_UNIT_KIND="missing"
UNIT_LINK_TARGET=""
DISPATCH_UNIT_LINK_TARGET=""
if sudo test -L "$UNIT_PATH"; then
  UNIT_KIND="symlink"
  UNIT_LINK_TARGET="$(sudo readlink "$UNIT_PATH")"
  HAD_UNIT=1
elif sudo test -f "$UNIT_PATH"; then
  UNIT_KIND="file"
  sudo cat "$UNIT_PATH" >"$UNIT_BACKUP"
  HAD_UNIT=1
fi
if sudo test -L "$DISPATCH_UNIT_PATH"; then
  DISPATCH_UNIT_KIND="symlink"
  DISPATCH_UNIT_LINK_TARGET="$(sudo readlink "$DISPATCH_UNIT_PATH")"
  HAD_DISPATCH_UNIT=1
elif sudo test -f "$DISPATCH_UNIT_PATH"; then
  DISPATCH_UNIT_KIND="file"
  sudo cat "$DISPATCH_UNIT_PATH" >"$DISPATCH_UNIT_BACKUP"
  HAD_DISPATCH_UNIT=1
fi
DB_PATH="$STATE_ROOT/certforge.sqlite3"
DB_BACKUP="$STATE_ROOT/deploy-scratch/echo-certforge-db.$RELEASE_ID"
HAD_DB=0
DB_SNAPSHOT_READY=0

PROMOTION_ARMED=1
rollback_production() {
  exit_status=$?
  if [ "$PROMOTION_ARMED" != 1 ]; then
    return "$exit_status"
  fi
  set +e
  echo "!! deployment failed - restoring prior production state"
  rollback_status=0
  sudo systemctl stop "$DISPATCH_SERVICE.service" >/dev/null 2>&1 || true
  sudo systemctl stop "$SERVICE.service" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$SERVICE.service"; then
    rollback_status=1
  fi
  sudo systemctl disable "$SERVICE.service" >/dev/null 2>&1 || true
  if [ "$DB_SNAPSHOT_READY" = 1 ]; then
    rm -f "$DB_PATH-wal" "$DB_PATH-shm"
    if [ "$HAD_DB" = 1 ]; then
      DB_RESTORE="$DB_PATH.rollback.$$"
      cp "$DB_BACKUP" "$DB_RESTORE" &&
        mv -f "$DB_RESTORE" "$DB_PATH" || rollback_status=1
    else
      rm -f "$DB_PATH" || rollback_status=1
    fi
  fi
  if [ -n "$PREV_LINK" ]; then
    ROLLBACK_LINK="$CURRENT_LINK.rollback.$$"
    ln -s "$PREV_LINK" "$ROLLBACK_LINK" &&
      mv -Tf "$ROLLBACK_LINK" "$CURRENT_LINK" || rollback_status=1
  else
    rm -f "$CURRENT_LINK" || rollback_status=1
  fi
  if [ "$HAD_UNIT" = 1 ]; then
    sudo rm -f "$UNIT_PATH" || rollback_status=1
    if [ "$UNIT_KIND" = "symlink" ]; then
      sudo ln -s "$UNIT_LINK_TARGET" "$UNIT_PATH" || rollback_status=1
    else
      sudo cp "$UNIT_BACKUP" "$UNIT_PATH" || rollback_status=1
    fi
    sudo systemctl daemon-reload || rollback_status=1
    case "$PREV_ENABLED" in
      enabled)
        sudo systemctl enable "$SERVICE.service" >/dev/null || rollback_status=1
        ;;
      enabled-runtime)
        sudo systemctl enable --runtime "$SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
      masked)
        sudo systemctl mask "$SERVICE.service" >/dev/null || rollback_status=1
        ;;
      masked-runtime)
        sudo systemctl mask --runtime "$SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
    esac
    if [ "$PREV_ACTIVE" = "active" ]; then
      sudo systemctl start "$SERVICE.service" || rollback_status=1
      restored=0
      for _ in $(seq 1 40); do
        service_owns_port "$PROD_PORT" &&
          curl -sf "http://127.0.0.1:$PROD_PORT/healthz" >/dev/null 2>&1 && {
          restored=1
          break
        }
        sleep 0.5
      done
      [ "$restored" = 1 ] || rollback_status=1
    else
      sudo systemctl stop "$SERVICE.service" || rollback_status=1
      systemctl is-active --quiet "$SERVICE.service" && rollback_status=1
    fi
  else
    sudo systemctl disable --now "$SERVICE.service" >/dev/null 2>&1 || true
    systemctl is-active --quiet "$SERVICE.service" && rollback_status=1
    [ "$(systemctl is-enabled "$SERVICE.service" 2>/dev/null || true)" != "enabled" ] ||
      rollback_status=1
    sudo rm -f "$UNIT_PATH" || rollback_status=1
    sudo systemctl daemon-reload || rollback_status=1
  fi
  if [ "$HAD_DISPATCH_UNIT" = 1 ]; then
    sudo rm -f "$DISPATCH_UNIT_PATH" || rollback_status=1
    if [ "$DISPATCH_UNIT_KIND" = "symlink" ]; then
      sudo ln -s "$DISPATCH_UNIT_LINK_TARGET" "$DISPATCH_UNIT_PATH" ||
        rollback_status=1
    else
      sudo cp "$DISPATCH_UNIT_BACKUP" "$DISPATCH_UNIT_PATH" || rollback_status=1
    fi
    sudo systemctl daemon-reload || rollback_status=1
    case "$PREV_DISPATCH_ENABLED" in
      enabled)
        sudo systemctl enable "$DISPATCH_SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
      enabled-runtime)
        sudo systemctl enable --runtime "$DISPATCH_SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
      masked)
        sudo systemctl mask "$DISPATCH_SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
      masked-runtime)
        sudo systemctl mask --runtime "$DISPATCH_SERVICE.service" >/dev/null ||
          rollback_status=1
        ;;
    esac
    if [ "$PREV_DISPATCH_ACTIVE" = "active" ]; then
      sudo systemctl start "$DISPATCH_SERVICE.service" || rollback_status=1
      systemctl is-active --quiet "$DISPATCH_SERVICE.service" ||
        rollback_status=1
    else
      sudo systemctl stop "$DISPATCH_SERVICE.service" || rollback_status=1
      systemctl is-active --quiet "$DISPATCH_SERVICE.service" &&
        rollback_status=1
    fi
  else
    sudo systemctl disable --now "$DISPATCH_SERVICE.service" >/dev/null 2>&1 ||
      true
    sudo rm -f "$DISPATCH_UNIT_PATH" || rollback_status=1
    sudo systemctl daemon-reload || rollback_status=1
  fi
  rm -f "$UNIT_BACKUP" "$DISPATCH_UNIT_BACKUP" "$DB_BACKUP"
  if [ "$rollback_status" = 0 ]; then
    echo "ROLLBACK COMPLETE - prior production state is healthy"
  else
    echo "ROLLBACK FAILED - prior production state could not be proven healthy" >&2
  fi
  exit 1
}
trap rollback_production EXIT

if [ "$PREV_DISPATCH_ACTIVE" = "active" ]; then
  sudo systemctl stop "$DISPATCH_SERVICE.service"
  if systemctl is-active --quiet "$DISPATCH_SERVICE.service"; then
    echo "!! could not quiesce dispatcher before database snapshot"
    exit 1
  fi
fi
if [ "$PREV_ACTIVE" = "active" ]; then
  sudo systemctl stop "$SERVICE.service"
  if systemctl is-active --quiet "$SERVICE.service"; then
    echo "!! could not quiesce production before database snapshot"
    exit 1
  fi
fi
if [ -f "$DB_PATH" ]; then
  python3 - "$DB_PATH" "$DB_BACKUP" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
destination = sqlite3.connect(sys.argv[2])
with destination:
    source.backup(destination)
source.close()
destination.close()
PY
  HAD_DB=1
fi
DB_SNAPSHOT_READY=1

echo "== [7/9] atomic promote -> systemd on 0.0.0.0:$PROD_PORT =="
NEXT_LINK="$CURRENT_LINK.next.$$"
ln -s "$RELEASE_DIR" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT_LINK"
sudo rm -f "$UNIT_PATH"
sudo tee "$UNIT_PATH" >/dev/null <<UNIT
[Unit]
Description=echo-certification-forge - autonomous release-certification control plane
After=network.target

[Service]
Type=simple
User=forge
WorkingDirectory=$CURRENT_LINK
Environment=PYTHONUNBUFFERED=1
Environment=ECHO_CERTFORGE_DB=$STATE_ROOT/certforge.sqlite3
Environment=ECHO_CERTFORGE_EVIDENCE_ROOT=$STATE_ROOT/evidence
Environment=ECHO_CERTFORGE_POLICY=$CURRENT_LINK/policies/mandatory-rules.v2.json
Environment=ECHO_CERTFORGE_SUBSCRIBER_POLICY=$CURRENT_LINK/policies/subscriber-governance.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1
Environment=ECHO_CERTFORGE_ADAPTER_MODE=$ADAPTER_MODE
Environment=ECHO_CERTFORGE_TRUSTED_KEYS=$STATE_ROOT/trusted-public-keys
Environment=ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE=$ADAPTER_RESPONSE
Environment=ECHO_CERTFORGE_PROD_ADAPTER_POLICY=$ADAPTER_POLICY
Environment=ECHO_CERTFORGE_ADAPTER_REGISTRY=$ADAPTER_REGISTRY
Environment=ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY=$ADAPTER_SIGNING_KEY
Environment=ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256=$TRUSTED_MANIFEST_SHA256
Environment=ECHO_CERTFORGE_TRANSPORT_KEYS=$STATE_ROOT/trusted-transport-keys
EnvironmentFile=$ENV_FILE
ExecStart=$CURRENT_LINK/.venv/bin/python -m uvicorn echo_certification_forge.app:app --host 0.0.0.0 --port $PROD_PORT --log-level info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo rm -f "$DISPATCH_UNIT_PATH"
sudo tee "$DISPATCH_UNIT_PATH" >/dev/null <<UNIT
[Unit]
Description=echo-certification-forge - durable subscriber run dispatcher
After=network.target $SERVICE.service
Requires=$SERVICE.service

[Service]
Type=simple
User=forge
WorkingDirectory=$CURRENT_LINK
Environment=PYTHONUNBUFFERED=1
Environment=ECHO_CERTFORGE_DB=$STATE_ROOT/certforge.sqlite3
Environment=ECHO_CERTFORGE_EVIDENCE_ROOT=$STATE_ROOT/evidence
Environment=ECHO_CERTFORGE_POLICY=$CURRENT_LINK/policies/mandatory-rules.v2.json
Environment=ECHO_CERTFORGE_SUBSCRIBER_POLICY=$CURRENT_LINK/policies/subscriber-governance.v1.json
Environment=ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1
Environment=ECHO_CERTFORGE_ADAPTER_MODE=$ADAPTER_MODE
Environment=ECHO_CERTFORGE_TRUSTED_KEYS=$STATE_ROOT/trusted-public-keys
Environment=ECHO_CERTFORGE_RUN_SIGNING_KEY=$STATE_ROOT/run-signing-key.pem
Environment=ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE=$ADAPTER_RESPONSE
Environment=ECHO_CERTFORGE_PROD_ADAPTER_POLICY=$ADAPTER_POLICY
Environment=ECHO_CERTFORGE_ADAPTER_REGISTRY=$ADAPTER_REGISTRY
Environment=ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY=$ADAPTER_SIGNING_KEY
Environment=ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256=$TRUSTED_MANIFEST_SHA256
EnvironmentFile=$ENV_FILE
ExecStart=$CURRENT_LINK/.venv/bin/python -m echo_certification_forge.dispatch_worker --sandbox $DISPATCH_COMPAT_FLAG
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl stop "$DISPATCH_SERVICE.service" >/dev/null 2>&1 || true
sudo systemctl enable "$SERVICE.service"
sudo systemctl restart "$SERVICE.service"
sudo systemctl enable "$DISPATCH_SERVICE.service"

echo "== [8/9] production health + live-smoke =="
ready=0
for _ in $(seq 1 40); do
  service_owns_port "$PROD_PORT" &&
    curl -sf "http://127.0.0.1:$PROD_PORT/healthz" >/dev/null 2>&1 && {
    ready=1
    break
  }
  sleep 0.5
done
if [ "$ready" != 1 ] || ! ECHO_CERTFORGE_DB="$STATE_ROOT/certforge.sqlite3" \
    ECHO_CERTFORGE_SUBSCRIBER_POLICY="$RELEASE_DIR/policies/subscriber-governance.v1.json" \
    ECHO_CERTFORGE_API_KEY_PEPPER="$PROD_PEPPER" \
    "$RELEASE_DIR/.venv/bin/python" "$RELEASE_DIR/deploy/smoke_live.py" \
      "http://127.0.0.1:$PROD_PORT"; then
  echo "!! PROD RED"
  exit 1
fi
service_owns_port "$PROD_PORT" || {
  echo "!! production listener is not owned by $SERVICE"
  exit 1
}
sudo systemctl restart "$DISPATCH_SERVICE.service"
dispatcher_ready=0
for _ in $(seq 1 20); do
  systemctl is-active --quiet "$DISPATCH_SERVICE.service" && {
    dispatcher_ready=1
    break
  }
  sleep 0.5
done
if [ "$dispatcher_ready" != 1 ]; then
  echo "!! dispatcher failed to start after green production smoke"
  exit 1
fi
if [ "$ADAPTER_MODE" = required ]; then
  ECHO_CERTFORGE_DB="$STATE_ROOT/certforge.sqlite3" \
  ECHO_CERTFORGE_SUBSCRIBER_POLICY="$RELEASE_DIR/policies/subscriber-governance.v1.json" \
  ECHO_CERTFORGE_API_KEY_PEPPER="$PROD_PEPPER" \
  "$RELEASE_DIR/.venv/bin/python" "$RELEASE_DIR/deploy/smoke_dispatch.py" \
    "http://127.0.0.1:$PROD_PORT" || {
    echo "!! PRODUCTION DISPATCH SMOKE RED"
    exit 1
  }
fi

echo "== [9/9] persist and verify complete SDK schemas =="
sudo -n -u postgres psql -1 -v ON_ERROR_STOP=1 -d echo \
  -f "$RELEASE_DIR/scripts/register_certforge_caps.sql" \
  -f "$RELEASE_DIR/scripts/register_certforge_run_cap.sql" \
  -f "$RELEASE_DIR/scripts/register_certforge_r5_async_caps.sql" \
  -f "$RELEASE_DIR/scripts/register_certification_forge_r5_cap.sql" \
  -f "$RELEASE_DIR/scripts/register_certforge_sdk_schemas.sql"

PROMOTION_ARMED=0
trap - EXIT
rm -f "$UNIT_BACKUP" "$DISPATCH_UNIT_BACKUP" "$DB_BACKUP"
echo "DEPLOY GREEN - $SERVICE live on :$PROD_PORT @ $NEW_SHA"
sudo systemctl status "$SERVICE.service" --no-pager -l | head -6 || true
sudo systemctl status "$DISPATCH_SERVICE.service" --no-pager -l | head -6 || true
