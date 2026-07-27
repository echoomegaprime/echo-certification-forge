#!/usr/bin/env bash
# Immutable, staging-gated deploy for echo-certification-forge on FORGE.
# Fetches without changing the source checkout, builds a content-addressed release,
# promotes through an atomic symlink, and restores the prior unit/link on red.
set -euo pipefail

SOURCE_REPO="$(cd "$(dirname "$0")/.." && pwd)"
STAGING_PORT="${CERTFORGE_STAGING_PORT:-8311}"
PROD_PORT="${CERTFORGE_PROD_PORT:-8309}"
SERVICE="echo-certforge"
BRANCH="${CERTFORGE_BRANCH:-main}"
RELEASE_ROOT="${CERTFORGE_RELEASE_ROOT:-/home/forge/echo-certification-forge-releases}"
CURRENT_LINK="${CERTFORGE_CURRENT_LINK:-/home/forge/echo-certification-forge-current}"
STATE_ROOT="${CERTFORGE_STATE_ROOT:-/home/forge/echo-certification-forge/var}"
UNIT_PATH="/etc/systemd/system/$SERVICE.service"
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
echo "== [1/8] fetch immutable source ($BRANCH) =="
git "${GITC[@]}" fetch --quiet origin "$BRANCH"
NEW_SHA="$(git rev-parse "origin/$BRANCH^{commit}")"
RELEASE_ID="$NEW_SHA-$(date -u +%Y%m%dT%H%M%SZ)-$$"
RELEASE_DIR="$RELEASE_ROOT/$RELEASE_ID"
RELEASE_TMP="$RELEASE_DIR.tmp.$$"
echo "   candidate=$NEW_SHA"

mkdir -p "$RELEASE_ROOT" "$STATE_ROOT/evidence" "$STATE_ROOT/trusted-public-keys"
trap 'rm -rf "$RELEASE_TMP"' EXIT
mkdir "$RELEASE_TMP"
git archive "$NEW_SHA" | tar -x -C "$RELEASE_TMP"
mv "$RELEASE_TMP" "$RELEASE_DIR"
trap 'test -f "$RELEASE_DIR/.certforge-release-sha" || rm -rf "$RELEASE_DIR"' EXIT

echo "== [2/8] isolated venv + install =="
python3 -m venv "$RELEASE_DIR/.venv"
"$RELEASE_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$RELEASE_DIR/.venv/bin/pip" install --quiet "$RELEASE_DIR"
"$RELEASE_DIR/.venv/bin/python" -m compileall -q \
  "$RELEASE_DIR/src" "$RELEASE_DIR/tests" "$RELEASE_DIR/deploy"
printf '%s\n' "$NEW_SHA" >"$RELEASE_DIR/.certforge-release-sha"
trap - EXIT

echo "== [3/8] verify release inputs =="
test -f "$RELEASE_DIR/policies/mandatory-rules.v1.json" || {
  echo "!! policy manifest missing"
  exit 1
}
test -x "$RELEASE_DIR/.venv/bin/python" || {
  echo "!! release venv missing"
  exit 1
}

echo "== [4/8] staging boot on 127.0.0.1:$STAGING_PORT =="
STAGING_ROOT="$(mktemp -d /tmp/certforge-staging.XXXXXX)"
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
# Snapshot the PRODUCTION values before staging overwrites them. Step [8/8] smokes the real
# service against the real database; if these stay pointed at the throwaway staging DB the
# smoke mints its API key somewhere the production service cannot see it and fails
# 401 api_key_invalid, which reads exactly like a broken release.
PROD_DB="${ECHO_CERTFORGE_DB:-$STATE_ROOT/certforge.sqlite3}"
PROD_EVIDENCE_ROOT="${ECHO_CERTFORGE_EVIDENCE_ROOT:-$STATE_ROOT/evidence}"
PROD_SUBSCRIBER_POLICY="${ECHO_CERTFORGE_SUBSCRIBER_POLICY:-}"
export ECHO_CERTFORGE_DB="$STAGING_ROOT/staging.sqlite3"
export ECHO_CERTFORGE_EVIDENCE_ROOT="$STAGING_ROOT/evidence"
export ECHO_CERTFORGE_POLICY="$RELEASE_DIR/policies/mandatory-rules.v1.json"
export ECHO_CERTFORGE_TRUSTED_KEYS="$STATE_ROOT/trusted-public-keys"
# Subscriber governance must be ON in staging or the gate is weaker than production:
# the smoke's subscriber checks fail closed without these, and any auth regression on a
# governance-gated endpoint would sail through a staging run that had governance off.
# The staging pepper is a separate value from production's and already exists in
# certforge.env; it was simply never wired up here, so this stage could not pass.
CERTFORGE_ENV_FILE="${CERTFORGE_ENV_FILE:-/home/forge/.config/echo/certforge.env}"
if [ -f "$CERTFORGE_ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$CERTFORGE_ENV_FILE"
  set +a
fi
export ECHO_CERTFORGE_SUBSCRIBER_POLICY="$RELEASE_DIR/policies/subscriber-governance.v1.json"
export ECHO_CERTFORGE_SUBSCRIBERS_ENABLED=1
# Keep the PRODUCTION pepper aside: staging must use its own, but step [8/8] smokes the
# real service against the real database and has to mint keys with the production pepper.
# Exporting the staging value for the whole script made the prod smoke fail 401
# api_key_invalid — a self-inflicted red that looks exactly like a broken release.
PROD_API_KEY_PEPPER="${ECHO_CERTFORGE_API_KEY_PEPPER:-}"
export ECHO_CERTFORGE_API_KEY_PEPPER="${ECHO_CERTFORGE_STAGING_API_KEY_PEPPER:-${ECHO_CERTFORGE_API_KEY_PEPPER:-}}"
if [ -z "$ECHO_CERTFORGE_API_KEY_PEPPER" ]; then
  echo "!! no staging API-key pepper available (set ECHO_CERTFORGE_STAGING_API_KEY_PEPPER in $CERTFORGE_ENV_FILE)"
  exit 1
fi
test -f "$ECHO_CERTFORGE_SUBSCRIBER_POLICY" || {
  echo "!! missing $ECHO_CERTFORGE_SUBSCRIBER_POLICY in the release"
  exit 1
}
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

echo "== [5/8] staging live-smoke =="
"$RELEASE_DIR/.venv/bin/python" "$RELEASE_DIR/deploy/smoke_live.py" \
  "http://127.0.0.1:$STAGING_PORT" || {
  echo "!! STAGING SMOKE RED - production untouched"
  exit 1
}
cleanup_staging
trap - EXIT
STAGING_PID=""

echo "== [6/8] capture rollback state =="
PREV_LINK=""
if [ -L "$CURRENT_LINK" ]; then
  PREV_LINK="$(readlink -f "$CURRENT_LINK")"
fi
PREV_ENABLED="$(systemctl is-enabled "$SERVICE.service" 2>/dev/null || true)"
PREV_ACTIVE="$(systemctl is-active "$SERVICE.service" 2>/dev/null || true)"
UNIT_BACKUP="$(mktemp /tmp/echo-certforge.service.XXXXXX)"
HAD_UNIT=0
UNIT_KIND="missing"
UNIT_LINK_TARGET=""
if sudo test -L "$UNIT_PATH"; then
  UNIT_KIND="symlink"
  UNIT_LINK_TARGET="$(sudo readlink "$UNIT_PATH")"
  HAD_UNIT=1
elif sudo test -f "$UNIT_PATH"; then
  UNIT_KIND="file"
  sudo cat "$UNIT_PATH" >"$UNIT_BACKUP"
  HAD_UNIT=1
fi
DB_PATH="$STATE_ROOT/certforge.sqlite3"
DB_BACKUP="$(mktemp /tmp/echo-certforge-db.XXXXXX)"
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
  rm -f "$UNIT_BACKUP" "$DB_BACKUP"
  if [ "$rollback_status" = 0 ]; then
    echo "ROLLBACK COMPLETE - prior production state is healthy"
  else
    echo "ROLLBACK FAILED - prior production state could not be proven healthy" >&2
  fi
  exit 1
}
trap rollback_production EXIT

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

echo "== [7/8] atomic promote -> systemd on 0.0.0.0:$PROD_PORT =="
NEXT_LINK="$CURRENT_LINK.next.$$"
ln -s "$RELEASE_DIR" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT_LINK"
# The unit is already expressed in terms of $CURRENT_LINK, so a promote only needs the
# symlink repointed (done above) plus a restart. Rewriting the unit from the template
# below USED TO run unconditionally, and the template carries 5 Environment lines while
# production's unit carries 16 plus an EnvironmentFile. Every deploy therefore silently
# stripped subscriber governance (ECHO_CERTFORGE_SUBSCRIBER_POLICY / _SUBSCRIBERS_ENABLED),
# adapter enforcement, the P5 adapter chain, transport keys and the API-key pepper, and
# downgraded ECHO_CERTFORGE_POLICY from mandatory-rules.v2 to v1 — on a compliance service,
# while /healthz stayed 200 throughout. Observed 2026-07-27: the promoted service came up
# with subscribers=None and answered 503 subscriber_governance_disabled.
# The template is now a BOOTSTRAP path only: written when no unit exists yet.
ENV_BEFORE="$(systemctl show "$SERVICE.service" -p Environment --value 2>/dev/null | tr ' ' '
' | grep -oE '^[A-Z_]+' | sort -u)"
if [ ! -f "$UNIT_PATH" ]; then
  echo "   no unit present - writing bootstrap unit"
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
Environment=ECHO_CERTFORGE_POLICY=$CURRENT_LINK/policies/mandatory-rules.v1.json
Environment=ECHO_CERTFORGE_TRUSTED_KEYS=$STATE_ROOT/trusted-public-keys
ExecStart=$CURRENT_LINK/.venv/bin/python -m uvicorn echo_certification_forge.app:app --host 0.0.0.0 --port $PROD_PORT --log-level info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
else
  echo "   preserving existing unit (release path follows $CURRENT_LINK)"
fi
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE.service"
sudo systemctl restart "$SERVICE.service"

# Fail the promote if the restart dropped any environment key the service had before.
# A missing key here is invisible at /healthz and only shows up as a governance or
# adapter-enforcement regression much later.
ENV_AFTER="$(systemctl show "$SERVICE.service" -p Environment --value 2>/dev/null | tr ' ' '
' | grep -oE '^[A-Z_]+' | sort -u)"
MISSING="$(comm -23 <(printf '%s
' "$ENV_BEFORE") <(printf '%s
' "$ENV_AFTER") | tr '
' ' ')"
if [ -n "${MISSING// /}" ]; then
  echo "!! PROMOTE DROPPED ENVIRONMENT KEYS: $MISSING"
  echo "!! refusing to continue - restoring previous release"
  exit 1
fi

# Back to the PRODUCTION environment before smoking production.
export ECHO_CERTFORGE_API_KEY_PEPPER="$PROD_API_KEY_PEPPER"
export ECHO_CERTFORGE_DB="$PROD_DB"
export ECHO_CERTFORGE_EVIDENCE_ROOT="$PROD_EVIDENCE_ROOT"
[ -n "$PROD_SUBSCRIBER_POLICY" ] && export ECHO_CERTFORGE_SUBSCRIBER_POLICY="$PROD_SUBSCRIBER_POLICY"
export ECHO_CERTFORGE_SUBSCRIBER_POLICY="${ECHO_CERTFORGE_SUBSCRIBER_POLICY:-$CURRENT_LINK/policies/subscriber-governance.v1.json}"
echo "== [8/8] production health + live-smoke =="
ready=0
for _ in $(seq 1 40); do
  service_owns_port "$PROD_PORT" &&
    curl -sf "http://127.0.0.1:$PROD_PORT/healthz" >/dev/null 2>&1 && {
    ready=1
    break
  }
  sleep 0.5
done
if [ "$ready" != 1 ] || ! "$RELEASE_DIR/.venv/bin/python" \
  "$RELEASE_DIR/deploy/smoke_live.py" "http://127.0.0.1:$PROD_PORT"; then
  echo "!! PROD RED"
  exit 1
fi
service_owns_port "$PROD_PORT" || {
  echo "!! production listener is not owned by $SERVICE"
  exit 1
}

PROMOTION_ARMED=0
trap - EXIT
rm -f "$UNIT_BACKUP" "$DB_BACKUP"
echo "DEPLOY GREEN - $SERVICE live on :$PROD_PORT @ $NEW_SHA"
sudo systemctl status "$SERVICE.service" --no-pager -l | head -6 || true
