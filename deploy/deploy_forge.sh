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

cd "$SOURCE_REPO"
echo "== [1/8] fetch immutable source ($BRANCH) =="
git "${GITC[@]}" fetch --quiet origin "$BRANCH"
NEW_SHA="$(git rev-parse "origin/$BRANCH^{commit}")"
RELEASE_DIR="$RELEASE_ROOT/$NEW_SHA"
RELEASE_TMP="$RELEASE_DIR.tmp.$$"
echo "   candidate=$NEW_SHA"

mkdir -p "$RELEASE_ROOT" "$STATE_ROOT/evidence" "$STATE_ROOT/trusted-public-keys"
if [ -e "$RELEASE_DIR" ]; then
  test "$(cat "$RELEASE_DIR/.certforge-release-sha" 2>/dev/null)" = "$NEW_SHA" || {
    echo "!! existing release directory is incomplete or mismatched: $RELEASE_DIR"
    exit 1
  }
  echo "   reusing verified release directory"
else
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
fi

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
export ECHO_CERTFORGE_DB="$STAGING_ROOT/staging.sqlite3"
export ECHO_CERTFORGE_EVIDENCE_ROOT="$STAGING_ROOT/evidence"
export ECHO_CERTFORGE_POLICY="$RELEASE_DIR/policies/mandatory-rules.v1.json"
export ECHO_CERTFORGE_TRUSTED_KEYS="$STATE_ROOT/trusted-public-keys"
"$RELEASE_DIR/.venv/bin/python" -m uvicorn echo_certification_forge.app:app \
  --host 127.0.0.1 --port "$STAGING_PORT" --log-level warning \
  >"$STAGING_ROOT/service.log" 2>&1 &
STAGING_PID=$!

ready=0
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$STAGING_PORT/healthz" >/dev/null 2>&1 && {
    ready=1
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
UNIT_BACKUP="$(mktemp /tmp/echo-certforge.service.XXXXXX)"
HAD_UNIT=0
if sudo test -f "$UNIT_PATH"; then
  sudo cat "$UNIT_PATH" >"$UNIT_BACKUP"
  HAD_UNIT=1
fi

echo "== [7/8] atomic promote -> systemd on 0.0.0.0:$PROD_PORT =="
NEXT_LINK="$CURRENT_LINK.next.$$"
ln -s "$RELEASE_DIR" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT_LINK"
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
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE.service"
sudo systemctl restart "$SERVICE.service"

echo "== [8/8] production health + live-smoke =="
ready=0
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$PROD_PORT/healthz" >/dev/null 2>&1 && {
    ready=1
    break
  }
  sleep 0.5
done
if [ "$ready" != 1 ] || ! "$RELEASE_DIR/.venv/bin/python" \
  "$RELEASE_DIR/deploy/smoke_live.py" "http://127.0.0.1:$PROD_PORT"; then
  echo "!! PROD RED - restoring prior release"
  if [ -n "$PREV_LINK" ]; then
    ROLLBACK_LINK="$CURRENT_LINK.rollback.$$"
    ln -s "$PREV_LINK" "$ROLLBACK_LINK"
    mv -Tf "$ROLLBACK_LINK" "$CURRENT_LINK"
  fi
  if [ "$HAD_UNIT" = 1 ]; then
    sudo cp "$UNIT_BACKUP" "$UNIT_PATH"
    sudo systemctl daemon-reload
    sudo systemctl restart "$SERVICE.service" || true
  else
    sudo systemctl stop "$SERVICE.service" || true
  fi
  rm -f "$UNIT_BACKUP"
  echo "ROLLBACK COMPLETE - production kept on the prior unit/release"
  exit 1
fi

rm -f "$UNIT_BACKUP"
echo "DEPLOY GREEN - $SERVICE live on :$PROD_PORT @ $NEW_SHA"
sudo systemctl status "$SERVICE.service" --no-pager -l | head -6 || true
