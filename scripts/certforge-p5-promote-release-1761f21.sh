#!/usr/bin/env bash
# Thin wrapper: older release tree reuses the canonical promote script so the
# exit-code contract (0 / 75 / 1) cannot drift. Path pins live in the .env.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# Prefer co-located canonical; fall back to the live c696e39 install on ANVIL.
if [ -x "$here/certforge-p5-promote.sh" ]; then
  canonical="$here/certforge-p5-promote.sh"
else
  canonical=/home/anvil/certforge-p5-v2-c696e39/scripts/certforge-p5-promote.sh
fi
# shellcheck source=/dev/null
source "$here/certforge-p5-promote-release-1761f21.env.sh"
exec "$canonical" "$@"
