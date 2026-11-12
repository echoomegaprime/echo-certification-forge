#!/usr/bin/env bash
# Sourced by deploy_forge.sh; defining these helpers has no side effects.

configure_readiness_timeout() {
  local value="$1"
  # Validate before arithmetic: Bash otherwise accepts expressions and overflows.
  if [[ ! "$value" =~ ^[1-9][0-9]{0,3}$ ]] || (( value > 1800 )); then
    echo "!! CERTFORGE_READY_TIMEOUT_S must be an integer between 1 and 1800" >&2
    return 1
  fi
  READY_TIMEOUT_S="$value"
}

readiness_start() {
  READY_DEADLINE=$(( SECONDS + READY_TIMEOUT_S ))
}

readiness_pending() {
  (( SECONDS < READY_DEADLINE ))
}

readiness_probe() {
  local port="$1"
  local remaining=$(( READY_DEADLINE - SECONDS ))
  (( remaining > 0 )) || return 1
  # Each probe consumes the existing deadline, never a fresh total budget.
  # Small individual probes allow the caller to recheck process ownership.
  local probe_timeout="$remaining"
  (( probe_timeout <= 2 )) || probe_timeout=2
  curl -sf "http://127.0.0.1:$port/healthz" \
    --connect-timeout "$probe_timeout" --max-time "$probe_timeout"
}

readiness_pause() {
  # SECONDS has one-second resolution; the polling pause adds at most 0.5s.
  # Callers retain their process ownership checks outside these HTTP helpers.
  if readiness_pending; then
    sleep 0.5
  fi
}
