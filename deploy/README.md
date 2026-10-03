# Deployment readiness

`deploy_forge.sh` uses `readiness.sh` for staging, production, and rollback
health polling. Keep the two files together when invoking the deployment script.

`CERTFORGE_READY_TIMEOUT_S` defaults to `90` and accepts a decimal integer from
`1` through `1800`, without leading zeroes. Invalid values fail before locking,
fetching, or changing deployment state. Each wait has a fresh elapsed-time
deadline; failed HTTP probes consume that budget. Each connection/response is
limited to the smaller of two seconds and the remaining budget. A healthy probe
returns immediately. Shell clock granularity and the polling pause can add a
subsecond tolerance; service-manager and listener-ownership commands are separate
from the HTTP budget.

Staging failures retain the service log under
`$STATE_ROOT/deploy-logs/staging-<release>.log`. Listener ownership, signed
readiness verification, live-smoke gates, and rollback requirements still apply.

A green source-validation run does not prove current production identity or
provide signed production E2E evidence. Every changed candidate needs fresh
exact-SHA certification. Historical smoke reports and old certified tags must not
be reused as certification for a new commit.
