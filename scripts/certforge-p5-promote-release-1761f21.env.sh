#!/usr/bin/env bash
# Env overlay for the older certforge-release-1761f21 tree.
# Values are defaults only — callers/tests may override any CERTFORGE_PROMOTE_* var.
# Usage: source this file, then exec the canonical certforge-p5-promote.sh
# (or use scripts/certforge-p5-promote-release-1761f21.sh wrapper).
: "${CERTFORGE_PROMOTE_ROOT:=/home/anvil/certforge-release-1761f21}"
: "${CERTFORGE_PROMOTE_SKIP_SOURCE_CHECK:=1}"
: "${CERTFORGE_PROMOTE_EVAL_ROOT:=/home/anvil/certforge-p5-eval-v2-e0877af}"
: "${CERTFORGE_PROMOTE_QUALIFICATION:=/home/anvil/certforge-p5-eval-v2-e0877af/qualification-e0877af/qualification-report.json}"
: "${CERTFORGE_PROMOTE_ATTESTATION:=/home/anvil/certforge-p5-eval-v2-e0877af/operator-p5-v2-trusted-attestation.json}"
: "${CERTFORGE_PROMOTE_RUN_ID:=certforge-p5-v2-e0877af-promotion}"
: "${CERTFORGE_PROMOTE_LOG:=/home/anvil/adapter_training/certforge-p5-v2-promotion.log}"
: "${CERTFORGE_PROMOTE_PIDFILE:=/home/anvil/adapter_training/certforge-p5-v2-promotion.pid}"
: "${CERTFORGE_PROMOTE_LOCK:=/home/anvil/adapter_training/certforge-p5-v2-promotion.lock}"
: "${CERTFORGE_PROMOTE_EVALUATOR_PIDFILE:=/home/anvil/adapter_training/certforge-p5-v2-evaluator.pid}"

export CERTFORGE_PROMOTE_ROOT
export CERTFORGE_PROMOTE_SKIP_SOURCE_CHECK
export CERTFORGE_PROMOTE_EVAL_ROOT
export CERTFORGE_PROMOTE_QUALIFICATION
export CERTFORGE_PROMOTE_ATTESTATION
export CERTFORGE_PROMOTE_RUN_ID
export CERTFORGE_PROMOTE_LOG
export CERTFORGE_PROMOTE_PIDFILE
export CERTFORGE_PROMOTE_LOCK
export CERTFORGE_PROMOTE_EVALUATOR_PIDFILE
