#!/usr/bin/env bash
# certforge-p5-promote.sh — P5 adapter promotion gate + deploy orchestrator
#
# Exit codes (contract — do not dilute):
#   0  promotion actually completed (or already FORGE_DEPLOYED)
#   75 soft stop / retry later (EX_TEMPFAIL) — pending hosted CI, pending
#      qualification, in-progress, lock busy, launched-but-not-done
#   1  hard failure (bad source SHA, missing artefact, pipeline failure)
#
# Soft stops MUST NOT exit 0. Callers using `cmd && next` or `if cmd; then`
# must not advance on pending-hosted-ci.
#
# Status lines are emitted to BOTH stdout and stderr so a caller that only
# captures one stream still sees the reason.
set -euo pipefail

# --- Exit-code contract -------------------------------------------------------
readonly EXIT_PROMOTED=0
readonly EXIT_HARD=1
readonly EXIT_PENDING=75   # EX_TEMPFAIL — retryable soft stop

# --- Path configuration (env-overridable for release variants / tests) --------
root="${CERTFORGE_PROMOTE_ROOT:-/home/anvil/certforge-p5-v2-c696e39}"
expected_commit="${CERTFORGE_PROMOTE_EXPECTED_COMMIT:-c696e397867916254234385efdc4f9568a885d53}"
python="${CERTFORGE_PROMOTE_PYTHON:-/home/anvil/adapter_training/venv/bin/python}"
eval_root="${CERTFORGE_PROMOTE_EVAL_ROOT:-/home/anvil/certforge-p5-eval-v2-c696e39}"
qualification="${CERTFORGE_PROMOTE_QUALIFICATION:-$eval_root/qualification-c696e39/qualification-report.json}"
attestation="${CERTFORGE_PROMOTE_ATTESTATION:-$eval_root/operator-p5-v2-trusted-attestation.json}"
run_id="${CERTFORGE_PROMOTE_RUN_ID:-certforge-p5-v2-c696e39-promotion}"
promotion="${CERTFORGE_PROMOTE_PROMOTION_DIR:-$eval_root/$run_id}"
log="${CERTFORGE_PROMOTE_LOG:-/home/anvil/adapter_training/certforge-p5-v2-c696e39-promotion.log}"
pidfile="${CERTFORGE_PROMOTE_PIDFILE:-/home/anvil/adapter_training/certforge-p5-v2-c696e39-promotion.pid}"
lock="${CERTFORGE_PROMOTE_LOCK:-/home/anvil/adapter_training/certforge-p5-v2-c696e39-promotion.lock}"
evaluator_pidfile="${CERTFORGE_PROMOTE_EVALUATOR_PIDFILE:-/home/anvil/adapter_training/certforge-p5-v2-c696e39-evaluator.pid}"
source_commit_file="${CERTFORGE_PROMOTE_SOURCE_COMMIT_FILE:-$root/SOURCE_COMMIT}"

# Test / harness hooks (production leaves these unset):
#   CERTFORGE_HOSTED_CI_MOCK=pending|green:<sha>
#   CERTFORGE_PROMOTE_STUB_PIPELINE=1  — after CI green, mark deployed without R5/deploy
#   CERTFORGE_PROMOTE_SKIP_SOURCE_CHECK=1

# --- Emit helpers -------------------------------------------------------------
emit() {
  # Print the reason to stdout AND stderr (survives single-stream capture).
  printf '%s\n' "$*"
  printf '%s\n' "$*" >&2
}

soft_stop() {
  emit "$1"
  exit "$EXIT_PENDING"
}

hard_fail() {
  emit "$1"
  exit "$EXIT_HARD"
}

promoted_ok() {
  emit "$1"
  exit "$EXIT_PROMOTED"
}

# --- Source pin ---------------------------------------------------------------
if [ "${CERTFORGE_PROMOTE_SKIP_SOURCE_CHECK:-}" != "1" ]; then
  if [ "$(cat "$source_commit_file" 2>/dev/null || true)" != "$expected_commit" ]; then
    hard_fail "promotion=blocked-source-commit-mismatch"
  fi
fi

# --- Hosted CI gate -----------------------------------------------------------
hosted_ci_green() {
  # Mock path for acceptance tests / offline harness.
  if [ -n "${CERTFORGE_HOSTED_CI_MOCK:-}" ]; then
    case "$CERTFORGE_HOSTED_CI_MOCK" in
      pending)
        return 1
        ;;
      green:*)
        printf '%s\n' "${CERTFORGE_HOSTED_CI_MOCK#green:}"
        return 0
        ;;
      *)
        # Unknown mock value is a hard configuration error, not "pending".
        return 2
        ;;
    esac
  fi

  ssh -o BatchMode=yes forge python3 - <<'PY'
import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

repo = "ECHO-OMEGA-PRIME/echo-certification-forge"
credential = next(
    line.strip()
    for line in Path("/home/forge/.config/echo/omega_git_creds").read_text().splitlines()
    if line.strip()
)
token = urlparse(credential).password
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "echo-certforge-release-gate",
}

def get(path: str) -> dict:
    request = Request(f"https://api.github.com/repos/{repo}{path}", headers=headers)
    with urlopen(request, timeout=20) as response:
        return json.load(response)

head_sha = get("/branches/main")["commit"]["sha"]
runs = get("/actions/runs?event=push&branch=main&per_page=20")["workflow_runs"]
matches = [
    run for run in runs
    if run.get("name") == "certification-forge-ci" and run.get("head_sha") == head_sha
]
if not any(
    run.get("status") == "completed" and run.get("conclusion") == "success"
    for run in matches
):
    sys.exit(1)
print(head_sha)
PY
}

qualification_promotes() {
  "$python" - "$qualification" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report.get("schema") == "echo.certification-forge.p5-qualification/v2"
assert report.get("scoring_contract", {}).get("schema") == "echo.certification-forge.p5-semantic-scoring/v2"
assert report.get("run_outcome") == "COMPLETE"
assert report.get("promotion_decision") == "PROMOTE"
assert report.get("release_verdict") == "NOT_READY"
assert report.get("training_split_used") is False
assert report.get("response_receipts", {}).get("successful_rows") == 960
for adapter in ("gs343", "r2d2"):
    result = report["qualification"][adapter]
    assert result["candidate"]["hard_gates_passed"] is True
    assert result["promotion_threshold"]["passed"] is True
    assert result["promotion_decision"] == "PROMOTE"
PY
}

ensure_evaluator() {
  local pid
  pid=$(cat "$evaluator_pidfile" 2>/dev/null || true)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && \
      curl -fsS --max-time 3 http://127.0.0.1:8210/health >/dev/null; then
    return 0
  fi

  local eval_out="$eval_root/server-r5-$(date -u +%Y%m%dT%H%M%SZ)"
  nohup env PYTHONUNBUFFERED=1 CUDA_VISIBLE_DEVICES=0 HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false \
    "$python" -u /home/anvil/certforge-serve-p5-candidate-eval.py \
    --family-source /home/anvil/echo_prime_serve \
    --adapter-root /home/anvil/adapter_training \
    --gs-incumbent runpod_out/echo-gs343-14b-v3 \
    --gs-candidate runpod_out/echo-gs343-certforge-p5-v2 \
    --r2-incumbent runpod_out/echo-r2d2-14b-v2 \
    --r2-candidate runpod_out/echo-r2d2-certforge-p5-v2 \
    --output-dir "$eval_out" \
    --private-key /home/anvil/.config/echo-family/routing-attestation-private.pem \
    --public-key /home/anvil/.config/echo-family/routing-attestation-public.pem \
    --base-revision /home/anvil/.cache/huggingface/hub/models--Qwen--Qwen2.5-14B-Instruct/refs/main \
    --host 127.0.0.1 --port 8210 \
    >>/home/anvil/adapter_training/certforge-p5-v2-c696e39-evaluator.log 2>&1 < /dev/null &
  pid=$!
  printf '%s\n' "$pid" >"$evaluator_pidfile"

  for _ in $(seq 1 240); do
    kill -0 "$pid" 2>/dev/null || return 1
    curl -fsS --max-time 3 http://127.0.0.1:8210/health >/dev/null && return 0
    sleep 5
  done
  return 1
}

nonce() {
  local path="$1"
  if [ ! -s "$path" ]; then
    "$python" - "$path" <<'PY'
import secrets
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  fi
  tr -d '\r\n' <"$path"
}

run_r5() {
  local adapter="$1"
  local target_model="$2"
  local wrong_model="$3"
  local target_digest="$4"
  local wrong_digest="$5"
  local evidence="$promotion/r5-$adapter"
  local nonce_file="$promotion/r5-$adapter.nonce"
  local evidence_run_id="$run_id-$adapter-r5"
  local evidence_nonce
  evidence_nonce=$(nonce "$nonce_file")
  if [ -f "$evidence/R5_COMPLETE" ]; then
    return 0
  fi
  if [ -f "$evidence/evidence-manifest.json" ] && [ -f "$evidence/r5-report.json" ]; then
    if "$python" - "$evidence/r5-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report.get("run_outcome") == "COMPLETE"
assert report.get("r5_gate") == "PASS"
assert report.get("completion_marker") == "[R5 COMPLETE]"
PY
    then
      touch "$evidence/R5_COMPLETE"
      return 0
    fi
  fi
  if [ -e "$evidence" ]; then
    mv "$evidence" "$evidence.incomplete.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  "$python" "$root/scripts/family_r5_operator.py" \
    --server-build-digest b47fd90d585dde270ba986cf7016ad7bd01c6eba4fb398d6d17c545f3d202989 \
    --registry-snapshot-digest ecbcba88a7a5c8a00b91ca8c2c2d2840cbe6c1cc117fe96bfdd7fe9ac83ec24b \
    --registry-revision cff02f9c46a5a6908f7c0c5de1ab4daabaca99ea994481457111e0418bb030a6 \
    --signature-key-id ed25519:030941e03db7cf24b7ad2a2e8993a791 \
    --base-model-digest 09aaac89da4520c2105a841273b15f99f5a28a55eb31fd692f00e0df6c0b29d2 \
    --base-model-revision cf98f3b3bbb457ad9e2bb7baf9a0125b6b88caa8 \
    --target-adapter-digest "$target_digest" \
    --wrong-adapter-digest "$wrong_digest" \
    --target-model "$target_model" \
    --wrong-model "$wrong_model" \
    --base-url http://127.0.0.1:8210 \
    --mode full \
    --evidence-directory "$evidence" \
    --evidence-run-id "$evidence_run_id" \
    --evidence-run-nonce "$evidence_nonce" \
    >"$promotion/r5-$adapter.log"
  "$python" - "$evidence/r5-report.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report.get("run_outcome") == "COMPLETE"
assert report.get("r5_gate") == "PASS"
assert report.get("completion_marker") == "[R5 COMPLETE]"
assert len(report.get("controls", [])) == 2
assert all(control.get("passed") is True for control in report["controls"])
PY
  touch "$evidence/R5_COMPLETE"
}

build_bundle() {
  local key="$promotion/adapter-runner-signing-key.pem"
  if [ ! -s "$key" ]; then
    "$python" - "$key" <<'PY'
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

path = Path(sys.argv[1])
path.write_bytes(
    Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
path.chmod(0o600)
PY
  fi
  local gs_nonce r2_nonce
  gs_nonce=$(nonce "$promotion/r5-gs343.nonce")
  r2_nonce=$(nonce "$promotion/r5-r2d2.nonce")
  export PYTHONPATH="$root/src"
  "$python" "$root/scripts/build_p5_adapter_bundle.py" \
    --run-id "$run_id" \
    --tenant-id echo-certification-forge-production \
    --adapter-registry-id certforge-p5-v2-production \
    --adapter-policy-id certforge-p5-v2-stable-only \
    --adapter-runner-signing-key "$key" \
    --qualification-report "$qualification" \
    --gs343-r5-evidence "$promotion/r5-gs343" \
    --r2d2-r5-evidence "$promotion/r5-r2d2" \
    --trusted-qualification-public-key /home/anvil/.config/echo-family/routing-attestation-public.pem \
    --trusted-qualification-key-id ed25519:030941e03db7cf24b7ad2a2e8993a791 \
    --gs343-r5-public-key /home/anvil/.config/echo-family/routing-attestation-public.pem \
    --gs343-r5-key-id ed25519:030941e03db7cf24b7ad2a2e8993a791 \
    --gs343-r5-run-id "$run_id-gs343-r5" \
    --gs343-r5-run-nonce "$gs_nonce" \
    --r2d2-r5-public-key /home/anvil/.config/echo-family/routing-attestation-public.pem \
    --r2d2-r5-key-id ed25519:030941e03db7cf24b7ad2a2e8993a791 \
    --r2d2-r5-run-id "$run_id-r2d2-r5" \
    --r2d2-r5-run-nonce "$r2_nonce" \
    --gs-candidate-sha256 5d21e5989083aff3a09e3a15ebe9c0262580334cfefe3fe82e74726452b4757a \
    --gs-incumbent-sha256 206e898ecd8b011d6e3fcdc6fefff42dedc131df1769625b7b7c52de0d855c50 \
    --r2-candidate-sha256 d3a2312b2b5ee8d0dbed6f6e812945692a2c8cc241d08051e61123cdad9a1a6f \
    --r2-incumbent-sha256 bb7fb603afaeb722ee0387aee7335fd6026571fd4ae8bebaca5cd61724ff7138 \
    --gs343-model echo-gs343-candidate \
    --gs343-incumbent-model echo-gs343-incumbent \
    --r2d2-model echo-r2d2-candidate \
    --r2d2-incumbent-model echo-r2d2-incumbent \
    --server-build-sha256 b47fd90d585dde270ba986cf7016ad7bd01c6eba4fb398d6d17c545f3d202989 \
    --registry-snapshot-sha256 ecbcba88a7a5c8a00b91ca8c2c2d2840cbe6c1cc117fe96bfdd7fe9ac83ec24b \
    --registry-revision cff02f9c46a5a6908f7c0c5de1ab4daabaca99ea994481457111e0418bb030a6 \
    --base-model-id Qwen/Qwen2.5-14B-Instruct \
    --base-model-revision cf98f3b3bbb457ad9e2bb7baf9a0125b6b88caa8 \
    --base-model-sha256 09aaac89da4520c2105a841273b15f99f5a28a55eb31fd692f00e0df6c0b29d2 \
    --output-directory "$promotion" \
    >"$promotion/adapter-bundle.log"
  "$python" - "$promotion" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
report = json.loads((root / "adapter-acceptance-report.json").read_text())
assert report.get("adapter_gate_eligible") is True
for name in (
    "adapter-bundle-response.json",
    "adapter-policy.json",
    "trusted-adapter-registry.json",
    "adapter-runner-signing-key.pem",
):
    assert (root / name).is_file() and (root / name).stat().st_size > 0
PY
  touch "$promotion/PROMOTION_READY"
}

deploy_forge() {
  local expected_commit_sha="$1"
  local destination="/home/forge/echo-certification-forge/var/p5-releases/$run_id"
  ssh -o BatchMode=yes forge "mkdir -p '$destination' && chmod 700 '$destination'"
  scp -q \
    "$promotion/adapter-bundle-response.json" \
    "$promotion/adapter-policy.json" \
    "$promotion/trusted-adapter-registry.json" \
    "$promotion/adapter-runner-signing-key.pem" \
    "$promotion/adapter-acceptance-report.json" \
    forge:"$destination/"
  ssh -o BatchMode=yes forge \
    "chmod 600 '$destination/adapter-runner-signing-key.pem' && \
     chmod 644 '$destination/adapter-bundle-response.json' \
       '$destination/adapter-policy.json' \
       '$destination/trusted-adapter-registry.json' \
       '$destination/adapter-acceptance-report.json' && \
     env CERTFORGE_SOURCE_REPO=/home/forge/echo-certification-forge \
       CERTFORGE_EXPECTED_COMMIT_SHA='$expected_commit_sha' \
       CERTFORGE_ADAPTER_MODE=required \
       ECHO_CERTFORGE_PROD_ADAPTER_DIR='$destination' \
       /home/forge/echo-certification-forge-current/deploy/deploy_forge.sh" \
    | tee "$promotion/forge-deploy.log"
  ssh -o BatchMode=yes forge \
    "systemctl is-active --quiet echo-certforge.service && \
     systemctl is-active --quiet echo-certforge-dispatcher.service && \
     curl -fsS http://127.0.0.1:8309/healthz >/dev/null && \
     curl -fsS https://cert-api.echosforge.com/healthz >/dev/null"
  touch "$promotion/FORGE_DEPLOYED"
}

run_all() {
  exec 9>"$lock"
  # Lock held elsewhere: soft stop (retry later), never pretend success.
  if ! flock -n 9; then
    soft_stop "promotion=busy"
  fi
  mkdir -p "$promotion"
  chmod 700 "$promotion"

  if ! qualification_promotes; then
    hard_fail "promotion=qualification-rejected"
  fi

  local approved_commit_sha
  local ci_rc=0
  approved_commit_sha=$(hosted_ci_green) || ci_rc=$?
  if [ "$ci_rc" -eq 2 ]; then
    hard_fail "promotion=hosted-ci-misconfigured"
  fi
  if [ "$ci_rc" -ne 0 ]; then
    # Soft stop: hosted CI not yet green — retry later. NEVER exit 0 here.
    soft_stop "promotion=pending-hosted-ci"
  fi
  emit "promotion=hosted-ci-green:$approved_commit_sha"

  # Acceptance / dry-run: short-circuit after CI approval without R5/deploy.
  if [ "${CERTFORGE_PROMOTE_STUB_PIPELINE:-}" = "1" ]; then
    touch "$promotion/FORGE_DEPLOYED"
    promoted_ok "promotion=deployed:$run_id"
  fi

  if ! ensure_evaluator; then
    hard_fail "promotion=evaluator-unavailable"
  fi
  run_r5 gs343 echo-gs343-candidate echo-r2d2-candidate \
    5d21e5989083aff3a09e3a15ebe9c0262580334cfefe3fe82e74726452b4757a \
    d3a2312b2b5ee8d0dbed6f6e812945692a2c8cc241d08051e61123cdad9a1a6f
  run_r5 r2d2 echo-r2d2-candidate echo-gs343-candidate \
    d3a2312b2b5ee8d0dbed6f6e812945692a2c8cc241d08051e61123cdad9a1a6f \
    5d21e5989083aff3a09e3a15ebe9c0262580334cfefe3fe82e74726452b4757a
  build_bundle
  deploy_forge "$approved_commit_sha"
  local eval_pid
  eval_pid=$(cat "$evaluator_pidfile" 2>/dev/null || true)
  if [ -n "$eval_pid" ] && kill -0 "$eval_pid" 2>/dev/null; then
    kill -TERM "$eval_pid" || true
  fi
  promoted_ok "promotion=deployed:$run_id"
}

# --- Entry points -------------------------------------------------------------

if [ "${1:-}" = check-hosted-ci ]; then
  if approved_commit_sha=$(hosted_ci_green); then
    emit "hosted-ci=green:$approved_commit_sha"
    exit "$EXIT_PROMOTED"
  fi
  # Pending is retryable — same soft-stop code as promote path.
  soft_stop "hosted-ci=pending"
fi

if [ "${1:-}" = run ]; then
  run_all
  # run_all always exits; if it returns, treat as hard failure.
  hard_fail "promotion=run-all-returned-unexpectedly"
fi

# Default: status / launch helper (exit 0 ONLY if already promoted).
if [ -f "$promotion/FORGE_DEPLOYED" ]; then
  promoted_ok "promotion=deployed:$run_id"
fi
if ! qualification_promotes 2>/dev/null; then
  soft_stop "promotion=pending-qualification"
fi
pid=$(cat "$pidfile" 2>/dev/null || true)
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
  soft_stop "promotion=running:$pid"
fi
nohup "$0" run >"$log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" >"$pidfile"
# Launched is NOT a completed promotion — soft stop so && chains do not advance.
soft_stop "promotion=launched:$pid"
