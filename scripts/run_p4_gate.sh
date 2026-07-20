#!/usr/bin/env bash
#
# run_p4_gate.sh — one-command, fail-closed driver for the P4 hostile-runner /
# image-supply-chain acceptance gate. Reconstructed from the source scripts
# (generate_p4_attestation_key.py, build_p4_images.py, seal_p4_images.py,
# p4_hostile_acceptance.py) so a full P4 gate run is repeatable instead of ad-hoc.
#
# MUST run on FORGE (rootful Docker + the pinned base image + cosign/trivy/clamav).
# It clones the repo at an EXACT commit, builds all 12 role images from that
# commit, seals their identities, then runs the 14-step hostile-acceptance gate
# and prints the verdict. Nothing is faked; every step fails closed.
#
# Usage:
#   scripts/run_p4_gate.sh [SOURCE_COMMIT] [RUN_LABEL]
#     SOURCE_COMMIT  full 40-char SHA to certify (default: tip of BRANCH below)
#     RUN_LABEL      short label for the run dir (default: rerunN by timestamp)
#
# Override any pinned input via env (defaults are the verified FORGE values):
#   REPO_URL, BRANCH, GIT_CRED_FILE, BASE_DIGEST, CLAMAV_IMAGE,
#   COSIGN, TRIVY, PY, WORK_ROOT
#
set -Eeuo pipefail

# ---- pinned, verified inputs (2026-07-20) --------------------------------
REPO_URL="${REPO_URL:-https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge}"
BRANCH="${BRANCH:-feat/certforge-r5-negative-controls}"
GIT_CRED_FILE="${GIT_CRED_FILE:-/home/forge/.config/echo/omega_git_creds}"
BASE_DIGEST="${BASE_DIGEST:-sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df}"
CLAMAV_IMAGE="${CLAMAV_IMAGE:-clamav/clamav@sha256:7f5389ccaa2368c383fa80e167ccfe44348d71e685f926fce4755eed1757673a}"
COSIGN="${COSIGN:-/home/forge/.cache/echo-certforge/p4-9c07eb7/tools/cosign/cosign}"
TRIVY="${TRIVY:-/home/forge/.cache/echo-certforge/p4-9c07eb7/tools/trivy/trivy}"
PY="${PY:-/home/forge/echo-worker-server/venv/bin/python}"
WORK_ROOT="${WORK_ROOT:-/home/forge/.cache/echo-certforge/p4-runs}"
ROLES=(runner custody anchor signer worker verifier)

log() { printf '[p4-gate %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf '[p4-gate FAIL] %s\n' "$*" >&2; exit 1; }

# ---- 0. resolve commit + preflight (fail-closed) -------------------------
git_c() { git -c credential.helper= -c credential.helper="store --file=${GIT_CRED_FILE}" "$@"; }

SOURCE_COMMIT="${1:-}"
if [[ -z "${SOURCE_COMMIT}" ]]; then
  SOURCE_COMMIT="$(git_c ls-remote "${REPO_URL}" "refs/heads/${BRANCH}" | awk '{print $1}')"
fi
[[ "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || die "source commit must be an exact 40-char SHA (got '${SOURCE_COMMIT}')"
RUN_LABEL="${2:-run-$(date -u +%Y%m%dT%H%M%SZ)}"
SHORT="${SOURCE_COMMIT:0:7}"
TAG_PREFIX="p4-${SHORT}"

command -v docker >/dev/null || die "docker not on PATH"
[[ -x "${COSIGN}" ]] || die "cosign missing: ${COSIGN}"
[[ -x "${TRIVY}"  ]] || die "trivy missing: ${TRIVY}"
[[ -x "${PY}"     ]] || die "python missing: ${PY}"
[[ -f "${GIT_CRED_FILE}" ]] || die "git cred file missing: ${GIT_CRED_FILE}"
docker image inspect "python:3.12-alpine@${BASE_DIGEST}" >/dev/null 2>&1 || die "pinned base image absent: python:3.12-alpine@${BASE_DIGEST}"
docker image inspect "${CLAMAV_IMAGE}" >/dev/null 2>&1 || die "pinned clamav image absent: ${CLAMAV_IMAGE}"
"${PY}" -c 'import cryptography, pydantic' 2>/dev/null || die "python ${PY} lacks cryptography/pydantic"

RUN_DIR="${WORK_ROOT}/${TAG_PREFIX}-${RUN_LABEL}"
SRC="${RUN_DIR}/src"
KEYS="${RUN_DIR}/keys"
SEALED="${RUN_DIR}/sealed"
WS="${RUN_DIR}/ws"
mkdir -p "${SRC}" "${KEYS}" "${SEALED}" "${WS}"
log "commit=${SOURCE_COMMIT} tag_prefix=${TAG_PREFIX} run_dir=${RUN_DIR}"

# ---- 1. checkout the exact commit ----------------------------------------
if [[ ! -d "${SRC}/.git" ]]; then
  log "cloning ${BRANCH} ..."
  git_c clone --no-checkout --branch "${BRANCH}" "${REPO_URL}" "${SRC}" >/dev/null 2>&1 \
    || git_c clone --no-checkout "${REPO_URL}" "${SRC}" >/dev/null
fi
git_c -C "${SRC}" fetch --depth 1 origin "${SOURCE_COMMIT}" >/dev/null 2>&1 || git_c -C "${SRC}" fetch origin >/dev/null
git -C "${SRC}" checkout -q -f "${SOURCE_COMMIT}"
HAVE="$(git -C "${SRC}" rev-parse HEAD)"
[[ "${HAVE}" == "${SOURCE_COMMIT}" ]] || die "checkout mismatch: have ${HAVE}, want ${SOURCE_COMMIT}"
[[ -f "${SRC}/images/runner/Dockerfile" ]] || die "source tree missing images/runner/Dockerfile"
export PYTHONPATH="${SRC}/src${PYTHONPATH:+:${PYTHONPATH}}"

# ---- 2. attestation key (fresh; keygen refuses to overwrite) -------------
log "generating attestation key ..."
"${PY}" "${SRC}/scripts/generate_p4_attestation_key.py" \
  --private-key "${KEYS}/p4-attestation-private.pem" \
  --public-key  "${KEYS}/p4-attestation-public.pem" \
  --metadata    "${KEYS}/p4-attestation-metadata.json" >/dev/null
KEY_ID="$("${PY}" -c "import json,sys;print(json.load(open(sys.argv[1]))['key_id'])" "${KEYS}/p4-attestation-metadata.json")"
log "key_id=${KEY_ID}"

# ---- 3. build all 12 role images from the exact commit -------------------
log "building 12 images (6 roles x 2 variants, --no-cache) — this is the long step ..."
"${PY}" "${SRC}/scripts/build_p4_images.py" \
  --source-root "${SRC}" \
  --source-commit "${SOURCE_COMMIT}" \
  --tag-prefix "${TAG_PREFIX}" \
  --public-metadata "${KEYS}/p4-attestation-metadata.json" \
  --output "${RUN_DIR}/build.json"
log "images built"

# ---- 4. images role-map (primary=variant a, comparison=variant b) --------
IMAGES_MAP="${RUN_DIR}/images_map.json"
{
  printf '{"images":{'
  first=1
  for role in "${ROLES[@]}"; do
    [[ $first -eq 1 ]] && first=0 || printf ','
    printf '"%s":{"primary":"echo-certforge-%s:%s-a","comparison":"echo-certforge-%s:%s-b"}' \
      "${role}" "${role}" "${TAG_PREFIX}" "${role}" "${TAG_PREFIX}"
  done
  printf '}}'
} > "${IMAGES_MAP}"

# ---- 5. seal the twelve images (identity + SBOM + provenance) -------------
log "sealing image identities ..."
"${PY}" "${SRC}/scripts/seal_p4_images.py" \
  --images "${IMAGES_MAP}" \
  --source-commit "${SOURCE_COMMIT}" \
  --base-digest "${BASE_DIGEST}" \
  --trivy "${TRIVY}" \
  --attestation-private-key "${KEYS}/p4-attestation-private.pem" \
  --output-dir "${SEALED}" \
  --manifest "${SEALED}/manifest.json"
log "sealed manifest: ${SEALED}/manifest.json"

# ---- 6. the 14-step hostile-acceptance gate ------------------------------
# NOTE: seal writes ${SEALED}/images.json (role map + sealed_manifest_sha256
# binding) — that bound document, NOT the raw input map, is the gate's --images.
GATE_IMAGES="${SEALED}/images.json"
[[ -f "${GATE_IMAGES}" ]] || die "seal did not produce ${GATE_IMAGES}"
RESULT="${RUN_DIR}/p4_hostile_result.json"
log "running hostile-acceptance gate ..."
set +e
"${PY}" "${SRC}/scripts/p4_hostile_acceptance.py" \
  --images "${GATE_IMAGES}" \
  --sealed-manifest "${SEALED}/manifest.json" \
  --base-digest "${BASE_DIGEST}" \
  --source-commit "${SOURCE_COMMIT}" \
  --trivy "${TRIVY}" \
  --cosign "${COSIGN}" \
  --clamav-image "${CLAMAV_IMAGE}" \
  --workspace "${WS}" \
  --output "${RESULT}"
GATE_RC=$?
set -e

# ---- 7. verdict ----------------------------------------------------------
echo "======================== P4 GATE VERDICT ========================"
echo "run_dir:      ${RUN_DIR}"
echo "source_commit ${SOURCE_COMMIT}"
echo "gate_exit:    ${GATE_RC}"
if [[ -f "${RESULT}" ]]; then
  "${PY}" - "${RESULT}" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("passed:          ", d.get("passed"))
print("run_outcome:     ", d.get("run_outcome"))
print("release_verdict: ", d.get("release_verdict"))
fc = d.get("failed_checks") or []
print("failed_checks:   ", fc if fc else "[] (none)")
# surface the specific signer-identity check the 307667a fix targets
def walk(o, hits):
    if isinstance(o, dict):
        for k, v in o.items():
            if "signer_image_identity" in str(k):
                hits.append((k, v))
            walk(v, hits)
    elif isinstance(o, list):
        for x in o: walk(x, hits)
hits = []; walk(d, hits)
for k, v in hits[:6]:
    print("  signer-check:", k, "=", v)
PYEOF
else
  echo "NO RESULT FILE WRITTEN — gate aborted before producing output"
fi
echo "================================================================="
exit "${GATE_RC}"
