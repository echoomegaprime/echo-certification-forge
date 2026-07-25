#!/usr/bin/env python3
"""P6 deployment admission hook — the enforcement point a deployment pipeline MUST pass.

Called immediately before an artifact is promoted (staging or production). It asks the
Certification Forge admission API for a recorded decision and converts it into an exit
code the pipeline gates on:

    0  admission ALLOWED — proceed with the deployment
    2  admission DENIED  — the artifact is uncertified/mismatched/stale/revoked/untrusted
                           or staging acceptance is missing; the deployment MUST stop
    3  fail-closed error — the forge was unreachable, returned a malformed/unexpected
                           response, or the invocation was invalid; the deployment MUST stop

Usage:
    python scripts/deployment_admission_hook.py \
        --forge-url http://127.0.0.1:8309 \
        --tenant tenant-alpha \
        --artifact-digest sha256:<64-hex> \
        --environment production \
        --environment-identity-digest <64-hex> \
        --rule-manifest-digest <64-hex> \
        --deployment-id deploy-2026-07-25-01 \
        --requested-by ci.pipeline

Only the standard library is used so any pipeline can vendor this file as-is.

Authentication: the forge requires an HMAC deployment credential on every admission
request. The shared secret is read from the CERTFORGE_DEPLOY_SECRET environment
variable (never a CLI flag, so it cannot leak into process listings); a missing
secret is a fail-closed error (exit 3).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

EXIT_ALLOWED = 0
EXIT_DENIED = 2
EXIT_ERROR = 3

DEPLOY_SIGNATURE_HEADER = "X-Certforge-Deploy-Signature"
DEPLOY_TIMESTAMP_HEADER = "X-Certforge-Deploy-Timestamp"
SECRET_ENV = "CERTFORGE_DEPLOY_SECRET"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Certification Forge deployment admission hook")
    parser.add_argument("--forge-url", required=True, help="Base URL of the certification forge API")
    parser.add_argument("--tenant", required=True, help="Tenant identifier (X-Tenant-ID)")
    parser.add_argument("--artifact-digest", required=True, help="Exact artifact digest (sha256:<hex> or bare hex)")
    parser.add_argument("--environment", required=True, choices=["staging", "production"])
    parser.add_argument("--environment-identity-digest", required=True)
    parser.add_argument("--rule-manifest-digest", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--requested-by", default="deployment.pipeline")
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser


def _signed_headers(secret: str, body: bytes) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    digest = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256)
    return {
        DEPLOY_TIMESTAMP_HEADER: timestamp,
        DEPLOY_SIGNATURE_HEADER: f"sha256={digest.hexdigest()}",
    }


def request_admission(args: argparse.Namespace, secret: str) -> dict:
    body = json.dumps(
        {
            "artifact_sha256": args.artifact_digest,
            "deployment_environment": args.environment,
            "environment_identity_digest": args.environment_identity_digest,
            "rule_manifest_digest": args.rule_manifest_digest,
            "deployment_id": args.deployment_id,
            "requested_by": args.requested_by,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Tenant-ID": args.tenant}
    headers.update(_signed_headers(secret, body))
    request = urllib.request.Request(
        args.forge_url.rstrip("/") + "/v1/deployments/admissions",
        data=body,
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=args.timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected admission status: {response.status}")
        return json.loads(response.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse exits itself on --help (0) or bad args (2)
        return EXIT_ALLOWED if exc.code == 0 else EXIT_ERROR
    secret = os.environ.get(SECRET_ENV, "")
    if not secret:
        print(json.dumps({"allowed": False, "error": f"deployment_credential_missing: set {SECRET_ENV}"}))
        return EXIT_ERROR
    try:
        decision = request_admission(args, secret)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"allowed": False, "error": f"admission_unavailable: {exc}"}))
        return EXIT_ERROR
    allowed = decision.get("allowed")
    if not isinstance(allowed, bool) or "admission_id" not in decision:
        print(json.dumps({"allowed": False, "error": "admission_response_malformed", "raw": decision}))
        return EXIT_ERROR
    print(json.dumps(decision, sort_keys=True))
    return EXIT_ALLOWED if allowed else EXIT_DENIED


if __name__ == "__main__":
    sys.exit(main())
