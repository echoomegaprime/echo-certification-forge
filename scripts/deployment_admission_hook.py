#!/usr/bin/env python3
"""P6 deployment admission hook — the enforcement point a deployment pipeline MUST pass.

Two subcommands cover the full enforcement loop:

``admit`` — called immediately before an artifact is promoted (staging or production).
It asks the Certification Forge admission API for a recorded decision and converts it
into an exit code the pipeline gates on:

    0  admission ALLOWED — proceed with the deployment
    2  admission DENIED  — the artifact is uncertified/mismatched/stale/revoked/untrusted
                           or staging acceptance is missing; the deployment MUST stop
    3  fail-closed error — the forge was unreachable, returned a malformed/unexpected
                           response, or the invocation was invalid; the deployment MUST stop

``outcome`` — called immediately after the deployment attempt finishes. It records the
REAL result (SUCCEEDED / FAILED / ROLLED_BACK) against the exact admission_id returned by
``admit``, which is what unlocks production after a successful staging deployment and what
produces rollback evidence after a failed one:

    0  outcome RECORDED — the ledger accepted the deployment result
    3  fail-closed error — the outcome could NOT be recorded; the pipeline must alert,
                           because an unrecorded staging success cannot unlock production

Usage:
    python scripts/deployment_admission_hook.py admit \
        --forge-url http://127.0.0.1:8309 \
        --tenant tenant-alpha \
        --artifact-digest sha256:<64-hex> \
        --environment production \
        --environment-identity-digest <64-hex> \
        --rule-manifest-digest <64-hex> \
        --deployment-id deploy-2026-07-25-01 \
        --requested-by ci.pipeline

    python scripts/deployment_admission_hook.py outcome \
        --forge-url http://127.0.0.1:8309 \
        --tenant tenant-alpha \
        --admission-id <admission_id from admit> \
        --status SUCCEEDED \
        --detail "staging smoke green"

Only the standard library is used so any pipeline can vendor this file as-is. Legacy
invocations without a subcommand are treated as ``admit`` for backward compatibility.

Authentication: the forge requires an HMAC deployment credential on every mutation.
The shared secret is read from the CERTFORGE_DEPLOY_SECRET environment variable (never
a CLI flag, so it cannot leak into process listings); a missing secret is a fail-closed
error (exit 3). Requests are signed with the ``certforge-deploy-v2`` scheme: HMAC-SHA256
over tenant, HTTP method, canonical request path, timestamp, a unique random nonce, and
the SHA-256 of the exact request body — so a captured signature can never be replayed or
retargeted at a different admission, endpoint, or verb.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

EXIT_ALLOWED = 0
EXIT_DENIED = 2
EXIT_ERROR = 3

DEPLOY_SIGNATURE_HEADER = "X-Certforge-Deploy-Signature"
DEPLOY_TIMESTAMP_HEADER = "X-Certforge-Deploy-Timestamp"
DEPLOY_NONCE_HEADER = "X-Certforge-Deploy-Nonce"
DEPLOY_SIGNATURE_SCHEME = "certforge-deploy-v2"
SECRET_ENV = "CERTFORGE_DEPLOY_SECRET"

OUTCOME_STATUSES = ("SUCCEEDED", "FAILED", "ROLLED_BACK")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Certification Forge deployment admission hook")
    subcommands = parser.add_subparsers(dest="command", required=True)

    admit = subcommands.add_parser("admit", help="request a recorded admission decision")
    admit.add_argument("--forge-url", required=True, help="Base URL of the certification forge API")
    admit.add_argument("--tenant", required=True, help="Tenant identifier (X-Tenant-ID)")
    admit.add_argument("--artifact-digest", required=True, help="Exact artifact digest (sha256:<hex> or bare hex)")
    admit.add_argument("--environment", required=True, choices=["staging", "production"])
    admit.add_argument("--environment-identity-digest", required=True)
    admit.add_argument("--rule-manifest-digest", required=True)
    admit.add_argument("--deployment-id", required=True)
    admit.add_argument("--requested-by", default="deployment.pipeline")
    admit.add_argument("--timeout", type=float, default=30.0)

    outcome = subcommands.add_parser("outcome", help="record the real deployment result")
    outcome.add_argument("--forge-url", required=True, help="Base URL of the certification forge API")
    outcome.add_argument("--tenant", required=True, help="Tenant identifier (X-Tenant-ID)")
    outcome.add_argument("--admission-id", required=True, help="Exact admission_id returned by admit")
    outcome.add_argument("--status", required=True, choices=list(OUTCOME_STATUSES))
    outcome.add_argument("--detail", required=True, help="Human-readable deployment result detail")
    outcome.add_argument("--rollback-to", default=None, help="Artifact digest restored by a rollback")
    outcome.add_argument(
        "--operation-id",
        default=None,
        help=(
            "Stable client operation id reused (with a FRESH nonce) on every retry of the"
            " SAME outcome submission: if the forge committed the outcome but the response"
            " was lost, the retry idempotently returns the committed record instead of"
            " outcome_already_terminal"
        ),
    )
    outcome.add_argument("--timeout", type=float, default=30.0)
    return parser


def _signed_headers(secret: str, tenant: str, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    nonce = secrets.token_hex(16)
    canonical = "\n".join(
        [
            DEPLOY_SIGNATURE_SCHEME,
            tenant,
            method.upper(),
            path,
            timestamp,
            nonce,
            hashlib.sha256(body).hexdigest(),
        ]
    )
    digest = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256)
    return {
        DEPLOY_TIMESTAMP_HEADER: timestamp,
        DEPLOY_NONCE_HEADER: nonce,
        DEPLOY_SIGNATURE_HEADER: f"sha256={digest.hexdigest()}",
    }


def _post_signed(forge_url: str, path: str, tenant: str, secret: str, body: bytes,
                 timeout: float, expected_status: tuple[int, ...]) -> dict:
    url = forge_url.rstrip("/") + path
    headers = {"Content-Type": "application/json", "X-Tenant-ID": tenant}
    headers.update(_signed_headers(secret, tenant, "POST", urllib.parse.urlsplit(url).path, body))
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status not in expected_status:
            raise RuntimeError(f"unexpected status: {response.status}")
        return json.loads(response.read().decode("utf-8"))


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
    return _post_signed(args.forge_url, "/v1/deployments/admissions", args.tenant, secret,
                        body, args.timeout, expected_status=(200,))


def record_outcome(args: argparse.Namespace, secret: str) -> dict:
    payload: dict = {"status": args.status, "detail": args.detail}
    if args.rollback_to:
        payload["rollback_to"] = args.rollback_to
    if args.operation_id:
        payload["operation_id"] = args.operation_id
    body = json.dumps(payload).encode("utf-8")
    path = f"/v1/deployments/admissions/{urllib.parse.quote(args.admission_id, safe='')}/outcome"
    # 201 = newly committed; 200 = idempotent replay of the SAME committed operation
    # (recovery after a lost response) — both mean the ledger holds the outcome.
    return _post_signed(args.forge_url, path, args.tenant, secret, body,
                        args.timeout, expected_status=(201, 200))


def run_admit(args: argparse.Namespace, secret: str) -> int:
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


def run_outcome(args: argparse.Namespace, secret: str) -> int:
    try:
        record = record_outcome(args, secret)
    except urllib.error.HTTPError as exc:
        detail: object
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except (ValueError, OSError):
            detail = str(exc)
        print(json.dumps({"recorded": False,
                          "error": f"outcome_rejected: http {exc.code}", "detail": detail}))
        return EXIT_ERROR
    except (urllib.error.URLError, OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"recorded": False, "error": f"outcome_unavailable: {exc}"}))
        return EXIT_ERROR
    if record.get("admission_id") != args.admission_id or record.get("status") != args.status:
        print(json.dumps({"recorded": False, "error": "outcome_response_malformed", "raw": record}))
        return EXIT_ERROR
    print(json.dumps({"recorded": True, **record}, sort_keys=True, default=str))
    return EXIT_ALLOWED


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backward compatibility: legacy invocations passed admit flags with no subcommand.
    if argv and argv[0].startswith("--"):
        argv.insert(0, "admit")
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse exits itself on --help (0) or bad args (2)
        return EXIT_ALLOWED if exc.code == 0 else EXIT_ERROR
    secret = os.environ.get(SECRET_ENV, "")
    if not secret:
        print(json.dumps({"allowed": False, "error": f"deployment_credential_missing: set {SECRET_ENV}"}))
        return EXIT_ERROR
    if args.command == "outcome":
        return run_outcome(args, secret)
    return run_admit(args, secret)


if __name__ == "__main__":
    sys.exit(main())
