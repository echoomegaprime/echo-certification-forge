#!/usr/bin/env python3
"""Production subscriber-to-dispatcher fail-closed certification smoke.

This test runs only after the real API and dispatcher are active. It submits an exact-identity
local target through the customer HTTP contract without a trusted production-E2E attestation,
waits for the durable dispatcher, and verifies that the service signs ``NOT_READY`` while keeping
the append-only evidence and public signature-verification paths healthy. A deploy smoke must not
manufacture the external evidence that the production gate is intended to require.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from echo_certification_forge.acquisition import acquire_target
from echo_certification_forge.models import TargetIdentity
from echo_certification_forge.subscriber import (
    OrganizationStatus,
    SubscriberGovernance,
    SubscriberPolicy,
)

_NONCE = str(time.time_ns())


def _request(
    base: str,
    method: str,
    path: str,
    *,
    tenant: str | None = None,
    token: str | None = None,
    body: dict | None = None,
) -> tuple[int, dict]:
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method=method,
    )
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if tenant is not None:
        request.add_header("X-Tenant-ID", tenant)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"detail": "non_json_response"}


def _require(condition: bool, message: str, detail: object | None = None) -> None:
    if not condition:
        suffix = "" if detail is None else f": {detail}"
        raise RuntimeError(message + suffix)
    print(f"  [ok ] {message}")


def _require_attestation_gate_closed(terminal: dict) -> None:
    """Prove an unattested run cannot be promoted by the production dispatcher."""

    _require(
        terminal.get("release_verdict") == "NOT_READY",
        "unattested customer run is NOT_READY",
        terminal.get("release_verdict"),
    )
    production_e2e = terminal.get("production_e2e")
    _require(
        isinstance(production_e2e, dict) and production_e2e.get("verified") is False,
        "unattested customer run has no verified production E2E",
        production_e2e,
    )


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8309"
    db_path = os.environ.get("ECHO_CERTFORGE_DB")
    policy_path = os.environ.get("ECHO_CERTFORGE_SUBSCRIBER_POLICY")
    pepper = os.environ.get("ECHO_CERTFORGE_API_KEY_PEPPER")
    _require(bool(db_path and policy_path and pepper), "subscriber runtime is configured")
    assert db_path is not None and policy_path is not None and pepper is not None

    status_code, status = _request(base, "GET", "/v1/status")
    _require(status_code == 200, "service status is reachable", status_code)
    _require(status.get("adapter_qualification") == "REQUIRED", "required adapter mode is active")
    environment_digest = status.get("certification_environment_identity_digest")
    runner_image_digest = status.get("runner_image_digest")
    _require(
        isinstance(environment_digest, str) and len(environment_digest) == 64,
        "customer certification environment is published",
    )
    _require(
        isinstance(runner_image_digest, str) and runner_image_digest.startswith("sha256:"),
        "customer runner image is published",
    )

    governance = SubscriberGovernance(
        Path(db_path), SubscriberPolicy.load(Path(policy_path)), pepper.encode("utf-8")
    )
    owner = governance.provision_organization(
        slug=f"production-dispatch-smoke-{_NONCE}",
        display_name="Production Dispatch Smoke",
        owner_email=f"owner-{_NONCE}@smoke.invalid",
        owner_display_name="Production Dispatch Smoke",
        plan_code="sovereign",
        status=OrganizationStatus.ACTIVE,
    )
    headers = {
        "tenant": owner.organization_id,
        "token": owner.bootstrap_api_key,
    }
    target_root = Path(db_path).parent / "deploy-scratch" / f"dispatch-smoke-{_NONCE}"
    target_root.mkdir(parents=True)
    try:
        (target_root / "certforge_smoke.py").write_text(
            "print('echo-certification-forge-production-smoke')\n",
            encoding="utf-8",
        )
        (target_root / "README.md").write_text(
            "# Certification Forge production dispatch smoke\n",
            encoding="utf-8",
        )
        acquired = acquire_target(
            {"type": "local", "path": str(target_root)}, target_root / ".unused"
        )
        target = TargetIdentity(
            tenant_id=owner.organization_id,
            target_type=acquired.target_type,
            canonical_ref=acquired.canonical_ref,
            artifact_sha256=acquired.artifact_sha256,
        )

        project_status, project = _request(
            base,
            "POST",
            "/v1/subscriber/projects",
            **headers,
            body={
                "slug": f"production-dispatch-smoke-{_NONCE}",
                "name": "Production Dispatch Smoke",
                "target_reference": acquired.canonical_ref,
            },
        )
        _require(project_status == 201, "production smoke project was created", project_status)
        project_id = project.get("project_id")
        _require(isinstance(project_id, str), "production smoke project id was returned")

        submit_status, submitted = _request(
            base,
            "POST",
            "/v1/certifications",
            **headers,
            body={
                "tenant_id": owner.organization_id,
                "project_id": project_id,
                "target": {
                    "target_type": "local",
                    "identity_digest": target.identity_digest,
                    "reference": acquired.canonical_ref,
                    "path": acquired.canonical_ref,
                },
                "environment": {
                    "identity_digest": environment_digest,
                    "runner_image_digest": runner_image_digest,
                },
                "policy_version": status["rule_manifest_id"],
                "idempotency_key": f"production-dispatch-smoke-{_NONCE}",
                "journey": ["python3", "certforge_smoke.py"],
            },
        )
        _require(submit_status == 201, "customer certification was accepted", submitted)
        run_id = submitted.get("run_id")
        _require(isinstance(run_id, str), "customer run id was returned")

        terminal: dict = {}
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            read_status, terminal = _request(
                base, "GET", f"/v1/certifications/{run_id}", **headers
            )
            _require(read_status == 200, "customer run remains readable", read_status)
            if terminal.get("state") in {"COMPLETE", "FAILED", "CANCELLED"}:
                break
            time.sleep(1)
        _require(terminal.get("state") == "COMPLETE", "dispatcher completed the customer run", terminal)
        _require(terminal.get("run_outcome") == "COMPLETE", "customer run outcome is COMPLETE")
        _require_attestation_gate_closed(terminal)
        _require(
            terminal.get("environment_identity_digest") == environment_digest,
            "verdict retained the published environment identity",
        )

        evidence_status, evidence = _request(
            base, "POST", f"/v1/certifications/{run_id}/verify", **headers
        )
        _require(evidence_status == 200 and evidence.get("valid") is True, "evidence chain verifies")
        _require(int(evidence.get("artifact_count", 0)) > 0, "customer evidence is non-empty")

        verdict_status, verdict = _request(
            base, "GET", f"/v1/certifications/{run_id}/verdict", **headers
        )
        _require(verdict_status == 200, "signed verdict is retrievable", verdict_status)
        payload = verdict.get("payload", {})
        _require(payload.get("release_verdict") == "NOT_READY", "signed verdict is NOT_READY")
        _require(
            "production_e2e_attestation_missing" in payload.get("reasons", []),
            "signed verdict records the missing production E2E attestation",
            payload.get("reasons"),
        )
        _require(payload.get("environment_identity_digest") == environment_digest, "signed verdict binds environment")

        verify_status, verified = _request(
            base, "GET", f"/v1/certifications/{run_id}/verdict/verify", **headers
        )
        _require(
            verify_status == 200 and verified.get("valid") is True,
            "public verdict verification succeeds",
            verified,
        )
        print(f"PRODUCTION DISPATCH FAIL-CLOSED SMOKE GREEN - run_id={run_id}")
        return 0
    finally:
        shutil.rmtree(target_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"PRODUCTION DISPATCH SMOKE RED - {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
