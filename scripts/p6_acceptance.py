#!/usr/bin/env python3
"""P6 live acceptance — deployment enforcement proven against the REAL running service.

Boots the real ASGI app (the same module systemd runs) on 127.0.0.1 with a fresh store,
certifies a real target end-to-end (real RunExecutor, real Ed25519 signing, real
subprocess journey), then proves over live HTTP AND through the real pipeline hook
subprocess (scripts/deployment_admission_hook.py):

  A1  a production deployment using an uncertified artifact FAILS (hook exit 2)
  A2  a deployment using a different digest from the certified artifact FAILS
  A3  a valid, unexpired READY artifact under the required policy PASSES
      (staging admit -> succeeded outcome -> production admit, hook exit 0)
  A4  production before staging acceptance FAILS (staging-first)
  A5  a revoked certification FAILS afterwards (fail-closed on lifecycle)
  A6  a failed production deployment yields rollback evidence + a live rollback target
  A7  the deployment audit chain verifies end-to-end
  A8  a signed build webhook creates a run; a replay deduplicates; a bad signature is 401
  A9  with the forge DOWN the hook fails CLOSED (exit 3) — no forge, no deployment
  A10 a mutation without a deployment credential signature is 401 (tenant header alone
      is NOT authorization)
  A11 an EXACT byte-for-byte replay of a previously accepted signed mutation is rejected
      401 (persistent atomic nonce consumption — replay protection)

All deployment outcomes (staging acceptance, production success, failure, rollback) are
recorded through the REAL pipeline integration — the hook's ``outcome`` subcommand — so
staging provably unlocks production via the supplied integration, not via raw test HTTP.

Writes artifacts/p6_acceptance.json (+ .summary.json). Exit 0 only if every check passed.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import uvicorn  # noqa: E402

from echo_certification_forge.canonical import to_utc_iso, utc_now  # noqa: E402
from echo_certification_forge.deployment_service import (  # noqa: E402
    DEPLOY_NONCE_HEADER,
    DEPLOY_SIGNATURE_HEADER,
    DEPLOY_TIMESTAMP_HEADER,
    sign_deployment_request,
)
from echo_certification_forge.evidence import EvidenceStore  # noqa: E402
from echo_certification_forge.executor import RunExecutor, StaticEntitlement  # noqa: E402
from echo_certification_forge.models import (  # noqa: E402
    EnvironmentIdentity,
    TargetIdentity,
    VerdictLifecycleEvent,
)
from echo_certification_forge.policy import RuleManifest  # noqa: E402
from echo_certification_forge.production_e2e import (  # noqa: E402
    BASE_CHECKS,
    GENERIC_PROFILE,
    SCHEMA_VERSION,
    verify_signed_attestation,
)
from echo_certification_forge.release_hooks import (  # noqa: E402
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookSecretRegistry,
    sign_webhook,
)
from echo_certification_forge.service import ServiceContext, create_app  # noqa: E402
from echo_certification_forge.signing import (  # noqa: E402
    Ed25519VerdictSigner,
    TrustedPublicKeyRegistry,
)

TENANT = "tenant-alpha"
WEBHOOK_SECRET = "p6-acceptance-webhook-secret-0001"
DEPLOY_SECRET = "p6-acceptance-deploy-secret-0001"
HOOK = REPO_ROOT / "scripts" / "deployment_admission_hook.py"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(method: str, url: str, body: dict | bytes | None = None, headers: dict | None = None,
         sign: bool = False):
    data = None
    all_headers = {"X-Tenant-ID": TENANT, "Content-Type": "application/json"}
    if headers:
        all_headers.update(headers)
    if isinstance(body, dict):
        data = json.dumps(body).encode("utf-8")
    elif isinstance(body, bytes):
        data = body
    if sign:
        ts = to_utc_iso(utc_now())
        nonce = secrets.token_hex(16)
        all_headers[DEPLOY_TIMESTAMP_HEADER] = ts
        all_headers[DEPLOY_NONCE_HEADER] = nonce
        all_headers[DEPLOY_SIGNATURE_HEADER] = sign_deployment_request(
            DEPLOY_SECRET, TENANT, method, urllib.parse.urlsplit(url).path, ts, nonce, data or b""
        )
    request = urllib.request.Request(url, data=data, method=method, headers=all_headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # noqa: F821 — urllib.request imports urllib.error
        return exc.code, json.loads(exc.read().decode("utf-8"))


def run_hook(base_url: str, artifact: str, env: str, env_digest: str, rule_digest: str,
             deployment_id: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable, str(HOOK), "admit",
            "--forge-url", base_url,
            "--tenant", TENANT,
            "--artifact-digest", artifact,
            "--environment", env,
            "--environment-identity-digest", env_digest,
            "--rule-manifest-digest", rule_digest,
            "--deployment-id", deployment_id,
            "--requested-by", "p6.acceptance",
            "--timeout", "15",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET},
    )
    return proc.returncode, proc.stdout.strip()


def run_hook_outcome(base_url: str, admission_id: str, status: str, detail: str,
                     rollback_to: str | None = None) -> tuple[int, str]:
    """Record a REAL deployment outcome through the supplied pipeline integration."""
    command = [
        sys.executable, str(HOOK), "outcome",
        "--forge-url", base_url,
        "--tenant", TENANT,
        "--admission-id", admission_id,
        "--status", status,
        "--detail", detail,
        "--timeout", "15",
    ]
    if rollback_to:
        command += ["--rollback-to", rollback_to]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "CERTFORGE_DEPLOY_SECRET": DEPLOY_SECRET},
    )
    return proc.returncode, proc.stdout.strip()


def main() -> int:
    import urllib.error  # noqa: F401 — ensure urllib.error is importable inside http()

    checks: list[dict] = []

    def check(check_id: str, description: str, passed: bool, detail: object) -> None:
        checks.append(
            {"id": check_id, "description": description, "passed": bool(passed), "detail": detail}
        )
        marker = "PASS" if passed else "FAIL"
        print(f"[{marker}] {check_id} — {description}")

    (REPO_ROOT / "var").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="p6-acceptance-", dir=str(REPO_ROOT / "var"), ignore_cleanup_errors=True
    ) as tmp:
        tmp_path = Path(tmp)
        store = EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")
        manifest = RuleManifest.load(REPO_ROOT / "policies" / "mandatory-rules.v1.json")
        signer = Ed25519VerdictSigner.generate()
        trusted = TrustedPublicKeyRegistry.empty()
        trusted.add_pem(signer.public_key_pem)
        e2e_signer = Ed25519VerdictSigner.generate()
        e2e_trusted = TrustedPublicKeyRegistry.empty()
        e2e_trusted.add_pem(e2e_signer.public_key_pem)

        environment = EnvironmentIdentity(
            runner_image_sha256=digest("runner"),
            adapter_set_sha256=digest("adapters"),
            test_plan_sha256=digest("test-plan"),
            policy_sha256=digest("policy"),
            harness_sha256=digest("harness"),
            prompt_set_sha256=digest("prompts"),
            model_route_sha256=digest("models"),
            os_runtime_sha256=digest("os-runtime"),
            egress_policy_sha256=digest("egress"),
        )

        def certify(run_id: str, target: TargetIdentity) -> None:
            store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
            workdir = tmp_path / f"src-{run_id}"
            workdir.mkdir()
            (workdir / "hello.py").write_text("print('service ok')\n", encoding="utf-8")
            observed_at = utc_now()
            e2e_payload = {
                "schema_version": SCHEMA_VERSION,
                "attestation_id": f"p6-e2e-{target.identity_digest[:16]}",
                "profile": GENERIC_PROFILE,
                "target_identity_digest": target.identity_digest,
                "environment_identity_digest": environment.identity_digest,
                "source_commit": target.source_commit,
                "deployment_sha": target.source_commit,
                "canonical_target": target.canonical_ref,
                "required_checks": sorted(BASE_CHECKS),
                "checks": {name: True for name in sorted(BASE_CHECKS)},
                "stability_probe_count": 3,
                "observed_at": to_utc_iso(observed_at),
                "expires_at": to_utc_iso(observed_at + timedelta(minutes=30)),
                "signing_key_id": e2e_signer.key_id,
            }
            production_e2e = verify_signed_attestation(
                e2e_signer.sign_payload(e2e_payload), e2e_trusted
            )
            result = RunExecutor(store, manifest, signer).execute(
                run_id,
                target.tenant_id,
                workdir,
                entitlement=StaticEntitlement(frozenset({target.tenant_id})),
                journey=[sys.executable, "hello.py"],
                control_attestations={
                    "runner_control_channel": True,
                    "signing_authority_separation": True,
                },
                production_e2e_attestation=production_e2e,
            )
            if result.release_verdict != "PRODUCTION_READY":
                raise RuntimeError(f"certification failed: {result.blocking_findings}")

        def make_target(label: str) -> TargetIdentity:
            return TargetIdentity(
                tenant_id=TENANT,
                target_type="container",
                canonical_ref=f"registry.echo/app@{label}",
                artifact_sha256=digest(label),
                source_commit=digest("source-commit")[:40],
                dependency_sha256=digest("dependencies"),
                configuration_sha256=digest("configuration"),
            )

        v1 = make_target("p6-app-v1")
        v2 = make_target("p6-app-v2")
        certify("cert-p6-v1", v1)
        certify("cert-p6-v2", v2)

        context = ServiceContext(
            store=store,
            manifest=manifest,
            trusted_keys=trusted,
            deployment_ledger_path=tmp_path / "deployments.sqlite3",
            webhook_secrets=WebhookSecretRegistry(secrets={TENANT: WEBHOOK_SECRET}),
            deployment_credentials=WebhookSecretRegistry(secrets={TENANT: DEPLOY_SECRET}),
        )
        app = create_app(context)
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                status, _ = http("GET", f"{base}/healthz")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("live service never became healthy")

        env_digest = environment.identity_digest
        rule_digest = manifest.digest

        try:
            # A1 — uncertified artifact must fail (through the REAL pipeline hook subprocess)
            code, out = run_hook(base, digest("never-certified"), "production",
                                 env_digest, rule_digest, "deploy-a1")
            check("A1", "uncertified artifact production deployment fails via hook",
                  code == 2 and "artifact_not_certified" in out, {"exit": code, "stdout": out})

            # bind both certifications over live HTTP (signed with the deployment credential)
            status, body = http("POST", f"{base}/v1/certifications/cert-p6-v1/bindings", sign=True)
            bound_v1 = status == 201 and body["artifact_sha256"] == v1.artifact_sha256
            status, body = http("POST", f"{base}/v1/certifications/cert-p6-v2/bindings", sign=True)
            bound_v2 = status == 201 and body["artifact_sha256"] == v2.artifact_sha256
            check("A0", "certifications bind to exact artifact digests over live HTTP",
                  bound_v1 and bound_v2, {"v1": bound_v1, "v2": bound_v2})

            # A2 — different digest from the certified artifact must fail
            code, out = run_hook(base, digest("p6-app-v1-TAMPERED"), "staging",
                                 env_digest, rule_digest, "deploy-a2")
            check("A2", "different digest from certified artifact fails via hook",
                  code == 2 and "artifact_not_certified" in out, {"exit": code, "stdout": out})

            # A4 — production before staging acceptance fails (staging-first)
            code, out = run_hook(base, v1.artifact_sha256, "production",
                                 env_digest, rule_digest, "deploy-a4")
            check("A4", "production before staging acceptance fails (staging-first)",
                  code == 2 and "staging_acceptance_missing" in out, {"exit": code, "stdout": out})

            # A3 — valid unexpired READY artifact under the required policy passes; the
            # staging SUCCESS is recorded through the REAL pipeline integration (hook
            # outcome subcommand), which is what unlocks production.
            code, out = run_hook(base, f"sha256:{v1.artifact_sha256}", "staging",
                                 env_digest, rule_digest, "deploy-a3-stg")
            staging_ok = code == 0
            staging_admission = json.loads(out)["admission_id"] if staging_ok else None
            outcome_ok = False
            production_ok = False
            prod_admission: str | None = None
            if staging_ok:
                outcome_code, outcome_out = run_hook_outcome(
                    base, staging_admission, "SUCCEEDED", "staging smoke green")
                outcome_ok = (outcome_code == 0
                              and json.loads(outcome_out).get("recorded") is True)
                code, out = run_hook(base, v1.artifact_sha256, "production",
                                     env_digest, rule_digest, "deploy-a3-prd")
                production_ok = code == 0
                prod_admission = json.loads(out)["admission_id"] if production_ok else None
            check("A3", "READY artifact passes staging->production, outcomes via pipeline hook",
                  staging_ok and outcome_ok and production_ok,
                  {"staging_exit0": staging_ok, "outcome_recorded": outcome_ok,
                   "production_exit0": production_ok})

            # A6 — failed v2 production deployment yields rollback evidence to v1; every
            # outcome (success, failure, rollback) is recorded through the pipeline hook.
            if prod_admission is None:
                raise RuntimeError("A3 did not produce a production admission; cannot continue")
            run_hook_outcome(base, prod_admission, "SUCCEEDED", "v1 live in production")
            code, out = run_hook(base, v2.artifact_sha256, "staging",
                                 env_digest, rule_digest, "deploy-a6-stg")
            v2_staging = json.loads(out)["admission_id"]
            run_hook_outcome(base, v2_staging, "SUCCEEDED", "v2 staging green")
            code, out = run_hook(base, v2.artifact_sha256, "production",
                                 env_digest, rule_digest, "deploy-a6-prd")
            v2_production = json.loads(out)["admission_id"]
            failure_code, failure_out = run_hook_outcome(
                base, v2_production, "FAILED", "v2 production smoke red")
            failure = json.loads(failure_out) if failure_out else {}
            candidate = (failure.get("payload") or {}).get("rollback_candidate") or {}
            status, rollback = http("GET", f"{base}/v1/deployments/rollback-target")
            target_info = rollback.get("rollback_target") or {}
            rolled_code, rolled_out = run_hook_outcome(
                base, v2_production, "ROLLED_BACK", "restored v1",
                rollback_to=v1.artifact_sha256)
            rolled = json.loads(rolled_out) if rolled_out else {}
            check("A6", "failed production deployment produces rollback evidence to last-known-good",
                  failure_code == 0
                  and candidate.get("artifact_sha256") == v1.artifact_sha256
                  and target_info.get("artifact_sha256") == v1.artifact_sha256
                  and rolled_code == 0
                  and (rolled.get("payload") or {}).get("rollback_to") == v1.artifact_sha256,
                  {"failure_candidate": candidate, "rollback_target": target_info,
                   "rolled_back": rolled.get("payload")})

            # A5 — revoked certification fails afterwards
            store.append_lifecycle_event(
                "cert-p6-v1", TENANT, VerdictLifecycleEvent.REVOKED,
                "p6.acceptance", "critical vulnerability discovered",
            )
            code, out = run_hook(base, v1.artifact_sha256, "production",
                                 env_digest, rule_digest, "deploy-a5")
            check("A5", "revoked certification is denied afterwards (fail-closed lifecycle)",
                  code == 2 and "verdict_revoked" in out, {"exit": code, "stdout": out})

            # A7 — the deployment audit chain verifies end-to-end
            status, audit = http("GET", f"{base}/v1/deployments/audit")
            admissions = [r for r in audit["records"] if r["record_type"] == "ADMISSION"]
            outcomes = [r for r in audit["records"] if r["record_type"] == "OUTCOME"]
            check("A7", "append-only deployment audit chain verifies with full decision history",
                  audit["chain_valid"] is True and len(admissions) >= 8 and len(outcomes) >= 5,
                  {"chain_valid": audit["chain_valid"], "admissions": len(admissions),
                   "outcomes": len(outcomes)})

            # A8 — signed build webhook creates a run, replay deduplicates, bad signature 401
            event = {
                "event_id": "evt-p6-accept-1",
                "event_type": "build.artifact.published",
                "tenant_id": TENANT,
                "artifact_sha256": digest("webhook-artifact"),
                "source_commit": "abc123def456",
                "repository": "https://github.com/echo/app",
                "environment_identity_digest": digest("build-env"),
                "policy_version": manifest.manifest_id,
            }
            payload = json.dumps(event).encode("utf-8")
            ts = to_utc_iso(utc_now())
            signed_headers = {
                TIMESTAMP_HEADER: ts,
                SIGNATURE_HEADER: sign_webhook(WEBHOOK_SECRET, ts, payload),
            }
            status1, first = http("POST", f"{base}/v1/hooks/build", payload, signed_headers)
            status2, second = http("POST", f"{base}/v1/hooks/build", payload, signed_headers)
            bad_headers = {
                TIMESTAMP_HEADER: ts,
                SIGNATURE_HEADER: sign_webhook("wrong-secret", ts, payload),
            }
            status3, third = http("POST", f"{base}/v1/hooks/build", payload, bad_headers)
            check("A8", "signed webhook creates run, replay deduplicates, bad signature is 401",
                  status1 == 201 and status2 == 200
                  and second["run"]["run_id"] == first["run"]["run_id"]
                  and status3 == 401,
                  {"first": status1, "replay": status2, "bad_signature": status3})

            # A10 — tenant header alone is NOT authorization for mutations (fail-closed 401)
            status_unsigned, unsigned_body = http(
                "POST",
                f"{base}/v1/deployments/admissions",
                {"artifact_sha256": v2.artifact_sha256,
                 "deployment_environment": "staging",
                 "environment_identity_digest": env_digest,
                 "rule_manifest_digest": rule_digest,
                 "deployment_id": "deploy-a10",
                 "requested_by": "p6.acceptance"},
            )
            check("A10", "unsigned mutation with tenant header only is rejected 401",
                  status_unsigned == 401
                  and unsigned_body.get("detail") == "deployment_credential_signature_missing",
                  {"status": status_unsigned, "body": unsigned_body})

            # A11 — an EXACT byte-for-byte replay of an accepted signed mutation is rejected
            replay_body = json.dumps({
                "artifact_sha256": digest("replay-check"),
                "deployment_environment": "staging",
                "environment_identity_digest": env_digest,
                "rule_manifest_digest": rule_digest,
                "deployment_id": "deploy-a11",
                "requested_by": "p6.acceptance",
            }).encode("utf-8")
            replay_ts = to_utc_iso(utc_now())
            replay_nonce = secrets.token_hex(16)
            replay_headers = {
                DEPLOY_TIMESTAMP_HEADER: replay_ts,
                DEPLOY_NONCE_HEADER: replay_nonce,
                DEPLOY_SIGNATURE_HEADER: sign_deployment_request(
                    DEPLOY_SECRET, TENANT, "POST", "/v1/deployments/admissions",
                    replay_ts, replay_nonce, replay_body),
            }
            first_status, _ = http("POST", f"{base}/v1/deployments/admissions",
                                   replay_body, replay_headers)
            replay_status, replay_response = http("POST", f"{base}/v1/deployments/admissions",
                                                  replay_body, replay_headers)
            check("A11", "exact replay of a signed mutation is rejected (nonce consumed)",
                  first_status == 200 and replay_status == 401
                  and replay_response.get("detail") == "deployment_credential_nonce_reused",
                  {"first": first_status, "replay": replay_status, "body": replay_response})
        finally:
            server.should_exit = True
            thread.join(timeout=10)

        # A9 — with the forge DOWN, the hook fails CLOSED
        code, out = run_hook(base, v1.artifact_sha256, "production",
                             env_digest, rule_digest, "deploy-a9")
        check("A9", "forge unreachable -> hook fails closed (exit 3), deployment blocked",
              code == 3 and "admission_unavailable" in out, {"exit": code, "stdout": out})

    passed = all(item["passed"] for item in checks)
    report = {
        "phase": "P6",
        "title": "deployment enforcement and platform integration — live local acceptance",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "python": sys.version,
        "passed": passed,
        "checks": checks,
    }
    artifacts = REPO_ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "p6_acceptance.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (artifacts / "p6_acceptance.summary.json").write_text(
        json.dumps(
            {
                "phase": "P6",
                "passed": passed,
                "checks_total": len(checks),
                "checks_passed": sum(1 for item in checks if item["passed"]),
                "generated_at": report["generated_at"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"\nP6 acceptance: {'PASSED' if passed else 'FAILED'} "
          f"({sum(1 for item in checks if item['passed'])}/{len(checks)}) "
          f"-> artifacts/p6_acceptance.json")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
