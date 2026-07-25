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

Writes artifacts/p6_acceptance.json (+ .summary.json). Exit 0 only if every check passed.
"""
from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import uvicorn  # noqa: E402

from echo_certification_forge.canonical import to_utc_iso, utc_now  # noqa: E402
from echo_certification_forge.evidence import EvidenceStore  # noqa: E402
from echo_certification_forge.executor import RunExecutor, StaticEntitlement  # noqa: E402
from echo_certification_forge.models import (  # noqa: E402
    EnvironmentIdentity,
    TargetIdentity,
    VerdictLifecycleEvent,
)
from echo_certification_forge.policy import RuleManifest  # noqa: E402
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
HOOK = REPO_ROOT / "scripts" / "deployment_admission_hook.py"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(method: str, url: str, body: dict | bytes | None = None, headers: dict | None = None):
    data = None
    all_headers = {"X-Tenant-ID": TENANT, "Content-Type": "application/json"}
    if headers:
        all_headers.update(headers)
    if isinstance(body, dict):
        data = json.dumps(body).encode("utf-8")
    elif isinstance(body, bytes):
        data = body
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
            sys.executable, str(HOOK),
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
            )
            if result.release_verdict != "PRODUCTION_READY":
                raise RuntimeError(f"certification failed: {result.blocking_findings}")

        def make_target(label: str) -> TargetIdentity:
            return TargetIdentity(
                tenant_id=TENANT,
                target_type="container",
                canonical_ref=f"registry.echo/app@{label}",
                artifact_sha256=digest(label),
                source_commit="abc123def456",
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

            # bind both certifications over live HTTP
            status, body = http("POST", f"{base}/v1/certifications/cert-p6-v1/bindings")
            bound_v1 = status == 201 and body["artifact_sha256"] == v1.artifact_sha256
            status, body = http("POST", f"{base}/v1/certifications/cert-p6-v2/bindings")
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

            # A3 — valid unexpired READY artifact under the required policy passes
            code, out = run_hook(base, f"sha256:{v1.artifact_sha256}", "staging",
                                 env_digest, rule_digest, "deploy-a3-stg")
            staging_ok = code == 0
            staging_admission = json.loads(out)["admission_id"] if staging_ok else None
            outcome_ok = False
            production_ok = False
            prod_admission: str | None = None
            if staging_ok:
                status, _ = http(
                    "POST",
                    f"{base}/v1/deployments/admissions/{staging_admission}/outcome",
                    {"status": "SUCCEEDED", "detail": "staging smoke green"},
                )
                outcome_ok = status == 201
                code, out = run_hook(base, v1.artifact_sha256, "production",
                                     env_digest, rule_digest, "deploy-a3-prd")
                production_ok = code == 0
                prod_admission = json.loads(out)["admission_id"] if production_ok else None
            check("A3", "valid unexpired READY artifact passes staging->production via hook",
                  staging_ok and outcome_ok and production_ok,
                  {"staging_exit0": staging_ok, "outcome_201": outcome_ok,
                   "production_exit0": production_ok})

            # A6 — failed v2 production deployment yields rollback evidence to v1
            if prod_admission is None:
                raise RuntimeError("A3 did not produce a production admission; cannot continue")
            status, _ = http(
                "POST",
                f"{base}/v1/deployments/admissions/{prod_admission}/outcome",
                {"status": "SUCCEEDED", "detail": "v1 live in production"},
            )
            code, out = run_hook(base, v2.artifact_sha256, "staging",
                                 env_digest, rule_digest, "deploy-a6-stg")
            v2_staging = json.loads(out)["admission_id"]
            http("POST", f"{base}/v1/deployments/admissions/{v2_staging}/outcome",
                 {"status": "SUCCEEDED", "detail": "v2 staging green"})
            code, out = run_hook(base, v2.artifact_sha256, "production",
                                 env_digest, rule_digest, "deploy-a6-prd")
            v2_production = json.loads(out)["admission_id"]
            status, failure = http(
                "POST",
                f"{base}/v1/deployments/admissions/{v2_production}/outcome",
                {"status": "FAILED", "detail": "v2 production smoke red"},
            )
            candidate = (failure.get("payload") or {}).get("rollback_candidate") or {}
            status, rollback = http("GET", f"{base}/v1/deployments/rollback-target")
            target_info = rollback.get("rollback_target") or {}
            status, rolled = http(
                "POST",
                f"{base}/v1/deployments/admissions/{v2_production}/outcome",
                {"status": "ROLLED_BACK", "detail": "restored v1",
                 "rollback_to": v1.artifact_sha256},
            )
            check("A6", "failed production deployment produces rollback evidence to last-known-good",
                  candidate.get("artifact_sha256") == v1.artifact_sha256
                  and target_info.get("artifact_sha256") == v1.artifact_sha256
                  and status == 201
                  and rolled["payload"]["rollback_to"] == v1.artifact_sha256,
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
        json.dumps(report, indent=2), encoding="utf-8"
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
        ),
        encoding="utf-8",
    )
    print(f"\nP6 acceptance: {'PASSED' if passed else 'FAILED'} "
          f"({sum(1 for item in checks if item['passed'])}/{len(checks)}) "
          f"-> artifacts/p6_acceptance.json")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
