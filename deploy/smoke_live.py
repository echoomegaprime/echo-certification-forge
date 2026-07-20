#!/usr/bin/env python3
"""Live smoke for a running echo-certification-forge instance.

Exercises the fail-closed, tenant-scoped behaviors of the real HTTP surface — not just a 200 on
/healthz. Exits non-zero (and prints the failing check) on any red so the deploy gate can roll back.

Usage: python3 deploy/smoke_live.py http://127.0.0.1:8311
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request

FAILS: list[str] = []


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _req(base: str, method: str, path: str, *, tenant: str | None = None, body: dict | None = None):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if tenant is not None:
        request.add_header("X-Tenant-ID", tenant)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"_raw": raw.decode(errors="replace")}


def check(name: str, cond: bool, detail: str = "") -> None:
    status = "ok " if cond else "FAIL"
    print(f"  [{status}] {name}{'' if cond else ' -> ' + detail}")
    if not cond:
        FAILS.append(name)


def _submit_body(policy: str, *, target_digest: str, key: str, tenant: str = "smoke-tenant") -> dict:
    return {
        "tenant_id": tenant,
        "target": {"target_type": "git", "identity_digest": target_digest,
                   "reference": "https://example/repo@deadbeef"},
        "environment": {"identity_digest": _digest("smoke-env")},
        "policy_version": policy,
        "idempotency_key": key,
    }


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8311"
    print(f"== echo-certification-forge live smoke @ {base} ==")

    # 1. health shape (echo.certforge.health output_schema)
    status, health = _req(base, "GET", "/healthz")
    check("health 200", status == 200, str(status))
    for key in ("status", "version", "custody", "anchor", "signing"):
        check(f"health.{key} present", key in health, json.dumps(health))
    check("health: no private key in control plane", health.get("private_signing_key_loaded") is False)
    check("health: control plane runs no customer code",
          health.get("control_plane_executes_customer_code") is False)

    # resolve the active policy id from /v1/status
    _, svc = _req(base, "GET", "/v1/status")
    policy = svc.get("rule_manifest_id")
    check("active policy id resolved", bool(policy), json.dumps(svc)[:200])
    if not policy:
        print("!! cannot resolve policy; aborting"); return 1

    # 2. no tenant header -> 401 (fail closed)
    status, _ = _req(base, "GET", "/v1/certifications")
    check("list without tenant -> 401", status == 401, str(status))

    # 3. submit -> 201 QUEUED bound to declared target
    key = "smoke-key-" + _digest("k")[:12]
    tgt = _digest("smoke-target-A")
    status, run = _req(base, "POST", "/v1/certifications", tenant="smoke-tenant",
                       body=_submit_body(policy, target_digest=tgt, key=key))
    check("submit -> 201", status == 201, f"{status}:{json.dumps(run)[:200]}")
    run_id = run.get("run_id", "")
    check("submit state QUEUED", run.get("state") == "QUEUED", json.dumps(run)[:200])
    check("submit binds declared target", run.get("target_identity_digest") == tgt)
    check("submit default-deny NOT_READY", run.get("release_verdict") == "NOT_READY")

    # 4. idempotent replay -> 200 same run_id
    status, replay = _req(base, "POST", "/v1/certifications", tenant="smoke-tenant",
                          body=_submit_body(policy, target_digest=tgt, key=key))
    check("idempotent replay -> 200", status == 200, str(status))
    check("replay same run_id", replay.get("run_id") == run_id)

    # 5. same key, different target -> 409 conflict
    status, conflict = _req(base, "POST", "/v1/certifications", tenant="smoke-tenant",
                            body=_submit_body(policy, target_digest=_digest("smoke-target-B"), key=key))
    check("key reuse w/ diff target -> 409", status == 409, str(status))
    check("conflict code idempotency_conflict", conflict.get("detail") == "idempotency_conflict")

    # 6. status readable by owner
    status, _got = _req(base, "GET", f"/v1/certifications/{run_id}", tenant="smoke-tenant")
    check("owner status -> 200", status == 200, str(status))

    # 7. cross-tenant is 404 (no existence leak) across the surface
    for path, method in [
        (f"/v1/certifications/{run_id}", "GET"),
        (f"/v1/certifications/{run_id}/findings", "GET"),
        (f"/v1/certifications/{run_id}/evidence", "GET"),
        (f"/v1/certifications/{run_id}/verdict", "GET"),
        (f"/v1/certifications/{run_id}/verify", "POST"),
        (f"/v1/certifications/{run_id}/cancel", "POST"),
    ]:
        status, _ = _req(base, method, path, tenant="intruder-tenant")
        check(f"cross-tenant {method} {path.split('/')[-1]} -> 404", status == 404, str(status))

    # 8. verdict not available before signing -> 404
    status, _ = _req(base, "GET", f"/v1/certifications/{run_id}/verdict", tenant="smoke-tenant")
    check("verdict before signing -> 404", status == 404, str(status))

    # 9. cancel -> 200 CANCELLED, second cancel -> 409 fail closed
    status, cancelled = _req(base, "POST", f"/v1/certifications/{run_id}/cancel", tenant="smoke-tenant")
    check("cancel -> 200", status == 200, str(status))
    check("cancel state CANCELLED", cancelled.get("state") == "CANCELLED", json.dumps(cancelled)[:200])
    status, again = _req(base, "POST", f"/v1/certifications/{run_id}/cancel", tenant="smoke-tenant")
    check("second cancel -> 409", status == 409, str(status))
    check("second cancel not_cancellable", again.get("detail") == "run_not_cancellable")

    print()
    if FAILS:
        print(f"SMOKE RED — {len(FAILS)} failed: {', '.join(FAILS)}")
        return 1
    print("SMOKE GREEN — all fail-closed + happy-path checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
