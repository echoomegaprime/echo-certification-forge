"""Live reversible acceptance for the Echo Desktop administrative SDK bridge.

Run on FORGE with the echo-worker-server virtualenv. The script signs Tier-2
envelopes locally, creates a tenant-wide legal hold, releases it in ``finally``,
and emits metadata-only results. API keys, HMAC seeds, signatures, and Vault
values are never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import httpx


def sdk_params(capability: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return the strict SDK payload without mutating the caller's mapping."""
    return {"command": capability.rsplit(".", 1)[-1], **params}


def sovereign_key(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SOVEREIGN_KEY="):
            value = line.split("=", 1)[1].strip()
            if value:
                return value
    raise RuntimeError("sovereign key unavailable")


async def invoke(
    *,
    client: httpx.AsyncClient,
    api_key: str,
    secret_hmac: str,
    capability: str,
    params: dict[str, Any],
    tier: int,
) -> dict[str, Any]:
    from routers._auth_p4 import hmac_sign

    request_params = sdk_params(capability, params)
    envelope: dict[str, Any] = {
        "envelope_version": 1,
        "capability": capability,
        "params": request_params,
    }
    if tier >= 2:
        nonce = secrets.token_hex(24)
        timestamp = int(time.time())
        envelope["auth"] = {
            "hmac": hmac_sign(
                secret_hmac,
                api_key,
                capability,
                request_params,
                nonce,
                timestamp,
            ),
            "nonce": nonce,
            "ts": timestamp,
        }
        envelope["context"] = {
            "bypass_reason": (
                "Verify the reversible vault-backed Certification Forge "
                "administrative SDK bridge end to end."
            )
        }
    response = await client.post(
        "/sdk/invoke",
        headers={"X-Echo-API-Key": api_key},
        json=envelope,
    )
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"{capability} returned non-JSON HTTP {response.status_code}") from exc
    target = payload.get("result") if isinstance(payload, dict) else None
    target_status = target.get("status_code") if isinstance(target, dict) else None
    if response.status_code != 200 or target_status not in (200, 201):
        error = payload.get("detail") or payload.get("error") or target
        raise RuntimeError(
            f"{capability} failed: gate={response.status_code} target={target_status} error={error}"
        )
    return target.get("body")


async def smoke(args: argparse.Namespace) -> dict[str, Any]:
    sys.path.insert(0, args.worker_root)
    from routers.sdk_invoke import _authenticate

    api_key = sovereign_key(Path(args.sovereign_key_file))
    key_info = await _authenticate(api_key)
    secret_hmac = str(key_info.get("secret_hmac") or "")
    if len(secret_hmac) < 64:
        raise RuntimeError("active sovereign key has no usable HMAC seed")
    hold_id = args.hold_id or f"hold-desktop-sdk-smoke-{int(time.time())}"
    report: dict[str, Any] = {
        "ok": False,
        "hold_id": hold_id,
        "created": False,
        "released": False,
    }
    async with httpx.AsyncClient(base_url=args.gate, timeout=45) as client:
        audit_before = await invoke(
            client=client,
            api_key=api_key,
            secret_hmac=secret_hmac,
            capability="echo.certforge.admin.audit",
            params={"limit": 100},
            tier=1,
        )
        try:
            created = await invoke(
                client=client,
                api_key=api_key,
                secret_hmac=secret_hmac,
                capability="echo.certforge.admin.legal_hold_create",
                params={
                    "hold_id": hold_id,
                    "reason": "Reversible Desktop administrative SDK bridge acceptance.",
                },
                tier=2,
            )
            report["created"] = created.get("active") is True
        finally:
            if report["created"]:
                released = await invoke(
                    client=client,
                    api_key=api_key,
                    secret_hmac=secret_hmac,
                    capability="echo.certforge.admin.legal_hold_release",
                    params={"hold_id": hold_id},
                    tier=2,
                )
                report["released"] = released.get("active") is False
        audit_after = await invoke(
            client=client,
            api_key=api_key,
            secret_hmac=secret_hmac,
            capability="echo.certforge.admin.audit",
            params={"limit": 100},
            tier=1,
        )
    actions = {
        str(row.get("action"))
        for row in audit_after
        if isinstance(row, dict) and row.get("action")
    }
    report.update(
        {
            "audit_before": len(audit_before),
            "audit_after": len(audit_after),
            "audit_actions_verified": {
                "legal_hold.create",
                "legal_hold.release",
            }.issubset(actions),
        }
    )
    report["ok"] = all(
        (
            report["created"],
            report["released"],
            report["audit_actions_verified"],
            report["audit_after"] >= report["audit_before"] + 2,
        )
    )
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--gate", default="http://127.0.0.1:8000")
    result.add_argument("--worker-root", default="/home/forge/echo-worker-server")
    result.add_argument("--sovereign-key-file", default="/home/forge/.echo_sovereign_key")
    result.add_argument("--hold-id")
    return result


def main() -> int:
    report = asyncio.run(smoke(parser().parse_args()))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
