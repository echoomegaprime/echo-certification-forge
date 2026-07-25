"""/sdk/certification-forge/r5/* — Family-14B R5 negative-control capability.

Backs (once registered) the cap ``echo.certification_forge.r5.run_negative_controls``.
This router is deliberately THIN: all verifiable logic lives in
``routers.certforge_r5_core``. The router only performs the privileged wiring —
sovereign auth, the Action-Broker grant lookup, the direct-SSH hop to the live
ANVIL family node, and the audit trail.

Fail-closed governance:
  * Sovereign key required even while the route is un-registered.
  * A matching ACTIVE, unexpired row in ``arcanum_sdk.action_broker_grants``
    (agent/task/scope FIXED in code) is required — no grant, no run.
  * Request model forbids extra fields; the operator command is a FIXED template
    over validated identity values (no shell/script/url/token is accepted).
  * The maintenance lease/token never leaves the ANVIL operator process.
  * FORGE re-verifies every Ed25519 receipt itself (``core.verify_forge_bundle``).
  * ``dry_run=true`` (default) runs a read-only preflight that mutates NOTHING.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
from functools import lru_cache
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from routers._common import audit, pg_pool, rate_limit
from routers._ssh_connector import _get_node

try:  # asyncssh is present on FORGE (the SSH connector uses it)
    import asyncssh  # type: ignore
    _ASYNCSSH = True
except Exception:  # pragma: no cover - environment probe
    _ASYNCSSH = False

from routers import certforge_r5_core as core

router = APIRouter(prefix="/sdk/certification-forge/r5", tags=["certification-forge-r5"])

_SOVEREIGN_KEY_FILE = "/home/forge/.echo_sovereign_key"
_DEFAULT_CLIENT_KEY = "/home/forge/.ssh/id_ed25519_sdk"


@lru_cache(maxsize=1)
def _sovereign_key() -> str | None:
    path = os.environ.get("ECHO_SOVEREIGN_KEY_FILE", _SOVEREIGN_KEY_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("SOVEREIGN_KEY="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _require_sovereign(x_echo_api_key: str | None) -> None:
    expected = _sovereign_key()
    if not expected or not x_echo_api_key or not hmac.compare_digest(x_echo_api_key, expected):
        raise HTTPException(status_code=401, detail="sovereign key required")


class R5Request(BaseModel):
    """Structured-only request. Extra fields are rejected — no shell/script/url/
    adapter/key/token surface reaches this capability."""
    model_config = ConfigDict(extra="forbid")

    expected_server_build_digest: str = Field(..., min_length=64, max_length=64)
    expected_registry_snapshot_digest: str = Field(..., min_length=64, max_length=64)
    expected_registry_revision: str = Field(..., min_length=6, max_length=128)
    expected_signing_key_id: str = Field(..., min_length=8, max_length=48)
    expected_base_model_digest: str = Field(..., min_length=64, max_length=64)
    expected_base_model_revision: str = Field(..., min_length=6, max_length=128)
    expected_gs343_digest: str = Field(..., min_length=64, max_length=64)
    expected_r2d2_digest: str = Field(..., min_length=64, max_length=64)
    evidence_run_id: str = Field(..., min_length=1, max_length=64)
    evidence_run_nonce: str = Field(..., min_length=16, max_length=128)
    dry_run: bool = True


async def _grant_active() -> bool:
    """Fail-closed Action-Broker grant lookup: agent/task/scope are FIXED here;
    the DB row is only the active/expiry/audit switch."""
    pool = await pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT 1 FROM arcanum_sdk.action_broker_grants
                 WHERE agent = $1 AND task = $2 AND scope = $3
                   AND active IS TRUE
                   AND (expires_at IS NULL OR expires_at > now())""",
            core.GRANT_AGENT, core.GRANT_TASK, core.GRANT_SCOPE,
        )
    return row is not None


async def _ssh_run(node: dict[str, Any], command: str, *, timeout: float) -> tuple[int, str, str]:
    key = node.get("ssh_key_path") or _DEFAULT_CLIENT_KEY
    async with asyncssh.connect(  # type: ignore[attr-defined]
        node["lan_ip"],
        username=node["ssh_user"],
        port=node["ssh_port"],
        client_keys=[key],
        known_hosts=None,
    ) as conn:
        result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
    stdout = result.stdout if isinstance(result.stdout, str) else (result.stdout or b"").decode("utf-8", "replace")
    stderr = result.stderr if isinstance(result.stderr, str) else (result.stderr or b"").decode("utf-8", "replace")
    return int(result.exit_status or 0), stdout, stderr


@router.post("/run-negative-controls",
             summary="echo.certification_forge.r5.run_negative_controls — Family-14B R5 controls",
             dependencies=[Depends(rate_limit)])
async def run_negative_controls(
    req: R5Request,
    x_echo_api_key: str | None = Header(None),
) -> dict[str, Any]:
    _require_sovereign(x_echo_api_key)

    # 1) validate identity + run id (fail-closed on any malformed value)
    try:
        identity = core.validate_identity(req.model_dump())
        run_id = core.validate_run_id(req.evidence_run_id)
    except core.R5CoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mode = "preflight" if req.dry_run else "full"

    # 2) Action-Broker grant (fail-closed)
    if not await _grant_active():
        await audit(
            "certforge-r5", "grant_denied", core.GRANT_AGENT, run_id,
            {"agent": core.GRANT_AGENT, "task": core.GRANT_TASK,
             "scope": core.GRANT_SCOPE, "run_id": run_id, "mode": mode},
        )
        raise HTTPException(status_code=403, detail="action-broker grant not active")

    if not _ASYNCSSH:
        raise HTTPException(status_code=503, detail="asyncssh unavailable on FORGE")

    # 3) resolve the live ANVIL node from the registry — NO fallback path
    node = await _get_node(core.ANVIL_NODE)
    if not node:
        raise HTTPException(status_code=503, detail="anvil node not in registry")
    if not node.get("is_reachable_from_forge"):
        raise HTTPException(status_code=503, detail="anvil not reachable from forge")

    # 4) FIXED operator command over validated identity values
    command = core.build_operator_command(
        identity,
        mode=mode,
        evidence_run_id=run_id,
        evidence_run_nonce=req.evidence_run_nonce,
    )
    timeout = 120.0 if mode == "preflight" else 900.0

    # 5) direct-SSH hop → operator runs the loopback controls on ANVIL
    try:
        exit_code, stdout, stderr = await _ssh_run(node, command, timeout=timeout)
    except (asyncio.TimeoutError, OSError, Exception) as exc:  # noqa: BLE001
        await audit(
            "certforge-r5", "ssh_failure", core.GRANT_AGENT, run_id,
            {"run_id": run_id, "mode": mode,
             "error": f"{type(exc).__name__}: {exc}"},
        )
        raise HTTPException(status_code=502,
                            detail=f"anvil operator transport failed: {type(exc).__name__}") from exc

    # 6) parse the operator's report (never trusted as proof by itself)
    report: dict[str, Any]
    try:
        report = json.loads(stdout.strip().splitlines()[-1] if stdout.strip() else "{}")
        if not isinstance(report, dict):
            raise ValueError("operator report is not an object")
    except (ValueError, IndexError):
        # try to salvage a JSON object from the tail
        report = _salvage_json(stdout)

    bundle = report.get("forge_verification_bundle") or {}

    # 7) FORGE independently re-verifies the bundle
    try:
        forge_verify = core.verify_forge_bundle(
            bundle,
            identity,
            mode=mode,
            expected_run_id=run_id,
            expected_run_nonce=req.evidence_run_nonce,
        )
    except core.R5CoreError as exc:
        forge_verify = {"all_ok": False, "reason": str(exc), "receipts": [],
                        "identity_ok": False, "key_id_ok": False}

    result = core.assemble_result(report, forge_verify, mode=mode,
                                  exit_code=exit_code, evidence_run_id=run_id)
    result["stderr_tail"] = stderr[-500:] if stderr else ""

    await audit(
        "certforge-r5", "run", core.GRANT_AGENT, run_id,
        {"run_id": run_id, "mode": mode, "exit_code": exit_code,
         "r5_gate": result["r5_gate"], "run_outcome": result["run_outcome"],
         "forge_all_ok": forge_verify.get("all_ok")},
    )
    return result


def _salvage_json(text: str) -> dict[str, Any]:
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    obj = json.loads(text[start:i + 1])
                    if isinstance(obj, dict) and "r5_gate" in obj:
                        return obj
                except ValueError:
                    start = -1
    return {"run_outcome": "INCONCLUSIVE", "r5_gate": "BLOCK",
            "blocker": "operator produced no parseable report"}
