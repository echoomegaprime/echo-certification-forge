"""/sdk/certification-forge/r5/* async — non-blocking R5 negative-control runs.

A FULL R5 run performs 4x 14B inferences on ANVIL and exceeds the :8000 gate proxy read timeout
(and the gunicorn worker timeout). This ADDITIVE router (auto-mounted; it does NOT modify the proven
synchronous ``certification_forge_r5_router``) provides an async submit/poll pair:

  POST /sdk/certification-forge/r5/submit-async  -> launches the operator DETACHED on ANVIL
                                                    (survives gate worker recycling), persists a
                                                    RUNNING row in arcanum_sdk.r5_async_runs, returns
                                                    a run_id immediately.
  GET  /sdk/certification-forge/r5/status/{run_id} -> reads the row; if still RUNNING, checks the
                                                    ANVIL result file; on completion FORGE
                                                    independently re-verifies the Ed25519 bundle and
                                                    the row is finalized to COMPLETE.

Same fail-closed governance as the sync path: sovereign key required, active Action-Broker grant
required, FIXED operator command over validated identity values, FORGE re-verifies every receipt.
"""
from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from routers._common import audit, pg_pool, rate_limit
from routers._ssh_connector import _get_node

try:
    import asyncssh  # type: ignore
    _ASYNCSSH = True
except Exception:  # pragma: no cover
    _ASYNCSSH = False

from routers import certforge_r5_core as core

router = APIRouter(prefix="/sdk/certification-forge/r5", tags=["certification-forge-r5-async"])

_SOVEREIGN_KEY_FILE = "/home/forge/.echo_sovereign_key"
_DEFAULT_CLIENT_KEY = "/home/forge/.ssh/id_ed25519_sdk"
_ASYNC_DIR = "/tmp/r5_async"


# --- self-contained helpers (kept independent of the sync router) ---------------------------------
def _sovereign_key() -> str | None:
    try:
        with open(_SOVEREIGN_KEY_FILE, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("SOVEREIGN_KEY="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


def _require_sovereign(x_echo_api_key: str | None) -> None:
    expected = _sovereign_key()
    if not expected or x_echo_api_key != expected:
        raise HTTPException(status_code=403, detail="sovereign key required")


async def _grant_active() -> bool:
    pool = await pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT 1 FROM arcanum_sdk.action_broker_grants
                 WHERE agent = $1 AND task = $2 AND scope = $3
                   AND active IS TRUE AND (expires_at IS NULL OR expires_at > now())""",
            core.GRANT_AGENT, core.GRANT_TASK, core.GRANT_SCOPE,
        )
    return row is not None


async def _ssh_run(node: dict[str, Any], command: str, *, timeout: float) -> tuple[int, str, str]:
    key = node.get("ssh_key_path") or _DEFAULT_CLIENT_KEY
    async with asyncssh.connect(  # type: ignore[attr-defined]
        node["lan_ip"], username=node["ssh_user"], port=node["ssh_port"],
        client_keys=[key], known_hosts=None,
    ) as conn:
        result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
    out = result.stdout if isinstance(result.stdout, str) else (result.stdout or b"").decode("utf-8", "replace")
    err = result.stderr if isinstance(result.stderr, str) else (result.stderr or b"").decode("utf-8", "replace")
    return int(result.exit_status or 0), out, err


def _launch_command(operator_cmd: str, run_id: str) -> str:
    """Wrap the (already fully shell-quoted) operator command so it runs DETACHED on ANVIL,
    writing stdout/stderr/return-code to files under _ASYNC_DIR. Returns immediately after launch."""
    # run_id is validated [A-Za-z0-9._-]{1,64} upstream, so it is safe as a path component.
    base = f"{_ASYNC_DIR}/{run_id}"
    inner = f"{operator_cmd} > {base}.out 2> {base}.err; echo $? > {base}.rc"
    return (
        f"mkdir -p {_ASYNC_DIR} && "
        f"setsid sh -c {shlex.quote(inner)} >/dev/null 2>&1 </dev/null & "
        f"echo LAUNCHED:{run_id}"
    )


def _poll_command(run_id: str) -> str:
    base = f"{_ASYNC_DIR}/{run_id}"
    return (
        f"if [ -f {base}.rc ]; then echo RC=$(cat {base}.rc); echo '---OUT---'; cat {base}.out; "
        f"echo '---ERR---'; tail -c 500 {base}.err 2>/dev/null; else echo RUNNING; fi"
    )


def _salvage_json(text: str) -> dict[str, Any]:
    depth, start = 0, -1
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
                    if isinstance(obj, dict):
                        return obj
                except ValueError:
                    start = -1
    return {}


# --- request models -------------------------------------------------------------------------------
class R5AsyncSubmit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_server_build_digest: str = Field(..., min_length=64, max_length=64)
    expected_registry_snapshot_digest: str = Field(..., min_length=64, max_length=64)
    expected_registry_revision: str = Field(..., min_length=6, max_length=128)
    expected_signing_key_id: str = Field(..., min_length=8, max_length=128)
    expected_base_model_digest: str = Field(..., min_length=64, max_length=64)
    expected_base_model_revision: str = Field(..., min_length=6, max_length=128)
    expected_gs343_digest: str = Field(..., min_length=64, max_length=64)
    expected_r2d2_digest: str = Field(..., min_length=64, max_length=64)
    evidence_run_id: str = Field(..., min_length=1, max_length=64)
    evidence_run_nonce: str = Field(..., min_length=16, max_length=128)
    dry_run: bool = False  # async is for the FULL run; preflight also supported for plumbing checks


async def _ensure_table() -> None:
    pool = await pg_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """CREATE TABLE IF NOT EXISTS arcanum_sdk.r5_async_runs (
                 run_id text PRIMARY KEY,
                 mode text NOT NULL,
                 status text NOT NULL DEFAULT 'RUNNING',
                 request_sha256 text,
                 identity_json jsonb NOT NULL,
                 requested_by text NOT NULL,
                 started_at timestamptz NOT NULL DEFAULT now(),
                 completed_at timestamptz,
                 result_json jsonb
               )"""
        )
        await conn.execute(
            "ALTER TABLE arcanum_sdk.r5_async_runs "
            "ADD COLUMN IF NOT EXISTS request_sha256 text"
        )


@router.post("/submit-async", summary="echo.certforge.r5.submit_async — launch a non-blocking R5 run",
             dependencies=[Depends(rate_limit)])
async def submit_async(req: R5AsyncSubmit, x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    _require_sovereign(x_echo_api_key)
    try:
        identity = core.validate_identity(req.model_dump())
        run_id = core.validate_run_id(req.evidence_run_id)
    except core.R5CoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    mode = "preflight" if req.dry_run else "full"

    request_data, request_sha256 = core.build_async_request_binding(
        identity,
        mode=mode,
        evidence_run_id=run_id,
        evidence_run_nonce=req.evidence_run_nonce,
    )
    await _ensure_table()
    pool = await pg_pool()
    async with pool.acquire() as conn:
        reserved = await conn.fetchrow(
            """INSERT INTO arcanum_sdk.r5_async_runs
                 (run_id, mode, status, request_sha256, identity_json, requested_by)
               VALUES ($1, $2, 'RESERVED', $3, $4, $5)
               ON CONFLICT (run_id) DO NOTHING
               RETURNING run_id, status, mode, request_sha256""",
            run_id,
            mode,
            request_sha256,
            json.dumps(request_data),
            "sovereign",
        )
        if reserved is None:
            existing = await conn.fetchrow(
                "SELECT run_id, status, mode, request_sha256 "
                "FROM arcanum_sdk.r5_async_runs WHERE run_id = $1",
                run_id,
            )
            decision = core.async_reservation_decision(
                existing["request_sha256"] if existing else None,
                request_sha256,
            )
            if decision == "idempotent":
                return {
                    "run_id": run_id,
                    "status": existing["status"],
                    "mode": existing["mode"],
                    "poll_capability": "echo.certforge.r5.status",
                    "idempotent": True,
                }
            raise HTTPException(
                status_code=409,
                detail="evidence_run_id already reserved for different request",
            )

    if not await _grant_active():
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": "action-broker grant not active"}),
                request_sha256,
            )
        await audit("certforge-r5-async", "grant_denied", core.GRANT_AGENT, run_id,
                    {"run_id": run_id, "mode": mode})
        raise HTTPException(status_code=403, detail="action-broker grant not active")
    if not _ASYNCSSH:
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": "asyncssh unavailable"}),
                request_sha256,
            )
        raise HTTPException(status_code=503, detail="asyncssh unavailable on FORGE")
    node = await _get_node(core.ANVIL_NODE)
    if not node:
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": "anvil node not in registry"}),
                request_sha256,
            )
        raise HTTPException(status_code=503, detail="anvil node not in registry")
    if not node.get("is_reachable_from_forge"):
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": "anvil not reachable"}),
                request_sha256,
            )
        raise HTTPException(status_code=503, detail="anvil not reachable from forge")

    operator_cmd = core.build_operator_command(
        identity,
        mode=mode,
        evidence_run_id=run_id,
        evidence_run_nonce=req.evidence_run_nonce,
    )
    launch = _launch_command(operator_cmd, run_id)
    try:
        _exit, stdout, stderr = await _ssh_run(node, launch, timeout=30.0)
    except (asyncio.TimeoutError, OSError, Exception) as exc:  # noqa: BLE001
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": f"launch_failure:{type(exc).__name__}"}),
                request_sha256,
            )
        await audit("certforge-r5-async", "launch_failure", core.GRANT_AGENT, run_id,
                    {"run_id": run_id, "mode": mode, "error": f"{type(exc).__name__}: {exc}"})
        raise HTTPException(status_code=502, detail=f"anvil launch failed: {type(exc).__name__}") from exc
    if f"LAUNCHED:{run_id}" not in stdout:
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE arcanum_sdk.r5_async_runs
                      SET status='FAILED', completed_at=now(), result_json=$2
                    WHERE run_id=$1 AND request_sha256=$3""",
                run_id,
                json.dumps({"error": "launch_not_confirmed"}),
                request_sha256,
            )
        raise HTTPException(status_code=502,
                            detail={"error": "launch_not_confirmed", "stderr_tail": stderr[-300:]})

    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE arcanum_sdk.r5_async_runs
                  SET status='RUNNING'
                WHERE run_id=$1 AND request_sha256=$2 AND status='RESERVED'""",
            run_id,
            request_sha256,
        )
    await audit("certforge-r5-async", "launched", core.GRANT_AGENT, run_id,
                {"run_id": run_id, "mode": mode})
    return {"run_id": run_id, "status": "RUNNING", "mode": mode,
            "poll_capability": "echo.certforge.r5.status"}


@router.get("/status/{run_id}", summary="echo.certforge.r5.status — poll a non-blocking R5 run",
            dependencies=[Depends(rate_limit)])
async def status(run_id: str, x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    _require_sovereign(x_echo_api_key)
    try:
        run_id = core.validate_run_id(run_id)
    except core.R5CoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await _ensure_table()
    pool = await pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM arcanum_sdk.r5_async_runs WHERE run_id = $1", run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown async run")
    if row["status"] in ("COMPLETE", "FAILED"):
        return {"run_id": run_id, "status": row["status"],
                "result": json.loads(row["result_json"]) if row["result_json"] else None}

    # still RUNNING — check ANVIL for the completion marker
    request_data = json.loads(row["identity_json"])
    identity = request_data.get("identity", request_data)
    mode = row["mode"]
    node = await _get_node(core.ANVIL_NODE)
    if not node or not node.get("is_reachable_from_forge"):
        return {"run_id": run_id, "status": "RUNNING", "note": "anvil unreachable; not yet finalizable"}
    try:
        _rc, out, _err = await _ssh_run(node, _poll_command(run_id), timeout=30.0)
    except (asyncio.TimeoutError, OSError, Exception) as exc:  # noqa: BLE001
        return {"run_id": run_id, "status": "RUNNING", "note": f"poll transport: {type(exc).__name__}"}

    if out.strip().startswith("RUNNING") or "---OUT---" not in out:
        return {"run_id": run_id, "status": "RUNNING"}

    # parse: RC=<n>\n---OUT---\n<report json>\n---ERR---\n<tail>
    header, _, rest = out.partition("---OUT---")
    exit_code = 0
    for line in header.splitlines():
        if line.startswith("RC="):
            try:
                exit_code = int(line[3:].strip())
            except ValueError:
                exit_code = 1
    report_text, _, err_tail = rest.partition("---ERR---")
    try:
        report = json.loads(report_text.strip().splitlines()[-1] if report_text.strip() else "{}")
        if not isinstance(report, dict):
            raise ValueError
    except (ValueError, IndexError):
        report = _salvage_json(report_text)

    bundle = report.get("forge_verification_bundle") or {}
    try:
        forge_verify = core.verify_forge_bundle(
            bundle,
            identity,
            mode=mode,
            expected_run_id=run_id,
            expected_run_nonce=request_data["evidence_run_nonce"],
        )
    except core.R5CoreError as exc:
        forge_verify = {"all_ok": False, "reason": str(exc), "receipts": [],
                        "identity_ok": False, "key_id_ok": False}
    result = core.assemble_result(report, forge_verify, mode=mode,
                                  exit_code=exit_code, evidence_run_id=run_id)
    result["stderr_tail"] = err_tail.strip()[-500:]
    # COMPLETE requires FORGE's independent bundle re-verification to pass — an operator that exits 0
    # with a bundle FORGE cannot verify is NOT a completed run (it is FAILED). Never call an
    # unverified run COMPLETE. (Fable review — fail-open lifecycle signal.)
    final_status = "COMPLETE" if forge_verify.get("all_ok") else "FAILED"

    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE arcanum_sdk.r5_async_runs
                 SET status = $2, result_json = $3, completed_at = now()
               WHERE run_id = $1 AND status = 'RUNNING'""",
            run_id, final_status, json.dumps(result),
        )
    await audit("certforge-r5-async", "finalized", core.GRANT_AGENT, run_id,
                {"run_id": run_id, "mode": mode, "status": final_status,
                 "r5_gate": result.get("r5_gate"), "forge_all_ok": forge_verify.get("all_ok")})
    return {"run_id": run_id, "status": final_status, "result": result}
