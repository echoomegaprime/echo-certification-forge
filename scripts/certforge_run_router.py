"""/sdk/certification-forge/run — trigger an existing governed subscriber run.

The subscriber intake API owns run identity, reservation, metering, and the transactional outbox.
This gate route accepts only that returned run ID and confirms it for the always-on dispatcher. It
never creates a second identity or bypasses subscriber governance.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from routers._common import audit, rate_limit

router = APIRouter(prefix="/sdk/certification-forge", tags=["certification-forge-run"])

_SOVEREIGN_KEY_FILE = "/home/forge/.echo_sovereign_key"
_REPO = "/home/forge/echo-certification-forge"
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


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


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(min_length=1, max_length=128)
    tenant: str = Field(min_length=1, max_length=128)


@router.post(
    "/run",
    summary="echo.certforge.run — dispatch an existing governed subscriber run",
    dependencies=[Depends(rate_limit)],
)
async def certforge_run(
    req: RunRequest, x_echo_api_key: str | None = Header(None)
) -> dict[str, Any]:
    _require_sovereign(x_echo_api_key)
    if not _RUN_ID_RE.fullmatch(req.run_id) or not _RUN_ID_RE.fullmatch(req.tenant):
        raise HTTPException(status_code=400, detail="invalid run or tenant identifier")

    db_path = Path(f"{_REPO}/var/certforge.sqlite3")
    try:
        with sqlite3.connect(db_path) as connection:
            row = connection.execute(
                """
                SELECT state FROM subscriber_run_dispatches
                WHERE run_id = ? AND organization_id = ?
                """,
                (req.run_id, req.tenant),
            ).fetchone()
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=503,
            detail=f"subscriber dispatch store unavailable:{type(exc).__name__}",
        ) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="governed run dispatch not found")
    if str(row[0]) not in {"PENDING", "CLAIMED"}:
        raise HTTPException(status_code=409, detail=f"dispatch is {row[0]}")

    await audit(
        "certforge-run",
        "outbox-confirmed",
        "certforge-run",
        req.run_id,
        {"run_id": req.run_id, "tenant": req.tenant, "sandboxed": True},
    )
    return {
        "run_id": req.run_id,
        "status": str(row[0]),
        "tenant": req.tenant,
        "sandboxed": True,
        "poll_capability": "echo.certforge.status",
    }
