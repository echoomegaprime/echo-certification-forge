"""/sdk/certification-forge/run — self-service certification of an (untrusted) target.

Gate-triggered full certification. Sovereign-authenticated. Launches the KEY-HOLDING run-worker
DETACHED on FORGE with the isolated Docker sandbox enabled (``--sandbox``), so the target's critical
journey executes only inside a locked-down container (no host escape) while the trusted orchestration
(acquire → scan → sign) runs on the host and never executes target code. Returns a run_id
immediately; poll with the existing ``echo.certforge.status`` cap (the worker writes the shared store).

Additive router (auto-mounted). Does NOT modify the read API or the R5 routers.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from routers._common import audit, rate_limit
from echo_certification_forge.production_launch import production_worker_args

router = APIRouter(prefix="/sdk/certification-forge", tags=["certification-forge-run"])

_SOVEREIGN_KEY_FILE = "/home/forge/.echo_sovereign_key"
_REPO = "/home/forge/echo-certification-forge"
_VENV_PY = f"{_REPO}/.venv/bin/python"
_RUN_OUT_DIR = f"{_REPO}/var/run-output"
_TENANT = "echo-sovereign"  # the sovereign gate tenant (matches echo.certforge.* static X-Tenant-ID)
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_POLICY_ID = "certforge.release-strict.v2"
_POLICY_PATH = f"{_REPO}/policies/mandatory-rules.v2.json"


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


class RunTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(pattern=r"^(git|local)$")
    url: str | None = Field(default=None, max_length=2048)
    path: str | None = Field(default=None, max_length=2048)
    ref: str | None = Field(default=None, max_length=256)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: RunTarget
    journey: list[str] | None = Field(default=None, max_length=32)
    policy_version: str | None = Field(default=None, max_length=128)


@router.post("/run", summary="echo.certforge.run — certify an (untrusted) target in the sandbox",
             dependencies=[Depends(rate_limit)])
async def certforge_run(req: RunRequest, x_echo_api_key: str | None = Header(None)) -> dict[str, Any]:
    _require_sovereign(x_echo_api_key)

    target = req.target.model_dump(exclude_none=True)
    if req.target.type == "git" and not req.target.url:
        raise HTTPException(status_code=400, detail="git target requires url")
    if req.target.type == "local" and not req.target.path:
        raise HTTPException(status_code=400, detail="local target requires path")
    if req.journey is not None and not all(isinstance(x, str) and x for x in req.journey):
        raise HTTPException(status_code=400, detail="journey must be a non-empty list of strings")
    if req.policy_version not in (None, _POLICY_ID):
        raise HTTPException(
            status_code=400,
            detail=f"production certification requires policy {_POLICY_ID}",
        )
    adapter_response = os.environ.get(
        "ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE",
        f"{_REPO}/var/p5/adapter-bundle-response.json",
    )
    adapter_policy = os.environ.get(
        "ECHO_CERTFORGE_PROD_ADAPTER_POLICY",
        f"{_REPO}/var/p5/adapter-policy.json",
    )
    adapter_registry = os.environ.get(
        "ECHO_CERTFORGE_ADAPTER_REGISTRY",
        f"{_REPO}/var/p5/trusted-adapter-registry.json",
    )
    adapter_runner_signing_key = os.environ.get(
        "ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY",
        f"{_REPO}/var/p5/adapter-runner-signing-key.pem",
    )
    missing = [
        path
        for path in (
            adapter_response,
            adapter_policy,
            adapter_registry,
            adapter_runner_signing_key,
            _POLICY_PATH,
        )
        if not Path(path).is_file()
    ]
    if missing:
        raise HTTPException(
            status_code=503,
            detail={"error": "production_adapter_inputs_unavailable", "missing": missing},
        )

    seed = f"{target}|{req.journey}|{time.time_ns()}".encode("utf-8")
    run_id = "cert_run_" + hashlib.sha256(seed).hexdigest()[:40]
    if not _RUN_ID_RE.fullmatch(run_id):  # defensive; the charset is fixed
        raise HTTPException(status_code=500, detail="run_id generation error")

    argv = [
        _VENV_PY,
        "-m",
        "echo_certification_forge.run_worker",
        *production_worker_args(
            run_id=run_id,
            tenant=_TENANT,
            target=target,
            journey=req.journey,
            policy_id=_POLICY_ID,
            adapter_response=Path(adapter_response),
            adapter_policy=Path(adapter_policy),
            adapter_registry=Path(adapter_registry),
            adapter_runner_signing_key=Path(adapter_runner_signing_key),
        ),
    ]
    env = {
        **os.environ,
        "ECHO_CERTFORGE_DB": f"{_REPO}/var/certforge.sqlite3",
        "ECHO_CERTFORGE_EVIDENCE_ROOT": f"{_REPO}/var/evidence",
        "ECHO_CERTFORGE_POLICY": _POLICY_PATH,
        "ECHO_CERTFORGE_TRUSTED_KEYS": f"{_REPO}/var/trusted-public-keys",
        "ECHO_CERTFORGE_RUN_SIGNING_KEY": f"{_REPO}/var/run-signing-key.pem",
        "ECHO_CERTFORGE_ENTITLED_TENANTS": _TENANT,
        "ECHO_CERTFORGE_SANDBOX_DOCKER": "docker",
        "ECHO_CERTFORGE_ADAPTER_REGISTRY": adapter_registry,
        "ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY": adapter_runner_signing_key,
    }

    Path(_RUN_OUT_DIR).mkdir(parents=True, exist_ok=True)
    out_path = Path(_RUN_OUT_DIR) / f"{run_id}.out"
    try:
        out_fd = open(out_path, "wb")  # noqa: SIM115 — handed to the detached child
        # No shell: argv is passed directly (no injection surface). start_new_session detaches the
        # worker so it survives gate-worker recycling; its output goes to a file, not our pipes.
        await asyncio.create_subprocess_exec(
            *argv, cwd=_REPO, env=env, stdout=out_fd, stderr=out_fd,
            stdin=asyncio.subprocess.DEVNULL, start_new_session=True,
        )
    except OSError as exc:
        raise HTTPException(status_code=502, detail=f"run-worker launch failed: {type(exc).__name__}") from exc

    await audit("certforge-run", "launched", "certforge-run", run_id,
                {"run_id": run_id, "target_type": req.target.type, "sandboxed": True})
    return {
        "run_id": run_id, "status": "RUNNING", "tenant": _TENANT, "sandboxed": True,
        "poll_capability": "echo.certforge.status",
    }
