"""Environment-configured P3 service runtime used by deployment and acceptance."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from .anchor import IndependentFileAnchorProvider
from .custody import CustodyStore
from .p3_service import (
    AnchorServiceContext,
    CustodyServiceContext,
    create_anchor_app,
    create_custody_app,
)
from .runner import RunnerStore, TrustedTransportRegistry


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


def build_app() -> FastAPI:
    mode = _required("ECHO_CERTFORGE_P3_MODE")
    if mode == "custody":
        registry = TrustedTransportRegistry.empty()
        registry.add_pem(Path(_required("ECHO_CERTFORGE_TRANSPORT_PUBLIC_KEY")).read_text(encoding="ascii"))
        runner_store = RunnerStore(Path(_required("ECHO_CERTFORGE_RUNNER_DB")))
        custody = CustodyStore(
            Path(_required("ECHO_CERTFORGE_CUSTODY_DB")),
            Path(_required("ECHO_CERTFORGE_CUSTODY_ROOT")),
            runner_store,
            registry,
        )
        return create_custody_app(CustodyServiceContext(custody))
    if mode == "anchor":
        provider = IndependentFileAnchorProvider.from_private_pem(
            Path(_required("ECHO_CERTFORGE_ANCHOR_ROOT")),
            _required("ECHO_CERTFORGE_ANCHOR_PROVIDER_ID"),
            Path(_required("ECHO_CERTFORGE_ANCHOR_PRIVATE_KEY")).read_bytes(),
        )
        return create_anchor_app(AnchorServiceContext(provider))
    raise RuntimeError(f"unsupported P3 runtime mode: {mode}")


app = build_app()
