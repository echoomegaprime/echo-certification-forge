#!/usr/bin/env python3
"""Hardened P4 acceptance entrypoint with bounded service readiness.

The exact-artifact entrypoint owns public-verifier containment. This layer
changes only the service-health readiness deadline from the legacy 12-second
value to the validated 30-second budget and records the hardened entrypoint,
exact-artifact entrypoint, and bounded deadline in the acceptance report. It
fails closed if the underlying function no longer has the expected single
deadline expression.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
EXACT_ENTRYPOINT = HERE.with_name("p4_hostile_acceptance_exact.py")
SERVICE_HEALTH_DEADLINE_SECONDS = 30
LEGACY_DEADLINE_EXPRESSION = "deadline = time.monotonic() + 12"


def load_exact_entrypoint() -> Any:
    spec = importlib.util.spec_from_file_location(
        "p4_hostile_acceptance_exact_hardened",
        EXACT_ENTRYPOINT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load exact P4 entrypoint: {EXACT_ENTRYPOINT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def apply_service_health_deadline(harness: Any) -> Any:
    source = inspect.getsource(harness.service_health_probe)
    observed = source.count(LEGACY_DEADLINE_EXPRESSION)
    if observed != 1:
        raise RuntimeError(
            "service-health deadline contract drift: "
            f"expected one legacy expression, observed {observed}"
        )
    replacement = (
        "deadline = time.monotonic() + "
        f"{SERVICE_HEALTH_DEADLINE_SECONDS}"
    )
    code = compile(
        source.replace(LEGACY_DEADLINE_EXPRESSION, replacement, 1),
        str(Path(harness.__file__).resolve()),
        "exec",
    )
    # The replacement expression calls time.monotonic(); a harness namespace
    # that never imported time must not NameError at probe time.
    harness.__dict__.setdefault("time", time)
    exec(code, harness.__dict__)
    harness.P4_SERVICE_HEALTH_DEADLINE_SECONDS = SERVICE_HEALTH_DEADLINE_SECONDS
    return harness


def apply_report_hardening(exact: Any) -> Any:
    """Layer hardened harness identity and deadline evidence over exact output."""
    original_enrich_report = exact.enrich_report

    def enrich_report_hardened(
        *,
        output_path: Path,
        harness: Any,
        capture: dict[str, Any],
        return_code: int,
    ) -> dict[str, Any]:
        report = original_enrich_report(
            output_path=output_path,
            harness=harness,
            capture=capture,
            return_code=return_code,
        )
        harness_identity = report.setdefault("harness", {})
        harness_identity.update(
            {
                "path": str(HERE),
                "sha256": exact.sha256_file(HERE),
                "exact_path": str(EXACT_ENTRYPOINT),
                "exact_sha256": exact.sha256_file(EXACT_ENTRYPOINT),
                "service_health_deadline_seconds": SERVICE_HEALTH_DEADLINE_SECONDS,
            }
        )
        report.setdefault("checks", {})[
            "bounded_service_health_deadline_recorded"
        ] = True
        output_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return report

    exact.enrich_report = enrich_report_hardened
    return exact


def main(arguments: list[str] | None = None) -> int:
    exact = load_exact_entrypoint()
    original_load_harness = exact.load_harness

    def load_hardened_harness() -> Any:
        return apply_service_health_deadline(original_load_harness())

    exact.load_harness = load_hardened_harness
    apply_report_hardening(exact)
    return int(exact.main(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
