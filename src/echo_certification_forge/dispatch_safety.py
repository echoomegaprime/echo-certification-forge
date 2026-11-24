"""Lightweight dispatcher safety helpers (no heavy product imports).

Keeps incident #9676 guards importable in unit tests and partial overlays.
"""
from __future__ import annotations

from typing import Any, Callable


def safe_reconcile_dispatch_outbox(governance: Any) -> dict[str, int] | None:
    """Call reconcile_dispatch_outbox when present (overlay vs product skew safe).

    Live product package may lag SYSTEMS overlay methods. Calling a missing
    method caused AttributeError restart storms (incident #9676 follow-on).
    """
    reconcile = getattr(governance, "reconcile_dispatch_outbox", None)
    if not callable(reconcile):
        return None
    result = reconcile()
    return result if isinstance(result, dict) else {"ok": 1}


def safe_dispatch_queue_stats(governance: Any) -> dict[str, Any]:
    stats_fn = getattr(governance, "dispatch_queue_stats", None)
    if not callable(stats_fn):
        return {}
    try:
        stats = stats_fn()
    except Exception as exc:  # noqa: BLE001 — telemetry only; never kill loop
        return {"stats_error": type(exc).__name__}
    return stats if isinstance(stats, dict) else {}


def is_callable_attr(obj: Any, name: str) -> bool:
    return callable(getattr(obj, name, None))


__all__ = [
    "safe_reconcile_dispatch_outbox",
    "safe_dispatch_queue_stats",
    "is_callable_attr",
]
