"""Secret-safe public identity projections committed by signed verdicts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from .production_e2e import canonical_public_https_target

_PUBLIC_E2E_FIELDS = frozenset(
    {
        "schema_version",
        "attestation_id",
        "profile",
        "target_identity_digest",
        "environment_identity_digest",
        "source_commit",
        "deployment_sha",
        "canonical_target",
        "required_checks",
        "checks",
        "stability_probe_count",
        "tool_count",
        "account_count",
        "client_count",
        "upstream_reconciled",
        "private_public_visible",
        "read_write_certify",
        "registry_persistent",
        "oauth_verified",
        "ledger_integrity",
        "sharing_verified",
        "import_verified",
        "read_write_continuity",
        "observed_at",
        "expires_at",
        "signing_key_id",
        "signature_verified",
        "collector_key_id",
        "attestation_envelope_sha256",
    }
)


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _safe_github_repository(canonical_ref: object) -> str | None:
    if not isinstance(canonical_ref, str) or len(canonical_ref) > 2048:
        return None
    try:
        parsed = urlsplit(canonical_ref)
        port = parsed.port
    except (ValueError, UnicodeError):
        return None
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold() != "github.com"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    repository = parsed.path.strip("/").split("@", 1)[0].removesuffix(".git")
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return f"{parts[0]}/{parts[1]}"


def public_target_identity(target: Mapping[str, Any]) -> dict[str, Any]:
    """Return only source facts safe for an unauthenticated public verifier."""

    projection: dict[str, Any] = {
        "target_type": str(target.get("target_type") or "")[:128],
        "artifact_sha256": target.get("artifact_sha256"),
        "source_commit": target.get("source_commit"),
    }
    repository = _safe_github_repository(target.get("canonical_ref"))
    if repository is not None:
        projection["repository"] = repository
    return projection


def public_production_e2e_identity(details: Mapping[str, Any]) -> dict[str, Any]:
    """Expose signed aggregate proof without repository or credential details."""

    projection = {
        key: _json_copy(value)
        for key, value in details.items()
        if key in _PUBLIC_E2E_FIELDS
    }
    checks = details.get("checks")
    safe_checks = checks if isinstance(checks, Mapping) else {}
    accounts = details.get("accounts")
    account_values = list(accounts.values()) if isinstance(accounts, Mapping) else []
    clients = details.get("clients")
    projection.update(
        {
            "account_count": len(accounts) if isinstance(accounts, Mapping) else None,
            "client_count": len(clients) if isinstance(clients, Mapping) else None,
            "upstream_reconciled": bool(account_values)
            and all(
                isinstance(item, Mapping)
                and item.get("enumerated_count") == item.get("upstream_total_count")
                for item in account_values
            ),
            "private_public_visible": bool(account_values)
            and all(
                isinstance(item, Mapping)
                and isinstance(item.get("public_count"), int)
                and not isinstance(item.get("public_count"), bool)
                and item["public_count"] > 0
                and isinstance(item.get("private_count"), int)
                and not isinstance(item.get("private_count"), bool)
                and item["private_count"] > 0
                for item in account_values
            ),
            "read_write_certify": bool(account_values)
            and all(
                isinstance(item, Mapping)
                and all(item.get(name) is True for name in ("read", "write", "certify"))
                for item in account_values
            ),
            "registry_persistent": safe_checks.get("registry_persistence") is True,
            "oauth_verified": safe_checks.get("oauth_discovery") is True,
            "ledger_integrity": safe_checks.get("ledger_integrity") is True,
            "sharing_verified": safe_checks.get("sharing") is True,
            "import_verified": safe_checks.get("import") is True,
            "read_write_continuity": safe_checks.get("read_write_continuity") is True,
        }
    )
    canonical_target = projection.get("canonical_target")
    normalized_target = canonical_public_https_target(canonical_target)
    if normalized_target is None:
        projection.pop("canonical_target", None)
    else:
        projection["canonical_target"] = normalized_target
    return projection
