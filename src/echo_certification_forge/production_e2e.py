"""Fail-closed validation for signed production end-to-end attestations.

Source checks, a successful process exit, and a reachable URL are not production
evidence.  This contract is evaluated by the deterministic verdict authority
after a trusted collector has signed the attestation.  Target-controlled code
cannot manufacture the attestation or select its trust key.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import sha256_json
from .models import EnvironmentIdentity, SignedVerdictEnvelope, TargetIdentity
from .signing import TrustedPublicKeyRegistry

RULE_ID = "production_e2e"
SCHEMA_VERSION = "certforge.production-e2e.v1"
GENERIC_PROFILE = "generic-production-v1"
ECHO_GITHUB_AUTONOMY_PROFILE = "echo-github-autonomy-remote-mcp-v1"
ECHO_GITHUB_AUTONOMY_REPOSITORY = "echoomegaprime/echo-github-autonomy"
ECHO_GITHUB_AUTONOMY_CANONICAL_MCP = "https://echo-ghub.grok.me/api/plugin/mcp"

BASE_CHECKS = frozenset(
    {
        "runtime_or_artifact_executed",
        "exact_identity_readback",
        "critical_journeys_complete",
        "negative_controls_pass",
        "stability_verified",
        "external_acceptance_verified",
    }
)
ECHO_GITHUB_AUTONOMY_CHECKS = BASE_CHECKS | frozenset(
    {
        "canonical_mcp_health",
        "oauth_discovery",
        "mcp_initialize",
        "tool_schema",
        "repeated_tool_invocation",
        "registry_persistence",
        "four_account_reconciliation",
        "private_public_visibility",
        "read_write_certify",
        "cross_client_consistency",
    }
)
ECHO_GITHUB_ACCOUNTS = {
    "echoomegaprime": 314902331,
    "ECHO-OMEGA-PRIME": 264607697,
    "Bmcbob76": 203470412,
    "bobmcwilliams4": 235318155,
}
ECHO_CLIENTS = frozenset({"chatgpt", "claude", "codex", "grok"})

_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SIGNING_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_SECRET_VALUE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~-]{16,})"
)
_RESTRICTED_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "authorization",
    "cookie",
    "api_key",
}
_VERIFIED_MARKER = object()


@dataclass(frozen=True, slots=True)
class VerifiedProductionE2E:
    """An attestation whose envelope was verified by an independently pinned key registry."""

    payload: dict[str, Any]
    collector_key_id: str
    envelope_sha256: str
    _marker: object

    def __post_init__(self) -> None:
        if self._marker is not _VERIFIED_MARKER:
            raise ValueError("VerifiedProductionE2E must come from signature verification")

    def result_details(self) -> dict[str, Any]:
        return {
            **self.payload,
            "signature_verified": True,
            "collector_key_id": self.collector_key_id,
            "attestation_envelope_sha256": self.envelope_sha256,
        }


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _contains_restricted_value(value: Any, *, key_name: str = "") -> bool:
    normalized = key_name.casefold().replace("-", "_")
    if normalized in _RESTRICTED_KEYS:
        return True
    if isinstance(value, Mapping):
        return any(
            _contains_restricted_value(item, key_name=str(key)) for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_restricted_value(item) for item in value)
    return isinstance(value, str) and bool(_SECRET_VALUE.search(value))


def _source_repository(target: TargetIdentity) -> str | None:
    reference = target.canonical_ref.casefold()
    marker = "github.com/"
    if marker not in reference:
        return None
    suffix = reference.split(marker, 1)[1].split("@", 1)[0]
    if suffix.endswith(".git"):
        suffix = suffix[:-4]
    return suffix


def _validate_common(
    payload: Mapping[str, Any],
    target: TargetIdentity,
    environment: EnvironmentIdentity,
    *,
    now: datetime,
) -> str | None:
    if _contains_restricted_value(payload):
        return "production_e2e_contains_restricted_value"
    if payload.get("schema_version") != SCHEMA_VERSION:
        return "production_e2e_schema_invalid"
    if not _IDENTIFIER.fullmatch(str(payload.get("attestation_id") or "")):
        return "production_e2e_attestation_id_invalid"
    if payload.get("target_identity_digest") != target.identity_digest:
        return "production_e2e_target_identity_mismatch"
    if payload.get("environment_identity_digest") != environment.identity_digest:
        return "production_e2e_environment_identity_mismatch"
    if not _SIGNING_KEY_ID.fullmatch(str(payload.get("signing_key_id") or "")):
        return "production_e2e_signing_key_id_invalid"

    observed_at = _parse_time(payload.get("observed_at"))
    expires_at = _parse_time(payload.get("expires_at"))
    current = now.astimezone(UTC) if now.tzinfo is not None else None
    if current is None or observed_at is None or expires_at is None:
        return "production_e2e_time_invalid"
    if expires_at <= observed_at or (expires_at - observed_at).total_seconds() > 3600:
        return "production_e2e_lifetime_invalid"
    if observed_at > current or current >= expires_at:
        return "production_e2e_attestation_not_current"

    source_commit = payload.get("source_commit")
    deployment_sha = payload.get("deployment_sha")
    if target.source_commit is not None:
        expected = target.source_commit.casefold()
        if not _SHA.fullmatch(expected):
            return "production_e2e_target_source_commit_not_exact"
        if source_commit != expected or deployment_sha != expected:
            return "production_e2e_deployment_sha_mismatch"
    elif source_commit is not None or deployment_sha is not None:
        if source_commit != deployment_sha or not _SHA.fullmatch(str(source_commit)):
            return "production_e2e_deployment_sha_invalid"

    required_checks = payload.get("required_checks")
    checks = payload.get("checks")
    if not isinstance(required_checks, list) or not isinstance(checks, Mapping):
        return "production_e2e_checks_invalid"
    if len(required_checks) != len(set(required_checks)):
        return "production_e2e_checks_duplicated"
    check_set = frozenset(required_checks)
    if set(checks) != set(check_set) or any(checks.get(name) is not True for name in check_set):
        return "production_e2e_checks_incomplete"
    if not BASE_CHECKS <= check_set:
        return "production_e2e_baseline_checks_missing"
    if not isinstance(payload.get("stability_probe_count"), int) or payload["stability_probe_count"] < 3:
        return "production_e2e_stability_probe_count_insufficient"
    return None


def _validate_echo_github_autonomy(payload: Mapping[str, Any]) -> str | None:
    if payload.get("canonical_target") != ECHO_GITHUB_AUTONOMY_CANONICAL_MCP:
        return "production_e2e_canonical_mcp_mismatch"
    if frozenset(payload.get("required_checks") or ()) != ECHO_GITHUB_AUTONOMY_CHECKS:
        return "production_e2e_github_autonomy_checks_incomplete"
    if payload.get("tool_count") != 30:
        return "production_e2e_tool_count_mismatch"

    repositories = payload.get("sample_private_repositories")
    if not isinstance(repositories, Mapping) or set(repositories) != set(ECHO_GITHUB_ACCOUNTS):
        return "production_e2e_sample_repositories_incomplete"
    sample_digests: dict[str, str] = {}
    for login, sample in repositories.items():
        if not isinstance(sample, Mapping):
            return "production_e2e_sample_repository_invalid"
        if (
            not isinstance(sample.get("repository_id"), int)
            or isinstance(sample["repository_id"], bool)
            or sample["repository_id"] <= 0
        ):
            return "production_e2e_sample_repository_id_invalid"
        if not str(sample.get("node_id") or "").strip():
            return "production_e2e_sample_node_id_invalid"
        if not str(sample.get("default_branch") or "").strip():
            return "production_e2e_sample_default_branch_invalid"
        if not _SHA.fullmatch(str(sample.get("head_sha") or "")):
            return "production_e2e_sample_head_sha_invalid"
        digest = str(sample.get("fingerprint_sha256") or "")
        if not _SHA256.fullmatch(digest):
            return "production_e2e_sample_fingerprint_invalid"
        sample_digests[login] = digest

    accounts = payload.get("accounts")
    if not isinstance(accounts, Mapping) or set(accounts) != set(ECHO_GITHUB_ACCOUNTS):
        return "production_e2e_accounts_incomplete"
    for login, account_id in ECHO_GITHUB_ACCOUNTS.items():
        account = accounts.get(login)
        if not isinstance(account, Mapping) or account.get("account_id") != account_id:
            return "production_e2e_account_identity_mismatch"
        counts = (
            account.get("enumerated_count"),
            account.get("upstream_total_count"),
            account.get("public_count"),
            account.get("private_count"),
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            return "production_e2e_account_counts_invalid"
        if counts[0] != counts[1] or counts[2] <= 0 or counts[3] <= 0:
            return "production_e2e_account_reconciliation_failed"
        if any(account.get(name) is not True for name in ("read", "write", "certify")):
            return "production_e2e_account_authority_incomplete"
        if account.get("credential_source") not in {
            "github_app_installation",
            "vault_user_token_fallback",
        }:
            return "production_e2e_credential_source_invalid"
        if account.get("secret_exposed") is not False:
            return "production_e2e_secret_boundary_failed"

    clients = payload.get("clients")
    if not isinstance(clients, Mapping) or set(clients) != set(ECHO_CLIENTS):
        return "production_e2e_clients_incomplete"
    for client in clients.values():
        if not isinstance(client, Mapping) or client.get("accepted") is not True:
            return "production_e2e_client_not_accepted"
        fingerprints = client.get("repository_fingerprints")
        if not isinstance(fingerprints, Mapping) or dict(fingerprints) != sample_digests:
            return "production_e2e_cross_client_repository_mismatch"
    return None


def validate_production_e2e(
    payload: Mapping[str, Any] | None,
    target: TargetIdentity,
    environment: EnvironmentIdentity,
    *,
    now: datetime,
) -> tuple[bool, str]:
    """Validate one trusted-collector payload against the exact run identities."""

    if not isinstance(payload, Mapping):
        return False, "production_e2e_attestation_missing"
    error = _validate_common(payload, target, environment, now=now)
    if error is not None:
        return False, error
    repository = _source_repository(target)
    profile = payload.get("profile")
    if repository == ECHO_GITHUB_AUTONOMY_REPOSITORY:
        if profile != ECHO_GITHUB_AUTONOMY_PROFILE:
            return False, "production_e2e_profile_mismatch"
        error = _validate_echo_github_autonomy(payload)
        return (error is None, error or "production_e2e_verified")
    if profile != GENERIC_PROFILE:
        return False, "production_e2e_profile_mismatch"
    if frozenset(payload.get("required_checks") or ()) != BASE_CHECKS:
        return False, "production_e2e_generic_checks_incomplete"
    return True, "production_e2e_verified"


def validate_attestation_trust_metadata(payload: Mapping[str, Any]) -> tuple[bool, str]:
    """Require the signature-verification metadata added by ``VerifiedProductionE2E``."""

    if payload.get("signature_verified") is not True:
        return False, "production_e2e_signature_not_verified"
    if payload.get("collector_key_id") != payload.get("signing_key_id"):
        return False, "production_e2e_collector_key_mismatch"
    if not _SIGNING_KEY_ID.fullmatch(str(payload.get("collector_key_id") or "")):
        return False, "production_e2e_collector_key_invalid"
    if not _SHA256.fullmatch(str(payload.get("attestation_envelope_sha256") or "")):
        return False, "production_e2e_envelope_sha256_invalid"
    return True, "production_e2e_signature_verified"


def verify_signed_attestation(
    envelope: SignedVerdictEnvelope,
    trusted_keys: TrustedPublicKeyRegistry,
) -> VerifiedProductionE2E:
    """Verify one collector envelope against an independently selected key registry."""

    verified, reason = trusted_keys.verify(envelope)
    if not verified:
        raise ValueError(f"production E2E attestation is not trusted: {reason}")
    if envelope.payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("production E2E attestation schema is unsupported")
    if envelope.payload.get("signing_key_id") != envelope.key_id:
        raise ValueError("production E2E attestation key binding is invalid")
    envelope_sha256 = sha256_json(
        {
            "payload": envelope.payload,
            "signature_b64": envelope.signature_b64,
            "key_id": envelope.key_id,
        }
    )
    return VerifiedProductionE2E(
        payload=dict(envelope.payload),
        collector_key_id=envelope.key_id,
        envelope_sha256=envelope_sha256,
        _marker=_VERIFIED_MARKER,
    )


def load_signed_attestation(path: Path, trusted_key_directory: Path) -> VerifiedProductionE2E:
    """Load and independently verify a collector envelope using pinned public keys."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        envelope = SignedVerdictEnvelope(
            payload=dict(document["payload"]),
            signature_b64=str(document["signature_b64"]),
            key_id=str(document["key_id"]),
            public_key_pem=str(document.get("public_key_pem") or ""),
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("production E2E attestation envelope is invalid") from exc
    registry = TrustedPublicKeyRegistry.from_directory(trusted_key_directory)
    return verify_signed_attestation(envelope, registry)
