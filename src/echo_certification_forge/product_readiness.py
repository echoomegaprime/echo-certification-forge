"""Signed whole-product readiness attestation verification.

The service status endpoint must never infer its own readiness from deployed code or
mutable phase labels.  A production verdict is exposed only when an out-of-process
acceptance runner signs an exact-source attestation covering every required release
gate.  Missing, stale, untrusted, malformed, or partially passing attestations remain
``NOT_READY``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import parse_utc_iso, require_sha256, sha256_bytes
from .models import SignedVerdictEnvelope
from .signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

_SCHEMA_VERSION = "1.0.0"
_PRODUCT_ID = "echo-certification-forge"
_REQUIRED_GATES = (
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P6",
    "P7",
    "SDK",
    "CI",
    "MASTER",
)


@dataclass(frozen=True, slots=True)
class ProductReadinessStatus:
    """Fail-closed result returned to the public status surface."""

    release_verdict: str
    reason: str
    report_sha256: str | None = None
    source_commit: str | None = None
    generated_at: str | None = None
    expires_at: str | None = None

    @property
    def ready(self) -> bool:
        return self.release_verdict == "PRODUCTION_READY"


def create_product_readiness_envelope(
    *,
    signer: Ed25519VerdictSigner,
    source_commit: str,
    source_tree_sha256: str,
    generated_at: str,
    expires_at: str,
    gates: dict[str, dict[str, Any]],
    master_run: dict[str, Any],
) -> SignedVerdictEnvelope:
    """Create the signed final-release attestation after all gates pass.

    The function rejects incomplete evidence before signing, which prevents an
    operator from producing a syntactically valid partial readiness report.
    """
    _validate_source_commit(source_commit)
    require_sha256(source_tree_sha256, "source_tree_sha256")
    _validate_gate_map(gates)
    _validate_master_run(master_run)
    issued = parse_utc_iso(generated_at)
    expiry = parse_utc_iso(expires_at)
    if expiry <= issued:
        raise ValueError("product readiness expiry must follow generation time")
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "product_id": _PRODUCT_ID,
        "source_commit": source_commit.lower(),
        "source_tree_sha256": source_tree_sha256,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "run_outcome": "COMPLETE",
        "release_verdict": "PRODUCTION_READY",
        "completed_phase_gate": "P8C",
        "required_gates": {name: gates[name] for name in _REQUIRED_GATES},
        "master_run": master_run,
        "signing_key_id": signer.key_id,
    }
    return signer.sign_payload(payload)


def verify_product_readiness(
    report_path: Path | None,
    trusted_keys: TrustedPublicKeyRegistry,
    *,
    expected_source_commit: str | None,
    now: datetime | None = None,
) -> ProductReadinessStatus:
    """Verify a product report against trust roots and the deployed source commit."""
    if report_path is None:
        return ProductReadinessStatus("NOT_READY", "product_readiness_report_missing")
    try:
        raw_bytes = report_path.read_bytes()
        raw = json.loads(raw_bytes)
    except FileNotFoundError:
        return ProductReadinessStatus("NOT_READY", "product_readiness_report_missing")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ProductReadinessStatus("NOT_READY", "product_readiness_report_unreadable")
    if not isinstance(raw, dict):
        return ProductReadinessStatus("NOT_READY", "product_readiness_report_malformed")
    try:
        envelope = SignedVerdictEnvelope(
            payload=raw["payload"],
            signature_b64=raw["signature_b64"],
            key_id=raw["key_id"],
            public_key_pem=raw["public_key_pem"],
        )
    except (KeyError, TypeError, ValueError):
        return ProductReadinessStatus("NOT_READY", "product_readiness_report_malformed")

    verified, reason = trusted_keys.verify(envelope)
    if not verified:
        return ProductReadinessStatus("NOT_READY", f"product_readiness_{reason}")
    payload = envelope.payload
    report_sha256 = sha256_bytes(raw_bytes)
    source_commit = str(payload.get("source_commit", ""))
    generated_at = payload.get("generated_at")
    expires_at = payload.get("expires_at")
    try:
        _validate_payload(payload)
        if expected_source_commit is None:
            raise ValueError("deployed source commit is not configured")
        _validate_source_commit(expected_source_commit)
        if source_commit.lower() != expected_source_commit.lower():
            raise ValueError("product readiness source commit does not match deployment")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if parse_utc_iso(str(expires_at)) <= current:
            raise ValueError("product readiness report expired")
    except (TypeError, ValueError, KeyError):
        return ProductReadinessStatus(
            "NOT_READY",
            "product_readiness_contract_invalid",
            report_sha256,
            source_commit or None,
            str(generated_at) if generated_at else None,
            str(expires_at) if expires_at else None,
        )
    return ProductReadinessStatus(
        "PRODUCTION_READY",
        "signed_exact_source_acceptance_verified",
        report_sha256,
        source_commit,
        str(generated_at),
        str(expires_at),
    )


def _validate_payload(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("unsupported product readiness schema")
    if payload.get("product_id") != _PRODUCT_ID:
        raise ValueError("product readiness product mismatch")
    if payload.get("run_outcome") != "COMPLETE":
        raise ValueError("product readiness run is incomplete")
    if payload.get("release_verdict") != "PRODUCTION_READY":
        raise ValueError("product readiness verdict is not production ready")
    if payload.get("completed_phase_gate") != "P8C":
        raise ValueError("product readiness phase gate is incomplete")
    _validate_source_commit(str(payload["source_commit"]))
    require_sha256(str(payload["source_tree_sha256"]), "source_tree_sha256")
    generated = parse_utc_iso(str(payload["generated_at"]))
    expires = parse_utc_iso(str(payload["expires_at"]))
    if expires <= generated:
        raise ValueError("product readiness timestamps are invalid")
    gates = payload["required_gates"]
    if not isinstance(gates, dict):
        raise ValueError("required_gates must be an object")
    _validate_gate_map(gates)
    master_run = payload["master_run"]
    if not isinstance(master_run, dict):
        raise ValueError("master_run must be an object")
    _validate_master_run(master_run)


def _validate_source_commit(value: str) -> None:
    normalized = value.lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("source_commit must be a full lowercase Git SHA")


def _validate_gate_map(gates: dict[str, dict[str, Any]]) -> None:
    if set(gates) != set(_REQUIRED_GATES):
        raise ValueError("required release gates are incomplete")
    for name in _REQUIRED_GATES:
        gate = gates[name]
        if not isinstance(gate, dict) or gate.get("state") != "COMPLETE":
            raise ValueError(f"release gate {name} is incomplete")
        require_sha256(str(gate.get("evidence_sha256", "")), f"{name} evidence_sha256")


def _validate_master_run(master_run: dict[str, Any]) -> None:
    required = {
        "run_id",
        "run_outcome",
        "target_release_verdict",
        "signed_verdict_verified",
        "evidence_chain_verified",
        "sandbox_isolation",
        "requirements_passed",
        "rerun_command",
    }
    if set(master_run) != required:
        raise ValueError("master acceptance result has an invalid shape")
    if master_run["run_outcome"] != "COMPLETE":
        raise ValueError("master acceptance did not complete")
    if master_run["target_release_verdict"] != "NOT_READY":
        raise ValueError("imperfect master target was not blocked")
    if master_run["signed_verdict_verified"] is not True:
        raise ValueError("master target verdict is not independently verified")
    if master_run["evidence_chain_verified"] is not True:
        raise ValueError("master evidence chain is not verified")
    if master_run["sandbox_isolation"] != "docker":
        raise ValueError("master target did not execute in the required sandbox")
    if master_run["requirements_passed"] is not True:
        raise ValueError("master acceptance requirements did not all pass")
    if not str(master_run["run_id"]).strip() or not str(master_run["rerun_command"]).strip():
        raise ValueError("master acceptance identity and rerun command are required")
