"""Pure, dependency-light core for the R5 negative-control SDK capability.

This module holds every piece of R5 governance logic that can be verified in
isolation — identity validation, fixed-command construction, independent
FORGE-side receipt verification, and result assembly. It imports NOTHING from
echo-worker-server, so the unit suite runs standalone. The FastAPI/DB/SSH
wiring lives in ``certification_forge_r5_router.py`` and calls into here.

Security posture (fail-closed):
  * The caller supplies ONLY expected identity digests + an evidence run id.
    No shell, script path, URL, adapter name, key, or maintenance token is ever
    accepted — the request model forbids extra fields and the command is built
    from a FIXED template over already-validated identity values.
  * FORGE re-verifies every Ed25519 receipt itself; the ANVIL operator's
    self-report is never trusted as proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# --- fixed governance constants (never caller-supplied) -------------------
GRANT_AGENT = "chatgpt-echo-connector"
GRANT_TASK = "echo-certification-forge-r5"
GRANT_SCOPE = "exec.shell"

ANVIL_NODE = "anvil"
OPERATOR_PATH = "/home/anvil/echo_certification_forge/family_r5_operator.py"
EVIDENCE_ROOT = "/home/anvil/echo_certification_forge/evidence"
TARGET_MODEL = "echo-gs343"
WRONG_MODEL = "echo-r2d2"
LOOPBACK_URL = "http://127.0.0.1:8200"  # informational; the operator enforces it

RECEIPT_SCHEMA = "echo.family-routing-receipt/v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_RE = re.compile(r"^ed25519:[0-9a-f]{32}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REV_RE = re.compile(r"^[0-9a-fA-F]{6,128}$")

# Identity fields the caller MUST supply (mapped to operator CLI flags).
_IDENTITY_FIELDS = (
    ("expected_server_build_digest", "server_build_digest", "sha256"),
    ("expected_registry_snapshot_digest", "registry_snapshot_digest", "sha256"),
    ("expected_registry_revision", "registry_revision", "rev"),
    ("expected_signing_key_id", "signature_key_id", "keyid"),
    ("expected_base_model_digest", "base_model_digest", "sha256"),
    ("expected_base_model_revision", "base_model_revision", "rev"),
    ("expected_gs343_digest", "target_adapter_digest", "sha256"),
    ("expected_r2d2_digest", "wrong_adapter_digest", "sha256"),
)


class R5CoreError(ValueError):
    """A structured R5 governance/validation requirement failed."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _check(kind: str, value: str, field: str) -> str:
    if not isinstance(value, str):
        raise R5CoreError(f"{field} must be a string")
    if kind == "sha256":
        v = value.lower()
        if not _SHA256_RE.fullmatch(v):
            raise R5CoreError(f"{field} must be a 64-char lowercase sha256 hex")
        return v
    if kind == "keyid":
        if not _KEY_RE.fullmatch(value):
            raise R5CoreError(f"{field} must look like 'ed25519:<32 hex>'")
        return value
    if kind == "rev":
        if not _REV_RE.fullmatch(value):
            raise R5CoreError(f"{field} must be a 6-128 char hex revision")
        return value
    raise R5CoreError(f"unknown validator kind {kind!r}")


def validate_identity(payload: Mapping[str, Any]) -> dict[str, str]:
    """Validate + normalise every caller-supplied identity value. Returns a dict
    keyed by the operator CLI flag name (without the leading ``--``)."""
    out: dict[str, str] = {}
    for req_field, cli_field, kind in _IDENTITY_FIELDS:
        if req_field not in payload:
            raise R5CoreError(f"missing required field: {req_field}")
        out[cli_field] = _check(kind, payload[req_field], req_field)
    if out["target_adapter_digest"] == out["wrong_adapter_digest"]:
        raise R5CoreError("gs343 and r2d2 digests must differ")
    return out


def validate_run_id(evidence_run_id: Any) -> str:
    if not isinstance(evidence_run_id, str) or not _RUN_ID_RE.fullmatch(evidence_run_id):
        raise R5CoreError("evidence_run_id must match [A-Za-z0-9._-]{1,64}")
    return evidence_run_id


def build_operator_command(
    identity: Mapping[str, str],
    *,
    mode: str,
    evidence_run_id: str,
    operator_path: str = OPERATOR_PATH,
    evidence_root: str = EVIDENCE_ROOT,
) -> str:
    """Build the FIXED, fully-quoted operator invocation. Every argument is a
    pre-validated identity value or a fixed constant — there is no path from a
    caller string into an unquoted shell position."""
    if mode not in {"full", "preflight"}:
        raise R5CoreError("mode must be 'full' or 'preflight'")
    run_id = validate_run_id(evidence_run_id)
    identity = validate_identity_reverse(identity)  # revalidate the flag-keyed dict
    evidence_dir = f"{evidence_root.rstrip('/')}/{run_id}"
    argv = [
        "python3", operator_path,
        "--mode", mode,
        "--target-model", TARGET_MODEL,
        "--wrong-model", WRONG_MODEL,
        "--evidence-directory", evidence_dir,
    ]
    for _req, cli_field, _kind in _IDENTITY_FIELDS:
        argv.extend([f"--{cli_field.replace('_', '-')}", identity[cli_field]])
    return " ".join(shlex.quote(a) for a in argv)


def validate_identity_reverse(identity: Mapping[str, str]) -> dict[str, str]:
    """Revalidate a flag-keyed identity dict (defence in depth before it reaches
    a command line)."""
    out: dict[str, str] = {}
    for _req, cli_field, kind in _IDENTITY_FIELDS:
        if cli_field not in identity:
            raise R5CoreError(f"identity missing {cli_field}")
        out[cli_field] = _check(kind, identity[cli_field], cli_field)
    return out


def _load_public_key(pem: Any) -> Ed25519PublicKey:
    if not isinstance(pem, str):
        raise R5CoreError("bundle lacks public_key_pem")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise R5CoreError("invalid public_key_pem") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise R5CoreError("attested key is not Ed25519")
    return key


def _derive_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519:{sha256_bytes(raw)[:32]}"


def verify_forge_bundle(
    bundle: Mapping[str, Any],
    identity: Mapping[str, str],
    *,
    mode: str,
) -> dict[str, Any]:
    """Independent FORGE-side verification of the operator's evidence bundle.

    Re-derives the key id from the attested PEM, checks it equals the expected
    signing key id AND the attested key id, checks every attested identity digest
    equals what the caller expected, and (full mode) re-verifies each negative
    control's Ed25519 signature over its canonical payload. Never trusts the
    operator's own pass/fail claim."""
    ident = validate_identity_reverse(identity)
    problems: list[str] = []
    if not isinstance(bundle, Mapping):
        return {"all_ok": False, "identity_ok": False, "key_id_ok": False,
                "receipts": [], "reason": "bundle missing"}

    key = _load_public_key(bundle.get("public_key_pem"))
    derived = _derive_key_id(key)
    expected_kid = ident["signature_key_id"]
    key_id_ok = derived == expected_kid and bundle.get("attested_key_id") == expected_kid
    if not key_id_ok:
        problems.append("key_id mismatch")

    attested = {
        "server_build_digest": bundle.get("attested_server_build_digest"),
        "registry_snapshot_digest": bundle.get("attested_registry_snapshot_digest"),
        "registry_revision": bundle.get("attested_registry_revision"),
        "base_model_digest": bundle.get("attested_base_model_digest"),
        "base_model_revision": bundle.get("attested_base_model_revision"),
    }
    identity_ok = all(attested[name] == ident[name] for name in attested)
    if not identity_ok:
        problems.append("attested identity mismatch")

    receipt_results: list[dict[str, Any]] = []
    if mode == "full":
        receipts = bundle.get("receipts")
        if not isinstance(receipts, list) or len(receipts) != 2:
            problems.append("expected exactly two control receipts")
            receipts = receipts if isinstance(receipts, list) else []
        for entry in receipts:
            control = entry.get("control") if isinstance(entry, Mapping) else None
            sig_ok = False
            kid_ok = False
            try:
                payload = entry["payload"]
                signature = entry["signature_b64"]
                kid_ok = (entry.get("key_id") == expected_kid
                          and payload.get("signature_key_id") == expected_kid)
                key.verify(base64.b64decode(signature, validate=True),
                           canonical_json(payload).encode())
                sig_ok = True
            except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError):
                sig_ok = False
            receipt_results.append(
                {"control": control, "signature_ok": sig_ok, "key_id_ok": kid_ok})
            if not (sig_ok and kid_ok):
                problems.append(f"receipt {control} failed verification")

    all_ok = key_id_ok and identity_ok and (
        mode == "preflight"
        or (len(receipt_results) == 2
            and all(r["signature_ok"] and r["key_id_ok"] for r in receipt_results)))
    return {
        "all_ok": all_ok,
        "identity_ok": identity_ok,
        "key_id_ok": key_id_ok,
        "derived_key_id": derived,
        "receipts": receipt_results,
        "reason": None if all_ok else "; ".join(problems) or "verification failed",
    }


_REDACT_KEYS = {"lease_token", "token", "authorization", "public_key_pem",
                "x-echo-maintenance-lease", "x-echo-api-key"}


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if str(k).lower() in _REDACT_KEYS else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def assemble_result(
    report: Mapping[str, Any],
    forge_verify: Mapping[str, Any],
    *,
    mode: str,
    exit_code: int,
    evidence_run_id: str,
) -> dict[str, Any]:
    """Produce the final redacted, metadata-only capability result. The gate
    verdict is the AND of: operator report, exit status, and FORGE's own
    independent verification — release stays NOT_READY regardless."""
    operator_gate = report.get("r5_gate")
    operator_outcome = report.get("run_outcome")
    forge_ok = bool(forge_verify.get("all_ok"))

    if mode == "preflight":
        passed = exit_code == 0 and operator_outcome == "PREFLIGHT_OK" and forge_ok
        run_outcome = "PREFLIGHT_OK" if passed else "INCONCLUSIVE"
        r5_gate = "BLOCK"  # preflight can never authorise; live controls do
        completion_marker = None
    else:
        passed = (exit_code == 0 and operator_gate == "PASS" and forge_ok
                  and not report.get("blocker"))
        run_outcome = "COMPLETE" if passed else "INCONCLUSIVE"
        r5_gate = "PASS" if passed else "BLOCK"
        completion_marker = "[R5 COMPLETE]" if passed else None

    return {
        "schema": "echo.certification-forge.r5-capability-result/v1",
        "mode": mode,
        "evidence_run_id": evidence_run_id,
        "run_outcome": run_outcome,
        "release_verdict": "NOT_READY",
        "r5_gate": r5_gate,
        "deployment_authorized": False,
        "completion_marker": completion_marker,
        "operator_report": redact({
            "run_outcome": operator_outcome,
            "r5_gate": operator_gate,
            "blocker": report.get("blocker"),
            "controls": report.get("controls"),
            "evidence_manifest": report.get("evidence_manifest"),
        }),
        "forge_verification": redact(dict(forge_verify)),
        "operator_exit_code": exit_code,
    }
