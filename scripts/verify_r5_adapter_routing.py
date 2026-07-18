"""Independent offline verifier and signed completion-marker emitter for R5."""
from __future__ import annotations

import argparse
import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge.adapter_routing import (
    AdapterIdentity,
    MARKER_SCHEMA,
    verify_base_routing,
    verify_persona_routing,
    verify_unloaded_adapter_failure,
)
from echo_certification_forge.canonical import canonical_json, sha256_bytes, sha256_json


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_trust_store(directory: Path) -> dict[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    trusted: dict[str, str] = {}
    for path in sorted(directory.glob("*.pem")):
        pem = path.read_text(encoding="ascii")
        key = serialization.load_pem_public_key(pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"{path} is not an Ed25519 key")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        trusted[f"ed25519:{sha256_bytes(raw)[:32]}"] = pem
    if not trusted:
        raise ValueError("empty routing trust store")
    return trusted


def sign_marker(marker: dict[str, Any], private_key_path: Path) -> dict[str, Any]:
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("phase marker signing key must be Ed25519")
    public = key.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    payload = dict(marker)
    payload["verifier_key_id"] = key_id
    signature = key.sign(canonical_json(payload).encode("utf-8"))
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_id": key_id,
        "public_key_pem": public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--registry-snapshot", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--p4-completion-commit", required=True)
    parser.add_argument("--harness-digest", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--verifier-build-digest", required=True)
    parser.add_argument("--signing-key-pem", type=Path)
    parser.add_argument("--require-unloaded-controls", action="store_true")
    parser.add_argument("--require-slot-contention", action="store_true")
    args = parser.parse_args()

    report = load_json(args.report)
    snapshot = load_json(args.registry_snapshot)
    trusted = load_trust_store(args.trust_store)
    identities = {
        item.persona_id: item
        for item in (AdapterIdentity.from_mapping(raw) for raw in snapshot.get("personas", []))
        if item.enabled and item.maturity_state == "CERTIFIED"
    }

    failures: list[str] = []
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: Any = None) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
        if not passed:
            failures.append(name)

    record("report_schema", report.get("schema") == "echo.r5-adapter-routing-report/v1", report.get("schema"))
    record("report_run_outcome", report.get("run_outcome") == "COMPLETE", report.get("run_outcome"))
    record("report_phase_status", report.get("phase_status") == "PASS", report.get("phase_status"))
    record("report_release_verdict_fail_closed", report.get("release_verdict") == "NOT_READY", report.get("release_verdict"))
    record("report_no_mandatory_failures", report.get("mandatory_failures") == [], report.get("mandatory_failures"))
    record("registry_snapshot_hash", report.get("registry_snapshot_sha256") == sha256_json(snapshot), report.get("registry_snapshot_sha256"))
    record("trust_store_identity", sorted(report.get("trust_store_key_ids", [])) == sorted(trusted), report.get("trust_store_key_ids"))

    positive = report.get("positive_controls")
    if not isinstance(positive, list):
        positive = []
        failures.append("positive_controls_missing")
    counts = {persona_id: 0 for persona_id in identities}
    for index, item in enumerate(positive):
        persona_id = item.get("persona_id")
        identity = identities.get(persona_id)
        if identity is None:
            failures.append(f"positive_unknown_persona:{index}")
            continue
        request = item.get("request")
        exchange = item.get("exchange")
        nonce = item.get("nonce")
        final = exchange.get("final") if isinstance(exchange, dict) else None
        response = final.get("body") if isinstance(final, dict) else None
        if not isinstance(request, dict) or not isinstance(response, dict) or not isinstance(nonce, str):
            failures.append(f"positive_malformed:{persona_id}:{index}")
            continue
        proof = verify_persona_routing(
            response=response,
            request_payload=request,
            challenge_nonce=nonce,
            expected=identity,
            trusted_public_keys=trusted,
        )
        counts[persona_id] += 1
        record(f"positive_proof:{persona_id}:{index}", proof.ok, proof.to_dict())
        record(f"positive_http_200:{persona_id}:{index}", final.get("status") == 200, final.get("status"))

    for persona_id, count in sorted(counts.items()):
        record(f"positive_repetitions:{persona_id}", count >= 3, count)

    base = report.get("base_control")
    if not isinstance(base, dict):
        record("base_control_present", False)
    else:
        base_request = base.get("request")
        base_exchange = base.get("exchange")
        base_final = base_exchange.get("final") if isinstance(base_exchange, dict) else None
        base_response = base_final.get("body") if isinstance(base_final, dict) else None
        if isinstance(base_request, dict) and isinstance(base_response, dict) and isinstance(base.get("nonce"), str):
            proof = verify_base_routing(
                response=base_response,
                request_payload=base_request,
                challenge_nonce=base["nonce"],
                trusted_public_keys=trusted,
            )
            record("base_control_proof", proof.ok, proof.to_dict())
            record("base_control_http_200", base_final.get("status") == 200, base_final.get("status"))
        else:
            record("base_control_malformed", False)

    contention = report.get("slot_contention_control")
    if args.require_slot_contention:
        record("slot_contention_present", isinstance(contention, dict))
        if isinstance(contention, dict):
            record("slot_contention_passed", contention.get("passed") is True, contention)
            record("slot_contention_no_silent_base", contention.get("silent_base_fallback") is False, contention.get("silent_base_fallback"))

    unloaded = report.get("unloaded_negative_controls")
    if not isinstance(unloaded, list):
        unloaded = []
    unloaded_personas: set[str] = set()
    for index, item in enumerate(unloaded):
        persona_id = item.get("persona_id")
        identity = identities.get(persona_id)
        if identity is None:
            failures.append(f"unloaded_unknown_persona:{index}")
            continue
        request = item.get("request")
        inference = item.get("inference")
        response = inference.get("body") if isinstance(inference, dict) else None
        nonce = item.get("proof", {}).get("receipt_payload", {}).get("challenge_nonce")
        if not isinstance(request, dict) or not isinstance(response, dict) or not isinstance(nonce, str):
            failures.append(f"unloaded_malformed:{persona_id}:{index}")
            continue
        proof = verify_unloaded_adapter_failure(
            error_response=response,
            request_payload=request,
            challenge_nonce=nonce,
            expected=identity,
            trusted_public_keys=trusted,
        )
        unloaded_personas.add(persona_id)
        record(f"unloaded_proof:{persona_id}", proof.ok, proof.to_dict())
        record(f"unloaded_http_failure:{persona_id}", inference.get("status") in {409, 503}, inference.get("status"))
        record(f"unloaded_reload_ok:{persona_id}", item.get("reload", {}).get("status") == 200, item.get("reload"))

    if args.require_unloaded_controls:
        for persona_id in identities:
            record(f"unloaded_control_present:{persona_id}", persona_id in unloaded_personas)

    failures = sorted(set(failures))
    verification = {
        "schema": "echo.r5-adapter-routing-verification/v1",
        "verified_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "report_sha256": sha256_bytes(args.report.read_bytes()),
        "registry_snapshot_sha256": sha256_json(snapshot),
        "source_commit": args.source_commit,
        "p4_completion_commit": args.p4_completion_commit,
        "harness_digest": args.harness_digest,
        "policy_digest": args.policy_digest,
        "verifier_build_digest": args.verifier_build_digest,
        "checks": checks,
        "failures": failures,
        "status": "PASS" if not failures else "BLOCK",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "r5_verification_report.json", verification)

    if not failures and args.signing_key_pem:
        marker = {
            "schema": MARKER_SCHEMA,
            "phase": "R5_ADAPTER_ROUTING",
            "status": "COMPLETE",
            "source_commit": args.source_commit,
            "prerequisite_p4_commit": args.p4_completion_commit,
            "policy_digest": args.policy_digest,
            "harness_digest": args.harness_digest,
            "process_exit_code": 0,
            "mandatory_checks_passed": len(checks),
            "mandatory_checks_failed": 0,
            "evidence_report_sha256": verification["report_sha256"],
            "verification_report_sha256": sha256_json(verification),
            "verifier_build_digest": args.verifier_build_digest,
            "issued_at": verification["verified_at"],
            "release_verdict": "NOT_READY",
        }
        envelope = sign_marker(marker, args.signing_key_pem)
        write_json(args.output_dir / "r5_completion_marker.json", envelope)

    print(json.dumps({"status": verification["status"], "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
