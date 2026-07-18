"""Executable R5 Family 14B adapter-routing provenance gate."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from echo_certification_forge.adapter_routing import (
    AdapterIdentity,
    verify_base_routing,
    verify_persona_routing,
    verify_unloaded_adapter_failure,
)
from echo_certification_forge.canonical import sha256_bytes, sha256_json

DEFAULT_FAMILY_URL = "http://192.168.1.49:8200"


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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
            raise TypeError(f"{path} is not an Ed25519 public key")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        trusted[key_id] = pem
    if not trusted:
        raise ValueError("routing trust store contains no Ed25519 public keys")
    return trusted


def http_json(
    *,
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request_headers = dict(headers or {})
    if data is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return {
                "status": response.status,
                "headers": {key.lower(): value for key, value in response.headers.items()},
                "body": json.loads(raw.decode("utf-8")) if raw else {},
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body: Any = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            body = {"raw_text": raw.decode("utf-8", errors="replace")}
        return {
            "status": error.code,
            "headers": {key.lower(): value for key, value in error.headers.items()},
            "body": body,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }


def make_nonce(prefix: str, ordinal: int) -> str:
    entropy = os.urandom(16).hex()
    return f"{prefix}-{ordinal}-{entropy}"


def build_probe(identity: AdapterIdentity, nonce: str) -> dict[str, Any]:
    return {
        "model": identity.requested_model,
        "messages": [
            {
                "role": "system",
                "content": "Return one JSON object only. Do not issue a release verdict.",
            },
            {
                "role": "user",
                "content": (
                    f"Adapter routing proof challenge={nonce}. "
                    "Classify: the harness reached the configured port and the application "
                    "then returned 500 with NullReferenceException in product code."
                ),
            },
        ],
        "temperature": 0.0,
        "max_tokens": 180,
    }


def completion(
    family_url: str,
    payload: dict[str, Any],
    nonce: str,
    timeout: float,
) -> dict[str, Any]:
    return http_json(
        method="POST",
        url=family_url.rstrip("/") + "/v1/chat/completions",
        payload=payload,
        headers={"X-Echo-Routing-Challenge": nonce},
        timeout=timeout,
    )


def retry_completion(
    family_url: str,
    payload: dict[str, Any],
    nonce: str,
    timeout: float,
    attempts: int,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        result = completion(family_url, payload, nonce, timeout)
        result["attempt"] = attempt
        records.append(result)
        if result["status"] not in {429, 503}:
            return {"attempts": records, "final": result}
        retry_after = result["headers"].get("retry-after", "2")
        try:
            delay = min(max(float(retry_after), 0.5), 10.0)
        except ValueError:
            delay = 2.0
        time.sleep(delay)
    return {"attempts": records, "final": records[-1]}


def admin_call(
    *,
    admin_url: str,
    path: str,
    token: str,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    return http_json(
        method="POST",
        url=admin_url.rstrip("/") + path,
        payload=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--family-url", default=DEFAULT_FAMILY_URL)
    parser.add_argument("--registry-snapshot", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--positive-repetitions", type=int, default=3)
    parser.add_argument("--request-timeout", type=float, default=120.0)
    parser.add_argument("--retry-attempts", type=int, default=6)
    parser.add_argument("--run-slot-contention-control", action="store_true")
    parser.add_argument("--run-unloaded-negative-control", action="store_true")
    parser.add_argument("--admin-url")
    parser.add_argument("--admin-token-env", default="ECHO_FAMILY_ADMIN_TOKEN")
    args = parser.parse_args()

    if args.positive_repetitions < 3:
        parser.error("--positive-repetitions must be at least 3")
    if args.retry_attempts < 1:
        parser.error("--retry-attempts must be positive")

    snapshot = load_json(args.registry_snapshot)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("personas"), list):
        raise SystemExit("registry snapshot must contain a personas list")
    identities = [AdapterIdentity.from_mapping(item) for item in snapshot["personas"]]
    enabled = [item for item in identities if item.enabled and item.maturity_state == "CERTIFIED"]
    trusted = load_trust_store(args.trust_store)

    report: dict[str, Any] = {
        "schema": "echo.r5-adapter-routing-report/v1",
        "started_at": utc_now(),
        "family_url": args.family_url,
        "registry_snapshot_sha256": sha256_json(snapshot),
        "trust_store_key_ids": sorted(trusted),
        "run_outcome": "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
        "phase_status": "BLOCK",
        "health": None,
        "models": None,
        "positive_controls": [],
        "base_control": None,
        "slot_contention_control": None,
        "unloaded_negative_controls": [],
        "mandatory_failures": [],
    }

    health = http_json(method="GET", url=args.family_url.rstrip("/") + "/health", timeout=20.0)
    models = http_json(method="GET", url=args.family_url.rstrip("/") + "/v1/models", timeout=20.0)
    report["health"] = health
    report["models"] = models
    if health["status"] != 200 or health["body"].get("status") != "ok":
        report["mandatory_failures"].append("family_health_not_ok")
    model_ids = {
        item.get("id")
        for item in models.get("body", {}).get("data", [])
        if isinstance(item, dict)
    }
    if models["status"] != 200:
        report["mandatory_failures"].append("models_endpoint_failed")

    for identity in enabled:
        if identity.requested_model not in model_ids:
            report["mandatory_failures"].append(f"model_not_listed:{identity.requested_model}")
        for ordinal in range(args.positive_repetitions):
            nonce = make_nonce(identity.persona_id, ordinal)
            request_payload = build_probe(identity, nonce)
            exchange = retry_completion(
                args.family_url,
                request_payload,
                nonce,
                args.request_timeout,
                args.retry_attempts,
            )
            final = exchange["final"]
            response_body = final.get("body") if isinstance(final.get("body"), dict) else {}
            proof = verify_persona_routing(
                response=response_body,
                request_payload=request_payload,
                challenge_nonce=nonce,
                expected=identity,
                trusted_public_keys=trusted,
            )
            item = {
                "persona_id": identity.persona_id,
                "adapter_id": identity.adapter_id,
                "adapter_digest": identity.adapter_digest,
                "ordinal": ordinal,
                "nonce": nonce,
                "request": request_payload,
                "exchange": exchange,
                "proof": proof.to_dict(),
            }
            report["positive_controls"].append(item)
            if final["status"] != 200:
                report["mandatory_failures"].append(
                    f"positive_request_failed:{identity.persona_id}:{ordinal}:{final['status']}"
                )
            if not proof.ok:
                report["mandatory_failures"].append(
                    f"positive_routing_unproven:{identity.persona_id}:{ordinal}"
                )

    base_nonce = make_nonce("base", 0)
    base_request = {
        "model": "echo-prime",
        "messages": [{"role": "user", "content": f"Base routing control challenge={base_nonce}."}],
        "temperature": 0.0,
        "max_tokens": 32,
    }
    base_exchange = retry_completion(
        args.family_url,
        base_request,
        base_nonce,
        args.request_timeout,
        args.retry_attempts,
    )
    base_final = base_exchange["final"]
    base_body = base_final.get("body") if isinstance(base_final.get("body"), dict) else {}
    base_proof = verify_base_routing(
        response=base_body,
        request_payload=base_request,
        challenge_nonce=base_nonce,
        trusted_public_keys=trusted,
    )
    report["base_control"] = {
        "nonce": base_nonce,
        "request": base_request,
        "exchange": base_exchange,
        "proof": base_proof.to_dict(),
    }
    if base_final["status"] != 200 or not base_proof.ok:
        report["mandatory_failures"].append("explicit_base_control_failed")

    if args.run_slot_contention_control:
        target = enabled[0] if enabled else None
        if target is None:
            report["mandatory_failures"].append("slot_contention_no_certified_adapter")
        else:
            requests: list[tuple[str, dict[str, Any]]] = []
            for ordinal in range(2):
                nonce = make_nonce("contention", ordinal)
                requests.append((nonce, build_probe(target, nonce)))
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        completion,
                        args.family_url,
                        payload,
                        nonce,
                        args.request_timeout,
                    )
                    for nonce, payload in requests
                ]
                results = [future.result() for future in futures]
            statuses = [item["status"] for item in results]
            silent_base = any(
                isinstance(item.get("body"), dict)
                and item["body"].get("model") == "echo-prime"
                and requests[index][1]["model"] != "echo-prime"
                for index, item in enumerate(results)
            )
            contention_ok = (
                all(status in {200, 429, 503} for status in statuses)
                and not silent_base
                and any(status == 200 for status in statuses)
            )
            report["slot_contention_control"] = {
                "requests": [
                    {"nonce": nonce, "request": payload}
                    for nonce, payload in requests
                ],
                "results": results,
                "silent_base_fallback": silent_base,
                "passed": contention_ok,
            }
            if not contention_ok:
                report["mandatory_failures"].append("slot_contention_control_failed")

    if args.run_unloaded_negative_control:
        token = os.environ.get(args.admin_token_env)
        if not args.admin_url or not token:
            report["mandatory_failures"].append("unloaded_control_admin_authority_missing")
        else:
            lease = admin_call(
                admin_url=args.admin_url,
                path="/admin/adapter-routing/lease",
                token=token,
                payload={"purpose": "R5_UNLOADED_NEGATIVE_CONTROL", "adapter_ids": [item.adapter_id for item in enabled]},
                timeout=30.0,
            )
            lease_id = lease.get("body", {}).get("lease_id") if isinstance(lease.get("body"), dict) else None
            if lease["status"] != 200 or not lease_id:
                report["mandatory_failures"].append("unloaded_control_lease_failed")
            else:
                for identity in enabled:
                    unload = admin_call(
                        admin_url=args.admin_url,
                        path=f"/admin/adapters/{urllib.parse.quote(identity.adapter_id, safe='')}/unload",
                        token=token,
                        payload={"lease_id": lease_id},
                        timeout=60.0,
                    )
                    nonce = make_nonce("unloaded", 0)
                    request_payload = build_probe(identity, nonce)
                    inference = completion(
                        args.family_url,
                        request_payload,
                        nonce,
                        args.request_timeout,
                    )
                    body = inference.get("body") if isinstance(inference.get("body"), dict) else {}
                    proof = verify_unloaded_adapter_failure(
                        error_response=body,
                        request_payload=request_payload,
                        challenge_nonce=nonce,
                        expected=identity,
                        trusted_public_keys=trusted,
                    )
                    load = admin_call(
                        admin_url=args.admin_url,
                        path=f"/admin/adapters/{urllib.parse.quote(identity.adapter_id, safe='')}/load",
                        token=token,
                        payload={"lease_id": lease_id},
                        timeout=120.0,
                    )
                    control = {
                        "persona_id": identity.persona_id,
                        "adapter_id": identity.adapter_id,
                        "unload": unload,
                        "request": request_payload,
                        "inference": inference,
                        "proof": proof.to_dict(),
                        "reload": load,
                    }
                    report["unloaded_negative_controls"].append(control)
                    if unload["status"] != 200:
                        report["mandatory_failures"].append(f"adapter_unload_failed:{identity.adapter_id}")
                    if inference["status"] not in {409, 503} or not proof.ok:
                        report["mandatory_failures"].append(f"unloaded_negative_control_failed:{identity.adapter_id}")
                    if load["status"] != 200:
                        report["mandatory_failures"].append(f"adapter_reload_failed:{identity.adapter_id}")

    report["completed_at"] = utc_now()
    report["mandatory_failures"] = sorted(set(report["mandatory_failures"]))
    if not report["mandatory_failures"]:
        report["run_outcome"] = "COMPLETE"
        report["phase_status"] = "PASS"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / "r5_adapter_routing_report.json"
    write_json(output, report)
    print(
        json.dumps(
            {
                "output": str(output),
                "run_outcome": report["run_outcome"],
                "release_verdict": report["release_verdict"],
                "phase_status": report["phase_status"],
                "mandatory_failures": report["mandatory_failures"],
            },
            indent=2,
        )
    )
    return 0 if report["phase_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
