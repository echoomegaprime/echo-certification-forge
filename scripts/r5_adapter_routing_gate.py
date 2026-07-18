"""Executable R5 Family 14B adapter-routing provenance gate."""
from __future__ import annotations

import argparse
import json
import os
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
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


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
        trusted[f"ed25519:{sha256_bytes(raw)[:32]}"] = pem
    if not trusted:
        raise ValueError("routing trust store contains no Ed25519 public keys")
    return trusted


def http_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    data = None
    if payload is not None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
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


def nonce(prefix: str, ordinal: int) -> str:
    return f"{prefix}-{ordinal}-{os.urandom(16).hex()}"


def probe(identity: AdapterIdentity, challenge: str) -> dict[str, Any]:
    return {
        "model": identity.requested_model,
        "messages": [
            {"role": "system", "content": "Return one JSON object only. Do not issue a release verdict."},
            {
                "role": "user",
                "content": (
                    f"Adapter routing proof challenge={challenge}. "
                    "Classify: the harness reached the configured port and the application "
                    "then returned 500 with NullReferenceException in product code."
                ),
            },
        ],
        "temperature": 0.0,
        "max_tokens": 180,
    }


def completion(base_url: str, payload: dict[str, Any], challenge: str, timeout: float) -> dict[str, Any]:
    return http_json(
        "POST",
        base_url.rstrip("/") + "/v1/chat/completions",
        payload,
        {"X-Echo-Routing-Challenge": challenge},
        timeout,
    )


def retry_completion(
    base_url: str,
    payload: dict[str, Any],
    challenge: str,
    timeout: float,
    attempts: int,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        result = completion(base_url, payload, challenge, timeout)
        result["attempt"] = attempt
        records.append(result)
        if result["status"] not in {429, 503}:
            break
        try:
            delay = float(result["headers"].get("retry-after", "2"))
        except ValueError:
            delay = 2.0
        time.sleep(min(max(delay, 0.5), 10.0))
    return {"attempts": records, "final": records[-1]}


def admin_call(base_url: str, path: str, token: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    return http_json(
        "POST",
        base_url.rstrip("/") + path,
        payload,
        {"Authorization": f"Bearer {token}"},
        timeout,
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

    snapshot = load_json(args.registry_snapshot)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("personas"), list):
        raise SystemExit("registry snapshot must contain a personas list")
    identities = [AdapterIdentity.from_mapping(item) for item in snapshot["personas"]]
    enabled = [item for item in identities if item.enabled]
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

    health = http_json("GET", args.family_url.rstrip("/") + "/health", timeout=20.0)
    models = http_json("GET", args.family_url.rstrip("/") + "/v1/models", timeout=20.0)
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
            challenge = nonce(identity.persona_id, ordinal)
            request_payload = probe(identity, challenge)
            exchange = retry_completion(
                args.family_url,
                request_payload,
                challenge,
                args.request_timeout,
                args.retry_attempts,
            )
            final = exchange["final"]
            body = final.get("body") if isinstance(final.get("body"), dict) else {}
            proof = verify_persona_routing(
                response=body,
                request_payload=request_payload,
                challenge_nonce=challenge,
                expected=identity,
                trusted_public_keys=trusted,
            )
            report["positive_controls"].append(
                {
                    "persona_id": identity.persona_id,
                    "adapter_id": identity.adapter_id,
                    "adapter_digest": identity.adapter_digest,
                    "maturity_state": identity.maturity_state,
                    "ordinal": ordinal,
                    "nonce": challenge,
                    "request": request_payload,
                    "exchange": exchange,
                    "proof": proof.to_dict(),
                }
            )
            if final["status"] != 200:
                report["mandatory_failures"].append(
                    f"positive_request_failed:{identity.persona_id}:{ordinal}:{final['status']}"
                )
            if not proof.ok:
                report["mandatory_failures"].append(
                    f"positive_routing_unproven:{identity.persona_id}:{ordinal}"
                )

    base_challenge = nonce("base", 0)
    base_request = {
        "model": "echo-prime",
        "messages": [{"role": "user", "content": f"Base routing control challenge={base_challenge}."}],
        "temperature": 0.0,
        "max_tokens": 32,
    }
    base_exchange = retry_completion(
        args.family_url,
        base_request,
        base_challenge,
        args.request_timeout,
        args.retry_attempts,
    )
    base_final = base_exchange["final"]
    base_body = base_final.get("body") if isinstance(base_final.get("body"), dict) else {}
    base_proof = verify_base_routing(
        response=base_body,
        request_payload=base_request,
        challenge_nonce=base_challenge,
        trusted_public_keys=trusted,
    )
    report["base_control"] = {
        "nonce": base_challenge,
        "request": base_request,
        "exchange": base_exchange,
        "proof": base_proof.to_dict(),
    }
    if base_final["status"] != 200 or not base_proof.ok:
        report["mandatory_failures"].append("explicit_base_control_failed")

    if args.run_slot_contention_control:
        if not enabled:
            report["mandatory_failures"].append("slot_contention_no_enabled_adapter")
        else:
            target = enabled[0]
            requests = [(nonce("contention", i), None) for i in range(2)]
            requests = [(challenge, probe(target, challenge)) for challenge, _ in requests]
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        completion,
                        args.family_url,
                        payload,
                        challenge,
                        args.request_timeout,
                    )
                    for challenge, payload in requests
                ]
                results = [future.result() for future in futures]
            statuses = [item["status"] for item in results]
            silent_base = any(
                isinstance(item.get("body"), dict)
                and item["body"].get("model") == "echo-prime"
                for item in results
            )
            passed = (
                all(status in {200, 429, 503} for status in statuses)
                and any(status == 200 for status in statuses)
                and not silent_base
            )
            report["slot_contention_control"] = {
                "requests": [{"nonce": c, "request": p} for c, p in requests],
                "results": results,
                "silent_base_fallback": silent_base,
                "passed": passed,
            }
            if not passed:
                report["mandatory_failures"].append("slot_contention_control_failed")

    if args.run_unloaded_negative_control:
        token = os.environ.get(args.admin_token_env)
        if not args.admin_url or not token:
            report["mandatory_failures"].append("unloaded_control_admin_authority_missing")
        else:
            lease = admin_call(
                args.admin_url,
                "/admin/adapter-routing/lease",
                token,
                {"purpose": "R5_UNLOADED_NEGATIVE_CONTROL", "adapter_ids": [i.adapter_id for i in enabled]},
                30.0,
            )
            lease_id = lease.get("body", {}).get("lease_id") if isinstance(lease.get("body"), dict) else None
            if lease["status"] != 200 or not lease_id:
                report["mandatory_failures"].append("unloaded_control_lease_failed")
            else:
                for identity in enabled:
                    quoted = urllib.parse.quote(identity.adapter_id, safe="")
                    unload = admin_call(
                        args.admin_url,
                        f"/admin/adapters/{quoted}/unload",
                        token,
                        {"lease_id": lease_id},
                        60.0,
                    )
                    challenge = nonce("unloaded", 0)
                    request_payload = probe(identity, challenge)
                    inference = completion(
                        args.family_url,
                        request_payload,
                        challenge,
                        args.request_timeout,
                    )
                    body = inference.get("body") if isinstance(inference.get("body"), dict) else {}
                    proof = verify_unloaded_adapter_failure(
                        error_response=body,
                        request_payload=request_payload,
                        challenge_nonce=challenge,
                        expected=identity,
                        trusted_public_keys=trusted,
                    )
                    reload_result = admin_call(
                        args.admin_url,
                        f"/admin/adapters/{quoted}/load",
                        token,
                        {"lease_id": lease_id},
                        120.0,
                    )
                    report["unloaded_negative_controls"].append(
                        {
                            "persona_id": identity.persona_id,
                            "adapter_id": identity.adapter_id,
                            "nonce": challenge,
                            "unload": unload,
                            "request": request_payload,
                            "inference": inference,
                            "proof": proof.to_dict(),
                            "reload": reload_result,
                        }
                    )
                    if unload["status"] != 200:
                        report["mandatory_failures"].append(f"adapter_unload_failed:{identity.adapter_id}")
                    if inference["status"] not in {409, 503} or not proof.ok:
                        report["mandatory_failures"].append(f"unloaded_negative_control_failed:{identity.adapter_id}")
                    if reload_result["status"] != 200:
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
