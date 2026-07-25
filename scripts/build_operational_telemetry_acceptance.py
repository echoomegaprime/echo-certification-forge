#!/usr/bin/env python3
"""Build public-only live-acceptance reports from real P5 adapter evidence.

Private Ed25519 keys exist only in this process.  The output contains short-lived
signed credentials, signed reports, and control-plane public keys suitable for a
one-time live acceptance.  It never emits private key material.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from echo_certification_forge.canonical import (  # noqa: E402
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from echo_certification_forge.operational_telemetry import SignedOperationalReport  # noqa: E402
from echo_certification_forge.runner import (  # noqa: E402
    ControlPlaneTransportAuthority,
    RunnerCommand,
    RunnerEphemeralIdentity,
    create_transport_request,
)


def _write(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tenant", default="echo-sovereign")
    parser.add_argument("--adapter-bundle-response", type=Path, required=True)
    parser.add_argument("--adapter-control-public-key", type=Path, required=True)
    args = parser.parse_args()

    try:
        adapter_report = SignedOperationalReport.model_validate_json(
            args.adapter_bundle_response.read_text(encoding="utf-8")
        )
        adapter_public_key = args.adapter_control_public_key.read_text(encoding="ascii")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"invalid adapter acceptance input: {exc}") from exc
    if adapter_report.credential.claims.tenant_id != args.tenant:
        raise SystemExit("adapter bundle tenant differs from --tenant")
    if adapter_report.response.body.get("kind") != "adapter_execution_bundle":
        raise SystemExit("adapter response is not an adapter_execution_bundle")
    adapter_records = adapter_report.response.body.get("records")
    if not isinstance(adapter_records, list) or not adapter_records:
        raise SystemExit("adapter response contains no records")
    adapter_ids = sorted(
        str(record.get("identity", {}).get("adapter_id", ""))
        for record in adapter_records
    )
    if any(not adapter_id for adapter_id in adapter_ids):
        raise SystemExit("adapter response contains an unidentified record")

    timestamp = utc_now()
    suffix = str(int(timestamp.timestamp() * 1_000_000))

    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
    heartbeat_credential = authority.issue(
        credential_id=f"heartbeat-credential-{suffix}",
        run_id=f"cert-worker-heartbeat-{suffix}",
        tenant_id=args.tenant,
        runner_id="hammer-live-acceptance-runner",
        runner_public_key_pem=runner.public_key_pem,
        scopes=(RunnerCommand.HEARTBEAT.value,),
        issued_at=timestamp,
        ttl=timedelta(minutes=15),
    )
    heartbeat_request = create_transport_request(
        request_id=f"heartbeat-request-{suffix}",
        credential=heartbeat_credential,
        nonce=f"heartbeat-nonce-{suffix}-0000000000000000",
        command=RunnerCommand.HEARTBEAT,
        sequence=1,
        issued_at=timestamp,
        body={"action": "live_acceptance_heartbeat"},
    )
    heartbeat_response = runner.sign_response(
        response_id=f"heartbeat-response-{suffix}",
        request=heartbeat_request,
        status="ACCEPTED",
        body={
            "kind": "worker_heartbeat",
            "health": "HEALTHY",
            "capacity_total": 1,
            "capacity_available": 1,
            "active_run_count": 0,
            "worker_image_sha256": sha256_bytes(Path(sys.executable).read_bytes()),
        },
        issued_at=timestamp,
    )

    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "heartbeat-control-public-key.pem").write_text(
        authority.public_key_pem, encoding="ascii", newline="\n"
    )
    (args.output / "adapter-control-public-key.pem").write_text(
        adapter_public_key, encoding="ascii", newline="\n"
    )
    _write(
        args.output / "worker-heartbeat-report.json",
        SignedOperationalReport(
            credential=heartbeat_credential,
            response=heartbeat_response,
        ).model_dump(mode="json"),
    )
    _write(
        args.output / "adapter-inventory-report.json",
        adapter_report.model_dump(mode="json"),
    )
    _write(
        args.output / "manifest.json",
        {
            "schema_version": 1,
            "generated_at": to_utc_iso(timestamp),
            "tenant_id": args.tenant,
            "private_key_material_written": False,
            "adapter_ids": adapter_ids,
            "adapter_set_sha256": sha256_json(adapter_records),
            "heartbeat_runner_id": heartbeat_response.runner_id,
            "heartbeat_response_id": heartbeat_response.response_id,
            "adapter_response_id": adapter_report.response.response_id,
        },
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
