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

from echo_certification_forge.adapter_execution import (
    AdapterEvidenceSource,
    build_records_from_evidence,
    load_json,
    sign_adapter_bundle,
)
from echo_certification_forge.canonical import sha256_bytes, to_utc_iso, utc_now
from echo_certification_forge.operational_telemetry import SignedOperationalReport
from echo_certification_forge.runner import (
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
    parser.add_argument("--family-evidence", type=Path, default=Path("artifacts/family14b"))
    args = parser.parse_args()

    family = args.family_evidence.resolve()
    qualification = load_json(family / "qualification_report.json")
    records = build_records_from_evidence(
        (
            AdapterEvidenceSource(
                "gs343", "echo-gs343", family / "r5-gs343-20260723", "gs_adapter_v2_context"
            ),
            AdapterEvidenceSource(
                "r2d2", "echo-r2d2", family / "r5-r2d2-20260723", "r2_adapter_context"
            ),
        ),
        qualification_report=qualification,
    )

    timestamp = utc_now()
    suffix = str(int(timestamp.timestamp() * 1_000_000))
    adapter = sign_adapter_bundle(
        records,
        run_id=f"cert-adapter-inventory-{suffix}",
        tenant_id=args.tenant,
    )

    authority = ControlPlaneTransportAuthority.generate()
    runner = RunnerEphemeralIdentity.generate()
    heartbeat_credential = authority.issue(
        credential_id=f"heartbeat-credential-{suffix}",
        run_id=f"cert-worker-heartbeat-{suffix}",
        tenant_id=args.tenant,
        runner_id=f"hammer-live-acceptance-runner-{suffix}",
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
        adapter.control_plane_public_key_pem, encoding="ascii", newline="\n"
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
        SignedOperationalReport(
            credential=adapter.credential,
            response=adapter.response,
        ).model_dump(mode="json"),
    )
    _write(
        args.output / "manifest.json",
        {
            "schema_version": 1,
            "generated_at": to_utc_iso(timestamp),
            "tenant_id": args.tenant,
            "private_key_material_written": False,
            "adapter_ids": [record.identity.adapter_id for record in records],
            "adapter_set_sha256": adapter.adapter_set_sha256,
            "heartbeat_runner_id": heartbeat_response.runner_id,
            "heartbeat_response_id": heartbeat_response.response_id,
            "adapter_response_id": adapter.response.response_id,
        },
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
