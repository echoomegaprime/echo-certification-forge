"""Build a signed P5 adapter execution bundle from ANVIL evidence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from echo_certification_forge.adapter_execution import (
    AdapterEvidenceSource,
    build_acceptance_report,
    build_records_from_evidence,
    default_p5_policy,
    load_json,
    sign_adapter_bundle,
    write_adapter_execution_artifacts,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--qualification-report", required=True, type=Path)
    parser.add_argument("--gs343-r5-evidence", required=True, type=Path)
    parser.add_argument("--r2d2-r5-evidence", required=True, type=Path)
    parser.add_argument("--gs343-quality-mode", default="gs_adapter_context")
    parser.add_argument("--r2d2-quality-mode", default="r2_adapter_context")
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()

    records = build_records_from_evidence(
        (
            AdapterEvidenceSource("gs343", "echo-gs343", args.gs343_r5_evidence, args.gs343_quality_mode),
            AdapterEvidenceSource("r2d2", "echo-r2d2", args.r2d2_r5_evidence, args.r2d2_quality_mode),
        ),
        qualification_report=load_json(args.qualification_report),
    )
    policy = default_p5_policy(records)
    signed = sign_adapter_bundle(records, run_id=args.run_id, tenant_id=args.tenant_id)
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id=args.run_id,
        tenant_id=args.tenant_id,
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
    )
    write_adapter_execution_artifacts(
        args.output_directory,
        signed_bundle=signed,
        acceptance_report=report,
        policy=policy,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["adapter_gate_eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
