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
    parser.add_argument("--gs343-model")
    parser.add_argument("--r2d2-model")
    parser.add_argument("--gs343-quality-mode", default="gs_adapter_context")
    parser.add_argument("--r2d2-quality-mode", default="r2_adapter_context")
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()

    qualification_report = load_json(args.qualification_report)
    if qualification_report.get("schema") == "echo.certification-forge.p5-qualification/v1":
        try:
            gs343_model = qualification_report["models"]["gs343"]["candidate"]
            r2d2_model = qualification_report["models"]["r2d2"]["candidate"]
        except (KeyError, TypeError) as exc:
            raise SystemExit("new P5 qualification report lacks candidate model bindings") from exc
        if args.gs343_model and args.gs343_model != gs343_model:
            raise SystemExit("--gs343-model differs from qualification report candidate")
        if args.r2d2_model and args.r2d2_model != r2d2_model:
            raise SystemExit("--r2d2-model differs from qualification report candidate")
    else:
        gs343_model = args.gs343_model or "echo-gs343"
        r2d2_model = args.r2d2_model or "echo-r2d2"

    records = build_records_from_evidence(
        (
            AdapterEvidenceSource("gs343", gs343_model, args.gs343_r5_evidence, args.gs343_quality_mode),
            AdapterEvidenceSource("r2d2", r2d2_model, args.r2d2_r5_evidence, args.r2d2_quality_mode),
        ),
        qualification_report=qualification_report,
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
