#!/usr/bin/env python3
"""Run the resumable, fail-closed P5 adapter qualification benchmark."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from echo_certification_forge.p5_qualification import (
    QualificationConfig,
    QualificationModels,
    run_qualification,
)

DEFAULT_GS_EVAL = REPO / "artifacts" / "p5" / "corpora" / "gs343_p5_v1" / "eval.jsonl"
DEFAULT_R2_EVAL = REPO / "artifacts" / "p5" / "corpora" / "r2d2_p5_v1" / "eval.jsonl"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare corrective GS343 and R2D2 candidates against incumbents "
            "using unchanged held-out eval rows and signed Family routing receipts."
        )
    )
    parser.add_argument("--base-url", default="http://192.168.1.49:8200")
    parser.add_argument("--trusted-attestation", required=True, type=Path)
    parser.add_argument("--gs-eval", type=Path, default=DEFAULT_GS_EVAL)
    parser.add_argument("--r2-eval", type=Path, default=DEFAULT_R2_EVAL)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--gs-candidate-model", required=True)
    parser.add_argument("--gs-incumbent-model", required=True)
    parser.add_argument("--r2-candidate-model", required=True)
    parser.add_argument("--r2-incumbent-model", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=190.0)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args(argv)

    config = QualificationConfig(
        base_url=args.base_url,
        trusted_attestation_path=args.trusted_attestation,
        gs_eval_path=args.gs_eval,
        r2_eval_path=args.r2_eval,
        output_directory=args.output_directory,
        models=QualificationModels(
            gs_candidate=args.gs_candidate_model,
            gs_incumbent=args.gs_incumbent_model,
            r2_candidate=args.r2_candidate_model,
            r2_incumbent=args.r2_incumbent_model,
        ),
        timeout_seconds=args.timeout_seconds,
        max_tokens=args.max_tokens,
    )
    report = run_qualification(config)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["promotion_decision"] == "PROMOTE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
