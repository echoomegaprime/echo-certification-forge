#!/usr/bin/env python3
"""Export, attest, build, or validate GS343/R2D2 P5 corrective corpora."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from echo_certification_forge.p5_corpus import (
    TEACHER_REQUESTS_FILENAME,
    build_corpora,
    export_teacher_requests,
    materialize_curriculum_ledger,
    sign_teacher_response_ledger,
    validate_corpora,
    verify_teacher_provenance,
)
from echo_certification_forge.signing import Ed25519VerdictSigner
from echo_certification_forge.teacher_generator import (
    DEFAULT_GROK_MODEL,
    DEFAULT_MODEL,
    GROK_PROVIDER,
    TeacherGenerationError,
    VERTEX_PROVIDER,
    XAI_API_PROVIDER,
    generate_teacher_responses,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export-requests")
    export_parser.add_argument("--gs343-curriculum-ledger", type=Path, required=True)
    export_parser.add_argument("--r2d2-curriculum-ledger", type=Path, required=True)
    export_parser.add_argument("--provenance-root", type=Path, required=True)
    export_parser.add_argument("--requests-per-adapter", type=int, default=1_600)

    generate_parser = subparsers.add_parser("generate-teacher-responses")
    generate_parser.add_argument("--requests", type=Path, required=True)
    generate_parser.add_argument("--successes", type=Path, required=True)
    generate_parser.add_argument("--failures", type=Path, required=True)
    generate_parser.add_argument(
        "--provider",
        choices=(VERTEX_PROVIDER, GROK_PROVIDER, XAI_API_PROVIDER),
        default=VERTEX_PROVIDER,
    )
    generate_parser.add_argument("--api-key-env", default="VERTEX_EXPRESS_API_KEY")
    generate_parser.add_argument("--model")
    generate_parser.add_argument("--grok-command", default="grok")
    generate_parser.add_argument("--grok-cwd", type=Path)
    generate_parser.add_argument("--timeout-seconds", type=float, default=120.0)
    generate_parser.add_argument("--max-attempts", type=int, default=5)
    generate_parser.add_argument("--base-backoff-seconds", type=float, default=1.0)
    generate_parser.add_argument("--max-backoff-seconds", type=float, default=30.0)
    generate_parser.add_argument("--concurrency", type=int, default=1)
    generate_parser.add_argument("--max-cost-usd", type=float, default=25.0)

    materialize_parser = subparsers.add_parser("materialize-curriculum")
    materialize_parser.add_argument(
        "--adapter", choices=("gs343", "r2d2"), required=True
    )
    materialize_parser.add_argument("--raw-source", type=Path, required=True)
    materialize_parser.add_argument("--ledger-output", type=Path, required=True)
    materialize_parser.add_argument("--row-count", type=int, default=1_600)

    sign_parser = subparsers.add_parser("sign-responses")
    sign_parser.add_argument("--provenance-root", type=Path, required=True)
    sign_parser.add_argument("--generated-responses", type=Path, required=True)
    sign_parser.add_argument("--private-key-pem", type=Path, required=True)
    sign_parser.add_argument("--signer-identity", required=True)

    verify_parser = subparsers.add_parser("verify-provenance")
    verify_parser.add_argument("--provenance-root", type=Path, required=True)
    verify_parser.add_argument("--trusted-key-dir", type=Path, required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--gs343-curriculum-ledger", type=Path, required=True)
    build_parser.add_argument("--r2d2-curriculum-ledger", type=Path, required=True)
    build_parser.add_argument("--output-root", type=Path, required=True)
    build_parser.add_argument("--provenance-root", type=Path, required=True)
    build_parser.add_argument("--trusted-key-dir", type=Path, required=True)

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--output-root", type=Path, required=True)
    validate_parser.add_argument("--provenance-root", type=Path, required=True)
    validate_parser.add_argument("--trusted-key-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "materialize-curriculum":
        manifest, manifest_path = materialize_curriculum_ledger(
            args.adapter,
            args.raw_source,
            args.ledger_output,
            row_count=args.row_count,
        )
        report = {
            "adapter": args.adapter,
            "ledger": str(args.ledger_output),
            "manifest": str(manifest_path),
            "row_count": manifest["row_count"],
            "ledger_sha256": manifest["ledger"]["sha256"],
        }
    elif args.command == "export-requests":
        report = export_teacher_requests(
            args.gs343_curriculum_ledger,
            args.r2d2_curriculum_ledger,
            args.provenance_root,
            requests_per_adapter=args.requests_per_adapter,
        )
    elif args.command == "generate-teacher-responses":
        api_key = os.environ.get(args.api_key_env, "")
        if args.provider in {VERTEX_PROVIDER, XAI_API_PROVIDER} and not api_key:
            raise TeacherGenerationError(
                f"required API key environment variable is unset: {args.api_key_env}"
            )
        model = args.model or (
            DEFAULT_GROK_MODEL if args.provider == GROK_PROVIDER else DEFAULT_MODEL
        )
        report = generate_teacher_responses(
            requests_path=args.requests,
            successes_path=args.successes,
            failures_path=args.failures,
            api_key=api_key,
            provider=args.provider,
            model=model,
            grok_command=args.grok_command,
            grok_cwd=args.grok_cwd,
            timeout_seconds=args.timeout_seconds,
            max_attempts=args.max_attempts,
            base_backoff_seconds=args.base_backoff_seconds,
            max_backoff_seconds=args.max_backoff_seconds,
            concurrency=args.concurrency,
            max_cost_usd=args.max_cost_usd,
        )
        if report["failed_count"]:
            print(json.dumps(report, indent=2, sort_keys=True))
            raise TeacherGenerationError(
                f"{report['failed_count']} requests failed; response ledger is incomplete"
            )
    elif args.command == "sign-responses":
        signer = Ed25519VerdictSigner.from_private_pem(
            args.private_key_pem.read_bytes()
        )
        report = sign_teacher_response_ledger(
            args.provenance_root / TEACHER_REQUESTS_FILENAME,
            args.generated_responses,
            args.provenance_root,
            signer=signer,
            signer_identity=args.signer_identity,
        )
    elif args.command == "verify-provenance":
        verified = verify_teacher_provenance(
            args.provenance_root, args.trusted_key_dir
        )
        report = {
            "passed": True,
            "verified_targets": {
                adapter: len(targets) for adapter, targets in verified.items()
            },
        }
    elif args.command == "build":
        report = build_corpora(
            args.gs343_curriculum_ledger,
            args.r2d2_curriculum_ledger,
            args.output_root,
            args.provenance_root,
            args.trusted_key_dir,
        )
    else:
        report = validate_corpora(
            args.output_root,
            args.provenance_root,
            args.trusted_key_dir,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
