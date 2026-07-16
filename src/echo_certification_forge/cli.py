"""Read-only verification CLI for operators and deployment systems."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .deploy_gate import DeployGate
from .evidence import EvidenceStore
from .signing import TrustedPublicKeyRegistry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="echo-cert")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_evidence = subparsers.add_parser("verify-evidence")
    verify_evidence.add_argument("--tenant", required=True)
    verify_evidence.add_argument("--run", required=True)

    gate = subparsers.add_parser("deploy-gate")
    gate.add_argument("--tenant", required=True)
    gate.add_argument("--run", required=True)
    gate.add_argument("--target-digest", required=True)
    gate.add_argument("--environment-digest", required=True)
    gate.add_argument("--manifest-digest", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = EvidenceStore(args.db, args.evidence_root)
    if args.command == "verify-evidence":
        report = store.verify_evidence(args.run, args.tenant)
        output = {
            "valid": report.valid,
            "run_id": report.run_id,
            "artifact_count": report.artifact_count,
            "invalid_artifacts": list(report.invalid_artifacts),
            "merkle_root": report.merkle_root,
        }
        print(json.dumps(output, indent=2))
        return 0 if report.valid else 2
    trusted = TrustedPublicKeyRegistry.from_directory(args.trusted_keys)
    decision = DeployGate(store, trusted).evaluate(
        tenant_id=args.tenant,
        run_id=args.run,
        target_identity_digest=args.target_digest,
        environment_identity_digest=args.environment_digest,
        rule_manifest_digest=args.manifest_digest,
    )
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())
