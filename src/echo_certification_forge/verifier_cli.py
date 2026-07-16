"""Public-only image/SBOM verifier entrypoint for the P4 verifier image."""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from .canonical import parse_utc_iso
from .supply_chain import (
    ImageAdmissionPolicy,
    ImageAttestation,
    evaluate_image_admission,
    verify_spdx_document,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="echo-certforge-verifier")
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--now")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    attestation = ImageAttestation.model_validate_json(args.attestation.read_text(encoding="utf-8"))
    policy = ImageAdmissionPolicy.model_validate_json(args.policy.read_text(encoding="utf-8"))
    now: datetime | None = parse_utc_iso(args.now) if args.now else None
    admission = evaluate_image_admission(attestation, policy, now=now)
    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    sbom_valid, sbom_reason = verify_spdx_document(sbom, image_digest=args.image_digest)
    result = {
        "schema_version": "1.0.0",
        "admission": admission.model_dump(mode="json"),
        "sbom_valid": sbom_valid,
        "sbom_reason": sbom_reason,
        "private_key_loaded": False,
        "passed": admission.allowed and sbom_valid,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
