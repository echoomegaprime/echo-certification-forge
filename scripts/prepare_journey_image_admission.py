#!/usr/bin/env python3
"""Prepare a new unsigned image policy using exact reviewed public inputs. No signing mode."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pydantic import ValidationError  # noqa: E402

from echo_certification_forge.journey_image_admission import (  # noqa: E402
    JourneyQualification, prepare_admission_request, proposed_policy,
)
from echo_certification_forge.supply_chain import (  # noqa: E402
    ImageAdmissionDenied, ImageAdmissionPolicy, ImageAttestation, ImageIdentity,
)


def plain_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ImageAdmissionDenied("reparse_path_refused")
    return absolute


def read_bounded(path: Path) -> bytes:
    checked = plain_path(path)
    info = checked.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4 * 1024 * 1024:
        raise ImageAdmissionDenied("input_type_or_size_refused")
    with checked.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ImageAdmissionDenied("input_changed_during_open")
        raw = handle.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ImageAdmissionDenied("input_size_limit")
    return raw


def write_new(path: Path, value: object) -> str:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--dockerfile", type=Path, required=True)
    parser.add_argument("--prior-policy", type=Path, required=True)
    parser.add_argument("--prior-attestation", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy_bytes = read_bounded(args.prior_policy)
        if hashlib.sha256(policy_bytes).hexdigest() != args.expected_policy_sha256:
            raise ImageAdmissionDenied("prior_policy_pin_mismatch")
        identity = ImageIdentity.model_validate_json(read_bounded(args.packet / "runner.identity.UNSIGNED.json"))
        if (identity.source_commit, identity.image_digest) != (args.expected_source, args.expected_image):
            raise ImageAdmissionDenied("candidate_pin_mismatch")
        request = prepare_admission_request(
            identity=identity,
            qualification=JourneyQualification.model_validate_json(read_bounded(args.qualification)),
            prior_policy=ImageAdmissionPolicy.model_validate_json(policy_bytes),
            prior_attestation=ImageAttestation.model_validate_json(read_bounded(args.prior_attestation)),
            dockerfile=read_bounded(args.dockerfile),
            lockfile=read_bounded(args.packet / "journey-image-inputs.lock.json"),
            sbom=read_bounded(args.packet / "runner.spdx.json"),
            provenance=read_bounded(args.packet / "runner.provenance.json"),
        )
        policy = proposed_policy(request)
        plain_path(args.output.parent)
        args.output.mkdir(exist_ok=False)
        request_hash = write_new(args.output / "request.UNSIGNED.json", request.model_dump(mode="json"))
        policy_hash = write_new(args.output / "policy.UNSIGNED.json", policy.model_dump(mode="json"))
        receipt = {
            "state": "UNSIGNED_NOT_ADMITTED", "request_digest": request.digest,
            "request_file_sha256": request_hash, "policy_file_sha256": policy_hash,
            "source_commit": identity.source_commit, "image_digest": identity.image_digest,
            "existing_key_id": request.prior_attestation.key_id,
            "live_changes": False, "signed": False, "production_ready": False,
        }
        # The completion receipt is written last. A partial directory is never ready.
        write_new(args.output / "preparation-receipt.json", receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (ImageAdmissionDenied, ValidationError, OSError, ValueError, TypeError, KeyError):
        # Public input may contain private garbage: never reflect its values/errors.
        print(json.dumps({"state": "NOT_READY", "error": "preparation_failed",
                          "signed": False, "live_changes": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
