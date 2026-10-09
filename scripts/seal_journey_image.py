#!/usr/bin/env python3
"""Admitted FORGE control-plane owner only: seal one reviewed image with its existing P4 key.

No key generation, bootstrap, policy installation, service restart or runner access.
Run only after independent exact-request review and owner admission. The supplied
digest binds that review; it is not a replacement for authenticated authorization.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from datetime import timedelta
from pathlib import Path

from prepare_journey_image_admission import plain_path, read_bounded, write_new
from seal_p4_images import load_private_key

from echo_certification_forge.journey_image_admission import (
    JourneyAdmissionRequest, proposed_policy, seal_admission_request, verify_current_authority,
)
from echo_certification_forge.supply_chain import (
    ImageAdmissionDenied, ImageAdmissionPolicy, ImageAttestation, ImageAttestationAuthority,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--approved-request-sha256',required=True)
    parser.add_argument('--attestation-private-key',type=Path,required=True)
    parser.add_argument('--current-policy',type=Path,required=True)
    parser.add_argument('--current-attestation',type=Path,required=True)
    parser.add_argument('--valid-days',type=int,default=7)
    parser.add_argument('--output-dir',type=Path,required=True)
    args = parser.parse_args()
    try:
        request = JourneyAdmissionRequest.model_validate_json(read_bounded(args.request))
        if request.digest != args.approved_request_sha256:
            raise ImageAdmissionDenied('reviewed_request_mismatch')
        proposed_policy(request)
        verify_current_authority(request,
            ImageAdmissionPolicy.model_validate_json(read_bounded(args.current_policy)),
            ImageAttestation.model_validate_json(read_bounded(args.current_attestation)))
        # The existing P4 custody is POSIX, owner-only. No mode changes or copies.
        if os.name != 'posix':
            raise ImageAdmissionDenied('control_plane_platform_required')
        path = plain_path(args.attestation_private_key)
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise ImageAdmissionDenied('existing_key_custody_invalid')
        plain_path(args.output_dir.parent)
        if args.output_dir.exists():
            raise ImageAdmissionDenied('new_output_required')
        # Reuse the existing P4 loader only inside the admitted control plane.
        # The key object is never serialized, printed, passed to a child or worker.
        authority = ImageAttestationAuthority(load_private_key(path, expected_stat=info))
        # Re-read the actual owner files immediately before the signing guard.
        # Owner serialization must span these reads, signing and output creation.
        current_policy = ImageAdmissionPolicy.model_validate_json(read_bounded(args.current_policy))
        current_attestation = ImageAttestation.model_validate_json(read_bounded(args.current_attestation))
        attestation, policy = seal_admission_request(request,authority=authority,
            current_policy=current_policy,current_attestation=current_attestation,
            approved_request_sha256=args.approved_request_sha256,
            valid_for=timedelta(days=args.valid_days))
        args.output_dir.mkdir(exist_ok=False)
        attestation_hash = write_new(args.output_dir/'runner.attestation.json',attestation.model_dump(mode='json'))
        policy_hash = write_new(args.output_dir/'runner.admission-policy.json',policy.model_dump(mode='json'))
        receipt = {'state':'SEALED_NOT_INSTALLED','request_digest':request.digest,
                   'image_digest':request.identity.image_digest,'key_id':attestation.key_id,
                   'attestation_sha256':attestation_hash,'policy_sha256':policy_hash,
                   'policy_id':policy.policy_id,'expires_at':attestation.expires_at.isoformat(),
                   'live_changes':False,'source_certified':False,'production_ready':False}
        write_new(args.output_dir/'sealing-receipt.json',receipt)
        print(json.dumps(receipt,sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, RuntimeError):
        print(json.dumps({'state':'NOT_READY','error':'sealing_failed',
                          'live_changes':False,'production_ready':False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
