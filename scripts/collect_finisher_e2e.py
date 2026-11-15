#!/usr/bin/env python3
"""Run the owner-admitted Finisher collector; output is never a signed verdict."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from echo_certification_forge.finisher_collector import (  # noqa: E402
    CollectorError, FinisherCollector, PinnedOwnerProbe, bounded_document, require,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        require(os.name == "posix", "collector_platform_unsupported")
        require(args.policy.is_absolute() and not args.policy.is_symlink(), "policy_path_invalid")
        descriptor = os.open(args.policy, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 65536, "policy_file_invalid")
            require(metadata.st_uid in (0, os.geteuid()) and not metadata.st_mode & 0o022, "policy_file_permissions")
            raw = handle.read(65537)
        require(hashlib.sha256(raw).hexdigest() == args.policy_sha256, "policy_pin_mismatch")
        policy = bounded_document(raw, 65536)
        probe = policy.get("probe")
        require(isinstance(probe, dict), "owner_probe_unconfigured")
        require(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), "output_path_invalid")
        parent = args.output.parent
        require(parent.resolve(strict=True) == parent and parent.is_dir(), "output_parent_invalid")
        metadata = parent.stat()
        require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o077, "output_parent_not_private")
        owner = PinnedOwnerProbe(probe.get("command"), probe.get("sha256"),
                                 dependencies=probe.get("dependencies"), timeout=probe.get("timeout", 120))
        result = FinisherCollector(policy, owner).collect()
        data = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        print(json.dumps({"status": "UNSIGNED_CANDIDATE", "release_verdict": "NOT_READY",
                          "signature_verified": False, "sha256": hashlib.sha256(data).hexdigest(),
                          "observations": len(result["evidence"])}))
        return 0
    except CollectorError as exc:
        print(json.dumps({"status": "HELD", "release_verdict": "NOT_READY", "reason": str(exc)}))
        return 2
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "HELD", "release_verdict": "NOT_READY", "reason": "collector_input_or_io_failed"}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
