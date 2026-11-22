#!/usr/bin/env python3
"""Verify P4 public-verifier and service-readiness hardening evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "artifacts/p4_forge_acceptance.json"
EXPECTED_TARGETS = {
    "attestation": "/input/runner.attestation.json",
    "policy": "/input/runner.admission-policy.json",
    "sbom": "/input/runner.spdx.json",
}
EXPECTED_LIMITS = {
    "timeout_seconds": 60,
    "memory": "256m",
    "pids": 64,
    "workspace_size": "8m",
    "nofile": 256,
}
EXPECTED_SERVICE_DEADLINE_SECONDS = 30


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, failures: list[str], reason: str) -> None:
    if not condition:
        failures.append(reason)


def verify_report(report_path: Path) -> dict[str, Any]:
    failures: list[str] = []
    details: dict[str, Any] = {}
    require(report_path.is_file(), failures, "acceptance_report_missing")
    if failures:
        return {"passed": False, "failures": failures, "details": details}

    report = json.loads(report_path.read_text(encoding="utf-8"))
    require(report.get("passed") is True, failures, "acceptance_not_passed")
    require(report.get("run_outcome") == "COMPLETE", failures, "run_outcome_invalid")
    require(report.get("release_verdict") == "NOT_READY", failures, "release_verdict_not_fail_closed")

    harness = report.get("harness") or {}
    require(
        harness.get("service_health_deadline_seconds") == EXPECTED_SERVICE_DEADLINE_SECONDS,
        failures,
        "service_health_deadline_invalid",
    )
    for prefix in ("", "core_"):
        path_value = harness.get(prefix + "path")
        expected_hash = harness.get(prefix + "sha256")
        path = Path(path_value).resolve() if path_value else None
        require(path is not None and path.is_file(), failures, prefix + "harness_missing")
        if path is not None and path.is_file():
            require(
                sha256_file(path) == expected_hash,
                failures,
                prefix + "harness_hash_mismatch",
            )

    verifier = ((report.get("service_runtime") or {}).get("verifier") or {})
    require(verifier.get("passed") is True, failures, "public_verifier_failed")
    require(verifier.get("exit_code") == 0, failures, "public_verifier_exit_nonzero")
    require(verifier.get("timed_out") is False, failures, "public_verifier_timed_out")
    require(verifier.get("oom_killed") is False, failures, "public_verifier_oom_killed")
    require(verifier.get("private_key_mounted") is False, failures, "private_key_mounted")
    require(
        verifier.get("execution_limits") == EXPECTED_LIMITS,
        failures,
        "public_verifier_limits_invalid",
    )
    containment = verifier.get("containment") or {}
    require(bool(containment) and all(containment.values()), failures, "public_verifier_containment_failed")

    artifacts = verifier.get("artifacts") or {}
    require(set(artifacts) == set(EXPECTED_TARGETS), failures, "public_verifier_artifact_set_invalid")
    artifact_results: dict[str, Any] = {}
    for name, target in EXPECTED_TARGETS.items():
        item = artifacts.get(name) or {}
        source_value = item.get("source")
        source = Path(source_value).resolve() if source_value else None
        exists = source is not None and source.is_file()
        actual_sha = sha256_file(source) if exists and source is not None else None
        passed = (
            exists
            and item.get("target") == target
            and item.get("read_only") is True
            and actual_sha == item.get("sha256")
        )
        require(passed, failures, f"public_verifier_artifact_invalid:{name}")
        artifact_results[name] = {
            "source": str(source) if source is not None else None,
            "target": item.get("target"),
            "read_only": item.get("read_only"),
            "expected_sha256": item.get("sha256"),
            "actual_sha256": actual_sha,
            "passed": passed,
        }
    details["artifacts"] = artifact_results

    output = verifier.get("output") or {}
    require(output.get("passed") is True, failures, "verifier_cli_not_passed")
    require(output.get("private_key_loaded") is False, failures, "verifier_cli_loaded_private_key")
    require(output.get("sbom_valid") is True, failures, "verifier_cli_sbom_invalid")
    require((output.get("admission") or {}).get("allowed") is True, failures, "verifier_cli_admission_denied")

    checks = report.get("checks") or {}
    require(checks.get("public_verifier_passed") is True, failures, "public_verifier_check_missing")
    require(
        checks.get("bounded_service_health_deadline_recorded") is True,
        failures,
        "service_deadline_check_missing",
    )
    require(bool(checks) and all(checks.values()), failures, "acceptance_checks_not_all_green")

    cleanup = report.get("cleanup") or {}
    require(cleanup.get("unrelated_container_ids_preserved") is True, failures, "unrelated_containers_changed")
    require(cleanup.get("ephemeral_private_files_removed") is True, failures, "private_files_not_removed")
    require(not cleanup.get("residual_private_paths"), failures, "residual_private_paths")

    details.update(
        {
            "harness": harness,
            "verifier_limits": verifier.get("execution_limits"),
            "containment": containment,
            "check_count": len(checks),
        }
    )
    return {"passed": not failures, "failures": sorted(set(failures)), "details": details}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report_path = args.report.resolve()
    verification = verify_report(report_path)
    result = {
        "schema_version": "1.0.0",
        "phase": "P4",
        "verified_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "report": str(report_path),
        "report_sha256": sha256_file(report_path) if report_path.is_file() else None,
        "release_verdict": "NOT_READY",
        **verification,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
