#!/usr/bin/env python3
"""Exact-artifact P4 hostile acceptance entrypoint.

This wrapper preserves the complete P4 hostile acceptance workflow while
replacing only the public-verifier container invocation. The verifier receives
three exact sealed runner artifacts as read-only file mounts and no broad
workspace mount or private signing material.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
LEGACY_HARNESS = ROOT / "scripts" / "p4_hostile_acceptance.py"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_harness() -> Any:
    spec = importlib.util.spec_from_file_location("p4_hostile_acceptance_core", LEGACY_HARNESS)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load P4 harness: {LEGACY_HARNESS}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_wrapper_paths(arguments: list[str]) -> tuple[Path, Path]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--sealed-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parsed, _ = parser.parse_known_args(arguments)
    return parsed.sealed_manifest.resolve(strict=True), parsed.output.resolve()


def resolve_runner_artifacts(harness: Any, sealed_manifest_path: Path) -> dict[str, Path]:
    document = harness.P4ImageManifest.model_validate_json(
        sealed_manifest_path.read_text(encoding="utf-8")
    )
    matches = [
        item
        for item in document.records
        if item.role is harness.ImageRole.RUNNER and item.variant == "a"
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one sealed runner/a record, observed {len(matches)}")
    record = matches[0]
    parent = sealed_manifest_path.parent
    artifacts = {
        "attestation": (parent / record.attestation.path).resolve(strict=True),
        "policy": (parent / record.admission_policy.path).resolve(strict=True),
        "sbom": (parent / record.sbom.path).resolve(strict=True),
    }
    for name, path in artifacts.items():
        if not path.is_file():
            raise RuntimeError(f"public verifier artifact is not a file: {name}:{path}")
    expected = {
        "attestation": record.attestation.sha256,
        "policy": record.admission_policy.sha256,
        "sbom": record.sbom.sha256,
    }
    for name, path in artifacts.items():
        observed = sha256_file(path)
        if observed != expected[name]:
            raise RuntimeError(
                f"public verifier artifact hash mismatch: {name}:expected={expected[name]}:observed={observed}"
            )
    return artifacts


def make_execute_container_override(
    original: Callable[..., dict[str, Any]],
    *,
    artifacts: dict[str, Path],
    capture: dict[str, Any],
) -> Callable[..., dict[str, Any]]:
    targets = {
        "attestation": "/input/runner.attestation.json",
        "policy": "/input/runner.admission-policy.json",
        "sbom": "/input/runner.spdx.json",
    }
    if set(artifacts) != set(targets):
        raise RuntimeError(f"public verifier artifact set mismatch: {sorted(artifacts)}")

    def execute_container_exact(**kwargs: Any) -> dict[str, Any]:
        if kwargs.get("role") != "verifier" or kwargs.get("case") != "public-verify":
            return original(**kwargs)
        mounts = [
            (artifacts[name].resolve(strict=True), target, True)
            for name, target in targets.items()
        ]
        kwargs.update(
            mounts=mounts,
            timeout_seconds=60,
            memory="256m",
            pids=64,
            workspace_size="8m",
            nofile=256,
        )
        result = original(**kwargs)
        capture.clear()
        capture.update(
            {
                "result": result,
                "artifacts": {
                    name: {
                        "source": str(artifacts[name]),
                        "target": targets[name],
                        "sha256": sha256_file(artifacts[name]),
                        "read_only": True,
                    }
                    for name in targets
                },
                "execution_limits": {
                    "timeout_seconds": 60,
                    "memory": "256m",
                    "pids": 64,
                    "workspace_size": "8m",
                    "nofile": 256,
                },
                "private_key_mounted": False,
            }
        )
        return result

    return execute_container_exact


def enrich_report(
    *,
    output_path: Path,
    harness: Any,
    capture: dict[str, Any],
    return_code: int,
) -> dict[str, Any]:
    if not output_path.is_file():
        raise RuntimeError(f"P4 harness did not produce an output report: {output_path}")
    report = json.loads(output_path.read_text(encoding="utf-8"))
    report["harness"] = {
        "path": str(HERE),
        "sha256": sha256_file(HERE),
        "core_path": str(LEGACY_HARNESS),
        "core_sha256": sha256_file(LEGACY_HARNESS),
    }
    if capture:
        result = capture["result"]
        output = harness.parse_last_json(result.get("logs", ""))
        passed = (
            result.get("exit_code") == 0
            and result.get("timed_out") is False
            and result.get("oom_killed") is False
            and all((result.get("containment") or {}).values())
            and output.get("passed") is True
            and output.get("private_key_loaded") is False
            and output.get("sbom_valid") is True
            and (output.get("admission") or {}).get("allowed") is True
        )
        report.setdefault("service_runtime", {})["verifier"] = {
            "exit_code": result.get("exit_code"),
            "timed_out": result.get("timed_out"),
            "oom_killed": result.get("oom_killed"),
            "logs_sha256": hashlib.sha256(
                result.get("logs", "").encode("utf-8", errors="replace")
            ).hexdigest(),
            "sanitized_logs": result.get("sanitized_logs"),
            "containment": result.get("containment"),
            "artifacts": capture["artifacts"],
            "execution_limits": capture["execution_limits"],
            "output": output,
            "private_key_mounted": False,
            "passed": passed,
        }
        report.setdefault("checks", {})["public_verifier_passed"] = passed
        if not passed:
            report["passed"] = False
            report["run_outcome"] = "INFRA_FAILED"
            report["release_verdict"] = "NOT_READY"
            report["error"] = {
                "type": "PublicVerifierFailure",
                "message": "exact-artifact public verifier probe failed",
            }
            return_code = 1
    else:
        report.setdefault("checks", {})["public_verifier_passed"] = False
        report["passed"] = False
        report["run_outcome"] = "INFRA_FAILED"
        report["release_verdict"] = "NOT_READY"
        report.setdefault(
            "error",
            {
                "type": "PublicVerifierNotReached",
                "message": "public verifier invocation was not observed",
            },
        )
        return_code = 1
    report["wrapper_return_code"] = return_code
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(arguments: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if arguments is None else arguments)
    sealed_manifest_path, output_path = parse_wrapper_paths(argv)
    harness = load_harness()
    artifacts = resolve_runner_artifacts(harness, sealed_manifest_path)
    capture: dict[str, Any] = {}
    harness.execute_container = make_execute_container_override(
        harness.execute_container,
        artifacts=artifacts,
        capture=capture,
    )
    original_argv = sys.argv
    try:
        sys.argv = [str(HERE), *argv]
        with contextlib.redirect_stdout(io.StringIO()):
            return_code = int(harness.main())
    finally:
        sys.argv = original_argv
    report = enrich_report(
        output_path=output_path,
        harness=harness,
        capture=capture,
        return_code=return_code,
    )
    final_code = 0 if report.get("passed") is True and report.get("run_outcome") == "COMPLETE" else 1
    print(
        json.dumps(
            {
                "output": str(output_path),
                "bytes": output_path.stat().st_size,
                "sha256": sha256_file(output_path),
                "harness_sha256": sha256_file(HERE),
                "core_harness_sha256": sha256_file(LEGACY_HARNESS),
                "passed": report.get("passed"),
                "run_outcome": report.get("run_outcome"),
                "release_verdict": report.get("release_verdict"),
                "failed_checks": sorted(
                    name for name, passed in report.get("checks", {}).items() if not passed
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return final_code


if __name__ == "__main__":
    raise SystemExit(main())
