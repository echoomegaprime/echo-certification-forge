#!/usr/bin/env python3
"""Run SPEC section 48 and emit the signed whole-product readiness report."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from echo_certification_forge.canonical import sha256_bytes, to_utc_iso
from echo_certification_forge.master_acceptance import MasterAcceptanceRunner
from echo_certification_forge.product_readiness import create_product_readiness_envelope
from echo_certification_forge.sandbox import DEFAULT_IMAGE, DockerSandbox
from echo_certification_forge.signing import Ed25519VerdictSigner


def _load(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"acceptance evidence must be an object: {path}")
    return value, sha256_bytes(raw)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _generic_passed(value: dict[str, Any], phase: str) -> None:
    _require(value.get("passed") is True, f"{phase} acceptance is not passed")


def _complete_passed(value: dict[str, Any], phase: str) -> None:
    _generic_passed(value, phase)
    _require(value.get("run_outcome") == "COMPLETE", f"{phase} run did not complete")


def _p4(value: dict[str, Any], *, now: datetime | None = None) -> None:
    _require(value.get("completed_phase_gate") == "P4", "P4 gate is incomplete")
    _require(value.get("run_outcome") == "COMPLETE", "P4 run did not complete")
    _generic_passed(value, "P4")
    _require(value.get("release_verdict") == "NOT_READY", "P4 phase verdict must remain NOT_READY")
    checks = value.get("checks")
    _require(isinstance(checks, dict) and bool(checks)
             and all(item is True for item in checks.values()), "P4 checks are incomplete")
    for name in ("current_official_definitions_authenticated", "definition_profile_bytes_bound"):
        _require(checks.get(name) is True, f"P4 definition check missing: {name}")

    tools = value.get("tools")
    _require(isinstance(tools, dict), "P4 definition tools are missing")
    authenticated = tools.get("clamav_database_profile")
    _require(isinstance(authenticated, dict) and authenticated.get("passed") is True,
             "P4 definition vendor authentication is incomplete")
    profile = authenticated.get("profile")
    _require(isinstance(profile, dict), "P4 definition profile is missing")
    digest = profile.get("manifest_sha256")
    _require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
             "P4 definition manifest digest is invalid")
    engine = profile.get("engine_reference")
    _require(isinstance(engine, str)
             and re.fullmatch(r"clamav/clamav@sha256:[0-9a-f]{64}", engine) is not None
             and tools.get("clamav_image") == engine, "P4 definition engine identity mismatch")
    _require(profile.get("daily_max_age_seconds") == 172800
             and profile.get("future_clock_skew_seconds") == 300,
             "P4 definition freshness policy changed")
    files, databases = profile.get("files"), profile.get("databases")
    _require(isinstance(files, dict) and isinstance(databases, dict)
             and set(databases) == {"main", "daily", "bytecode"},
             "P4 definition database inventory is incomplete")
    expected_files: set[str] = set()
    expected_commands: dict[tuple[str, str], tuple[str, list[str], str]] = {}
    current = now or datetime.now(UTC)
    _require(current.tzinfo is not None, "P4 definition clock must be timezone aware")
    qualified = authenticated.get("qualified_at_utc")
    _require(isinstance(qualified, str), "P4 definition qualification timestamp is missing")
    try:
        qualified_time = datetime.fromisoformat(qualified.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("P4 definition qualification timestamp is invalid") from exc
    _require(qualified_time.tzinfo is not None and qualified_time.utcoffset() is not None,
             "P4 definition qualification timestamp must be timezone aware")
    _require(qualified_time.timestamp() <= current.timestamp() + 300,
             "P4 definition qualification timestamp is in the future")
    for name, identity in databases.items():
        _require(isinstance(identity, dict), "P4 definition database identity is invalid")
        path = identity.get("path")
        _require(path in (f"{name}.cvd", f"{name}.cld"), "P4 definition database path is invalid")
        _require(all(type(identity.get(field)) is int and identity[field] > 0
                     for field in ("version", "signatures", "build_epoch"))
                 and type(identity.get("required_functionality_level")) is int
                 and identity["required_functionality_level"] >= 0,
                 "P4 definition database numbers are invalid")
        _require(isinstance(identity.get("header_sha256"), str)
                 and re.fullmatch(r"[0-9a-f]{64}", identity["header_sha256"]) is not None,
                 "P4 definition header digest is invalid")
        _require(identity["build_epoch"] <= qualified_time.timestamp() + 300,
                 "P4 definition qualification predates database generation")
        _require(identity["build_epoch"] <= current.timestamp() + 300,
                 "P4 definition timestamp is in the future")
        if name == "daily":
            _require(current.timestamp() - identity["build_epoch"] <= 172800,
                     "P4 daily definitions are stale")
        expected_files.add(path)
        target = "/var/lib/clamav/" + path
        expected_commands[(name, "container")] = (
            path, ["sigtool", "--fips-limits", "--info=" + target], "verification ok.")
        if path.endswith(".cvd"):
            expected_files.add(f'{name}-{identity["version"]}.cvd.sign')
            expected_commands[(name, "detached")] = (
                path, ["sigtool", "--verify=" + target], "successfully verified")
    _require(set(files) == expected_files, "P4 definition file inventory mismatch")
    for name, record in files.items():
        _require(isinstance(record, dict) and record.get("path") == name
                 and type(record.get("size_bytes")) is int
                 and 0 < record["size_bytes"] <= 512 * 1024 * 1024
                 and isinstance(record.get("sha256"), str)
                 and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None,
                 "P4 definition file identity is invalid")

    commands = authenticated.get("commands")
    _require(isinstance(commands, list) and len(commands) == len(expected_commands),
             "P4 definition authentication coverage is incomplete")
    observed: set[tuple[str, str]] = set()
    for command in commands:
        _require(isinstance(command, dict), "P4 definition authentication command is invalid")
        name, kind = command.get("database"), command.get("kind")
        _require(isinstance(name, str) and isinstance(kind, str),
                 "P4 definition authentication identity is invalid")
        key = (name, kind)
        _require(key in expected_commands and key not in observed,
                 "P4 definition authentication coverage mismatch")
        observed.add(key)
        path, argv, marker = expected_commands[key]
        logs = command.get("sanitized_logs")
        _require(command.get("path") == path and command.get("argv") == argv,
                 "P4 definition authentication command drift")
        _require(type(command.get("exit_code")) is int and command["exit_code"] == 0
                 and command.get("passed") is True and command.get("readonly_mount_verified") is True,
                 "P4 definition authentication failed")
        _require(isinstance(command.get("logs_sha256"), str)
                 and re.fullmatch(r"[0-9a-f]{64}", command["logs_sha256"]) is not None
                 and isinstance(logs, str) and marker in logs.casefold()
                 and "unsigned" not in logs.casefold()
                 and "this version of the clamav engine is outdated." not in logs.casefold(),
                 "P4 definition authenticated output is missing")
    _require(observed == set(expected_commands), "P4 definition authentication coverage is incomplete")

    images = value.get("images")
    _require(isinstance(images, dict)
             and set(images) == {"runner", "custody", "anchor", "signer", "worker", "verifier"},
             "P4 definition scan role coverage is incomplete")
    for image in images.values():
        _require(isinstance(image, dict), "P4 image scan record is invalid")
        scan = image.get("malware_scan")
        _require(isinstance(scan, dict) and scan.get("passed") is True
                 and type(scan.get("exit_code")) is int and scan["exit_code"] == 0
                 and scan.get("scanner_image") == engine, "P4 definition scanner identity or outcome failed")
        bound = scan.get("database_profile")
        _require(isinstance(bound, dict) and bound.get("manifest_sha256") == digest
                 and bound.get("files") == files
                 and all(bound.get(flag) is True for flag in
                         ("readonly_mount_verified", "official_db_only", "pre_post_bytes_verified")),
                 "P4 definition scan bytes or containment binding failed")


def _p5(value: dict[str, Any]) -> None:
    _require(value.get("adapter_gate_eligible") is True, "P5 adapter gate is ineligible")
    _require(value.get("adapter_gate") == "GO", "P5 adapter gate is not GO")
    _require(sorted(value.get("accepted_adapters", [])) == ["gs343", "r2d2"], "P5 adapter set is incomplete")
    records = value.get("records")
    _require(isinstance(records, list) and len(records) == 2, "P5 records are incomplete")
    for record in records:
        identity = record.get("identity", {})
        quality = record.get("quality", {})
        _require(identity.get("maturity") == "STABLE", "P5 adapter is not STABLE")
        _require(quality.get("passed_cases") == quality.get("total_cases") == 240, "P5 quality suite is incomplete")
        _require(not quality.get("critical_failures"), "P5 adapter has critical failures")


def _p6(value: dict[str, Any]) -> None:
    _generic_passed(value, "P6")
    _require(value.get("checks_total") == value.get("checks_passed") == 12, "P6 checks are incomplete")


def _p7(value: dict[str, Any]) -> None:
    _generic_passed(value, "P7")
    scenarios = value.get("scenarios")
    _require(isinstance(scenarios, dict) and scenarios, "P7 scenarios are missing")
    _require(all(item.get("passed") is True for item in scenarios.values()), "P7 scenario failure")


def _sdk(value: dict[str, Any]) -> None:
    capabilities = value.get("capabilities")
    _require(value.get("capability_count") == 62, "SDK contract must contain exactly 62 capabilities")
    _require(isinstance(capabilities, dict) and len(capabilities) == 62, "SDK capability rows are incomplete")
    names = list(capabilities)
    _require(len(set(names)) == 62, "SDK capability IDs are not unique")
    _require(all(isinstance(name, str) and name.startswith("echo.cert") for name in names), "SDK capability namespace drift")
    _require(
        all(
            isinstance(row, dict)
            and isinstance(row.get("operation"), str)
            and isinstance(row.get("input_schema"), dict)
            and isinstance(row.get("output_schema"), dict)
            for row in capabilities.values()
        ),
        "SDK capability contract rows are malformed",
    )


def _ci(value: dict[str, Any], source_commit: str) -> None:
    status = value.get("status")
    conclusion = value.get("conclusion")
    head = value.get("headSha", value.get("head_sha"))
    _require(status == "completed", "hosted CI run is not complete")
    _require(conclusion == "success", "hosted CI run is not successful")
    _require(head == source_commit, "hosted CI did not test the exact source commit")


def _gate(
    name: str,
    path: Path,
    validator: Callable[[dict[str, Any]], None],
) -> dict[str, str]:
    value, digest = _load(path)
    validator(value)
    return {"state": "COMPLETE", "evidence_sha256": digest}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree-sha256", required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--vulnerability-policy", type=Path, required=True)
    parser.add_argument("--rule-manifest", type=Path, required=True)
    parser.add_argument("--p1", type=Path, required=True)
    parser.add_argument("--p2", type=Path, required=True)
    parser.add_argument("--p3", type=Path, required=True)
    parser.add_argument("--p4", type=Path, required=True)
    parser.add_argument("--p5", type=Path, required=True)
    parser.add_argument("--p6", type=Path, required=True)
    parser.add_argument("--p7", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--ci", type=Path, required=True)
    parser.add_argument("--sandbox-image", default=DEFAULT_IMAGE)
    parser.add_argument("--run-id")
    parser.add_argument("--valid-days", type=int, default=30)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Reject incomplete supplied evidence before reading any private signing key
    # or executing MASTER. P4 freshness uses the current admission clock.
    gates = {
        "P1": _gate("P1", args.p1, lambda value: _generic_passed(value, "P1")),
        "P2": _gate("P2", args.p2, lambda value: _complete_passed(value, "P2")),
        "P3": _gate("P3", args.p3, lambda value: _complete_passed(value, "P3")),
        "P4": _gate("P4", args.p4, _p4),
        "P5": _gate("P5", args.p5, _p5),
        "P6": _gate("P6", args.p6, _p6),
        "P7": _gate("P7", args.p7, _p7),
        "SDK": _gate("SDK", args.sdk, _sdk),
        "CI": _gate("CI", args.ci, lambda value: _ci(value, args.source_commit)),
    }
    signer = Ed25519VerdictSigner.from_private_pem(args.signing_key.read_bytes())
    timestamp = datetime.now(UTC)
    run_id = args.run_id or "master-" + timestamp.strftime("%Y%m%dT%H%M%SZ")
    args.output.mkdir(parents=True, exist_ok=True)
    runner = MasterAcceptanceRunner(
        fixture_root=args.fixture,
        vulnerability_policy=args.vulnerability_policy,
        rule_manifest=args.rule_manifest,
        output_directory=args.output / run_id,
        signer=signer,
        sandbox=DockerSandbox(image=args.sandbox_image),
        source_commit=args.source_commit,
    )
    master = runner.run(run_id)

    gates["MASTER"] = {
        "state": "COMPLETE",
        "evidence_sha256": sha256_bytes(Path(master.artifact_path).read_bytes()),
    }
    envelope = create_product_readiness_envelope(
        signer=signer,
        source_commit=args.source_commit,
        source_tree_sha256=args.source_tree_sha256,
        generated_at=to_utc_iso(timestamp),
        expires_at=to_utc_iso(timestamp + timedelta(days=args.valid_days)),
        gates=gates,
        master_run=master.product_binding(),
    )
    report = args.output / "product-readiness.json"
    report.write_text(json.dumps(asdict(envelope), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "passed": True,
        "release_verdict": "PRODUCTION_READY",
        "source_commit": args.source_commit,
        "master_run_id": master.run_id,
        "report": str(report),
        "report_sha256": sha256_bytes(report.read_bytes()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"passed": False, "error": type(error).__name__, "detail": str(error)}), file=sys.stderr)
        raise SystemExit(1)
