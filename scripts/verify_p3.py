#!/usr/bin/env python3
"""Deterministic P3 closure verifier and evidence package generator."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
FULL_REPORT = ARTIFACTS / "p3_forge_acceptance.json"
SUMMARY_REPORT = ARTIFACTS / "p3_forge_acceptance.summary.json"
OFFLINE_ROOT = ARTIFACTS / "p3_offline_bundle"
VERIFICATION_REPORT = ARTIFACTS / "p3_verification_report.json"

# Pins below are the golden evidence from the real FORGE P3 re-cert on 2026-07-18
# after the reviewed signer image-identity fix (commits 307667a, 5ec68c8). They were
# derived from a fresh p3_forge_acceptance.py run (not hand-edited hashes alone).
EXPECTED_REPORT_BYTES = 27322
EXPECTED_REPORT_SHA256 = "e805e6b9913a8a3712fee4710aec5d6b180b149ed2e729723bb178e7327a1ee6"
EXPECTED_SOURCE_COMMIT = "cbb46be008bb611fe0211eb8fbeb30cdc1cd4405"
EXPECTED_RUNNER_IMAGE = "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
EXPECTED_ISOLATION_PROFILE = "f0722821d2658705626bca74623438db30416de174ead34df15588b80dcc72bc"
EXPECTED_SIGNER_IMAGE = (
    "ghcr.io/home-assistant/home-assistant@"
    "sha256:f73512ba4fe06bb4d57636fe3578d0820cdec46f81e8f837ab59e451662ff3cb"
)
EXPECTED_SIGNER_IMAGE_DIGEST = "sha256:f73512ba4fe06bb4d57636fe3578d0820cdec46f81e8f837ab59e451662ff3cb"

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "phase",
    "started_at_utc",
    "completed_at_utc",
    "host",
    "source_identity",
    "p2_runner_image_digest",
    "p2_isolation_profile_digest",
    "custody",
    "anchor",
    "signing",
    "checks",
    "cleanup",
    "passed",
    "run_outcome",
    "release_verdict",
}
EXPECTED_CHECKS = {
    "all_key_domains_distinct",
    "anchor_duplicate_idempotent",
    "anchor_health",
    "anchor_outage_observed",
    "anchor_restart_verified",
    "anchor_storage_independent",
    "anchor_verified",
    "compromise_invalidates_verdict",
    "conflicting_signing_request_denied",
    "cross_tenant_denied",
    "custody_has_no_verdict_key",
    "custody_health",
    "custody_restart_health",
    "custody_verified_before_anchor",
    "exact_private_key_bytes_absent_from_non_secret_files",
    "historical_verdict_after_rotation",
    "idempotent_signing_retry",
    "isolated_signing_succeeded",
    "modified_anchor_receipt_detected",
    "modified_evidence_after_anchor_detected",
    "offline_anchor_verified",
    "offline_verdict_verified",
    "partial_upload_detected",
    "partial_upload_resumed",
    "private_key_absent_from_outputs",
    "private_key_absent_from_service_logs",
    "restricted_evidence_authorized",
    "restricted_evidence_denied",
    "runner_crash_during_upload_denied",
    "runner_signing_request_denied",
    "signer_image_distinct_from_runner_image",
    "signing_database_contains_no_private_key",
    "signing_key_outage_denied",
    "signing_replay_denied",
}
EXPECTED_ACCEPTANCE_SOURCE = {
    "scripts/p3_forge_acceptance.py": "dc733b6af0b8b7589c3e2a9c2d1d1e7e8e819bab434dae9f32e5edd2eddccc94",
    "src/echo_certification_forge/anchor.py": "73f800e92e003a0ed09534075f49867f983d4d7ea8d3c2afbb3427219fa25353",
    "src/echo_certification_forge/custody.py": "d2bc817cd1c452937988e0103ce9d79b04681a6a52adfafc837f7cfec5c91fbd",
    "src/echo_certification_forge/p3_runtime.py": "3ae4a5984d3b578d537e1357f9fc6d2fd1e7eead871cddbd2b90f886022c6d90",
    "src/echo_certification_forge/p3_service.py": "4995b4840391026955ba284831b5b3a7f3ad43195329256ec5ee195ccc1f4401",
    "src/echo_certification_forge/signer_cli.py": "be26768f59a8a5b163a2a1198f198df29107fca4790e81b603a401fe01572654",
    "src/echo_certification_forge/signing_service.py": "f5701f02d7ae965e8096708b6048f40f3e72f313a26e54c00002e9b9742320e9",
}
EXPECTED_CLOSURE_SOURCE = {
    "scripts/p3_forge_acceptance.py": "dc733b6af0b8b7589c3e2a9c2d1d1e7e8e819bab434dae9f32e5edd2eddccc94",
    "src/echo_certification_forge/anchor.py": "73f800e92e003a0ed09534075f49867f983d4d7ea8d3c2afbb3427219fa25353",
    "src/echo_certification_forge/custody.py": "d2bc817cd1c452937988e0103ce9d79b04681a6a52adfafc837f7cfec5c91fbd",
    "src/echo_certification_forge/p3_runtime.py": "3ae4a5984d3b578d537e1357f9fc6d2fd1e7eead871cddbd2b90f886022c6d90",
    "src/echo_certification_forge/p3_service.py": "4995b4840391026955ba284831b5b3a7f3ad43195329256ec5ee195ccc1f4401",
    "src/echo_certification_forge/signer_cli.py": "be26768f59a8a5b163a2a1198f198df29107fca4790e81b603a401fe01572654",
    "src/echo_certification_forge/signing_service.py": "f5701f02d7ae965e8096708b6048f40f3e72f313a26e54c00002e9b9742320e9",
    "contracts/certforge-capabilities.v1.json": "ba723dbe3c4bc0eb1926278314e41f932b65f0cf91e8c0fbefe4d8000d36f26c",
}
EXPECTED_OFFLINE_FILES = {
    "anchor-log.jsonl": (448, "f17a65ab14822d570d11feb7d81b136db493e6f507ca570778a50e56d5d6a7a1"),
    "anchor-public.pem": (113, "d4f908471d6d04de09f1c5204ec16d3773875c2e08c1d50bf8159f53689aaf3b"),
    "anchor-receipt.json": (1066, "48435cc80d7a9695a6544840e4eef2588c195940945c4d7046f10062b2bd718b"),
    "public-keys.json": (572, "69b1d1f6aaf821d77721367fa3b2637f4021f2a6c351824a82fcd06588cb90aa"),
    "signing-request.json": (3403, "436f50df1982e144c3f122295957250c2f1b7b787357ef18a5ef1a21c1d41b51"),
    "verdict.json": (1546, "d3415579b69b15354bf73f4dbf32dfd02fab268c11634227e2aef004532b6879"),
}
EXPECTED_CAPABILITIES = {
    "echo.certforge.health",
    "echo.certforge.submit",
    "echo.certforge.status",
    "echo.certforge.cancel",
    "echo.certforge.findings",
    "echo.certforge.evidence",
    "echo.certforge.verify",
    "echo.certforge.verdict",
    "echo.certforge.deploy_gate",
}
EXPECTED_CAPABILITY_FIELDS = {
    "id",
    "method",
    "path",
    "input_schema",
    "output_schema",
    "required_scope",
    "danger_tier",
    "authentication",
    "authorization",
    "timeout_seconds",
    "idempotency",
    "error_model",
    "redaction",
    "audit",
    "health_criteria",
}
EXPECTED_OWNED_CONTAINERS = {
    "5253f03a7f9acce5064a0424c67a47ace7760e76c4740418c19379fb6bcae144",
    "755142f4e99f08313125dff5a4b1bdf3b82f2831a85294477bf7da651069dda6",
    "916c671b388437abe40578e8a069ebfdcc7ff1bcc6ba66b0d6ad811aa071bf6b",
    "9e08885f415ccdeb2601b59d1ca8dac95952ed7a70ce9cd4f8aa13727585ca9a",
    "b918dfc250ee2e33084c331101a931cc0606fc7f0acd51b8c743a9b90cfc6afb",
    "dee20be4f5e9bb256f87915a58058a4f6f68c010d7849a8fbc3a69e989a2e8f1",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(actual == expected, f"{label} key mismatch: missing={sorted(expected-actual)} extra={sorted(actual-expected)}")


def run_check(name: str, command: list[str], log_name: str) -> dict[str, Any]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_path = ARTIFACTS / log_name
    log_path.write_text(result.stdout, encoding="utf-8")
    return {
        "name": name,
        "command": command,
        "exit_code": result.returncode,
        "log": str(log_path.relative_to(ROOT)).replace("\\", "/"),
        "log_sha256": sha256(log_path),
    }


def verify_source_identities() -> dict[str, Any]:
    current: dict[str, str] = {}
    for relative, expected in EXPECTED_CLOSURE_SOURCE.items():
        path = ROOT / relative
        require(path.is_file(), f"missing closure source: {relative}")
        digest = sha256(path)
        require(digest == expected, f"closure source identity mismatch: {relative}: {digest}")
        current[relative] = digest
    return {
        "acceptance_source": EXPECTED_ACCEPTANCE_SOURCE,
        "closure_source": current,
        "accepted_closure_delta": {
            "path": "scripts/p3_forge_acceptance.py",
            "reason": (
                "P3 re-certified 2026-07-18 after reviewed signer image-identity fix "
                "(307667a, 5ec68c8); acceptance re-run under corrected source so "
                "acceptance and closure identities match"
            ),
            "acceptance_sha256": EXPECTED_ACCEPTANCE_SOURCE["scripts/p3_forge_acceptance.py"],
            "closure_sha256": current["scripts/p3_forge_acceptance.py"],
        },
    }


def verify_full_report() -> dict[str, Any]:
    require(FULL_REPORT.is_file(), "missing imported P3 acceptance report")
    payload = FULL_REPORT.read_bytes()
    require(len(payload) == EXPECTED_REPORT_BYTES, "P3 acceptance report byte count mismatch")
    require(hashlib.sha256(payload).hexdigest() == EXPECTED_REPORT_SHA256, "P3 acceptance report hash mismatch")
    report = json.loads(payload)
    require(isinstance(report, dict), "P3 acceptance report must be an object")
    require_exact_keys(report, EXPECTED_TOP_LEVEL, "P3 report")
    require(report["schema_version"] == "1.0.0" and report["phase"] == "P3", "P3 report identity mismatch")
    require(report["passed"] is True, "P3 acceptance did not pass")
    require(report["run_outcome"] == "COMPLETE", "P3 run outcome is not COMPLETE")
    require(report["release_verdict"] == "NOT_READY", "P3 product verdict must remain NOT_READY")
    require(report["p2_runner_image_digest"] == EXPECTED_RUNNER_IMAGE, "P2 runner image digest mismatch")
    require(report["p2_isolation_profile_digest"] == EXPECTED_ISOLATION_PROFILE, "P2 isolation profile digest mismatch")
    require(report["source_identity"] == EXPECTED_ACCEPTANCE_SOURCE, "acceptance source manifest mismatch")

    host = report["host"]
    require(host["node"] == "forge" and host["uid"] == 1000 and host["gid"] == 1002, "FORGE host identity mismatch")
    require(str(host["platform"]).startswith("Linux-6.8.0-134"), "FORGE platform identity mismatch")

    checks = report["checks"]
    require_exact_keys(checks, EXPECTED_CHECKS, "P3 acceptance checks")
    failed_checks = sorted(name for name, passed in checks.items() if passed is not True)
    require(not failed_checks, f"P3 acceptance checks failed: {failed_checks}")

    custody = report["custody"]
    descriptor = custody["descriptor"]
    require(descriptor["sha256"] == "61d4fd7ed282d9c0cb3f358a35c521c3304149b70e56fea7260281121c996a74", "custody artifact digest mismatch")
    require(descriptor["leaf_hash"] == "e15e6fbf084d5923859d203a2f97b6d5e9a8f968ec38bb19c3d6b48cc59ad44f", "custody leaf hash mismatch")
    require(descriptor["manifest_sha256"] == "89bca0d2c87d848bde0aee52ad81f136aa43c55ca08806bc944620e09ac58abc", "custody manifest digest mismatch")
    require(descriptor["visibility"] == "RESTRICTED", "custody visibility mismatch")
    require(custody["audit_chain_tip"] == "3637f34a32c5f05adb32da6dae8b26cdd28650a487ab2360c204425ae2c7eccb", "custody audit-chain tip mismatch")
    require(custody["retention"]["legal_hold"] is True, "custody legal hold missing")
    before = custody["verification_before_anchor"]
    require(before["valid"] is True and before["merkle_root"] == descriptor["leaf_hash"], "pre-anchor custody verification failed")
    require(before["invalid_artifacts"] == [] and before["incomplete_artifacts"] == [], "pre-anchor custody evidence incomplete")
    after = custody["verification_after_tamper"]
    require(after["valid"] is False and after["invalid_artifacts"], "modified evidence was not detected")

    anchor = report["anchor"]
    require(anchor["provider_id"] == "anchor.p3.acceptance", "anchor provider mismatch")
    require(anchor["provider_key_id"] == "ed25519:1deacb149700b3240831959d9ecf1ea6", "anchor public-key id mismatch")
    require(anchor["receipt_id"] == "anchor.3d49d3001351aba6eb62c0a397e40a83", "anchor receipt id mismatch")
    require(anchor["receipt_hash"] == "860b43dfef222302a186a6c1c0935c8db62dffc712d42ce70173ac1d0e5cffe4", "anchor receipt digest mismatch")
    require(anchor["statement_sha256"] == "ad78a7f1d50f5a95fb732e5c3cb48aeba3635d8da86884646b77177aa25d1bb5", "anchor statement digest mismatch")
    require(anchor["chain_hash"] == "0d8e27ea82e60311ef96672954c2f2bb3d0e758893024fcc6fd90405df7e8b88", "anchor chain tip mismatch")
    require(anchor["offline_verification"] == {"reason": "verified", "valid": True}, "offline anchor verification mismatch")
    require(anchor["log"]["valid"] is True and anchor["log"]["chain_tip"] == anchor["chain_hash"], "anchor log invalid")
    require(anchor["health"]["storage_separate_from_custody_database"] is True, "anchor storage is not independent")
    require(anchor["tampered_receipt_verification"]["valid"] is False, "modified anchor receipt was not rejected")

    signing = report["signing"]
    require(signing["signer_image"] == EXPECTED_SIGNER_IMAGE, "signer image digest mismatch")
    require(signing["public_key_id"] == "ed25519:d4e68fd22fab12c91a146a55a24eaa95", "verdict public-key id mismatch")
    require(signing["authorization_key_id"] == "ed25519:3c88f9b6b9b77a1e7ac465df685522f3", "authorization public-key id mismatch")
    require(signing["anchor_provider_key_id"] == anchor["provider_key_id"], "anchor key binding mismatch")
    require(len({signing["public_key_id"], signing["authorization_key_id"], signing["anchor_provider_key_id"]}) == 3, "key domains are not distinct")
    require(signing["runner_has_signing_key_mount"] is False, "runner had a signing-key mount")
    require(signing["private_key_persisted_in_signing_database"] is False, "private key persisted in signing database")
    require(signing["verdict_signature_verified"] is True, "verdict signature did not verify")
    require(signing["offline_verification_reason"] == "verified", "offline verdict verification failed")
    require(signing["historical_after_rotation"] == {"reason": "verified", "valid": True}, "historical verdict failed after rotation")
    require(signing["after_compromise"] == {"reason": "signing_key_compromised", "valid": False}, "compromise did not invalidate verdict")

    cases = signing["cases"]
    require_exact_keys(cases, {"success", "idempotent_retry", "replay", "conflict", "runner_request", "key_unavailable"}, "signer cases")
    expected_case_results = {
        "success": (True, 0, '"ok":true'),
        "idempotent_retry": (True, 0, '"ok":true'),
        "replay": (False, 1, "signing_request_replay"),
        "conflict": (False, 1, "conflicting_idempotent_signing_request"),
        "runner_request": (False, 1, "only_control_plane_may_request_signing"),
        "key_unavailable": (False, 1, "missing-key.pem"),
    }
    for name, (passed, exit_code, log_token) in expected_case_results.items():
        case = cases[name]
        require(case["passed"] is passed, f"signer case result mismatch: {name}")
        require(case["state"]["ExitCode"] == exit_code, f"signer exit code mismatch: {name}")
        require(log_token in case["logs"], f"signer log evidence mismatch: {name}")
        require(case["image"] == EXPECTED_SIGNER_IMAGE_DIGEST, f"signer image mismatch: {name}")
        require(case["config_user"] == "1000:1002" and case["inspect_issues"] == [], f"signer identity/inspect mismatch: {name}")
        config = case["host_config"]
        require(config["ReadonlyRootfs"] is True and config["NetworkMode"] == "none", f"signer filesystem/network containment mismatch: {name}")
        require(config["CapDrop"] == ["ALL"] and config["PidsLimit"] == 32, f"signer capability/PID containment mismatch: {name}")
        require(config["Memory"] == 268435456 and config["MemorySwap"] == 268435456, f"signer memory containment mismatch: {name}")
        require(config["NanoCpus"] == 250000000, f"signer CPU containment mismatch: {name}")
        require(set(config["SecurityOpt"]) == {"no-new-privileges:true", "seccomp=builtin", "apparmor=docker-default"}, f"signer security options mismatch: {name}")
        mount_targets = {item["Target"]: item for item in config["Mounts"]}
        require(set(mount_targets) == {"/app/src", "/input", "/output"}, f"signer mount set mismatch: {name}")
        require(mount_targets["/app/src"].get("ReadOnly") is True and mount_targets["/input"].get("ReadOnly") is True, f"signer input mounts not read-only: {name}")
        require("docker.sock" not in json.dumps(config), f"Docker socket exposed to signer: {name}")

    cleanup = report["cleanup"]
    require(set(cleanup["owned_container_ids"]) == EXPECTED_OWNED_CONTAINERS, "owned-container cleanup set mismatch")
    require(cleanup["container_cleanup_errors"] == [], "container cleanup errors present")
    require(cleanup["containers_before"] == 22 and cleanup["containers_after"] == 22, "unrelated container count changed")
    require(cleanup["unrelated_container_ids_preserved"] is True, "unrelated containers were not preserved")
    require(cleanup["custody_service"] == {"pid": 718998, "returncode": -15, "stopped": True}, "custody service cleanup mismatch")
    require(cleanup["anchor_service"] == {"pid": 719042, "returncode": -15, "stopped": True}, "anchor service cleanup mismatch")
    require(len(cleanup["private_key_files_removed"]) == 2 and all(cleanup["private_key_files_removed"].values()), "ephemeral private-key removal mismatch")
    return report


def verify_offline_material(report: dict[str, Any]) -> dict[str, Any]:
    from echo_certification_forge.anchor import AnchorReceipt
    from echo_certification_forge.signing_service import (
        OfflineVerificationBundle,
        ProductionSignedVerdict,
        ProductionSigningRequest,
        verify_offline_bundle,
    )

    manifest_path = OFFLINE_ROOT / "manifest.json"
    require(manifest_path.is_file(), "offline bundle manifest missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest["schema_version"] == "1.0.0" and manifest["source_node"] == "forge", "offline manifest identity mismatch")
    require(set(manifest["files"]) == set(EXPECTED_OFFLINE_FILES), "offline manifest file set mismatch")
    private_markers = (
        b"-----BEGIN " + b"PRIVATE KEY-----",
        b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
    )
    identities: dict[str, Any] = {}
    for name, (expected_size, expected_hash) in EXPECTED_OFFLINE_FILES.items():
        path = OFFLINE_ROOT / name
        require(path.is_file(), f"offline bundle file missing: {name}")
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        require(len(payload) == expected_size and digest == expected_hash, f"offline bundle identity mismatch: {name}")
        require(not any(marker in payload for marker in private_markers), f"private key material in offline bundle: {name}")
        recorded = manifest["files"][name]
        require(recorded["bytes"] == expected_size and recorded["sha256"] == expected_hash, f"offline manifest entry mismatch: {name}")
        identities[name] = {"bytes": expected_size, "sha256": expected_hash}

    request = ProductionSigningRequest.model_validate_json((OFFLINE_ROOT / "signing-request.json").read_text(encoding="utf-8"))
    verdict = ProductionSignedVerdict.model_validate_json((OFFLINE_ROOT / "verdict.json").read_text(encoding="utf-8"))
    public_keys = json.loads((OFFLINE_ROOT / "public-keys.json").read_text(encoding="utf-8"))
    receipt = AnchorReceipt.model_validate_json((OFFLINE_ROOT / "anchor-receipt.json").read_text(encoding="utf-8"))
    log_entry = json.loads((OFFLINE_ROOT / "anchor-log.jsonl").read_text(encoding="utf-8").strip())
    anchor_public_key = (OFFLINE_ROOT / "anchor-public.pem").read_text(encoding="ascii")
    require(request.anchor_bundle.receipt == receipt, "offline anchor receipt differs from signing request")
    require(request.anchor_bundle.log_entry == log_entry, "offline anchor log differs from signing request")
    require(request.anchor_bundle.provider_public_key_pem == anchor_public_key, "offline anchor public key differs from signing request")
    require(receipt.receipt_id == report["anchor"]["receipt_id"], "offline receipt id differs from acceptance report")
    bundle = OfflineVerificationBundle(
        verdict=verdict,
        anchor_bundle=request.anchor_bundle,
        public_key_bundle=public_keys,
    )
    valid, reason = verify_offline_bundle(bundle, now=verdict.payload.issued_at + timedelta(minutes=1))
    require(valid and reason == "verified", f"offline verdict verification failed: {reason}")
    require(verdict.key_id == report["signing"]["public_key_id"], "offline verdict key id mismatch")
    require(verdict.payload.anchor_receipt_id == report["anchor"]["receipt_id"], "offline verdict anchor binding mismatch")
    require(verdict.payload.evidence_merkle_root == report["custody"]["verification_before_anchor"]["merkle_root"], "offline verdict Merkle-root mismatch")
    return {"files": identities, "verification": {"valid": valid, "reason": reason}}


def verify_sdk_contract() -> dict[str, Any]:
    path = ROOT / "contracts/certforge-capabilities.v1.json"
    contract = json.loads(path.read_text(encoding="utf-8"))
    require_exact_keys(contract, {"schema_version", "registration_state", "registration_gate", "capabilities"}, "SDK contract")
    require(contract["schema_version"] == "1.0.0", "SDK contract version mismatch")
    require(contract["registration_state"] == "NOT_REGISTERED", "incomplete SDK capabilities must remain unregistered")
    capabilities = contract["capabilities"]
    require(isinstance(capabilities, list) and len(capabilities) == len(EXPECTED_CAPABILITIES), "SDK capability count mismatch")
    require({item["id"] for item in capabilities} == EXPECTED_CAPABILITIES, "SDK capability id set mismatch")
    for item in capabilities:
        require_exact_keys(item, EXPECTED_CAPABILITY_FIELDS, f"SDK capability {item.get('id')}")
        require(isinstance(item["input_schema"], dict) and isinstance(item["output_schema"], dict), f"SDK schemas incomplete: {item['id']}")
        for schema_name in ("input_schema", "output_schema"):
            schema = item[schema_name]
            if "$ref" in schema:
                reference = schema["$ref"]
                require(isinstance(reference, str) and reference.startswith("schemas/"), f"SDK schema reference invalid: {item['id']}:{schema_name}")
                reference_path = path.parent / reference
                require(reference_path.is_file(), f"SDK schema reference missing: {item['id']}:{reference}")
                referenced_schema = json.loads(reference_path.read_text(encoding="utf-8"))
                require(referenced_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", f"SDK referenced schema dialect mismatch: {reference}")
                require(referenced_schema.get("type") == "object", f"SDK referenced schema root type mismatch: {reference}")
        require(isinstance(item["danger_tier"], int) and item["danger_tier"] in {0, 1, 2}, f"SDK danger tier invalid: {item['id']}")
        require(isinstance(item["timeout_seconds"], int) and item["timeout_seconds"] > 0, f"SDK timeout invalid: {item['id']}")
        for field in ("authentication", "authorization", "idempotency", "redaction", "audit", "health_criteria"):
            require(isinstance(item[field], str) and item[field].strip(), f"SDK field incomplete: {item['id']}:{field}")
        require(isinstance(item["error_model"], list) and item["error_model"], f"SDK error model incomplete: {item['id']}")
    text = path.read_text(encoding="utf-8").lower()
    incomplete_markers = ("to" + "do", "place" + "holder", "st" + "ub")
    require(not any(marker in text for marker in incomplete_markers), "SDK contract contains incomplete markers")
    return {"path": str(path.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(path), "registration_state": contract["registration_state"], "capability_ids": sorted(EXPECTED_CAPABILITIES)}


def write_summary(report: dict[str, Any]) -> dict[str, Any]:
    custody = report["custody"]
    anchor = report["anchor"]
    signing = report["signing"]
    success_config = signing["cases"]["success"]["host_config"]
    failed_checks = sorted(name for name, passed in report["checks"].items() if passed is not True)
    summary = {
        "schema_version": "1.0.0",
        "phase": "P3",
        "acceptance_identity": {
            "path": "artifacts/p3_forge_acceptance.json",
            "bytes": EXPECTED_REPORT_BYTES,
            "sha256": EXPECTED_REPORT_SHA256,
            "started_at_utc": report["started_at_utc"],
            "completed_at_utc": report["completed_at_utc"],
        },
        "forge_host": report["host"],
        "source_commit": EXPECTED_SOURCE_COMMIT,
        "source_commit_contains_p3": False,
        "acceptance_source_identity": report["source_identity"],
        "runner": {
            "image_digest": report["p2_runner_image_digest"],
            "isolation_profile_digest": report["p2_isolation_profile_digest"],
            "rootful_docker_engine": True,
            "container_execution_non_root": True,
        },
        "signer": {
            "image": signing["signer_image"],
            "public_key_id": signing["public_key_id"],
            "authorization_key_id": signing["authorization_key_id"],
            "anchor_provider_key_id": signing["anchor_provider_key_id"],
            "key_domains_distinct": report["checks"]["all_key_domains_distinct"],
            "isolated_signing_succeeded": report["checks"]["isolated_signing_succeeded"],
            "offline_verdict_verified": report["checks"]["offline_verdict_verified"],
            "rotation_historical_verification": signing["historical_after_rotation"],
            "compromise_invalidation": signing["after_compromise"],
            "runner_has_signing_key_mount": signing["runner_has_signing_key_mount"],
            "containment": {
                "user": signing["cases"]["success"]["config_user"],
                "read_only_root": success_config["ReadonlyRootfs"],
                "network_mode": success_config["NetworkMode"],
                "cap_drop": success_config["CapDrop"],
                "pids_limit": success_config["PidsLimit"],
                "memory_bytes": success_config["Memory"],
                "nano_cpus": success_config["NanoCpus"],
                "security_options": success_config["SecurityOpt"],
            },
        },
        "custody": {
            "artifact_id": custody["descriptor"]["artifact_id"],
            "artifact_sha256": custody["descriptor"]["sha256"],
            "leaf_hash": custody["descriptor"]["leaf_hash"],
            "manifest_sha256": custody["descriptor"]["manifest_sha256"],
            "merkle_root": custody["verification_before_anchor"]["merkle_root"],
            "audit_chain_tip": custody["audit_chain_tip"],
            "visibility": custody["descriptor"]["visibility"],
            "legal_hold": custody["retention"]["legal_hold"],
        },
        "anchor": {
            "provider_id": anchor["provider_id"],
            "public_key_id": anchor["provider_key_id"],
            "receipt_id": anchor["receipt_id"],
            "receipt_sha256": anchor["receipt_hash"],
            "statement_sha256": anchor["statement_sha256"],
            "chain_tip": anchor["chain_hash"],
            "storage_independent": anchor["health"]["storage_separate_from_custody_database"],
            "offline_verification": anchor["offline_verification"],
        },
        "adversarial_tests": {
            "total": len(report["checks"]),
            "passed": len(report["checks"]) - len(failed_checks),
            "failed": len(failed_checks),
            "failed_checks": failed_checks,
        },
        "cleanup": report["cleanup"],
        "private_key_leakage": {
            "non_secret_files_clear": report["checks"]["exact_private_key_bytes_absent_from_non_secret_files"],
            "outputs_clear": report["checks"]["private_key_absent_from_outputs"],
            "service_logs_clear": report["checks"]["private_key_absent_from_service_logs"],
            "signing_database_clear": report["checks"]["signing_database_contains_no_private_key"],
        },
        "run_outcome": report["run_outcome"],
        "release_verdict": report["release_verdict"],
        "passed": report["passed"],
    }
    SUMMARY_REPORT.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": str(SUMMARY_REPORT.relative_to(ROOT)).replace("\\", "/"), "bytes": SUMMARY_REPORT.stat().st_size, "sha256": sha256(SUMMARY_REPORT)}


def evidence_hashes() -> dict[str, str]:
    paths = [
        FULL_REPORT,
        SUMMARY_REPORT,
        OFFLINE_ROOT / "manifest.json",
        ROOT / "contracts/certforge-capabilities.v1.json",
        ROOT / "artifacts/p2_forge_acceptance.json",
        ROOT / "artifacts/p2_forge_acceptance.summary.json",
    ]
    paths.extend(OFFLINE_ROOT / name for name in sorted(EXPECTED_OFFLINE_FILES))
    return {str(path.relative_to(ROOT)).replace("\\", "/"): sha256(path) for path in paths}


def main() -> int:
    python = sys.executable
    report = verify_full_report()
    source_identity = verify_source_identities()
    offline = verify_offline_material(report)
    sdk_contract = verify_sdk_contract()
    summary = write_summary(report)

    actor_source = (ROOT / "tests/test_p3_custody_anchor_signing.py").read_text(encoding="utf-8")
    for actor in ("SigningActorType.RUNNER", "SigningActorType.MODEL", "SigningActorType.DESKTOP", "SigningActorType.ORDINARY_WORKER"):
        require(actor in actor_source, f"missing actor signing-denial test: {actor}")

    checks = [
        run_check("p2_regression", [python, "scripts/verify_p2.py"], "p3_p2_regression.txt"),
        run_check(
            "actor_signing_denials",
            [python, "-m", "pytest", "-q", "tests/test_p3_custody_anchor_signing.py::test_signing_denial_matrix"],
            "p3_actor_signing_denials.txt",
        ),
    ]
    require(all(item["exit_code"] == 0 for item in checks), f"P3 closure checks failed: {checks}")
    p2_report = json.loads((ARTIFACTS / "p2_verification_report.json").read_text(encoding="utf-8"))
    require(p2_report["passed"] is True and p2_report["run_outcome"] == "COMPLETE", "P2 regression verification failed")

    verification = {
        "schema_version": "1.0.0",
        "phase": "P3",
        "acceptance": {
            "path": "artifacts/p3_forge_acceptance.json",
            "bytes": EXPECTED_REPORT_BYTES,
            "sha256": EXPECTED_REPORT_SHA256,
            "passed": True,
            "failed_checks": [],
        },
        "source_identity": source_identity,
        "offline_bundle": offline,
        "sdk_contract": sdk_contract,
        "summary": summary,
        "closure_checks": checks,
        "p2_regression_report_sha256": sha256(ARTIFACTS / "p2_verification_report.json"),
        "evidence_hashes": evidence_hashes(),
        "completed_phase_gate": "P3",
        "run_outcome": "COMPLETE",
        "release_verdict": "NOT_READY",
        "passed": True,
    }
    VERIFICATION_REPORT.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "report": str(VERIFICATION_REPORT),
                "report_sha256": sha256(VERIFICATION_REPORT),
                "summary_sha256": summary["sha256"],
                "acceptance_sha256": EXPECTED_REPORT_SHA256,
                "passed": True,
                "completed_phase_gate": "P3",
                "run_outcome": "COMPLETE",
                "release_verdict": "NOT_READY",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        failure = {
            "schema_version": "1.0.0",
            "phase": "P3",
            "passed": False,
            "completed_phase_gate": "P2",
            "run_outcome": "INCONCLUSIVE",
            "release_verdict": "NOT_READY",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
        VERIFICATION_REPORT.write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(failure, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
