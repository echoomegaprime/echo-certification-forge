from __future__ import annotations

# Recovered from the HAMMER owner workspace; see docs/ACCOUNT_CONTINUITY_COLLECTOR.md.
# Historical source SHA256: 9451710e9ec0323b7784411720fd76214268a2a7fa64da28d97a80fcae922ef4

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SCHEMA_VERSION = "certforge.production-e2e.v1"
REPORT_SCHEMA = "echo.account-continuity.hammer-attestor-report.v1"
PROFILE = "generic-production-v1"
REPOSITORY = "echoomegaprime/account-continuity-bridge"
BRANCH = "agent/grok47-provider-recovery-20261003"
SOURCE_COMMIT = "d9ffe76ad63b71545d5378f154e15af10e4f7a9e"
PLUGIN_VERSION = "1.1.0+codex.20261003194149"
PULL_REQUEST = 4
COLLECTOR_KEY_ID = "ed25519:59de9be507b39b291ee13c4a57378ec6"
BASE_CHECKS = frozenset(
    {
        "runtime_or_artifact_executed",
        "exact_identity_readback",
        "critical_journeys_complete",
        "negative_controls_pass",
        "stability_verified",
        "external_acceptance_verified",
    }
)
EXPECTED_ASSERTIONS = {
    "repository_policy": 8,
    "account_continuity_core": 6,
    "provider_auth_monitor": 18,
    "provider_content_import": 9,
    "multiprovider_mcp": 35,
    "account_continuity_bridge": 22,
    "provider_registry": 21,
}
POWERSHELL_TESTS = {
    "repository_policy": "tests/Test-RepositoryPolicy.ps1",
    "provider_auth_monitor": "tests/Test-ProviderAuthMonitor.ps1",
    "provider_content_import": "tests/Test-ProviderContentImport.ps1",
    "multiprovider_mcp": "tests/Test-MultiproviderMcp.ps1",
}
HAMMER_EXPECTED_ASSERTIONS = {
    name: EXPECTED_ASSERTIONS[name]
    for name in (*POWERSHELL_TESTS, "provider_registry")
}
HAMMER_DPAPI_BOUNDARY = {
    "account_continuity_core": EXPECTED_ASSERTIONS["account_continuity_core"],
    "account_continuity_bridge": EXPECTED_ASSERTIONS["account_continuity_bridge"],
}
ATOMIC_RENAME_CONTROLS = frozenset({
    "actual_windows_reader_recovers_without_target_delete",
    "EPERM_has_expected_platform_retry_boundary",
    "EACCES_has_expected_platform_retry_boundary",
    "EBUSY_has_expected_platform_retry_boundary",
    "EIO_has_expected_platform_retry_boundary",
    "persistent_failure_is_bounded_and_preserves_previous_state",
})
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOCK_ACQUISITION_CONTROLS = frozenset({
    "EPERM_acquisition_has_expected_platform_retry_boundary",
    "EACCES_acquisition_has_expected_platform_retry_boundary",
    "EBUSY_acquisition_has_expected_platform_retry_boundary",
    "EIO_acquisition_has_expected_platform_retry_boundary",
    "persistent_acquisition_failure_preserves_unowned_lock_and_state",
})
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# E5 is a separate unsigned recipe, never admitted to the legacy key path.
E5_SOURCE = "e5b8c7b7f3fd59c79cd9c436ef14ec40216da119"
E5_BRANCH = "agent/innovator-provider-readiness-20261030"
E5_VERSION = "1.1.0+codex.20261030230943"
E5_MODEL = "huihui_ai/Qwen3.8-abliterated:27b"
E5_ASSERTIONS = {
    "repository_policy": 8, "account_continuity_core": 6,
    "provider_auth_monitor": 5, "provider_content_import": 9,
    "multiprovider_mcp": 35, "account_continuity_bridge": 22,
    "provider_registry": 16, "node_regressions": 94,
}
E5_PS_TESTS = {
    **POWERSHELL_TESTS,
    "account_continuity_core": "tests/Test-AccountContinuityCore.ps1",
    "account_continuity_bridge": "scripts/Test-AccountContinuityBridge.ps1",
}
E5_NODE_TESTS = (
    "tests/Test-ProviderStatus.mjs", "tests/Test-RouterConcurrency.mjs",
    "tests/Test-ProviderProcess.mjs", "tests/Test-ReceiptProvenance.mjs",
    "tests/Test-RouterSafety.mjs", "tests/Test-Boundaries.mjs",
)


class AttestationError(RuntimeError):
    """A fail-closed rejection with no secret-bearing detail."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path, *, expected_sha256: str | None = None) -> tuple[dict[str, Any], str]:
    try:
        content = path.read_bytes()
        digest = sha256_bytes(content)
        if expected_sha256 is not None and (not SHA256.fullmatch(expected_sha256) or digest != expected_sha256):
            raise AttestationError("owner-collected evidence custody digest mismatch")
        value = json.loads(content.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AttestationError(f"invalid JSON evidence: {path.name}") from exc
    if not isinstance(value, dict):
        raise AttestationError(f"JSON evidence must be an object: {path.name}")
    return value, digest


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise AttestationError(
            f"verification command failed ({completed.returncode}): {Path(command[0]).name}"
        )
    return completed


def verify_hosted_receipt(
    path: Path,
    *,
    source_commit: str,
    target_digest: str,
    environment_digest: str,
    delivery_id: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    document, document_sha256 = read_json(path, expected_sha256=expected_sha256)
    if document.get("app_key") != "certification-forge":
        raise AttestationError("hosted receipt has the wrong app identity")
    if document.get("repository") != REPOSITORY:
        raise AttestationError("hosted receipt has the wrong repository")
    if document.get("target_sha") != source_commit:
        raise AttestationError("hosted receipt is not bound to the exact source")
    chain = document.get("receipt_chain")
    if not isinstance(chain, dict) or chain.get("ok") is not True:
        raise AttestationError("hosted receipt chain is invalid")
    receipts = document.get("receipts")
    if not isinstance(receipts, list):
        raise AttestationError("hosted receipt list is invalid")
    matches = [
        row
        for row in receipts
        if isinstance(row, dict)
        and row.get("target_sha") == source_commit
        and row.get("repository") == REPOSITORY
        and row.get("delivery_id") == delivery_id
        and row.get("state") == "succeeded"
    ]
    if len(matches) != 1:
        raise AttestationError("exact-source hosted delivery is missing or ambiguous")
    receipt = matches[0]
    result = receipt.get("result")
    if not isinstance(result, dict) or result.get("effect") != "certification":
        raise AttestationError("hosted receipt is not a certification receipt")
    if result.get("target_identity_digest") != target_digest:
        raise AttestationError("hosted receipt target identity mismatch")
    if result.get("environment_identity_digest") != environment_digest:
        raise AttestationError("hosted receipt environment identity mismatch")
    if result.get("run_outcome") != "COMPLETE" or result.get("release_verdict") != "NOT_READY":
        raise AttestationError("hosted initial certification state is unexpected")
    if result.get("production_e2e_valid") is not False:
        raise AttestationError("hosted initial certification did not fail closed")
    if not isinstance(result.get("check_run"), int) or result["check_run"] <= 0:
        raise AttestationError("hosted receipt check-run identity is invalid")
    receipt_hash = str(receipt.get("receipt_hash") or "")
    if not SHA256.fullmatch(receipt_hash):
        raise AttestationError("hosted receipt custody hash is invalid")
    return {
        "receipt_hash": receipt_hash,
        "delivery_id": str(receipt.get("delivery_id") or ""),
        "check_run": result["check_run"],
        "initial_certification_id": str(result.get("run_id") or ""),
        "initial_release_verdict": str(result.get("release_verdict") or ""),
        "chain_receipts": int(chain.get("receipts") or 0),
        "document_sha256": document_sha256,
    }


def verify_quench_evidence(path: Path, source_commit: str, *, expected_sha256: str | None = None) -> dict[str, Any]:
    document, document_sha256 = read_json(path, expected_sha256=expected_sha256)
    if source_commit != SOURCE_COMMIT:
        raise AttestationError("collector requires its reviewed exact-source candidate")
    if document.get("schema_version") != "echo.account-continuity.quench-evidence.v2":
        raise AttestationError("QUENCH evidence schema is invalid")
    verify_current_time(document.get("observed_at"))
    if str(document.get("host", "")).casefold() != "quench":
        raise AttestationError("runtime evidence was not produced on QUENCH")
    for field in (
        "source_commit",
        "installed_cache_commit",
        "remote_branch_commit",
        "pull_request_head_commit",
    ):
        if document.get(field) != source_commit:
            raise AttestationError(f"QUENCH evidence {field} is not exact-source")
    if type(document.get("pull_request")) is not int or document["pull_request"] != PULL_REQUEST:
        raise AttestationError("QUENCH evidence has the wrong pull request")
    if document.get("branch") != BRANCH:
        raise AttestationError("QUENCH evidence has the wrong branch")
    if document.get("installed_version") != PLUGIN_VERSION:
        raise AttestationError("QUENCH installed plugin version is unexpected")
    if document.get("installation_scope") not in {"production", "isolated_canary"}:
        raise AttestationError("QUENCH installation scope is unsupported")
    if document.get("native_plugin_enabled") is not True or document.get("fresh_native_session") is not True:
        raise AttestationError("QUENCH native installed plugin acceptance is incomplete")
    if not SHA256.fullmatch(str(document.get("installed_manifest_sha256") or "")):
        raise AttestationError("QUENCH installed manifest identity is missing")
    if document.get("iterations") != 3:
        raise AttestationError("QUENCH stability iteration count is invalid")
    if document.get("assertions_passed_per_iteration") != [119, 119, 119]:
        raise AttestationError("QUENCH test stability evidence is invalid")
    if document.get("critical_journeys") != ["PASS", "PASS", "PASS"]:
        raise AttestationError("QUENCH journey stability evidence is invalid")
    test_runs = document.get("test_runs")
    if not isinstance(test_runs, list) or len(test_runs) != 3:
        raise AttestationError("QUENCH detailed test evidence is invalid")
    for iteration, row in enumerate(test_runs, start=1):
        if not isinstance(row, dict) or row.get("iteration") != iteration:
            raise AttestationError("QUENCH test iteration identity is invalid")
        verify_current_time(row.get("observed_at"))
        if row.get("source_commit") != source_commit or row.get("total") != 119:
            raise AttestationError("QUENCH test iteration is not exact-source")
        if row.get("critical_journey") != "PASS" or row.get("assertions") != EXPECTED_ASSERTIONS:
            raise AttestationError("QUENCH detailed assertions are invalid")
        verify_router_result(row.get("router_concurrency"))
        verify_atomic_rename_result(row.get("atomic_rename"))
        verify_lock_acquisition_result(row.get("router_lock_acquisition"))
    live_runs = document.get("live_runs")
    if not isinstance(live_runs, list) or len(live_runs) != 3:
        raise AttestationError("QUENCH live canary evidence is invalid")
    seen_nonces: set[str] = set()
    seen_sessions: set[str] = set()
    for row in live_runs:
        if not isinstance(row, dict):
            raise AttestationError("QUENCH live canary record is invalid")
        verify_current_time(row.get("observed_at"))
        if row.get("source_commit") != source_commit or row.get("governance") != "PASS":
            raise AttestationError("QUENCH canary is not governed exact-source execution")
        session = row.get("session_id")
        if not isinstance(session, str) or not session or not isinstance(row.get("model"), str) or not row["model"]:
            raise AttestationError("QUENCH canary model/session identity is missing")
        if row.get("exact_canary_match") is not True:
            raise AttestationError("QUENCH live canary did not match")
        if row.get("selected_provider") != "forge-qwen" or row.get("selected_outcome") != "success":
            raise AttestationError("QUENCH live canary used the wrong route")
        if row.get("provenance") != "LIVE_PROVIDER_BRIDGE":
            raise AttestationError("QUENCH live canary provenance is invalid")
        if row.get("credential_copied_or_exposed") is not False:
            raise AttestationError("QUENCH live canary reports credential exposure")
        if row.get("canary_sha256") != row.get("response_sha256"):
            raise AttestationError("QUENCH live canary digest does not match")
        if not SHA256.fullmatch(str(row.get("canary_sha256", ""))):
            raise AttestationError("QUENCH live canary digest is invalid")
        if row["canary_sha256"] in seen_nonces or session in seen_sessions:
            raise AttestationError("QUENCH requires three distinct live nonce sessions")
        seen_nonces.add(row["canary_sha256"])
        seen_sessions.add(session)
    status_runs = document.get("status_runs")
    if not isinstance(status_runs, list) or len(status_runs) != 3:
        raise AttestationError("QUENCH status stability evidence is invalid")
    for row in status_runs:
        if not isinstance(row, dict) or row.get("status_nonspending") is not True:
            raise AttestationError("QUENCH status probe was not non-spending")
        verify_current_time(row.get("observed_at"))
        if row.get("source_commit") != source_commit:
            raise AttestationError("QUENCH status probe is not exact-source")
        if row.get("server_name") != "account_continuity_multiprovider_mcp":
            raise AttestationError("QUENCH status probe has the wrong server")
        if row.get("server_version") != "0.5.0" or row.get("provider_count") != 7 or row.get("tool_count") != 17:
            raise AttestationError("QUENCH status probe surface is incomplete")
    if document.get("gitleaks_exact_tree") != "PASS":
        raise AttestationError("QUENCH secret scan is not passing")
    if document.get("codex_mcp_config") != "ok":
        raise AttestationError("QUENCH MCP configuration is not healthy")
    if document.get("private_key_exported") is not False:
        raise AttestationError("QUENCH evidence reports private-key export")
    if document.get("credentials_in_evidence") is not False:
        raise AttestationError("QUENCH evidence reports credential material")
    return {
        "document_sha256": document_sha256,
        "installed_version": document["installed_version"],
        "installation_scope": document["installation_scope"],
        "installed_manifest_sha256": document["installed_manifest_sha256"],
        "assertions_passed_per_iteration": document["assertions_passed_per_iteration"],
        "critical_journeys": document["critical_journeys"],
        "live_canaries": len(live_runs),
        "status_probes": len(status_runs),
        "atomic_rename_controls_per_iteration": len(ATOMIC_RENAME_CONTROLS),
        "router_lock_acquisition_controls_per_iteration": len(LOCK_ACQUISITION_CONTROLS),
        "tool_count": status_runs[0]["tool_count"],
        "provider_count": status_runs[0]["provider_count"],
        "selected_provider": "forge-qwen",
        "provenance": "LIVE_PROVIDER_BRIDGE",
        "gitleaks_exact_tree": "PASS",
        "codex_mcp_config": "ok",
        "private_key_exported": False,
    }


def verify_current_time(value: Any) -> None:
    try:
        observed = datetime.fromisoformat(value)
        if observed.tzinfo is None or not -5 <= (datetime.now(UTC) - observed).total_seconds() <= 3600:
            raise ValueError("outside acceptance window")
    except (TypeError, ValueError) as exc:
        raise AttestationError("QUENCH evidence time is not current and timezone-aware") from exc


def verify_production_quench_evidence(path: Path, source_commit: str, *, expected_sha256: str) -> dict[str, Any]:
    evidence = verify_quench_evidence(path, source_commit, expected_sha256=expected_sha256)
    if evidence["installation_scope"] != "production":
        raise AttestationError("production installation is required; isolated_canary evidence remains unsigned and NOT_READY")
    return evidence


def verify_router_result(value: Any) -> None:
    if (not isinstance(value, dict) or value.get("ok") is not True
            or type(value.get("concurrent_requests")) is not int or value["concurrent_requests"] != 12
            or type(value.get("concurrent_processes")) is not int or value["concurrent_processes"] != 8
            or value.get("contended_lock_preserved") is not True):
        raise AttestationError("router concurrency/negative-control acceptance is incomplete")


def read_router_command(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AttestationError("router command did not return JSON") from exc
    verify_router_result(value)
    return value


def verify_atomic_rename_result(value: Any) -> None:
    if not isinstance(value, dict) or value.get("ok") is not True or value.get("platform") != "win32":
        raise AttestationError("Windows atomic rename acceptance is incomplete")
    assertions = value.get("assertions")
    if (not isinstance(assertions, dict) or set(assertions) != ATOMIC_RENAME_CONTROLS
            or any(passed is not True for passed in assertions.values())):
        raise AttestationError("Windows atomic rename controls are incomplete or failed")


def read_atomic_rename_command(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AttestationError("atomic rename command did not return JSON") from exc
    verify_atomic_rename_result(value)
    return value


def verify_lock_acquisition_result(value: Any) -> None:
    if not isinstance(value, dict) or value.get("ok") is not True or value.get("platform") != "win32":
        raise AttestationError("Windows lock acquisition acceptance is incomplete")
    assertions = value.get("assertions")
    if (not isinstance(assertions, dict) or set(assertions) != LOCK_ACQUISITION_CONTROLS
            or any(passed is not True for passed in assertions.values())):
        raise AttestationError("Windows lock acquisition controls are incomplete or failed")


def read_lock_acquisition_command(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AttestationError("lock acquisition command did not return JSON") from exc
    verify_lock_acquisition_result(value)
    return value


def verify_private_key(
    path: Path,
    repository: Path,
    bundle: Path,
    quench_evidence: Path,
) -> tuple[Ed25519PrivateKey, str, str]:
    resolved = path.resolve(strict=True)
    if resolved.is_relative_to(repository) or resolved in {bundle, quench_evidence}:
        raise AttestationError("collector private key is inside source or transfer state")
    try:
        key = serialization.load_pem_private_key(resolved.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise AttestationError("collector private key is unavailable") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AttestationError("collector private key is not Ed25519")
    public_key = key.public_key()
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = "ed25519:" + sha256_bytes(raw)[:32]
    if key_id != COLLECTOR_KEY_ID:
        raise AttestationError("collector key does not match the existing admitted identity")
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, key_id, public_pem


def verify_quench_reachability(address: str, port: int) -> None:
    try:
        with socket.create_connection((address, port), timeout=5.0):
            return
    except OSError as exc:
        raise AttestationError("HAMMER cannot reach the QUENCH management listener") from exc


def parse_test_json(completed: subprocess.CompletedProcess[str], label: str) -> int:
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise AttestationError(f"{label} returned no evidence")
    try:
        value = json.loads("\n".join(lines))
    except json.JSONDecodeError as exc:
        raise AttestationError(f"{label} did not return JSON") from exc
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise AttestationError(f"{label} did not pass")
    assertions = value.get("assertions")
    if isinstance(assertions, dict):
        if not assertions or any(passed is not True for passed in assertions.values()):
            raise AttestationError(f"{label} named assertion failed or is missing")
        return len(assertions)
    if type(assertions) is int and assertions > 0:
        return assertions
    raise AttestationError(f"{label} assertion count is unavailable")


def parse_node_check(completed: subprocess.CompletedProcess[str]) -> int:
    for line in reversed(completed.stdout.splitlines()):
        if not line.strip().startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("ok") is True and type(value.get("assertions")) is int and value["assertions"] > 0:
            return value["assertions"]
    raise AttestationError("Node registry assertion count is unavailable")


def atomic_write(path: Path, data: bytes) -> None:
    """Publish complete new evidence without replacing any existing owner file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as stream:
        stream.write(data)
        temporary = Path(stream.name)
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def e5_snapshot(repository: Path) -> dict[str, str]:
    """Measure the reviewed first-party tree before executing any child."""
    repository = repository.resolve(strict=True)
    git_environment = os.environ.copy()
    git_environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")

    def git(*arguments: str) -> str:
        return run(["git", "-c", "core.fsmonitor=false", "-C", str(repository), *arguments],
                   env=git_environment).stdout.strip()

    root = git("rev-parse", "--show-toplevel").replace("\\", "/")
    if root.casefold() != repository.as_posix().casefold():
        raise AttestationError("E5 source must be the repository root")
    if git("rev-parse", "HEAD") != E5_SOURCE or git("branch", "--show-current") != E5_BRANCH:
        raise AttestationError("E5 source or branch is not the reviewed candidate")
    if git("remote", "get-url", "origin") not in {
        "https://github.com/echoomegaprime/account-continuity-bridge.git",
        "git@github.com:echoomegaprime/account-continuity-bridge.git",
    } or git("status", "--porcelain"):
        raise AttestationError("E5 source origin or clean-tree binding failed")
    entries = [entry for entry in git("ls-tree", "-rz", "--full-tree", E5_SOURCE).split("\0") if entry]
    if not entries or len(entries) > 10000:
        raise AttestationError("E5 source inventory is invalid")
    manifest = {}
    for entry in sorted(entries):
        header, relative = entry.split("\t", 1)
        mode, kind, blob = header.split()
        path = repository / relative
        if (mode not in {"100644", "100755"} or kind != "blob" or not SHA40.fullmatch(blob)
                or path.is_symlink() or not path.resolve().is_relative_to(repository)):
            raise AttestationError("E5 inventory contains an unsafe path")
        if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise AttestationError("E5 inventory file is missing or oversized")
        content = path.read_bytes()
        # A clean index alone can conceal assume-unchanged/stat-cache edits.
        # Bind actual bytes to the immutable tree, allowing only Windows CRLF
        # checkout conversion for these reviewed text source types.
        candidates = [content]
        if path.suffix.lower() in {".md", ".ps1", ".psm1", ".mjs", ".json", ".yml", ".yaml"}:
            candidates.append(content.replace(b"\r\n", b"\n"))
        identities = {hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value,
                                   usedforsecurity=False).hexdigest() for value in candidates}
        if blob not in identities:
            raise AttestationError("E5 working bytes differ from the immutable source blob")
        manifest[relative] = sha256_bytes(content)
    plugin, _ = read_json(repository / ".codex-plugin/plugin.json")
    if plugin.get("version") != E5_VERSION:
        raise AttestationError("E5 source plugin version is unexpected")
    return manifest


def e5_installed_snapshot(installed: Path | None, manifest: dict[str, str]) -> dict[str, Any]:
    if installed is None:
        return {"state": "MISSING", "reason": "installed_root_not_supplied"}
    installed = installed.resolve(strict=True)
    mismatches, actual = [], {}
    for relative, expected in sorted(manifest.items()):
        path = installed / relative
        if (path.is_symlink() or not path.resolve().is_relative_to(installed)
                or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024):
            mismatches.append(relative)
            continue
        actual[relative] = sha256_bytes(path.read_bytes())
        if actual[relative] != expected:
            mismatches.append(relative)
    return {"state": "MATCH" if not mismatches else "MISMATCH",
            "manifest_sha256": sha256_bytes(canonical_json(actual)),
            "mismatch_count": len(mismatches), "mismatches": mismatches[:32],
            "tracked_files": len(manifest), "scope": "tracked_bytes_only; native enablement unverified"}


def e5_node_counts(completed: subprocess.CompletedProcess[str]) -> int:
    metrics = {}
    for line in completed.stdout.splitlines():
        match = re.fullmatch(r"# (tests|pass|fail|cancelled|skipped|todo) (\d+)", line.strip())
        if match:
            if match[1] in metrics:
                raise AttestationError("E5 Node summary is ambiguous")
            metrics[match[1]] = int(match[2])
    if (completed.returncode or set(metrics) != {"tests", "pass", "fail", "cancelled", "skipped", "todo"}
            or metrics["tests"] != 94 or metrics["pass"] != 94
            or any(metrics[key] for key in ("fail", "cancelled", "skipped", "todo"))):
        raise AttestationError("E5 Node suite is incomplete or failing")
    return metrics["pass"]


def verify_e5_owner_evidence(path: Path, *, expected_sha256: str,
                             installed: dict[str, Any]) -> dict[str, Any]:
    """Validate custody and structure only; owner assertions never admit signing."""
    if installed.get("state") != "MATCH":
        raise AttestationError("E5 installed bytes were not independently matched")
    if path.stat().st_size > 1024 * 1024:
        raise AttestationError("E5 owner evidence exceeds the bounded input size")
    document, digest = read_json(path, expected_sha256=expected_sha256)
    if document.get("schema_version") != "echo.account-continuity.quench-evidence.e5.v1":
        raise AttestationError("E5 owner evidence schema is invalid")
    verify_current_time(document.get("observed_at"))
    expected = {
        "host": "QUENCH", "branch": E5_BRANCH, "pull_request": 7,
        "installed_version": E5_VERSION, "installation_scope": "production",
        "native_plugin_enabled": True, "fresh_native_session": True,
        "installed_manifest_sha256": installed["manifest_sha256"],
        "iterations": 3, "credentials_in_evidence": False, "private_key_exported": False,
    }
    for key in ("source_commit", "installed_cache_commit", "remote_branch_commit", "pull_request_head_commit"):
        expected[key] = E5_SOURCE
    for key, value in expected.items():
        if type(document.get(key)) is not type(value) or document[key] != value:
            raise AttestationError("E5 owner evidence identity or production boundary failed")
    rows = document.get("test_runs")
    if not isinstance(rows, list) or len(rows) != 3:
        raise AttestationError("E5 requires three measured test passes")
    for iteration, row in enumerate(rows, 1):
        if (not isinstance(row, dict) or type(row.get("iteration")) is not int
                or row["iteration"] != iteration or row.get("source_commit") != E5_SOURCE
                or row.get("assertions") != E5_ASSERTIONS or row.get("total") != 195
                or row.get("critical_journey") != "PASS"):
            raise AttestationError("E5 detailed test evidence is incomplete")
        verify_current_time(row.get("observed_at"))
    seen, sessions = set(), set()
    rows = document.get("live_runs")
    if not isinstance(rows, list) or len(rows) != 3:
        raise AttestationError("E5 requires three distinct governed live runs")
    for row in rows:
        if not isinstance(row, dict):
            raise AttestationError("E5 live record is invalid")
        verify_current_time(row.get("observed_at"))
        nonce, session = row.get("canary_sha256"), row.get("session_id")
        if (row.get("source_commit") != E5_SOURCE or row.get("governance") != "PASS"
                or row.get("selected_provider") != "forge-qwen"
                or row.get("selected_route") != "forge-qwen-worker" or row.get("model") != E5_MODEL
                or row.get("selected_outcome") != "success" or row.get("exact_canary_match") is not True
                or row.get("provenance") != "LIVE_PROVIDER_BRIDGE"
                or row.get("credential_copied_or_exposed") is not False
                or not isinstance(nonce, str) or not SHA256.fullmatch(nonce)
                or nonce != row.get("response_sha256") or nonce in seen
                or not isinstance(session, str) or not session or session in sessions):
            raise AttestationError("E5 live route, nonce or session binding failed")
        seen.add(nonce)
        sessions.add(session)
    rows = document.get("status_runs")
    if not isinstance(rows, list) or len(rows) != 3:
        raise AttestationError("E5 requires three non-spending installed status readbacks")
    for row in rows:
        if (not isinstance(row, dict) or row.get("source_commit") != E5_SOURCE
                or row.get("status_nonspending") is not True
                or row.get("server_name") != "account_continuity_multiprovider_mcp"
                or row.get("server_version") != "0.5.0"
                or row.get("provider_count") != 7 or row.get("tool_count") != 17):
            raise AttestationError("E5 installed status identity is invalid")
        verify_current_time(row.get("observed_at"))
    return {"state": "STRUCTURE_VALIDATED_ONLY", "document_sha256": digest,
            "authority": "owner_readback_not_independently_authenticated"}


def measure_e5(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Unsigned exact-E5 measurement; no signing capability")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path)
    parser.add_argument("--node", required=True)
    parser.add_argument("--pwsh", required=True)
    parser.add_argument("--iterations", type=int, choices=(1, 3), default=3)
    parser.add_argument("--owner-evidence", type=Path)
    parser.add_argument("--owner-evidence-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    source, output = args.source.resolve(strict=True), args.output.resolve()
    installed_root = args.installed_root.resolve(strict=True) if args.installed_root else None
    if (output.exists() or output.is_relative_to(source)
            or (installed_root and (output.is_relative_to(installed_root)
                                   or installed_root.is_relative_to(source)
                                   or source.is_relative_to(installed_root)))):
        raise AttestationError("E5 source, install and new output paths must be separate")
    if bool(args.owner_evidence) != bool(args.owner_evidence_sha256):
        raise AttestationError("E5 owner evidence requires its independently retrieved custody hash")
    if args.owner_evidence and (args.owner_evidence.resolve().is_relative_to(source)
                               or (installed_root and args.owner_evidence.resolve().is_relative_to(installed_root))):
        raise AttestationError("E5 owner evidence must be outside target and installed trees")
    before = e5_snapshot(source)
    installed = e5_installed_snapshot(installed_root, before)
    environment = {key: value for key, value in os.environ.items() if key.upper() in {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "USERPROFILE",
        "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PSMODULEPATH", "PATHEXT",
    }}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    test_runs = []
    commands = {label: [args.pwsh, "-NoLogo", "-NoProfile", "-File", relative]
                for label, relative in E5_PS_TESTS.items()}
    commands["provider_registry"] = [args.node, "tests/Test-ProviderRegistry.mjs"]
    commands["node_regressions"] = [args.node, "--test", "--test-reporter=tap", *E5_NODE_TESTS]
    for iteration in range(1, args.iterations + 1):
        counts, receipts = {}, {}
        for label, command in commands.items():
            try:
                completed = run(command, cwd=source, env=environment, timeout=300)
                count = (e5_node_counts(completed) if label == "node_regressions"
                         else parse_node_check(completed) if label == "provider_registry"
                         else parse_test_json(completed, label))
                if count != E5_ASSERTIONS[label]:
                    raise AttestationError("E5 assertion count mismatch")
            except (AttestationError, OSError, subprocess.SubprocessError) as exc:
                print(json.dumps({"event": "e5_suite_rejected", "iteration": iteration,
                                  "suite": label, "failure_kind": type(exc).__name__}), file=sys.stderr)
                raise AttestationError("E5 fixed source suite failed: " + label) from exc
            counts[label] = count
            receipts[label] = {"stdout_sha256": sha256_bytes(completed.stdout.encode("utf-8")),
                               "command": command[1:], "exit_code": completed.returncode}
            print(json.dumps({"event": "e5_suite_measured", "iteration": iteration,
                              "suite": label, "assertions": count}), file=sys.stderr)
        test_runs.append({"iteration": iteration, "observed_at": datetime.now(UTC).isoformat(),
                          "source_commit": E5_SOURCE, "assertions": counts,
                          "total": sum(counts.values()), "receipts": receipts})
    if e5_snapshot(source) != before or e5_installed_snapshot(installed_root, before) != installed:
        raise AttestationError("E5 source or installed bytes changed during measurement")
    owner = {"state": "MISSING"}
    if args.owner_evidence:
        owner = verify_e5_owner_evidence(args.owner_evidence,
                                        expected_sha256=args.owner_evidence_sha256, installed=installed)
    report = {
        "schema_version": "echo.account-continuity.e5-measurement.v1",
        "run_outcome": "COMPLETE", "release_verdict": "NOT_READY", "unsigned": True,
        "repository": REPOSITORY, "source_commit": E5_SOURCE, "branch": E5_BRANCH,
        "pull_request": 7, "plugin_version": E5_VERSION,
        "observed_at": datetime.now(UTC).isoformat(), "host": socket.gethostname(),
        "source_manifest_sha256": sha256_bytes(canonical_json(before)),
        "installed": installed, "test_runs": test_runs, "owner_evidence": owner,
        "missing_production_prerequisites": [
            "independently_verified_native_enabled_fresh_session",
            "three_installed_governed_qwen_live_runs_and_status_readbacks",
            "current_exact_source_hosted_app_receipt_and_custody",
            "current_public_collector_trust_and_independent_e5_recipe_admission",
            "genuine_commander_acceptance",
        ] + ([] if installed["state"] == "MATCH" else ["exact_production_installed_bytes"])
          + ([] if args.iterations == 3 else ["three_source_stability_iterations"]),
        "signing_available": False, "private_key_accessed": False, "inference_performed": False,
    }
    atomic_write(output, canonical_json(report) + b"\n")
    print(json.dumps({"run_outcome": "COMPLETE", "release_verdict": "NOT_READY",
                      "unsigned": True, "report_sha256": sha256_bytes(output.read_bytes()),
                      "iterations": len(test_runs), "assertions_per_iteration": 195}))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Attest Account Continuity Bridge from HAMMER")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target-identity-digest", required=True)
    parser.add_argument("--environment-identity-digest", required=True)
    parser.add_argument("--revision-receipt", type=Path, required=True)
    parser.add_argument("--revision-receipt-sha256", required=True)
    parser.add_argument("--hosted-delivery-id", required=True)
    parser.add_argument("--quench-evidence", type=Path, required=True)
    parser.add_argument("--quench-evidence-sha256", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--pwsh", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--quench-address", required=True)
    parser.add_argument("--quench-management-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-key-output", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if socket.gethostname().casefold() != "hammer":
        raise AttestationError("collector must run on HAMMER")
    source_commit = args.source_commit.casefold()
    base_commit = args.base_commit.casefold()
    target_digest = args.target_identity_digest.casefold()
    environment_digest = args.environment_identity_digest.casefold()
    if not SHA40.fullmatch(source_commit) or not SHA40.fullmatch(base_commit):
        raise AttestationError("source and base commits must be exact")
    if source_commit != SOURCE_COMMIT:
        raise AttestationError("collector requires its reviewed exact-source candidate")
    if not SHA256.fullmatch(target_digest) or not SHA256.fullmatch(environment_digest):
        raise AttestationError("run identity digests must be exact")

    bundle = args.bundle.resolve(strict=True)
    python = args.python.resolve(strict=True)
    pwsh = args.pwsh.resolve(strict=True)
    node = args.node.resolve(strict=True)
    gitleaks = args.gitleaks.resolve(strict=True)
    workspace_root = args.workspace_root.resolve(strict=True)
    quench_evidence_path = args.quench_evidence.resolve(strict=True)
    if not workspace_root.is_dir():
        raise AttestationError("collector workspace root is not a directory")
    output_paths = [path.resolve() for path in (args.output, args.public_key_output, args.report_output)]
    protected_paths = {args.private_key.resolve(), bundle, quench_evidence_path,
                       args.revision_receipt.resolve(), Path(__file__).resolve()}
    if (len(set(output_paths)) != 3 or any(path in protected_paths or path.exists() for path in output_paths)
            or args.private_key.resolve().is_relative_to(workspace_root)):
        raise AttestationError("collector output/key paths violate ownership separation")
    quench = verify_production_quench_evidence(quench_evidence_path, source_commit,
                                              expected_sha256=args.quench_evidence_sha256)
    hosted = verify_hosted_receipt(
        args.revision_receipt.resolve(strict=True),
        source_commit=source_commit,
        target_digest=target_digest,
        environment_digest=environment_digest,
        delivery_id=args.hosted_delivery_id,
        expected_sha256=args.revision_receipt_sha256,
    )
    verify_quench_reachability(args.quench_address, args.quench_management_port)

    test_runs: list[dict[str, int]] = []
    journey_runs: list[str] = []
    router_runs: list[dict[str, Any]] = []
    atomic_rename_runs: list[dict[str, Any]] = []
    lock_acquisition_runs: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="acb-attest-", dir=workspace_root) as temporary:
        root = Path(temporary)
        repository = root / "repo"
        run(["git", "clone", "--quiet", str(bundle), str(repository)], timeout=600)
        run(["git", "-C", str(repository), "checkout", "--detach", "--quiet", source_commit])
        head = run(["git", "-C", str(repository), "rev-parse", "HEAD"]).stdout.strip()
        if head != source_commit:
            raise AttestationError("bundle checkout is not the exact source")
        bundle_refs = run(["git", "-C", str(repository), "bundle", "list-heads", str(bundle)]).stdout
        if f"{source_commit} refs/heads/{BRANCH}" not in bundle_refs:
            raise AttestationError("bundle branch does not resolve to the exact source")
        run(["git", "-C", str(repository), "fsck", "--full"], timeout=600)
        run(["git", "-C", str(repository), "merge-base", "--is-ancestor", base_commit, source_commit])
        run(["git", "-C", str(repository), "diff", "--check", base_commit, source_commit])

        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for _ in range(3):
            counts: dict[str, int] = {}
            for label, relative in POWERSHELL_TESTS.items():
                completed = run(
                    [str(pwsh), "-NoLogo", "-NoProfile", "-File", str(repository / relative)],
                    cwd=repository,
                    env=environment,
                    timeout=300,
                )
                counts[label] = parse_test_json(completed, label)
            for relative in (
                "mcp/server.mjs",
                "mcp/commands.mjs",
                "mcp/provider-registry.mjs",
                "mcp/router.mjs",
                "mcp/governance.mjs",
                "mcp/status.mjs",
                "mcp/tools.mjs",
                "mcp/forge-plugins.mjs",
            ):
                run([str(node), "--check", str(repository / relative)], cwd=repository, env=environment)
            counts["provider_registry"] = parse_node_check(
                run([str(node), str(repository / "tests/Test-ProviderRegistry.mjs")], cwd=repository, env=environment)
            )
            if counts != HAMMER_EXPECTED_ASSERTIONS or sum(counts.values()) != 91:
                raise AttestationError("HAMMER assertion totals are invalid")
            router_result = read_router_command(run(
                [str(node), str(repository / "tests/Test-RouterConcurrency.mjs")],
                cwd=repository, env=environment))
            router_runs.append(router_result)
            atomic_rename_runs.append(read_atomic_rename_command(run(
                [str(node), str(repository / "tests/Test-RouterAtomicRename.mjs")],
                cwd=repository, env=environment)))
            lock_acquisition_runs.append(read_lock_acquisition_command(run(
                [str(node), str(repository / "tests/Test-RouterLockAcquisition.mjs")],
                cwd=repository, env=environment)))
            test_runs.append(counts)
            journey = run(
                [str(python), "-B", str(repository / "scripts/certforge_journey.py")],
                cwd=repository,
                env=environment,
            ).stdout.strip()
            if journey != "ACCOUNT_CONTINUITY_CRITICAL_JOURNEY_OK surfaces=26 apps=8 providers=7 secret_fields=0":
                raise AttestationError("HAMMER critical journey output is invalid")
            journey_runs.append("PASS")

        run([str(gitleaks), "dir", "--no-banner", "--redact", str(repository)], timeout=300)
        status = run(["git", "-C", str(repository), "status", "--porcelain"]).stdout.strip()
        if status:
            raise AttestationError("exact-source checkout became dirty during verification")

        observed_at = datetime.now(UTC)
        canonical_target = f"https://github.com/{REPOSITORY}.git@{source_commit}"
        evidence_summary = {
            "bundle_sha256": sha256_bytes(bundle.read_bytes()),
            "hosted_receipt_document_sha256": hosted["document_sha256"],
            "hosted_receipt_hash": hosted["receipt_hash"],
            "hosted_delivery_id": hosted["delivery_id"],
            "hosted_check_run": hosted["check_run"],
            "quench_evidence_sha256": quench["document_sha256"],
            "installed_version": quench["installed_version"],
            "installation_scope": quench["installation_scope"],
            "installed_manifest_sha256": quench["installed_manifest_sha256"],
            "hammer_router_concurrency": router_runs,
            "hammer_atomic_rename": atomic_rename_runs,
            "hammer_router_lock_acquisition": lock_acquisition_runs,
            "quench_atomic_rename_controls_per_iteration": quench["atomic_rename_controls_per_iteration"],
            "quench_router_lock_acquisition_controls_per_iteration": quench["router_lock_acquisition_controls_per_iteration"],
            "hammer_test_iterations": len(test_runs),
            "hammer_assertions_passed_per_iteration": [sum(row.values()) for row in test_runs],
            "hammer_assertion_detail": test_runs,
            "hammer_dpapi_remote_session_boundary": HAMMER_DPAPI_BOUNDARY,
            "hammer_dpapi_remote_session_result": "NOT_EXECUTED_ON_HAMMER_REQUIRES_QUENCH_ACCEPTANCE",
            "hammer_critical_journeys": journey_runs,
            "quench_assertions_passed_per_iteration": quench["assertions_passed_per_iteration"],
            "quench_critical_journeys": quench["critical_journeys"],
            "quench_live_canaries": quench["live_canaries"],
            "quench_status_probes": quench["status_probes"],
            "tool_count": quench["tool_count"],
            "provider_count": quench["provider_count"],
            "selected_provider": quench["selected_provider"],
            "provenance": quench["provenance"],
            "gitleaks_exact_tree_quench": quench["gitleaks_exact_tree"],
            "gitleaks_exact_tree_hammer": "PASS",
            "codex_mcp_config": quench["codex_mcp_config"],
            "private_key_exported": False,
        }
        checks = {
            "runtime_or_artifact_executed": len(test_runs) == 3,
            "exact_identity_readback": head == source_commit == SOURCE_COMMIT,
            "critical_journeys_complete": journey_runs == ["PASS"] * 3,
            "negative_controls_pass": (len(router_runs) == 3
                and all(row["contended_lock_preserved"] is True for row in router_runs)
                and len(atomic_rename_runs) == 3
                and all(set(row["assertions"]) == ATOMIC_RENAME_CONTROLS
                        and all(passed is True for passed in row["assertions"].values())
                        for row in atomic_rename_runs)
                and len(lock_acquisition_runs) == 3
                and all(set(row["assertions"]) == LOCK_ACQUISITION_CONTROLS
                        and all(passed is True for passed in row["assertions"].values())
                        for row in lock_acquisition_runs)),
            "stability_verified": test_runs == [HAMMER_EXPECTED_ASSERTIONS] * 3,
            "external_acceptance_verified": quench["live_canaries"] == 3 and quench["status_probes"] == 3,
        }
        if not all(checks.values()):
            raise AttestationError("production acceptance did not complete")
        payload = {
            "schema_version": SCHEMA_VERSION,
            "attestation_id": (
                f"hammer-account-continuity-{observed_at.strftime('%Y%m%dT%H%M%SZ')}-{source_commit[:12]}"
            ),
            "profile": PROFILE,
            "target_identity_digest": target_digest,
            "environment_identity_digest": environment_digest,
            "source_commit": source_commit,
            "deployment_sha": source_commit,
            "canonical_target": canonical_target,
            "required_checks": sorted(BASE_CHECKS),
            "checks": checks,
            "stability_probe_count": len(test_runs),
            "evidence_summary": evidence_summary,
            "observed_at": observed_at.isoformat(),
            "expires_at": (observed_at + timedelta(minutes=45)).isoformat(),
            "signing_key_id": COLLECTOR_KEY_ID,
        }
    # Source subprocesses and their temporary checkout have finished before key access.
    # This is the existing native owner signing operation, never worker-side key injection.
    # Long test runs cannot refresh expired upstream evidence by issuing a new envelope.
    verify_production_quench_evidence(quench_evidence_path, source_commit,
                                     expected_sha256=args.quench_evidence_sha256)
    key, key_id, public_pem = verify_private_key(args.private_key, repository, bundle, quench_evidence_path)
    signature = key.sign(canonical_json(payload))
    envelope = {
        "payload": payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_id": key_id,
        "public_key_pem": public_pem,
    }
    signed_digest = sha256_bytes(
        canonical_json(
            {
                "payload": payload,
                "signature_b64": envelope["signature_b64"],
                "key_id": key_id,
            }
        )
    )
    report = {
        "schema_version": REPORT_SCHEMA,
        "collector_host": "HAMMER",
        "target_host": "QUENCH",
        "repository": REPOSITORY,
        "branch": BRANCH,
        "base_commit": base_commit,
        "source_commit": source_commit,
        "target_identity_digest": target_digest,
        "environment_identity_digest": environment_digest,
        "collector_key_id": key_id,
        "attestation_envelope_sha256": signed_digest,
        "bundle_sha256": evidence_summary["bundle_sha256"],
        "hosted_receipt": hosted,
        "quench_evidence": quench,
        "hammer_test_iterations": len(test_runs),
        "hammer_assertions_passed_per_iteration": evidence_summary["hammer_assertions_passed_per_iteration"],
        "hammer_critical_journeys": journey_runs,
        "gitleaks_exact_tree_hammer": "PASS",
        "private_key_exported": False,
        "signed_evidence_summary_sha256": sha256_bytes(canonical_json(evidence_summary)),
        "checks": {name: "PASS" if passed else "FAIL" for name, passed in checks.items()},
        "installation_scope": quench["installation_scope"],
        "completed_at": datetime.now(UTC).isoformat(),
    }

    atomic_write(args.output, json.dumps(envelope, indent=2, sort_keys=True).encode() + b"\n")
    atomic_write(args.public_key_output, public_pem.encode("ascii"))
    atomic_write(args.report_output, json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    print(
        json.dumps(
            {
                "result": "ATTESTATION_READY",
                "collector_key_id": key_id,
                "source_commit": source_commit,
                "tests_per_iteration": 91,
                "stability_probe_count": len(test_runs),
                "live_canaries_bound": quench["live_canaries"],
                "attestation_envelope_sha256": signed_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "measure-e5":
            raise SystemExit(measure_e5(sys.argv[2:]))
        raise SystemExit(main())
    except (AttestationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"result": "NOT_READY", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1)
