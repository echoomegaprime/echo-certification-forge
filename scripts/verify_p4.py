#!/usr/bin/env python3
"""Deterministically verify the complete P4 closure evidence package."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from echo_certification_forge.p4_manifest import verify_p4_image_manifest  # noqa: E402

INDEX_PATH = ROOT / "artifacts/p4_evidence_index.json"
FINAL_REPORT_PATH = ROOT / "artifacts/p4_forge_acceptance.json"
IMAGE_MANIFEST_PATH = ROOT / "artifacts/p4_images/manifest.json"
P2_REPORT_PATH = ROOT / "artifacts/p2_forge_acceptance.json"
P3_REPORT_PATH = ROOT / "artifacts/p3_forge_acceptance.json"
P2_EXPECTED_SHA256 = "d563aefcb121f91f5b6beda0f82ce80d776dd7bc6f2caaf6253226370883ef68"
P3_EXPECTED_SHA256 = "e805e6b9913a8a3712fee4710aec5d6b180b149ed2e729723bb178e7327a1ee6"
BASE_DIGEST = "sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def require(condition: bool, failures: list[str], reason: str) -> None:
    if not condition:
        failures.append(reason)


def resolve_repo_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    if ROOT not in path.parents and path != ROOT:
        raise ValueError(f"evidence path escapes repository: {value}")
    return path


def verify_tracked_identity(path: Path, *, allow_uncommitted: bool) -> tuple[bool, str]:
    relative = path.relative_to(ROOT).as_posix()
    tracked = run(["git", "ls-files", "--error-unmatch", "--", relative])
    if tracked.returncode != 0:
        return allow_uncommitted, "untracked_allowed" if allow_uncommitted else "not_tracked"
    if allow_uncommitted:
        return True, "tracked"
    blob = run(["git", "show", f"HEAD:{relative}"])
    if blob.returncode != 0:
        return False, "head_blob_missing"
    current = path.read_text(encoding="utf-8")
    return blob.stdout == current, "verified" if blob.stdout == current else "head_blob_mismatch"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-uncommitted", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    failures: list[str] = []
    details: dict[str, Any] = {}

    require(INDEX_PATH.is_file(), failures, "p4_evidence_index_missing")
    if failures:
        report = {"schema_version": "1.0.0", "phase": "P4", "passed": False, "failures": failures}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    require(index.get("schema_version") == "1.0.0", failures, "evidence_index_schema_invalid")
    require(index.get("phase") == "P4", failures, "evidence_index_phase_invalid")
    source_commit = str(index.get("source_commit") or "")
    require(len(source_commit) == 40 and all(ch in "0123456789abcdef" for ch in source_commit), failures, "source_commit_invalid")
    require(index.get("completed_phase_gate") == "P4", failures, "completed_phase_gate_invalid")
    require(index.get("run_outcome") == "COMPLETE", failures, "run_outcome_invalid")
    require(index.get("release_verdict") == "NOT_READY", failures, "release_verdict_invalid")

    index_tracked, index_reason = verify_tracked_identity(INDEX_PATH, allow_uncommitted=args.allow_uncommitted)
    require(index_tracked, failures, f"evidence_index_git_identity:{index_reason}")
    details["evidence_index_git_identity"] = index_reason

    expected_files = index.get("files") or []
    require(isinstance(expected_files, list) and len(expected_files) >= 1, failures, "evidence_file_list_missing")
    file_results: list[dict[str, Any]] = []
    for item in expected_files:
        try:
            path = resolve_repo_path(str(item["path"]))
            expected_sha = str(item["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"evidence_file_record_invalid:{exc}")
            continue
        exists = path.is_file()
        actual_sha = sha256_file(path) if exists else None
        ok = exists and actual_sha == expected_sha
        require(ok, failures, f"evidence_file_invalid:{item.get('path')}")
        file_results.append({"path": str(item.get("path")), "exists": exists, "expected_sha256": expected_sha, "actual_sha256": actual_sha, "passed": ok})
    details["files"] = file_results

    report_record = index.get("acceptance_report") or {}
    manifest_record = index.get("image_manifest") or {}
    require(report_record.get("path") == "artifacts/p4_forge_acceptance.json", failures, "acceptance_report_path_invalid")
    require(manifest_record.get("path") == "artifacts/p4_images/manifest.json", failures, "image_manifest_path_invalid")
    require(FINAL_REPORT_PATH.is_file(), failures, "acceptance_report_missing")
    require(IMAGE_MANIFEST_PATH.is_file(), failures, "image_manifest_missing")
    if FINAL_REPORT_PATH.is_file():
        require(sha256_file(FINAL_REPORT_PATH) == report_record.get("sha256"), failures, "acceptance_report_sha256_mismatch")
        acceptance = json.loads(FINAL_REPORT_PATH.read_text(encoding="utf-8"))
        require(acceptance.get("passed") is True, failures, "acceptance_not_passed")
        require(acceptance.get("run_outcome") == "COMPLETE", failures, "acceptance_run_outcome_invalid")
        require(acceptance.get("release_verdict") == "NOT_READY", failures, "acceptance_release_verdict_invalid")
        require(acceptance.get("source_commit") == source_commit, failures, "acceptance_source_commit_mismatch")
        require(acceptance.get("base_image", "").endswith(BASE_DIGEST), failures, "acceptance_base_digest_mismatch")
        sealed = acceptance.get("sealed_image_manifest") or {}
        require(sealed.get("sha256") == manifest_record.get("sha256"), failures, "acceptance_manifest_binding_mismatch")
        require(sealed.get("record_count") == 12 and sealed.get("passed") is True, failures, "acceptance_manifest_verification_invalid")
        checks = acceptance.get("checks") or {}
        require(bool(checks) and all(checks.values()), failures, "acceptance_checks_not_all_green")
        cleanup = acceptance.get("cleanup") or {}
        require(cleanup.get("unrelated_container_ids_preserved") is True, failures, "cleanup_unrelated_container_preservation_failed")
        require(cleanup.get("ephemeral_private_files_removed") is True, failures, "cleanup_private_files_remain")
        private_scan = acceptance.get("private_key_scan") or {}
        require(private_scan.get("passed") is True and not private_scan.get("findings"), failures, "acceptance_private_key_scan_failed")
        images = acceptance.get("images") or {}
        require(set(images) == {"runner", "custody", "anchor", "signer", "worker", "verifier"}, failures, "acceptance_image_role_set_invalid")
        for role, item in images.items():
            require((item.get("vulnerability_scan") or {}).get("passed") is True, failures, f"{role}:vulnerability_scan_failed")
            require((item.get("malware_scan") or {}).get("passed") is True, failures, f"{role}:malware_scan_failed")
            require((item.get("sbom") or {}).get("verified") is True, failures, f"{role}:sbom_unverified")
            require((item.get("admission") or {}).get("allowed") is True, failures, f"{role}:admission_denied")
    if IMAGE_MANIFEST_PATH.is_file():
        require(sha256_file(IMAGE_MANIFEST_PATH) == manifest_record.get("sha256"), failures, "image_manifest_sha256_mismatch")
        manifest_verification = verify_p4_image_manifest(
            IMAGE_MANIFEST_PATH,
            expected_source_commit=source_commit,
            expected_base_digest=BASE_DIGEST,
            now=datetime.now(UTC),
        )
        details["image_manifest_verification"] = manifest_verification
        require(manifest_verification["passed"], failures, "image_manifest_verification_failed")
        require(manifest_verification["record_count"] == 12, failures, "image_manifest_record_count_invalid")

    require(P2_REPORT_PATH.is_file() and sha256_file(P2_REPORT_PATH) == P2_EXPECTED_SHA256, failures, "p2_prerequisite_identity_invalid")
    require(P3_REPORT_PATH.is_file() and sha256_file(P3_REPORT_PATH) == P3_EXPECTED_SHA256, failures, "p3_prerequisite_identity_invalid")
    for verifier in ("scripts/verify_p2.py", "scripts/verify_p3.py"):
        completed = run([sys.executable, verifier])
        details[verifier] = {"returncode": completed.returncode, "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(), "stderr": completed.stderr[-2000:]}
        require(completed.returncode == 0, failures, f"prerequisite_verifier_failed:{verifier}")

    authoritative_reports = sorted(ROOT.glob("artifacts/p4_forge_acceptance*.json"))
    require(authoritative_reports == [FINAL_REPORT_PATH], failures, "duplicate_authoritative_p4_report")
    ledger = (ROOT / "docs/PHASE_LEDGER.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require("| P4 hostile runner, signer image, and supply-chain qualification | COMPLETE |" in ledger, failures, "phase_ledger_not_complete")
    require("completed_phase_gate: P4" in ledger, failures, "phase_ledger_gate_missing")
    require("completed_phase_gate: P4" in readme, failures, "readme_gate_missing")
    require("release_verdict: NOT_READY" in readme, failures, "readme_release_verdict_missing")

    branch = run(["git", "branch", "--show-current"])
    require(branch.returncode == 0 and branch.stdout.strip() == "main", failures, "git_branch_not_main")
    if not args.allow_uncommitted:
        staged = run(["git", "diff", "--cached", "--quiet"])
        require(staged.returncode == 0, failures, "staged_changes_present")

    result = {
        "schema_version": "1.0.0",
        "phase": "P4",
        "verified_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_commit": source_commit,
        "acceptance_report_sha256": sha256_file(FINAL_REPORT_PATH) if FINAL_REPORT_PATH.is_file() else None,
        "image_manifest_sha256": sha256_file(IMAGE_MANIFEST_PATH) if IMAGE_MANIFEST_PATH.is_file() else None,
        "completed_phase_gate": "P4" if not failures else "P3",
        "run_outcome": "COMPLETE" if not failures else "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
        "details": details,
        "failures": sorted(set(failures)),
        "passed": not failures,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
