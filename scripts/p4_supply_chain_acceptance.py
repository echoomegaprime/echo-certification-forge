#!/usr/bin/env python3
"""Real FORGE P4 supply-chain foundation acceptance.

This gate uses exact owned containers, public-only image attestations, deterministic
SBOM/provenance records, normalized independent-build comparison, and fail-closed
admission decisions. It does not mark the full hostile-runner P4 phase complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from echo_certification_forge.canonical import canonical_json, parse_utc_iso, sha256_bytes, to_utc_iso  # noqa: E402
from echo_certification_forge.supply_chain import (  # noqa: E402
    ImageAdmissionPolicy,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    build_spdx_document,
    evaluate_image_admission,
    scan_build_context,
    scan_dockerfile,
    sha256_json_document,
    verify_spdx_document,
)

PRIVATE_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
)
MALWARE_MARKERS = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
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
BASE_IMAGE_NAME = "python:3.12.10-slim-bookworm"
OWNED_CONTAINER_IDS: list[str] = []


def run(command: list[str], *, check: bool = True, text: bool = True) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        command,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def docker_json(*arguments: str) -> Any:
    result = run(["docker", *arguments])
    return json.loads(result.stdout)


def image_inspect(reference: str) -> dict[str, Any]:
    result = docker_json("image", "inspect", reference)
    if not isinstance(result, list) or len(result) != 1:
        raise RuntimeError(f"unexpected inspect result for {reference}")
    return result[0]


def container_ids() -> set[str]:
    result = run(["docker", "ps", "-aq"])
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def create_owned_container(
    *,
    image: str,
    name: str,
    ownership_token: str,
    command: list[str] | None = None,
    entrypoint: str | None = None,
) -> str:
    arguments = [
        "docker",
        "create",
        "--name",
        name,
        "--label",
        "echo.certforge.phase=P4",
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
        "--pids-limit",
        "32",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "0.25",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=16777216,mode=700,uid=65532,gid=65532",
    ]
    if entrypoint is not None:
        arguments.extend(["--entrypoint", entrypoint])
    arguments.append(image)
    if command:
        arguments.extend(command)
    result = run(arguments)
    container_id = result.stdout.strip()
    OWNED_CONTAINER_IDS.append(container_id)
    return container_id


def remove_exact(container_id: str) -> None:
    run(["docker", "rm", "-f", container_id], check=False)


def run_owned(
    *,
    image: str,
    case: str,
    ownership_token: str,
    command: list[str],
    entrypoint: str | None = None,
) -> dict[str, Any]:
    name = f"certforge-p4-{case}-{ownership_token[-10:]}"
    container_id = create_owned_container(
        image=image,
        name=name,
        ownership_token=ownership_token,
        command=command,
        entrypoint=entrypoint,
    )
    try:
        run(["docker", "start", container_id])
        wait_result = run(["docker", "wait", container_id])
        wait_code = int(wait_result.stdout.strip())
        inspect = docker_json("container", "inspect", container_id)[0]
        logs = run(["docker", "logs", container_id], check=False).stdout
        return {
            "container_id": container_id,
            "name": name,
            "exit_code": wait_code,
            "logs": logs,
            "config": inspect["Config"],
            "host_config": inspect["HostConfig"],
            "network_settings": inspect["NetworkSettings"],
            "state": inspect["State"],
        }
    finally:
        remove_exact(container_id)


def normalized_image_manifest(image: str, ownership_token: str) -> dict[str, Any]:
    script = r'''
import hashlib, importlib.metadata as metadata, json, pathlib, platform
root = pathlib.Path('/opt/echo')
source_files = [path for path in root.rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc']
source_manifest = [
    {
        'path': path.relative_to(root).as_posix(),
        'bytes': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    for path in sorted(source_files)
]
packages = sorted(
    [
        {'name': dist.metadata.get('Name', '').lower(), 'version': dist.version}
        for dist in metadata.distributions()
        if dist.metadata.get('Name')
    ],
    key=lambda item: (item['name'], item['version']),
)
print(json.dumps({
    'python': platform.python_version(),
    'architecture': platform.machine(),
    'source_manifest_sha256': hashlib.sha256(json.dumps(source_manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
    'source_file_count': len(source_manifest),
    'packages': packages,
}, sort_keys=True, separators=(',', ':')))
'''.strip()
    role = image_inspect(image)["Config"].get("Labels", {}).get("echo.certforge.image.role")
    entrypoint = "python" if role == "signer" else None
    command = ["-c", script] if entrypoint else ["python", "-c", script]
    result = run_owned(
        image=image,
        case=f"normalize-{role}",
        ownership_token=ownership_token,
        command=command,
        entrypoint=entrypoint,
    )
    if result["exit_code"] != 0:
        raise RuntimeError(f"normalized manifest failed for {image}: {result['logs']}")
    return json.loads(result["logs"].strip())


def containment_probe(image: str, role: ImageRole, ownership_token: str) -> dict[str, Any]:
    shell = (
        "set -eu; "
        "printf 'uid='; id -u; printf 'gid='; id -g; "
        "grep '^CapEff:' /proc/self/status; grep '^NoNewPrivs:' /proc/self/status; grep '^Seccomp:' /proc/self/status; "
        "test ! -e /var/run/docker.sock; "
        "touch /tmp/write-ok; "
        "if touch /root/forbidden 2>/dev/null; then exit 91; fi; "
        "python -c \"import echo_certification_forge; print('import=ok')\""
    )
    result = run_owned(
        image=image,
        case=f"containment-{role.value}",
        ownership_token=ownership_token,
        command=["-lc", shell],
        entrypoint="/bin/sh" if role is ImageRole.SIGNER else "/bin/sh",
    )
    host = result["host_config"]
    networks = result["network_settings"].get("Networks") or {}
    checks = {
        "exit_zero": result["exit_code"] == 0,
        "uid_65532": "uid=65532" in result["logs"],
        "gid_65532": "gid=65532" in result["logs"],
        "capabilities_zero": "CapEff:\t0000000000000000" in result["logs"],
        "no_new_privileges": "NoNewPrivs:\t1" in result["logs"],
        "seccomp_enforcing": "Seccomp:\t2" in result["logs"],
        "read_only_root": host.get("ReadonlyRootfs") is True,
        "network_none": host.get("NetworkMode") == "none" and not [name for name in networks if name != "none"],
        "all_capabilities_dropped": host.get("CapDrop") == ["ALL"],
        "pids_limited": host.get("PidsLimit") == 32,
        "memory_limited": host.get("Memory") == 268435456 and host.get("MemorySwap") == 268435456,
        "cpu_limited": host.get("NanoCpus") == 250000000,
        "tmp_writable": "import=ok" in result["logs"],
        "docker_socket_absent": "docker.sock" not in canonical_json(
            {
                "binds": host.get("Binds"),
                "mounts": host.get("Mounts"),
                "volumes_from": host.get("VolumesFrom"),
                "config_volumes": result["config"].get("Volumes"),
            }
        ),
    }
    return {**result, "checks": checks, "passed": all(checks.values())}


def scan_image_filesystem(image: str, ownership_token: str) -> dict[str, Any]:
    role = image_inspect(image)["Config"].get("Labels", {}).get("echo.certforge.image.role", "unknown")
    name = f"certforge-p4-files-{role}-{ownership_token[-10:]}"
    container_id = create_owned_container(
        image=image,
        name=name,
        ownership_token=ownership_token,
        command=["/bin/true"],
        entrypoint="/bin/true",
    )
    findings: list[dict[str, Any]] = []
    file_count = 0
    try:
        process = subprocess.Popen(["docker", "export", container_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                file_count += 1
                normalized = PurePosixPath(member.name.lstrip("./"))
                components = set(normalized.parts)
                forbidden = sorted(components & FORBIDDEN_PATH_COMPONENTS)
                if forbidden:
                    findings.append({"path": member.name, "rule": "forbidden_path", "tokens": forbidden})
                if member.mode & (stat.S_ISUID | stat.S_ISGID):
                    findings.append({"path": member.name, "rule": "setuid_or_setgid"})
                if member.issym() or member.islnk():
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or ".." in target.parts:
                        findings.append({"path": member.name, "rule": "escaping_link", "target": member.linkname})
                if member.isfile() and 0 < member.size <= 1024 * 1024:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    payload = extracted.read()
                    if any(marker in payload for marker in PRIVATE_MARKERS):
                        findings.append({"path": member.name, "rule": "private_key_material"})
                    if any(marker in payload for marker in MALWARE_MARKERS):
                        findings.append({"path": member.name, "rule": "malware_signature"})
        stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr is not None else ""
        exit_code = process.wait(timeout=60)
        if exit_code != 0:
            raise RuntimeError(f"docker export failed for {image}: {stderr}")
    finally:
        remove_exact(container_id)
    return {"image": image, "file_count": file_count, "findings": findings, "passed": not findings}


def make_provenance(
    *,
    image_name: str,
    image_digest: str,
    base_digest: str,
    source_commit: str,
    dockerfile_sha256: str,
    lockfile_sha256: str,
    context_sha256: str,
    created_at: datetime,
) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": image_name, "digest": {"sha256": image_digest.split(":", 1)[1]}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://cert.echoforge.com/buildtypes/docker-v1",
                "externalParameters": {
                    "source_commit": source_commit,
                    "dockerfile_sha256": dockerfile_sha256,
                    "lockfile_sha256": lockfile_sha256,
                },
                "internalParameters": {"network_during_dependency_resolution": True},
                "resolvedDependencies": [
                    {"uri": f"docker-image://{BASE_IMAGE_NAME}", "digest": {"sha256": base_digest.split(":", 1)[1]}},
                    {"uri": "git+https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge", "digest": {"gitCommit": source_commit}},
                    {"uri": "build-context://normalized", "digest": {"sha256": context_sha256}},
                ],
            },
            "runDetails": {
                "builder": {"id": "docker-buildx://forge"},
                "metadata": {"invocationId": str(uuid.uuid4()), "startedOn": to_utc_iso(created_at)},
            },
        },
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--runner-compare-image", required=True)
    parser.add_argument("--signer-image", required=True)
    parser.add_argument("--signer-compare-image", required=True)
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    workspace = arguments.workspace.resolve()
    output = arguments.output.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    ownership_token = f"owner.p4.{uuid.uuid4().hex}"
    containers_before = container_ids()
    OWNED_CONTAINER_IDS.clear()
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "phase": "P4",
        "phase_state": "SUPPLY_CHAIN_FOUNDATION",
        "started_at_utc": to_utc_iso(started),
        "source_commit": arguments.source_commit,
        "base_image": f"{BASE_IMAGE_NAME}@{arguments.base_digest}",
        "images": {},
        "checks": {},
        "cleanup": {},
        "passed": False,
        "run_outcome": "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
    }
    try:
        source_root = ROOT
        dockerfiles = {
            ImageRole.RUNNER: source_root / "images/runner/Dockerfile",
            ImageRole.SIGNER: source_root / "images/signer/Dockerfile",
        }
        lockfile = source_root / "images/requirements.lock"
        context_scan = scan_build_context(source_root, max_files=20_000, max_bytes=1024 * 1024 * 1024)
        require(context_scan.valid, f"build context invalid: {context_scan.findings}")
        lockfile_sha256 = hashlib.sha256(lockfile.read_bytes()).hexdigest()
        authority = ImageAttestationAuthority.generate()

        image_pairs = {
            ImageRole.RUNNER: (arguments.runner_image, arguments.runner_compare_image),
            ImageRole.SIGNER: (arguments.signer_image, arguments.signer_compare_image),
        }
        for role, (image, comparison_image) in image_pairs.items():
            inspect = image_inspect(image)
            compare_inspect = image_inspect(comparison_image)
            labels = inspect["Config"].get("Labels") or {}
            image_digest = inspect["Id"]
            compare_digest = compare_inspect["Id"]
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None, f"invalid image digest: {image}")
            require(labels.get("echo.certforge.image.role") == role.value, f"role label mismatch: {image}")
            require(labels.get("org.opencontainers.image.base.digest") == arguments.base_digest, f"base label mismatch: {image}")
            require(labels.get("org.opencontainers.image.revision") == arguments.source_commit, f"source label mismatch: {image}")
            require(inspect["Config"].get("User") == "65532:65532", f"image user mismatch: {image}")
            dockerfile_text = dockerfiles[role].read_text(encoding="utf-8")
            dockerfile_scan = scan_dockerfile(dockerfile_text)
            require(dockerfile_scan.valid, f"Dockerfile invalid for {role.value}: {dockerfile_scan.findings}")

            normalized = normalized_image_manifest(image, ownership_token)
            comparison = normalized_image_manifest(comparison_image, ownership_token)
            comparable = normalized == comparison
            require(comparable, f"independent build comparison failed for {role.value}")
            packages = normalized["packages"]
            sbom = build_spdx_document(
                image_name=f"echo-certforge-{role.value}",
                image_digest=image_digest,
                packages=packages,
                created_at=parse_utc_iso(inspect["Created"]),
            )
            sbom_valid, sbom_reason = verify_spdx_document(sbom, image_digest=image_digest)
            require(sbom_valid, f"SBOM invalid for {role.value}: {sbom_reason}")
            sbom_path = workspace / f"{role.value}.spdx.json"
            sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            sbom_sha256 = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
            provenance = make_provenance(
                image_name=f"echo-certforge-{role.value}",
                image_digest=image_digest,
                base_digest=arguments.base_digest,
                source_commit=arguments.source_commit,
                dockerfile_sha256=dockerfile_scan.sha256,
                lockfile_sha256=lockfile_sha256,
                context_sha256=context_scan.manifest_sha256,
                created_at=parse_utc_iso(inspect["Created"]),
            )
            provenance_path = workspace / f"{role.value}.provenance.json"
            provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            provenance_sha256 = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
            identity = ImageIdentity(
                role=role,
                image_digest=image_digest,
                base_image_digest=arguments.base_digest,
                source_commit=arguments.source_commit,
                dockerfile_sha256=dockerfile_scan.sha256,
                lockfile_sha256=lockfile_sha256,
                sbom_sha256=sbom_sha256,
                provenance_sha256=provenance_sha256,
                architecture=inspect["Architecture"],
                operating_system=inspect["Os"],
                created_at=parse_utc_iso(inspect["Created"]),
            )
            attestation = authority.sign(identity)
            attestation_path = workspace / f"{role.value}.attestation.json"
            attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
            policy = ImageAdmissionPolicy(
                policy_id=f"p4.{role.value}.v1",
                required_role=role,
                expected_image_digest=image_digest,
                approved_base_digests=(arguments.base_digest,),
                approved_source_commits=(arguments.source_commit,),
                approved_dockerfile_sha256=dockerfile_scan.sha256,
                approved_lockfile_sha256=lockfile_sha256,
                trusted_attestation_keys={authority.key_id: authority.public_key_pem},
            )
            admitted = evaluate_image_admission(attestation, policy)
            revoked = evaluate_image_admission(
                attestation,
                policy.model_copy(update={"revoked_image_digests": (image_digest,)}),
            )
            drifted = evaluate_image_admission(
                attestation,
                policy.model_copy(update={"expected_image_digest": "sha256:" + "0" * 64}),
            )
            require(admitted.allowed, f"image admission failed: {role.value}:{admitted.reasons}")
            require(not revoked.allowed and "image_digest_revoked" in revoked.reasons, f"revocation denial failed: {role.value}")
            require(not drifted.allowed and "image_digest_drift" in drifted.reasons, f"drift denial failed: {role.value}")
            containment = containment_probe(image, role, ownership_token)
            require(containment["passed"], f"containment failed: {role.value}:{containment['checks']}")
            filesystem = scan_image_filesystem(image, ownership_token)
            require(filesystem["passed"], f"image file scan failed: {role.value}:{filesystem['findings']}")
            report["images"][role.value] = {
                "reference": image,
                "image_digest": image_digest,
                "comparison_reference": comparison_image,
                "comparison_image_digest": compare_digest,
                "exact_digest_reproducible": image_digest == compare_digest,
                "independently_comparable": comparable,
                "normalized_manifest": normalized,
                "dockerfile_sha256": dockerfile_scan.sha256,
                "lockfile_sha256": lockfile_sha256,
                "sbom": {"path": str(sbom_path), "sha256": sbom_sha256, "verified": True},
                "provenance": {"path": str(provenance_path), "sha256": provenance_sha256},
                "attestation": {
                    "path": str(attestation_path),
                    "key_id": authority.key_id,
                    "public_key_pem": authority.public_key_pem,
                    "private_key_persisted": False,
                },
                "admission": admitted.model_dump(mode="json"),
                "revoked_admission": revoked.model_dump(mode="json"),
                "drifted_admission": drifted.model_dump(mode="json"),
                "containment": containment,
                "filesystem_scan": filesystem,
            }

        checks = {
            "pinned_base_digest": True,
            "hash_locked_dependencies": True,
            "runner_purpose_built": report["images"]["runner"]["image_digest"] != report["images"]["signer"]["image_digest"],
            "signer_purpose_built": report["images"]["signer"]["image_digest"] != report["images"]["runner"]["image_digest"],
            "runner_independently_comparable": report["images"]["runner"]["independently_comparable"],
            "signer_independently_comparable": report["images"]["signer"]["independently_comparable"],
            "runner_sbom_verified": report["images"]["runner"]["sbom"]["verified"],
            "signer_sbom_verified": report["images"]["signer"]["sbom"]["verified"],
            "runner_admitted": report["images"]["runner"]["admission"]["allowed"],
            "signer_admitted": report["images"]["signer"]["admission"]["allowed"],
            "runner_revocation_denied": not report["images"]["runner"]["revoked_admission"]["allowed"],
            "signer_revocation_denied": not report["images"]["signer"]["revoked_admission"]["allowed"],
            "runner_drift_denied": not report["images"]["runner"]["drifted_admission"]["allowed"],
            "signer_drift_denied": not report["images"]["signer"]["drifted_admission"]["allowed"],
            "runner_containment": report["images"]["runner"]["containment"]["passed"],
            "signer_containment": report["images"]["signer"]["containment"]["passed"],
            "runner_forbidden_file_scan": report["images"]["runner"]["filesystem_scan"]["passed"],
            "signer_forbidden_file_scan": report["images"]["signer"]["filesystem_scan"]["passed"],
            "attestation_key_domains_public_only": all(
                not image["attestation"]["private_key_persisted"] for image in report["images"].values()
            ),
        }
        report["checks"] = checks
        require(all(checks.values()), f"P4 supply-chain checks failed: {checks}")
        report["passed"] = True
        report["run_outcome"] = "COMPLETE"
        return_code = 0
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        report["run_outcome"] = "INFRA_FAILED"
        return_code = 1
    finally:
        containers_after = container_ids()
        report["cleanup"] = {
            "containers_before": len(containers_before),
            "containers_after": len(containers_after),
            "unrelated_container_ids_preserved": containers_before == containers_after,
            "owned_container_ids": list(OWNED_CONTAINER_IDS),
        }
        report["completed_at_utc"] = to_utc_iso(datetime.now(UTC))
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "output": str(output),
                    "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                    "passed": report["passed"],
                    "run_outcome": report["run_outcome"],
                    "release_verdict": report["release_verdict"],
                    "phase_state": report["phase_state"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
