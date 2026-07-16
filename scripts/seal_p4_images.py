#!/usr/bin/env python3
"""Seal and independently preflight the twelve immutable P4 production images."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from echo_certification_forge.canonical import parse_utc_iso, sha256_bytes, to_utc_iso  # noqa: E402
from echo_certification_forge.p4_manifest import (  # noqa: E402
    P4ArtifactRef,
    P4ImageManifest,
    P4ImageRecord,
    sha256_file,
    verify_p4_image_manifest,
    write_manifest,
)
from echo_certification_forge.supply_chain import (  # noqa: E402
    ImageAdmissionPolicy,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    build_spdx_document,
    evaluate_image_admission,
    scan_dockerfile,
    verify_spdx_document,
)

ROLE_ORDER = tuple(ImageRole)
VARIANTS = ("a", "b")
BASE_NAME = "python:3.12-alpine"
SENSITIVE_ENV_TOKENS = ("PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY", "STRIPE", "AWS_ACCESS", "ECHO_SOVEREIGN")
DEV_PACKAGES = {"pytest", "pytest-cov", "hatchling", "build", "twine", "ruff", "mypy", "tox", "coverage"}
NETWORK_PACKAGES = {"curl", "git", "openssh-client", "openssh", "netcat", "nmap", "socat"}


def run(
    command: list[str],
    *,
    check: bool = True,
    text: bool = True,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[Any]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        command,
        check=check,
        text=text,
        timeout=timeout,
        env=merged,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def relative_ref(manifest_parent: Path, path: Path) -> P4ArtifactRef:
    return P4ArtifactRef(path=path.relative_to(manifest_parent).as_posix(), sha256=sha256_file(path))


def inspect_image(reference: str) -> dict[str, Any]:
    document = json.loads(run(["docker", "image", "inspect", reference]).stdout)
    require(isinstance(document, list) and len(document) == 1, f"unexpected image inspect response: {reference}")
    return document[0]


def saved_image_metadata(reference: str, workspace: Path) -> dict[str, str]:
    with tempfile.NamedTemporaryFile(prefix="p4-image-", suffix=".tar", dir=workspace, delete=False) as handle:
        archive_path = Path(handle.name)
    try:
        run(["docker", "image", "save", reference, "-o", str(archive_path)], timeout=240)
        with tarfile.open(archive_path, "r:") as archive:
            names = set(archive.getnames())
            require("manifest.json" in names and "index.json" in names, f"sealed image archive metadata missing: {reference}")
            docker_manifest = json.load(archive.extractfile("manifest.json"))
            oci_index = json.load(archive.extractfile("index.json"))
            require(len(docker_manifest) == 1, f"unexpected docker manifest count: {reference}")
            require(len(oci_index.get("manifests") or []) == 1, f"unexpected OCI index count: {reference}")
            config_name = str(docker_manifest[0]["Config"])
            config_digest = "sha256:" + Path(config_name).name
            manifest_digest = str(oci_index["manifests"][0]["digest"])
            require(config_digest.startswith("sha256:") and len(config_digest) == 71, "invalid config digest")
            require(manifest_digest.startswith("sha256:") and len(manifest_digest) == 71, "invalid manifest digest")
            return {
                "config_digest": config_digest,
                "manifest_digest": manifest_digest,
                "archive_sha256": sha256_file(archive_path),
            }
    finally:
        archive_path.unlink(missing_ok=True)


def normalized_manifest(reference: str) -> dict[str, Any]:
    code = r'''
import hashlib, importlib.metadata as metadata, json, pathlib, platform
root=pathlib.Path('/opt/echo')
files=[]
for p in sorted(root.rglob('*')):
    if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc':
        files.append({'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
packages=sorted([{'name':d.metadata.get('Name','').lower(),'version':d.version} for d in metadata.distributions() if d.metadata.get('Name')],key=lambda x:(x['name'],x['version']))
print(json.dumps({'python':platform.python_version(),'architecture':platform.machine(),'source_manifest_sha256':hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'source_file_count':len(files),'packages':packages},sort_keys=True,separators=(',',':')))
'''.strip()
    result = run(
        [
            "docker",
            "run",
            "--rm",
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
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.25",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=8m,mode=700,uid=65532,gid=65532",
            "--entrypoint",
            "python",
            reference,
            "-c",
            code,
        ],
        timeout=60,
    )
    return json.loads(result.stdout.splitlines()[-1])


def runtime_preflight(reference: str, inspect: dict[str, Any], output: Path) -> dict[str, Any]:
    code = r'''
import importlib.metadata as metadata, json, os, pathlib
packages=sorted({d.metadata.get('Name','').lower() for d in metadata.distributions() if d.metadata.get('Name')})
forbidden_env=[]
for key in os.environ:
    upper=key.upper()
    if any(token in upper for token in ('PASSWORD','SECRET','TOKEN','PRIVATE_KEY','STRIPE','AWS_ACCESS','ECHO_SOVEREIGN')):
        forbidden_env.append(key)
history=[p for p in ('/root/.ash_history','/root/.bash_history','/home/certforge/.ash_history','/home/certforge/.bash_history') if pathlib.Path(p).exists()]
cache=[]
for p in ('/root/.cache/pip','/var/cache/apk','/tmp/requirements.lock'):
    path=pathlib.Path(p)
    if path.is_file() or (path.is_dir() and any(path.iterdir())): cache.append(p)
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'forbidden_env':forbidden_env,'shell_history':history,'unexpected_cache':cache,'packages':packages},sort_keys=True,separators=(',',':')))
'''.strip()
    result = run(
        [
            "docker",
            "run",
            "--rm",
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
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.25",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=8m,mode=700,uid=65532,gid=65532",
            "--entrypoint",
            "python",
            reference,
            "-c",
            code,
        ],
        check=False,
        timeout=60,
    )
    payload = json.loads(result.stdout.splitlines()[-1]) if result.returncode == 0 and result.stdout.strip() else {}
    package_names = set(payload.get("packages") or [])
    dev_found = sorted(package_names & DEV_PACKAGES)
    network_found = sorted(package_names & NETWORK_PACKAGES)
    config = inspect.get("Config") or {}
    health = (config.get("Healthcheck") or {}).get("Test") or []
    entrypoint = config.get("Entrypoint") or []
    command = config.get("Cmd") or []
    privileged_entrypoint = bool(entrypoint and str(entrypoint[0]).lower() in {"su", "sudo", "doas"})
    document = {
        "reference": reference,
        "container_returncode": result.returncode,
        "uid": payload.get("uid"),
        "gid": payload.get("gid"),
        "read_only_root_compatible": result.returncode == 0,
        "network_mode": "none",
        "forbidden_environment_names": payload.get("forbidden_env") or [],
        "shell_history": payload.get("shell_history") or [],
        "unexpected_package_cache": payload.get("unexpected_cache") or [],
        "development_packages": dev_found,
        "network_client_packages": network_found,
        "privileged_entrypoint": privileged_entrypoint,
        "entrypoint": entrypoint,
        "command": command,
        "health_command": health,
    }
    document["passed"] = (
        result.returncode == 0
        and payload.get("uid") == 65532
        and payload.get("gid") == 65532
        and not document["forbidden_environment_names"]
        and not document["shell_history"]
        and not document["unexpected_package_cache"]
        and not dev_found
        and not network_found
        and not privileged_entrypoint
        and bool(health)
    )
    write_json(output, document)
    return document


def trivy_scan(trivy: Path, reference: str, raw_output: Path, summary_output: Path) -> dict[str, Any]:
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
            str(raw_output),
            reference,
        ],
        check=False,
        timeout=600,
    )
    require(raw_output.is_file(), f"Trivy output missing for {reference}: {result.stderr}")
    document = json.loads(raw_output.read_text(encoding="utf-8"))
    vulnerabilities: list[dict[str, Any]] = []
    secrets_found: list[dict[str, Any]] = []
    for section in document.get("Results") or []:
        vulnerabilities.extend(section.get("Vulnerabilities") or [])
        secrets_found.extend(section.get("Secrets") or [])
    critical = [item for item in vulnerabilities if str(item.get("Severity", "")).upper() == "CRITICAL"]
    fixed = [
        item
        for item in vulnerabilities
        if str(item.get("Severity", "")).upper() in {"HIGH", "CRITICAL"}
        and str(item.get("FixedVersion") or "").strip()
    ]
    summary = {
        "reference": reference,
        "tool_returncode": result.returncode,
        "raw_report_path": raw_output.name,
        "raw_report_sha256": sha256_file(raw_output),
        "vulnerability_count": len(vulnerabilities),
        "critical_count": len(critical),
        "fixed_high_or_critical_count": len(fixed),
        "secret_finding_count": len(secrets_found),
        "passed": not critical and not fixed and not secrets_found,
        "blocking_findings": [
            {
                "id": item.get("VulnerabilityID"),
                "package": item.get("PkgName"),
                "installed": item.get("InstalledVersion"),
                "fixed": item.get("FixedVersion"),
                "severity": item.get("Severity"),
            }
            for item in (critical + fixed)[:100]
        ],
    }
    write_json(summary_output, summary)
    return summary


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    require(isinstance(key, Ed25519PrivateKey), "P4 attestation key must be Ed25519")
    return key


def parse_reference(reference: str) -> tuple[str, str]:
    require("@" not in reference, "sealer expects the exact locally built tag and resolves its immutable repo digest")
    require(":" in reference, f"image reference has no tag: {reference}")
    repository, tag = reference.rsplit(":", 1)
    return repository, tag


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--images", type=Path, required=True, help="Role mapping with primary and comparison tags")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--attestation-private-key", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--build-host-identity", default="forge:192.168.1.220:rootful-docker")
    args = parser.parse_args()

    require(len(args.source_commit) == 40, "source commit must be exact")
    require(args.base_digest.startswith("sha256:") and len(args.base_digest) == 71, "base digest must be exact")
    require(args.trivy.is_file(), "Trivy binary missing")
    require(args.attestation_private_key.is_file(), "attestation private key missing")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.manifest.resolve()
    require(manifest_path.parent == output_dir, "manifest must be stored directly in output-dir")

    image_document = json.loads(args.images.read_text(encoding="utf-8"))
    image_map = image_document.get("images")
    require(isinstance(image_map, dict) and set(image_map) == {role.value for role in ROLE_ORDER}, "image role map mismatch")

    private_key = load_private_key(args.attestation_private_key)
    authority = ImageAttestationAuthority(private_key)
    issued_at = datetime.now(UTC)
    public_path = output_dir / "p4-attestation-public.pem"
    public_path.write_text(authority.public_key_pem, encoding="ascii")
    lockfile = ROOT / "images/requirements.lock"
    lock_sha = sha256_file(lockfile)
    records: list[P4ImageRecord] = []
    images_for_acceptance: dict[str, dict[str, str]] = {}

    for role in ROLE_ORDER:
        images_for_acceptance[role.value] = {}
        pair_normalized: dict[str, dict[str, Any]] = {}
        for variant, source_key in (("a", "primary"), ("b", "comparison")):
            reference = str(image_map[role.value][source_key])
            repository, tag = parse_reference(reference)
            inspect = inspect_image(reference)
            labels = {str(key): str(value) for key, value in ((inspect.get("Config") or {}).get("Labels") or {}).items()}
            expected_policy = f"p4.{role.value}.production.v1"
            expected_labels = {
                "echo.certforge.image.role": role.value,
                "echo.certforge.image.variant": variant,
                "echo.certforge.admission.policy": expected_policy,
                "echo.certforge.attestation.key_id": authority.key_id,
                "org.opencontainers.image.revision": args.source_commit,
                "org.opencontainers.image.base.digest": args.base_digest,
            }
            for name, value in expected_labels.items():
                require(labels.get(name) == value, f"image label mismatch {role.value}.{variant}:{name}")
            require((inspect.get("Config") or {}).get("User") == "65532:65532", f"runtime user mismatch: {role.value}.{variant}")
            health = ((inspect.get("Config") or {}).get("Healthcheck") or {}).get("Test") or []
            require(bool(health), f"health command missing: {role.value}.{variant}")
            dockerfile = ROOT / f"images/{role.value}/Dockerfile"
            docker_scan = scan_dockerfile(dockerfile.read_text(encoding="utf-8"))
            require(docker_scan.valid, f"Dockerfile policy failed: {role.value}:{docker_scan.findings}")
            archive_meta = saved_image_metadata(reference, output_dir)
            repo_digests = inspect.get("RepoDigests") or []
            require(len(repo_digests) == 1, f"exact repo digest missing: {role.value}.{variant}")
            repo_digest = str(repo_digests[0])
            require(repo_digest.endswith(archive_meta["manifest_digest"]), f"repo/manifest digest mismatch: {role.value}.{variant}")
            normalized = normalized_manifest(reference)
            pair_normalized[variant] = normalized

            record_dir = output_dir / "records" / role.value / variant
            record_dir.mkdir(parents=True, exist_ok=True)
            sbom_path = record_dir / f"{role.value}-{variant}.spdx.json"
            sbom = build_spdx_document(
                image_name=f"echo-certforge-{role.value}-{variant}",
                image_digest=archive_meta["manifest_digest"],
                packages=normalized["packages"],
                created_at=parse_utc_iso(inspect["Created"]),
            )
            valid_sbom, sbom_reason = verify_spdx_document(sbom, image_digest=archive_meta["manifest_digest"])
            require(valid_sbom, f"SBOM failed: {role.value}.{variant}:{sbom_reason}")
            write_json(sbom_path, sbom)

            provenance_path = record_dir / f"{role.value}-{variant}.provenance.json"
            provenance = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": f"echo-certforge-{role.value}-{variant}",
                        "digest": {"sha256": archive_meta["manifest_digest"].split(":", 1)[1]},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://cert.echoforge.com/buildtypes/docker-v2",
                        "externalParameters": {
                            "source_commit": args.source_commit,
                            "variant": variant,
                            "dockerfile_sha256": docker_scan.sha256,
                            "lockfile_sha256": lock_sha,
                            "attestation_key_id": authority.key_id,
                            "admission_policy_id": expected_policy,
                        },
                        "resolvedDependencies": [
                            {"uri": f"docker-image://{BASE_NAME}", "digest": {"sha256": args.base_digest.split(":", 1)[1]}},
                            {
                                "uri": "git+https://github.com/ECHO-OMEGA-PRIME/echo-certification-forge",
                                "digest": {"gitCommit": args.source_commit},
                            },
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": args.build_host_identity},
                        "metadata": {"startedOn": inspect["Created"]},
                    },
                },
            }
            write_json(provenance_path, provenance)

            identity = ImageIdentity(
                role=role,
                image_digest=archive_meta["manifest_digest"],
                base_image_digest=args.base_digest,
                source_commit=args.source_commit,
                dockerfile_sha256=docker_scan.sha256,
                lockfile_sha256=lock_sha,
                sbom_sha256=sha256_file(sbom_path),
                provenance_sha256=sha256_file(provenance_path),
                architecture=str(inspect["Architecture"]),
                operating_system=str(inspect["Os"]),
                created_at=parse_utc_iso(inspect["Created"]),
            )
            attestation = authority.sign(identity, issued_at=issued_at, valid_for=timedelta(days=30))
            attestation_path = record_dir / f"{role.value}-{variant}.attestation.json"
            attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
            policy = ImageAdmissionPolicy(
                policy_id=expected_policy,
                required_role=role,
                expected_image_digest=archive_meta["manifest_digest"],
                approved_base_digests=(args.base_digest,),
                approved_source_commits=(args.source_commit,),
                approved_dockerfile_sha256=docker_scan.sha256,
                approved_lockfile_sha256=lock_sha,
                trusted_attestation_keys={authority.key_id: authority.public_key_pem},
            )
            policy_path = record_dir / f"{role.value}-{variant}.admission-policy.json"
            policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
            admission = evaluate_image_admission(attestation, policy, now=issued_at + timedelta(seconds=1))
            require(admission.allowed, f"sealed image admission failed: {role.value}.{variant}:{admission.reasons}")

            raw_scan = record_dir / f"{role.value}-{variant}.trivy.raw.json"
            scan_summary = record_dir / f"{role.value}-{variant}.vulnerability.json"
            vulnerability = trivy_scan(args.trivy, reference, raw_scan, scan_summary)
            require(vulnerability["passed"], f"vulnerability policy failed: {role.value}.{variant}:{vulnerability['blocking_findings']}")
            runtime_path = record_dir / f"{role.value}-{variant}.runtime.json"
            runtime = runtime_preflight(reference, inspect, runtime_path)
            require(runtime["passed"], f"runtime preflight failed: {role.value}.{variant}:{runtime}")

            record = P4ImageRecord(
                role=role,
                variant=variant,
                repository=repository,
                tag=tag,
                reference=reference,
                image_id=str(inspect["Id"]),
                repo_digest=repo_digest,
                config_digest=archive_meta["config_digest"],
                manifest_digest=archive_meta["manifest_digest"],
                platform=f"{inspect['Os']}/{inspect['Architecture']}",
                architecture=str(inspect["Architecture"]),
                operating_system=str(inspect["Os"]),
                source_commit=args.source_commit,
                base_image_reference=f"{BASE_NAME}@{args.base_digest}",
                base_digest=args.base_digest,
                dockerfile_path=f"images/{role.value}/Dockerfile",
                dockerfile_sha256=docker_scan.sha256,
                lockfile_path="images/requirements.lock",
                lockfile_sha256=lock_sha,
                sbom=relative_ref(output_dir, sbom_path),
                provenance=relative_ref(output_dir, provenance_path),
                attestation=relative_ref(output_dir, attestation_path),
                admission_policy=relative_ref(output_dir, policy_path),
                vulnerability_scan=relative_ref(output_dir, scan_summary),
                runtime_scan=relative_ref(output_dir, runtime_path),
                attestation_identity=authority.key_id,
                attestation_public_key_fingerprint=authority.key_id,
                attestation_created_at=attestation.issued_at,
                attestation_expiration_time=attestation.expires_at,
                runtime_uid=65532,
                runtime_gid=65532,
                entrypoint=tuple((inspect.get("Config") or {}).get("Entrypoint") or ()),
                command=tuple((inspect.get("Config") or {}).get("Cmd") or ()),
                health_command=tuple(health),
                admission_policy_identity=expected_policy,
                build_timestamp=parse_utc_iso(inspect["Created"]),
                build_host_identity=args.build_host_identity,
                normalized_manifest_sha256=normalized["source_manifest_sha256"],
                source_file_count=int(normalized["source_file_count"]),
                package_count=len(normalized["packages"]),
                labels=labels,
            )
            records.append(record)
            images_for_acceptance[role.value][source_key] = reference
        require(pair_normalized["a"] == pair_normalized["b"], f"A/B normalized comparison failed: {role.value}")

    manifest = P4ImageManifest(
        source_commit=args.source_commit,
        base_image_reference=f"{BASE_NAME}@{args.base_digest}",
        base_digest=args.base_digest,
        created_at_utc=issued_at,
        build_host_identity=args.build_host_identity,
        attestation_public_key=relative_ref(output_dir, public_path),
        attestation_key_id=authority.key_id,
        records=tuple(sorted(records, key=lambda item: (item.role.value, item.variant))),
    )
    manifest_sha = write_manifest(manifest_path, manifest)
    acceptance_images = output_dir / "images.json"
    write_json(
        acceptance_images,
        {
            "schema_version": "1.0.0",
            "source_commit": args.source_commit,
            "sealed_manifest": manifest_path.name,
            "sealed_manifest_sha256": manifest_sha,
            "images": images_for_acceptance,
        },
    )
    verification = verify_p4_image_manifest(
        manifest_path,
        expected_source_commit=args.source_commit,
        expected_base_digest=args.base_digest,
        now=issued_at + timedelta(seconds=1),
    )
    verification_path = output_dir / "manifest-verification.json"
    write_json(verification_path, verification)
    require(verification["passed"], f"sealed manifest verification failed: {verification['failures']}")
    print(
        json.dumps(
            {
                "manifest": str(manifest_path),
                "manifest_sha256": manifest_sha,
                "records": len(records),
                "attestation_key_id": authority.key_id,
                "images": str(acceptance_images),
                "verification": str(verification_path),
                "passed": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
