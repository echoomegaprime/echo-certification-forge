from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from echo_certification_forge.p4_manifest import (
    P4ArtifactRef,
    P4ImageManifest,
    P4ImageRecord,
    sha256_file,
    verify_p4_image_manifest,
    write_manifest,
)
from echo_certification_forge.supply_chain import (
    ImageAdmissionPolicy,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    build_spdx_document,
)

SOURCE = "1" * 40
BASE = "sha256:" + "2" * 64
NOW = datetime(2026, 7, 16, 12, tzinfo=UTC)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ref(root: Path, path: Path) -> P4ArtifactRef:
    return P4ArtifactRef(path=path.relative_to(root).as_posix(), sha256=sha256_file(path))


def _build_manifest(root: Path) -> Path:
    authority = ImageAttestationAuthority.generate()
    public_path = root / "public.pem"
    public_path.write_text(authority.public_key_pem, encoding="ascii")
    records: list[P4ImageRecord] = []
    index = 0
    for role in ImageRole:
        for variant in ("a", "b"):
            index += 1
            digest = "sha256:" + f"{index:064x}"
            config = "sha256:" + f"{index + 100:064x}"
            record_dir = root / "records" / role.value / variant
            sbom_path = record_dir / "sbom.json"
            provenance_path = record_dir / "provenance.json"
            attestation_path = record_dir / "attestation.json"
            policy_path = record_dir / "policy.json"
            vulnerability_path = record_dir / "vulnerability.json"
            runtime_path = record_dir / "runtime.json"
            sbom = build_spdx_document(
                image_name=f"{role.value}-{variant}",
                image_digest=digest,
                packages=[{"name": "pydantic", "version": "2.13.4"}],
                created_at=NOW,
            )
            _write_json(sbom_path, sbom)
            dockerfile_sha = f"{index + 200:064x}"
            lockfile_sha = "3" * 64
            provenance = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": f"{role.value}-{variant}", "digest": {"sha256": digest.split(":", 1)[1]}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "externalParameters": {
                            "source_commit": SOURCE,
                            "dockerfile_sha256": dockerfile_sha,
                            "lockfile_sha256": lockfile_sha,
                        }
                    }
                },
            }
            _write_json(provenance_path, provenance)
            identity = ImageIdentity(
                role=role,
                image_digest=digest,
                base_image_digest=BASE,
                source_commit=SOURCE,
                dockerfile_sha256=dockerfile_sha,
                lockfile_sha256=lockfile_sha,
                sbom_sha256=sha256_file(sbom_path),
                provenance_sha256=sha256_file(provenance_path),
                architecture="amd64",
                operating_system="linux",
                created_at=NOW,
            )
            attestation = authority.sign(identity, issued_at=NOW, valid_for=timedelta(days=30))
            attestation_path.parent.mkdir(parents=True, exist_ok=True)
            attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
            policy = ImageAdmissionPolicy(
                policy_id=f"p4.{role.value}.production.v1",
                required_role=role,
                expected_image_digest=digest,
                approved_base_digests=(BASE,),
                approved_source_commits=(SOURCE,),
                approved_dockerfile_sha256=dockerfile_sha,
                approved_lockfile_sha256=lockfile_sha,
                trusted_attestation_keys={authority.key_id: authority.public_key_pem},
            )
            policy_path.write_text(policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
            _write_json(
                vulnerability_path,
                {
                    "critical_count": 0,
                    "fixed_high_or_critical_count": 0,
                    "secret_finding_count": 0,
                    "passed": True,
                },
            )
            _write_json(runtime_path, {"passed": True})
            labels = {
                "echo.certforge.image.role": role.value,
                "echo.certforge.image.variant": variant,
                "echo.certforge.admission.policy": policy.policy_id,
                "echo.certforge.attestation.key_id": authority.key_id,
                "org.opencontainers.image.revision": SOURCE,
                "org.opencontainers.image.base.digest": BASE,
            }
            records.append(
                P4ImageRecord(
                    role=role,
                    variant=variant,
                    repository=f"echo-certforge-{role.value}",
                    tag=f"p4-test-{variant}",
                    reference=f"echo-certforge-{role.value}:p4-test-{variant}",
                    image_id=digest,
                    repo_digest=f"echo-certforge-{role.value}@{digest}",
                    config_digest=config,
                    manifest_digest=digest,
                    platform="linux/amd64",
                    architecture="amd64",
                    operating_system="linux",
                    source_commit=SOURCE,
                    base_image_reference=f"python:3.12-alpine@{BASE}",
                    base_digest=BASE,
                    dockerfile_path=f"images/{role.value}/Dockerfile",
                    dockerfile_sha256=dockerfile_sha,
                    lockfile_path="images/requirements.lock",
                    lockfile_sha256=lockfile_sha,
                    sbom=_ref(root, sbom_path),
                    provenance=_ref(root, provenance_path),
                    attestation=_ref(root, attestation_path),
                    admission_policy=_ref(root, policy_path),
                    vulnerability_scan=_ref(root, vulnerability_path),
                    runtime_scan=_ref(root, runtime_path),
                    attestation_identity=authority.key_id,
                    attestation_public_key_fingerprint=authority.key_id,
                    attestation_created_at=NOW,
                    attestation_expiration_time=NOW + timedelta(days=30),
                    health_command=("CMD", "python", "-c", "pass"),
                    admission_policy_identity=policy.policy_id,
                    build_timestamp=NOW,
                    build_host_identity="forge:test",
                    normalized_manifest_sha256="4" * 64,
                    source_file_count=1,
                    package_count=1,
                    labels=labels,
                )
            )
    manifest = P4ImageManifest(
        source_commit=SOURCE,
        base_image_reference=f"python:3.12-alpine@{BASE}",
        base_digest=BASE,
        created_at_utc=NOW,
        build_host_identity="forge:test",
        attestation_public_key=_ref(root, public_path),
        attestation_key_id=authority.key_id,
        records=tuple(records),
    )
    manifest_path = root / "manifest.json"
    write_manifest(manifest_path, manifest)
    return manifest_path


def test_verify_p4_image_manifest_accepts_complete_twelve_image_set(tmp_path: Path) -> None:
    manifest_path = _build_manifest(tmp_path)
    result = verify_p4_image_manifest(
        manifest_path,
        expected_source_commit=SOURCE,
        expected_base_digest=BASE,
        now=NOW + timedelta(minutes=1),
    )
    assert result["passed"] is True
    assert result["record_count"] == 12
    assert result["failures"] == []


def test_verify_p4_image_manifest_fails_closed_on_artifact_tamper(tmp_path: Path) -> None:
    manifest_path = _build_manifest(tmp_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    sbom_path = manifest_path.parent / document["records"][0]["sbom"]["path"]
    sbom_path.write_text("{}\n", encoding="utf-8")
    result = verify_p4_image_manifest(
        manifest_path,
        expected_source_commit=SOURCE,
        expected_base_digest=BASE,
        now=NOW + timedelta(minutes=1),
    )
    assert result["passed"] is False
    assert any("sbom:sha256_mismatch" in failure for failure in result["failures"])


def test_manifest_rejects_duplicate_immutable_image_identity(tmp_path: Path) -> None:
    manifest_path = _build_manifest(tmp_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["records"][1]["image_id"] = document["records"][0]["image_id"]
    try:
        P4ImageManifest.model_validate(document)
    except ValueError as exc:
        assert "unexpected duplicate image_id" in str(exc)
    else:
        raise AssertionError("duplicate image identity was accepted")
