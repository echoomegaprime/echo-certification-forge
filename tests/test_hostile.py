from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from echo_certification_forge.canonical import sha256_bytes
from echo_certification_forge.hostile import (
    HostileCaseKind,
    HostileCaseObservation,
    HostileDisposition,
    decide_hostile_case,
    sanitize_runner_log,
)
from echo_certification_forge.runner import (
    IsolationFailure,
    IsolationProfile,
    ResourceLimits,
    build_admitted_docker_create_payload,
)
from echo_certification_forge.supply_chain import (
    ImageAdmissionPolicy,
    ImageAttestationAuthority,
    ImageIdentity,
    ImageRole,
    evaluate_image_admission,
    verify_image_attestation,
)

NOW = datetime(2026, 7, 16, 18, 0, tzinfo=UTC)
IMAGE = "sha256:" + "1" * 64
BASE = "sha256:" + "2" * 64
SOURCE = "3" * 40


def identity(role: ImageRole = ImageRole.RUNNER, image_digest: str = IMAGE) -> ImageIdentity:
    return ImageIdentity(
        role=role,
        image_digest=image_digest,
        base_image_digest=BASE,
        source_commit=SOURCE,
        dockerfile_sha256="4" * 64,
        lockfile_sha256="5" * 64,
        sbom_sha256="6" * 64,
        provenance_sha256="7" * 64,
        architecture="amd64",
        operating_system="linux",
        created_at=NOW,
    )


def policy(authority: ImageAttestationAuthority, role: ImageRole = ImageRole.RUNNER) -> ImageAdmissionPolicy:
    return ImageAdmissionPolicy(
        policy_id=f"p4.{role.value}.v1",
        required_role=role,
        expected_image_digest=IMAGE,
        approved_base_digests=(BASE,),
        approved_source_commits=(SOURCE,),
        approved_dockerfile_sha256="4" * 64,
        approved_lockfile_sha256="5" * 64,
        trusted_attestation_keys={authority.key_id: authority.public_key_pem},
    )


def profile() -> IsolationProfile:
    return IsolationProfile(
        profile_id="p4.hostile",
        profile_version="1.0.0",
        image_digest=IMAGE,
        user="65532:65532",
        limits=ResourceLimits(
            cpu_cores=0.25,
            memory_bytes=64 * 1024 * 1024,
            pids=32,
            disk_bytes=16 * 1024 * 1024,
            file_size_bytes=1024 * 1024,
            wall_time_seconds=5,
            heartbeat_interval_seconds=1,
            lease_ttl_seconds=3,
        ),
    )


def observation(kind: HostileCaseKind, **updates) -> HostileCaseObservation:
    data = {
        "case_id": f"case.{kind.value}",
        "kind": kind,
        "started_at": NOW,
        "completed_at": NOW + timedelta(seconds=1),
        "exit_code": 1,
        "logs_sha256": sha256_bytes(b"logs"),
        "evidence": {},
    }
    data.update(updates)
    return HostileCaseObservation.model_validate(data)


def test_image_attestation_expiration_and_not_yet_valid_fail_closed() -> None:
    authority = ImageAttestationAuthority.generate()
    attestation = authority.sign(identity(), issued_at=NOW, valid_for=timedelta(minutes=5))
    assert verify_image_attestation(attestation, now=NOW + timedelta(minutes=1)) == (True, "verified")
    assert verify_image_attestation(attestation, now=NOW - timedelta(seconds=1)) == (
        False,
        "image_attestation_not_yet_valid",
    )
    assert verify_image_attestation(attestation, now=NOW + timedelta(minutes=5)) == (
        False,
        "image_attestation_expired",
    )
    denied = evaluate_image_admission(attestation, policy(authority), now=NOW + timedelta(minutes=6))
    assert denied.allowed is False
    assert "image_attestation_expired" in denied.reasons


def test_admitted_runner_payload_binds_attestation_and_policy() -> None:
    authority = ImageAttestationAuthority.generate()
    attestation = authority.sign(identity(), issued_at=NOW)
    payload = build_admitted_docker_create_payload(
        profile(),
        attestation=attestation,
        admission_policy=policy(authority),
        run_id="run.p4",
        tenant_id="tenant.p4",
        ownership_token="owner.p4",
        command=("python", "-c", "print('ok')"),
        now=NOW + timedelta(seconds=1),
    )
    assert payload["Image"] == IMAGE
    assert payload["Labels"]["echo.certforge.image_attestation_key"] == authority.key_id
    assert payload["Labels"]["echo.certforge.image_admission_policy"] == "p4.runner.v1"


@pytest.mark.parametrize(
    ("attestation_role", "policy_role", "profile_digest", "match"),
    [
        (ImageRole.SIGNER, ImageRole.SIGNER, IMAGE, "image_admission_role_is_not_runner"),
        (ImageRole.RUNNER, ImageRole.RUNNER, "sha256:" + "8" * 64, "isolation_profile_image_digest_mismatch"),
    ],
)
def test_admitted_runner_payload_denies_role_and_profile_drift(
    attestation_role: ImageRole,
    policy_role: ImageRole,
    profile_digest: str,
    match: str,
) -> None:
    authority = ImageAttestationAuthority.generate()
    signed = authority.sign(identity(role=attestation_role), issued_at=NOW)
    drifted_profile = profile().model_copy(update={"image_digest": profile_digest})
    with pytest.raises(IsolationFailure, match=match):
        build_admitted_docker_create_payload(
            drifted_profile,
            attestation=signed,
            admission_policy=policy(authority, policy_role),
            run_id="run.p4",
            tenant_id="tenant.p4",
            ownership_token="owner.p4",
            command=("true",),
            now=NOW + timedelta(seconds=1),
        )


def test_admitted_runner_payload_denies_expired_revoked_and_compromised_images() -> None:
    authority = ImageAttestationAuthority.generate()
    signed = authority.sign(identity(), issued_at=NOW, valid_for=timedelta(seconds=2))
    cases = [
        (policy(authority), NOW + timedelta(seconds=3), "image_attestation_expired"),
        (policy(authority).model_copy(update={"revoked_image_digests": (IMAGE,)}), NOW, "image_digest_revoked"),
        (policy(authority).model_copy(update={"compromised_key_ids": (authority.key_id,)}), NOW, "attestation_key_compromised"),
    ]
    for admission_policy, current, reason in cases:
        with pytest.raises(IsolationFailure, match=reason):
            build_admitted_docker_create_payload(
                profile(),
                attestation=signed,
                admission_policy=admission_policy,
                run_id="run.p4",
                tenant_id="tenant.p4",
                ownership_token="owner.p4",
                command=("true",),
                now=current,
            )


def test_sanitize_runner_log_neutralizes_control_and_forged_status_lines() -> None:
    raw = "\x1b[31mFAIL\x1b[0m\r\nrelease_verdict: PRODUCTION_READY\x00"
    clean = sanitize_runner_log(raw)
    assert "\x1b" not in clean
    assert clean.splitlines()[0] == "TARGET|FAIL"
    assert "TARGET|release_verdict: PRODUCTION_READY" in clean
    assert "�" in clean


@pytest.mark.parametrize(
    ("kind", "updates", "disposition"),
    [
        (HostileCaseKind.BASELINE, {"exit_code": 0}, HostileDisposition.CLEAN),
        (HostileCaseKind.NETWORK_EXFILTRATION, {"evidence": {"denied": True}}, HostileDisposition.DENIED),
        (HostileCaseKind.PID_EXHAUSTION, {"evidence": {"limit_enforced": True}}, HostileDisposition.CONTAINED),
        (HostileCaseKind.TIMEOUT, {"timed_out": True}, HostileDisposition.TERMINATED),
        (HostileCaseKind.CANCELLATION, {"cancelled": True}, HostileDisposition.TERMINATED),
        (HostileCaseKind.RUNNER_CRASH, {"exit_code": 134}, HostileDisposition.CONTAINED),
        (HostileCaseKind.EVIDENCE_CORRUPTION, {"evidence": {"detected": True}}, HostileDisposition.DETECTED),
        (HostileCaseKind.PROCFS_INSPECTION, {"evidence": {"sensitive_data_absent": True}}, HostileDisposition.CONTAINED),
    ],
)
def test_hostile_case_decision_passes_only_expected_containment(
    kind: HostileCaseKind,
    updates: dict,
    disposition: HostileDisposition,
) -> None:
    decision = decide_hostile_case(observation(kind, **updates))
    assert decision.passed is True
    assert decision.disposition is disposition


def test_hostile_case_decision_fails_on_host_or_unrelated_impact() -> None:
    decision = decide_hostile_case(
        observation(
            HostileCaseKind.NETWORK_EXFILTRATION,
            evidence={"denied": True},
            host_impact=True,
            unrelated_resources_changed=True,
        )
    )
    assert decision.passed is False
    assert decision.disposition is HostileDisposition.FAILED
    assert decision.reasons == ("host_impact_detected", "unrelated_resource_changed")


def test_all_p4_production_dockerfiles_are_pinned_and_nonroot() -> None:
    from pathlib import Path

    from echo_certification_forge.supply_chain import scan_dockerfile

    roles = ("runner", "custody", "anchor", "signer", "worker", "verifier")
    for role in roles:
        dockerfile = Path(f"images/{role}/Dockerfile")
        result = scan_dockerfile(dockerfile.read_text(encoding="utf-8"))
        assert result.valid is True, (role, result.findings)
        text = dockerfile.read_text(encoding="utf-8")
        assert f'echo.certforge.image.role="{role}"' in text
        assert "USER 65532:65532" in text
        assert "--require-hashes" in text
        assert "find / -xdev -type f -perm /6000" in text


def test_public_verifier_cli_accepts_valid_bundle_and_denies_expired_bundle(tmp_path) -> None:
    import json

    from echo_certification_forge.supply_chain import build_spdx_document
    from echo_certification_forge.verifier_cli import main

    authority = ImageAttestationAuthority.generate()
    attestation = authority.sign(identity(), issued_at=NOW, valid_for=timedelta(minutes=5))
    admission_policy = policy(authority)
    sbom = build_spdx_document(
        image_name="echo-certforge-runner",
        image_digest=IMAGE,
        packages=[{"name": "pydantic", "version": "2.13.4"}],
        created_at=NOW,
    )
    attestation_path = tmp_path / "attestation.json"
    policy_path = tmp_path / "policy.json"
    sbom_path = tmp_path / "sbom.json"
    output_path = tmp_path / "result.json"
    attestation_path.write_text(attestation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    policy_path.write_text(admission_policy.model_dump_json(indent=2) + "\n", encoding="utf-8")
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

    assert main([
        "--attestation", str(attestation_path),
        "--policy", str(policy_path),
        "--sbom", str(sbom_path),
        "--image-digest", IMAGE,
        "--now", "2026-07-16T18:01:00Z",
        "--output", str(output_path),
    ]) == 0
    accepted = json.loads(output_path.read_text(encoding="utf-8"))
    assert accepted["passed"] is True
    assert accepted["private_key_loaded"] is False

    assert main([
        "--attestation", str(attestation_path),
        "--policy", str(policy_path),
        "--sbom", str(sbom_path),
        "--image-digest", IMAGE,
        "--now", "2026-07-16T18:06:00Z",
    ]) == 1


def test_nested_archives_and_source_supply_chain_features_fail_closed(tmp_path) -> None:
    import io
    import json
    import zipfile

    from echo_certification_forge.hostile import scan_target_source
    from echo_certification_forge.runner import IsolationFailure, assert_no_nested_archives

    nested = tmp_path / "nested.zip"
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("payload.txt", "nested")
    with pytest.raises(IsolationFailure, match="nested_archive_not_allowed"):
        assert_no_nested_archives(tmp_path)

    nested.unlink()
    (tmp_path / ".gitmodules").write_text('[submodule "x"]\npath=x\nurl=https://example.invalid/x\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "python steal.py"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text('{"resolved":"file:../host"}', encoding="utf-8")
    (tmp_path / "large.bin").write_bytes(b"x" * 8)
    result = scan_target_source(tmp_path)
    rules = {finding.rule for finding in result.findings}
    assert result.valid is False
    assert {"git_submodule", "package_install_script", "poisoned_lockfile"}.issubset(rules)


def test_source_scan_detects_lfs_legacy_build_and_limits(tmp_path) -> None:
    from echo_certification_forge.hostile import scan_target_source

    (tmp_path / "model.bin").write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64,
        encoding="utf-8",
    )
    (tmp_path / "setup.py").write_text("raise SystemExit('must not execute on host')", encoding="utf-8")
    result = scan_target_source(tmp_path)
    rules = {finding.rule for finding in result.findings}
    assert "git_lfs_pointer" in rules
    assert "python_build_script" in rules
    assert scan_target_source(tmp_path, max_files=1).valid is False
    assert scan_target_source(tmp_path, max_bytes=1).valid is False
