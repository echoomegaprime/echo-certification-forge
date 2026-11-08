"""Exercise the real signature boundary and the owner's atomic filesystem intake."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from echo_certification_forge.canonical import canonical_json, sha256_bytes, to_utc_iso
from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.production_e2e import BASE_CHECKS, DirectoryProductionE2EProvider
from echo_certification_forge.production_e2e_intake import (
    IntakeError, IntakeOutcomeUnknown, ProductionE2EIntake, verify_intake_document,
)
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry


@pytest.fixture
def candidate(tmp_path):
    now = datetime.now(UTC)
    target = TargetIdentity("tenant-a", "repository", "https://github.com/example/product@" + "a" * 40,
                            "b" * 64, source_commit="a" * 40)
    environment = EnvironmentIdentity(**{name: "c" * 64 for name in EnvironmentIdentity.__dataclass_fields__})
    signer = Ed25519VerdictSigner.generate()  # Private, ephemeral TEST key; never operational trust.
    registry = TrustedPublicKeyRegistry.empty()
    registry.add_pem(signer.public_key_pem)
    payload = {
        "schema_version": "certforge.production-e2e.v1", "profile": "generic-production-v1",
        "attestation_id": "test-collector-fresh-observation", "signing_key_id": signer.key_id,
        "target_identity_digest": target.identity_digest, "environment_identity_digest": environment.identity_digest,
        "source_commit": target.source_commit, "deployment_sha": target.source_commit,
        "observed_at": to_utc_iso(now - timedelta(seconds=1)), "expires_at": to_utc_iso(now + timedelta(minutes=10)),
        "required_checks": sorted(BASE_CHECKS), "checks": {name: True for name in BASE_CHECKS},
        "stability_probe_count": 3, "execution_scope": "private_exact_artifact_acceptance",
        "public_deployment_verified": False,
    }

    def encode(changes=None, use_signer=signer):
        body = {**payload, **(changes or {}), "signing_key_id": use_signer.key_id}
        signed = use_signer.sign_payload(body)
        return canonical_json({"payload": signed.payload, "signature_b64": signed.signature_b64,
                               "key_id": signed.key_id, "public_key_pem": signed.public_key_pem}).encode()

    return now, target, environment, registry, signer, payload, encode


def test_signature_is_verified_against_independent_trust_and_exact_pair(candidate):
    now, target, environment, registry, _, _, encode = candidate
    raw = encode()
    verified = verify_intake_document(raw, registry, target, environment, now=now,
                                     expected_content_sha256=sha256_bytes(raw))
    assert verified.payload["execution_scope"] == "private_exact_artifact_acceptance"
    assert verified.payload["public_deployment_verified"] is False
    assert verified.collector_key_id in registry.keys


@pytest.mark.parametrize("changes,reason", [
    ({"target_identity_digest": "d" * 64}, "target_identity_mismatch"),
    ({"environment_identity_digest": "d" * 64}, "environment_identity_mismatch"),
    ({"deployment_sha": "d" * 40}, "deployment_sha_mismatch"),
    ({"source_commit": "d" * 40}, "deployment_sha_mismatch"),
    ({"checks": {name: name != "external_acceptance_verified" for name in BASE_CHECKS}}, "checks_incomplete"),
    ({"stability_probe_count": 2}, "probe_count"),
    ({"profile": "echo-github-autonomy-remote-mcp-v2"}, "profile_mismatch"),
    ({"token": "should-not-be-persisted"}, "restricted_value"),
])
def test_signed_but_ineligible_documents_never_reach_intake(candidate, changes, reason):
    now, target, environment, registry, _, _, encode = candidate
    raw = encode(changes)
    with pytest.raises(IntakeError, match=reason):
        verify_intake_document(raw, registry, target, environment, now=now,
                               expected_content_sha256=sha256_bytes(raw))


def test_self_supplied_public_key_does_not_establish_trust(candidate):
    now, target, environment, registry, _, _, encode = candidate
    raw = encode(use_signer=Ed25519VerdictSigner.generate())
    with pytest.raises(IntakeError, match="untrusted_signing_key"):
        verify_intake_document(raw, registry, target, environment, now=now,
                               expected_content_sha256=sha256_bytes(raw))


def test_stale_tampered_or_unreviewed_bytes_are_rejected(candidate):
    now, target, environment, registry, _, _, encode = candidate
    raw = encode()
    with pytest.raises(IntakeError, match="not_current"):
        verify_intake_document(raw, registry, target, environment, now=now + timedelta(hours=2),
                               expected_content_sha256=sha256_bytes(raw))
    with pytest.raises(IntakeError, match="content_digest_mismatch"):
        verify_intake_document(raw, registry, target, environment, now=now, expected_content_sha256="0" * 64)
    document = json.loads(raw)
    document["payload"]["stability_probe_count"] = 4
    changed = canonical_json(document).encode()
    with pytest.raises(IntakeError, match="invalid_signature"):
        verify_intake_document(changed, registry, target, environment, now=now,
                               expected_content_sha256=sha256_bytes(changed))


@pytest.mark.parametrize("raw", [b'{}', b'{"payload":{},"payload":{}}', b'{"payload":NaN}', b'[]', b'x' * (1024 * 1024 + 1)],
                         ids=["empty", "duplicate", "nonfinite", "array", "oversized"])
def test_unparseable_envelope_is_refused_before_any_write(candidate, raw):
    now, target, environment, registry, *_ = candidate
    with pytest.raises(IntakeError):
        verify_intake_document(raw, registry, target, environment, now=now,
                               expected_content_sha256=sha256_bytes(raw))


@pytest.fixture
def owner(tmp_path, candidate):
    if os.name != "posix":
        pytest.skip("The deployed directory intake uses POSIX owner/atomic-rename semantics")
    now, target, environment, _, signer, _, encode = candidate
    root, trust = tmp_path / "intake", tmp_path / "public-trust"
    root.mkdir(mode=0o700)
    trust.mkdir(mode=0o700)
    (trust / "collector.pem").write_text(signer.public_key_pem)
    lane = ProductionE2EIntake(root, trust, owner_uid=os.getuid(), clock=lambda: now)
    source = tmp_path / "reviewed-envelope.json"
    source.write_bytes(encode())
    return lane, source, root, trust, target, environment, encode


def install(owner, **kwargs):
    lane, source, _, _, target, environment, _ = owner
    return lane.install(source, target, environment,
                        expected_content_sha256=sha256_bytes(source.read_bytes()), **kwargs)


def test_atomic_install_is_consumed_by_actual_directory_provider(owner):
    lane, source, root, trust, target, environment, _ = owner
    receipt = install(owner)
    path = root / (target.identity_digest + "." + environment.identity_digest + ".json")
    assert path.read_bytes() == source.read_bytes()
    assert receipt["state"] == "installed" and receipt["signature_verified"] is True
    assert receipt["release_verdict"] == "NOT_ISSUED"
    assert receipt["content_sha256"] == sha256_bytes(path.read_bytes())
    verified = DirectoryProductionE2EProvider(root, trust)(target, environment)
    assert verified is not None and verified.envelope_sha256 == receipt["envelope_sha256"]
    assert not any(path.name.endswith(".tmp") for path in root.iterdir())
    assert install(owner)["state"] == "already_present"


def test_replacement_requires_exact_old_bytes_and_preserves_old_on_conflict(owner):
    _, source, root, _, target, environment, encode = owner
    first = install(owner)
    path = root / (target.identity_digest + "." + environment.identity_digest + ".json")
    before = path.read_bytes()
    source.write_bytes(encode({"attestation_id": "test-fresh-replacement"}))
    with pytest.raises(IntakeError, match="replacement_conflict"):
        install(owner)
    with pytest.raises(IntakeError, match="replacement_conflict"):
        install(owner, replace_content_sha256="0" * 64)
    assert path.read_bytes() == before
    result = install(owner, replace_content_sha256=first["content_sha256"])
    assert result["state"] == "replaced" and path.read_bytes() == source.read_bytes()


def test_dry_run_has_no_intake_or_lock_mutation(owner):
    lane, source, root, _, target, environment, _ = owner
    result = lane.preview(source, target, environment, expected_content_sha256=sha256_bytes(source.read_bytes()))
    assert result["state"] == "verified_not_installed" and list(root.iterdir()) == []


def test_untrusted_signature_cannot_replace_an_existing_attestation(owner):
    _, source, root, trust, target, environment, encode = owner
    first = install(owner)
    path = root / (target.identity_digest + "." + environment.identity_digest + ".json")
    before = path.read_bytes()
    source.write_bytes(encode(use_signer=Ed25519VerdictSigner.generate()))
    with pytest.raises(IntakeError, match="untrusted_signing_key"):
        install(owner, replace_content_sha256=first["content_sha256"])
    assert path.read_bytes() == before
    assert len(list(trust.iterdir())) == 1


def test_symlinked_evidence_or_intake_is_not_followed(owner, tmp_path):
    lane, source, root, trust, target, environment, _ = owner
    link = tmp_path / "source-link"
    link.symlink_to(source)
    with pytest.raises(IntakeError, match="symlink"):
        lane.install(link, target, environment, expected_content_sha256=sha256_bytes(source.read_bytes()))
    alias = tmp_path / "root-link"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(IntakeError, match="symlink"):
        ProductionE2EIntake(alias, trust, owner_uid=os.getuid())
    output = root / (target.identity_digest + "." + environment.identity_digest + ".json")
    output.symlink_to(source)
    with pytest.raises(IntakeError, match="symlink"):
        install(owner)


def test_world_writable_trust_or_wrong_owner_is_refused(owner):
    _, _, root, trust, *_ = owner
    trust.chmod(0o777)
    with pytest.raises(IntakeError, match="unprotected_directory"):
        ProductionE2EIntake(root, trust, owner_uid=os.getuid())
    trust.chmod(0o700)
    with pytest.raises(IntakeError, match="owner_mismatch"):
        ProductionE2EIntake(root, trust, owner_uid=os.getuid() + 1)


def test_expiry_is_rechecked_on_install_not_only_preview(owner, candidate):
    lane, source, root, trust, target, environment, _ = owner
    now = candidate[0]
    lane.preview(source, target, environment, expected_content_sha256=sha256_bytes(source.read_bytes()))
    later = ProductionE2EIntake(root, trust, owner_uid=os.getuid(), clock=lambda: now + timedelta(hours=2))
    with pytest.raises(IntakeError, match="not_current"):
        later.install(source, target, environment, expected_content_sha256=sha256_bytes(source.read_bytes()))
    assert not list(root.glob("*.json"))


def test_concurrent_owner_operation_refuses_without_waiting_or_overwriting(owner):
    lane, _, root, *_ = owner
    with lane._locked_directory():
        with pytest.raises(IntakeError, match="intake_busy"):
            install(owner)
    assert not list(root.glob("*.json"))
    assert install(owner)["state"] == "installed"


def test_nonregular_source_is_rejected_without_blocking(owner, tmp_path):
    lane, _, _, _, target, environment, _ = owner
    pipe = tmp_path / "not-an-envelope"
    os.mkfifo(pipe)
    with pytest.raises(IntakeError, match="file_bound"):
        lane.preview(pipe, target, environment, expected_content_sha256="0" * 64)


def test_post_publish_io_failure_reports_unknown_and_is_reconciled_by_idempotent_readback(owner, monkeypatch):
    real_fsync = os.fsync

    def fail_directory_fsync(fd):
        import stat
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("fixture: directory durability readback unavailable")
        real_fsync(fd)

    with monkeypatch.context() as faults:
        faults.setattr(os, "fsync", fail_directory_fsync)
        with pytest.raises(IntakeOutcomeUnknown, match="installation_outcome_unknown"):
            install(owner)
        # Reading identical bytes alone must not turn failed durability into success.
        with pytest.raises(IntakeOutcomeUnknown, match="installation_outcome_unknown"):
            install(owner)
    assert install(owner)["state"] == "already_present"


def test_cleanup_error_after_publication_preserves_unknown_outcome(owner, monkeypatch):
    def fail_cleanup(*_args, **_kwargs):
        raise OSError("fixture: cleanup state is unavailable")

    with monkeypatch.context() as faults:
        faults.setattr(os, "unlink", fail_cleanup)
        with pytest.raises(IntakeOutcomeUnknown, match="installation_outcome_unknown"):
            install(owner)
    assert install(owner)["state"] == "already_present"
