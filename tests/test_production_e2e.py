from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.production_e2e import (
    ECHO_CLIENTS,
    ECHO_GITHUB_ACCOUNTS,
    ECHO_GITHUB_AUTONOMY_CANONICAL_MCP,
    ECHO_GITHUB_AUTONOMY_CHECKS,
    ECHO_GITHUB_AUTONOMY_PROFILE,
    SCHEMA_VERSION,
    load_signed_attestation,
    validate_production_e2e,
)
from echo_certification_forge.signing import Ed25519VerdictSigner

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
SOURCE_SHA = "5" * 40


def _target() -> TargetIdentity:
    return TargetIdentity(
        tenant_id="echo-github-apps",
        target_type="git",
        canonical_ref=(
            "https://github.com/echoomegaprime/echo-github-autonomy.git@" + SOURCE_SHA
        ),
        artifact_sha256="a" * 64,
        source_commit=SOURCE_SHA,
        dependency_sha256="b" * 64,
        configuration_sha256="c" * 64,
    )


def _environment() -> EnvironmentIdentity:
    return EnvironmentIdentity(
        **{
            name: str(index) * 64
            for index, name in enumerate(EnvironmentIdentity.__dataclass_fields__, start=1)
        }
    )


def _payload(*, signing_key_id: str = "ed25519:" + "d" * 32) -> dict:
    target = _target()
    environment = _environment()
    samples = {
        login: {
            "repository_id": index,
            "node_id": f"R_repo_{index}",
            "default_branch": "main",
            "head_sha": str(index) * 40,
            "fingerprint_sha256": str(index) * 64,
        }
        for index, login in enumerate(ECHO_GITHUB_ACCOUNTS, start=1)
    }
    accounts = {
        login: {
            "account_id": account_id,
            "enumerated_count": 10 + index,
            "upstream_total_count": 10 + index,
            "public_count": 5,
            "private_count": 5 + index,
            "read": True,
            "write": True,
            "certify": True,
            "credential_source": (
                "github_app_installation"
                if index == 1
                else "vault_user_token_fallback"
            ),
            "secret_exposed": False,
        }
        for index, (login, account_id) in enumerate(ECHO_GITHUB_ACCOUNTS.items(), start=1)
    }
    fingerprints = {
        login: sample["fingerprint_sha256"] for login, sample in samples.items()
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "attestation_id": "echo-github-autonomy-live-001",
        "profile": ECHO_GITHUB_AUTONOMY_PROFILE,
        "target_identity_digest": target.identity_digest,
        "environment_identity_digest": environment.identity_digest,
        "source_commit": SOURCE_SHA,
        "deployment_sha": SOURCE_SHA,
        "canonical_target": ECHO_GITHUB_AUTONOMY_CANONICAL_MCP,
        "required_checks": sorted(ECHO_GITHUB_AUTONOMY_CHECKS),
        "checks": {name: True for name in sorted(ECHO_GITHUB_AUTONOMY_CHECKS)},
        "stability_probe_count": 3,
        "tool_count": 30,
        "accounts": accounts,
        "sample_private_repositories": samples,
        "clients": {
            name: {"accepted": True, "repository_fingerprints": fingerprints}
            for name in sorted(ECHO_CLIENTS)
        },
        "observed_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat(),
        "signing_key_id": signing_key_id,
    }


def test_echo_github_autonomy_requires_complete_exact_cross_client_e2e() -> None:
    valid, reason = validate_production_e2e(
        _payload(), _target(), _environment(), now=NOW + timedelta(minutes=1)
    )
    assert valid, reason


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda value: value.__setitem__("deployment_sha", "6" * 40), "production_e2e_deployment_sha_mismatch"),
        (lambda value: value.__setitem__("tool_count", 27), "production_e2e_tool_count_mismatch"),
        (
            lambda value: value["accounts"]["Bmcbob76"].__setitem__("private_count", 0),
            "production_e2e_account_reconciliation_failed",
        ),
        (
            lambda value: value["clients"]["grok"].__setitem__("accepted", False),
            "production_e2e_client_not_accepted",
        ),
        (
            lambda value: value["accounts"]["Bmcbob76"].__setitem__(
                "credential_source", "model_config_pat"
            ),
            "production_e2e_credential_source_invalid",
        ),
        (
            lambda value: value["accounts"]["Bmcbob76"].__setitem__(
                "secret_exposed", True
            ),
            "production_e2e_secret_boundary_failed",
        ),
        (
            lambda value: value["sample_private_repositories"]["Bmcbob76"].__setitem__(
                "repository_id", True
            ),
            "production_e2e_sample_repository_id_invalid",
        ),
    ],
)
def test_incomplete_or_mismatched_e2e_fails_closed(mutation, reason: str) -> None:
    payload = _payload()
    mutation(payload)
    valid, actual = validate_production_e2e(
        payload, _target(), _environment(), now=NOW + timedelta(minutes=1)
    )
    assert not valid
    assert actual == reason


def test_stale_e2e_attestation_fails_closed() -> None:
    valid, reason = validate_production_e2e(
        _payload(), _target(), _environment(), now=NOW + timedelta(hours=2)
    )
    assert not valid
    assert reason == "production_e2e_attestation_not_current"


def test_attestation_loader_requires_a_pinned_collector_key(tmp_path) -> None:
    signer = Ed25519VerdictSigner.generate()
    payload = _payload(signing_key_id=signer.key_id)
    envelope = signer.sign_payload(payload)
    envelope_path = tmp_path / "attestation.json"
    envelope_path.write_text(
        json.dumps(
            {
                "payload": envelope.payload,
                "signature_b64": envelope.signature_b64,
                "key_id": envelope.key_id,
                "public_key_pem": envelope.public_key_pem,
            }
        ),
        encoding="utf-8",
    )
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    with pytest.raises(ValueError, match="untrusted_signing_key"):
        load_signed_attestation(envelope_path, trusted)
    (trusted / "collector.pem").write_text(signer.public_key_pem, encoding="ascii")
    verified = load_signed_attestation(envelope_path, trusted)
    assert verified.payload == payload
    assert verified.collector_key_id == signer.key_id
    assert len(verified.envelope_sha256) == 64


def test_self_selected_public_key_cannot_replace_the_pinned_collector(tmp_path) -> None:
    trusted_signer = Ed25519VerdictSigner.generate()
    attacker = Ed25519VerdictSigner.generate()
    payload = _payload(signing_key_id=attacker.key_id)
    envelope = attacker.sign_payload(payload)
    envelope_path = tmp_path / "attestation.json"
    envelope_path.write_text(
        json.dumps(
            {
                "payload": envelope.payload,
                "signature_b64": envelope.signature_b64,
                "key_id": envelope.key_id,
                "public_key_pem": envelope.public_key_pem,
            }
        ),
        encoding="utf-8",
    )
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "collector.pem").write_text(trusted_signer.public_key_pem, encoding="ascii")
    with pytest.raises(ValueError, match="untrusted_signing_key"):
        load_signed_attestation(envelope_path, trusted)
