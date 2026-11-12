from __future__ import annotations

from echo_certification_forge.public_verification import (
    public_production_e2e_identity,
    public_target_identity,
)


def test_public_target_projection_never_returns_local_path_or_raw_remote() -> None:
    local = public_target_identity(
        {
            "target_type": "local",
            "canonical_ref": "C:/private/operator/worktree",
            "artifact_sha256": "a" * 64,
            "source_commit": None,
        }
    )
    credential_remote = public_target_identity(
        {
            "target_type": "git",
            "canonical_ref": "https://token@github.com/example/project.git",
            "artifact_sha256": "b" * 64,
            "source_commit": "c" * 40,
        }
    )
    safe_remote = public_target_identity(
        {
            "target_type": "git",
            "canonical_ref": "https://github.com/example/project.git@" + "c" * 40,
            "artifact_sha256": "b" * 64,
            "source_commit": "c" * 40,
        }
    )

    assert "canonical_ref" not in local
    assert "repository" not in local
    assert "canonical_ref" not in credential_remote
    assert "repository" not in credential_remote
    assert safe_remote["repository"] == "example/project"


def test_public_e2e_projection_drops_credential_like_canonical_target() -> None:
    details = {
        "schema_version": "certforge.production-e2e.v1",
        "profile": "generic-production-v1",
        "canonical_target": "https://api.github.com/mcp?access_token=secret",
        "checks": {"runtime_or_artifact_executed": True},
        "private_debug_path": "C:/private/evidence",
    }

    projection = public_production_e2e_identity(details)

    assert "canonical_target" not in projection
    assert "private_debug_path" not in projection


def test_public_e2e_projection_drops_malformed_or_nonpublic_targets() -> None:
    for canonical_target in (
        "https://[::1",
        "https://api.github.com:bad/runtime",
        "https://api.github.com:99999/runtime",
        "https://api.github.com:0/runtime",
        "https://api.github.com:00/runtime",
        "https://[2606:4700:4700::1111]:0/runtime",
        "https://a b.github.com/runtime",
        "https://localhost/runtime",
        "https://service.local/runtime",
        "https://service.home.arpa/runtime",
        "https://service.invalid/runtime",
        "https://service.test/runtime",
        "https://service.example/runtime",
        "https://service.example.com/runtime",
        "https://service.example.net/runtime",
        "https://service.example.org/runtime",
        "https://service.onion/runtime",
        "https://service.alt/runtime",
        "https://resolver.arpa/runtime",
        "https://service.arpa/runtime",
        "https://api。localhost/runtime",
        "https://service．onion/runtime",
        "https://service｡alt/runtime",
        "https://service。example。com/runtime",
        "https://resolver。arpa/runtime",
        "https://service.ｅｘａｍｐｌｅ.com/runtime",
        "https://service.ｏｎｉｏｎ/runtime",
        "https://service.ａｌｔ/runtime",
        "https://service.ａｒｐａ/runtime",
        "https://127.0.0.1/runtime",
        "https://10.0.0.1/runtime",
        "https://169.254.1.1/runtime",
        "https://100.64.0.1/runtime",
        "https://100.127.255.254/runtime",
        "https://0x7f.0.0.1/runtime",
        "https://0x7f.1/runtime",
        "https://127.0.0x0.1/runtime",
        "https://0x7f.0x0.0x0.0x1/runtime",
        "https://0177.0.0.1/runtime",
        "https://0x.0.0.1/runtime",
        "https://0x0.0x.0.1/runtime",
        "https://0x7f.0x.0.1/runtime",
        "https://xn--a.com/runtime",
        "https://xn--0.com/runtime",
        "https://xn--abc.com/runtime",
        "https://xn--123.com/runtime",
        "https://xn--a-ecp.com/runtime",
        "https://foo.0x7f/runtime",
        "https://foo.127/runtime",
        "https://foo.0x/runtime",
        "https://[2606:4700:4700::1111%25eth0]/runtime",
        "https://[2606:4700:4700::1111%eth0]/runtime",
        "https://[fec0::1]/runtime",
        "https://[fedf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/runtime",
        "https://[64:ff9b::7f00:1]/runtime",
        "https://[64:ff9b::a00:1]/runtime",
        "https://[64:ff9b:1::808:808]/runtime",
    ):
        projection = public_production_e2e_identity(
            {
                "profile": "generic-production-v1",
                "canonical_target": canonical_target,
            }
        )
        assert "canonical_target" not in projection


def test_public_e2e_projection_normalizes_safe_public_target() -> None:
    projection = public_production_e2e_identity(
        {
            "profile": "generic-production-v1",
            "canonical_target": "https://API.GITHUB.COM.:8443/runtime",
        }
    )

    assert projection["canonical_target"] == "https://api.github.com:8443/runtime"


def test_public_e2e_projection_preserves_public_nat64_literal() -> None:
    target = "https://[64:ff9b::808:808]/runtime"
    projection = public_production_e2e_identity(
        {"profile": "generic-production-v1", "canonical_target": target}
    )

    assert projection["canonical_target"] == target


def test_public_e2e_projection_exposes_only_signed_aggregates() -> None:
    details = {
        "schema_version": "certforge.production-e2e.v1",
        "profile": "echo-github-autonomy-remote-mcp-v2",
        "checks": {
            "registry_persistence": True,
            "oauth_discovery": True,
        },
        "tool_count": 30,
        "accounts": {
            "private-login": {
                "enumerated_count": 2,
                "upstream_total_count": 2,
                "public_count": 1,
                "private_count": 1,
                "read": True,
                "write": True,
                "certify": True,
                "credential_source": "vault_user_token_fallback",
                "notes": "customer-private-repository",
            }
        },
        "sample_private_repositories": {
            "private-login": {
                "repository_id": 123,
                "node_id": "R_private",
                "default_branch": "main",
                "head_sha": "a" * 40,
            }
        },
        "clients": {
            "chatgpt": {
                "accepted": True,
                "repository_fingerprints": {"private-login": "b" * 64},
                "notes": "internal-client-detail",
            }
        },
    }

    projection = public_production_e2e_identity(details)
    serialized = str(projection)

    assert projection["account_count"] == 1
    assert projection["client_count"] == 1
    assert projection["upstream_reconciled"] is True
    assert projection["private_public_visible"] is True
    assert projection["read_write_certify"] is True
    assert projection["registry_persistent"] is True
    assert projection["oauth_verified"] is True
    assert "accounts" not in projection
    assert "sample_private_repositories" not in projection
    assert "clients" not in projection
    for private_value in (
        "private-login",
        "customer-private-repository",
        "R_private",
        "internal-client-detail",
        "vault_user_token_fallback",
    ):
        assert private_value not in serialized
