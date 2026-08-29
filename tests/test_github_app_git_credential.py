from __future__ import annotations

import io
import json
import urllib.error

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from echo_certification_forge.github_app_git_credential import (
    DEFAULT_ACCOUNTS,
    GitHubAppCredentialIssuer,
    GitHubCredentialError,
    build_app_jwt,
    issuer_from_environment,
    parse_credential_request,
    repository_identity,
)


def _private_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def test_default_allowlist_binds_all_four_accounts_to_exact_numeric_ids() -> None:
    assert DEFAULT_ACCOUNTS == {
        "echoomegaprime": ("echoomegaprime", 314902331),
        "echo-omega-prime": ("ECHO-OMEGA-PRIME", 264607697),
        "bmcbob76": ("Bmcbob76", 203470412),
        "bobmcwilliams4": ("bobmcwilliams4", 235318155),
    }


@pytest.mark.parametrize(
    "owner", ["echoomegaprime", "ECHO-OMEGA-PRIME", "Bmcbob76", "bobmcwilliams4"]
)
def test_repository_identity_accepts_only_one_allowlisted_github_repo(
    owner: str,
) -> None:
    canonical, account_id, repository = repository_identity(
        {"protocol": "https", "host": "github.com", "path": f"{owner}/private-repo.git"}
    )
    assert canonical.casefold() == owner.casefold()
    assert account_id > 0
    assert repository == "private-repo"


@pytest.mark.parametrize(
    "credential_request",
    [
        {"protocol": "http", "host": "github.com", "path": "echoomegaprime/repo.git"},
        {
            "protocol": "https",
            "host": "evil.example",
            "path": "echoomegaprime/repo.git",
        },
        {"protocol": "https", "host": "github.com", "path": "unknown/repo.git"},
        {"protocol": "https", "host": "github.com", "path": "echoomegaprime/a/b.git"},
    ],
)
def test_repository_identity_fails_closed_outside_exact_scope(
    credential_request: dict[str, str],
) -> None:
    with pytest.raises(GitHubCredentialError):
        repository_identity(credential_request)


def test_credential_request_rejects_duplicate_and_unbounded_fields() -> None:
    assert (
        parse_credential_request(io.StringIO("protocol=https\nhost=github.com\n\n"))[
            "host"
        ]
        == "github.com"
    )
    with pytest.raises(GitHubCredentialError, match="malformed"):
        parse_credential_request(io.StringIO("host=github.com\nhost=github.com\n\n"))
    with pytest.raises(GitHubCredentialError, match="too large"):
        parse_credential_request(io.StringIO("path=" + "a" * (16 * 1024) + "\n"))


def test_app_jwt_is_rs256_and_never_contains_key_material() -> None:
    key = _private_key()
    token = build_app_jwt(4535414, key, now=1_800_000_000)
    header, claims, signature = token.split(".")
    assert json.loads(__import__("base64").urlsafe_b64decode(header + "==")) == {
        "alg": "RS256",
        "typ": "JWT",
    }
    assert (
        json.loads(__import__("base64").urlsafe_b64decode(claims + "=="))["iss"]
        == "4535414"
    )
    assert signature
    assert key.decode() not in token


def test_issuer_verifies_owner_id_and_requests_one_repo_read_only_token() -> None:
    calls: list[tuple[str, str, str, dict | None]] = []

    def request(method: str, path: str, bearer: str, body: dict | None):
        calls.append((method, path, bearer, body))
        if method == "GET":
            return {
                "id": 152387231,
                "account": {"login": "echoomegaprime", "id": 314902331},
            }
        return {"token": "short-lived-installation-token"}

    issuer = GitHubAppCredentialIssuer(
        app_id=4535414,
        private_key_pem=_private_key(),
        request_json=request,
    )
    owner, repository, token = issuer.issue(
        {
            "protocol": "https",
            "host": "github.com",
            "path": "echoomegaprime/private-repo.git",
        }
    )
    assert (owner, repository, token) == (
        "echoomegaprime",
        "private-repo",
        "short-lived-installation-token",
    )
    assert calls[0][0:2] == ("GET", "/repos/echoomegaprime/private-repo/installation")
    assert calls[1][0:2] == ("POST", "/app/installations/152387231/access_tokens")
    assert calls[1][3] == {
        "repositories": ["private-repo"],
        "permissions": {"contents": "read"},
    }
    assert "short-lived-installation-token" not in json.dumps(calls)


def test_github_api_request_retries_transient_transport_failure(monkeypatch) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"id":152387231}'

    attempts = 0

    def urlopen(_request, *, timeout):
        nonlocal attempts
        attempts += 1
        assert timeout == 20
        if attempts < 3:
            raise urllib.error.URLError("temporary")
        return Response()

    monkeypatch.setattr(
        "echo_certification_forge.github_app_git_credential.urllib.request.urlopen",
        urlopen,
    )
    monkeypatch.setattr(
        "echo_certification_forge.github_app_git_credential.time.sleep",
        lambda _seconds: None,
    )
    issuer = GitHubAppCredentialIssuer(
        app_id=4535414,
        private_key_pem=_private_key(),
    )

    assert issuer._request_json("GET", "/app", "jwt", None) == {"id": 152387231}
    assert attempts == 3


def test_issuer_rejects_account_id_mismatch_before_token_minting() -> None:
    def request(_method: str, _path: str, _bearer: str, _body: dict | None):
        return {"id": 99, "account": {"login": "echoomegaprime", "id": 1}}

    issuer = GitHubAppCredentialIssuer(
        app_id=4535414,
        private_key_pem=_private_key(),
        request_json=request,
    )
    with pytest.raises(GitHubCredentialError, match="identity"):
        issuer.issue(
            {
                "protocol": "https",
                "host": "github.com",
                "path": "echoomegaprime/repo.git",
            }
        )


def test_environment_requires_file_key_and_rejects_direct_secret(tmp_path) -> None:
    key_path = tmp_path / "app.pem"
    key_path.write_bytes(_private_key())
    issuer = issuer_from_environment(
        {
            "ECHO_CERTFORGE_GITHUB_APP_ID": "4535414",
            "ECHO_CERTFORGE_GITHUB_PRIVATE_KEY_FILE": str(key_path),
        }
    )
    assert issuer.app_id == 4535414
    with pytest.raises(GitHubCredentialError, match="forbidden"):
        issuer_from_environment(
            {
                "ECHO_CERTFORGE_GITHUB_APP_ID": "4535414",
                "ECHO_CERTFORGE_GITHUB_PRIVATE_KEY_FILE": str(key_path),
                "ECHO_CERTFORGE_GITHUB_PRIVATE_KEY": "not-allowed",
            }
        )
