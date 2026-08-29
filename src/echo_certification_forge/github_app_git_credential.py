"""Owner-verified GitHub App credential helper for exact-revision acquisition.

Git invokes this module through the standard credential-helper protocol.  The
short-lived installation token is written only to Git's private stdin/stdout
pipe; it is never placed in a URL, environment variable, process argument, or
log record.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_ACCOUNTS: Mapping[str, tuple[str, int]] = {
    "echoomegaprime": ("echoomegaprime", 314902331),
    "echo-omega-prime": ("ECHO-OMEGA-PRIME", 264607697),
    "bmcbob76": ("Bmcbob76", 203470412),
    "bobmcwilliams4": ("bobmcwilliams4", 235318155),
}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_MAX_INPUT_BYTES = 16 * 1024


class GitHubCredentialError(RuntimeError):
    """A fail-closed error safe to report without credential material."""


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_app_jwt(
    app_id: int, private_key_pem: bytes, *, now: int | None = None
) -> str:
    """Build a ten-minute RS256 GitHub App JWT from file-loaded key material."""

    issued = int(time.time() if now is None else now)
    header = _b64url(
        json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    claims = _b64url(
        json.dumps(
            {"iat": issued - 60, "exp": issued + 540, "iss": str(app_id)},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise GitHubCredentialError("GitHub App private key file is invalid") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubCredentialError("GitHub App private key must be RSA")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{_b64url(signature)}"


def parse_credential_request(stream: TextIO) -> dict[str, str]:
    """Read a bounded, duplicate-free Git credential request."""

    request: dict[str, str] = {}
    consumed = 0
    for raw_line in stream:
        consumed += len(raw_line.encode("utf-8"))
        if consumed > _MAX_INPUT_BYTES:
            raise GitHubCredentialError("Git credential request is too large")
        line = raw_line.rstrip("\r\n")
        if not line:
            break
        key, separator, value = line.partition("=")
        if not separator or not key or key in request or "\x00" in value:
            raise GitHubCredentialError("Git credential request is malformed")
        request[key] = value
    return request


def repository_identity(request: Mapping[str, str]) -> tuple[str, int, str]:
    """Return the canonical owner, exact numeric account ID, and repository."""

    if (
        request.get("protocol") != "https"
        or request.get("host", "").casefold() != "github.com"
    ):
        raise GitHubCredentialError("credential helper accepts only https://github.com")
    path = urllib.parse.unquote(request.get("path", "")).strip("/")
    owner, separator, repository = path.partition("/")
    repository = repository.removesuffix(".git")
    if (
        not separator
        or "/" in repository
        or not all(_IDENTIFIER.fullmatch(part or "") for part in (owner, repository))
    ):
        raise GitHubCredentialError(
            "credential request must name one GitHub repository"
        )
    account = DEFAULT_ACCOUNTS.get(owner.casefold())
    if account is None:
        raise GitHubCredentialError(
            "repository owner is outside the four-account allowlist"
        )
    canonical_owner, account_id = account
    return canonical_owner, account_id, repository


RequestJson = Callable[[str, str, str, Mapping[str, Any] | None], Any]


class GitHubAppCredentialIssuer:
    """Mint a least-privilege installation token for one allowlisted repository."""

    def __init__(
        self,
        *,
        app_id: int,
        private_key_pem: bytes,
        request_json: RequestJson | None = None,
        api_base: str = "https://api.github.com",
    ) -> None:
        if app_id <= 0 or not private_key_pem:
            raise GitHubCredentialError(
                "GitHub App ID and private key file are required"
            )
        if api_base != "https://api.github.com" and not api_base.startswith(
            ("http://127.0.0.1:", "http://localhost:")
        ):
            raise GitHubCredentialError(
                "GitHub API origin must be HTTPS or loopback HTTP"
            )
        self.app_id = app_id
        self.private_key_pem = private_key_pem
        self.api_base = api_base.rstrip("/")
        self.request_json = request_json or self._request_json

    def _request_json(
        self, method: str, path: str, bearer: str, body: Mapping[str, Any] | None
    ) -> Any:
        request = urllib.request.Request(
            f"{self.api_base}{path}",
            data=(
                json.dumps(body, separators=(",", ":")).encode()
                if body is not None
                else None
            ),
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "User-Agent": "echo-certforge-git-credential/1.0",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read())
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            raise GitHubCredentialError(
                f"GitHub API request failed for {method} {path}"
            ) from exc

    def issue(self, request: Mapping[str, str]) -> tuple[str, str, str]:
        owner, expected_account_id, repository = repository_identity(request)
        app_jwt = build_app_jwt(self.app_id, self.private_key_pem)
        installation = self.request_json(
            "GET",
            f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repository, safe='')}/installation",
            app_jwt,
            None,
        )
        account = (
            installation.get("account") if isinstance(installation, Mapping) else None
        )
        login = account.get("login") if isinstance(account, Mapping) else None
        account_id = account.get("id") if isinstance(account, Mapping) else None
        installation_id = (
            installation.get("id") if isinstance(installation, Mapping) else None
        )
        if (
            str(login or "").casefold() != owner.casefold()
            or account_id != expected_account_id
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise GitHubCredentialError(
                "GitHub App installation identity did not match the owner"
            )
        response = self.request_json(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            app_jwt,
            {"repositories": [repository], "permissions": {"contents": "read"}},
        )
        token = response.get("token") if isinstance(response, Mapping) else None
        if not isinstance(token, str) or not token:
            raise GitHubCredentialError("GitHub did not mint an installation token")
        return owner, repository, token


def issuer_from_environment(
    settings: Mapping[str, str] | None = None,
) -> GitHubAppCredentialIssuer:
    """Load only a file-mounted private key; direct secret environment values fail closed."""

    env = settings or os.environ
    if env.get("ECHO_CERTFORGE_GITHUB_PRIVATE_KEY"):
        raise GitHubCredentialError(
            "direct GitHub App private-key environment values are forbidden"
        )
    raw_app_id = env.get("ECHO_CERTFORGE_GITHUB_APP_ID", "")
    key_path = env.get("ECHO_CERTFORGE_GITHUB_PRIVATE_KEY_FILE", "")
    if not raw_app_id.isdigit() or not key_path:
        raise GitHubCredentialError(
            "GitHub App ID and private-key file reference are required"
        )
    path = Path(key_path)
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise GitHubCredentialError(
            "GitHub App private-key file could not be read"
        ) from exc
    return GitHubAppCredentialIssuer(app_id=int(raw_app_id), private_key_pem=key)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    operation = arguments[0] if len(arguments) == 1 else ""
    if operation in {"store", "erase"}:
        return 0
    if operation != "get":
        print(
            "echo-cert-git-credential: unsupported credential operation",
            file=sys.stderr,
        )
        return 1
    try:
        request = parse_credential_request(sys.stdin)
        owner, repository, token = issuer_from_environment().issue(request)
    except GitHubCredentialError as exc:
        print(f"echo-cert-git-credential: {exc}", file=sys.stderr)
        return 1
    print("protocol=https")
    print("host=github.com")
    print(f"path={owner}/{repository}.git")
    print("username=x-access-token")
    print(f"password={token}")
    print()
    return 0


if (
    __name__ == "__main__"
):  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
