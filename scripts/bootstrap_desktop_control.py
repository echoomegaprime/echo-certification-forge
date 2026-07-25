"""Provision the sovereign Echo Desktop tenant and vault its API key.

The generated subscriber key moves directly from CertificationPlatform.bootstrap()
to the encrypted Vault HTTP endpoint. It is never printed, written to disk, or
accepted as a command-line argument.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from echo_certification_forge.platform import CertificationPlatform


DEFAULT_SERVICE = "certforge.desktop_admin_api_key"


def _sovereign_key(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SOVEREIGN_KEY="):
            value = line.split("=", 1)[1].strip()
            if value:
                return value
    raise RuntimeError("sovereign key is unavailable")


def _organization_exists(db_path: Path, organization_id: str) -> bool:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM organizations WHERE organization_id = ?",
            (organization_id,),
        ).fetchone()
    return row is not None


def _vault_has_service(vault_base: str, sovereign_key: str, service: str) -> bool:
    request = Request(
        f"{vault_base.rstrip('/')}/vault/credentials/{service}",
        method="GET",
        headers={"X-Echo-API-Key": sovereign_key},
    )
    try:
        with urlopen(request, timeout=15) as response:
            # Read and discard the body: callers need only existence, never plaintext.
            response.read()
        return True
    except Exception as exc:
        status = getattr(exc, "code", None)
        if status == 404:
            return False
        raise RuntimeError("vault availability check failed") from exc


def _store_in_vault(
    *,
    vault_base: str,
    sovereign_key: str,
    service: str,
    account: dict[str, str],
) -> dict[str, Any]:
    payload = json.dumps(
        {
            "service": service,
            "username": "echo-desktop",
            "secret": account["api_key"],
            "metadata": {
                "organization_id": account["organization_id"],
                "tenant_id": account["tenant_id"],
                "project_id": account["project_id"],
                "key_id": account["key_id"],
                "purpose": "server-side Certification Forge administrative SDK bridge",
            },
            "tags": ["certforge", "echo-desktop", "server-side", "admin"],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        f"{vault_base.rstrip('/')}/vault/credentials",
        data=payload,
        method="POST",
        headers={
            "X-Echo-API-Key": sovereign_key,
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
    except Exception as exc:
        raise RuntimeError("vault write failed") from exc
    if result.get("stored") is not True or result.get("service") != service:
        raise RuntimeError("vault did not confirm the expected credential write")
    return {
        "stored": True,
        "service": service,
        "version": result.get("version"),
        "key_fingerprint": result.get("key_fingerprint"),
    }


def provision(args: argparse.Namespace) -> dict[str, Any]:
    db_path = Path(args.database).resolve()
    platform = CertificationPlatform(db_path)
    sovereign_key = _sovereign_key(Path(args.sovereign_key_file))
    organization_exists = _organization_exists(db_path, args.organization_id)
    vault_exists = _vault_has_service(args.vault_base, sovereign_key, args.vault_service)
    if organization_exists or vault_exists:
        if organization_exists and vault_exists:
            return {
                "ok": True,
                "created": False,
                "organization_id": args.organization_id,
                "project_id": args.project_id,
                "vault_service": args.vault_service,
            }
        raise RuntimeError(
            "partial provisioning state detected; refusing to create or overwrite credentials"
        )

    account = platform.bootstrap(
        organization_id=args.organization_id,
        tenant_id=args.tenant_id,
        organization_name=args.organization_name,
        project_id=args.project_id,
        project_name=args.project_name,
        target_reference=args.target_reference,
        required_policy=args.required_policy,
        owner_user_id=args.owner_user_id,
        owner_email=args.owner_email,
        plan_id=args.plan,
        billing_status="active",
    )
    try:
        vault = _store_in_vault(
            vault_base=args.vault_base,
            sovereign_key=sovereign_key,
            service=args.vault_service,
            account=account,
        )
    except Exception:
        # The raw key is intentionally unrecoverable after this process exits. Stop
        # loudly instead of leaving a deceptively usable half-provisioned bridge.
        raise RuntimeError(
            "tenant created but vault storage failed; rotate the subscriber key before retrying"
        ) from None
    return {
        "ok": True,
        "created": True,
        "organization_id": account["organization_id"],
        "tenant_id": account["tenant_id"],
        "project_id": account["project_id"],
        "key_id": account["key_id"],
        "vault": vault,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--database", default=os.environ.get("ECHO_CERTFORGE_DB", "var/certforge.sqlite3"))
    result.add_argument("--vault-base", default="http://127.0.0.1:8000")
    result.add_argument("--vault-service", default=DEFAULT_SERVICE)
    result.add_argument("--sovereign-key-file", default="/home/forge/.echo_sovereign_key")
    result.add_argument("--organization-id", default="org-echo-sovereign")
    result.add_argument("--tenant-id", default="echo-sovereign")
    result.add_argument("--organization-name", default="Echo Omega Prime")
    result.add_argument("--project-id", default="project-echo-desktop")
    result.add_argument("--project-name", default="Echo Desktop")
    result.add_argument("--target-reference", default="github:ECHO-OMEGA-PRIME/echo-desktop")
    result.add_argument("--required-policy", default="mandatory-rules-v1")
    result.add_argument("--owner-user-id", default="user-echo-desktop-admin")
    result.add_argument("--owner-email", default="certforge-admin@echo-op.com")
    result.add_argument("--plan", choices=("starter", "team", "enterprise"), default="enterprise")
    return result


def main() -> int:
    result = provision(parser().parse_args())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
