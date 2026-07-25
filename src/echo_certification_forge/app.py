"""Environment-configured ASGI application."""
from __future__ import annotations

import os
from pathlib import Path

from .evidence import EvidenceStore
from .policy import RuleManifest
from .release_hooks import WebhookSecretRegistry
from .service import ServiceContext, create_app
from .signing import TrustedPublicKeyRegistry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_db = Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO_ROOT / "var" / "certforge.sqlite3"))
_evidence = Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO_ROOT / "var" / "evidence"))
_policy = Path(os.environ.get("ECHO_CERTFORGE_POLICY", _REPO_ROOT / "policies" / "mandatory-rules.v1.json"))
_public_keys = Path(os.environ.get("ECHO_CERTFORGE_TRUSTED_KEYS", _REPO_ROOT / "var" / "trusted-public-keys"))
_deployment_ledger = Path(
    os.environ.get("ECHO_CERTFORGE_DEPLOYMENT_LEDGER", _REPO_ROOT / "var" / "deployments.sqlite3")
)
_webhook_keys = Path(
    os.environ.get("ECHO_CERTFORGE_WEBHOOK_KEYS", _REPO_ROOT / "var" / "webhook-keys.json")
)

app = create_app(
    ServiceContext(
        store=EvidenceStore(_db, _evidence),
        manifest=RuleManifest.load(_policy),
        trusted_keys=TrustedPublicKeyRegistry.from_directory(_public_keys),
        deployment_ledger_path=_deployment_ledger,
        webhook_secrets=WebhookSecretRegistry.from_file(_webhook_keys),
    )
)
