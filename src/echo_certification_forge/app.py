"""Environment-configured ASGI application."""
from __future__ import annotations

import os
from pathlib import Path

from .evidence import EvidenceStore
from .policy import RuleManifest
from .service import ServiceContext, create_app
from .signing import TrustedPublicKeyRegistry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_db = Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO_ROOT / "var" / "certforge.sqlite3"))
_evidence = Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO_ROOT / "var" / "evidence"))
_policy = Path(os.environ.get("ECHO_CERTFORGE_POLICY", _REPO_ROOT / "policies" / "mandatory-rules.v2.json"))
_public_keys = Path(os.environ.get("ECHO_CERTFORGE_TRUSTED_KEYS", _REPO_ROOT / "var" / "trusted-public-keys"))

app = create_app(
    ServiceContext(
        store=EvidenceStore(_db, _evidence),
        manifest=RuleManifest.load(_policy),
        trusted_keys=TrustedPublicKeyRegistry.from_directory(_public_keys),
        billing_webhook_secret=os.environ.get(
            "ECHO_CERTFORGE_BILLING_WEBHOOK_SECRET", ""
        ),
    )
)
