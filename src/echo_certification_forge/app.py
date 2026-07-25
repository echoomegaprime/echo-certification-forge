"""Environment-configured ASGI application."""
from __future__ import annotations

import os
from pathlib import Path

from .evidence import EvidenceStore
from .policy import RuleManifest
from .runner import TrustedTransportRegistry
from .service import ServiceContext, create_app
from .signing import TrustedPublicKeyRegistry

_REPO_ROOT = Path(__file__).resolve().parents[2]
_db = Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO_ROOT / "var" / "certforge.sqlite3"))
_evidence = Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO_ROOT / "var" / "evidence"))
_policy = Path(os.environ.get("ECHO_CERTFORGE_POLICY", _REPO_ROOT / "policies" / "mandatory-rules.v1.json"))
_public_keys = Path(os.environ.get("ECHO_CERTFORGE_TRUSTED_KEYS", _REPO_ROOT / "var" / "trusted-public-keys"))
_transport_keys = Path(
    os.environ.get(
        "ECHO_CERTFORGE_TRANSPORT_KEYS",
        _REPO_ROOT / "var" / "trusted-transport-keys",
    )
)


def _load_transport_registry(directory: Path) -> TrustedTransportRegistry:
    registry = TrustedTransportRegistry.empty()
    if directory.is_dir():
        for path in sorted(directory.glob("*.pem")):
            registry.add_pem(path.read_text(encoding="ascii"))
    return registry

app = create_app(
    ServiceContext(
        store=EvidenceStore(_db, _evidence),
        manifest=RuleManifest.load(_policy),
        trusted_keys=TrustedPublicKeyRegistry.from_directory(_public_keys),
        transport_registry=_load_transport_registry(_transport_keys),
        billing_webhook_secret=os.environ.get(
            "ECHO_CERTFORGE_BILLING_WEBHOOK_SECRET", ""
        ),
    )
)
