"""Environment-configured ASGI application."""
from __future__ import annotations

import os
from pathlib import Path

from .evidence import EvidenceStore
from .policy import RuleManifest
from .release_hooks import WebhookSecretRegistry
from .runner import TrustedTransportRegistry
from .service import ServiceContext, create_app
from .signing import TrustedPublicKeyRegistry
from .subscriber import SubscriberGovernance, SubscriberPolicy

_REPO_ROOT = Path(__file__).resolve().parents[2]
_db = Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO_ROOT / "var" / "certforge.sqlite3"))
_evidence = Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO_ROOT / "var" / "evidence"))
_policy = Path(os.environ.get("ECHO_CERTFORGE_POLICY", _REPO_ROOT / "policies" / "mandatory-rules.v2.json"))
_public_keys = Path(os.environ.get("ECHO_CERTFORGE_TRUSTED_KEYS", _REPO_ROOT / "var" / "trusted-public-keys"))
_deployment_ledger = Path(
    os.environ.get("ECHO_CERTFORGE_DEPLOYMENT_LEDGER", _REPO_ROOT / "var" / "deployments.sqlite3")
)
_webhook_keys = Path(
    os.environ.get("ECHO_CERTFORGE_WEBHOOK_KEYS", _REPO_ROOT / "var" / "webhook-keys.json")
)
_deployment_keys = Path(
    os.environ.get("ECHO_CERTFORGE_DEPLOYMENT_KEYS", _REPO_ROOT / "var" / "deployment-keys.json")
)
_subscriber_policy_path = Path(
    os.environ.get(
        "ECHO_CERTFORGE_SUBSCRIBER_POLICY",
        _REPO_ROOT / "policies" / "subscriber-governance.v1.json",
    )
)
_subscribers_enabled = os.environ.get("ECHO_CERTFORGE_SUBSCRIBERS_ENABLED", "0") == "1"
_subscriber_pepper = os.environ.get("ECHO_CERTFORGE_API_KEY_PEPPER")
if _subscribers_enabled and _subscriber_pepper is None:
    raise RuntimeError(
        "ECHO_CERTFORGE_API_KEY_PEPPER is required when subscriber governance is enabled"
    )
_subscribers = (
    SubscriberGovernance(
        _db,
        SubscriberPolicy.load(_subscriber_policy_path),
        _subscriber_pepper.encode("utf-8"),
    )
    if _subscribers_enabled and _subscriber_pepper is not None
    else None
)
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
        subscribers=_subscribers,
        deployment_ledger_path=_deployment_ledger,
        webhook_secrets=WebhookSecretRegistry.from_file(_webhook_keys),
        deployment_credentials=WebhookSecretRegistry.from_file(_deployment_keys),
        transport_registry=_load_transport_registry(_transport_keys),
        adapter_mode=os.environ.get("ECHO_CERTFORGE_ADAPTER_MODE", "pending"),
    )
)
