"""Independent trusted registry for production adapter bundle verification."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import require_identifier, require_sha256, sha256_bytes, sha256_json


class AdapterRegistryError(ValueError):
    """The independent adapter registry is missing or malformed."""


@dataclass(frozen=True, slots=True)
class TrustedAdapterRegistry:
    registry_id: str
    runner_id: str
    runner_key_id: str
    runner_public_key_pem: str
    policy_id: str
    policy_sha256: str
    qualification_trust_pins_sha256: str
    r5_trust_pins_sha256: str
    external_trust_pins_sha256: str

    def __post_init__(self) -> None:
        for field in ("registry_id", "runner_id", "policy_id"):
            require_identifier(str(getattr(self, field)), field)
        for field in (
            "policy_sha256",
            "qualification_trust_pins_sha256",
            "r5_trust_pins_sha256",
            "external_trust_pins_sha256",
        ):
            object.__setattr__(
                self,
                field,
                require_sha256(str(getattr(self, field)), field),
            )
        try:
            key = serialization.load_pem_public_key(
                self.runner_public_key_pem.encode("ascii")
            )
        except (ValueError, TypeError, UnicodeEncodeError) as error:
            raise AdapterRegistryError("registry runner public key is invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise AdapterRegistryError("registry runner key is not Ed25519")
        raw = key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        expected_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        if self.runner_key_id != expected_key_id:
            raise AdapterRegistryError(
                "registry runner key id does not match its public key"
            )
        expected_external = sha256_json(
            {
                "qualification_trust_pins_sha256": (
                    self.qualification_trust_pins_sha256
                ),
                "r5_trust_pins_sha256": self.r5_trust_pins_sha256,
            }
        )
        if self.external_trust_pins_sha256 != expected_external:
            raise AdapterRegistryError(
                "registry external trust digest does not bind qualification and R5 pins"
            )

    @property
    def trust_roots(self) -> dict[str, str]:
        return {
            "registry_id": self.registry_id,
            "runner_key_id": self.runner_key_id,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "qualification_trust_pins_sha256": self.qualification_trust_pins_sha256,
            "r5_trust_pins_sha256": self.r5_trust_pins_sha256,
            "external_trust_pins_sha256": self.external_trust_pins_sha256,
        }


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AdapterRegistryError(
            f"{field} schema mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def parse_trusted_adapter_registry(raw: Any) -> TrustedAdapterRegistry:
    if not isinstance(raw, dict):
        raise AdapterRegistryError("adapter registry must be an object")
    _exact_keys(
        raw,
        {
            "schema_version",
            "registry_id",
            "runner",
            "policy",
            "qualification_trust_pins_sha256",
            "r5_trust_pins_sha256",
            "external_trust_pins_sha256",
        },
        "adapter registry",
    )
    if raw["schema_version"] != "1.0.0":
        raise AdapterRegistryError("unsupported adapter registry schema_version")
    runner = raw["runner"]
    policy = raw["policy"]
    if not isinstance(runner, dict) or not isinstance(policy, dict):
        raise AdapterRegistryError("registry runner and policy must be objects")
    _exact_keys(runner, {"runner_id", "key_id", "public_key_pem"}, "registry runner")
    _exact_keys(policy, {"policy_id", "sha256"}, "registry policy")
    return TrustedAdapterRegistry(
        registry_id=str(raw["registry_id"]),
        runner_id=str(runner["runner_id"]),
        runner_key_id=str(runner["key_id"]),
        runner_public_key_pem=str(runner["public_key_pem"]),
        policy_id=str(policy["policy_id"]),
        policy_sha256=str(policy["sha256"]),
        qualification_trust_pins_sha256=str(
            raw["qualification_trust_pins_sha256"]
        ),
        r5_trust_pins_sha256=str(raw["r5_trust_pins_sha256"]),
        external_trust_pins_sha256=str(raw["external_trust_pins_sha256"]),
    )


def load_trusted_adapter_registry(path: Path) -> TrustedAdapterRegistry:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterRegistryError(
            f"adapter registry unreadable: {type(error).__name__}"
        ) from error
    return parse_trusted_adapter_registry(raw)
