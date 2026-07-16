"""Ed25519 verdict signing and trusted-public-key verification."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json, sha256_bytes
from .models import SignedVerdictEnvelope, VerdictDecision


class Ed25519VerdictSigner:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "Ed25519VerdictSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_pem(cls, private_key_pem: bytes, password: bytes | None = None) -> "Ed25519VerdictSigner":
        key = serialization.load_pem_private_key(private_key_pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("private key must be Ed25519")
        return cls(key)

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    def sign(self, decision: VerdictDecision) -> SignedVerdictEnvelope:
        if decision.signing_key_id != self.key_id:
            raise ValueError("decision signing_key_id does not match signer")
        payload = decision.to_dict()
        signature = self._private_key.sign(canonical_json(payload).encode("utf-8"))
        return SignedVerdictEnvelope(
            payload=payload,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            key_id=self.key_id,
            public_key_pem=self.public_key_pem,
        )


@dataclass(slots=True)
class TrustedPublicKeyRegistry:
    keys: dict[str, Ed25519PublicKey]

    @classmethod
    def empty(cls) -> "TrustedPublicKeyRegistry":
        return cls(keys={})

    @classmethod
    def from_directory(cls, directory: Path) -> "TrustedPublicKeyRegistry":
        registry = cls.empty()
        if directory.exists():
            for path in sorted(directory.glob("*.pem")):
                registry.add_pem(path.read_text(encoding="utf-8"))
        return registry

    def add_pem(self, public_key_pem: str) -> str:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("public key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        self.keys[key_id] = key
        return key_id

    def verify(self, envelope: SignedVerdictEnvelope) -> tuple[bool, str]:
        key = self.keys.get(envelope.key_id)
        if key is None:
            return False, "untrusted_signing_key"
        try:
            key.verify(
                base64.b64decode(envelope.signature_b64, validate=True),
                canonical_json(envelope.payload).encode("utf-8"),
            )
        except (InvalidSignature, ValueError):
            return False, "invalid_signature"
        if envelope.payload.get("signing_key_id") != envelope.key_id:
            return False, "payload_key_id_mismatch"
        return True, "verified"
