"""Independent signed evidence-root anchoring outside the custody database."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import (
    canonical_json,
    parse_utc_iso,
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)

_ZERO_HASH = "0" * 64


class AnchorError(RuntimeError):
    """Base anchor-provider failure."""


class AnchorUnavailable(AnchorError):
    """The independent provider cannot currently accept anchors."""


class AnchorConflict(AnchorError):
    """An idempotency or receipt identity was reused with different content."""


class AnchorStatement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: str
    tenant_ref: str
    artifact_id: str
    evidence_merkle_root: str
    policy_version: str
    anchored_at: datetime
    anchor_provider_id: str
    supersedes_receipt_id: str | None = None
    invalidates_receipt_id: str | None = None

    @model_validator(mode="after")
    def validate_statement(self) -> "AnchorStatement":
        for name in ("run_id", "artifact_id", "policy_version", "anchor_provider_id"):
            require_identifier(getattr(self, name), name)
        require_sha256(self.tenant_ref, "tenant_ref")
        require_sha256(self.evidence_merkle_root, "evidence_merkle_root")
        if self.anchored_at.tzinfo is None:
            raise ValueError("anchored_at must be timezone-aware")
        if self.supersedes_receipt_id is not None:
            require_identifier(self.supersedes_receipt_id, "supersedes_receipt_id")
        if self.invalidates_receipt_id is not None:
            require_identifier(self.invalidates_receipt_id, "invalidates_receipt_id")
        if self.supersedes_receipt_id and self.invalidates_receipt_id:
            raise ValueError("an anchor may supersede or invalidate, but not both")
        return self

    @property
    def statement_sha256(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class AnchorReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    receipt_id: str
    statement: AnchorStatement
    statement_sha256: str
    provider_key_id: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    log_index: int = Field(ge=1)
    prev_chain_hash: str
    receipt_hash: str
    chain_hash: str
    signature_b64: str

    @model_validator(mode="after")
    def validate_receipt(self) -> "AnchorReceipt":
        require_identifier(self.receipt_id, "receipt_id")
        for name in ("statement_sha256", "prev_chain_hash", "receipt_hash", "chain_hash"):
            require_sha256(getattr(self, name), name)
        if self.statement_sha256 != self.statement.statement_sha256:
            raise ValueError("statement_sha256 mismatch")
        return self

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "statement": self.statement.model_dump(mode="json"),
            "statement_sha256": self.statement_sha256,
            "provider_key_id": self.provider_key_id,
            "algorithm": self.algorithm,
            "log_index": self.log_index,
            "prev_chain_hash": self.prev_chain_hash,
        }


class AnchorVerificationBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    receipt: AnchorReceipt
    provider_public_key_pem: str
    log_entry: dict[str, Any]


@dataclass(slots=True)
class IndependentFileAnchorProvider:
    """Signed append-only JSONL provider in storage separate from custody DB."""

    root: Path
    provider_id: str
    _private_key: Ed25519PrivateKey
    available: bool = True

    def __post_init__(self) -> None:
        require_identifier(self.provider_id, "provider_id")
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "receipts").mkdir(parents=True, exist_ok=True)
        (self.root / "idempotency").mkdir(parents=True, exist_ok=True)

    @classmethod
    def generate(cls, root: Path, provider_id: str) -> "IndependentFileAnchorProvider":
        return cls(root=root, provider_id=provider_id, _private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_pem(
        cls,
        root: Path,
        provider_id: str,
        private_key_pem: bytes,
        *,
        password: bytes | None = None,
    ) -> "IndependentFileAnchorProvider":
        key = serialization.load_pem_private_key(private_key_pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("anchor private key must be Ed25519")
        return cls(root=root, provider_id=provider_id, _private_key=key)

    @property
    def public_key_pem(self) -> str:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    def health(self) -> dict[str, Any]:
        writable = os.access(self.root, os.W_OK)
        return {
            "status": "ok" if self.available and writable else "unavailable",
            "provider_id": self.provider_id,
            "provider_key_id": self.key_id,
            "storage_root": str(self.root),
            "storage_separate_from_custody_database": True,
        }

    def create_anchor(self, statement: AnchorStatement, *, idempotency_key: str) -> AnchorReceipt:
        if not self.available or not os.access(self.root, os.W_OK):
            raise AnchorUnavailable("anchor_provider_unavailable")
        require_identifier(idempotency_key, "idempotency_key")
        if statement.anchor_provider_id != self.provider_id:
            raise AnchorConflict("anchor_provider_identity_mismatch")
        self._verify_link_target(statement.supersedes_receipt_id)
        self._verify_link_target(statement.invalidates_receipt_id)
        identity_path = self.root / "idempotency" / f"{idempotency_key}.json"
        if identity_path.exists():
            record = json.loads(identity_path.read_text(encoding="utf-8"))
            if record["statement_sha256"] != statement.statement_sha256:
                raise AnchorConflict("idempotency_payload_conflict")
            receipt = self.get_receipt(record["receipt_id"])
            self._ensure_receipt_logged(receipt)
            return receipt

        log_entries = self._read_log()
        log_index = len(log_entries) + 1
        prev_chain_hash = _ZERO_HASH if not log_entries else log_entries[-1]["chain_hash"]
        receipt_id = f"anchor.{sha256_bytes((self.provider_id + ':' + statement.statement_sha256).encode())[:32]}"
        existing_path = self.root / "receipts" / f"{receipt_id}.json"
        if existing_path.exists():
            existing = AnchorReceipt.model_validate_json(existing_path.read_text(encoding="utf-8"))
            if existing.statement_sha256 != statement.statement_sha256:
                raise AnchorConflict("receipt_identity_conflict")
            self._ensure_receipt_logged(existing)
            if not identity_path.exists():
                self._atomic_json(identity_path, {
                    "idempotency_key": idempotency_key,
                    "statement_sha256": statement.statement_sha256,
                    "receipt_id": receipt_id,
                })
            return existing
        unsigned = {
            "schema_version": "1.0.0",
            "receipt_id": receipt_id,
            "statement": statement.model_dump(mode="json"),
            "statement_sha256": statement.statement_sha256,
            "provider_key_id": self.key_id,
            "algorithm": "Ed25519",
            "log_index": log_index,
            "prev_chain_hash": prev_chain_hash,
        }
        signature = self._private_key.sign(canonical_json(unsigned).encode("utf-8"))
        receipt_hash = sha256_json({**unsigned, "signature_b64": base64.b64encode(signature).decode("ascii")})
        chain_hash = sha256_bytes(bytes.fromhex(prev_chain_hash) + bytes.fromhex(receipt_hash))
        receipt = AnchorReceipt(
            **unsigned,
            receipt_hash=receipt_hash,
            chain_hash=chain_hash,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )
        log_entry = {
            "log_index": log_index,
            "receipt_id": receipt_id,
            "statement_sha256": statement.statement_sha256,
            "receipt_hash": receipt_hash,
            "prev_chain_hash": prev_chain_hash,
            "chain_hash": chain_hash,
            "anchored_at": to_utc_iso(statement.anchored_at),
        }
        self._atomic_json(existing_path, receipt.model_dump(mode="json"))
        self._append_log(log_entry)
        self._atomic_json(identity_path, {
            "idempotency_key": idempotency_key,
            "statement_sha256": statement.statement_sha256,
            "receipt_id": receipt_id,
        })
        return receipt

    def get_receipt(self, receipt_id: str) -> AnchorReceipt:
        require_identifier(receipt_id, "receipt_id")
        path = self.root / "receipts" / f"{receipt_id}.json"
        if not path.is_file():
            raise KeyError(receipt_id)
        return AnchorReceipt.model_validate_json(path.read_text(encoding="utf-8"))

    def verification_bundle(self, receipt_id: str) -> AnchorVerificationBundle:
        receipt = self.get_receipt(receipt_id)
        entries = self._read_log()
        entry = next((item for item in entries if item["receipt_id"] == receipt_id), None)
        if entry is None:
            raise AnchorError("receipt_missing_from_provider_log")
        return AnchorVerificationBundle(
            receipt=receipt,
            provider_public_key_pem=self.public_key_pem,
            log_entry=entry,
        )

    def verify_receipt(self, receipt: AnchorReceipt) -> tuple[bool, str]:
        bundle = self.verification_bundle(receipt.receipt_id)
        if bundle.receipt != receipt:
            return False, "provider_receipt_mismatch"
        return verify_anchor_bundle(bundle)

    def verify_log(self) -> dict[str, Any]:
        entries = self._read_log()
        previous = _ZERO_HASH
        failures: list[int] = []
        for entry in entries:
            if entry["prev_chain_hash"] != previous:
                failures.append(int(entry["log_index"]))
            calculated = sha256_bytes(bytes.fromhex(previous) + bytes.fromhex(entry["receipt_hash"]))
            if entry["chain_hash"] != calculated:
                failures.append(int(entry["log_index"]))
            previous = calculated
        return {
            "valid": bool(entries) and not failures,
            "entry_count": len(entries),
            "chain_tip": previous,
            "invalid_log_indices": sorted(set(failures)),
        }

    def _ensure_receipt_logged(self, receipt: AnchorReceipt) -> None:
        entries = self._read_log()
        matching = next((entry for entry in entries if entry["receipt_id"] == receipt.receipt_id), None)
        expected = {
            "log_index": receipt.log_index,
            "receipt_id": receipt.receipt_id,
            "statement_sha256": receipt.statement_sha256,
            "receipt_hash": receipt.receipt_hash,
            "prev_chain_hash": receipt.prev_chain_hash,
            "chain_hash": receipt.chain_hash,
            "anchored_at": to_utc_iso(receipt.statement.anchored_at),
        }
        if matching is not None:
            if matching != expected:
                raise AnchorConflict("existing_anchor_log_entry_conflict")
            return
        if len(entries) + 1 != receipt.log_index:
            raise AnchorConflict("anchor_log_index_gap")
        previous = _ZERO_HASH if not entries else entries[-1]["chain_hash"]
        if previous != receipt.prev_chain_hash:
            raise AnchorConflict("anchor_log_predecessor_conflict")
        self._append_log(expected)

    def _verify_link_target(self, receipt_id: str | None) -> None:
        if receipt_id is None:
            return
        self.get_receipt(receipt_id)

    def _read_log(self) -> list[dict[str, Any]]:
        path = self.root / "anchor-log.jsonl"
        if not path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def _append_log(self, entry: dict[str, Any]) -> None:
        path = self.root / "anchor-log.jsonl"
        with path.open("ab") as handle:
            handle.write(canonical_json(entry).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise AnchorConflict(f"append_only_path_exists:{path.name}")
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write((canonical_json(value) + "\n").encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise


def privacy_preserving_tenant_ref(tenant_id: str, namespace: str) -> str:
    require_identifier(tenant_id, "tenant_id")
    require_identifier(namespace, "namespace")
    return sha256_bytes(f"{namespace}:{tenant_id}".encode("utf-8"))


def verify_anchor_bundle(bundle: AnchorVerificationBundle) -> tuple[bool, str]:
    receipt = bundle.receipt
    try:
        key = serialization.load_pem_public_key(bundle.provider_public_key_pem.encode("ascii"))
    except ValueError:
        return False, "invalid_provider_public_key"
    if not isinstance(key, Ed25519PublicKey):
        return False, "provider_key_not_ed25519"
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    if expected_key_id != receipt.provider_key_id:
        return False, "provider_key_id_mismatch"
    try:
        signature = base64.b64decode(receipt.signature_b64, validate=True)
        key.verify(signature, canonical_json(receipt.signed_payload()).encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False, "invalid_anchor_signature"
    expected_receipt_hash = sha256_json({
        **receipt.signed_payload(),
        "signature_b64": receipt.signature_b64,
    })
    if receipt.receipt_hash != expected_receipt_hash:
        return False, "anchor_receipt_hash_mismatch"
    expected_chain = sha256_bytes(
        bytes.fromhex(receipt.prev_chain_hash) + bytes.fromhex(receipt.receipt_hash)
    )
    if receipt.chain_hash != expected_chain:
        return False, "anchor_chain_hash_mismatch"
    entry = bundle.log_entry
    expected_entry = {
        "log_index": receipt.log_index,
        "receipt_id": receipt.receipt_id,
        "statement_sha256": receipt.statement_sha256,
        "receipt_hash": receipt.receipt_hash,
        "prev_chain_hash": receipt.prev_chain_hash,
        "chain_hash": receipt.chain_hash,
        "anchored_at": to_utc_iso(receipt.statement.anchored_at),
    }
    if entry != expected_entry:
        return False, "anchor_log_entry_mismatch"
    try:
        parse_utc_iso(entry["anchored_at"])
    except ValueError:
        return False, "anchor_timestamp_invalid"
    return True, "verified"
