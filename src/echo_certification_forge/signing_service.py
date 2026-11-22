"""Isolated production verdict signing with anchor and key-lifecycle gates."""
from __future__ import annotations

import base64
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .anchor import AnchorVerificationBundle, privacy_preserving_tenant_ref, verify_anchor_bundle
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
from .models import ReleaseVerdict, RunOutcome


class SigningError(RuntimeError):
    """Base isolated signing failure."""


class SigningUnavailable(SigningError):
    """The isolated signing service cannot currently sign."""


class SigningAuthorizationError(SigningError):
    """Signing authorization or actor validation failed."""


class SigningConflict(SigningError):
    """A request, nonce, key, or immutable context conflicted."""


class SigningActorType(StrEnum):
    CONTROL_PLANE = "CONTROL_PLANE"
    RUNNER = "RUNNER"
    MODEL = "MODEL"
    DESKTOP = "DESKTOP"
    ORDINARY_WORKER = "ORDINARY_WORKER"


class VerdictLifecycleState(StrEnum):
    VALID = "VALID"
    REVOKED = "REVOKED"
    INVALIDATED = "INVALIDATED"
    SUPERSEDED = "SUPERSEDED"


class PublicKeyState(StrEnum):
    ACTIVE = "ACTIVE"
    GRACE = "GRACE"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"


class MandatoryRuleAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    passed: bool
    evidence_ids: tuple[str, ...]

    @model_validator(mode="after")
    def validate_attestation(self) -> "MandatoryRuleAttestation":
        require_identifier(self.rule_id, "rule_id")
        if not self.evidence_ids:
            raise ValueError("mandatory rule attestations require evidence ids")
        for evidence_id in self.evidence_ids:
            require_identifier(evidence_id, "evidence_id")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("evidence_ids must be unique and sorted")
        return self


class SigningRunContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: str
    tenant_id: str
    target_identity_digest: str
    environment_identity_digest: str
    policy_version: str
    policy_digest: str
    mandatory_rules_digest: str
    mandatory_rule_ids: tuple[str, ...]
    evidence_merkle_root: str
    anchor_artifact_id: str
    tenant_anchor_namespace: str
    lifecycle_state: VerdictLifecycleState = VerdictLifecycleState.VALID

    @model_validator(mode="after")
    def validate_context(self) -> "SigningRunContext":
        for name in (
            "run_id",
            "tenant_id",
            "policy_version",
            "anchor_artifact_id",
            "tenant_anchor_namespace",
        ):
            require_identifier(getattr(self, name), name)
        for name in (
            "target_identity_digest",
            "environment_identity_digest",
            "policy_digest",
            "mandatory_rules_digest",
            "evidence_merkle_root",
        ):
            require_sha256(getattr(self, name), name)
        if not self.mandatory_rule_ids:
            raise ValueError("at least one mandatory rule is required")
        for rule_id in self.mandatory_rule_ids:
            require_identifier(rule_id, "rule_id")
        if tuple(sorted(set(self.mandatory_rule_ids))) != self.mandatory_rule_ids:
            raise ValueError("mandatory_rule_ids must be unique and sorted")
        return self

    @property
    def identity_digest(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class SigningAuthorizationClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    authorization_id: str
    run_id: str
    tenant_id: str
    actor_id: str
    actor_type: Literal[SigningActorType.CONTROL_PLANE]
    scopes: tuple[Literal["verdict.sign"], ...] = ("verdict.sign",)
    issued_at: datetime
    expires_at: datetime
    authority_key_id: str

    @model_validator(mode="after")
    def validate_claims(self) -> "SigningAuthorizationClaims":
        for name in ("authorization_id", "run_id", "tenant_id", "actor_id"):
            require_identifier(getattr(self, name), name)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("authorization timestamps must be timezone-aware")
        lifetime = self.expires_at - self.issued_at
        if lifetime <= timedelta(0) or lifetime > timedelta(minutes=10):
            raise ValueError("authorization lifetime must be positive and no more than ten minutes")
        return self


class SignedSigningAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: SigningAuthorizationClaims
    signature_b64: str
    key_id: str


class SigningAuthorizationAuthority:
    """Issues short-lived authorizations; it cannot sign release verdicts."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "SigningAuthorizationAuthority":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self._public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return f"ed25519:{sha256_bytes(raw)[:32]}"

    def issue(
        self,
        *,
        authorization_id: str,
        run_id: str,
        tenant_id: str,
        actor_id: str,
        issued_at: datetime,
        ttl: timedelta,
    ) -> SignedSigningAuthorization:
        claims = SigningAuthorizationClaims(
            authorization_id=authorization_id,
            run_id=run_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_type=SigningActorType.CONTROL_PLANE,
            issued_at=issued_at,
            expires_at=issued_at + ttl,
            authority_key_id=self.key_id,
        )
        signature = self._private_key.sign(
            canonical_json(claims.model_dump(mode="json")).encode("utf-8")
        )
        return SignedSigningAuthorization(
            claims=claims,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            key_id=self.key_id,
        )


class TrustedSigningAuthorizationRegistry:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add_pem(self, public_key_pem: str) -> str:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("signing authorization key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        self._keys[key_id] = key
        return key_id

    def verify(
        self,
        authorization: SignedSigningAuthorization,
        *,
        now: datetime,
    ) -> SigningAuthorizationClaims:
        key = self._keys.get(authorization.key_id)
        if key is None:
            raise SigningAuthorizationError("unknown_signing_authority")
        try:
            key.verify(
                base64.b64decode(authorization.signature_b64, validate=True),
                canonical_json(authorization.claims.model_dump(mode="json")).encode("utf-8"),
            )
        except (InvalidSignature, ValueError) as exc:
            raise SigningAuthorizationError("invalid_signing_authorization") from exc
        claims = authorization.claims
        if claims.authority_key_id != authorization.key_id:
            raise SigningAuthorizationError("signing_authority_key_mismatch")
        if now >= claims.expires_at:
            raise SigningAuthorizationError("signing_authorization_expired")
        if now < claims.issued_at - timedelta(minutes=1):
            raise SigningAuthorizationError("signing_authorization_not_yet_valid")
        return claims


class ProductionSigningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = "1.0.0"
    request_id: str
    nonce: str = Field(min_length=16, max_length=256)
    actor_type: SigningActorType
    actor_id: str
    run_id: str
    tenant_id: str
    run_outcome: RunOutcome
    release_verdict: ReleaseVerdict
    target_identity_digest: str
    environment_identity_digest: str
    policy_version: str
    policy_digest: str
    mandatory_rules_digest: str
    mandatory_rule_results: tuple[MandatoryRuleAttestation, ...]
    evidence_merkle_root: str
    anchor_bundle: AnchorVerificationBundle
    lifecycle_state: VerdictLifecycleState
    signing_key_id: str
    issued_at: datetime
    expires_at: datetime
    authorization: SignedSigningAuthorization

    @model_validator(mode="after")
    def validate_request(self) -> "ProductionSigningRequest":
        for name in ("request_id", "actor_id", "run_id", "tenant_id", "policy_version"):
            require_identifier(getattr(self, name), name)
        for name in (
            "target_identity_digest",
            "environment_identity_digest",
            "policy_digest",
            "mandatory_rules_digest",
            "evidence_merkle_root",
        ):
            require_sha256(getattr(self, name), name)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("signing request timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > timedelta(days=90):
            raise ValueError("verdict expiration must be positive and no more than 90 days")
        rule_ids = tuple(item.rule_id for item in self.mandatory_rule_results)
        if tuple(sorted(set(rule_ids))) != rule_ids:
            raise ValueError("mandatory_rule_results must be unique and sorted")
        return self

    @property
    def semantic_digest(self) -> str:
        data = self.model_dump(mode="json", exclude={"nonce", "authorization"})
        data["authorization_sha256"] = sha256_json(self.authorization.claims.model_dump(mode="json"))
        return sha256_json(data)


class ProductionVerdictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0.0"] = "2.0.0"
    request_id: str
    run_id: str
    tenant_id: str
    run_outcome: RunOutcome
    release_verdict: ReleaseVerdict
    target_identity_digest: str
    environment_identity_digest: str
    policy_version: str
    policy_digest: str
    mandatory_rules_digest: str
    mandatory_rule_results_digest: str
    evidence_merkle_root: str
    anchor_receipt_id: str
    anchor_statement_sha256: str
    anchor_provider_id: str
    anchor_provider_key_id: str
    lifecycle_state: VerdictLifecycleState
    signing_key_id: str
    signing_algorithm: Literal["Ed25519"] = "Ed25519"
    issued_at: datetime
    expires_at: datetime


class ProductionSignedVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: ProductionVerdictPayload
    signature_b64: str
    key_id: str
    public_key_pem: str

    @property
    def payload_sha256(self) -> str:
        return sha256_json(self.payload.model_dump(mode="json"))


class PublicKeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_pem: str
    not_before: datetime
    not_after: datetime
    initial_state: PublicKeyState = PublicKeyState.ACTIVE

    @model_validator(mode="after")
    def validate_record(self) -> "PublicKeyRecord":
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("key validity timestamps must be timezone-aware")
        if self.not_after <= self.not_before:
            raise ValueError("key not_after must follow not_before")
        key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("published key must be Ed25519")
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        expected = f"ed25519:{sha256_bytes(raw)[:32]}"
        if self.key_id != expected:
            raise ValueError("public key id mismatch")
        return self


class OfflineVerificationBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: ProductionSignedVerdict
    anchor_bundle: AnchorVerificationBundle
    public_key_bundle: dict[str, Any]


class SigningStore:
    """Durable signing state. Private keys are never persisted here."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS signing_contexts (
                    run_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    context_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS signing_requests (
                    request_id TEXT PRIMARY KEY,
                    semantic_digest TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS signing_nonces (
                    nonce TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS public_keys (
                    key_id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS key_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT NOT NULL REFERENCES public_keys(key_id),
                    state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    effective_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS contexts_no_update BEFORE UPDATE ON signing_contexts
                BEGIN SELECT RAISE(ABORT, 'signing contexts are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS contexts_no_delete BEFORE DELETE ON signing_contexts
                BEGIN SELECT RAISE(ABORT, 'signing contexts are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS signing_requests_no_update BEFORE UPDATE ON signing_requests
                BEGIN SELECT RAISE(ABORT, 'signing requests are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS signing_requests_no_delete BEFORE DELETE ON signing_requests
                BEGIN SELECT RAISE(ABORT, 'signing requests are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS signing_nonces_no_update BEFORE UPDATE ON signing_nonces
                BEGIN SELECT RAISE(ABORT, 'signing nonces are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS signing_nonces_no_delete BEFORE DELETE ON signing_nonces
                BEGIN SELECT RAISE(ABORT, 'signing nonces are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS public_keys_no_update BEFORE UPDATE ON public_keys
                BEGIN SELECT RAISE(ABORT, 'public keys are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS public_keys_no_delete BEFORE DELETE ON public_keys
                BEGIN SELECT RAISE(ABORT, 'public keys are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS key_events_no_update BEFORE UPDATE ON key_events
                BEGIN SELECT RAISE(ABORT, 'key events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS key_events_no_delete BEFORE DELETE ON key_events
                BEGIN SELECT RAISE(ABORT, 'key events are append-only'); END;
                """
            )

    def register_context(self, context: SigningRunContext) -> dict[str, Any]:
        now = to_utc_iso(utc_now())
        encoded = canonical_json(context.model_dump(mode="json"))
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT * FROM signing_contexts WHERE run_id = ?", (context.run_id,)
            ).fetchone()
            if existing is not None:
                if existing["context_sha256"] != context.identity_digest:
                    raise SigningConflict("signing_context_conflict")
                return dict(existing)
            connection.execute(
                "INSERT INTO signing_contexts(run_id, tenant_id, context_json, context_sha256, created_at) VALUES (?, ?, ?, ?, ?)",
                (context.run_id, context.tenant_id, encoded, context.identity_digest, now),
            )
        return self.get_context(context.run_id, context.tenant_id).model_dump(mode="json")

    def get_context(self, run_id: str, tenant_id: str) -> SigningRunContext:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM signing_contexts WHERE run_id = ? AND tenant_id = ?", (run_id, tenant_id)
            ).fetchone()
        if row is None:
            raise KeyError(run_id)
        return SigningRunContext.model_validate_json(row["context_json"])

    def publish_key(self, record: PublicKeyRecord, *, reason: str = "initial publication") -> None:
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            existing = connection.execute("SELECT record_json FROM public_keys WHERE key_id = ?", (record.key_id,)).fetchone()
            if existing is not None:
                if sha256_json(json.loads(existing["record_json"])) != sha256_json(record.model_dump(mode="json")):
                    raise SigningConflict("public_key_record_conflict")
                return
            connection.execute(
                "INSERT INTO public_keys(key_id, record_json, created_at) VALUES (?, ?, ?)",
                (record.key_id, canonical_json(record.model_dump(mode="json")), now),
            )
            connection.execute(
                "INSERT INTO key_events(key_id, state, reason, effective_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (record.key_id, record.initial_state.value, reason, to_utc_iso(record.not_before), now),
            )

    def transition_key(
        self,
        key_id: str,
        state: PublicKeyState,
        *,
        reason: str,
        effective_at: datetime,
    ) -> None:
        if not reason.strip():
            raise ValueError("key transition reason is required")
        if effective_at.tzinfo is None:
            raise ValueError("effective_at must be timezone-aware")
        with self._connection() as connection:
            if connection.execute("SELECT 1 FROM public_keys WHERE key_id = ?", (key_id,)).fetchone() is None:
                raise KeyError(key_id)
            current = connection.execute(
                "SELECT state FROM key_events WHERE key_id = ? ORDER BY event_id DESC LIMIT 1", (key_id,)
            ).fetchone()
            if current is not None and current["state"] == state.value:
                return
            connection.execute(
                "INSERT INTO key_events(key_id, state, reason, effective_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (key_id, state.value, reason, to_utc_iso(effective_at), to_utc_iso(utc_now())),
            )

    def key_record(self, key_id: str) -> tuple[PublicKeyRecord, list[dict[str, Any]]]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM public_keys WHERE key_id = ?", (key_id,)).fetchone()
            events = connection.execute(
                "SELECT * FROM key_events WHERE key_id = ? ORDER BY event_id", (key_id,)
            ).fetchall()
        if row is None:
            raise KeyError(key_id)
        return PublicKeyRecord.model_validate_json(row["record_json"]), [dict(item) for item in events]

    def key_state_at(self, key_id: str, at: datetime) -> tuple[PublicKeyState, str]:
        record, events = self.key_record(key_id)
        if at < record.not_before or at >= record.not_after:
            raise SigningAuthorizationError("signing_key_outside_validity_window")
        applicable = [item for item in events if parse_utc_iso(item["effective_at"]) <= at]
        if not applicable:
            return record.initial_state, "initial publication"
        latest = applicable[-1]
        return PublicKeyState(latest["state"]), str(latest["reason"])

    def public_bundle(self) -> dict[str, Any]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM public_keys ORDER BY key_id").fetchall()
            events = connection.execute("SELECT * FROM key_events ORDER BY event_id").fetchall()
        return {
            "schema_version": "1.0.0",
            "keys": [json.loads(row["record_json"]) for row in rows],
            "events": [dict(row) for row in events],
        }

    def existing_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM signing_requests WHERE request_id = ?", (request_id,)).fetchone()
        return None if row is None else dict(row)

    def nonce_seen(self, nonce: str) -> bool:
        with self._connection() as connection:
            return connection.execute("SELECT 1 FROM signing_nonces WHERE nonce = ?", (nonce,)).fetchone() is not None

    def record_idempotent_nonce(self, nonce: str, request_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO signing_nonces(nonce, request_id, created_at) VALUES (?, ?, ?)",
                (nonce, request_id, to_utc_iso(utc_now())),
            )

    def save_signed_request(self, request: ProductionSigningRequest, envelope: ProductionSignedVerdict) -> None:
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO signing_nonces(nonce, request_id, created_at) VALUES (?, ?, ?)",
                (request.nonce, request.request_id, now),
            )
            connection.execute(
                """
                INSERT INTO signing_requests(
                    request_id, semantic_digest, run_id, tenant_id, envelope_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    request.request_id,
                    request.semantic_digest,
                    request.run_id,
                    request.tenant_id,
                    canonical_json(envelope.model_dump(mode="json")),
                    now,
                ),
            )


class IsolatedVerdictSigningService:
    """Private-key holder. The runner and ordinary control plane never instantiate it."""

    def __init__(
        self,
        store: SigningStore,
        private_keys: dict[str, Ed25519PrivateKey],
        authorization_registry: TrustedSigningAuthorizationRegistry,
        trusted_anchor_keys: dict[str, str],
        *,
        available: bool = True,
    ) -> None:
        self.store = store
        self._private_keys = dict(private_keys)
        self.authorization_registry = authorization_registry
        self.trusted_anchor_keys = dict(trusted_anchor_keys)
        self.available = available

    def sign(
        self,
        request: ProductionSigningRequest,
        *,
        now: datetime | None = None,
    ) -> ProductionSignedVerdict:
        if not self.available:
            raise SigningUnavailable("signing_service_unavailable")
        current = now or utc_now()
        if self.store.nonce_seen(request.nonce):
            raise SigningAuthorizationError("signing_request_replay")
        existing = self.store.existing_request(request.request_id)
        if existing is not None:
            if existing["semantic_digest"] != request.semantic_digest:
                raise SigningConflict("conflicting_idempotent_signing_request")
            self.store.record_idempotent_nonce(request.nonce, request.request_id)
            return ProductionSignedVerdict.model_validate_json(existing["envelope_json"])
        claims = self.authorization_registry.verify(request.authorization, now=current)
        if request.actor_type is not SigningActorType.CONTROL_PLANE:
            raise SigningAuthorizationError("only_control_plane_may_request_signing")
        if (claims.run_id, claims.tenant_id, claims.actor_id) != (
            request.run_id,
            request.tenant_id,
            request.actor_id,
        ):
            raise SigningAuthorizationError("signing_authorization_identity_mismatch")
        if request.issued_at < claims.issued_at - timedelta(minutes=1) or request.issued_at > current + timedelta(minutes=1):
            raise SigningAuthorizationError("signing_request_timestamp_invalid")
        context = self.store.get_context(request.run_id, request.tenant_id)
        self._validate_context(request, context)
        self._validate_anchor(request, context)
        try:
            state, _reason = self.store.key_state_at(request.signing_key_id, current)
        except KeyError as exc:
            raise SigningAuthorizationError("unknown_signing_key") from exc
        if state not in {PublicKeyState.ACTIVE, PublicKeyState.GRACE}:
            raise SigningAuthorizationError(f"signing_key_not_usable:{state.value}")
        private_key = self._private_keys.get(request.signing_key_id)
        if private_key is None:
            raise SigningAuthorizationError("unknown_private_signing_key")
        record, _events = self.store.key_record(request.signing_key_id)
        rule_digest = sha256_json(
            [item.model_dump(mode="json") for item in request.mandatory_rule_results]
        )
        receipt = request.anchor_bundle.receipt
        payload = ProductionVerdictPayload(
            request_id=request.request_id,
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            run_outcome=request.run_outcome,
            release_verdict=request.release_verdict,
            target_identity_digest=request.target_identity_digest,
            environment_identity_digest=request.environment_identity_digest,
            policy_version=request.policy_version,
            policy_digest=request.policy_digest,
            mandatory_rules_digest=request.mandatory_rules_digest,
            mandatory_rule_results_digest=rule_digest,
            evidence_merkle_root=request.evidence_merkle_root,
            anchor_receipt_id=receipt.receipt_id,
            anchor_statement_sha256=receipt.statement_sha256,
            anchor_provider_id=receipt.statement.anchor_provider_id,
            anchor_provider_key_id=receipt.provider_key_id,
            lifecycle_state=request.lifecycle_state,
            signing_key_id=request.signing_key_id,
            issued_at=request.issued_at,
            expires_at=request.expires_at,
        )
        signature = private_key.sign(canonical_json(payload.model_dump(mode="json")).encode("utf-8"))
        envelope = ProductionSignedVerdict(
            payload=payload,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            key_id=request.signing_key_id,
            public_key_pem=record.public_key_pem,
        )
        self.store.save_signed_request(request, envelope)
        return envelope

    @staticmethod
    def _validate_context(request: ProductionSigningRequest, context: SigningRunContext) -> None:
        comparisons = {
            "target_identity_digest": (request.target_identity_digest, context.target_identity_digest),
            "environment_identity_digest": (request.environment_identity_digest, context.environment_identity_digest),
            "policy_version": (request.policy_version, context.policy_version),
            "policy_digest": (request.policy_digest, context.policy_digest),
            "mandatory_rules_digest": (request.mandatory_rules_digest, context.mandatory_rules_digest),
            "evidence_merkle_root": (request.evidence_merkle_root, context.evidence_merkle_root),
        }
        mismatches = [name for name, values in comparisons.items() if values[0] != values[1]]
        if mismatches:
            raise SigningAuthorizationError("signing_context_mismatch:" + ",".join(sorted(mismatches)))
        if request.run_outcome is not RunOutcome.COMPLETE:
            raise SigningAuthorizationError("incomplete_run_cannot_be_signed")
        if request.lifecycle_state is not VerdictLifecycleState.VALID or context.lifecycle_state is not VerdictLifecycleState.VALID:
            raise SigningAuthorizationError("invalid_verdict_lifecycle_state")
        rule_ids = tuple(item.rule_id for item in request.mandatory_rule_results)
        if rule_ids != context.mandatory_rule_ids:
            raise SigningAuthorizationError("mandatory_rule_set_mismatch")
        if any(not item.passed for item in request.mandatory_rule_results):
            raise SigningAuthorizationError("mandatory_rule_failure")

    def _validate_anchor(self, request: ProductionSigningRequest, context: SigningRunContext) -> None:
        receipt = request.anchor_bundle.receipt
        trusted_pem = self.trusted_anchor_keys.get(receipt.provider_key_id)
        if trusted_pem is None:
            raise SigningAuthorizationError("unknown_anchor_provider_key")
        if trusted_pem != request.anchor_bundle.provider_public_key_pem:
            raise SigningAuthorizationError("anchor_provider_key_material_mismatch")
        valid, reason = verify_anchor_bundle(request.anchor_bundle)
        if not valid:
            raise SigningAuthorizationError(f"anchor_verification_failed:{reason}")
        statement = receipt.statement
        expected_tenant_ref = privacy_preserving_tenant_ref(
            request.tenant_id, context.tenant_anchor_namespace
        )
        checks = {
            "run": statement.run_id == request.run_id,
            "tenant": statement.tenant_ref == expected_tenant_ref,
            "artifact": statement.artifact_id == context.anchor_artifact_id,
            "merkle": statement.evidence_merkle_root == request.evidence_merkle_root,
            "policy": statement.policy_version == request.policy_version,
        }
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            raise SigningAuthorizationError("anchor_context_mismatch:" + ",".join(sorted(failed)))


def public_key_record_from_private_key(
    private_key: Ed25519PrivateKey,
    *,
    not_before: datetime,
    not_after: datetime,
    initial_state: PublicKeyState = PublicKeyState.ACTIVE,
) -> PublicKeyRecord:
    public = private_key.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return PublicKeyRecord(
        key_id=f"ed25519:{sha256_bytes(raw)[:32]}",
        public_key_pem=pem,
        not_before=not_before,
        not_after=not_after,
        initial_state=initial_state,
    )


def verify_production_verdict(
    envelope: ProductionSignedVerdict,
    public_key_bundle: dict[str, Any],
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    current = now or utc_now()
    records = {
        item["key_id"]: PublicKeyRecord.model_validate(item)
        for item in public_key_bundle.get("keys", [])
    }
    record = records.get(envelope.key_id)
    if record is None:
        return False, "unknown_signing_key"
    if record.public_key_pem != envelope.public_key_pem:
        return False, "published_key_material_mismatch"
    issued_at = envelope.payload.issued_at
    if issued_at < record.not_before or issued_at >= record.not_after:
        return False, "verdict_outside_key_validity"
    events = sorted(
        [item for item in public_key_bundle.get("events", []) if item["key_id"] == envelope.key_id],
        key=lambda item: int(item["event_id"]),
    )
    effective = [item for item in events if parse_utc_iso(item["effective_at"]) <= issued_at]
    state = record.initial_state if not effective else PublicKeyState(effective[-1]["state"])
    if state is PublicKeyState.COMPROMISED:
        return False, "signing_key_compromised"
    later_compromise = next(
        (
            item
            for item in events
            if PublicKeyState(item["state"]) is PublicKeyState.COMPROMISED
        ),
        None,
    )
    if later_compromise is not None:
        return False, "signing_key_compromised"
    later_revocations = [
        item
        for item in events
        if PublicKeyState(item["state"]) is PublicKeyState.REVOKED
        and parse_utc_iso(item["effective_at"]) <= current
    ]
    if later_revocations and "rotat" not in str(later_revocations[-1]["reason"]).lower():
        return False, "signing_key_revoked"
    try:
        key = serialization.load_pem_public_key(record.public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return False, "signing_key_not_ed25519"
        key.verify(
            base64.b64decode(envelope.signature_b64, validate=True),
            canonical_json(envelope.payload.model_dump(mode="json")).encode("utf-8"),
        )
    except (InvalidSignature, ValueError):
        return False, "invalid_verdict_signature"
    if envelope.payload.signing_key_id != envelope.key_id:
        return False, "verdict_key_id_mismatch"
    if current >= envelope.payload.expires_at:
        return False, "verdict_expired"
    if envelope.payload.lifecycle_state is not VerdictLifecycleState.VALID:
        return False, "verdict_lifecycle_invalid"
    return True, "verified"


def verify_offline_bundle(
    bundle: OfflineVerificationBundle,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    anchor_valid, anchor_reason = verify_anchor_bundle(bundle.anchor_bundle)
    if not anchor_valid:
        return False, f"anchor:{anchor_reason}"
    verdict = bundle.verdict
    receipt = bundle.anchor_bundle.receipt
    if (
        verdict.payload.anchor_receipt_id != receipt.receipt_id
        or verdict.payload.anchor_statement_sha256 != receipt.statement_sha256
        or verdict.payload.evidence_merkle_root != receipt.statement.evidence_merkle_root
    ):
        return False, "verdict_anchor_binding_mismatch"
    return verify_production_verdict(verdict, bundle.public_key_bundle, now=now)
