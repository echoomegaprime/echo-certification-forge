"""P6 deployment enforcement — exact-digest admission, staging-first release, rollback evidence.

This module makes certification MANDATORY in the release process (SPEC section 37):

* ``DeploymentLedger`` — an append-only, hash-chained ledger (same integrity model as the
  evidence chain) recording certification→artifact bindings, every admission decision
  (allowed AND denied), and every deployment outcome, including rollback evidence.
* ``DeploymentAdmissionController`` — the real deployment admission authority. It resolves the
  exact immutable artifact digest to its certifying run, re-evaluates the full ``DeployGate``
  live at admission time (signature trust, verdict, expiry, revocation, evidence integrity,
  environment and policy binding), enforces staging-first acceptance for production, and
  records every decision in the ledger. Fail-closed: an uncertified, mismatched, stale,
  revoked, or untrusted artifact is always denied.

Verdicts remain issued exclusively by the deterministic verdict engine; this layer only
enforces them at the deployment boundary. No private key material is ever present here.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterator

from .canonical import (
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from .deploy_gate import DeployGate
from .evidence import EvidenceStore
from .signing import TrustedPublicKeyRegistry

_ZERO_HASH = "0" * 64

STAGING = "staging"
PRODUCTION = "production"
_ENVIRONMENTS = (STAGING, PRODUCTION)


class DeploymentRecordType(StrEnum):
    BINDING = "BINDING"
    ADMISSION = "ADMISSION"
    OUTCOME = "OUTCOME"


class DeploymentOutcomeStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class BindingError(Exception):
    """Fail-closed refusal to attach a certification binding."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class OutcomeError(Exception):
    """Fail-closed refusal to record a deployment outcome."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _OutcomeReplay(Exception):
    """Internal signal: the exact same outcome operation was already committed.

    Raised UNDER the ledger write lock when a retried submission (same
    ``operation_id`` + identical terminal payload) matches a committed record, so
    the caller can return the committed outcome instead of inserting a duplicate —
    the recovery path for commit-then-response-loss."""

    def __init__(self, record: dict[str, Any]) -> None:
        super().__init__("outcome_operation_replayed")
        self.record = record


def _row_to_record(row: Any) -> dict[str, Any]:
    """Rehydrate a ledger row into the same shape ``DeploymentLedger.append`` returns."""
    return {
        "record_id": row["record_id"],
        "tenant_id": row["tenant_id"],
        "record_type": row["record_type"],
        "admission_id": row["admission_id"],
        "run_id": row["run_id"],
        "artifact_sha256": row["artifact_sha256"],
        "deployment_environment": row["deployment_environment"],
        "allowed": None if row["allowed"] is None else bool(row["allowed"]),
        "payload": json.loads(str(row["payload_json"])),
        "actor": row["actor"],
        "created_at": row["created_at"],
        "record_hash": row["record_hash"],
        "chain_hash": row["chain_hash"],
    }


def normalize_artifact_digest(value: str) -> str:
    """Accept ``sha256:<hex>`` (registry form) or bare hex; return validated bare lowercase hex."""
    candidate = value.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate[len("sha256:"):]
    return require_sha256(candidate, "artifact_sha256")


@dataclass(frozen=True, slots=True)
class AdmissionRequest:
    tenant_id: str
    artifact_sha256: str
    deployment_environment: str
    environment_identity_digest: str
    rule_manifest_digest: str
    deployment_id: str
    requested_by: str

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, "tenant_id")
        require_identifier(self.deployment_id, "deployment_id")
        require_identifier(self.requested_by, "requested_by")
        require_sha256(self.environment_identity_digest, "environment_identity_digest")
        require_sha256(self.rule_manifest_digest, "rule_manifest_digest")
        if self.deployment_environment not in _ENVIRONMENTS:
            raise ValueError("deployment_environment must be staging or production")


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    admission_id: str
    allowed: bool
    reasons: tuple[str, ...]
    tenant_id: str
    run_id: str | None
    artifact_sha256: str
    deployment_environment: str
    deployment_id: str
    chain_hash: str
    created_at: str
    rollback_candidate: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "admission_id": self.admission_id,
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "artifact_sha256": self.artifact_sha256,
            "deployment_environment": self.deployment_environment,
            "deployment_id": self.deployment_id,
            "chain_hash": self.chain_hash,
            "created_at": self.created_at,
            "rollback_candidate": self.rollback_candidate,
        }


class DeploymentLedger:
    """Append-only, hash-chained deployment enforcement ledger.

    Every row carries ``record_hash`` (canonical hash of the descriptor) and
    ``chain_hash = H(prev_chain_hash || record_hash)``; SQLite triggers forbid UPDATE and
    DELETE so history cannot be silently rewritten. ``verify_chain`` recomputes the whole
    chain and reports the first broken ordinal, providing the P6 auditability proof.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30.0)
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
        schema = """
        CREATE TABLE IF NOT EXISTS deployment_records (
            ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT NOT NULL UNIQUE,
            tenant_id TEXT NOT NULL,
            record_type TEXT NOT NULL,
            admission_id TEXT,
            run_id TEXT,
            artifact_sha256 TEXT,
            deployment_environment TEXT,
            allowed INTEGER,
            payload_json TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            prev_chain_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_deployment_tenant_artifact
            ON deployment_records(tenant_id, artifact_sha256, ordinal);
        CREATE INDEX IF NOT EXISTS idx_deployment_admission
            ON deployment_records(admission_id, ordinal);
        CREATE TRIGGER IF NOT EXISTS no_update_deployment_records
            BEFORE UPDATE ON deployment_records
        BEGIN SELECT RAISE(ABORT, 'deployment_records are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_deployment_records
            BEFORE DELETE ON deployment_records
        BEGIN SELECT RAISE(ABORT, 'deployment_records are append-only'); END;
        -- Deployment-credential replay protection. Lives in the SAME SQLite file as the
        -- ledger so nonce consumption is shared by every worker process and survives
        -- restarts. Deliberately NOT append-only: expired nonces are pruned.
        CREATE TABLE IF NOT EXISTS deployment_credential_nonces (
            tenant_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, nonce)
        );
        """
        with self._connection() as connection:
            connection.executescript(schema)

    def consume_nonce(self, tenant_id: str, nonce: str, ttl_seconds: float) -> bool:
        """Atomically consume a deployment-credential nonce; return False on replay.

        The INSERT under ``BEGIN IMMEDIATE`` is the atomic first-use claim: two racing
        requests presenting the same ``(tenant_id, nonce)`` cannot both win — the loser
        hits the primary key and the request is rejected. Persistence in the ledger's
        SQLite file makes the rejection hold across workers and service restarts for at
        least ``ttl_seconds`` (which must exceed the signature timestamp window, so an
        expired-then-pruned nonce can no longer be replayed anyway). Expired rows are
        pruned opportunistically inside the same transaction.
        """
        require_identifier(tenant_id, "tenant_id")
        now = utc_now()
        connection = self._connect()
        try:
            connection.isolation_level = None
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "DELETE FROM deployment_credential_nonces WHERE expires_at < ?",
                    (to_utc_iso(now),),
                )
                try:
                    connection.execute(
                        "INSERT INTO deployment_credential_nonces"
                        " (tenant_id, nonce, expires_at, created_at) VALUES (?, ?, ?, ?)",
                        (
                            tenant_id,
                            nonce,
                            to_utc_iso(now + timedelta(seconds=ttl_seconds)),
                            to_utc_iso(now),
                        ),
                    )
                except sqlite3.IntegrityError:
                    connection.execute("COMMIT")
                    return False
                connection.execute("COMMIT")
                return True
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

    def append(
        self,
        record_type: DeploymentRecordType,
        tenant_id: str,
        payload: dict[str, Any],
        actor: str,
        *,
        admission_id: str | None = None,
        run_id: str | None = None,
        artifact_sha256: str | None = None,
        deployment_environment: str | None = None,
        allowed: bool | None = None,
        precondition: Callable[[sqlite3.Connection], None] | None = None,
    ) -> dict[str, Any]:
        require_identifier(tenant_id, "tenant_id")
        require_identifier(actor, "actor")
        record_id = f"dep-{secrets.token_hex(16)}"
        created_at = to_utc_iso(utc_now())
        connection = self._connect()
        try:
            # Serialize appends: take the write lock BEFORE reading the chain tip so two
            # concurrent appends can never observe the same tip and fork the hash chain.
            connection.isolation_level = None
            connection.execute("BEGIN IMMEDIATE")
            try:
                if precondition is not None:
                    # Validated UNDER the write lock: state-transition checks (e.g. "no
                    # terminal outcome exists yet for this admission") are atomic with the
                    # insert — two racing writers cannot both pass the check.
                    precondition(connection)
                previous = connection.execute(
                    "SELECT ordinal, chain_hash FROM deployment_records ORDER BY ordinal DESC LIMIT 1"
                ).fetchone()
                prev_chain_hash = _ZERO_HASH if previous is None else str(previous["chain_hash"])
                descriptor = {
                    "record_id": record_id,
                    "tenant_id": tenant_id,
                    "record_type": record_type.value,
                    "admission_id": admission_id,
                    "run_id": run_id,
                    "artifact_sha256": artifact_sha256,
                    "deployment_environment": deployment_environment,
                    "allowed": allowed,
                    "payload": payload,
                    "actor": actor,
                    "created_at": created_at,
                }
                record_hash = sha256_json(descriptor)
                chain_hash = sha256_bytes(bytes.fromhex(prev_chain_hash) + bytes.fromhex(record_hash))
                connection.execute(
                    """
                    INSERT INTO deployment_records(
                        record_id, tenant_id, record_type, admission_id, run_id, artifact_sha256,
                        deployment_environment, allowed, payload_json, actor, created_at,
                        record_hash, prev_chain_hash, chain_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id, tenant_id, record_type.value, admission_id, run_id, artifact_sha256,
                        deployment_environment,
                        None if allowed is None else int(allowed),
                        json.dumps(payload, sort_keys=True), actor, created_at,
                        record_hash, prev_chain_hash, chain_hash,
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return {**descriptor, "record_hash": record_hash, "chain_hash": chain_hash}

    def _rows(self, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(sql, args).fetchall()]

    def find_bindings(self, tenant_id: str, artifact_sha256: str) -> list[dict[str, Any]]:
        """Every BINDING for the artifact, newest-first — admission selects the first one
        that is still valid under the ACTIVE manifest instead of trusting ordinal order."""
        return self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND artifact_sha256 = ?"
            " AND record_type = ? ORDER BY ordinal DESC",
            (tenant_id, artifact_sha256, DeploymentRecordType.BINDING.value),
        )

    def find_binding_for_run(
        self, tenant_id: str, run_id: str, artifact_sha256: str
    ) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND run_id = ?"
            " AND artifact_sha256 = ? AND record_type = ? ORDER BY ordinal DESC LIMIT 1",
            (tenant_id, run_id, artifact_sha256, DeploymentRecordType.BINDING.value),
        )
        return rows[0] if rows else None

    def find_admission(self, admission_id: str, tenant_id: str) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE record_id = ? AND tenant_id = ?"
            " AND record_type = ? LIMIT 1",
            (admission_id, tenant_id, DeploymentRecordType.ADMISSION.value),
        )
        return rows[0] if rows else None

    def first_outcome(self, admission_id: str, tenant_id: str) -> dict[str, Any] | None:
        """The FIRST recorded outcome for an admission — the authoritative terminal one.

        Outcome transitions are enforced atomically at write time (``report_outcome``), so
        the first outcome is immutable: a later contradictory record (e.g. FAILED followed
        by SUCCEEDED) can never exist. Reading the first record — never the latest — means
        even a hypothetical extra row could not flip a decision that reads this."""
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE admission_id = ? AND tenant_id = ?"
            " AND record_type = ? ORDER BY ordinal ASC LIMIT 1",
            (admission_id, tenant_id, DeploymentRecordType.OUTCOME.value),
        )
        return rows[0] if rows else None

    def outcomes(self, admission_id: str, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE admission_id = ? AND tenant_id = ?"
            " AND record_type = ? ORDER BY ordinal ASC",
            (admission_id, tenant_id, DeploymentRecordType.OUTCOME.value),
        )
        return rows

    def staging_accepted(self, tenant_id: str, artifact_sha256: str, run_id: str) -> bool:
        """True when an ALLOWED staging admission for this exact artifact digest AND certifying
        run has its ONE immutable outcome recorded as SUCCEEDED. A failed or missing staging
        deployment never unlocks production, and a success can never be forged after the fact:
        once any terminal outcome exists for an admission, contradictory transitions
        (especially FAILED -> SUCCEEDED) are rejected atomically at write time."""
        admissions = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND artifact_sha256 = ?"
            " AND run_id = ? AND record_type = ? AND deployment_environment = ? AND allowed = 1"
            " ORDER BY ordinal DESC",
            (tenant_id, artifact_sha256, run_id, DeploymentRecordType.ADMISSION.value, STAGING),
        )
        for admission in admissions:
            outcome = self.first_outcome(str(admission["record_id"]), tenant_id)
            if outcome is not None:
                payload = json.loads(str(outcome["payload_json"]))
                if payload.get("status") == DeploymentOutcomeStatus.SUCCEEDED.value:
                    return True
        return False

    def good_production_admissions(self, tenant_id: str) -> list[dict[str, Any]]:
        """Allowed production admissions whose one immutable outcome is SUCCEEDED, newest first."""
        admissions = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND record_type = ?"
            " AND deployment_environment = ? AND allowed = 1 ORDER BY ordinal DESC",
            (tenant_id, DeploymentRecordType.ADMISSION.value, PRODUCTION),
        )
        good: list[dict[str, Any]] = []
        for admission in admissions:
            outcome = self.first_outcome(str(admission["record_id"]), tenant_id)
            if outcome is None:
                continue
            payload = json.loads(str(outcome["payload_json"]))
            if payload.get("status") == DeploymentOutcomeStatus.SUCCEEDED.value:
                good.append(admission)
        return good

    def trail(self, tenant_id: str, artifact_sha256: str | None = None) -> list[dict[str, Any]]:
        if artifact_sha256 is None:
            rows = self._rows(
                "SELECT * FROM deployment_records WHERE tenant_id = ? ORDER BY ordinal",
                (tenant_id,),
            )
        else:
            rows = self._rows(
                "SELECT * FROM deployment_records WHERE tenant_id = ? AND artifact_sha256 = ?"
                " ORDER BY ordinal",
                (tenant_id, artifact_sha256),
            )
        return rows

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recompute every record hash and the chain; return (valid, first_broken_ordinal)."""
        rows = self._rows("SELECT * FROM deployment_records ORDER BY ordinal", ())
        prev_chain_hash = _ZERO_HASH
        for row in rows:
            descriptor = {
                "record_id": row["record_id"],
                "tenant_id": row["tenant_id"],
                "record_type": row["record_type"],
                "admission_id": row["admission_id"],
                "run_id": row["run_id"],
                "artifact_sha256": row["artifact_sha256"],
                "deployment_environment": row["deployment_environment"],
                "allowed": None if row["allowed"] is None else bool(row["allowed"]),
                "payload": json.loads(str(row["payload_json"])),
                "actor": row["actor"],
                "created_at": row["created_at"],
            }
            record_hash = sha256_json(descriptor)
            if record_hash != str(row["record_hash"]):
                return False, int(row["ordinal"])
            expected_chain = sha256_bytes(
                bytes.fromhex(prev_chain_hash) + bytes.fromhex(record_hash)
            )
            if expected_chain != str(row["chain_hash"]) or str(row["prev_chain_hash"]) != prev_chain_hash:
                return False, int(row["ordinal"])
            prev_chain_hash = expected_chain
        return True, None


class DeploymentAdmissionController:
    """The deployment admission authority: certification is mandatory to deploy."""

    def __init__(
        self,
        store: EvidenceStore,
        trusted_keys: TrustedPublicKeyRegistry,
        ledger: DeploymentLedger,
        active_rule_manifest_digest: str,
    ) -> None:
        self.store = store
        self.trusted_keys = trusted_keys
        self.ledger = ledger
        # The controller is bound to the ACTIVE mandatory-rule manifest at construction:
        # callers can never substitute a stale/rolled-over policy digest at admission time.
        self.active_rule_manifest_digest = require_sha256(
            active_rule_manifest_digest, "active_rule_manifest_digest"
        )
        self._gate = DeployGate(store, trusted_keys)

    # -- certification binding -------------------------------------------------------------

    def bind_certification(self, run_id: str, tenant_id: str, actor: str) -> dict[str, Any]:
        """Attach the run's certification to its exact immutable artifact digest and commit.

        The binding is derived exclusively from the server-side run record — never from
        caller input — and requires a signed verdict to exist (a run without a signed
        verdict has no certification to attach) AND the run to be certified under the
        CURRENTLY ACTIVE rule manifest. Idempotent per (tenant, run, digest).
        """
        row = self.store.get_run(run_id, tenant_id)  # KeyError -> not found (tenant-scoped)
        verdict_row = self.store.latest_signed_verdict(run_id, tenant_id)
        if verdict_row is None:
            raise BindingError("signed_verdict_missing")
        if str(row["rule_manifest_digest"]) != self.active_rule_manifest_digest:
            # A certification issued under a superseded (or unknown) policy must never gain
            # a binding after rollover — stale runs are recertified, never rebound. This
            # closes the shadowing window where a late stale binding could outrank a valid
            # one purely by ledger ordinal.
            raise BindingError("rule_manifest_not_active")
        target_identity = json.loads(str(row["target_identity_json"]))
        artifact_raw = target_identity.get("artifact_sha256")
        if not isinstance(artifact_raw, str) or not artifact_raw:
            raise BindingError("target_artifact_digest_missing")
        artifact_sha256 = normalize_artifact_digest(artifact_raw)
        existing = self.ledger.find_binding_for_run(tenant_id, run_id, artifact_sha256)
        if existing is not None:
            return {**existing, "created": False, "payload": json.loads(str(existing["payload_json"]))}
        payload = {
            "artifact_sha256": artifact_sha256,
            "source_commit": target_identity.get("source_commit"),
            "target_identity_digest": str(row["target_identity_digest"]),
            "environment_identity_digest": str(row["environment_identity_digest"]),
            "rule_manifest_digest": str(row["rule_manifest_digest"]),
            "verdict_payload_sha256": str(verdict_row["payload_sha256"]),
            "verdict_key_id": str(verdict_row["key_id"]),
        }
        record = self.ledger.append(
            DeploymentRecordType.BINDING,
            tenant_id,
            payload,
            actor,
            run_id=run_id,
            artifact_sha256=artifact_sha256,
        )
        return {**record, "created": True}

    # -- admission --------------------------------------------------------------------------

    def admit(self, request: AdmissionRequest, actor: str) -> AdmissionDecision:
        """Evaluate and RECORD a deployment admission. Fail-closed on every path."""
        artifact_sha256 = normalize_artifact_digest(request.artifact_sha256)
        reasons: list[str] = []
        run_id: str | None = None
        gate_reasons: tuple[str, ...] = ()

        if request.rule_manifest_digest != self.active_rule_manifest_digest:
            # A caller pinning anything other than the ACTIVE mandatory manifest (stale
            # pre-rollover digest, unknown digest) is denied outright — fail-closed.
            reasons.append("rule_manifest_not_active")

        bindings = self.ledger.find_bindings(request.tenant_id, artifact_sha256)
        if not bindings:
            reasons.append("artifact_not_certified")
        else:
            selected: tuple[str, list[str], tuple[str, ...]] | None = None
            newest: tuple[str, list[str], tuple[str, ...]] | None = None
            for binding in bindings:
                candidate_run_id = str(binding["run_id"])
                binding_reasons: list[str] = []
                binding_gate: tuple[str, ...] = ()
                try:
                    run_row = self.store.get_run(candidate_run_id, request.tenant_id)
                except KeyError:
                    run_row = None
                    binding_reasons.append("certification_record_missing")
                if run_row is not None:
                    # Defense in depth: re-derive the artifact digest from the immutable run
                    # record; a ledger row that disagrees with the run identity never admits.
                    target_identity = json.loads(str(run_row["target_identity_json"]))
                    stored_artifact = target_identity.get("artifact_sha256")
                    if (
                        not isinstance(stored_artifact, str)
                        or normalize_artifact_digest(stored_artifact) != artifact_sha256
                    ):
                        binding_reasons.append("artifact_digest_mismatch")
                    else:
                        gate_decision = self._gate.evaluate(
                            tenant_id=request.tenant_id,
                            run_id=candidate_run_id,
                            target_identity_digest=str(run_row["target_identity_digest"]),
                            environment_identity_digest=request.environment_identity_digest,
                            # The gate always evaluates against the ACTIVE manifest digest,
                            # never a caller-supplied one: a certification issued under a
                            # superseded policy fails with rule_manifest_mismatch.
                            rule_manifest_digest=self.active_rule_manifest_digest,
                        )
                        binding_gate = gate_decision.reasons
                        if not gate_decision.allowed:
                            binding_reasons.extend(gate_decision.reasons)
                if newest is None:
                    newest = (candidate_run_id, binding_reasons, binding_gate)
                if not binding_reasons:
                    # Select the first binding (newest-first) that is CURRENTLY valid under
                    # the active manifest — a stale legacy binding recorded later can never
                    # shadow a valid certification purely by ledger ordinal.
                    selected = (candidate_run_id, binding_reasons, binding_gate)
                    break
            chosen = selected if selected is not None else newest
            if chosen is not None:
                run_id = chosen[0]
                reasons.extend(chosen[1])
                gate_reasons = chosen[2]

        if request.deployment_environment == PRODUCTION and run_id is not None and not reasons:
            if not self.ledger.staging_accepted(request.tenant_id, artifact_sha256, run_id):
                reasons.append("staging_acceptance_missing")
        elif request.deployment_environment == PRODUCTION and reasons:
            # Still surface the staging state on denied production attempts for auditability.
            if run_id is None or not self.ledger.staging_accepted(
                request.tenant_id, artifact_sha256, run_id
            ):
                reasons.append("staging_acceptance_missing")

        allowed = not reasons
        rollback_candidate: dict[str, Any] | None = None
        if request.deployment_environment == PRODUCTION:
            # Freeze the exact rollback target NOW — before any deployment can begin — so
            # concurrent deployments succeeding between admission and a later failure can
            # never drift what this admission is allowed to roll back to.
            rollback_candidate = self.rollback_target(request.tenant_id)
        payload = {
            "artifact_sha256": artifact_sha256,
            "deployment_environment": request.deployment_environment,
            "deployment_id": request.deployment_id,
            "requested_by": request.requested_by,
            "environment_identity_digest": request.environment_identity_digest,
            "rule_manifest_digest": request.rule_manifest_digest,
            "run_id": run_id,
            "allowed": allowed,
            "reasons": sorted(set(reasons)) if reasons else ["exact_certification_valid"],
            "gate_reasons": list(gate_reasons),
        }
        if request.deployment_environment == PRODUCTION:
            payload["rollback_candidate"] = rollback_candidate
        record = self.ledger.append(
            DeploymentRecordType.ADMISSION,
            request.tenant_id,
            payload,
            actor,
            run_id=run_id,
            artifact_sha256=artifact_sha256,
            deployment_environment=request.deployment_environment,
            allowed=allowed,
        )
        return AdmissionDecision(
            admission_id=str(record["record_id"]),
            allowed=allowed,
            reasons=tuple(payload["reasons"]),
            tenant_id=request.tenant_id,
            run_id=run_id,
            artifact_sha256=artifact_sha256,
            deployment_environment=request.deployment_environment,
            deployment_id=request.deployment_id,
            chain_hash=str(record["chain_hash"]),
            created_at=str(record["created_at"]),
            rollback_candidate=rollback_candidate,
        )

    # -- outcomes and rollback evidence ------------------------------------------------------

    def report_outcome(
        self,
        admission_id: str,
        tenant_id: str,
        status: DeploymentOutcomeStatus,
        detail: str,
        actor: str,
        rollback_to: str | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Record the real deployment outcome for an ALLOWED admission (append-only).

        Terminal-transition enforcement (validated ATOMICALLY under the ledger write lock,
        so two racing writers can never both record):

        * ``SUCCEEDED`` / ``FAILED`` are terminal — once ANY outcome exists for the
          admission, a later contradictory or repeated transition (especially
          FAILED -> SUCCEEDED) is rejected with ``outcome_already_terminal``.
        * ``ROLLED_BACK`` is only valid as the single follow-up to a FAILED PRODUCTION
          outcome on the same admission, and its ``rollback_to`` digest must EXACTLY match
          the rollback candidate that was FROZEN INTO THE ADMISSION RECORD before the
          deployment began — concurrent deployment activity after admission can never
          drift the accepted rollback target.

        Idempotent recovery (commit-then-response-loss): when the caller supplies an
        ``operation_id``, it is persisted in the outcome payload (and therefore covered by
        the caller's request signature via the body hash). An EXACT retry — same
        ``operation_id``, same status, detail and ``rollback_to`` — returns the already
        committed record (``replayed: True``) instead of ``outcome_already_terminal``, so a
        client whose response was lost after the commit can recover the recorded outcome
        (including the bound rollback candidate). A reused ``operation_id`` carrying ANY
        different payload is rejected with ``outcome_operation_conflict``; submissions
        without an ``operation_id`` keep the strict terminal behavior.

        A FAILED production outcome persists the rollback candidate that the ADMISSION
        froze before deployment started (never recomputed at failure time); that frozen
        digest is the only digest a subsequent ``ROLLED_BACK`` may name.
        """
        admission = self.ledger.find_admission(admission_id, tenant_id)
        if admission is None:
            raise KeyError("admission not found")
        if not admission["allowed"]:
            raise OutcomeError("outcome_on_denied_admission")
        admission_payload: dict[str, Any] = json.loads(str(admission["payload_json"]))
        normalized_rollback: str | None = None
        if status is DeploymentOutcomeStatus.ROLLED_BACK:
            if rollback_to is None:
                raise OutcomeError("rollback_target_required")
            normalized_rollback = normalize_artifact_digest(rollback_to)
            if admission["deployment_environment"] != PRODUCTION:
                # Rollback evidence only exists for production; a staging admission can
                # never carry a ROLLED_BACK outcome.
                raise OutcomeError("rollback_requires_failed_production")
        elif rollback_to is not None:
            normalized_rollback = normalize_artifact_digest(rollback_to)
        payload: dict[str, Any] = {
            "status": status.value,
            "detail": detail,
            "admission_id": admission_id,
            "artifact_sha256": admission["artifact_sha256"],
            "deployment_environment": admission["deployment_environment"],
            "rollback_to": normalized_rollback,
            "operation_id": operation_id,
        }
        if (
            status is DeploymentOutcomeStatus.FAILED
            and admission["deployment_environment"] == PRODUCTION
        ):
            # Copy the candidate FROZEN at admission time — never recomputed here, so
            # deployments that succeeded between admission and this failure cannot drift
            # the rollback target this admission is bound to.
            payload["rollback_candidate"] = admission_payload.get("rollback_candidate")

        def _validate_transition(connection: sqlite3.Connection) -> None:
            rows = connection.execute(
                "SELECT * FROM deployment_records WHERE admission_id = ?"
                " AND tenant_id = ? AND record_type = ? ORDER BY ordinal ASC",
                (admission_id, tenant_id, DeploymentRecordType.OUTCOME.value),
            ).fetchall()
            existing = [json.loads(str(row["payload_json"])) for row in rows]
            if operation_id is not None:
                for row, entry in zip(rows, existing):
                    if entry.get("operation_id") != operation_id:
                        continue
                    same_operation = (
                        entry.get("status") == status.value
                        and entry.get("detail") == detail
                        and entry.get("rollback_to") == normalized_rollback
                    )
                    if not same_operation:
                        # The operation id is bound to ONE exact terminal payload — a
                        # reused id carrying anything different is a conflict, never a
                        # silent dedup to a stale outcome.
                        raise OutcomeError("outcome_operation_conflict")
                    raise _OutcomeReplay(_row_to_record(row))
            statuses = [entry.get("status") for entry in existing]
            if status is not DeploymentOutcomeStatus.ROLLED_BACK:
                if statuses:
                    # SUCCEEDED/FAILED after ANY terminal outcome — including the forgery
                    # FAILED -> SUCCEEDED and simple repeats — is rejected outright.
                    raise OutcomeError("outcome_already_terminal")
                return
            if (
                DeploymentOutcomeStatus.ROLLED_BACK.value in statuses
                or DeploymentOutcomeStatus.SUCCEEDED.value in statuses
            ):
                raise OutcomeError("outcome_already_terminal")
            failed = [
                entry
                for entry in existing
                if entry.get("status") == DeploymentOutcomeStatus.FAILED.value
            ]
            if not failed:
                raise OutcomeError("rollback_requires_failed_production")
            # Validate against the ADMISSION-frozen candidate (the FAILED record carries a
            # verbatim copy, so both views agree; the admission record is authoritative).
            bound = admission_payload.get("rollback_candidate") or {}
            bound_digest = bound.get("artifact_sha256")
            if not isinstance(bound_digest, str) or not bound_digest:
                # The admission bound no last-known-good candidate: there is nothing a
                # rollback can be verified against — fail closed.
                raise OutcomeError("rollback_candidate_missing")
            if normalized_rollback != bound_digest:
                raise OutcomeError("rollback_target_mismatch")

        try:
            record = self.ledger.append(
                DeploymentRecordType.OUTCOME,
                tenant_id,
                payload,
                actor,
                admission_id=admission_id,
                run_id=admission["run_id"],
                artifact_sha256=admission["artifact_sha256"],
                deployment_environment=admission["deployment_environment"],
                precondition=_validate_transition,
            )
        except _OutcomeReplay as replay:
            return {**replay.record, "replayed": True}
        return {**record, "replayed": False}

    def rollback_target(self, tenant_id: str) -> dict[str, Any] | None:
        """Last-known-good production artifact whose certification is STILL valid right now.

        Scans succeeded production admissions newest-first and re-runs the deploy gate with
        the environment digest each admission was granted under and the CURRENTLY ACTIVE
        rule manifest digest; a since-revoked, expired, or policy-rolled-over certification
        is never offered as a rollback target (fail-closed)."""
        for admission in self.ledger.good_production_admissions(tenant_id):
            run_id = admission["run_id"]
            if run_id is None:
                continue
            payload = json.loads(str(admission["payload_json"]))
            try:
                run_row = self.store.get_run(str(run_id), tenant_id)
                gate_decision = self._gate.evaluate(
                    tenant_id=tenant_id,
                    run_id=str(run_id),
                    target_identity_digest=str(run_row["target_identity_digest"]),
                    environment_identity_digest=str(payload["environment_identity_digest"]),
                    rule_manifest_digest=self.active_rule_manifest_digest,
                )
            except KeyError:
                continue
            if gate_decision.allowed:
                return {
                    "artifact_sha256": admission["artifact_sha256"],
                    "run_id": run_id,
                    "admission_id": admission["record_id"],
                    "deployment_id": payload.get("deployment_id"),
                    "admitted_at": admission["created_at"],
                }
        return None

    # -- release status checks ---------------------------------------------------------------

    def release_status(
        self,
        tenant_id: str,
        artifact_sha256: str,
        environment_identity_digest: str | None = None,
        rule_manifest_digest: str | None = None,
    ) -> dict[str, Any]:
        """Read-only release status check for CI (writes nothing). The gate is always
        evaluated against the ACTIVE rule manifest digest; a caller-supplied stale policy
        digest is reported as not-active and can never make the release admissible."""
        digest = normalize_artifact_digest(artifact_sha256)
        bindings = self.ledger.find_bindings(tenant_id, digest)
        status: dict[str, Any] = {
            "artifact_sha256": digest,
            "certified": False,
            "run_id": None,
            "gate_allowed": False,
            "reasons": ["artifact_not_certified"],
            "staging_accepted": False,
            "production_admissible": False,
        }
        if not bindings:
            return status
        extra_reasons: list[str] = []
        if rule_manifest_digest is not None and rule_manifest_digest != self.active_rule_manifest_digest:
            extra_reasons.append("rule_manifest_not_active")
        evaluated: list[tuple[str, Any]] = []
        chosen: tuple[str, Any] | None = None
        for binding in bindings:
            candidate_run_id = str(binding["run_id"])
            binding_payload = json.loads(str(binding["payload_json"]))
            env_digest = environment_identity_digest or str(
                binding_payload["environment_identity_digest"]
            )
            try:
                run_row = self.store.get_run(candidate_run_id, tenant_id)
            except KeyError:
                evaluated.append((candidate_run_id, None))
                continue
            gate_decision = self._gate.evaluate(
                tenant_id=tenant_id,
                run_id=candidate_run_id,
                target_identity_digest=str(run_row["target_identity_digest"]),
                environment_identity_digest=env_digest,
                rule_manifest_digest=self.active_rule_manifest_digest,
            )
            evaluated.append((candidate_run_id, gate_decision))
            if gate_decision.allowed:
                # Same selection rule as admission: the first (newest-first) binding that
                # is valid under the ACTIVE manifest, never blindly the newest ordinal.
                chosen = (candidate_run_id, gate_decision)
                break
        if chosen is None:
            run_id, gate_decision = evaluated[0]
            if gate_decision is None:
                status["reasons"] = ["certification_record_missing"]
                return status
        else:
            run_id, gate_decision = chosen
        gate_allowed = gate_decision.allowed and not extra_reasons
        staging_ok = self.ledger.staging_accepted(tenant_id, digest, run_id)
        status.update(
            {
                "certified": True,
                "run_id": run_id,
                "gate_allowed": gate_allowed,
                "reasons": sorted(set(extra_reasons + list(gate_decision.reasons))),
                "staging_accepted": staging_ok,
                "production_admissible": gate_allowed and staging_ok,
            }
        )
        return status
