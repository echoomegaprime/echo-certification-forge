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
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator

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
        connection = sqlite3.connect(self.db_path)
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
        """
        with self._connection() as connection:
            connection.executescript(schema)

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
    ) -> dict[str, Any]:
        require_identifier(tenant_id, "tenant_id")
        require_identifier(actor, "actor")
        record_id = f"dep-{secrets.token_hex(16)}"
        created_at = to_utc_iso(utc_now())
        with self._connection() as connection:
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
        return {**descriptor, "record_hash": record_hash, "chain_hash": chain_hash}

    def _rows(self, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(sql, args).fetchall()]

    def find_binding(self, tenant_id: str, artifact_sha256: str) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND artifact_sha256 = ?"
            " AND record_type = ? ORDER BY ordinal DESC LIMIT 1",
            (tenant_id, artifact_sha256, DeploymentRecordType.BINDING.value),
        )
        return rows[0] if rows else None

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

    def latest_outcome(self, admission_id: str, tenant_id: str) -> dict[str, Any] | None:
        rows = self._rows(
            "SELECT * FROM deployment_records WHERE admission_id = ? AND tenant_id = ?"
            " AND record_type = ? ORDER BY ordinal DESC LIMIT 1",
            (admission_id, tenant_id, DeploymentRecordType.OUTCOME.value),
        )
        return rows[0] if rows else None

    def staging_accepted(self, tenant_id: str, artifact_sha256: str, run_id: str) -> bool:
        """True when an ALLOWED staging admission for this exact artifact digest AND certifying
        run has a latest outcome of SUCCEEDED. A failed or missing staging deployment never
        unlocks production."""
        admissions = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND artifact_sha256 = ?"
            " AND run_id = ? AND record_type = ? AND deployment_environment = ? AND allowed = 1"
            " ORDER BY ordinal DESC",
            (tenant_id, artifact_sha256, run_id, DeploymentRecordType.ADMISSION.value, STAGING),
        )
        for admission in admissions:
            outcome = self.latest_outcome(str(admission["record_id"]), tenant_id)
            if outcome is not None:
                payload = json.loads(str(outcome["payload_json"]))
                if payload.get("status") == DeploymentOutcomeStatus.SUCCEEDED.value:
                    return True
        return False

    def good_production_admissions(self, tenant_id: str) -> list[dict[str, Any]]:
        """Allowed production admissions whose latest outcome is SUCCEEDED, newest first."""
        admissions = self._rows(
            "SELECT * FROM deployment_records WHERE tenant_id = ? AND record_type = ?"
            " AND deployment_environment = ? AND allowed = 1 ORDER BY ordinal DESC",
            (tenant_id, DeploymentRecordType.ADMISSION.value, PRODUCTION),
        )
        good: list[dict[str, Any]] = []
        for admission in admissions:
            outcome = self.latest_outcome(str(admission["record_id"]), tenant_id)
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
    ) -> None:
        self.store = store
        self.trusted_keys = trusted_keys
        self.ledger = ledger
        self._gate = DeployGate(store, trusted_keys)

    # -- certification binding -------------------------------------------------------------

    def bind_certification(self, run_id: str, tenant_id: str, actor: str) -> dict[str, Any]:
        """Attach the run's certification to its exact immutable artifact digest and commit.

        The binding is derived exclusively from the server-side run record — never from
        caller input — and requires a signed verdict to exist (a run without a signed
        verdict has no certification to attach). Idempotent per (tenant, run, digest).
        """
        row = self.store.get_run(run_id, tenant_id)  # KeyError -> not found (tenant-scoped)
        verdict_row = self.store.latest_signed_verdict(run_id, tenant_id)
        if verdict_row is None:
            raise BindingError("signed_verdict_missing")
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

        binding = self.ledger.find_binding(request.tenant_id, artifact_sha256)
        if binding is None:
            reasons.append("artifact_not_certified")
        else:
            run_id = str(binding["run_id"])
            try:
                run_row = self.store.get_run(run_id, request.tenant_id)
            except KeyError:
                run_row = None
                reasons.append("certification_record_missing")
            if run_row is not None:
                # Defense in depth: re-derive the artifact digest from the immutable run
                # record; a ledger row that disagrees with the run identity never admits.
                target_identity = json.loads(str(run_row["target_identity_json"]))
                stored_artifact = target_identity.get("artifact_sha256")
                if (
                    not isinstance(stored_artifact, str)
                    or normalize_artifact_digest(stored_artifact) != artifact_sha256
                ):
                    reasons.append("artifact_digest_mismatch")
                else:
                    gate_decision = self._gate.evaluate(
                        tenant_id=request.tenant_id,
                        run_id=run_id,
                        target_identity_digest=str(run_row["target_identity_digest"]),
                        environment_identity_digest=request.environment_identity_digest,
                        rule_manifest_digest=request.rule_manifest_digest,
                    )
                    gate_reasons = gate_decision.reasons
                    if not gate_decision.allowed:
                        reasons.extend(gate_decision.reasons)

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
    ) -> dict[str, Any]:
        """Record the real deployment outcome for an ALLOWED admission (append-only).

        ``ROLLED_BACK`` requires ``rollback_to`` — the exact digest that was restored —
        which is the durable rollback evidence. A FAILED production outcome includes the
        current last-known-good rollback candidate in the recorded payload.
        """
        admission = self.ledger.find_admission(admission_id, tenant_id)
        if admission is None:
            raise KeyError("admission not found")
        if not admission["allowed"]:
            raise OutcomeError("outcome_on_denied_admission")
        normalized_rollback: str | None = None
        if status is DeploymentOutcomeStatus.ROLLED_BACK:
            if rollback_to is None:
                raise OutcomeError("rollback_target_required")
            normalized_rollback = normalize_artifact_digest(rollback_to)
        elif rollback_to is not None:
            normalized_rollback = normalize_artifact_digest(rollback_to)
        payload: dict[str, Any] = {
            "status": status.value,
            "detail": detail,
            "admission_id": admission_id,
            "artifact_sha256": admission["artifact_sha256"],
            "deployment_environment": admission["deployment_environment"],
            "rollback_to": normalized_rollback,
        }
        if (
            status is DeploymentOutcomeStatus.FAILED
            and admission["deployment_environment"] == PRODUCTION
        ):
            candidate = self.rollback_target(tenant_id)
            payload["rollback_candidate"] = candidate
        record = self.ledger.append(
            DeploymentRecordType.OUTCOME,
            tenant_id,
            payload,
            actor,
            admission_id=admission_id,
            run_id=admission["run_id"],
            artifact_sha256=admission["artifact_sha256"],
            deployment_environment=admission["deployment_environment"],
        )
        return {**record}

    def rollback_target(self, tenant_id: str) -> dict[str, Any] | None:
        """Last-known-good production artifact whose certification is STILL valid right now.

        Scans succeeded production admissions newest-first and re-runs the deploy gate with
        the digests each admission was granted under; a since-revoked or expired
        certification is never offered as a rollback target (fail-closed)."""
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
                    rule_manifest_digest=str(payload["rule_manifest_digest"]),
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
        """Read-only release status check for CI (writes nothing). When the required release
        digests are not supplied, the certification's own bound digests are used."""
        digest = normalize_artifact_digest(artifact_sha256)
        binding = self.ledger.find_binding(tenant_id, digest)
        status: dict[str, Any] = {
            "artifact_sha256": digest,
            "certified": False,
            "run_id": None,
            "gate_allowed": False,
            "reasons": ["artifact_not_certified"],
            "staging_accepted": False,
            "production_admissible": False,
        }
        if binding is None:
            return status
        run_id = str(binding["run_id"])
        binding_payload = json.loads(str(binding["payload_json"]))
        env_digest = environment_identity_digest or str(binding_payload["environment_identity_digest"])
        rule_digest = rule_manifest_digest or str(binding_payload["rule_manifest_digest"])
        try:
            run_row = self.store.get_run(run_id, tenant_id)
        except KeyError:
            status["reasons"] = ["certification_record_missing"]
            return status
        gate_decision = self._gate.evaluate(
            tenant_id=tenant_id,
            run_id=run_id,
            target_identity_digest=str(run_row["target_identity_digest"]),
            environment_identity_digest=env_digest,
            rule_manifest_digest=rule_digest,
        )
        staging_ok = self.ledger.staging_accepted(tenant_id, digest, run_id)
        status.update(
            {
                "certified": True,
                "run_id": run_id,
                "gate_allowed": gate_decision.allowed,
                "reasons": list(gate_decision.reasons),
                "staging_accepted": staging_ok,
                "production_admissible": gate_decision.allowed and staging_ok,
            }
        )
        return status
