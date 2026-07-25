"""Durable tenant-scoped evidence store with append-only chain and Merkle verification."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Iterable

from .canonical import (
    canonical_json,
    contained_path,
    require_identifier,
    require_sha256,
    sha256_bytes,
    sha256_json,
    to_utc_iso,
    utc_now,
)
from .models import (
    EnvironmentIdentity,
    RedactionStatus,
    RuleResult,
    RunOutcome,
    RunState,
    TargetIdentity,
    VerdictLifecycleEvent,
    VerificationReport,
    declared_target_identity_digest,
)
from .state_machine import validate_transition

_ZERO_HASH = "0" * 64


def merkle_root(leaves: Iterable[str]) -> str:
    level = [bytes.fromhex(item) for item in leaves]
    if not level:
        return sha256_bytes(b"")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            bytes.fromhex(sha256_bytes(level[index] + level[index + 1]))
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


class EvidenceStore:
    def __init__(self, db_path: Path, evidence_root: Path) -> None:
        self.db_path = db_path
        self.evidence_root = evidence_root
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
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
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            target_identity_json TEXT NOT NULL,
            target_identity_digest TEXT NOT NULL,
            environment_identity_json TEXT NOT NULL,
            environment_identity_digest TEXT NOT NULL,
            rule_manifest_id TEXT NOT NULL,
            rule_manifest_digest TEXT NOT NULL,
            run_outcome TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            policy_version TEXT,
            target_reference TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id, created_at);

        CREATE TABLE IF NOT EXISTS idempotency_keys (
            tenant_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, idempotency_key)
        );

        CREATE TABLE IF NOT EXISTS evidence_retention (
            artifact_id TEXT PRIMARY KEY REFERENCES evidence_artifacts(artifact_id),
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            retention_class TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            purged_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS state_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            prior_state TEXT NOT NULL,
            next_state TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            workflow_version TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_artifacts (
            artifact_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            media_type TEXT NOT NULL,
            source_component TEXT NOT NULL,
            redaction_status TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            prev_chain_hash TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            UNIQUE(run_id, ordinal)
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence_artifacts(run_id, ordinal);

        CREATE TABLE IF NOT EXISTS rule_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            passed INTEGER NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, rule_id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            blocks_release INTEGER NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS signed_verdicts (
            verdict_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            key_id TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_verdict_run ON signed_verdicts(run_id, verdict_id);

        CREATE TABLE IF NOT EXISTS verdict_lifecycle_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            tenant_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            replacement_run_id TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS legal_holds (
            hold_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            run_id TEXT,
            reason TEXT NOT NULL,
            active INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            released_at TEXT
        );

        CREATE TRIGGER IF NOT EXISTS no_update_evidence BEFORE UPDATE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence_artifacts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_evidence BEFORE DELETE ON evidence_artifacts
        BEGIN SELECT RAISE(ABORT, 'evidence_artifacts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_state_events BEFORE UPDATE ON state_events
        BEGIN SELECT RAISE(ABORT, 'state_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_state_events BEFORE DELETE ON state_events
        BEGIN SELECT RAISE(ABORT, 'state_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_rule_results BEFORE UPDATE ON rule_results
        BEGIN SELECT RAISE(ABORT, 'rule_results are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_rule_results BEFORE DELETE ON rule_results
        BEGIN SELECT RAISE(ABORT, 'rule_results are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_signed_verdicts BEFORE UPDATE ON signed_verdicts
        BEGIN SELECT RAISE(ABORT, 'signed_verdicts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_signed_verdicts BEFORE DELETE ON signed_verdicts
        BEGIN SELECT RAISE(ABORT, 'signed_verdicts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_update_lifecycle BEFORE UPDATE ON verdict_lifecycle_events
        BEGIN SELECT RAISE(ABORT, 'verdict_lifecycle_events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS no_delete_lifecycle BEFORE DELETE ON verdict_lifecycle_events
        BEGIN SELECT RAISE(ABORT, 'verdict_lifecycle_events are append-only'); END;
        """
        with self._connection() as connection:
            connection.executescript(schema)
            existing = {row["name"] for row in connection.execute("PRAGMA table_info(runs)")}
            if "policy_version" not in existing:
                connection.execute("ALTER TABLE runs ADD COLUMN policy_version TEXT")
            if "target_reference" not in existing:
                connection.execute("ALTER TABLE runs ADD COLUMN target_reference TEXT")

    def register_run(
        self,
        run_id: str,
        target: TargetIdentity,
        environment: EnvironmentIdentity,
        manifest_id: str,
        manifest_digest: str,
    ) -> None:
        require_identifier(run_id, "run_id")
        require_identifier(manifest_id, "manifest_id")
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, tenant_id, target_identity_json, target_identity_digest,
                    environment_identity_json, environment_identity_digest,
                    rule_manifest_id, rule_manifest_digest, run_outcome, state,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    target.tenant_id,
                    canonical_json(target.to_dict()),
                    target.identity_digest,
                    canonical_json(environment.to_dict()),
                    environment.identity_digest,
                    manifest_id,
                    manifest_digest,
                    RunOutcome.INCONCLUSIVE.value,
                    RunState.CREATED.value,
                    now,
                    now,
                ),
            )

    def register_declared_run(
        self,
        run_id: str,
        tenant_id: str,
        target_type: str,
        target_identity_digest: str,
        target_reference: str,
        environment_identity_digest: str,
        environment_json: dict[str, Any],
        policy_version: str,
        manifest_id: str,
        manifest_digest: str,
        declared_artifact_sha256: str | None = None,
        declared_source_commit: str | None = None,
    ) -> None:
        """Register a run from a client-declared, pre-computed target identity digest.

        Intake (`echo.certforge.submit`) provides the immutable target binding as a digest, not
        the full canonical field set, so the digest is stored as the authoritative commitment;
        target acquisition later verifies the acquired artifact hashes to this digest. When a
        declared artifact commitment is provided (platform webhooks), it is stored alongside
        the digest so `reconcile_declared_target` can bind the run to its acquired identity.
        """
        require_identifier(run_id, "run_id")
        require_identifier(tenant_id, "tenant_id")
        require_identifier(target_type, "target_type")
        require_sha256(target_identity_digest, "target_identity_digest")
        require_sha256(environment_identity_digest, "environment_identity_digest")
        require_identifier(policy_version, "policy_version")
        require_identifier(manifest_id, "manifest_id")
        if not target_reference.strip():
            raise ValueError("target_reference is required")
        target_json = {
            "tenant_id": tenant_id,
            "target_type": target_type,
            "declared_identity_digest": target_identity_digest,
            "reference": target_reference,
        }
        if declared_artifact_sha256 is not None:
            require_sha256(declared_artifact_sha256, "declared_artifact_sha256")
            target_json["declared_artifact_sha256"] = declared_artifact_sha256
        if declared_source_commit is not None:
            target_json["declared_source_commit"] = declared_source_commit
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, tenant_id, target_identity_json, target_identity_digest,
                    environment_identity_json, environment_identity_digest,
                    rule_manifest_id, rule_manifest_digest, run_outcome, state,
                    created_at, updated_at, policy_version, target_reference
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    tenant_id,
                    canonical_json(target_json),
                    target_identity_digest,
                    canonical_json(environment_json),
                    environment_identity_digest,
                    manifest_id,
                    manifest_digest,
                    RunOutcome.INCONCLUSIVE.value,
                    RunState.CREATED.value,
                    now,
                    now,
                    policy_version,
                    target_reference,
                ),
            )

    def reconcile_declared_target(
        self,
        run_id: str,
        tenant_id: str,
        target: TargetIdentity,
        environment: EnvironmentIdentity,
    ) -> None:
        """Bind a DECLARED run to its ACQUIRED exact identity — pre-execution, fail-closed.

        A run registered from a declared commitment (webhook/intake) carries only a target
        identity digest plus, when supplied, a declared artifact commitment. Before execution
        the worker acquires the real artifact and calls this to replace the declared
        commitment with the full canonical ``TargetIdentity`` — but ONLY when every declared
        commitment matches the acquired identity exactly:

        * the run must still be pending (CREATED/QUEUED) — the window closes at acquisition;
        * a declared artifact commitment must exist and equal the acquired artifact digest
          (a declared run WITHOUT an artifact commitment can never reconcile — fail-closed);
        * a declared source commit, when present, must equal the acquired one;
        * the stored commitment must re-hash to the stored identity digest (tamper check);
        * the execution environment must match the declared environment identity digest.

        Any violation raises ``ValueError`` and the run must not execute. The declared
        ``target_type`` is a platform classification ("package"/"container"), not the
        acquisition transport ("local"/"git"); the artifact digest is the semantic
        commitment, so types are deliberately not compared.
        """
        row = self.get_run(run_id, tenant_id)  # KeyError -> unknown run (tenant-scoped)
        target_data: dict[str, Any] = json.loads(str(row["target_identity_json"]))
        if "declared_identity_digest" not in target_data:
            # Already a full identity: idempotent when identical, refused otherwise.
            if str(row["target_identity_digest"]) == target.identity_digest:
                return
            raise ValueError("target_already_reconciled_to_different_identity")
        if row["state"] not in (RunState.CREATED.value, RunState.QUEUED.value):
            raise ValueError("target_reconciliation_window_closed")
        if target.tenant_id != tenant_id or target_data.get("tenant_id") != tenant_id:
            raise ValueError("target_reconciliation_tenant_mismatch")
        declared_artifact = target_data.get("declared_artifact_sha256")
        if not isinstance(declared_artifact, str) or not declared_artifact:
            raise ValueError("target_declared_artifact_commitment_missing")
        if declared_artifact != target.artifact_sha256:
            raise ValueError("target_declared_artifact_mismatch")
        declared_commit = target_data.get("declared_source_commit")
        if declared_commit is not None and declared_commit != target.source_commit:
            raise ValueError("target_declared_source_commit_mismatch")
        recomputed = declared_target_identity_digest(
            tenant_id,
            str(target_data.get("target_type")),
            declared_artifact,
            declared_commit,
            str(target_data.get("reference")),
        )
        if recomputed != target_data.get("declared_identity_digest") or recomputed != str(
            row["target_identity_digest"]
        ):
            raise ValueError("target_declared_commitment_integrity_failed")
        if environment.identity_digest != str(row["environment_identity_digest"]):
            raise ValueError("environment_identity_mismatch")
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE runs SET target_identity_json = ?, target_identity_digest = ?,
                    environment_identity_json = ?, updated_at = ?
                WHERE run_id = ? AND tenant_id = ?
                """,
                (
                    canonical_json(target.to_dict()),
                    target.identity_digest,
                    canonical_json(environment.to_dict()),
                    now,
                    run_id,
                    tenant_id,
                ),
            )

    def find_idempotent(self, tenant_id: str, idempotency_key: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM idempotency_keys WHERE tenant_id = ? AND idempotency_key = ?",
                (tenant_id, idempotency_key),
            ).fetchone()
        return dict(row) if row is not None else None

    def bind_idempotent(
        self, tenant_id: str, idempotency_key: str, request_digest: str, run_id: str
    ) -> None:
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO idempotency_keys(tenant_id, idempotency_key, request_digest, run_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, idempotency_key, request_digest, run_id, now),
            )

    def get_run(self, run_id: str, tenant_id: str | None = None) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown run: {run_id}")
        result = dict(row)
        if tenant_id is not None and result["tenant_id"] != tenant_id:
            raise KeyError(f"unknown run: {run_id}")
        return result

    def list_runs(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM runs WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def transition_state(
        self,
        run_id: str,
        tenant_id: str,
        next_state: RunState,
        actor: str,
        reason: str,
        workflow_version: str,
    ) -> None:
        require_identifier(actor, "actor")
        require_identifier(workflow_version, "workflow_version")
        if not reason.strip():
            raise ValueError("transition reason is required")
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            row = connection.execute(
                "SELECT state, tenant_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None or row["tenant_id"] != tenant_id:
                raise KeyError(f"unknown run: {run_id}")
            current = RunState(row["state"])
            validate_transition(current, next_state)
            connection.execute(
                "INSERT INTO state_events(run_id, tenant_id, prior_state, next_state, actor, reason, workflow_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, tenant_id, current.value, next_state.value, actor, reason, workflow_version, now),
            )
            connection.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE run_id = ?",
                (next_state.value, now, run_id),
            )

    def set_run_outcome(self, run_id: str, tenant_id: str, outcome: RunOutcome) -> None:
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE runs SET run_outcome = ?, updated_at = ? WHERE run_id = ? AND tenant_id = ?",
                (outcome.value, now, run_id, tenant_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown run: {run_id}")

    def append_artifact(
        self,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
        content: bytes,
        media_type: str,
        source_component: str,
        redaction_status: RedactionStatus = RedactionStatus.COMPLETE,
    ) -> dict[str, Any]:
        require_identifier(artifact_id, "artifact_id")
        require_identifier(source_component, "source_component")
        run = self.get_run(run_id, tenant_id)
        del run
        created_at = to_utc_iso(utc_now())
        relative_path = f"{tenant_id}/{run_id}/artifacts/{artifact_id}.bin"
        destination = contained_path(self.evidence_root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(f"artifact already exists: {artifact_id}")
        descriptor: dict[str, Any]
        with self._connection() as connection:
            previous = connection.execute(
                "SELECT ordinal, chain_hash FROM evidence_artifacts WHERE run_id = ? ORDER BY ordinal DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            ordinal = 1 if previous is None else int(previous["ordinal"]) + 1
            prev_chain_hash = _ZERO_HASH if previous is None else str(previous["chain_hash"])
            digest = sha256_bytes(content)
            descriptor = {
                "artifact_id": artifact_id,
                "run_id": run_id,
                "tenant_id": tenant_id,
                "relative_path": relative_path,
                "sha256": digest,
                "size_bytes": len(content),
                "media_type": media_type,
                "source_component": source_component,
                "redaction_status": redaction_status.value,
                "ordinal": ordinal,
                "created_at": created_at,
            }
            record_hash = sha256_json(descriptor)
            chain_hash = sha256_bytes(bytes.fromhex(prev_chain_hash) + bytes.fromhex(record_hash))
            fd, temporary_name = tempfile.mkstemp(prefix=f".{artifact_id}.", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_name, destination)
                connection.execute(
                    """
                    INSERT INTO evidence_artifacts(
                        artifact_id, run_id, tenant_id, relative_path, sha256, size_bytes,
                        media_type, source_component, redaction_status, ordinal, created_at,
                        record_hash, prev_chain_hash, chain_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact_id, run_id, tenant_id, relative_path, digest, len(content),
                        media_type, source_component, redaction_status.value, ordinal, created_at,
                        record_hash, prev_chain_hash, chain_hash,
                    ),
                )
            except Exception:
                Path(temporary_name).unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise
        return {**descriptor, "record_hash": record_hash, "chain_hash": chain_hash}

    def record_rule_result(self, run_id: str, tenant_id: str, result: RuleResult) -> None:
        require_identifier(result.rule_id, "rule_id")
        if not result.evidence_ids:
            raise ValueError("rule results require evidence references")
        with self._connection() as connection:
            run = connection.execute(
                "SELECT tenant_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None or run["tenant_id"] != tenant_id:
                raise KeyError(f"unknown run: {run_id}")
            placeholders = ",".join("?" for _ in result.evidence_ids)
            rows = connection.execute(
                f"SELECT artifact_id, tenant_id, run_id FROM evidence_artifacts WHERE artifact_id IN ({placeholders})",
                tuple(result.evidence_ids),
            ).fetchall()
            if len(rows) != len(set(result.evidence_ids)):
                raise ValueError("every rule evidence reference must identify a registered artifact")
            if any(row["tenant_id"] != tenant_id or row["run_id"] != run_id for row in rows):
                raise ValueError("cross-tenant or cross-run evidence reference rejected")
            connection.execute(
                "INSERT INTO rule_results(run_id, tenant_id, rule_id, passed, evidence_ids_json, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    tenant_id,
                    result.rule_id,
                    int(result.passed),
                    canonical_json(list(result.evidence_ids)),
                    canonical_json(result.details),
                    to_utc_iso(utc_now()),
                ),
            )

    def list_rule_results(self, run_id: str, tenant_id: str) -> dict[str, RuleResult]:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM rule_results WHERE run_id = ? AND tenant_id = ?", (run_id, tenant_id)
            ).fetchall()
        return {
            row["rule_id"]: RuleResult(
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                evidence_ids=tuple(json.loads(row["evidence_ids_json"])),
                details=json.loads(row["details_json"]),
            )
            for row in rows
        }

    def record_finding(
        self,
        finding_id: str,
        run_id: str,
        tenant_id: str,
        severity: str,
        title: str,
        blocks_release: bool,
        evidence_ids: tuple[str, ...],
    ) -> None:
        require_identifier(finding_id, "finding_id")
        if not title.strip():
            raise ValueError("finding title is required")
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO findings(finding_id, run_id, tenant_id, severity, title, blocks_release, evidence_ids_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id, run_id, tenant_id, severity, title, int(blocks_release),
                    canonical_json(list(evidence_ids)), to_utc_iso(utc_now()),
                ),
            )

    def blocking_findings(self, run_id: str, tenant_id: str) -> list[dict[str, Any]]:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE run_id = ? AND tenant_id = ? AND blocks_release = 1",
                (run_id, tenant_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_findings(self, run_id: str, tenant_id: str) -> list[dict[str, Any]]:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT finding_id, severity, title, blocks_release, evidence_ids_json, created_at "
                "FROM findings WHERE run_id = ? AND tenant_id = ? ORDER BY created_at, finding_id",
                (run_id, tenant_id),
            ).fetchall()
        return [
            {
                "finding_id": row["finding_id"],
                "severity": row["severity"],
                "title": row["title"],
                "blocks_release": bool(row["blocks_release"]),
                "evidence_ids": json.loads(row["evidence_ids_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def list_evidence(self, run_id: str, tenant_id: str) -> list[dict[str, Any]]:
        """Redacted evidence index — metadata only, never raw content or secrets."""
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT artifact_id, sha256, size_bytes, media_type, source_component, "
                "redaction_status, ordinal, created_at FROM evidence_artifacts "
                "WHERE run_id = ? AND tenant_id = ? ORDER BY ordinal",
                (run_id, tenant_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_retention(
        self, run_id: str, tenant_id: str, artifact_id: str,
        retention_class: str, expires_at: str,
    ) -> None:
        self.get_run(run_id, tenant_id)
        now = to_utc_iso(utc_now())
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO evidence_retention
                     (artifact_id, run_id, tenant_id, retention_class, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(artifact_id) DO UPDATE SET
                     retention_class=excluded.retention_class, expires_at=excluded.expires_at""",
                (artifact_id, run_id, tenant_id, retention_class, expires_at, now),
            )

    def purge_expired_evidence(self, now: str) -> list[dict[str, Any]]:
        """Purge the raw CONTENT of retention-expired artifacts. The append-only metadata rows
        (and their sha256/chain hashes) and any signed verdict are left intact — so the recorded
        evidence Merkle root and the signed verdict remain valid historical records; only the raw
        bytes are removed. Returns the purged artifacts (id + run_id)."""
        purged: list[dict[str, Any]] = []
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT r.artifact_id, r.run_id, a.relative_path
                     FROM evidence_retention r
                     JOIN evidence_artifacts a ON a.artifact_id = r.artifact_id
                    WHERE r.expires_at <= ? AND r.purged_at IS NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM legal_holds h
                           WHERE h.tenant_id=r.tenant_id AND h.active=1
                             AND (h.run_id IS NULL OR h.run_id=r.run_id)
                      )""",
                (now,),
            ).fetchall()
            for row in rows:
                target = contained_path(self.evidence_root, row["relative_path"])
                if target.exists():
                    target.unlink()
                connection.execute(
                    "UPDATE evidence_retention SET purged_at = ? WHERE artifact_id = ?",
                    (now, row["artifact_id"]),
                )
                purged.append({"artifact_id": row["artifact_id"], "run_id": row["run_id"]})
        return purged

    def artifact_content_exists(self, run_id: str, tenant_id: str, artifact_id: str) -> bool:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT relative_path FROM evidence_artifacts WHERE artifact_id = ? AND run_id = ?",
                (artifact_id, run_id),
            ).fetchone()
        if row is None:
            return False
        return contained_path(self.evidence_root, row["relative_path"]).exists()

    def verify_evidence(self, run_id: str, tenant_id: str) -> VerificationReport:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_artifacts WHERE run_id = ? AND tenant_id = ? ORDER BY ordinal",
                (run_id, tenant_id),
            ).fetchall()
            purged_ids = {
                r["artifact_id"] for r in connection.execute(
                    "SELECT artifact_id FROM evidence_retention WHERE run_id = ? AND purged_at IS NOT NULL",
                    (run_id,),
                ).fetchall()
            }
        invalid: list[dict[str, str]] = []
        valid_ids: set[str] = set()
        record_hashes: list[str] = []
        expected_previous = _ZERO_HASH
        for expected_ordinal, row in enumerate(rows, start=1):
            descriptor = {
                "artifact_id": row["artifact_id"],
                "run_id": row["run_id"],
                "tenant_id": row["tenant_id"],
                "relative_path": row["relative_path"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "media_type": row["media_type"],
                "source_component": row["source_component"],
                "redaction_status": row["redaction_status"],
                "ordinal": row["ordinal"],
                "created_at": row["created_at"],
            }
            reasons: list[str] = []
            calculated_record_hash = sha256_json(descriptor)
            if int(row["ordinal"]) != expected_ordinal:
                reasons.append("non_contiguous_ordinal")
            if row["record_hash"] != calculated_record_hash:
                reasons.append("record_hash_mismatch")
            if row["prev_chain_hash"] != expected_previous:
                reasons.append("chain_predecessor_mismatch")
            calculated_chain = sha256_bytes(
                bytes.fromhex(expected_previous) + bytes.fromhex(calculated_record_hash)
            )
            if row["chain_hash"] != calculated_chain:
                reasons.append("chain_hash_mismatch")
            if row["redaction_status"] not in {
                RedactionStatus.COMPLETE.value,
                RedactionStatus.NOT_REQUIRED.value,
            }:
                reasons.append("redaction_incomplete")
            try:
                artifact_path = contained_path(self.evidence_root, row["relative_path"])
                if not artifact_path.is_file():
                    # A retention-purged artifact has intact metadata + hash-chain; its raw content
                    # is gone BY POLICY, which is not tamper. Only an unpurged missing file is.
                    if row["artifact_id"] not in purged_ids:
                        reasons.append("artifact_missing")
                else:
                    content = artifact_path.read_bytes()
                    if len(content) != int(row["size_bytes"]):
                        reasons.append("artifact_size_mismatch")
                    if sha256_bytes(content) != row["sha256"]:
                        reasons.append("artifact_sha256_mismatch")
            except ValueError:
                reasons.append("artifact_path_invalid")
            if reasons:
                invalid.append({"artifact_id": row["artifact_id"], "reason": ",".join(sorted(set(reasons)))})
            else:
                valid_ids.add(row["artifact_id"])
            record_hashes.append(calculated_record_hash)
            expected_previous = calculated_chain
        return VerificationReport(
            run_id=run_id,
            tenant_id=tenant_id,
            valid=bool(rows) and not invalid,
            artifact_count=len(rows),
            valid_artifact_ids=frozenset(valid_ids),
            invalid_artifacts=tuple(invalid),
            merkle_root=merkle_root(record_hashes),
            chain_tip=expected_previous,
        )

    def save_signed_verdict(self, run_id: str, tenant_id: str, envelope: Any) -> None:
        self.get_run(run_id, tenant_id)
        if envelope.payload.get("run_id") != run_id or envelope.payload.get("tenant_id") != tenant_id:
            raise ValueError("signed verdict identity does not match storage scope")
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO signed_verdicts(run_id, tenant_id, payload_json, payload_sha256, signature_b64, key_id, public_key_pem, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, tenant_id, canonical_json(envelope.payload), envelope.payload_sha256,
                    envelope.signature_b64, envelope.key_id, envelope.public_key_pem, to_utc_iso(utc_now()),
                ),
            )

    def latest_signed_verdict(self, run_id: str, tenant_id: str) -> dict[str, Any] | None:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM signed_verdicts WHERE run_id = ? AND tenant_id = ? ORDER BY verdict_id DESC LIMIT 1",
                (run_id, tenant_id),
            ).fetchone()
        return None if row is None else dict(row)

    def append_lifecycle_event(
        self,
        run_id: str,
        tenant_id: str,
        event_type: VerdictLifecycleEvent,
        actor: str,
        reason: str,
        replacement_run_id: str | None = None,
    ) -> None:
        require_identifier(actor, "actor")
        if not reason.strip():
            raise ValueError("lifecycle reason is required")
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO verdict_lifecycle_events(run_id, tenant_id, event_type, actor, reason, replacement_run_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id, tenant_id, event_type.value, actor, reason, replacement_run_id,
                    to_utc_iso(utc_now()),
                ),
            )

    def lifecycle_events(self, run_id: str, tenant_id: str) -> list[dict[str, Any]]:
        self.get_run(run_id, tenant_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM verdict_lifecycle_events WHERE run_id = ? AND tenant_id = ? ORDER BY event_id",
                (run_id, tenant_id),
            ).fetchall()
        return [dict(row) for row in rows]
