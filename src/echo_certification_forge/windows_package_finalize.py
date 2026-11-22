"""Key-holding control-plane finalizer for authenticated Windows package results."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from .evidence import EvidenceStore
from .executor import RetentionPolicy, RunExecutor, StaticEntitlement
from .models import EnvironmentIdentity, RedactionStatus, TargetIdentity
from .operational_telemetry import OperationalTelemetryRegistry
from .policy import RuleManifest
from .run_worker import _load_signer
from .subscriber import SubscriberError, SubscriberGovernance, SubscriberPolicy
from .windows_package import WindowsPackageResultBody

_REPO = Path(__file__).resolve().parents[2]


def _active_worker_attestation(db_path: Path, tenant_id: str, worker_id: str) -> str:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT attestation_sha256 FROM subscriber_private_workers
            WHERE organization_id=? AND worker_id=? AND status='ACTIVE'
            """,
            (tenant_id, worker_id),
        ).fetchone()
    if row is None:
        raise SubscriberError(403, "private_worker_not_active")
    return str(row[0])


def finalize_windows_package_result(
    *,
    run_id: str,
    tenant_id: str,
    store: EvidenceStore,
    registry: OperationalTelemetryRegistry,
    governance: SubscriberGovernance,
    manifest: RuleManifest,
    signer,
) -> dict[str, object]:
    stored = registry.windows_package_result(run_id, tenant_id)
    if stored is None:
        return {"run_id": run_id, "signed": False, "error": "windows_result_missing"}
    body = WindowsPackageResultBody.model_validate(stored["body"])
    worker_id = str(stored["runner_id"])
    worker_attestation = _active_worker_attestation(store.db_path, tenant_id, worker_id)
    target = TargetIdentity(
        tenant_id=tenant_id,
        target_type="package",
        canonical_ref=body.reference,
        artifact_sha256=body.artifact_sha256,
        source_commit=body.source_commit,
    )
    environment = body.environment
    claim = None
    try:
        claim = governance.claim_worker_run(
            run_id=run_id,
            organization_id=tenant_id,
            policy_version=manifest.manifest_id,
            target_type="package",
            target_reference=body.reference,
            worker_id=worker_id,
            worker_attestation_sha256=worker_attestation,
            execution_location="local",
            signing_authority="platform",
            signing_key_id=signer.key_id,
        )
        store.reconcile_declared_target(
            run_id,
            tenant_id,
            target,
            EnvironmentIdentity(**environment),
        )
        claim = governance.reconcile_worker_target_identity(
            claim,
            target_identity=target.to_dict(),
            target_identity_digest=target.identity_digest,
        )
        authorization = governance.authorize_worker_execution(
            claim,
            target_identity=target.to_dict(),
            target_identity_digest=target.identity_digest,
            environment_identity=environment,
            environment_identity_digest=body.environment_identity_digest,
        )
        artifact_id = f"{run_id}-windows-package-observation"
        store.append_artifact(
            run_id,
            tenant_id,
            artifact_id,
            json.dumps(body.model_dump(mode="json"), sort_keys=True).encode("utf-8"),
            "application/json",
            "certforge.windows-package-finalizer",
            RedactionStatus.COMPLETE,
        )
        if not body.ready_candidate:
            store.record_finding(
                f"{run_id}-windows-signature",
                run_id,
                tenant_id,
                "BLOCKER",
                f"windows_package_not_ready:authenticode_{body.authenticode_status.lower()}",
                True,
                (artifact_id,),
            )
        with tempfile.TemporaryDirectory(prefix="certforge-p8c-evidence-") as directory:
            source_root = Path(directory)
            (source_root / "authenticated-windows-result.json").write_text(
                json.dumps(body.model_dump(mode="json"), sort_keys=True),
                encoding="utf-8",
            )
            executor = RunExecutor(store, manifest, signer)
            result = executor.execute(
                run_id,
                tenant_id,
                source_root,
                entitlement=StaticEntitlement(frozenset({tenant_id})),
                retention=RetentionPolicy(
                    ttl_seconds=authorization.retention_days * 24 * 60 * 60
                ),
                journey=None,
                control_attestations={
                    "runner_control_channel": True,
                    "signing_authority_separation": True,
                },
                execution_guard=lambda: governance.assert_worker_claim_active(claim),
                completion_callback=lambda envelope: governance.complete_worker_execution(
                    claim, envelope
                ),
            )
        return {
            "run_id": run_id,
            "signed": result.signed,
            "release_verdict": result.release_verdict,
            "authenticode_status": body.authenticode_status,
        }
    except (OSError, sqlite3.Error, SubscriberError, TypeError, ValueError) as exc:
        if claim is not None:
            try:
                governance.fail_worker_execution(
                    claim,
                    reason=(
                        exc.code
                        if isinstance(exc, SubscriberError)
                        else "windows_package_finalization_failed"
                    ),
                )
            except (OSError, sqlite3.Error, SubscriberError):
                pass
        return {
            "run_id": run_id,
            "signed": False,
            "error": (
                exc.code if isinstance(exc, SubscriberError) else type(exc).__name__
            ),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO / "var" / "certforge.sqlite3")),
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path(
            os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO / "var" / "evidence")
        ),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(
            os.environ.get(
                "ECHO_CERTFORGE_POLICY", _REPO / "policies" / "mandatory-rules.v2.json"
            )
        ),
    )
    parser.add_argument(
        "--subscriber-policy",
        type=Path,
        default=Path(
            os.environ.get(
                "ECHO_CERTFORGE_SUBSCRIBER_POLICY",
                _REPO / "policies" / "subscriber-governance.v1.json",
            )
        ),
    )
    parser.add_argument(
        "--signing-key",
        type=Path,
        default=Path(
            os.environ.get(
                "ECHO_CERTFORGE_RUN_SIGNING_KEY", _REPO / "var" / "run-signing-key.pem"
            )
        ),
    )
    args = parser.parse_args(argv)
    pepper = os.environ.get("ECHO_CERTFORGE_API_KEY_PEPPER")
    if not pepper:
        print(json.dumps({"error": "subscriber_governance_pepper_missing"}))
        return 2
    store = EvidenceStore(args.db, args.evidence_root)
    result = finalize_windows_package_result(
        run_id=args.run_id,
        tenant_id=args.tenant,
        store=store,
        registry=OperationalTelemetryRegistry(args.db),
        governance=SubscriberGovernance(
            args.db,
            SubscriberPolicy.load(args.subscriber_policy),
            pepper.encode("utf-8"),
        ),
        manifest=RuleManifest.load(args.policy),
        signer=_load_signer(args.signing_key),
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("signed") is True else 3


if __name__ == "__main__":
    raise SystemExit(main())
