"""Certification run-worker — the KEY-HOLDING execution process.

Kept deliberately separate from the read/deploy-gate API. The worker holds the run signer, acquires
a target, registers a full-identity run, drives RunExecutor, and writes the signed result.

P5 adds an optional strict adapter lane. A production adapter set is accepted only from a verified,
signed RunnerResponse bound to this run/tenant plus a versioned exact-identity policy. The resulting
adapter-set digest is committed into EnvironmentIdentity before the run is registered.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .acquisition import AcquisitionError, acquire_target
from .adapter_policy import AdapterAcceptancePolicy, load_adapter_acceptance_policy
from .adapter_registry import load_trusted_adapter_registry
from .adapter_execution import (
    AdapterBundleTrustBinding,
    load_adapter_runner_identity,
    policy_to_json,
    sign_adapter_bundle,
)
from .adapter_transport import parse_verified_adapter_bundle
from .adapters import AdapterExecutionRecord, adapter_set_digest
from .canonical import sha256_bytes, sha256_json
from .evidence import EvidenceStore
from .executor import RetentionPolicy, RunExecutor, StaticEntitlement
from .models import EnvironmentIdentity, RunOutcome, RunState, TargetIdentity
from .policy import RuleManifest
from .runner import RunnerResponse
from .sandbox import DEFAULT_IMAGE, DockerSandbox, sandboxed_journey_runner
from .signing import Ed25519VerdictSigner
from .subscriber import SubscriberError, SubscriberGovernance, SubscriberPolicy

_REPO = Path(__file__).resolve().parents[2]
_ADAPTER_RULE = "adapter_identity_and_quality"


class _ClaimHeartbeat:
    def __init__(self, governance: SubscriberGovernance, claim) -> None:
        self._governance = governance
        self._claim = claim
        self._stop = threading.Event()
        self._failed = threading.Event()
        self._failure_code = "worker_run_heartbeat_lost"
        self._thread = threading.Thread(
            target=self._run,
            name=f"certforge-heartbeat-{claim.run_id}",
            daemon=True,
        )

    def _run(self) -> None:
        interval = self._governance.policy.worker_heartbeat_interval_seconds
        while not self._stop.wait(interval):
            try:
                self._governance.heartbeat_worker_claim(self._claim)
            except SubscriberError as exc:
                self._failure_code = exc.code
                self._failed.set()
                return
            except (OSError, sqlite3.Error):
                self._failure_code = "worker_run_heartbeat_storage_failed"
                self._failed.set()
                return

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def assert_active(self) -> None:
        if self._failed.is_set():
            raise SubscriberError(409, self._failure_code)
        self._governance.assert_worker_claim_active(self._claim)
        if self._failed.is_set():
            raise SubscriberError(409, self._failure_code)


def _env_digest(component: str) -> str:
    return sha256_bytes(f"certforge-worker-env:{component}".encode("utf-8"))


def _worker_environment(adapter_set_sha256: str | None = None) -> EnvironmentIdentity:
    """Declared certification environment.

    The legacy v1 path retains its historical environment commitment. P5/v2 callers pass the exact
    digest derived from the verified signed adapter execution records.
    """
    return EnvironmentIdentity(
        runner_image_sha256=_env_digest("runner-image"),
        adapter_set_sha256=adapter_set_sha256 or _env_digest("adapter-set"),
        test_plan_sha256=_env_digest("test-plan"),
        policy_sha256=_env_digest("policy"),
        harness_sha256=_env_digest("harness"),
        prompt_set_sha256=_env_digest("prompt-set"),
        model_route_sha256=_env_digest("model-route"),
        os_runtime_sha256=_env_digest("os-runtime"),
        egress_policy_sha256=_env_digest("egress-policy"),
    )


def _load_signer(path: Path) -> Ed25519VerdictSigner:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return Ed25519VerdictSigner.from_private_pem(path.read_bytes())


def run(
    run_id: str,
    tenant: str,
    target_spec: dict,
    *,
    store: EvidenceStore,
    manifest: RuleManifest,
    signer: Ed25519VerdictSigner,
    entitled: frozenset[str] | None = None,
    subscribers: SubscriberGovernance | None = None,
    journey: list[str] | None = None,
    sandbox: DockerSandbox | None = None,
    adapter_records: tuple[AdapterExecutionRecord, ...] | None = None,
    adapter_policy: AdapterAcceptancePolicy | None = None,
    adapter_bundle_response_sha256: str | None = None,
    worker_id: str | None = None,
    worker_attestation_sha256: str | None = None,
    execution_location: str = "local",
    signing_authority: str = "platform",
) -> dict:
    if subscribers is None:
        try:
            with sqlite3.connect(store.db_path) as connection:
                subscriber_tenant = bool(
                    connection.execute(
                        """
                        SELECT 1 FROM sqlite_master
                        WHERE type = 'table' AND name = 'subscriber_organizations'
                        """
                    ).fetchone()
                    and connection.execute(
                        """
                        SELECT 1 FROM subscriber_organizations
                        WHERE organization_id = ?
                        """,
                        (tenant,),
                    ).fetchone()
                )
        except sqlite3.Error:
            subscriber_tenant = True
        if subscriber_tenant:
            return {
                "run_id": run_id,
                "error": "subscriber_governance_required",
            }

    claim = None
    heartbeat = None
    if subscribers is not None:
        target_type = str(target_spec.get("type", "")).strip()
        if target_type == "local":
            raw_path = target_spec.get("path")
            target_reference = (
                Path(str(raw_path)).resolve(strict=False).as_posix()
                if raw_path
                else ""
            )
        elif target_type == "git":
            url = str(target_spec.get("url", "")).strip()
            ref = str(target_spec.get("ref", "")).strip()
            target_reference = f"{url}@{ref}" if ref else url
        else:
            target_reference = ""
        try:
            claim = subscribers.claim_worker_run(
                run_id=run_id,
                organization_id=tenant,
                policy_version=manifest.manifest_id,
                target_type=target_type,
                target_reference=target_reference,
                worker_id=worker_id,
                worker_attestation_sha256=worker_attestation_sha256,
                execution_location=execution_location,
                signing_authority=signing_authority,
                signing_key_id=signer.key_id,
            )
            heartbeat = _ClaimHeartbeat(subscribers, claim)
            heartbeat.start()
        except (OSError, sqlite3.Error, SubscriberError, TypeError, ValueError) as exc:
            return {
                "run_id": run_id,
                "error": "subscriber_worker_claim_denied",
                "detail": exc.code if isinstance(exc, SubscriberError) else type(exc).__name__,
            }

    work_root = store.evidence_root / ".worker"
    try:
        work_root.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="certforge-acq-", dir=work_root))
    except OSError as exc:
        if claim is not None:
            try:
                store.transition_state(
                    run_id,
                    tenant,
                    RunState.INFRASTRUCTURE_FAILURE,
                    "subscriber-worker",
                    "workspace_creation_failed",
                    manifest.manifest_id,
                )
                store.set_run_outcome(run_id, tenant, RunOutcome.INFRA_FAILED)
            finally:
                if heartbeat is not None:
                    heartbeat.stop()
                subscribers.finish_worker_claim(claim, reason="workspace_creation_failed")
        return {
            "run_id": run_id,
            "error": "workspace_creation_failed",
            "detail": type(exc).__name__,
        }
    try:
        acquired = acquire_target(target_spec, workdir / "src")
    except (AcquisitionError, OSError) as exc:
        if claim is not None:
            try:
                store.transition_state(
                    run_id,
                    tenant,
                    RunState.INFRASTRUCTURE_FAILURE,
                    "subscriber-worker",
                    "target_acquisition_failed",
                    manifest.manifest_id,
                )
                store.set_run_outcome(run_id, tenant, RunOutcome.INFRA_FAILED)
            finally:
                if heartbeat is not None:
                    heartbeat.stop()
                subscribers.finish_worker_claim(claim, reason="target_acquisition_failed")
        shutil.rmtree(workdir, ignore_errors=True)
        return {"run_id": run_id, "error": "acquisition_failed", "detail": str(exc)}

    try:
        existing = store.get_run(run_id, tenant)
    except KeyError:
        existing = None
    target_data: dict[str, object] = {}
    declared_commit: str | None = None
    if existing is not None:
        target_data = json.loads(str(existing["target_identity_json"]))
        raw_commit = target_data.get("declared_source_commit")
        if isinstance(raw_commit, str) and raw_commit:
            declared_commit = raw_commit

    target = TargetIdentity(
        tenant_id=tenant,
        target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref,
        artifact_sha256=acquired.artifact_sha256,
        source_commit=declared_commit,
    )
    adapter_digest = adapter_set_digest(adapter_records) if adapter_records is not None else None
    environment = _worker_environment(adapter_digest)
    if subscribers is not None:
        if existing is None or existing["state"] != RunState.QUEUED.value:
            if claim is not None:
                if heartbeat is not None:
                    heartbeat.stop()
                subscribers.finish_worker_claim(claim, reason="run_not_queued")
            shutil.rmtree(workdir, ignore_errors=True)
            return {
                "run_id": run_id,
                "error": "run_not_queued",
                "state": existing["state"] if existing is not None else "UNKNOWN",
            }
        if claim is None:
            try:
                store.transition_state(
                    run_id,
                    tenant,
                    RunState.INFRASTRUCTURE_FAILURE,
                    "subscriber-worker",
                    "target_identity_binding_mismatch",
                    manifest.manifest_id,
                )
                store.set_run_outcome(run_id, tenant, RunOutcome.INFRA_FAILED)
            finally:
                if claim is not None:
                    if heartbeat is not None:
                        heartbeat.stop()
                    subscribers.finish_worker_claim(
                        claim, reason="worker_run_claim_missing"
                    )
            shutil.rmtree(workdir, ignore_errors=True)
            return {"run_id": run_id, "error": "worker_run_claim_missing"}
    elif existing is None:
        store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    elif existing["state"] not in (RunState.CREATED.value, RunState.QUEUED.value):
        return {"run_id": run_id, "error": "run_not_pending", "state": existing["state"]}
    else:
        try:
            store.reconcile_declared_target(run_id, tenant, target, environment)
        except ValueError as exc:
            return {
                "run_id": run_id,
                "error": "target_reconciliation_failed",
                "detail": str(exc),
            }

    # Subscriber governance performs its own transactional exact-identity reconciliation
    # immediately before execution. If an intake also carries the P6 artifact commitment,
    # validate it first so both enforcement layers agree before authorization.
    if subscribers is not None and target_data.get("declared_artifact_sha256") is not None:
        try:
            store.reconcile_declared_target(run_id, tenant, target, environment)
        except ValueError as exc:
            if heartbeat is not None:
                heartbeat.stop()
            if claim is not None:
                try:
                    subscribers.fail_worker_execution(
                        claim, reason="target_reconciliation_failed"
                    )
                except (OSError, sqlite3.Error, SubscriberError):
                    pass
            shutil.rmtree(workdir, ignore_errors=True)
            return {
                "run_id": run_id,
                "error": "target_reconciliation_failed",
                "detail": str(exc),
            }

    executor = RunExecutor(store, manifest, signer)
    journey_runner = None
    entitlement = StaticEntitlement(entitled or frozenset())
    retention = RetentionPolicy()
    execution_guard = None
    completion_callback = None
    if subscribers is not None:
        try:
            if claim is None or heartbeat is None:
                raise SubscriberError(409, "worker_run_claim_missing")
            heartbeat.assert_active()
            authorization = subscribers.authorize_worker_execution(
                claim,
                target_identity=target.to_dict(),
                target_identity_digest=target.identity_digest,
                environment_identity=environment.to_dict(),
                environment_identity_digest=environment.identity_digest,
            )
            heartbeat.assert_active()
            retention_days = authorization.retention_days
            if retention_days <= 0:
                raise ValueError("subscriber retention must be positive")
        except (OSError, sqlite3.Error, SubscriberError, TypeError, ValueError) as exc:
            reason = (
                exc.code if isinstance(exc, SubscriberError)
                else "subscriber_governance_lookup_failed"
            )
            if heartbeat is not None:
                heartbeat.stop()
            if claim is not None:
                try:
                    subscribers.fail_worker_execution(claim, reason=reason)
                except (OSError, sqlite3.Error, SubscriberError):
                    pass
            current = store.get_run(run_id, tenant)
            shutil.rmtree(workdir, ignore_errors=True)
            return {
                "run_id": run_id,
                "state": current["state"],
                "signed": False,
                "error": "subscriber_execution_denied",
                "detail": reason,
            }
        else:
            allowed = True
            reason = "subscriber_entitled"
        entitlement = StaticEntitlement(
            frozenset({tenant}) if allowed else frozenset(),
            denied_reason=reason,
        )
        retention = RetentionPolicy(
            retention_class=f"subscriber-{retention_days}d",
            ttl_seconds=retention_days * 24 * 3600,
        )
        execution_guard = heartbeat.assert_active
        completion_callback = lambda envelope: subscribers.complete_worker_execution(
            claim, envelope
        )
    if sandbox is not None:
        journey_runner = sandboxed_journey_runner(sandbox, execution_guard)
    try:
        try:
            result = executor.execute(
                run_id,
                tenant,
                acquired.source_root,
                entitlement=entitlement,
                retention=retention,
                journey=journey,
                journey_runner=journey_runner,
                control_attestations={
                    "runner_control_channel": True,
                    "signing_authority_separation": True,
                },
                adapter_records=adapter_records,
                adapter_policy=adapter_policy,
                execution_guard=execution_guard,
                completion_callback=completion_callback,
            )
        except SubscriberError as exc:
            if heartbeat is not None:
                heartbeat.stop()
            if claim is not None and subscribers is not None:
                try:
                    subscribers.fail_worker_execution(claim, reason=exc.code)
                except (OSError, sqlite3.Error, SubscriberError):
                    pass
            current = store.get_run(run_id, tenant)
            return {
                "run_id": run_id,
                "state": current["state"],
                "signed": False,
                "error": "subscriber_execution_fenced",
                "detail": exc.code,
            }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if claim is not None and subscribers is not None:
        if heartbeat is not None:
            heartbeat.stop()
        if result.final_state != RunState.COMPLETED.value:
            try:
                subscribers.finish_worker_claim(
                    claim, reason="execution_finished", require_active=True
                )
            except SubscriberError as exc:
                return {
                    "run_id": run_id,
                    "state": store.get_run(run_id, tenant)["state"],
                    "signed": False,
                    "error": "subscriber_execution_fenced",
                    "detail": exc.code,
                }
    return {
        "run_id": result.run_id,
        "state": result.final_state,
        "run_outcome": result.run_outcome,
        "release_verdict": result.release_verdict,
        "signed": result.signed,
        "blocking_findings": list(result.blocking_findings),
        "target_identity_digest": target.identity_digest,
        "environment_identity_digest": environment.identity_digest,
        "adapter_set_sha256": environment.adapter_set_sha256,
        "adapter_bundle_response_sha256": adapter_bundle_response_sha256,
        "signer_public_key_id": signer.key_id,
        "journey_isolation": "docker" if sandbox is not None else "none",
    }


def _load_adapter_inputs(
    *,
    response_path: Path,
    policy_path: Path,
    registry_path: Path,
    runner_signing_key_path: Path,
    run_id: str,
    tenant: str,
) -> tuple[
    tuple[AdapterExecutionRecord, ...],
    AdapterAcceptancePolicy,
    RunnerResponse,
]:
    try:
        registry = load_trusted_adapter_registry(registry_path)
        response = RunnerResponse.model_validate_json(response_path.read_text(encoding="utf-8"))
        response_sha256 = sha256_json(response.model_dump(mode="json"))
        if response_sha256 != registry.reusable_bundle_sha256:
            raise ValueError("reusable adapter bundle differs from independent registry")
        records = parse_verified_adapter_bundle(
            response,
            registry.runner_public_key_pem,
            expected_run_id=registry.reusable_bundle_run_id,
            expected_tenant_id=registry.reusable_bundle_tenant_id,
            allowed_runner_ids=(registry.runner_id,),
            expected_trust_roots=registry.trust_roots,
        )
        policy = load_adapter_acceptance_policy(policy_path)
        if sha256_json(policy_to_json(policy)) != registry.policy_sha256:
            raise ValueError("adapter policy differs from independent registry")
        runner_identity = load_adapter_runner_identity(runner_signing_key_path)
        if runner_identity.key_id != registry.runner_key_id:
            raise ValueError("adapter runner signing key differs from independent registry")
        rebound = sign_adapter_bundle(
            records,
            run_id=run_id,
            tenant_id=tenant,
            trust_binding=AdapterBundleTrustBinding(**registry.trust_roots),
            runner_identity=runner_identity,
            runner_id=registry.runner_id,
            issued_at=response.issued_at,
        )
        rebound_records = parse_verified_adapter_bundle(
            rebound.response,
            registry.runner_public_key_pem,
            expected_run_id=run_id,
            expected_tenant_id=tenant,
            allowed_runner_ids=(registry.runner_id,),
            expected_trust_roots=registry.trust_roots,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError(f"adapter_input_rejected:{type(exc).__name__}:{exc}") from exc
    return rebound_records, policy, rebound.response


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--target-json", required=True, help='e.g. {"type":"local","path":"/abs/dir"}')
    parser.add_argument("--journey-json", default=None, help='e.g. ["python3","hello.py"]')
    parser.add_argument("--policy-version", default=None)
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO / "var" / "certforge.sqlite3")),
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO / "var" / "evidence")),
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path(
            os.environ.get(
                "ECHO_CERTFORGE_POLICY",
                _REPO / "policies" / "mandatory-rules.v2.json",
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
                "ECHO_CERTFORGE_RUN_SIGNING_KEY",
                _REPO / "var" / "run-signing-key.pem",
            )
        ),
    )
    parser.add_argument("--sandbox", action="store_true")
    parser.add_argument(
        "--non-production-compat",
        action="store_true",
        help="explicitly allow legacy manifests or missing adapter inputs for tests/dev only",
    )
    parser.add_argument(
        "--sandbox-image",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_IMAGE", DEFAULT_IMAGE),
    )
    parser.add_argument(
        "--sandbox-docker",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_DOCKER", "docker"),
    )
    parser.add_argument("--adapter-response", type=Path, default=None)
    parser.add_argument("--adapter-policy", type=Path, default=None)
    parser.add_argument(
        "--adapter-runner-signing-key",
        type=Path,
        default=(
            Path(os.environ["ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY"])
            if os.environ.get("ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY")
            else None
        ),
    )
    parser.add_argument(
        "--adapter-registry",
        type=Path,
        default=(
            Path(os.environ["ECHO_CERTFORGE_ADAPTER_REGISTRY"])
            if os.environ.get("ECHO_CERTFORGE_ADAPTER_REGISTRY")
            else None
        ),
    )
    parser.add_argument(
        "--worker-id",
        default=os.environ.get("ECHO_CERTFORGE_WORKER_ID"),
    )
    parser.add_argument(
        "--worker-attestation-sha256",
        default=os.environ.get("ECHO_CERTFORGE_WORKER_ATTESTATION_SHA256"),
    )
    parser.add_argument(
        "--execution-location",
        default=os.environ.get("ECHO_CERTFORGE_EXECUTION_LOCATION", "local"),
    )
    parser.add_argument(
        "--signing-authority",
        choices=("platform", "customer"),
        default=os.environ.get("ECHO_CERTFORGE_SIGNING_AUTHORITY", "platform"),
    )
    args = parser.parse_args(argv)

    manifest = RuleManifest.load(args.policy)
    if args.policy_version and args.policy_version != manifest.manifest_id:
        print(
            json.dumps(
                {
                    "error": "policy_unknown",
                    "want": args.policy_version,
                    "active": manifest.manifest_id,
                }
            )
        )
        return 2
    adapter_rule_required = any(rule.id == _ADAPTER_RULE for rule in manifest.rules)
    if not args.non_production_compat and not adapter_rule_required:
        print(
            json.dumps(
                {
                    "error": "production_manifest_lacks_adapter_enforcement",
                    "manifest_id": manifest.manifest_id,
                }
            )
        )
        return 2

    adapter_paths = (
        args.adapter_response,
        args.adapter_policy,
        args.adapter_registry,
        args.adapter_runner_signing_key,
    )
    supplied_count = sum(path is not None for path in adapter_paths)
    allowed_counts = (0, 4) if args.non_production_compat else (4,)
    if supplied_count not in allowed_counts:
        print(
            json.dumps(
                {
                    "error": "adapter_input_incomplete",
                    "required": [
                        "--adapter-response",
                        "--adapter-policy",
                        "--adapter-registry",
                        "--adapter-runner-signing-key",
                    ],
                }
            )
        )
        return 2

    adapter_records = None
    adapter_policy = None
    adapter_rebound_response = None
    if supplied_count == 4:
        try:
            adapter_records, adapter_policy, adapter_rebound_response = _load_adapter_inputs(
                response_path=args.adapter_response,
                policy_path=args.adapter_policy,
                registry_path=args.adapter_registry,
                runner_signing_key_path=args.adapter_runner_signing_key,
                run_id=args.run_id,
                tenant=args.tenant,
            )
        except ValueError as exc:
            print(json.dumps({"error": "adapter_input_rejected", "detail": str(exc)}))
            return 2

    # A v2 adapter rule without a bundle is allowed to execute only so it can issue an auditable,
    # signed NOT_READY verdict. It can never become PRODUCTION_READY because the executor rule fails.
    if adapter_rule_required and adapter_records is None:
        print(
            json.dumps(
                {
                    "warning": "adapter_bundle_missing",
                    "behavior": "run_continues_fail_closed_to_signed_NOT_READY",
                }
            )
        )

    store = EvidenceStore(args.db, args.evidence_root)
    signer = _load_signer(args.signing_key)
    entitled_raw = os.environ.get("ECHO_CERTFORGE_ENTITLED_TENANTS") or args.tenant
    entitled = frozenset(item.strip() for item in entitled_raw.split(",") if item.strip())
    subscribers = None
    if os.environ.get("ECHO_CERTFORGE_SUBSCRIBERS_ENABLED", "0") == "1":
        pepper = os.environ.get("ECHO_CERTFORGE_API_KEY_PEPPER")
        if not pepper:
            print(json.dumps({"error": "subscriber_governance_pepper_missing"}))
            return 2
        subscribers = SubscriberGovernance(
            args.db,
            SubscriberPolicy.load(args.subscriber_policy),
            pepper.encode("utf-8"),
        )
    target_spec = json.loads(args.target_json)
    journey = json.loads(args.journey_json) if args.journey_json else None
    sandbox = None
    if args.sandbox:
        sandbox = DockerSandbox(
            image=args.sandbox_image,
            docker=tuple(args.sandbox_docker.split()),
        )

    result = run(
        args.run_id,
        args.tenant,
        target_spec,
        store=store,
        manifest=manifest,
        signer=signer,
        entitled=entitled,
        subscribers=subscribers,
        journey=journey,
        sandbox=sandbox,
        adapter_records=adapter_records,
        adapter_policy=adapter_policy,
        adapter_bundle_response_sha256=(
            sha256_json(adapter_rebound_response.model_dump(mode="json"))
            if adapter_rebound_response is not None
            else None
        ),
        worker_id=args.worker_id,
        worker_attestation_sha256=args.worker_attestation_sha256,
        execution_location=args.execution_location,
        signing_authority=args.signing_authority,
    )
    print(json.dumps(result))
    return 0 if result.get("run_outcome") == RunOutcome.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
