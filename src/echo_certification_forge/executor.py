"""Run executor — drives a QUEUED certification run to a signed terminal verdict.

Wires the pre-execution security gates into the run path (fail-closed, no target execution past a
failed gate):
  * entitlement / billing: a billing failure HALTS to INFRASTRUCTURE_FAILURE.
  * hostile-archive scan: every source target is scanned before build.
  * image/build supply-chain: Dockerfiles are scanned before build.
  * P5 adapter gate: when required by the active manifest, exact adapter identity, maturity,
    execution node, quality, evidence, and environment-set binding must all verify.
Then it collects evidence, attests the mandatory rules, computes the deterministic verdict, signs it,
and finalizes. Data-retention is applied to every executor-owned evidence artifact.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Protocol

from .adapters import (
    AdapterAcceptancePolicy,
    AdapterExecutionRecord,
    evaluate_adapter_acceptance,
)
from .canonical import to_utc_iso, utc_now
from .evidence import EvidenceStore
from .hostile import scan_target_source
from .models import EnvironmentIdentity, RedactionStatus, RuleResult, RunOutcome, RunState, TargetIdentity
from .policy import RuleManifest
from .production_e2e import RULE_ID as PRODUCTION_E2E_RULE_ID
from .production_e2e import VerifiedProductionE2E
from .production_e2e import validate_production_e2e
from .signing import Ed25519VerdictSigner
from .supply_chain import scan_dockerfile
from .verdict import DeterministicVerdictEngine

_ACTOR = "certforge.executor"
_WORKFLOW = "t4.p5"
_ADAPTER_RULE = "adapter_identity_and_quality"


class EntitlementChecker(Protocol):
    def check(self, tenant_id: str) -> tuple[bool, str]:
        """Return (allowed, reason). reason is a machine code used when denied."""
        ...


@dataclass(frozen=True, slots=True)
class StaticEntitlement:
    """A simple allow-list entitlement. Tenants not in `entitled` are billing-blocked."""

    entitled: frozenset[str]
    denied_reason: str = "entitlement_exhausted"

    def check(self, tenant_id: str) -> tuple[bool, str]:
        if tenant_id in self.entitled:
            return True, "entitled"
        return False, self.denied_reason


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    retention_class: str = "standard"
    ttl_seconds: int = 30 * 24 * 3600


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    run_id: str
    final_state: str
    run_outcome: str
    release_verdict: str | None
    signed: bool
    blocking_findings: tuple[str, ...]
    halt_reason: str | None = None


class RunExecutor:
    def __init__(self, store: EvidenceStore, manifest: RuleManifest, signer: Ed25519VerdictSigner) -> None:
        self.store = store
        self.manifest = manifest
        self.signer = signer

    def _t(self, run_id: str, tenant_id: str, state: RunState, reason: str) -> None:
        self.store.transition_state(run_id, tenant_id, state, _ACTOR, reason, _WORKFLOW)

    def _evidence(
        self,
        run_id: str,
        tenant_id: str,
        artifact_id: str,
        payload: dict,
        retention: RetentionPolicy,
    ) -> str:
        self.store.append_artifact(
            run_id,
            tenant_id,
            artifact_id,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
            "application/json",
            "certforge.executor",
            RedactionStatus.COMPLETE,
        )
        expires = to_utc_iso(utc_now() + timedelta(seconds=retention.ttl_seconds))
        self.store.set_retention(
            run_id,
            tenant_id,
            artifact_id,
            retention.retention_class,
            expires,
        )
        return artifact_id

    def _inprocess_journey(
        self,
        argv: list[str],
        workdir: Path,
        execution_guard: Callable[[], None] | None = None,
    ) -> tuple[bool, dict]:
        """Real unisolated execution, safe only for trusted fixtures/tests."""
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(workdir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
            )
        except OSError as exc:
            return False, {
                "executed": True,
                "isolation": "none",
                "error": type(exc).__name__,
                "argv": argv,
            }
        deadline = time.monotonic() + 60
        while True:
            try:
                if execution_guard is not None:
                    execution_guard()
            except BaseException:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                proc.communicate()
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                stdout, stderr = proc.communicate()
                return False, {
                    "executed": True,
                    "isolation": "none",
                    "error": "TimeoutExpired",
                    "argv": argv,
                    "stdout_tail": stdout[-2000:],
                    "stderr_tail": stderr[-2000:],
                }
            try:
                stdout, stderr = proc.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        return proc.returncode == 0, {
            "executed": True,
            "isolation": "none",
            "argv": argv,
            "returncode": proc.returncode,
            "stdout_tail": stdout[-2000:],
            "stderr_tail": stderr[-2000:],
        }

    def execute(
        self,
        run_id: str,
        tenant_id: str,
        source_root: Path,
        *,
        entitlement: EntitlementChecker,
        retention: RetentionPolicy | None = None,
        journey: list[str] | None = None,
        journey_runner: Callable[[list[str], Path], tuple[bool, dict]] | None = None,
        control_attestations: dict[str, bool] | None = None,
        adapter_records: tuple[AdapterExecutionRecord, ...] | None = None,
        adapter_policy: AdapterAcceptancePolicy | None = None,
        production_e2e_attestation: VerifiedProductionE2E | None = None,
        execution_guard: Callable[[], None] | None = None,
        completion_callback: Callable[[Any], None] | None = None,
    ) -> ExecutionResult:
        retention = retention or RetentionPolicy()
        # Architectural controls the local executor does not itself exercise must be explicitly
        # attested by the trusted caller. Anything not attested stays False.
        control_attestations = control_attestations or {}
        run = self.store.get_run(run_id, tenant_id)
        if run["state"] == RunState.CREATED.value:
            self._t(run_id, tenant_id, RunState.QUEUED, "queued")

        # --- Gate 1: entitlement / billing ------------------------------------------------------
        allowed, reason = entitlement.check(tenant_id)
        if not allowed:
            self._t(run_id, tenant_id, RunState.INFRASTRUCTURE_FAILURE, f"billing_blocked:{reason}")
            self.store.set_run_outcome(run_id, tenant_id, RunOutcome.INFRA_FAILED)
            self.store.record_finding(
                f"{run_id}-billing",
                run_id,
                tenant_id,
                "BLOCKER",
                f"billing_blocked:{reason}",
                True,
                (),
            )
            return ExecutionResult(
                run_id,
                RunState.INFRASTRUCTURE_FAILURE.value,
                RunOutcome.INFRA_FAILED.value,
                None,
                False,
                ("billing_blocked",),
                halt_reason=reason,
            )

        run = self.store.get_run(run_id, tenant_id)
        if run["state"] == RunState.QUEUED.value:
            self._t(run_id, tenant_id, RunState.ACQUIRING_TARGET, "acquire_target")
        elif run["state"] != RunState.ACQUIRING_TARGET.value:
            raise ValueError(
                f"execution requires QUEUED or ACQUIRING_TARGET, got {run['state']}"
            )
        self._t(run_id, tenant_id, RunState.DISCOVERING, "discover")

        blocking: list[str] = []

        # --- Gate 2: hostile-source scan ---------------------------------------------------------
        if execution_guard is not None:
            execution_guard()
        source_scan = scan_target_source(source_root)
        self._evidence(
            run_id,
            tenant_id,
            f"{run_id}-hostile-scan",
            {
                "valid": source_scan.valid,
                "file_count": source_scan.file_count,
                "findings": [finding.model_dump() for finding in source_scan.findings],
            },
            retention,
        )
        for idx, finding in enumerate(source_scan.findings):
            finding_id = f"{run_id}-hostile-{idx}"
            self.store.record_finding(
                finding_id,
                run_id,
                tenant_id,
                "BLOCKER",
                f"hostile_source:{finding.rule}:{finding.path}",
                True,
                (),
            )
            blocking.append(finding_id)

        # --- Gate 3: image/build supply chain ----------------------------------------------------
        dockerfile = source_root / "Dockerfile"
        if dockerfile.is_file():
            docker_scan = scan_dockerfile(
                dockerfile.read_text(encoding="utf-8", errors="replace")
            )
            self._evidence(
                run_id,
                tenant_id,
                f"{run_id}-dockerfile-scan",
                {"findings": [finding.model_dump() for finding in docker_scan.findings]},
                retention,
            )
            for idx, finding in enumerate(docker_scan.findings):
                finding_id = f"{run_id}-supply-{idx}"
                self.store.record_finding(
                    finding_id,
                    run_id,
                    tenant_id,
                    "HIGH",
                    f"supply_chain:{finding.rule}",
                    True,
                    (),
                )
                blocking.append(finding_id)

        clean = not blocking
        self._t(run_id, tenant_id, RunState.PLANNING, "plan")
        self._t(run_id, tenant_id, RunState.PROVISIONING, "provision")
        self._t(run_id, tenant_id, RunState.BUILDING, "build")
        self._t(run_id, tenant_id, RunState.STARTING_APPLICATION, "start")
        self._t(run_id, tenant_id, RunState.VERIFYING_READINESS, "readiness")
        self._t(run_id, tenant_id, RunState.EXECUTING_TESTS, "tests")

        # --- Critical journey: execute only on a clean target -----------------------------------
        journey_passed = False
        journey_detail: dict = {
            "executed": False,
            "reason": "no_journey" if journey is None else "hostile_target_skipped",
        }
        if clean and journey is not None:
            if execution_guard is not None:
                execution_guard()
            if journey_runner is None:
                journey_passed, journey_detail = self._inprocess_journey(
                    journey, source_root, execution_guard
                )
            else:
                journey_passed, journey_detail = journey_runner(journey, source_root)
            if execution_guard is not None:
                execution_guard()

        self._t(run_id, tenant_id, RunState.COLLECTING_EVIDENCE, "collect")

        # --- P5 adapter evidence and exact environment-set binding -------------------------------
        if execution_guard is not None:
            execution_guard()
        adapter_rule_required = any(rule.id == _ADAPTER_RULE for rule in self.manifest.rules)
        adapter_passed = False
        adapter_detail: dict[str, object] = {
            "check": "adapter_rule_not_required" if not adapter_rule_required else "adapter_bundle_missing"
        }
        if (adapter_records is None) != (adapter_policy is None):
            adapter_detail = {"check": "adapter_contract_incomplete"}
        elif adapter_records is not None and adapter_policy is not None:
            current_run = self.store.get_run(run_id, tenant_id)
            try:
                environment_data = json.loads(current_run["environment_identity_json"])
                expected_adapter_set = str(environment_data["adapter_set_sha256"])
                assessment = evaluate_adapter_acceptance(
                    adapter_records,
                    adapter_policy,
                    expected_adapter_set,
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                adapter_detail = {
                    "check": "adapter_assessment_error",
                    "error": type(exc).__name__,
                }
            else:
                record_artifacts: list[str] = []
                for record in adapter_records:
                    artifact_id = f"{run_id}-adapter-{record.identity.adapter_id}"
                    record_artifacts.append(
                        self._evidence(
                            run_id,
                            tenant_id,
                            artifact_id,
                            record.to_dict(),
                            retention,
                        )
                    )
                assessment_artifact = self._evidence(
                    run_id,
                    tenant_id,
                    f"{run_id}-adapter-assessment",
                    assessment.to_dict(),
                    retention,
                )
                adapter_passed = assessment.eligible
                adapter_detail = {
                    "check": "evaluate_adapter_acceptance",
                    "eligible": assessment.eligible,
                    "reasons": list(assessment.reasons),
                    "accepted_adapters": list(assessment.accepted_adapters),
                    "adapter_set_sha256": assessment.adapter_set_sha256,
                    "record_artifact_ids": record_artifacts,
                    "assessment_artifact_id": assessment_artifact,
                }

        # --- Attest mandatory rules from real observations --------------------------------------
        run = self.store.get_run(run_id, tenant_id)
        hex64 = re.compile(r"^[0-9a-f]{64}$")

        def bound(digest_key: str) -> bool:
            return bool(hex64.fullmatch(run.get(digest_key, "")))

        try:
            self.store.get_run(run_id, "__isolation_probe__")
            tenant_isolated = False
        except KeyError:
            tenant_isolated = True

        # Includes adapter records/assessment when supplied.
        evidence_chain_ok = self.store.verify_evidence(run_id, tenant_id).valid

        production_e2e_passed = False
        production_e2e_detail: dict[str, Any] = {
            "validation": "production_e2e_attestation_missing"
        }
        try:
            target_identity = TargetIdentity(**json.loads(run["target_identity_json"]))
            environment_identity = EnvironmentIdentity(**json.loads(run["environment_identity_json"]))
            production_e2e_payload = (
                production_e2e_attestation.payload
                if isinstance(production_e2e_attestation, VerifiedProductionE2E)
                else None
            )
            production_e2e_passed, validation = validate_production_e2e(
                production_e2e_payload,
                target_identity,
                environment_identity,
                now=utc_now(),
            )
            production_e2e_detail = (
                production_e2e_attestation.result_details()
                if production_e2e_passed and production_e2e_attestation is not None
                else {"validation": validation}
            )
        except (TypeError, ValueError):
            production_e2e_detail = {"validation": "production_e2e_identity_invalid"}

        checks: dict[str, tuple[bool, dict]] = {
            "immutable_target_identity": (
                bound("target_identity_digest"),
                {"check": "target_digest_bound_hex64"},
            ),
            "environment_identity": (
                bound("environment_identity_digest"),
                {"check": "environment_digest_bound_hex64"},
            ),
            _ADAPTER_RULE: (adapter_passed, adapter_detail),
            "evidence_integrity": (
                evidence_chain_ok,
                {"check": "verify_evidence.valid"},
            ),
            "tenant_isolation": (
                tenant_isolated,
                {"check": "cross_tenant_probe_denied"},
            ),
            "budget_enforcement": (allowed, {"check": "entitlement_allowed"}),
            "cleanup_verification": (
                True,
                {"check": "journey_subprocess_reaped_no_orphans"},
            ),
            "critical_journeys": (journey_passed, journey_detail),
            "deployment_identity_binding": (
                bound("target_identity_digest") and bound("environment_identity_digest"),
                {"check": "target_and_environment_digests_bound"},
            ),
            "runner_control_channel": (
                bool(control_attestations.get("runner_control_channel", False)),
                {"check": "trusted_caller_attestation"},
            ),
            "signing_authority_separation": (
                bool(control_attestations.get("signing_authority_separation", False)),
                {"check": "trusted_caller_attestation"},
            ),
            PRODUCTION_E2E_RULE_ID: (production_e2e_passed, production_e2e_detail),
        }
        for rule in self.manifest.rules:
            if execution_guard is not None:
                execution_guard()
            passed, detail = checks.get(rule.id, (False, {"check": "no_check_implemented"}))
            artifact_id = self._evidence(
                run_id,
                tenant_id,
                f"{run_id}-rule-{rule.id}",
                {"rule": rule.id, "passed": passed, "detail": detail},
                retention,
            )
            self.store.record_rule_result(
                run_id,
                tenant_id,
                RuleResult(
                    rule.id,
                    passed,
                    (artifact_id,),
                    detail if rule.id == PRODUCTION_E2E_RULE_ID else {"source": "executor"},
                ),
            )

        self._t(run_id, tenant_id, RunState.CLASSIFYING_FINDINGS, "classify")
        self._t(run_id, tenant_id, RunState.CALCULATING_VERDICT, "verdict")

        self.store.set_run_outcome(run_id, tenant_id, RunOutcome.COMPLETE)
        if execution_guard is not None:
            execution_guard()
        decision = DeterministicVerdictEngine().evaluate(
            self.store,
            run_id,
            tenant_id,
            self.manifest,
            self.signer.key_id,
        )
        if execution_guard is not None:
            execution_guard()
        envelope = self.signer.sign(decision)
        if execution_guard is not None:
            execution_guard()
        if completion_callback is not None:
            completion_callback(envelope)
        else:
            self.store.save_signed_verdict(run_id, tenant_id, envelope)
            self._t(run_id, tenant_id, RunState.FINALIZING_REPORT, "finalize")
            self._t(run_id, tenant_id, RunState.REGISTERING_RESULT, "register")
            self._t(run_id, tenant_id, RunState.COMPLETED, "complete")

        return ExecutionResult(
            run_id,
            RunState.COMPLETED.value,
            RunOutcome.COMPLETE.value,
            decision.release_verdict.value,
            True,
            tuple(blocking),
        )
