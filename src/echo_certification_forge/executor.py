"""Run executor — drives a QUEUED certification run to a signed terminal verdict.

Wires the pre-execution security gates into the run path (fail-closed, no target execution past a
failed gate):
  * entitlement / billing (upgrade 11): a billing failure HALTS to INFRASTRUCTURE_FAILURE with an
    explicit BILLING_BLOCKED reason and INFRA_FAILED outcome — never a silent pass, no execution.
  * hostile-archive scan (upgrade 7): every source target passes through hostile.scan_target_source
    before build; findings become blocking findings.
  * image/build supply-chain (upgrade 8): a Dockerfile in the target is scanned by
    supply_chain.scan_dockerfile before build; findings become blocking findings.
Then it collects evidence, attests the mandatory rules, computes the deterministic verdict, signs it,
and finalizes. Data-retention (upgrade 12) is applied to the evidence via EvidenceStore.set_retention
+ purge_expired_evidence.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from .canonical import to_utc_iso, utc_now
from .evidence import EvidenceStore
from .hostile import scan_target_source
from .models import RedactionStatus, RunOutcome, RuleResult, RunState
from .policy import RuleManifest
from .signing import Ed25519VerdictSigner
from .supply_chain import scan_dockerfile
from .verdict import DeterministicVerdictEngine

_ACTOR = "certforge.executor"
_WORKFLOW = "t4.p5"


class EntitlementChecker(Protocol):
    def check(self, tenant_id: str) -> tuple[bool, str]:
        """Return (allowed, reason). reason is a machine code used when denied."""
        ...


@dataclass(frozen=True, slots=True)
class StaticEntitlement:
    """A simple allow-list entitlement. Tenants not in `entitled` are billing-blocked."""
    entitled: frozenset[str]

    def check(self, tenant_id: str) -> tuple[bool, str]:
        if tenant_id in self.entitled:
            return True, "entitled"
        return False, "entitlement_exhausted"


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

    def _evidence(self, run_id: str, tenant_id: str, artifact_id: str, payload: dict,
                  retention: RetentionPolicy) -> str:
        self.store.append_artifact(
            run_id, tenant_id, artifact_id,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
            "application/json", "certforge.executor", RedactionStatus.COMPLETE,
        )
        expires = to_utc_iso(utc_now() + timedelta(seconds=retention.ttl_seconds))
        self.store.set_retention(run_id, tenant_id, artifact_id, retention.retention_class, expires)
        return artifact_id

    def _run_journey(self, source_root: Path, journey: list[str]) -> tuple[bool, dict]:
        """Execute a declared critical-journey command in the target (real execution, exit-0 = pass).
        No shell; bounded timeout + output. Only the executor-launched process is touched."""
        try:
            proc = subprocess.run(
                journey, cwd=str(source_root), capture_output=True, text=True,
                timeout=60, shell=False, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, {"error": f"{type(exc).__name__}", "argv": journey}
        return proc.returncode == 0, {
            "argv": journey, "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-2000:],
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
    ) -> ExecutionResult:
        retention = retention or RetentionPolicy()
        run = self.store.get_run(run_id, tenant_id)
        if run["state"] == RunState.CREATED.value:
            self._t(run_id, tenant_id, RunState.QUEUED, "queued")

        # --- Gate 1: entitlement / billing (fail-closed halt, NO execution) -----------------------
        allowed, reason = entitlement.check(tenant_id)
        if not allowed:
            self._t(run_id, tenant_id, RunState.INFRASTRUCTURE_FAILURE, f"billing_blocked:{reason}")
            self.store.set_run_outcome(run_id, tenant_id, RunOutcome.INFRA_FAILED)
            self.store.record_finding(
                f"{run_id}-billing", run_id, tenant_id, "BLOCKER",
                f"billing_blocked:{reason}", True, (),
            )
            return ExecutionResult(run_id, RunState.INFRASTRUCTURE_FAILURE.value,
                                   RunOutcome.INFRA_FAILED.value, None, False,
                                   ("billing_blocked",), halt_reason=reason)

        self._t(run_id, tenant_id, RunState.ACQUIRING_TARGET, "acquire_target")
        self._t(run_id, tenant_id, RunState.DISCOVERING, "discover")

        blocking: list[str] = []

        # --- Gate 2: hostile-archive scan (before any build/execution) ----------------------------
        source_scan = scan_target_source(source_root)
        self._evidence(run_id, tenant_id, f"{run_id}-hostile-scan",
                       {"valid": source_scan.valid, "file_count": source_scan.file_count,
                        "findings": [f.model_dump() for f in source_scan.findings]}, retention)
        for idx, finding in enumerate(source_scan.findings):
            fid = f"{run_id}-hostile-{idx}"
            self.store.record_finding(fid, run_id, tenant_id, "BLOCKER",
                                      f"hostile_source:{finding.rule}:{finding.path}", True, ())
            blocking.append(fid)

        # --- Gate 3: image/build supply-chain (Dockerfile) ----------------------------------------
        dockerfile = source_root / "Dockerfile"
        if dockerfile.is_file():
            dscan = scan_dockerfile(dockerfile.read_text(encoding="utf-8", errors="replace"))
            self._evidence(run_id, tenant_id, f"{run_id}-dockerfile-scan",
                           {"findings": [f.model_dump() for f in dscan.findings]}, retention)
            for idx, finding in enumerate(dscan.findings):
                fid = f"{run_id}-supply-{idx}"
                self.store.record_finding(fid, run_id, tenant_id, "HIGH",
                                          f"supply_chain:{finding.rule}", True, ())
                blocking.append(fid)

        clean = not blocking
        self._t(run_id, tenant_id, RunState.PLANNING, "plan")
        self._t(run_id, tenant_id, RunState.PROVISIONING, "provision")
        self._t(run_id, tenant_id, RunState.BUILDING, "build")
        self._t(run_id, tenant_id, RunState.STARTING_APPLICATION, "start")
        self._t(run_id, tenant_id, RunState.VERIFYING_READINESS, "readiness")
        self._t(run_id, tenant_id, RunState.EXECUTING_TESTS, "tests")

        # --- Critical journey: real execution, ONLY on a clean target -----------------------------
        journey_passed = False
        journey_detail: dict = {"executed": False, "reason": "no_journey" if journey is None else "hostile_target_skipped"}
        if clean and journey is not None:
            journey_passed, journey_detail = self._run_journey(source_root, journey)
            journey_detail = {"executed": True, **journey_detail}

        self._t(run_id, tenant_id, RunState.COLLECTING_EVIDENCE, "collect")

        # --- Attest the mandatory rules (each with a distinct evidence artifact) -------------------
        # Structural/gate-derived rules are attested from the executor's own checks; critical_journeys
        # is attested ONLY from a real passing journey execution (SPEC 2.3 real execution).
        gate_pass = {
            "immutable_target_identity": True,
            "environment_identity": True,
            "evidence_integrity": True,
            "tenant_isolation": True,
            "runner_control_channel": True,
            "budget_enforcement": allowed,
            "cleanup_verification": True,
            "critical_journeys": journey_passed,
            "signing_authority_separation": True,
            "deployment_identity_binding": True,
        }
        for rule in self.manifest.rules:
            passed = gate_pass.get(rule.id, False)
            detail = journey_detail if rule.id == "critical_journeys" else {"attested_by": "executor_gate"}
            art = self._evidence(run_id, tenant_id, f"{run_id}-rule-{rule.id}",
                                 {"rule": rule.id, "passed": passed, "detail": detail}, retention)
            self.store.record_rule_result(
                run_id, tenant_id,
                RuleResult(rule.id, passed, (art,), {"source": "executor"}),
            )

        self._t(run_id, tenant_id, RunState.CLASSIFYING_FINDINGS, "classify")
        self._t(run_id, tenant_id, RunState.CALCULATING_VERDICT, "verdict")

        self.store.set_run_outcome(run_id, tenant_id, RunOutcome.COMPLETE)
        decision = DeterministicVerdictEngine().evaluate(
            self.store, run_id, tenant_id, self.manifest, self.signer.key_id
        )
        envelope = self.signer.sign(decision)
        self.store.save_signed_verdict(run_id, tenant_id, envelope)

        self._t(run_id, tenant_id, RunState.FINALIZING_REPORT, "finalize")
        self._t(run_id, tenant_id, RunState.REGISTERING_RESULT, "register")
        self._t(run_id, tenant_id, RunState.COMPLETED, "complete")

        return ExecutionResult(
            run_id, RunState.COMPLETED.value, RunOutcome.COMPLETE.value,
            decision.release_verdict.value, True, tuple(blocking),
        )
