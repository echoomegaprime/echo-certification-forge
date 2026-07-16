"""Reproducible P1 acceptance scenarios and evidence report generator."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.models import EnvironmentIdentity, RedactionStatus, RuleResult, RunOutcome, TargetIdentity
from echo_certification_forge.policy import RuleManifest
from echo_certification_forge.signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry
from echo_certification_forge.verdict import DeterministicVerdictEngine


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def identities() -> tuple[TargetIdentity, EnvironmentIdentity]:
    return (
        TargetIdentity(
            tenant_id="acceptance-tenant",
            target_type="archive",
            canonical_ref="fixture://p1-known-good",
            artifact_sha256=digest("fixture-archive"),
            dependency_sha256=digest("fixture-lock"),
            configuration_sha256=digest("fixture-config"),
        ),
        EnvironmentIdentity(
            runner_image_sha256=digest("runner"), adapter_set_sha256=digest("adapters"),
            test_plan_sha256=digest("plan"), policy_sha256=digest("policy"),
            harness_sha256=digest("harness"), prompt_set_sha256=digest("prompts"),
            model_route_sha256=digest("models"), os_runtime_sha256=digest("runtime"),
            egress_policy_sha256=digest("egress"),
        ),
    )


def main() -> int:
    manifest = RuleManifest.load(REPO / "policies" / "mandatory-rules.v1.json")
    workspace = Path(tempfile.mkdtemp(prefix="certforge-p1-"))
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "phase": "P1",
        "python": sys.version,
        "platform": platform.platform(),
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.digest,
        "scenarios": {},
    }
    try:
        store = EvidenceStore(workspace / "db.sqlite3", workspace / "evidence")
        target, environment = identities()
        signer = Ed25519VerdictSigner.generate()
        engine = DeterministicVerdictEngine()

        store.register_run("cert-default-block", target, environment, manifest.manifest_id, manifest.digest)
        default = engine.evaluate(store, "cert-default-block", target.tenant_id, manifest, signer.key_id)
        report["scenarios"]["default_block"] = {
            "passed": default.release_verdict.value == "NOT_READY",
            "verdict": default.release_verdict.value,
            "reasons": list(default.reasons),
        }

        store.register_run("cert-verified-ready", target, environment, manifest.manifest_id, manifest.digest)
        for index, rule in enumerate(manifest.rules, start=1):
            artifact_id = f"proof-{index:02d}"
            content = json.dumps({"rule": rule.id, "passed": True}, sort_keys=True).encode()
            store.append_artifact(
                "cert-verified-ready", target.tenant_id, artifact_id, content,
                "application/json", "p1-independent-harness", RedactionStatus.COMPLETE,
            )
            store.record_rule_result(
                "cert-verified-ready", target.tenant_id,
                RuleResult(rule.id, True, (artifact_id,), {"fixture": "known-good"}),
            )
        store.set_run_outcome("cert-verified-ready", target.tenant_id, RunOutcome.COMPLETE)
        ready = engine.evaluate(store, "cert-verified-ready", target.tenant_id, manifest, signer.key_id)
        envelope = signer.sign(ready)
        store.save_signed_verdict("cert-verified-ready", target.tenant_id, envelope)
        trusted = TrustedPublicKeyRegistry.empty()
        trusted.add_pem(signer.public_key_pem)
        gate = DeployGate(store, trusted).evaluate(
            target.tenant_id, "cert-verified-ready", target.identity_digest,
            environment.identity_digest, manifest.digest,
        )
        report["scenarios"]["verified_ready"] = {
            "passed": ready.release_verdict.value == "PRODUCTION_READY" and gate.allowed,
            "verdict": ready.release_verdict.value,
            "deploy_gate_allowed": gate.allowed,
            "evidence_merkle_root": ready.evidence_merkle_root,
            "payload_sha256": envelope.payload_sha256,
            "signing_key_id": envelope.key_id,
        }

        tampered_path = workspace / "evidence" / target.tenant_id / "cert-verified-ready" / "artifacts" / "proof-01.bin"
        tampered_path.write_bytes(b"tampered")
        tampered_gate = DeployGate(store, trusted).evaluate(
            target.tenant_id, "cert-verified-ready", target.identity_digest,
            environment.identity_digest, manifest.digest,
        )
        report["scenarios"]["tamper_blocks"] = {
            "passed": not tampered_gate.allowed,
            "deploy_gate_allowed": tampered_gate.allowed,
            "reasons": list(tampered_gate.reasons),
        }

        report["passed"] = all(item["passed"] for item in report["scenarios"].values())
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        artifacts = REPO / "artifacts"
        artifacts.mkdir(exist_ok=True)
        output = artifacts / "p1_acceptance_report.json"
        output.write_text(encoded, encoding="utf-8", newline="\n")
        print(encoded, end="")
        return 0 if report["passed"] else 1
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
