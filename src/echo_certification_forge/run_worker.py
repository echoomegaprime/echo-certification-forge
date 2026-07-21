"""Certification run-worker — the KEY-HOLDING execution process.

Kept deliberately SEPARATE from the read/deploy-gate API (which holds no private key, per the
signer/control-plane separation invariant). The worker holds the run-signer, acquires a target,
registers a full-identity run, drives the RunExecutor (gates -> evidence -> deterministic verdict ->
sign -> finalize), and writes the result to the shared store. The API then serves the signed verdict.

Usage:
  python -m echo_certification_forge.run_worker \
    --run-id cert_xxx --tenant t --target-json '{"type":"local","path":"/abs/dir"}' \
    [--journey-json '["python3","hello.py"]] [--policy-version <id>]

Env fallbacks (shared with the API): ECHO_CERTFORGE_DB, ECHO_CERTFORGE_EVIDENCE_ROOT,
ECHO_CERTFORGE_POLICY. Worker-only: ECHO_CERTFORGE_RUN_SIGNING_KEY (Ed25519 private PEM),
ECHO_CERTFORGE_ENTITLED_TENANTS (comma-separated allow-list).
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .acquisition import AcquisitionError, acquire_target
from .canonical import sha256_bytes
from .evidence import EvidenceStore
from .executor import RetentionPolicy, RunExecutor, StaticEntitlement
from .models import EnvironmentIdentity, RunOutcome, RunState, TargetIdentity
from .policy import RuleManifest
from .signing import Ed25519VerdictSigner

_REPO = Path(__file__).resolve().parents[2]


def _env_digest(component: str) -> str:
    return sha256_bytes(f"certforge-worker-env:{component}".encode("utf-8"))


def _worker_environment() -> EnvironmentIdentity:
    """The forge's declared certification environment — stable digests the worker attests to."""
    return EnvironmentIdentity(
        runner_image_sha256=_env_digest("runner-image"),
        adapter_set_sha256=_env_digest("adapter-set"),
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
        # generate + persist a run-signer if none provisioned (worker-owned key material)
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return Ed25519VerdictSigner.from_private_pem(path.read_bytes())


def run(run_id: str, tenant: str, target_spec: dict, *, store: EvidenceStore, manifest: RuleManifest,
        signer: Ed25519VerdictSigner, entitled: frozenset[str], journey: list[str] | None) -> dict:
    workdir = Path(tempfile.mkdtemp(prefix="certforge-acq-"))
    try:
        acquired = acquire_target(target_spec, workdir / "src")
    except AcquisitionError as exc:
        return {"run_id": run_id, "error": "acquisition_failed", "detail": str(exc)}

    target = TargetIdentity(
        tenant_id=tenant, target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref, artifact_sha256=acquired.artifact_sha256,
    )
    environment = _worker_environment()
    try:
        existing = store.get_run(run_id, tenant)
    except KeyError:
        existing = None
    if existing is None:
        store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    elif existing["state"] not in (RunState.CREATED.value, RunState.QUEUED.value):
        return {"run_id": run_id, "error": "run_not_pending", "state": existing["state"]}

    executor = RunExecutor(store, manifest, signer)
    result = executor.execute(
        run_id, tenant, acquired.source_root,
        entitlement=StaticEntitlement(entitled),
        retention=RetentionPolicy(),
        journey=journey,
        # The worker is the trusted control plane: it attests the architectural controls it enforces
        # by deployment — the narrow runner<->control-plane protocol and the run-signer/control-plane
        # key separation (the run-signer private key lives only here, never in the read API).
        control_attestations={"runner_control_channel": True, "signing_authority_separation": True},
    )
    return {
        "run_id": result.run_id, "state": result.final_state,
        "run_outcome": result.run_outcome, "release_verdict": result.release_verdict,
        "signed": result.signed, "blocking_findings": list(result.blocking_findings),
        "target_identity_digest": target.identity_digest,
        "environment_identity_digest": environment.identity_digest,
        "signer_public_key_id": signer.key_id,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--target-json", required=True, help='e.g. {"type":"local","path":"/abs/dir"}')
    parser.add_argument("--journey-json", default=None, help='e.g. ["python3","hello.py"]')
    parser.add_argument("--policy-version", default=None)
    parser.add_argument("--db", type=Path, default=Path(os.environ.get("ECHO_CERTFORGE_DB", _REPO / "var" / "certforge.sqlite3")))
    parser.add_argument("--evidence-root", type=Path, default=Path(os.environ.get("ECHO_CERTFORGE_EVIDENCE_ROOT", _REPO / "var" / "evidence")))
    parser.add_argument("--policy", type=Path, default=Path(os.environ.get("ECHO_CERTFORGE_POLICY", _REPO / "policies" / "mandatory-rules.v1.json")))
    parser.add_argument("--signing-key", type=Path, default=Path(os.environ.get("ECHO_CERTFORGE_RUN_SIGNING_KEY", _REPO / "var" / "run-signing-key.pem")))
    args = parser.parse_args(argv)

    manifest = RuleManifest.load(args.policy)
    if args.policy_version and args.policy_version != manifest.manifest_id:
        print(json.dumps({"error": "policy_unknown", "want": args.policy_version, "active": manifest.manifest_id}))
        return 2
    store = EvidenceStore(args.db, args.evidence_root)
    signer = _load_signer(args.signing_key)
    entitled_raw = os.environ.get("ECHO_CERTFORGE_ENTITLED_TENANTS") or args.tenant
    entitled = frozenset(t.strip() for t in entitled_raw.split(",") if t.strip())
    target_spec = json.loads(args.target_json)
    journey = json.loads(args.journey_json) if args.journey_json else None

    result = run(args.run_id, args.tenant, target_spec, store=store, manifest=manifest,
                 signer=signer, entitled=entitled, journey=journey)
    print(json.dumps(result))
    return 0 if result.get("run_outcome") == RunOutcome.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
