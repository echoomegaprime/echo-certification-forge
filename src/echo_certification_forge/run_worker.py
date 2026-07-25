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
import tempfile
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

_REPO = Path(__file__).resolve().parents[2]
_ADAPTER_RULE = "adapter_identity_and_quality"
_PRODUCTION_MANIFEST_ID = "certforge.release-strict.v2"
_PRODUCTION_MANIFEST_SHA256 = (
    "7dc98e0e95e6dd2c000ec069a8c46c4d1d49a4fe869ad4eae25e059d103644f4"
)


def _env_digest(component: str) -> str:
    return sha256_bytes(f"certforge-worker-env:{component}".encode("utf-8"))


def _worker_environment(
    adapter_set_sha256: str | None = None,
    adapter_bundle_response_sha256: str | None = None,
) -> EnvironmentIdentity:
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
        model_route_sha256=(
            sha256_json(
                {
                    "base_model_route_sha256": _env_digest("model-route"),
                    "adapter_bundle_response_sha256": adapter_bundle_response_sha256,
                }
            )
            if adapter_bundle_response_sha256
            else _env_digest("model-route")
        ),
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
    entitled: frozenset[str],
    journey: list[str] | None,
    sandbox: DockerSandbox | None = None,
    adapter_records: tuple[AdapterExecutionRecord, ...] | None = None,
    adapter_policy: AdapterAcceptancePolicy | None = None,
    adapter_bundle_response: RunnerResponse | None = None,
) -> dict:
    work_root = Path(
        os.environ.get(
            "ECHO_CERTFORGE_WORK_ROOT",
            Path.cwd() / "var" / "workspaces",
        )
    )
    work_root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="certforge-acq-", dir=work_root))
    try:
        acquired = acquire_target(target_spec, workdir / "src")
    except AcquisitionError as exc:
        return {"run_id": run_id, "error": "acquisition_failed", "detail": str(exc)}

    target = TargetIdentity(
        tenant_id=tenant,
        target_type=acquired.target_type,
        canonical_ref=acquired.canonical_ref,
        artifact_sha256=acquired.artifact_sha256,
    )
    adapter_digest = adapter_set_digest(adapter_records) if adapter_records is not None else None
    adapter_response_content = (
        (adapter_bundle_response.model_dump_json(indent=2) + "\n").encode("utf-8")
        if adapter_bundle_response is not None
        else None
    )
    adapter_response_sha256 = (
        sha256_bytes(adapter_response_content)
        if adapter_response_content is not None
        else None
    )
    environment = _worker_environment(adapter_digest, adapter_response_sha256)
    try:
        existing = store.get_run(run_id, tenant)
    except KeyError:
        existing = None
    if existing is None:
        store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    elif existing["state"] not in (RunState.CREATED.value, RunState.QUEUED.value):
        return {"run_id": run_id, "error": "run_not_pending", "state": existing["state"]}
    if adapter_response_content is not None:
        store.append_artifact(
            run_id,
            tenant,
            "adapter-bundle-response",
            adapter_response_content,
            "application/json",
            "run-worker",
        )

    executor = RunExecutor(store, manifest, signer)
    journey_runner = sandboxed_journey_runner(sandbox) if sandbox is not None else None
    result = executor.execute(
        run_id,
        tenant,
        acquired.source_root,
        entitlement=StaticEntitlement(entitled),
        retention=RetentionPolicy(),
        journey=journey,
        journey_runner=journey_runner,
        control_attestations={
            "runner_control_channel": True,
            "signing_authority_separation": True,
        },
        adapter_records=adapter_records,
        adapter_policy=adapter_policy,
    )
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
        "adapter_bundle_response_sha256": adapter_response_sha256,
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
            raise ValueError(
                "adapter runner signing key differs from independent registry"
            )
        trust_binding = AdapterBundleTrustBinding(**registry.trust_roots)
        rebound = sign_adapter_bundle(
            records,
            run_id=run_id,
            tenant_id=tenant,
            trust_binding=trust_binding,
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
    trusted_manifest_sha256 = os.environ.get(
        "ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256",
        _PRODUCTION_MANIFEST_SHA256,
    )
    if not args.non_production_compat and (
        manifest.manifest_id != _PRODUCTION_MANIFEST_ID
        or manifest.digest != trusted_manifest_sha256
    ):
        print(
            json.dumps(
                {
                    "error": "production_manifest_identity_mismatch",
                    "manifest_id": manifest.manifest_id,
                    "manifest_sha256": manifest.digest,
                }
            )
        )
        return 2
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
        journey=journey,
        sandbox=sandbox,
        adapter_records=adapter_records,
        adapter_policy=adapter_policy,
        adapter_bundle_response=adapter_rebound_response,
    )
    print(json.dumps(result))
    return 0 if result.get("run_outcome") == RunOutcome.COMPLETE.value else 1


if __name__ == "__main__":
    raise SystemExit(main())
