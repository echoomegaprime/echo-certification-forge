"""Restart-safe transactional-outbox dispatcher for subscriber certification runs."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from .canonical import sha256_json
from .evidence import EvidenceStore
from .intake import SubmitRequest
from .policy import RuleManifest
from .run_worker import _load_adapter_inputs, _load_signer, run
from .sandbox import DEFAULT_IMAGE, DockerSandbox
from .subscriber import SubscriberDispatch, SubscriberError, SubscriberGovernance, SubscriberPolicy

_REPO = Path(__file__).resolve().parents[2]


def recover_pending_intake(
    governance: SubscriberGovernance,
    store: EvidenceStore,
    manifest: RuleManifest,
) -> int:
    recovered = 0
    for pending in governance.pending_intake_requests():
        request = SubmitRequest.model_validate(pending.request)
        governance.materialize_reserved_run(
            pending.reservation,
            run_id=request.run_id(manifest.digest),
            target_type=request.target.target_type,
            target_reference=request.target.reference,
            target_identity_digest=request.target.identity_digest,
            environment_identity_digest=request.environment.identity_digest,
            environment_json=request.environment.model_dump(exclude_none=True),
            manifest_id=manifest.manifest_id,
            manifest_digest=manifest.digest,
            target_spec=pending.target_spec,
            journey=pending.journey,
        )
        recovered += 1
    return recovered


def dispatch_once(
    governance: SubscriberGovernance,
    worker: Callable[..., dict[str, Any]],
    *,
    dispatcher_id: str,
    run_id: str | None = None,
    organization_id: str | None = None,
    worker_options: dict[str, Any] | None = None,
) -> tuple[SubscriberDispatch | None, dict[str, Any] | None]:
    options = dict(worker_options or {})
    adapter_inputs = options.pop("adapter_inputs", None)
    signer = options.get("signer")
    signing_key_id = getattr(signer, "key_id", None)
    if signing_key_id is None:
        raise ValueError("dispatcher signer is required")
    if options.get("subscribers") is not governance:
        raise ValueError("dispatcher must use its subscriber governance instance")
    store = options.get("store")
    manifest = options.get("manifest")
    if not isinstance(store, EvidenceStore) or not isinstance(manifest, RuleManifest):
        raise ValueError("dispatcher store and manifest are required")
    recover_pending_intake(governance, store, manifest)
    dispatch = governance.claim_dispatch(
        dispatcher_id,
        run_id=run_id,
        organization_id=organization_id,
        worker_id=options.get("worker_id"),
        worker_attestation_sha256=options.get("worker_attestation_sha256"),
        execution_location=str(options.get("execution_location", "local")),
        signing_authority=str(options.get("signing_authority", "platform")),
        signing_key_id=signing_key_id,
    )
    if dispatch is None:
        return None, None
    if adapter_inputs is not None:
        try:
            records, adapter_policy, rebound = _load_adapter_inputs(
                response_path=adapter_inputs["response_path"],
                policy_path=adapter_inputs["policy_path"],
                registry_path=adapter_inputs["registry_path"],
                runner_signing_key_path=adapter_inputs["runner_signing_key_path"],
                run_id=dispatch.run_id,
                tenant=dispatch.organization_id,
            )
        except ValueError as exc:
            result = {
                "run_id": dispatch.run_id,
                "error": "adapter_input_rejected",
                "detail": str(exc),
            }
            governance.finish_dispatch(dispatch, error="adapter_input_rejected")
            return dispatch, result
        options.update(
            {
                "adapter_records": records,
                "adapter_policy": adapter_policy,
                "adapter_bundle_response_sha256": sha256_json(
                    rebound.model_dump(mode="json")
                ),
            }
        )
    try:
        result = worker(
            dispatch.run_id,
            dispatch.organization_id,
            dispatch.target_spec,
            journey=dispatch.journey,
            **options,
        )
    except Exception as exc:
        governance.finish_dispatch(
            dispatch,
            error=f"dispatcher_worker_exception:{type(exc).__name__}",
        )
        raise
    error = str(result.get("error")) if result.get("error") else None
    try:
        governance.finish_dispatch(dispatch, error=error)
    except SubscriberError as exc:
        if exc.code != "dispatch_claim_inactive":
            raise
    return dispatch, result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--tenant")
    parser.add_argument(
        "--dispatcher-id",
        default=os.environ.get("ECHO_CERTFORGE_DISPATCHER_ID", "certforge-dispatcher"),
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=float(os.environ.get("ECHO_CERTFORGE_DISPATCH_POLL_SECONDS", "2")),
    )
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
    parser.add_argument("--non-production-compat", action="store_true")
    parser.add_argument(
        "--sandbox-image",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_IMAGE", DEFAULT_IMAGE),
    )
    parser.add_argument(
        "--sandbox-docker",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_DOCKER", "docker"),
    )
    parser.add_argument(
        "--adapter-response",
        type=Path,
        default=(
            Path(os.environ["ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE"])
            if os.environ.get("ECHO_CERTFORGE_PROD_ADAPTER_RESPONSE")
            else None
        ),
    )
    parser.add_argument(
        "--adapter-policy",
        type=Path,
        default=(
            Path(os.environ["ECHO_CERTFORGE_PROD_ADAPTER_POLICY"])
            if os.environ.get("ECHO_CERTFORGE_PROD_ADAPTER_POLICY")
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
        "--adapter-runner-signing-key",
        type=Path,
        default=(
            Path(os.environ["ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY"])
            if os.environ.get("ECHO_CERTFORGE_ADAPTER_RUNNER_SIGNING_KEY")
            else None
        ),
    )
    parser.add_argument("--worker-id", default=os.environ.get("ECHO_CERTFORGE_WORKER_ID"))
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
    if args.poll_seconds <= 0:
        parser.error("--poll-seconds must be positive")
    pepper = os.environ.get("ECHO_CERTFORGE_API_KEY_PEPPER")
    if not pepper:
        print(json.dumps({"error": "subscriber_governance_pepper_missing"}))
        return 2

    policy = SubscriberPolicy.load(args.subscriber_policy)
    governance = SubscriberGovernance(args.db, policy, pepper.encode("utf-8"))
    manifest = RuleManifest.load(args.policy)
    adapter_paths = (
        args.adapter_response,
        args.adapter_policy,
        args.adapter_registry,
        args.adapter_runner_signing_key,
    )
    supplied_count = sum(path is not None for path in adapter_paths)
    adapter_rule_required = any(rule.id == "adapter_identity_and_quality" for rule in manifest.rules)
    if not args.non_production_compat and (
        not adapter_rule_required or supplied_count != len(adapter_paths)
    ):
        print(json.dumps({"error": "production_adapter_inputs_unavailable"}))
        return 2
    if args.non_production_compat and supplied_count not in (0, len(adapter_paths)):
        print(json.dumps({"error": "adapter_input_incomplete"}))
        return 2
    store = EvidenceStore(args.db, args.evidence_root)
    signer = _load_signer(args.signing_key)
    sandbox = (
        DockerSandbox(
            image=args.sandbox_image,
            docker=tuple(args.sandbox_docker.split()),
        )
        if args.sandbox
        else None
    )
    options = {
        "store": store,
        "manifest": manifest,
        "signer": signer,
        "subscribers": governance,
        "sandbox": sandbox,
        "worker_id": args.worker_id,
        "worker_attestation_sha256": args.worker_attestation_sha256,
        "execution_location": args.execution_location,
        "signing_authority": args.signing_authority,
    }
    if supplied_count == len(adapter_paths):
        options["adapter_inputs"] = {
            "response_path": args.adapter_response,
            "policy_path": args.adapter_policy,
            "registry_path": args.adapter_registry,
            "runner_signing_key_path": args.adapter_runner_signing_key,
        }
    while True:
        dispatch, result = dispatch_once(
            governance,
            run,
            dispatcher_id=args.dispatcher_id,
            run_id=args.run_id,
            organization_id=args.tenant,
            worker_options=options,
        )
        if dispatch is not None:
            print(json.dumps(result, sort_keys=True))
        if args.once:
            return 0 if dispatch is not None else 3
        if dispatch is None:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
