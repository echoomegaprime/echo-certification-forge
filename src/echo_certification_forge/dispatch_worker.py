"""Restart-safe transactional-outbox dispatcher for subscriber certification runs."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from .evidence import EvidenceStore
from .intake import SubmitRequest, submit
from .policy import RuleManifest
from .run_worker import _load_signer, run
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
        _status, body = submit(
            store,
            manifest,
            request,
            pending.reservation.organization_id,
        )
        governance.bind_run(
            pending.reservation,
            str(body["run_id"]),
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
                _REPO / "policies" / "mandatory-rules.v1.json",
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
        "--sandbox-image",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_IMAGE", DEFAULT_IMAGE),
    )
    parser.add_argument(
        "--sandbox-docker",
        default=os.environ.get("ECHO_CERTFORGE_SANDBOX_DOCKER", "docker"),
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
