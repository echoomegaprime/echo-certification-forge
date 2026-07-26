"""Build a signed P5 adapter execution bundle from ANVIL evidence."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from echo_certification_forge.adapter_execution import (  # noqa: E402
    AdapterBundleTrustBinding,
    AdapterEvidenceSource,
    build_acceptance_report,
    build_records_from_evidence,
    default_p5_policy,
    external_trust_pins_digest,
    policy_to_json,
    r5_trust_pins_digest,
    load_json,
    load_adapter_runner_identity,
    sign_adapter_bundle,
    write_adapter_execution_artifacts,
)
from echo_certification_forge.adapter_registry import (  # noqa: E402
    parse_trusted_adapter_registry,
)
from echo_certification_forge.canonical import sha256_json  # noqa: E402
from echo_certification_forge.family_r5 import RECEIPT_SCHEMA  # noqa: E402
from echo_certification_forge.p5_qualification import (  # noqa: E402
    QualificationArtifactDigests,
    QualificationEvidenceTrustPins,
    QualificationModels,
    RoutingDeploymentIdentity,
    TrustedRoutingKey,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--adapter-registry-id", required=True)
    parser.add_argument("--adapter-policy-id", required=True)
    parser.add_argument("--adapter-runner-signing-key", required=True, type=Path)
    parser.add_argument("--qualification-report", required=True, type=Path)
    parser.add_argument("--gs343-r5-evidence", required=True, type=Path)
    parser.add_argument("--r2d2-r5-evidence", required=True, type=Path)
    parser.add_argument(
        "--trusted-qualification-public-key", required=True, type=Path
    )
    parser.add_argument("--trusted-qualification-key-id", required=True)
    parser.add_argument("--gs343-r5-public-key", required=True, type=Path)
    parser.add_argument("--gs343-r5-key-id", required=True)
    parser.add_argument("--gs343-r5-run-id", required=True)
    parser.add_argument("--gs343-r5-run-nonce", required=True)
    parser.add_argument("--r2d2-r5-public-key", required=True, type=Path)
    parser.add_argument("--r2d2-r5-key-id", required=True)
    parser.add_argument("--r2d2-r5-run-id", required=True)
    parser.add_argument("--r2d2-r5-run-nonce", required=True)
    parser.add_argument("--gs-candidate-sha256", required=True)
    parser.add_argument("--gs-incumbent-sha256", required=True)
    parser.add_argument("--r2-candidate-sha256", required=True)
    parser.add_argument("--r2-incumbent-sha256", required=True)
    parser.add_argument("--gs343-model", required=True)
    parser.add_argument("--gs343-incumbent-model", required=True)
    parser.add_argument("--r2d2-model", required=True)
    parser.add_argument("--r2d2-incumbent-model", required=True)
    parser.add_argument("--server-build-sha256", required=True)
    parser.add_argument("--registry-snapshot-sha256", required=True)
    parser.add_argument("--registry-revision", required=True)
    parser.add_argument("--base-model-id", required=True)
    parser.add_argument("--base-model-revision", required=True)
    parser.add_argument("--base-model-sha256", required=True)
    parser.add_argument("--gs343-quality-mode", default="gs_adapter_context")
    parser.add_argument("--r2d2-quality-mode", default="r2_adapter_context")
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()

    qualification_report = load_json(args.qualification_report)
    if qualification_report.get("schema") == "echo.certification-forge.p5-qualification/v1":
        try:
            gs343_model = qualification_report["models"]["gs343"]["candidate"]
            r2d2_model = qualification_report["models"]["r2d2"]["candidate"]
        except (KeyError, TypeError) as exc:
            raise SystemExit("new P5 qualification report lacks candidate model bindings") from exc
        if args.gs343_model != gs343_model:
            raise SystemExit("--gs343-model differs from qualification report candidate")
        if args.r2d2_model != r2d2_model:
            raise SystemExit("--r2d2-model differs from qualification report candidate")
        if args.gs343_incumbent_model != qualification_report["models"]["gs343"]["incumbent"]:
            raise SystemExit("--gs343-incumbent-model differs from qualification report")
        if args.r2d2_incumbent_model != qualification_report["models"]["r2d2"]["incumbent"]:
            raise SystemExit("--r2d2-incumbent-model differs from qualification report")
    else:
        raise SystemExit("legacy qualification reports are not eligible")

    artifact_digests = QualificationArtifactDigests(
        gs_candidate=args.gs_candidate_sha256,
        gs_incumbent=args.gs_incumbent_sha256,
        r2_candidate=args.r2_candidate_sha256,
        r2_incumbent=args.r2_incumbent_sha256,
    )
    qualification_trust_pins = QualificationEvidenceTrustPins(
        routing_key=TrustedRoutingKey(
            args.trusted_qualification_public_key.read_text(encoding="ascii"),
            args.trusted_qualification_key_id,
        ),
        artifact_digests=artifact_digests,
        deployment_identity=RoutingDeploymentIdentity(
            models=QualificationModels(
                gs_candidate=args.gs343_model,
                gs_incumbent=args.gs343_incumbent_model,
                r2_candidate=args.r2d2_model,
                r2_incumbent=args.r2d2_incumbent_model,
            ),
            receipt_schema=RECEIPT_SCHEMA,
            server_build_digest=args.server_build_sha256,
            registry_snapshot_digest=args.registry_snapshot_sha256,
            registry_revision=args.registry_revision,
            base_model_id=args.base_model_id,
            base_model_revision=args.base_model_revision,
            base_model_digest=args.base_model_sha256,
        ),
    )
    sources = (
        AdapterEvidenceSource(
            "gs343",
            gs343_model,
            args.gs343_r5_evidence,
            args.gs343_quality_mode,
            TrustedRoutingKey(
                args.gs343_r5_public_key.read_text(encoding="ascii"),
                args.gs343_r5_key_id,
            ),
            args.gs343_r5_run_id,
            args.gs343_r5_run_nonce,
        ),
        AdapterEvidenceSource(
            "r2d2",
            r2d2_model,
            args.r2d2_r5_evidence,
            args.r2d2_quality_mode,
            TrustedRoutingKey(
                args.r2d2_r5_public_key.read_text(encoding="ascii"),
                args.r2d2_r5_key_id,
            ),
            args.r2d2_r5_run_id,
            args.r2d2_r5_run_nonce,
        ),
    )
    records = build_records_from_evidence(
        sources,
        qualification_report=qualification_report,
        qualification_trust_pins=qualification_trust_pins,
    )
    policy = default_p5_policy(records)
    runner_identity = load_adapter_runner_identity(args.adapter_runner_signing_key)
    trust_binding = AdapterBundleTrustBinding(
        registry_id=args.adapter_registry_id,
        runner_key_id=runner_identity.key_id,
        policy_id=args.adapter_policy_id,
        policy_sha256=sha256_json(policy_to_json(policy)),
        qualification_trust_pins_sha256=qualification_trust_pins.digest,
        r5_trust_pins_sha256=r5_trust_pins_digest(
            sources,
            qualification_trust_pins.deployment_identity.to_dict(),
        ),
        external_trust_pins_sha256=external_trust_pins_digest(
            qualification_trust_pins,
            sources,
        ),
    )
    signed = sign_adapter_bundle(
        records,
        run_id=args.run_id,
        tenant_id=args.tenant_id,
        trust_binding=trust_binding,
        runner_identity=runner_identity,
    )
    report = build_acceptance_report(
        signed.response,
        signed.runner_public_key_pem,
        run_id=args.run_id,
        tenant_id=args.tenant_id,
        policy=policy,
        expected_adapter_set_sha256=signed.adapter_set_sha256,
        trust_binding=trust_binding,
    )
    write_adapter_execution_artifacts(
        args.output_directory,
        signed_bundle=signed,
        acceptance_report=report,
        policy=policy,
    )
    registry = {
        "schema_version": "1.0.0",
        "registry_id": trust_binding.registry_id,
        "runner": {
            "runner_id": "anvil-adapter-runner",
            "key_id": trust_binding.runner_key_id,
            "public_key_pem": signed.runner_public_key_pem,
        },
        "policy": {
            "policy_id": trust_binding.policy_id,
            "sha256": trust_binding.policy_sha256,
        },
        "qualification_trust_pins_sha256": (
            trust_binding.qualification_trust_pins_sha256
        ),
        "r5_trust_pins_sha256": trust_binding.r5_trust_pins_sha256,
        "external_trust_pins_sha256": trust_binding.external_trust_pins_sha256,
        "reusable_bundle": {
            "run_id": signed.response.run_id,
            "tenant_id": signed.response.tenant_id,
            "sha256": sha256_json(signed.response.model_dump(mode="json")),
        },
    }
    parse_trusted_adapter_registry(registry)
    (args.output_directory / "trusted-adapter-registry.json").write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["adapter_gate_eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
