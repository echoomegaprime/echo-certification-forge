#!/usr/bin/env python3
"""Serve P5 incumbent and candidate adapters without changing production aliases."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REGISTRY_SCHEMA = "echo.family-adapter-registry-snapshot/v1"
MODEL_FILENAME = "adapter_model.safetensors"
CONFIG_FILENAME = "adapter_config.json"


@dataclass(frozen=True)
class EvalAdapter:
    requested_model: str
    persona_id: str
    evaluation_role: str
    relative_path: str


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def adapter_bundle_digest(model_digest: str, config_digest: str) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "adapter_config_sha256": config_digest,
                "adapter_model_sha256": model_digest,
            }
        )
    ).hexdigest()


def resolve_adapter(root: Path, relative_path: str) -> tuple[Path, str, str, str]:
    root = root.resolve()
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"adapter path escapes root: {relative_path}")
    model_path = candidate / MODEL_FILENAME
    config_path = candidate / CONFIG_FILENAME
    if not model_path.is_file() or not config_path.is_file():
        raise FileNotFoundError(
            f"adapter requires {MODEL_FILENAME} and {CONFIG_FILENAME}: {candidate}"
        )
    model_digest = sha256_file(model_path)
    config_digest = sha256_file(config_path)
    return (
        candidate,
        model_digest,
        config_digest,
        adapter_bundle_digest(model_digest, config_digest),
    )


def build_registry(
    adapter_root: Path,
    adapters: tuple[EvalAdapter, ...],
) -> tuple[dict[str, Any], dict[str, str]]:
    if len({item.requested_model for item in adapters}) != len(adapters):
        raise ValueError("evaluation adapter aliases must be unique")

    resolved: list[dict[str, str]] = []
    adapter_map: dict[str, str] = {}
    for adapter in adapters:
        _, model_digest, config_digest, bundle_digest = resolve_adapter(
            adapter_root,
            adapter.relative_path,
        )
        adapter_map[adapter.requested_model] = adapter.relative_path
        resolved.append(
            {
                "requested_model": adapter.requested_model,
                "persona_id": adapter.persona_id,
                "evaluation_role": adapter.evaluation_role,
                "relative_path": adapter.relative_path,
                "adapter_artifact_digest": model_digest,
                "adapter_config_digest": config_digest,
                "adapter_bundle_digest": bundle_digest,
            }
        )

    revision = hashlib.sha256(canonical_json(resolved)).hexdigest()
    personas = [
        {
            "persona_id": row["persona_id"],
            "requested_model": row["requested_model"],
            "adapter_id": row["requested_model"],
            "adapter_artifact_digest": row["adapter_artifact_digest"],
            "adapter_config_digest": row["adapter_config_digest"],
            "adapter_bundle_digest": row["adapter_bundle_digest"],
            "adapter_version": f"certforge-p5-{row['evaluation_role']}",
            "maturity_state": (
                "INCUMBENT_CONTROL"
                if row["evaluation_role"] == "incumbent"
                else "EVALUATION_CANDIDATE"
            ),
            "enabled": True,
            "registry_revision": revision,
            "evaluation_role": row["evaluation_role"],
            "adapter_relative_path": row["relative_path"],
        }
        for row in resolved
    ]
    registry = {
        "schema": REGISTRY_SCHEMA,
        "snapshot_id": f"certforge-p5-eval-{revision[:16]}",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "registry_revision": revision,
        "personas": personas,
    }
    return registry, adapter_map


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def create_isolated_output_dir(path: Path, protected_paths: tuple[Path, ...]) -> Path:
    output = path.resolve()
    for protected_path in protected_paths:
        protected = protected_path.resolve()
        if (
            output == protected
            or protected in output.parents
            or output in protected.parents
        ):
            raise ValueError(f"evaluation output overlaps protected path: {protected}")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    return output


def configure_family_module(
    family: Any,
    *,
    adapter_root: Path,
    adapter_map: dict[str, str],
    registry_path: Path,
    private_key_path: Path,
    public_key_path: Path,
    base_revision_path: Path,
    wrapper_path: Path,
    audit_path: Path,
) -> None:
    family.ADAPTER_DIR = str(adapter_root)
    family.ADAPTERS = dict(adapter_map)
    family._MEMORY_GROUND_ENABLED = False

    class EvalRoutingAttestor(family.RoutingAttestor):
        def _config_digest(self, requested_model: str) -> str:
            relative = self.adapter_map[requested_model]
            return sha256_file(self.adapter_dir / relative / CONFIG_FILENAME)

        def _bundle_digest(self, requested_model: str) -> str:
            return adapter_bundle_digest(
                self.adapter_digest(requested_model),
                self._config_digest(requested_model),
            )

        def verify_registry_artifacts(self) -> None:
            super().verify_registry_artifacts()
            for requested_model, identity in self.identities.items():
                if self._config_digest(requested_model) != identity.get(
                    "adapter_config_digest"
                ):
                    raise RuntimeError(
                        f"adapter config digest mismatch for {requested_model}"
                    )
                if self._bundle_digest(requested_model) != identity.get(
                    "adapter_bundle_digest"
                ):
                    raise RuntimeError(
                        f"adapter bundle digest mismatch for {requested_model}"
                    )

        def persona_receipt(self, **kwargs: Any) -> dict[str, Any]:
            signed = super().persona_receipt(**kwargs)
            payload = dict(signed["payload"])
            requested_model = str(payload["requested_model"])
            identity = self.identity(requested_model)
            config_digest = self._config_digest(requested_model)
            bundle_digest = self._bundle_digest(requested_model)
            if (
                config_digest != identity.get("adapter_config_digest")
                or bundle_digest != identity.get("adapter_bundle_digest")
            ):
                raise RuntimeError(
                    f"adapter configuration changed after registry verification: "
                    f"{requested_model}"
                )
            payload["selected_adapter_config_digest"] = config_digest
            payload["selected_adapter_bundle_digest"] = bundle_digest
            return self._sign(payload)

    def init_eval_attestation() -> None:
        family._R5_ATTESTOR = EvalRoutingAttestor(
            registry_path=str(registry_path),
            private_key_path=str(private_key_path),
            public_key_path=str(public_key_path),
            server_paths=[
                str(Path(family.__file__).resolve()),
                str((Path(family.__file__).parent / "family_routing_receipts.py").resolve()),
                str(wrapper_path.resolve()),
            ],
            adapter_dir=str(adapter_root),
            adapter_map=family.ADAPTERS,
            base_model_id=family.BASE,
            base_revision_path=str(base_revision_path),
        )
        family._R5_MAINTENANCE = family.MaintenanceController(
            state=family.STATE,
            adapter_map=family.ADAPTERS,
            adapter_dir=str(adapter_root),
            allowed_adapters=set(family._R5_ATTESTOR.requested_models),
            queue_lock=family._QUEUE_LOCK,
            queue_stats=family._QUEUE_STATS,
            audit_path=str(audit_path),
        )

    family._init_r5 = init_eval_attestation


def assert_exact_loaded_aliases(family: Any, expected: set[str]) -> None:
    loaded = family.STATE.get("loaded")
    if not isinstance(loaded, list) or set(loaded) != expected or len(loaded) != len(
        expected
    ):
        raise RuntimeError(
            f"evaluation server did not load exactly the required aliases: {loaded!r}"
        )


def default_adapters(args: argparse.Namespace) -> tuple[EvalAdapter, ...]:
    return (
        EvalAdapter(
            "echo-gs343-incumbent",
            "gs343",
            "incumbent",
            args.gs_incumbent,
        ),
        EvalAdapter(
            "echo-gs343-candidate",
            "gs343",
            "candidate",
            args.gs_candidate,
        ),
        EvalAdapter(
            "echo-r2d2-incumbent",
            "r2d2",
            "incumbent",
            args.r2_incumbent,
        ),
        EvalAdapter(
            "echo-r2d2-candidate",
            "r2d2",
            "candidate",
            args.r2_candidate,
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family-source", type=Path, required=True)
    parser.add_argument("--adapter-root", type=Path, required=True)
    parser.add_argument("--gs-incumbent", required=True)
    parser.add_argument("--gs-candidate", required=True)
    parser.add_argument("--r2-incumbent", required=True)
    parser.add_argument("--r2-candidate", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--base-revision", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8210)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    family_source = args.family_source.resolve()
    family_module_path = family_source / "serve_echo_family.py"
    receipt_module_path = family_source / "family_routing_receipts.py"
    if not family_module_path.is_file() or not receipt_module_path.is_file():
        raise FileNotFoundError("family source is missing server or routing receipt module")

    output_dir = create_isolated_output_dir(
        args.output_dir,
        (
            family_source,
            args.adapter_root,
            args.private_key.parent,
            args.public_key.parent,
            args.base_revision.parent,
        ),
    )
    registry_output = output_dir / "routing-registry.json"
    manifest_output = output_dir / "eval-server-manifest.json"
    registry, adapter_map = build_registry(args.adapter_root, default_adapters(args))
    write_json_atomic(registry_output, registry)
    manifest = {
        "schema": "echo.certforge.p5-eval-server/v1",
        "registry_path": str(registry_output),
        "registry_sha256": sha256_file(registry_output),
        "adapter_root": str(args.adapter_root.resolve()),
        "aliases": {
            row["requested_model"]: {
                "persona_id": row["persona_id"],
                "evaluation_role": row["evaluation_role"],
                "relative_path": row["adapter_relative_path"],
                "adapter_artifact_digest": row["adapter_artifact_digest"],
                "adapter_config_digest": row["adapter_config_digest"],
                "adapter_bundle_digest": row["adapter_bundle_digest"],
            }
            for row in registry["personas"]
        },
        "host": args.host,
        "port": args.port,
        "memory_grounding": False,
    }
    write_json_atomic(manifest_output, manifest)

    sys.path.insert(0, str(family_source))
    os.environ.pop("ECHO_FAMILY_ADAPTERS", None)
    family = importlib.import_module("serve_echo_family")
    configure_family_module(
        family,
        adapter_root=args.adapter_root.resolve(),
        adapter_map=adapter_map,
        registry_path=registry_output,
        private_key_path=args.private_key.resolve(),
        public_key_path=args.public_key.resolve(),
        base_revision_path=args.base_revision.resolve(),
        wrapper_path=Path(__file__),
        audit_path=output_dir / "maintenance-audit.jsonl",
    )
    first_alias = next(iter(adapter_map))
    family._load(default_first=first_alias)
    assert_exact_loaded_aliases(family, set(adapter_map))
    family._init_r5()

    import uvicorn

    uvicorn.run(family.app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
