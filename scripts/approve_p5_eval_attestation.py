#!/usr/bin/env python3
"""Approve an exact P5 evaluation routing deployment for qualification.

The evaluator cannot approve its own routing identity.  This command pins the
new deployment only after independently hashing every adapter artifact and
checking the complete registry against operator-supplied alias semantics.  It
also requires continuity with a previously trusted signing key, server build,
and base-model identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from serve_p5_candidate_eval import (
    CONFIG_FILENAME,
    MODEL_FILENAME,
    REGISTRY_SCHEMA,
    adapter_bundle_digest,
    canonical_json,
    sha256_file,
)


class ApprovalError(RuntimeError):
    """Raised when an evaluation deployment differs from operator intent."""


@dataclass(frozen=True)
class ExpectedAlias:
    requested_model: str
    persona_id: str
    evaluation_role: str
    relative_path: str


def _parse_alias(value: str) -> ExpectedAlias:
    fields = value.split(":", 3)
    if len(fields) != 4 or any(not field for field in fields):
        raise argparse.ArgumentTypeError(
            "alias must be requested_model:persona_id:evaluation_role:relative_path"
        )
    role = fields[2]
    if role not in {"candidate", "incumbent"}:
        raise argparse.ArgumentTypeError("evaluation_role must be candidate or incumbent")
    return ExpectedAlias(*fields)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ApprovalError(f"expected JSON object: {path}")
    return value


def _fetch_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ApprovalError(f"attestation endpoint returned HTTP {response.status}")
        value = json.load(response)
    if not isinstance(value, dict):
        raise ApprovalError("attestation endpoint did not return a JSON object")
    return value


def _within(root: Path, relative_path: str) -> Path:
    root = root.resolve()
    resolved = (root / relative_path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ApprovalError(f"adapter path escapes root: {relative_path}")
    return resolved


def _expected_registry_rows(
    adapter_root: Path, aliases: list[ExpectedAlias]
) -> tuple[str, list[dict[str, Any]]]:
    resolved: list[dict[str, str]] = []
    seen: set[str] = set()
    for alias in aliases:
        if alias.requested_model in seen:
            raise ApprovalError(f"duplicate requested model: {alias.requested_model}")
        seen.add(alias.requested_model)
        directory = _within(adapter_root, alias.relative_path)
        model_digest = sha256_file(directory / MODEL_FILENAME)
        config_digest = sha256_file(directory / CONFIG_FILENAME)
        resolved.append(
            {
                "requested_model": alias.requested_model,
                "persona_id": alias.persona_id,
                "evaluation_role": alias.evaluation_role,
                "relative_path": alias.relative_path,
                "adapter_artifact_digest": model_digest,
                "adapter_config_digest": config_digest,
                "adapter_bundle_digest": adapter_bundle_digest(
                    model_digest, config_digest
                ),
            }
        )
    revision = hashlib.sha256(canonical_json(resolved)).hexdigest()
    rows = [
        {
            "persona_id": item["persona_id"],
            "requested_model": item["requested_model"],
            "adapter_id": item["requested_model"],
            "adapter_artifact_digest": item["adapter_artifact_digest"],
            "adapter_config_digest": item["adapter_config_digest"],
            "adapter_bundle_digest": item["adapter_bundle_digest"],
            "adapter_version": f"certforge-p5-{item['evaluation_role']}",
            "maturity_state": (
                "INCUMBENT_CONTROL"
                if item["evaluation_role"] == "incumbent"
                else "EVALUATION_CANDIDATE"
            ),
            "enabled": True,
            "registry_revision": revision,
            "evaluation_role": item["evaluation_role"],
            "adapter_relative_path": item["relative_path"],
        }
        for item in resolved
    ]
    return revision, rows


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def approve(args: argparse.Namespace) -> dict[str, Any]:
    previous = _load_json(args.previous_trusted)
    registry = _load_json(args.registry)
    live = _fetch_json(args.attestation_url, args.timeout)

    continuity_fields = (
        "receipt_schema",
        "key_id",
        "public_key_pem",
        "server_build_digest",
        "base_model_id",
        "base_model_revision",
        "base_model_digest",
    )
    for field in continuity_fields:
        if live.get(field) != previous.get(field):
            raise ApprovalError(f"live {field} differs from the previous trust root")

    revision, expected_rows = _expected_registry_rows(args.adapter_root, args.alias)
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise ApprovalError("registry schema is not the P5 evaluation schema")
    if registry.get("registry_revision") != revision:
        raise ApprovalError("registry revision differs from independently hashed aliases")
    if registry.get("snapshot_id") != f"certforge-p5-eval-{revision[:16]}":
        raise ApprovalError("registry snapshot_id differs from the expected revision")
    if registry.get("personas") != expected_rows:
        raise ApprovalError("registry personas differ from operator alias intent")

    registry_digest = sha256_file(args.registry)
    expected_models = sorted(alias.requested_model for alias in args.alias)
    required_live = {
        "registry_snapshot_digest": registry_digest,
        "registry_revision": revision,
        "requested_models": expected_models,
    }
    for field, expected in required_live.items():
        if live.get(field) != expected:
            raise ApprovalError(f"live {field} differs from verified registry")

    _write_json_atomic(args.output, live)
    return {
        "approved": True,
        "output": str(args.output),
        "output_sha256": sha256_file(args.output),
        "key_id": live["key_id"],
        "server_build_digest": live["server_build_digest"],
        "registry_snapshot_digest": registry_digest,
        "registry_revision": revision,
        "requested_models": expected_models,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation-url", required=True)
    parser.add_argument("--previous-trusted", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--adapter-root", required=True, type=Path)
    parser.add_argument("--alias", action="append", required=True, type=_parse_alias)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = approve(args)
    except Exception as error:  # noqa: BLE001 - approval boundary must fail closed
        print(json.dumps({"approved": False, "error": f"{type(error).__name__}: {error}"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
