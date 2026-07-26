import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SERVE_SCRIPT = ROOT / "scripts" / "serve_p5_candidate_eval.py"
SERVE_SPEC = importlib.util.spec_from_file_location(
    "serve_p5_candidate_eval", SERVE_SCRIPT
)
assert SERVE_SPEC and SERVE_SPEC.loader
SERVE = importlib.util.module_from_spec(SERVE_SPEC)
sys.modules[SERVE_SPEC.name] = SERVE
SERVE_SPEC.loader.exec_module(SERVE)

APPROVE_SCRIPT = ROOT / "scripts" / "approve_p5_eval_attestation.py"
APPROVE_SPEC = importlib.util.spec_from_file_location(
    "approve_p5_eval_attestation", APPROVE_SCRIPT
)
assert APPROVE_SPEC and APPROVE_SPEC.loader
APPROVE = importlib.util.module_from_spec(APPROVE_SPEC)
sys.modules[APPROVE_SPEC.name] = APPROVE
APPROVE_SPEC.loader.exec_module(APPROVE)


def _adapter(root: Path, relative: str, content: bytes) -> None:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / SERVE.MODEL_FILENAME).write_bytes(content)
    (directory / SERVE.CONFIG_FILENAME).write_text("{}\n", encoding="utf-8")


def _aliases() -> list:
    return [
        APPROVE.ExpectedAlias("echo-gs-inc", "gs343", "incumbent", "gs-old"),
        APPROVE.ExpectedAlias("echo-gs-new", "gs343", "candidate", "gs-new"),
        APPROVE.ExpectedAlias("echo-r2-inc", "r2d2", "incumbent", "r2-old"),
        APPROVE.ExpectedAlias("echo-r2-new", "r2d2", "candidate", "r2-new"),
    ]


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> argparse.Namespace:
    for relative in ("gs-old", "gs-new", "r2-old", "r2-new"):
        _adapter(tmp_path, relative, relative.encode())
    eval_adapters = tuple(
        SERVE.EvalAdapter(
            alias.requested_model,
            alias.persona_id,
            alias.evaluation_role,
            alias.relative_path,
        )
        for alias in _aliases()
    )
    registry, _ = SERVE.build_registry(tmp_path, eval_adapters)
    registry_path = tmp_path / "registry.json"
    SERVE.write_json_atomic(registry_path, registry)

    previous = {
        "receipt_schema": "echo.family-routing-receipt/v1",
        "key_id": "ed25519:trusted",
        "public_key_pem": "trusted-public-key",
        "server_build_digest": "1" * 64,
        "base_model_id": "Qwen/Qwen2.5-14B-Instruct",
        "base_model_revision": "base-revision",
        "base_model_digest": "2" * 64,
        "registry_snapshot_digest": "old",
        "registry_revision": "old",
        "requested_models": sorted(alias.requested_model for alias in _aliases()),
    }
    previous_path = tmp_path / "previous.json"
    previous_path.write_text(json.dumps(previous), encoding="utf-8")
    live = {
        **previous,
        "registry_snapshot_digest": SERVE.sha256_file(registry_path),
        "registry_revision": registry["registry_revision"],
    }
    monkeypatch.setattr(APPROVE, "_fetch_json", lambda *_: live)
    return argparse.Namespace(
        attestation_url="http://127.0.0.1/attestation",
        previous_trusted=previous_path,
        registry=registry_path,
        adapter_root=tmp_path,
        alias=_aliases(),
        output=tmp_path / "approved.json",
        timeout=1.0,
    )


def test_approval_pins_exact_registry_and_continuous_trust_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path, monkeypatch)
    result = APPROVE.approve(args)
    assert result["approved"] is True
    assert result["requested_models"] == sorted(
        alias.requested_model for alias in args.alias
    )
    assert json.loads(args.output.read_text(encoding="utf-8"))[
        "registry_snapshot_digest"
    ] == result["registry_snapshot_digest"]


def test_approval_rejects_registry_after_artifact_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path, monkeypatch)
    (tmp_path / "gs-new" / SERVE.MODEL_FILENAME).write_bytes(b"tampered")
    with pytest.raises(APPROVE.ApprovalError, match="registry revision differs"):
        APPROVE.approve(args)


def test_approval_rejects_new_signing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _fixture(tmp_path, monkeypatch)
    live = APPROVE._load_json(args.previous_trusted)
    live.update(
        {
            "key_id": "ed25519:attacker",
            "registry_snapshot_digest": SERVE.sha256_file(args.registry),
            "registry_revision": APPROVE._load_json(args.registry)[
                "registry_revision"
            ],
        }
    )
    monkeypatch.setattr(APPROVE, "_fetch_json", lambda *_: live)
    with pytest.raises(APPROVE.ApprovalError, match="key_id differs"):
        APPROVE.approve(args)
