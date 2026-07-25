"""End-to-end contract: the FORGE-side fixed command parses on the ANVIL operator.

`certforge_r5_core.build_operator_command` (runs on FORGE inside the SDK router)
and `scripts/family_r5_operator.py` (deployed standalone to ANVIL) are two
halves of one wire protocol. They drifted once already — the router emitted
`--signing-key-id` while the operator only accepted `--signature-key-id` — and
no test caught it because nothing ever fed the built command to the operator's
REAL argparse. These tests close that gap: every command the core can emit must
parse cleanly with the operator's own parser, round-trip every identity value,
and construct a valid `ExpectedIdentity`.
"""
from __future__ import annotations

import importlib.util
import shlex
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _load(name: str):
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


core = _load("certforge_r5_core")
op = _load("family_r5_operator")

_DIGESTS = {
    "expected_server_build_digest": "1" * 64,
    "expected_registry_snapshot_digest": "2" * 64,
    "expected_base_model_digest": "3" * 64,
    "expected_gs343_digest": "4" * 64,
    "expected_r2d2_digest": "5" * 64,
}
_REQUEST = {
    **_DIGESTS,
    "expected_registry_revision": "deadbeef",
    "expected_signing_key_id": "ed25519:" + "a" * 32,
    "expected_base_model_revision": "cafe1234",
}


def _operator_argv(mode: str, run_id: str = "run-contract-1") -> list[str]:
    """Build the fixed command exactly as the router does, then split it the way
    a POSIX shell on ANVIL would."""
    identity = core.validate_identity(_REQUEST)
    command = core.build_operator_command(
        identity,
        mode=mode,
        evidence_run_id=run_id,
        evidence_run_nonce="operator-contract-nonce-01",
    )
    argv = shlex.split(command)
    assert argv[0] == "python3"
    assert argv[1] == core.OPERATOR_PATH
    return argv[2:]


@pytest.mark.parametrize("mode", ["preflight", "full"])
def test_built_command_parses_with_real_operator_argparse(mode: str) -> None:
    args = op._args(_operator_argv(mode))
    assert args.mode == mode
    assert args.target_model == core.TARGET_MODEL
    assert args.wrong_model == core.WRONG_MODEL
    assert args.evidence_directory == Path(f"{core.EVIDENCE_ROOT}/run-contract-1")
    assert args.evidence_run_id == "run-contract-1"
    assert args.evidence_run_nonce == "operator-contract-nonce-01"


def test_parsed_identity_round_trips_and_validates_operator_side() -> None:
    args = op._args(_operator_argv("full"))
    expected = op.ExpectedIdentity(
        server_build_digest=args.server_build_digest,
        registry_snapshot_digest=args.registry_snapshot_digest,
        registry_revision=args.registry_revision,
        signature_key_id=args.signature_key_id,
        base_model_digest=args.base_model_digest,
        base_model_revision=args.base_model_revision,
        target_adapter_digest=args.target_adapter_digest,
        wrong_adapter_digest=args.wrong_adapter_digest,
        target_model=args.target_model,
        wrong_model=args.wrong_model,
    )
    assert expected.server_build_digest == _REQUEST["expected_server_build_digest"]
    assert expected.registry_snapshot_digest == _REQUEST["expected_registry_snapshot_digest"]
    assert expected.registry_revision == _REQUEST["expected_registry_revision"]
    assert expected.signature_key_id == _REQUEST["expected_signing_key_id"]
    assert expected.base_model_digest == _REQUEST["expected_base_model_digest"]
    assert expected.base_model_revision == _REQUEST["expected_base_model_revision"]
    assert expected.target_adapter_digest == _REQUEST["expected_gs343_digest"]
    assert expected.wrong_adapter_digest == _REQUEST["expected_r2d2_digest"]


def test_every_emitted_identity_flag_is_required_by_the_operator() -> None:
    """Dropping ANY identity/evidence flag the core emits must hard-fail the
    operator parse — proving each one is a real, required operator option and
    not a silently ignored stray."""
    argv = _operator_argv("preflight")
    identity_flags = [token for token in argv if token.startswith("--")
                      and token not in {"--mode", "--target-model", "--wrong-model"}]
    assert len(identity_flags) == 11  # 8 identity + directory + run id + nonce
    for flag in identity_flags:
        index = argv.index(flag)
        mutilated = argv[:index] + argv[index + 2:]
        with pytest.raises(SystemExit):
            op._args(mutilated)


def test_stale_signing_key_id_flag_is_rejected_by_operator() -> None:
    """Regression: the exact historical drift (`--signing-key-id`) must fail."""
    argv = _operator_argv("preflight")
    stale = ["--signing-key-id" if token == "--signature-key-id" else token
             for token in argv]
    assert "--signing-key-id" in stale
    with pytest.raises(SystemExit):
        op._args(stale)
