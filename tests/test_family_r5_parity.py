"""Parity gate: package ``family_r5`` vs the deployed ANVIL operator script.

``src/echo_certification_forge/family_r5.py`` (importable package copy) and
``scripts/family_r5_operator.py`` (single-file operator deployed standalone to
ANVIL) are the SAME program in two homes. They drifted once already — the
operator grew ``--mode``/``run_preflight`` and the ``forge_verification_bundle``
while the package copy silently fell behind — which is exactly the drift class
R5 itself exists to catch. These tests make that divergence loud:

* every top-level function/class the two files share must be AST-identical,
* the ONLY allowed structural delta is the operator inlining the four
  ``canonical``/``evidence`` helpers it cannot import when deployed standalone
  (and those inlined helpers must stay behaviorally equal to the package ones),
* the argparse surface must parse identically on both,
* a preflight-mode ``execute`` must emit byte-identical reports (including the
  ``forge_verification_bundle`` shape) from both modules.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_certification_forge import canonical as pkg_canonical
from echo_certification_forge import evidence as pkg_evidence
from echo_certification_forge import family_r5 as pkg

_ROOT = Path(__file__).resolve().parents[1]
PKG_PATH = _ROOT / "src" / "echo_certification_forge" / "family_r5.py"
OP_PATH = _ROOT / "scripts" / "family_r5_operator.py"

#: The operator is deployed as ONE file with no package next to it, so it must
#: inline these helpers instead of importing them. This is the only sanctioned
#: structural difference between the two copies.
INLINED_HELPERS = frozenset(
    {"canonical_json", "sha256_bytes", "require_sha256", "merkle_root"}
)


def _load_operator():
    loaded = sys.modules.get("family_r5_operator")
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location("family_r5_operator", OP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["family_r5_operator"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


op = _load_operator()


def _top_level_defs(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def test_only_sanctioned_structural_delta_between_the_two_copies() -> None:
    pkg_defs = _top_level_defs(PKG_PATH)
    op_defs = _top_level_defs(OP_PATH)
    assert set(op_defs) - set(pkg_defs) == set(INLINED_HELPERS), (
        "operator defines names the package copy lacks (package fell behind)"
    )
    assert set(pkg_defs) - set(op_defs) == set(), (
        "package defines names the deployed operator lacks (operator fell behind)"
    )


def test_every_shared_definition_is_ast_identical() -> None:
    """Any change to run/run_preflight/execute/_build_bundle/_args/main or any
    helper in ONE copy without the other fails here with the exact names."""
    pkg_defs = _top_level_defs(PKG_PATH)
    op_defs = _top_level_defs(OP_PATH)
    shared = sorted(set(pkg_defs) & set(op_defs))
    assert shared, "no shared definitions found — a copy was gutted"
    diverged = [
        name for name in shared
        if ast.dump(pkg_defs[name]) != ast.dump(op_defs[name])
    ]
    assert diverged == [], f"copies diverged on: {diverged}"


def test_module_constants_match() -> None:
    for name in ("SCHEMA", "RECEIPT_SCHEMA", "LEASE_HEADER", "CHALLENGE_HEADER"):
        assert getattr(pkg, name) == getattr(op, name), name


def test_inlined_helpers_behave_like_the_package_canonical_ones() -> None:
    sample = {"b": [1, "x"], "a": {"nested": True}, "unicode": "café"}
    assert op.canonical_json(sample) == pkg_canonical.canonical_json(sample)
    assert op.sha256_bytes(b"parity") == pkg_canonical.sha256_bytes(b"parity")
    assert op.require_sha256("A" * 64, "f") == pkg_canonical.require_sha256("A" * 64, "f")
    with pytest.raises(ValueError):
        op.require_sha256("zz", "f")
    leaves = [op.sha256_bytes(bytes([i])) for i in range(5)]
    assert op.merkle_root(leaves) == pkg_evidence.merkle_root(leaves)
    assert op.merkle_root([]) == pkg_evidence.merkle_root([])


TARGET = "echo-gs343"
WRONG = "echo-r2d2"
_ARGV = [
    "--server-build-digest", "1" * 64,
    "--registry-snapshot-digest", "2" * 64,
    "--registry-revision", "registry-parity",
    "--signature-key-id", "ed25519:" + "a" * 32,
    "--base-model-digest", "3" * 64,
    "--base-model-revision", "base-parity",
    "--target-adapter-digest", "4" * 64,
    "--wrong-adapter-digest", "5" * 64,
    "--evidence-directory", "evidence-out",
]


@pytest.mark.parametrize("extra", [[], ["--mode", "preflight"], ["--mode", "full"]])
def test_arg_surface_parses_identically(extra: list[str]) -> None:
    assert vars(pkg._args(_ARGV + extra)) == vars(op._args(_ARGV + extra))


def test_both_parsers_reject_an_unknown_mode() -> None:
    for module in (pkg, op):
        with pytest.raises(SystemExit):
            module._args(_ARGV + ["--mode", "sideways"])


@dataclass
class _PreflightTransport:
    """Serves ONLY the read-only preflight surface; anything else asserts,
    proving preflight mutates nothing on either copy."""

    private_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return f"ed25519:{pkg_canonical.sha256_bytes(raw)[:32]}"

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ):
        del body, headers, timeout
        if method == "GET" and path == "/health":
            return pkg.HttpResult(200, {
                "status": "ok",
                "loaded": [TARGET, WRONG],
                "routing_maintenance": {
                    "active": False,
                    "drain_requested": False,
                    "lease_id": None,
                    "ttl_remaining_seconds": 0,
                    "unloaded": [],
                    "fault_targets": [],
                },
            })
        if method == "GET" and path == "/v1/routing/attestation":
            return pkg.HttpResult(200, {
                "receipt_schema": pkg.RECEIPT_SCHEMA,
                "key_id": self.key_id,
                "public_key_pem": self.public_key_pem,
                "server_build_digest": "1" * 64,
                "registry_snapshot_digest": "2" * 64,
                "registry_revision": "registry-parity",
                "base_model_digest": "3" * 64,
                "base_model_revision": "base-parity",
            })
        raise AssertionError(f"preflight must not touch {method} {path}")


def _identity(module, key_id: str):
    return module.ExpectedIdentity(
        server_build_digest="1" * 64,
        registry_snapshot_digest="2" * 64,
        registry_revision="registry-parity",
        signature_key_id=key_id,
        base_model_digest="3" * 64,
        base_model_revision="base-parity",
        target_adapter_digest="4" * 64,
        wrong_adapter_digest="5" * 64,
    )


def test_preflight_reports_and_bundle_shape_are_byte_identical() -> None:
    key = Ed25519PrivateKey.generate()
    transports = [_PreflightTransport(private_key=key) for _ in range(2)]
    pkg_report = pkg.execute(
        _identity(pkg, transports[0].key_id), mode="preflight",
        transport=transports[0],
    )
    op_report = op.execute(
        _identity(op, transports[1].key_id), mode="preflight",
        transport=transports[1],
    )
    assert pkg_report == op_report
    assert pkg_report["run_outcome"] == "PREFLIGHT_OK"
    assert pkg_report["r5_gate"] == "BLOCK"  # preflight NEVER passes the gate
    bundle = pkg_report["forge_verification_bundle"]
    assert bundle == op_report["forge_verification_bundle"]
    assert set(bundle) == {
        "schema", "mode", "public_key_pem", "attested_key_id",
        "attested_server_build_digest", "attested_registry_snapshot_digest",
        "attested_registry_revision", "attested_base_model_digest",
        "attested_base_model_revision", "receipts",
    }
    assert bundle["schema"] == "echo.certification-forge.forge-verification-bundle/v1"
    assert bundle["mode"] == "preflight"
    assert bundle["receipts"] == []


def test_execute_rejects_an_unknown_mode_on_both_copies() -> None:
    key = Ed25519PrivateKey.generate()
    transport = _PreflightTransport(private_key=key)
    for module in (pkg, op):
        with pytest.raises(ValueError, match="mode"):
            module.execute(_identity(module, transport.key_id),
                           mode="sideways", transport=transport)
