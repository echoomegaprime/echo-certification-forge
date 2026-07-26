"""Focused, standalone unit tests for the R5 capability core + operator preflight.

No echo-worker-server, no DB, no SSH, no live family server — a real Ed25519 key
is generated in-process to build valid/tampered attestations and receipts. Run:
    python -m pytest tests/test_certification_forge_r5_router.py -q
"""
from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


core = _load("certforge_r5_core")
op = _load("family_r5_operator")


# --- key + fixture helpers -------------------------------------------------

def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = f"ed25519:{core.sha256_bytes(raw)[:32]}"
    return priv, pem, kid


D = "a" * 64  # a valid-looking sha256
D2 = "b" * 64
RUN_ID = "forge-verify-run"
RUN_NONCE = "forge-verify-run-nonce-01"


def _identity(kid: str) -> dict[str, str]:
    return {
        "expected_server_build_digest": D,
        "expected_registry_snapshot_digest": D,
        "expected_registry_revision": "deadbeef",
        "expected_signing_key_id": kid,
        "expected_base_model_digest": D,
        "expected_base_model_revision": "cafe1234",
        "expected_gs343_digest": D,
        "expected_r2d2_digest": D2,
    }


def _bundle(
    pem: str,
    kid: str,
    *,
    mode: str,
    priv=None,
    tamper=False,
    wrong_kid=False,
    receipt_run_id: str = RUN_ID,
):
    b = {
        "public_key_pem": pem,
        "attested_key_id": kid,
        "attested_server_build_digest": D,
        "attested_registry_snapshot_digest": D,
        "attested_registry_revision": "deadbeef",
        "attested_base_model_digest": D,
        "attested_base_model_revision": "cafe1234",
        "receipts": [],
    }
    if mode == "full" and priv is not None:
        receipts = []
        controls = (
            ("positive_target", 200, None, core.TARGET_MODEL, core.TARGET_MODEL, D, "lora_adapter", True),
            ("positive_wrong", 200, None, core.WRONG_MODEL, core.WRONG_MODEL, D2, "lora_adapter", True),
            ("wrong_active_adapter", 409, "ADAPTER_IDENTITY_MISMATCH", core.TARGET_MODEL, core.WRONG_MODEL, None, "failure", False),
            ("unloaded_adapter", 503, "ADAPTER_NOT_ACTIVE", core.TARGET_MODEL, None, None, "failure", False),
        )
        labels = {
            "positive_target": f"positive:{core.TARGET_MODEL}",
            "positive_wrong": f"positive:{core.WRONG_MODEL}",
            "wrong_active_adapter": "wrong-active",
            "unloaded_adapter": "unloaded",
        }
        for index, (
            control,
            status,
            error,
            requested_model,
            selected_model,
            digest,
            routing_mode,
            applied,
        ) in enumerate(controls, start=1):
            payload = {
                "schema": op.RECEIPT_SCHEMA,
                "request_id": f"request-{index}",
                "challenge_nonce": (
                    f"certforge-r5:{receipt_run_id}:{RUN_NONCE}:"
                    f"{labels[control]}:challenge-{index}"
                ),
                "requested_model": requested_model,
                "registry_adapter_id": requested_model,
                "selected_adapter_id": selected_model,
                "selected_adapter_digest": digest,
                "routing_mode": routing_mode,
                "adapter_applied": applied,
                "persona_applied": applied,
                "fallback_used": False,
                "signature_key_id": (
                    "ed25519:" + "0" * 32
                ) if wrong_kid else kid,
            }
            sig = priv.sign(core.canonical_json(payload).encode())
            sig_b64 = base64.b64encode(sig).decode()
            if tamper:
                sig_b64 = base64.b64encode(b"\x00" + sig[1:]).decode()
            receipts.append({"control": control,
                             "status_code": status,
                             "error_code": error,
                             "key_id": ("ed25519:" + "0" * 32) if wrong_kid else kid,
                             "payload": payload, "signature_b64": sig_b64})
        b["receipts"] = receipts
    return b


# --- identity + run-id validation -----------------------------------------

def test_validate_identity_ok():
    _, _, kid = _keypair()
    out = core.validate_identity(_identity(kid))
    assert out["signature_key_id"] == kid
    assert "signing_key_id" not in out
    assert out["target_adapter_digest"] != out["wrong_adapter_digest"]


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("expected_gs343_digest"),
    lambda d: d.update(expected_server_build_digest="zz" + "a" * 62),
    lambda d: d.update(expected_signing_key_id="rsa:1234"),
    lambda d: d.update(expected_r2d2_digest=D),  # equals gs343 digest
    lambda d: d.update(expected_registry_revision="!!"),
])
def test_validate_identity_rejects(mutate):
    _, _, kid = _keypair()
    d = _identity(kid)
    mutate(d)
    with pytest.raises(core.R5CoreError):
        core.validate_identity(d)


@pytest.mark.parametrize("bad", ["../evil", "a" * 65, "has space", "semi;colon", ""])
def test_validate_run_id_rejects(bad):
    with pytest.raises(core.R5CoreError):
        core.validate_run_id(bad)


# --- fixed command construction -------------------------------------------

def test_build_command_is_fixed_and_quoted():
    _, _, kid = _keypair()
    ident = core.validate_identity(_identity(kid))
    cmd = core.build_operator_command(
        ident,
        mode="preflight",
        evidence_run_id="run-1",
        evidence_run_nonce="run-1-nonce-00000001",
        target_family="gs343",
    )
    assert cmd.startswith("python3 " + core.OPERATOR_PATH)
    assert "--mode preflight" in cmd
    assert "--target-model echo-gs343-candidate" in cmd
    assert "--wrong-model echo-r2d2-candidate" in cmd
    assert "--signature-key-id" in cmd
    assert "--signing-key-id" not in cmd
    assert core.EVIDENCE_ROOT + "/run-1" in cmd
    # no caller-controlled shell metacharacter can appear unquoted
    assert ";" not in cmd and "$(" not in cmd and "&&" not in cmd


def test_build_command_rejects_bad_mode_and_runid():
    _, _, kid = _keypair()
    ident = core.validate_identity(_identity(kid))
    with pytest.raises(core.R5CoreError):
        core.build_operator_command(
            ident,
            mode="destroy",
            evidence_run_id="x",
            evidence_run_nonce="destroy-nonce-000001",
            target_family="gs343",
        )
    with pytest.raises(core.R5CoreError):
        core.build_operator_command(
            ident,
            mode="full",
            evidence_run_id="../etc",
            evidence_run_nonce="invalid-run-id-nonce",
            target_family="gs343",
        )


def test_async_reservation_digest_is_exact_and_conflict_safe():
    _, _, kid = _keypair()
    identity = core.validate_identity(_identity(kid))
    first, first_sha = core.build_async_request_binding(
        identity,
        mode="full",
        evidence_run_id="async-reservation",
        evidence_run_nonce="async-reservation-nonce-01",
        target_family="gs343",
    )
    repeated, repeated_sha = core.build_async_request_binding(
        identity,
        mode="full",
        evidence_run_id="async-reservation",
        evidence_run_nonce="async-reservation-nonce-01",
        target_family="gs343",
    )
    _, mismatch_sha = core.build_async_request_binding(
        identity,
        mode="full",
        evidence_run_id="async-reservation",
        evidence_run_nonce="async-reservation-nonce-02",
        target_family="gs343",
    )
    assert first == repeated and first_sha == repeated_sha
    assert mismatch_sha != first_sha
    assert core.async_reservation_decision(None, first_sha) == "launch"
    assert core.async_reservation_decision(first_sha, repeated_sha) == "idempotent"
    assert core.async_reservation_decision(first_sha, mismatch_sha) == "conflict"


def test_reversed_target_family_swaps_models_and_digest_orientation():
    _, _, kid = _keypair()
    ident = core.validate_identity(_identity(kid))
    command = core.build_operator_command(
        ident,
        mode="full",
        evidence_run_id="r2-reversed",
        evidence_run_nonce="r2-reversed-nonce-01",
        target_family="r2d2",
    )
    assert "--target-model echo-r2d2-candidate" in command
    assert "--wrong-model echo-gs343-candidate" in command
    assert f"--target-adapter-digest {D2}" in command
    assert f"--wrong-adapter-digest {D}" in command


@pytest.mark.parametrize("bad", ["", "gs", "echo-gs343", "GS343", None])
def test_target_family_is_closed_to_two_exact_values(bad):
    with pytest.raises(core.R5CoreError):
        core.validate_target_family(bad)


def test_async_router_reserves_before_launch_and_persists_failures():
    text = (_SCRIPTS / "certforge_r5_async_router.py").read_text(encoding="utf-8")
    reserve_at = text.index("INSERT INTO arcanum_sdk.r5_async_runs")
    launch_at = text.index("_ssh_run(node, launch")
    assert reserve_at < launch_at
    assert "ON CONFLICT (run_id) DO NOTHING" in text
    assert "request_sha256" in text
    assert "status='FAILED'" in text
    assert "evidence_run_id already reserved for different request" in text


# --- FORGE-side bundle verification ---------------------------------------

def test_verify_bundle_preflight_ok():
    _, pem, kid = _keypair()
    v = core.verify_forge_bundle(_bundle(pem, kid, mode="preflight"),
                                 core.validate_identity(_identity(kid)), mode="preflight")
    assert v["all_ok"] and v["identity_ok"] and v["key_id_ok"]


def test_verify_bundle_key_id_mismatch():
    _, pem, kid = _keypair()
    ident = core.validate_identity(_identity("ed25519:" + "9" * 32))  # different expected
    v = core.verify_forge_bundle(_bundle(pem, kid, mode="preflight"), ident, mode="preflight")
    assert not v["all_ok"] and not v["key_id_ok"]


def test_verify_bundle_identity_mismatch():
    _, pem, kid = _keypair()
    b = _bundle(pem, kid, mode="preflight")
    b["attested_server_build_digest"] = D2  # diverge from expected D
    v = core.verify_forge_bundle(b, core.validate_identity(_identity(kid)), mode="preflight")
    assert not v["all_ok"] and not v["identity_ok"]


def test_verify_bundle_full_valid_receipts():
    priv, pem, kid = _keypair()
    b = _bundle(pem, kid, mode="full", priv=priv)
    v = core.verify_forge_bundle(
        b,
        core.validate_identity(_identity(kid)),
        mode="full",
        expected_run_id=RUN_ID,
        expected_run_nonce=RUN_NONCE,
    )
    assert v["all_ok"]
    assert len(v["receipts"]) == 4
    assert all(r["signature_ok"] and r["semantic_ok"] for r in v["receipts"])


def test_verify_bundle_full_tampered_signature():
    priv, pem, kid = _keypair()
    b = _bundle(pem, kid, mode="full", priv=priv, tamper=True)
    v = core.verify_forge_bundle(
        b,
        core.validate_identity(_identity(kid)),
        mode="full",
        expected_run_id=RUN_ID,
        expected_run_nonce=RUN_NONCE,
    )
    assert not v["all_ok"]
    assert any(not r["signature_ok"] for r in v["receipts"])


def test_verify_bundle_full_wrong_receipt_key_id():
    priv, pem, kid = _keypair()
    b = _bundle(pem, kid, mode="full", priv=priv, wrong_kid=True)
    v = core.verify_forge_bundle(
        b,
        core.validate_identity(_identity(kid)),
        mode="full",
        expected_run_id=RUN_ID,
        expected_run_nonce=RUN_NONCE,
    )
    assert not v["all_ok"]


def test_verify_bundle_rejects_old_run_duplicate_replay():
    priv, pem, kid = _keypair()
    bundle = _bundle(
        pem,
        kid,
        mode="full",
        priv=priv,
        receipt_run_id="old-forge-run",
    )
    bundle["receipts"][1] = dict(bundle["receipts"][0])
    v = core.verify_forge_bundle(
        bundle,
        core.validate_identity(_identity(kid)),
        mode="full",
        expected_run_id=RUN_ID,
        expected_run_nonce=RUN_NONCE,
    )
    assert not v["all_ok"]
    assert any(not receipt["semantic_ok"] for receipt in v["receipts"])


# --- result assembly + redaction ------------------------------------------

def test_assemble_preflight_pass_never_authorises():
    r = core.assemble_result({"run_outcome": "PREFLIGHT_OK", "r5_gate": "BLOCK"},
                             {"all_ok": True}, mode="preflight", exit_code=0,
                             evidence_run_id="r")
    assert r["run_outcome"] == "PREFLIGHT_OK"
    assert r["r5_gate"] == "BLOCK" and r["release_verdict"] == "NOT_READY"
    assert r["completion_marker"] is None and r["deployment_authorized"] is False


def test_assemble_full_pass_requires_forge_ok():
    ok_report = {"run_outcome": "COMPLETE", "r5_gate": "PASS", "blocker": None,
                 "controls": [{"passed": True}, {"passed": True}]}
    passed = core.assemble_result(ok_report, {"all_ok": True}, mode="full",
                                  exit_code=0, evidence_run_id="r")
    assert passed["r5_gate"] == "PASS" and passed["completion_marker"] == "[R5 COMPLETE]"
    # FORGE disagreeing forces BLOCK even if the operator claims PASS
    blocked = core.assemble_result(ok_report, {"all_ok": False}, mode="full",
                                   exit_code=0, evidence_run_id="r")
    assert blocked["r5_gate"] == "BLOCK"
    # non-zero exit forces BLOCK
    ec = core.assemble_result(ok_report, {"all_ok": True}, mode="full",
                              exit_code=2, evidence_run_id="r")
    assert ec["r5_gate"] == "BLOCK"


def test_redaction_scrubs_tokens_and_keys():
    red = core.redact({"lease_token": "SECRET", "public_key_pem": "PEM",
                       "nested": {"authorization": "Bearer x", "ok": 1}})
    assert red["lease_token"] == "[REDACTED]"
    assert red["public_key_pem"] == "[REDACTED]"
    assert red["nested"]["authorization"] == "[REDACTED]"
    assert red["nested"]["ok"] == 1


# --- operator preflight over a fake loopback transport --------------------

class _FakeTransport:
    def __init__(self, pem: str, kid: str, *, healthy=True, matching=True):
        self.pem, self.kid = pem, kid
        self.healthy, self.matching = healthy, matching

    def request(self, method, path, *, body=None, headers=None, timeout=30):
        if path == "/health":
            state = {"active": False, "drain_requested": False, "unloaded": [], "fault_targets": []}
            return op.HttpResult(200, {
                "status": "ok" if self.healthy else "degraded",
                "loaded": ["echo-gs343", "echo-r2d2"],
                "routing_maintenance": state})
        if path == "/v1/routing/attestation":
            digest = D if self.matching else D2
            return op.HttpResult(200, {
                "receipt_schema": op.RECEIPT_SCHEMA, "key_id": self.kid,
                "public_key_pem": self.pem,
                "server_build_digest": digest, "registry_snapshot_digest": D,
                "registry_revision": "deadbeef", "base_model_digest": D,
                "base_model_revision": "cafe1234"})
        raise AssertionError(f"unexpected loopback call in preflight: {path}")


def _expected(kid: str) -> "op.ExpectedIdentity":
    return op.ExpectedIdentity(
        server_build_digest=D, registry_snapshot_digest=D, registry_revision="deadbeef",
        signature_key_id=kid, base_model_digest=D, base_model_revision="cafe1234",
        target_adapter_digest=D, wrong_adapter_digest=D2)


def test_operator_preflight_ok():
    _, pem, kid = _keypair()
    report = op.execute(_expected(kid),
                        evidence_run_id="router-preflight-ok",
                        evidence_run_nonce="router-preflight-ok-nonce-01",
                        mode="preflight",
                        transport=_FakeTransport(pem, kid))
    assert report["run_outcome"] == "PREFLIGHT_OK"
    assert report["r5_gate"] == "BLOCK"  # preflight never authorises
    b = report["forge_verification_bundle"]
    assert b["attested_key_id"] == kid and b["receipts"] == []


def test_operator_preflight_identity_mismatch_inconclusive():
    _, pem, kid = _keypair()
    report = op.execute(_expected(kid),
                        evidence_run_id="router-preflight-bad",
                        evidence_run_nonce="router-preflight-bad-nonce",
                        mode="preflight",
                        transport=_FakeTransport(pem, kid, matching=False))
    assert report["run_outcome"] == "INCONCLUSIVE"
    assert report["blocker"]
