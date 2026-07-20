"""T4.P3 acceptance — signer/control-plane separation + mandatory external anchoring, at the
service boundary.

Deep signer/anchor enforcement (control-plane-only signing, forged-anchor rejection, key
lifecycle) is proven by tests/test_p3_custody_anchor_signing.py against signing_service.py. This
module proves the two SERVICE-boundary invariants T4 depends on:
  (1) the control-plane app graph holds NO private signing key material (upgrade 5);
  (2) no non-BLOCK verdict survives the deploy gate without the anchor->sign chain (upgrade 6),
      since a verdict can only be signed after signing_service._validate_anchor passes.
"""
from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from echo_certification_forge.deploy_gate import DeployGate
from echo_certification_forge.models import RedactionStatus, RunOutcome, RuleResult
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry


def _find_private_key_material(obj, *, _seen=None, _depth=0):
    """Bounded recursive walk collecting any Ed25519 private key reachable from obj."""
    if _seen is None:
        _seen = set()
    if _depth > 6 or id(obj) in _seen:
        return []
    _seen.add(id(obj))
    hits = []
    if isinstance(obj, Ed25519PrivateKey):
        hits.append(obj)
    # a signer exposing a private key handle
    priv = getattr(obj, "_private_key", None)
    if isinstance(priv, Ed25519PrivateKey):
        hits.append(priv)
    children = []
    if hasattr(obj, "__dict__"):
        children = list(vars(obj).values())
    elif isinstance(obj, (list, tuple, set, frozenset)):
        children = list(obj)
    elif isinstance(obj, dict):
        children = list(obj.keys()) + list(obj.values())
    for child in children:
        if isinstance(child, (str, bytes, int, float, bool, type(None))):
            continue
        hits.extend(_find_private_key_material(child, _seen=_seen, _depth=_depth + 1))
    return hits


def test_control_plane_holds_no_private_signing_key(store, manifest):
    context = ServiceContext(store, manifest, TrustedPublicKeyRegistry.empty())

    # the control-plane trust material is public-only
    assert isinstance(context.trusted_keys, TrustedPublicKeyRegistry)
    # no Ed25519 private key is reachable from the control-plane context object graph
    assert _find_private_key_material(context) == []

    client = TestClient(create_app(context))
    # health truthfully declares no private key + no customer-code execution in the control plane
    health = client.get("/healthz").json()
    assert health["private_signing_key_loaded"] is False
    assert health["control_plane_executes_customer_code"] is False


def _satisfy_all_rules(store, manifest, run_id, tenant_id):
    for index, rule in enumerate(manifest.rules, start=1):
        artifact_id = f"evidence-{index:02d}"
        store.append_artifact(
            run_id, tenant_id, artifact_id,
            json.dumps({"rule": rule.id, "passed": True}, sort_keys=True).encode(),
            "application/json", "harness", RedactionStatus.COMPLETE,
        )
        store.record_rule_result(run_id, tenant_id, RuleResult(rule.id, True, (artifact_id,), {"s": "a"}))


def test_no_signed_verdict_without_anchor_sign_chain_gate_denies(store, manifest, target, environment):
    """A run may complete all rules, but with no signed verdict (because anchoring+signing never
    happened) the deploy gate must DENY — proving no non-BLOCK release without the anchor chain."""
    run_id = "cert-noanchor"
    store.register_run(run_id, target, environment, manifest.manifest_id, manifest.digest)
    _satisfy_all_rules(store, manifest, run_id, target.tenant_id)
    store.set_run_outcome(run_id, target.tenant_id, RunOutcome.COMPLETE)

    # no signed verdict was ever produced (signing requires a validated anchor bundle)
    assert store.latest_signed_verdict(run_id, target.tenant_id) is None

    gate = DeployGate(store, TrustedPublicKeyRegistry.empty()).evaluate(
        target.tenant_id, run_id,
        target.identity_digest, environment.identity_digest, manifest.digest,
    )
    assert gate.allowed is False
    assert "signed_verdict_missing" in gate.reasons


def test_signer_module_enforces_anchor_before_signing_reference():
    """Guard: the isolated signer validates the anchor bundle before signing. If this wiring is
    ever removed, tests/test_p3_custody_anchor_signing.py::
    test_signing_rejects_missing_rule_tampered_anchor_unknown_key_revoked_key_and_outage fails.
    We assert the enforcement hook exists so the transitive gate proof above stays sound."""
    import inspect

    from echo_certification_forge import signing_service

    sign_src = inspect.getsource(signing_service.IsolatedVerdictSigningService.sign)
    assert "_validate_anchor" in sign_src, "signer.sign must validate the anchor bundle before signing"
