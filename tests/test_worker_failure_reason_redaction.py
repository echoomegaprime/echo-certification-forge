"""The worker failure path must redact untrusted identifier-form reasons at every durable sink."""
from __future__ import annotations

import json
import sqlite3

import pytest

from echo_certification_forge.models import RunState
from echo_certification_forge.signing import Ed25519VerdictSigner
from test_p7_subscriber_governance import _stack, _provision, _submit_local_run


@pytest.mark.parametrize(
    ("incoming", "expected"),
    [
        ("synthetic_private_token_12345", "redacted"),
        ("oci_journey_requires_sandbox", "oci_journey_requires_sandbox"),
    ],
)
def test_worker_failure_reason_is_bounded_across_state_and_immutable_audit(
    tmp_path, manifest, incoming, expected
):
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, "worker-reason")
    source = tmp_path / "source"
    source.mkdir()
    (source / "run.py").write_text("print('safe')\n", encoding="utf-8")
    run_id, target = _submit_local_run(
        client, manifest, org.organization_id, org.bootstrap_api_key,
        source, key="worker-reason-001",
    )
    signer = Ed25519VerdictSigner.generate()
    claim = governance.claim_worker_run(
        run_id=run_id,
        organization_id=org.organization_id,
        policy_version=manifest.manifest_id,
        target_type="local",
        target_reference=target.canonical_ref,
        worker_id=None,
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id=signer.key_id,
    )
    governance.fail_worker_execution(claim, reason=incoming)
    assert store.get_run(run_id, org.organization_id)["state"] == (
        RunState.INFRASTRUCTURE_FAILURE.value
    )
    assert governance.dispatch_status(run_id, org.organization_id)["last_error"] == expected
    with sqlite3.connect(governance.db_path) as conn:
        dispatch = conn.execute(
            "SELECT last_error FROM subscriber_run_dispatches WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0]
        history = conn.execute(
            "SELECT reason FROM state_events WHERE run_id = ? ORDER BY event_id DESC LIMIT 1",
            (run_id,),
        ).fetchone()[0]
        audit = conn.execute(
            """SELECT details_json FROM subscriber_audit_events
               WHERE organization_id = ? AND resource_id = ?
                 AND action = 'certification.worker_fail'
               ORDER BY event_id DESC LIMIT 1""",
            (org.organization_id, run_id),
        ).fetchone()[0]
    assert dispatch == history == json.loads(audit)["reason"] == expected
    if expected == "redacted":
        assert incoming not in (dispatch + history + audit)
