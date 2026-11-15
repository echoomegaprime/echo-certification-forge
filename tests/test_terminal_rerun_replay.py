"""Real-store regressions for replaying a terminal subscriber rerun."""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry
from echo_certification_forge.subscriber import (
    OrganizationStatus,
    SubscriberGovernance,
    SubscriberPolicy,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture
def replay_stack(tmp_path, manifest):
    db = tmp_path / "certforge.sqlite3"
    store = EvidenceStore(db, tmp_path / "evidence")
    governance = SubscriberGovernance(
        db,
        SubscriberPolicy.load(
            Path(__file__).parents[1] / "policies/subscriber-governance.v1.json"
        ),
        b"terminal-rerun-replay-isolated-test-pepper",
    )
    owner = governance.provision_organization(
        slug="terminal-replay",
        display_name="Terminal Replay",
        owner_email="owner@terminal-replay.example",
        owner_display_name="Synthetic Owner",
        plan_code="professional",
        status=OrganizationStatus.ACTIVE,
    )
    headers = {
        "X-Tenant-ID": owner.organization_id,
        "Authorization": f"Bearer {owner.bootstrap_api_key}",
    }
    with TestClient(create_app(ServiceContext(
        store, manifest, TrustedPublicKeyRegistry.empty(), governance
    ))) as client:
        project = client.post(
            "/v1/subscriber/projects",
            headers=headers,
            json={
                "slug": "synthetic-project",
                "name": "Synthetic Project",
                "target_reference": "https://github.com/example/synthetic",
            },
        )
        assert project.status_code == 201
        submitted = client.post(
            "/v1/certifications",
            headers=headers,
            json={
                "tenant_id": owner.organization_id,
                "project_id": project.json()["project_id"],
                "target": {
                    "target_type": "git",
                    "identity_digest": _digest("synthetic-source"),
                    "reference": "https://github.com/example/synthetic@abc123",
                },
                "environment": {
                    "identity_digest": _digest("synthetic-environment"),
                    "runner_image_digest": "sha256:" + _digest("synthetic-image"),
                },
                "policy_version": manifest.manifest_id,
                "idempotency_key": "terminal-replay-source",
            },
        )
        assert submitted.status_code == 201
        source_id = submitted.json()["run_id"]
        assert client.post(
            f"/v1/certifications/{source_id}/cancel", headers=headers
        ).status_code == 200
        yield db, store, governance, client, owner, headers, source_id, manifest


def _counts(db):
    # Read the isolated fixture database to prove retries add no work or charges.
    with sqlite3.connect(db) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "runs", "subscriber_run_reservations", "subscriber_run_dispatches",
                "subscriber_usage_events", "idempotency_keys",
            )
        }


def _claim(governance, store, run_id, owner, manifest):
    row = store.get_run(run_id, owner.organization_id)
    return governance.claim_worker_run(
        run_id=run_id,
        organization_id=owner.organization_id,
        policy_version=manifest.manifest_id,
        target_type="git",
        target_reference=row["target_reference"],
        worker_id="synthetic-replay-worker",
        worker_attestation_sha256=None,
        execution_location="local",
        signing_authority="platform",
        signing_key_id="synthetic-signing-key",
    )


@pytest.mark.parametrize("terminal_kind", ["cancelled", "infrastructure_failure"])
def test_terminal_rerun_replay_preserves_work_and_lineage(replay_stack, terminal_kind):
    db, store, governance, client, owner, headers, source_id, manifest = replay_stack
    path = f"/v1/subscriber/certifications/{source_id}/rerun"
    request = {"idempotency_key": "terminal-replay-child"}
    created = client.post(path, headers=headers, json=request)
    assert created.status_code == 201
    child_id = created.json()["run_id"]
    assert child_id != source_id
    if terminal_kind == "cancelled":
        assert client.post(
            f"/v1/certifications/{child_id}/cancel", headers=headers
        ).status_code == 200
    else:
        claim = _claim(governance, store, child_id, owner, manifest)
        governance.fail_worker_execution(claim, reason="synthetic_storage_failure")

    child_before = store.get_run(child_id, owner.organization_id)
    source_before = store.get_run(source_id, owner.organization_id)
    evidence_before = store.list_evidence(child_id, owner.organization_id)
    verdict_before = store.latest_signed_verdict(child_id, owner.organization_id)
    counts_before = _counts(db)
    with sqlite3.connect(db) as connection:
        reservation_before = connection.execute(
            "SELECT state FROM subscriber_run_reservations WHERE run_id = ?",
            (child_id,),
        ).fetchone()[0]
    assert reservation_before == (
        "RELEASED" if terminal_kind == "infrastructure_failure" else "BOUND"
    )
    usage_before = client.get("/v1/subscriber/usage", headers=headers).json()
    for _ in range(2):
        replay = client.post(path, headers=headers, json=request)
        assert replay.status_code == 200, replay.text
        result = replay.json()
        assert result["run_id"] == child_id
        assert result["source_run_id"] == source_id
        assert result["rerun_sequence"] == 1
        assert result["release_verdict"] == "NOT_READY"

    assert store.get_run(child_id, owner.organization_id) == child_before
    assert store.get_run(source_id, owner.organization_id) == source_before
    assert store.list_evidence(child_id, owner.organization_id) == evidence_before
    assert store.latest_signed_verdict(child_id, owner.organization_id) == verdict_before
    assert _counts(db) == counts_before
    assert client.get("/v1/subscriber/usage", headers=headers).json() == usage_before
    with sqlite3.connect(db) as connection:
        assert connection.execute(
            "SELECT state FROM subscriber_run_reservations WHERE run_id = ?",
            (child_id,),
        ).fetchone()[0] == reservation_before
        assert connection.execute(
            "SELECT COUNT(*) FROM runs WHERE source_run_id = ?", (source_id,)
        ).fetchone()[0] == 1


def test_rerun_replay_does_not_reopen_active_claim_or_cross_tenant(replay_stack):
    db, store, governance, client, owner, headers, source_id, manifest = replay_stack
    path = f"/v1/subscriber/certifications/{source_id}/rerun"
    request = {"idempotency_key": "terminal-replay-active-child"}
    created = client.post(path, headers=headers, json=request)
    assert created.status_code == 201
    child_id = created.json()["run_id"]
    claim = _claim(governance, store, child_id, owner, manifest)
    counts_before = _counts(db)
    active = client.post(path, headers=headers, json=request)
    assert active.status_code == 409
    governance.assert_worker_claim_active(claim)
    assert _counts(db) == counts_before

    other = governance.provision_organization(
        slug="other-replay-tenant",
        display_name="Other Synthetic Tenant",
        owner_email="owner@other-replay.example",
        owner_display_name="Other Synthetic Owner",
        plan_code="professional",
        status=OrganizationStatus.ACTIVE,
    )
    denied = client.post(path, headers={
        "X-Tenant-ID": other.organization_id,
        "Authorization": f"Bearer {other.bootstrap_api_key}",
    }, json=request)
    assert denied.status_code == 404
    assert _counts(db) == counts_before
    governance.assert_worker_claim_active(claim)
