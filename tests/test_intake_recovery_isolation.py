"""A stale tenant's crash gap cannot prevent independent work from dispatching."""
import sqlite3
from dataclasses import replace

import pytest

from echo_certification_forge.dispatch_worker import recover_pending_intake
from echo_certification_forge.intake import SubmitRequest
from echo_certification_forge.run_worker import _worker_environment
from echo_certification_forge.subscriber import Permission
from test_p7_subscriber_governance import _stack, _provision, _headers, _owner


def reserve(governance, client, manifest, tmp_path, label):
    org = _provision(governance, label)
    reference = (tmp_path / label).resolve().as_posix()
    project = client.post('/v1/subscriber/projects', headers=_headers(org.organization_id, org.bootstrap_api_key),
                          json={'slug': label, 'name': label, 'target_reference': reference}).json()
    environment = _worker_environment(manifest=manifest)
    request = SubmitRequest.model_validate({
        'tenant_id': org.organization_id, 'project_id': project['project_id'],
        'target': {'target_type': 'local', 'identity_digest': 'a' * 64, 'reference': reference, 'path': reference},
        'environment': {'identity_digest': environment.identity_digest, 'runner_image_digest': 'sha256:' + environment.runner_image_sha256},
        'policy_version': manifest.manifest_id, 'idempotency_key': label + '-request',
    })
    principal = _owner(governance, org.organization_id, org.bootstrap_api_key, Permission.RUN_CREATE)
    reservation = governance.reserve_certification_run(
        principal, project_id=request.project_id, idempotency_key=request.idempotency_key,
        request_digest=request.request_digest(), policy_version=request.policy_version,
        target_type=request.target.target_type, target_reference=request.target.reference,
        target_identity_digest=request.target.identity_digest, dispatch_target_spec=request.target.worker_spec(),
        journey=request.journey, submit_request=request.model_dump(exclude_none=True),
    )
    return org, request, reservation


@pytest.mark.parametrize('failure', ['archived_project', 'invalid_request', 'invalid_target_shape'])
def test_bad_intake_is_released_once_and_other_tenant_recovers(tmp_path, manifest, failure):
    store, governance, client = _stack(tmp_path, manifest)
    bad_org, bad_request, bad = reserve(governance, client, manifest, tmp_path, 'bad-first')
    good_org, good_request, good = reserve(governance, client, manifest, tmp_path, 'good-second')
    with sqlite3.connect(store.db_path) as db:
        if failure == 'archived_project':
            db.execute("UPDATE subscriber_projects SET status='ARCHIVED' WHERE project_id=?", (bad_request.project_id,))
        elif failure == 'invalid_request':
            db.execute("UPDATE subscriber_run_reservations SET submit_request_json='{}' WHERE organization_id=?", (bad_org.organization_id,))
        else:
            db.execute("UPDATE subscriber_run_reservations SET dispatch_target_json='[]' WHERE organization_id=?", (bad_org.organization_id,))
    assert recover_pending_intake(governance, store, manifest) == 1
    assert recover_pending_intake(governance, store, manifest) == 0
    assert store.get_run(good_request.run_id(manifest.digest), good_org.organization_id)['state'] == 'QUEUED'
    assert governance.pending_intake_requests() == []
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE organization_id=?', (bad_org.organization_id,)).fetchone() == ('RELEASED',)
        assert db.execute("SELECT count(*),sum(quantity) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0", (bad_org.organization_id,)).fetchone() == (1, -1)
    assert governance.claim_dispatch('healthy-dispatcher', organization_id=good_org.organization_id) is not None


def test_recovery_leaves_other_policy_and_concurrent_materialization_owned(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    org, request, reservation = reserve(governance, client, manifest, tmp_path, 'other-policy')
    with sqlite3.connect(store.db_path) as db:
        db.execute("UPDATE subscriber_run_reservations SET policy_version='different-policy' WHERE organization_id=?", (org.organization_id,))
    assert recover_pending_intake(governance, store, manifest) == 0
    assert len(governance.pending_intake_requests()) == 1
    with sqlite3.connect(store.db_path) as db:
        db.execute('UPDATE subscriber_run_reservations SET policy_version=? WHERE organization_id=?', (manifest.manifest_id, org.organization_id))
    assert recover_pending_intake(governance, store, manifest) == 1
    governance.release_reservation(reservation, reason='pending_intake_invalid', compensate_meter=True, only_reserved=True)
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE organization_id=?', (org.organization_id,)).fetchone() == ('BOUND',)
        assert db.execute('SELECT count(*) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (0,)


def test_recovery_release_requires_the_observed_request_digest(tmp_path, manifest):
    store, governance, client = _stack(tmp_path, manifest)
    org, _, reservation = reserve(governance, client, manifest, tmp_path, 'digest-fence')
    governance.release_reservation(replace(reservation, request_digest='b'*64), reason='pending_intake_invalid', compensate_meter=True, only_reserved=True)
    assert len(governance.pending_intake_requests()) == 1


def test_runtime_mismatch_exhaustion_terminalizes_and_compensates_before_acquisition(tmp_path, manifest, monkeypatch):
    from echo_certification_forge import run_worker
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.runtime_identity import RuntimeProfile
    from echo_certification_forge.sandbox import DockerSandbox
    from echo_certification_forge.signing import Ed25519VerdictSigner
    store, governance, client = _stack(tmp_path, manifest)
    org, request, reservation = reserve(governance, client, manifest, tmp_path, 'runtime-mismatch')
    profile = RuntimeProfile(DockerSandbox(image='sha256:' + 'a' * 64))
    monkeypatch.setattr(run_worker, 'acquire_target', lambda *a, **k: pytest.fail('mismatched runtime must not acquire'))
    for attempt in range(governance.policy.max_dispatch_attempts):
        dispatch, result = dispatch_once(governance, run_worker.run, dispatcher_id='mismatch-dispatcher',
            worker_options={'store': store, 'manifest': manifest, 'signer': Ed25519VerdictSigner.generate(),
                            'subscribers': governance, 'sandbox': profile.sandbox, 'runtime_profile': profile})
        assert result['error'] == 'runtime_environment_mismatch'
        if attempt + 1 < governance.policy.max_dispatch_attempts:
            assert governance.dispatch_status(dispatch.run_id, org.organization_id)['state'] == 'PENDING'
    run_id = request.run_id(manifest.digest)
    assert store.get_run(run_id, org.organization_id)['state'] == 'INFRASTRUCTURE_FAILURE'
    assert store.get_run(run_id, org.organization_id)['run_outcome'] == 'INFRA_FAILED'
    assert governance.dispatch_status(run_id, org.organization_id)['state'] == 'FAILED'
    assert governance.claim_dispatch('after-terminal', organization_id=org.organization_id) is None
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE organization_id=?', (org.organization_id,)).fetchone() == ('RELEASED',)
        assert db.execute('SELECT count(*),sum(quantity) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (1, -1)
