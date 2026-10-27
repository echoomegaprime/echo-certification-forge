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


def test_operator_runtime_mismatch_preserves_queued_work_and_retry_budget_before_acquisition(tmp_path, manifest, monkeypatch):
    from echo_certification_forge import run_worker
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.runtime_identity import RuntimeProfile
    from echo_certification_forge.sandbox import DockerSandbox
    from echo_certification_forge.signing import Ed25519VerdictSigner
    store, governance, client = _stack(tmp_path, manifest)
    org, request, reservation = reserve(governance, client, manifest, tmp_path, 'runtime-mismatch')
    profile = RuntimeProfile(DockerSandbox(image='sha256:' + 'a' * 64))
    monkeypatch.setattr(run_worker, 'acquire_target', lambda *a, **k: pytest.fail('mismatched runtime must not acquire'))
    for attempt in range(governance.policy.max_dispatch_attempts + 2):
        dispatch, result = dispatch_once(governance, run_worker.run, dispatcher_id='mismatch-dispatcher',
            worker_options={'store': store, 'manifest': manifest, 'signer': Ed25519VerdictSigner.generate(),
                            'subscribers': governance, 'sandbox': replace(profile.sandbox, memory='5g'), 'runtime_profile': profile})
        assert result['error'] == 'runtime_operator_profile_mismatch'
        assert result['dispatcher_halted'] is True
        assert result['retry_budget_consumed'] is False
        assert governance.dispatch_status(dispatch.run_id, org.organization_id)['state'] == 'PENDING'
        assert governance.dispatch_status(dispatch.run_id, org.organization_id)['attempts'] == 0
    run_id = request.run_id(manifest.digest)
    assert store.get_run(run_id, org.organization_id)['state'] == 'QUEUED'
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE organization_id=?', (org.organization_id,)).fetchone() == ('BOUND',)
        assert db.execute('SELECT count(*) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (0,)
    # A stale claim cannot undo the next dispatcher's ownership or attempts.
    next_claim = governance.claim_dispatch('next-dispatcher', organization_id=org.organization_id)
    from echo_certification_forge.subscriber import SubscriberError
    with pytest.raises(SubscriberError, match='dispatch_claim_inactive'):
        governance.defer_dispatch_runtime_failure(dispatch, error='runtime_identity_unavailable')
    assert governance.dispatch_status(run_id, org.organization_id)['attempts'] == 1


def test_job_specific_failure_exhaustion_compensates_once(tmp_path, manifest):
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.signing import Ed25519VerdictSigner
    store, governance, client = _stack(tmp_path, manifest)
    org, request, _ = reserve(governance, client, manifest, tmp_path, 'specific-failure')
    for _ in range(governance.policy.max_dispatch_attempts):
        dispatch_once(governance, lambda *a, **k: {'error': 'target_unavailable'}, dispatcher_id='job-dispatcher',
                      worker_options={'store': store, 'manifest': manifest, 'signer': Ed25519VerdictSigner.generate(), 'subscribers': governance})
    assert store.get_run(request.run_id(manifest.digest), org.organization_id)['state'] == 'INFRASTRUCTURE_FAILURE'
    assert governance.claim_dispatch('after-terminal', organization_id=org.organization_id) is None
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE organization_id=?', (org.organization_id,)).fetchone() == ('RELEASED',)
        assert db.execute('SELECT count(*),sum(quantity) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (1, -1)


def test_api_error_cannot_refund_concurrently_claimed_recovery(tmp_path, manifest, monkeypatch):
    from echo_certification_forge.signing import Ed25519VerdictSigner
    from echo_certification_forge.subscriber import SubscriberError
    store, governance, client = _stack(tmp_path, manifest)
    org, request, initial = reserve(governance, client, manifest, tmp_path, 'api-race')
    governance.release_reservation(initial, reason='fixture_setup', compensate_meter=True)
    # Use a fresh idempotency key so the API owns its newly created reservation.
    request = request.model_copy(update={'idempotency_key': 'api-race-new-request'})
    materialize = governance.materialize_reserved_run
    def race(reservation, **kwargs):
        materialize(reservation, **kwargs)
        governance.claim_worker_run(run_id=kwargs['run_id'], organization_id=org.organization_id,
            policy_version=manifest.manifest_id, target_type='local', target_reference=request.target.reference,
            worker_id=None, worker_attestation_sha256=None, execution_location='local',
            signing_authority='platform', signing_key_id=Ed25519VerdictSigner.generate().key_id)
        raise SubscriberError(409, 'run_materialization_state_conflict')
    monkeypatch.setattr(governance, 'materialize_reserved_run', race)
    response = client.post('/v1/certifications', headers=_headers(org.organization_id, org.bootstrap_api_key),
                           json=request.model_dump(exclude_none=True))
    assert response.status_code == 409
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT state FROM subscriber_run_reservations WHERE run_id=?', (request.run_id(manifest.digest),)).fetchone() == ('EXECUTING',)
        assert db.execute('SELECT count(*) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (1,)


def test_dispatcher_main_exits_on_circuit_open_before_next_claim(tmp_path, monkeypatch):
    from echo_certification_forge import dispatch_worker
    from echo_certification_forge.signing import Ed25519VerdictSigner
    calls = []
    def dispatch(*args, **kwargs):
        calls.append(True)
        assert len(calls) == 1, 'circuit must stop before claiming another run'
        return object(), {'error': 'runtime_identity_unavailable', 'dispatcher_halted': True}
    monkeypatch.setenv('ECHO_CERTFORGE_API_KEY_PEPPER', 'synthetic-isolated-circuit-test-pepper')
    monkeypatch.setattr(dispatch_worker, '_load_signer', lambda _: Ed25519VerdictSigner.generate())
    monkeypatch.setattr(dispatch_worker, 'dispatch_once', dispatch)
    result = dispatch_worker.main(['--non-production-compat', '--db', str(tmp_path/'isolated.sqlite3'),
                                  '--evidence-root', str(tmp_path/'evidence')])
    assert result == 2 and len(calls) == 1


def test_tenant_runtime_mismatch_delays_retries_and_other_tenant_progresses(tmp_path, manifest, monkeypatch):
    from datetime import timedelta
    from echo_certification_forge import run_worker
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.runtime_identity import RuntimeProfile
    from echo_certification_forge.sandbox import DockerSandbox
    from echo_certification_forge.signing import Ed25519VerdictSigner
    store, governance, client = _stack(tmp_path, manifest)
    org, request, _ = reserve(governance, client, manifest, tmp_path, 'tenant-mismatch')
    other, _, _ = reserve(governance, client, manifest, tmp_path, 'tenant-other')
    profile = RuntimeProfile(DockerSandbox(image='sha256:'+'a'*64))
    clock = [governance._now()]
    monkeypatch.setattr(governance, '_now', lambda: clock[0])
    monkeypatch.setattr(run_worker, 'acquire_target', lambda *a, **k: pytest.fail('bad declaration must not acquire'))
    for attempt in range(governance.policy.max_dispatch_attempts):
        dispatch, result = dispatch_once(governance, run_worker.run, dispatcher_id='tenant-delay', organization_id=org.organization_id,
            worker_options={'store':store,'manifest':manifest,'subscribers':governance,
                            'signer':Ed25519VerdictSigner.generate(),'sandbox':profile.sandbox,'runtime_profile':profile})
        assert result['error'] == 'runtime_environment_mismatch'
        assert not result.get('dispatcher_halted')
        assert governance.claim_dispatch('immediate-retry', organization_id=org.organization_id) is None
        if attempt == 0:
            assert governance.claim_dispatch('other-progress', organization_id=other.organization_id) is not None
        clock[0] += timedelta(seconds=61)
    assert store.get_run(request.run_id(manifest.digest), org.organization_id)['state'] == 'INFRASTRUCTURE_FAILURE'
    with sqlite3.connect(store.db_path) as db:
        assert db.execute('SELECT count(*) FROM subscriber_usage_events WHERE organization_id=? AND quantity<0', (org.organization_id,)).fetchone() == (1,)


def test_post_claim_measurement_failure_halts_cleanly_without_reopening_terminal_run(tmp_path, manifest, monkeypatch):
    from echo_certification_forge import run_worker
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.signing import Ed25519VerdictSigner
    from test_p7_subscriber_governance import _submit_local_run
    store, governance, client = _stack(tmp_path, manifest)
    org = _provision(governance, 'post-claim-runtime', plan_code='professional')
    source = tmp_path/'source';source.mkdir();(source/'README').write_text('trusted synthetic fixture')
    run_id, _ = _submit_local_run(client,manifest,org.organization_id,org.bootstrap_api_key,source,key='post-claim-runtime-request')
    acquire = run_worker.acquire_target
    def after_acquisition(*args):
        acquired = acquire(*args)
        def unavailable(*a, **k):raise ValueError('runtime_metadata_unavailable')
        monkeypatch.setattr(run_worker, '_worker_environment', unavailable)
        return acquired
    monkeypatch.setattr(run_worker,'acquire_target',after_acquisition)
    _, result = dispatch_once(governance,run_worker.run,dispatcher_id='post-claim-runtime',
        worker_options={'store':store,'manifest':manifest,'subscribers':governance,'signer':Ed25519VerdictSigner.generate()})
    assert result['dispatcher_halted'] is True
    assert store.get_run(run_id,org.organization_id)['state']=='INFRASTRUCTURE_FAILURE'
    assert governance.dispatch_status(run_id,org.organization_id)['state']=='FAILED'


@pytest.mark.parametrize('journey', [[], [''], ['x\x00y'], ['x'*2049]])
def test_invalid_journey_is_rejected_at_intake_and_classified_per_job_in_compat(tmp_path, manifest, monkeypatch, journey):
    from pydantic import ValidationError
    from echo_certification_forge import run_worker
    from echo_certification_forge.dispatch_worker import dispatch_once
    from echo_certification_forge.signing import Ed25519VerdictSigner
    store, governance, client = _stack(tmp_path, manifest)
    org, request, _ = reserve(governance, client, manifest, tmp_path, 'invalid-journey')
    payload = request.model_dump(exclude_none=True);payload['journey']=journey
    with pytest.raises(ValidationError):SubmitRequest.model_validate(payload)
    assert recover_pending_intake(governance,store,manifest)==1
    # Emulate an older persisted dispatch that predates item validation.
    import json
    with sqlite3.connect(store.db_path) as db:
        db.execute('UPDATE subscriber_run_dispatches SET journey_json=? WHERE organization_id=?',(json.dumps(journey),org.organization_id))
    monkeypatch.setattr(run_worker,'acquire_target',lambda *a,**k:pytest.fail('invalid argv must not acquire'))
    _,result=dispatch_once(governance,run_worker.run,dispatcher_id='compat-invalid',
        worker_options={'store':store,'manifest':manifest,'subscribers':governance,'signer':Ed25519VerdictSigner.generate()})
    assert result['error']=='runtime_profile_mismatch'
    assert not result.get('dispatcher_halted')
    assert governance.claim_dispatch('immediate-compat-retry',organization_id=org.organization_id) is None
