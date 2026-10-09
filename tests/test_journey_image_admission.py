"""Synthetic keys are local fixtures only; no production key or Docker access."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import stat
from types import SimpleNamespace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from echo_certification_forge.journey_image_admission import (
    JourneyQualification, prepare_admission_request, proposed_policy, seal_admission_request,
)
from echo_certification_forge.supply_chain import (
    ImageAdmissionDenied, ImageAdmissionPolicy, ImageAttestationAuthority,
    ImageIdentity, ImageRole, build_spdx_document, evaluate_image_admission,
)

ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


@pytest.fixture
def prepared():
    now = datetime.now(UTC)
    image = "sha256:" + "2" * 64
    source = "3" * 40
    material = {
        "dockerfile": ("FROM python@sha256:" + "4" * 64 + "\nUSER 65534:65534\n").encode(),
        "lockfile": encoded({"source_commit": source}),
        "sbom": encoded(build_spdx_document(image_name="synthetic", image_digest=image, created_at=now,
            packages=[{"name":"nodejs","version":"24.19.0"},{"name":"CPython","version":"3.11.17"}])),
        "provenance": encoded({"source_commit":source}),
    }
    identity = ImageIdentity(role=ImageRole.RUNNER, image_digest=image,
        base_image_digest="sha256:"+"4"*64,source_commit=source,
        **{name+"_sha256":hashlib.sha256(raw).hexdigest() for name,raw in material.items()},
        architecture="amd64",operating_system="linux",created_at=now)
    authority = ImageAttestationAuthority.generate()
    prior_identity = identity.model_copy(update={"image_digest":"sha256:"+"1"*64})
    prior_attestation = authority.sign(prior_identity,issued_at=now-timedelta(hours=1),valid_for=timedelta(days=14))
    policy = ImageAdmissionPolicy(policy_id="p4.runner.production.v1", required_role=ImageRole.RUNNER,
        expected_image_digest=prior_identity.image_digest,approved_base_digests=(identity.base_image_digest,),
        approved_source_commits=(source,),approved_dockerfile_sha256=identity.dockerfile_sha256,
        approved_lockfile_sha256=identity.lockfile_sha256,trusted_attestation_keys={authority.key_id:authority.public_key_pem},
        revoked_image_digests=("sha256:"+"9"*64,),compromised_key_ids=("historical-compromised-fixture",))
    qualification = JourneyQualification(identity_digest=identity.digest,
        archive_sha256="5"*64,independent_archive_sha256="6"*64,
        normalized_first_sha256="7"*64,normalized_second_sha256="7"*64,
        scanner_report_sha256="8"*64,node_core_report_sha256="a"*64,runtime_probe_sha256="b"*64,
        critical_count=0,fixed_high_or_critical_count=0,secret_count=0,node_core_finding_count=0,
        node_version="24.19.0",python_version="3.11.17",uid=65534,read_only_root=True,
        network_disabled=True,utf8=True,observed_at=now)
    kwargs=dict(identity=identity,qualification=qualification,prior_policy=policy,
                prior_attestation=prior_attestation,**material,now=now)
    return kwargs,authority


def test_owner_seal_retains_trust_and_does_not_mutate_old_policy(prepared):
    kwargs,authority=prepared
    before=kwargs['prior_policy'].model_dump_json()
    request=prepare_admission_request(**kwargs)
    proposed=proposed_policy(request,now=kwargs['now'])
    assert proposed.policy_id != kwargs['prior_policy'].policy_id
    assert proposed.trusted_attestation_keys == kwargs['prior_policy'].trusted_attestation_keys
    assert proposed.revoked_image_digests == kwargs['prior_policy'].revoked_image_digests
    assert proposed.compromised_key_ids == kwargs['prior_policy'].compromised_key_ids
    assert request.state == 'UNSIGNED_NOT_ADMITTED'
    signed,policy=seal_admission_request(request,authority=authority,approved_request_sha256=request.digest,now=kwargs['now'])
    assert evaluate_image_admission(signed,policy,now=kwargs['now']).allowed
    assert not evaluate_image_admission(signed,kwargs['prior_policy'],now=kwargs['now']).allowed
    assert kwargs['prior_policy'].model_dump_json() == before


@pytest.mark.parametrize('field',['dockerfile','lockfile','sbom','provenance'])
def test_material_drift_rejected(prepared,field):
    kwargs,_=prepared
    kwargs[field]+=b' '
    with pytest.raises(ImageAdmissionDenied,match=field+'_hash_mismatch'):
        prepare_admission_request(**kwargs)


@pytest.mark.parametrize('field,value',[
    ('critical_count',1),('fixed_high_or_critical_count',1),('secret_count',1),
    ('node_core_finding_count',1),('critical_count',False),('secret_count','0'),
    ('read_only_root',1),('read_only_root',False),('network_disabled',False),('utf8',False),
    ('normalized_second_sha256','c'*64),('independent_archive_sha256','5'*64),
    ('node_version','24.18.0'),('python_version','3.12.1'),('uid',0),
])
def test_failed_or_coerced_qualification_refused(prepared,field,value):
    kwargs,_=prepared
    payload=kwargs['qualification'].model_dump()
    payload[field]=value
    with pytest.raises(ValidationError): JourneyQualification.model_validate(payload)


@pytest.mark.parametrize('change',['unknown_key','expired','revoked','stale','future','wrong_identity'])
def test_trust_and_identity_fail_before_signing(prepared,change):
    kwargs,authority=prepared
    if change=='unknown_key': kwargs['prior_policy']=kwargs['prior_policy'].model_copy(update={'trusted_attestation_keys':{}})
    elif change=='expired':
        kwargs['now']+=timedelta(days=15)
        kwargs['qualification']=kwargs['qualification'].model_copy(update={'observed_at':kwargs['now']})
    elif change=='revoked': kwargs['prior_policy']=kwargs['prior_policy'].model_copy(update={'revoked_image_digests':(kwargs['identity'].image_digest,)})
    elif change=='stale': kwargs['now']+=timedelta(hours=25)
    elif change=='future': kwargs['now']-=timedelta(minutes=1)
    else: kwargs['qualification']=kwargs['qualification'].model_copy(update={'identity_digest':'f'*64})
    authority.sign=Mock(side_effect=AssertionError('must never sign'))
    with pytest.raises((ImageAdmissionDenied,ValidationError)): prepare_admission_request(**kwargs)
    authority.sign.assert_not_called()


def test_invalid_model_copy_does_not_bypass_qualification(prepared):
    kwargs,_=prepared
    kwargs['qualification']=kwargs['qualification'].model_copy(update={'critical_count':1})
    with pytest.raises(ValidationError): prepare_admission_request(**kwargs)


@pytest.mark.parametrize('change',['changed_review','new_authority','too_long','zero_lifetime'])
def test_seal_requires_exact_review_and_existing_authority(prepared,change):
    kwargs,authority=prepared
    request=prepare_admission_request(**kwargs)
    if change=='new_authority': authority=ImageAttestationAuthority.generate()
    authority.sign=Mock(side_effect=AssertionError('must never sign'))
    options={'approved_request_sha256':request.digest,'valid_for':timedelta(days=7)}
    if change=='changed_review': options['approved_request_sha256']='f'*64
    elif change=='too_long': options['valid_for']=timedelta(days=20)
    elif change=='zero_lifetime': options['valid_for']=timedelta(0)
    with pytest.raises(ImageAdmissionDenied): seal_admission_request(request,authority=authority,now=kwargs['now'],**options)
    authority.sign.assert_not_called()


def test_changed_signer_output_refused(prepared):
    kwargs,authority=prepared
    request=prepare_admission_request(**kwargs)
    authority.sign=Mock(return_value=kwargs['prior_attestation'])
    with pytest.raises(ImageAdmissionDenied,match='signed_candidate_not_admitted'):
        seal_admission_request(request,authority=authority,approved_request_sha256=request.digest,now=kwargs['now'])


def test_cli_new_outputs_only_and_safe_error(prepared,tmp_path):
    kwargs,_=prepared
    packet=tmp_path/'packet';packet.mkdir()
    for file,field in [('Dockerfile','dockerfile'),('journey-image-inputs.lock.json','lockfile'),
                       ('runner.spdx.json','sbom'),('runner.provenance.json','provenance')]:
        (packet/file).write_bytes(kwargs[field])
    for file,field in [('runner.identity.UNSIGNED.json','identity'),('qualification.json','qualification'),
                       ('policy.json','prior_policy'),('attestation.json','prior_attestation')]:
        (packet/file).write_text(kwargs[field].model_dump_json(),encoding='utf-8')
    out=tmp_path/'new-output'
    command=[sys.executable,str(ROOT/'scripts/prepare_journey_image_admission.py'),
             '--packet',str(packet),'--qualification',str(packet/'qualification.json'),
             '--dockerfile',str(packet/'Dockerfile'),'--prior-policy',str(packet/'policy.json'),
             '--prior-attestation',str(packet/'attestation.json'),'--expected-source',kwargs['identity'].source_commit,
             '--expected-image',kwargs['identity'].image_digest,'--expected-policy-sha256',
             hashlib.sha256((packet/'policy.json').read_bytes()).hexdigest(),'--output',str(out)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    receipt=json.loads(result.stdout)
    assert receipt['signed'] is False and receipt['state']=='UNSIGNED_NOT_ADMITTED'
    before={p.name:p.read_bytes() for p in out.iterdir()}
    repeated=subprocess.run(command,capture_output=True,text=True,timeout=15)
    assert repeated.returncode==1 and not repeated.stderr
    assert {p.name:p.read_bytes() for p in out.iterdir()}==before
    (packet/'qualification.json').write_text('{"private":"synthetic-sensitive-marker"}',encoding='utf-8')
    failed=subprocess.run(command,capture_output=True,text=True,timeout=15)
    assert failed.returncode==1 and 'synthetic-sensitive-marker' not in failed.stdout+failed.stderr


def test_reader_rejects_oversize_and_reparse(tmp_path):
    spec=importlib.util.spec_from_file_location('preparer',ROOT/'scripts/prepare_journey_image_admission.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    huge=tmp_path/'huge';huge.write_bytes(b'x'*(4*1024*1024+1))
    with pytest.raises(ImageAdmissionDenied,match='input_type_or_size_refused'): module.read_bounded(huge)
    link=tmp_path/'link'
    try: link.symlink_to(huge)
    except OSError: pytest.skip('host does not admit synthetic symlink creation')
    with pytest.raises(ImageAdmissionDenied,match='reparse_path_refused'): module.read_bounded(link)


@pytest.mark.parametrize('field,value,category',[
    ('lockfile',[], 'material_object_required'),
    ('provenance',{'source_commit':'f'*40}, 'material_source_mismatch'),
    ('sbom',[], 'sbom_invalid'),
])
def test_rehashed_malformed_material_is_not_accepted(prepared,field,value,category):
    kwargs,_=prepared
    kwargs[field]=encoded(value)
    kwargs['identity']=kwargs['identity'].model_copy(update={field+'_sha256':hashlib.sha256(kwargs[field]).hexdigest()})
    kwargs['qualification']=kwargs['qualification'].model_copy(update={'identity_digest':kwargs['identity'].digest})
    with pytest.raises(ImageAdmissionDenied,match=category): prepare_admission_request(**kwargs)


@pytest.mark.parametrize('invalid',['none','review','custody','output'])
def test_owner_wrapper_uses_only_existing_injected_fixture_key(prepared,tmp_path,monkeypatch,capsys,invalid):
    kwargs,authority=prepared
    request=prepare_admission_request(**kwargs)
    request_file=tmp_path/'request.json';request_file.write_text(request.model_dump_json(),encoding='utf-8')
    output=tmp_path/'sealed'
    if invalid=='output': output.mkdir()
    keypath=tmp_path/'test-key-placeholder'
    keypath.write_text('No private key bytes in this fixture',encoding='utf-8')
    monkeypatch.syspath_prepend(str(ROOT/'scripts'))
    spec=importlib.util.spec_from_file_location('journey_sealer',ROOT/'scripts/seal_journey_image.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original_path=module.plain_path
    info=SimpleNamespace(st_mode=stat.S_IFREG|(0o644 if invalid=='custody' else 0o600),st_uid=1000,st_size=100)
    monkeypatch.setattr(module,'plain_path',lambda p:SimpleNamespace(stat=lambda:info) if p==keypath else original_path(p))
    monkeypatch.setattr(module,'os',SimpleNamespace(name='posix',geteuid=lambda:1000))
    loader=Mock(return_value=authority._private_key)
    monkeypatch.setattr(module,'load_private_key',loader)
    monkeypatch.setattr(sys,'argv',['seal','--request',str(request_file),
        '--approved-request-sha256','0'*64 if invalid=='review' else request.digest,
        '--attestation-private-key',str(keypath),'--output-dir',str(output)])
    code=module.main()
    printed=capsys.readouterr()
    assert not printed.err and 'PRIVATE KEY' not in printed.out
    if invalid=='none':
        assert code==0 and json.loads(printed.out)['state']=='SEALED_NOT_INSTALLED'
        loader.assert_called_once()
        assert (output/'sealing-receipt.json').is_file()
    else:
        assert code==1 and json.loads(printed.out)['state']=='NOT_READY'
        loader.assert_not_called()
        assert not (output/'sealing-receipt.json').exists()
