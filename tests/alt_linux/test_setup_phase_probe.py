"""Only fresh typed observations can make an original phase eligible."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from test_setup_phases import phase_job
from test_full_workflow_binding import full_setup
from test_component_catalog import project


@pytest.mark.parametrize('fault',['none','dns_blocked','rfb_timeout','computer_changed','helper_changed','employee_then_timeout'])
def test_production_probe_prepares_fixed_templates_but_publishes_only_safe_digests(phase_job,monkeypatch,fault):
    from alt_deploy.setup_phase_probe import WorkflowReadinessProbe
    from alt_deploy.setup_plans import digest
    from alt_deploy.vault import VaultHealthChecker
    from alt_deploy.component_verification import VerificationEngine
    store,jobs,job,ready,identity,admissions,setup=phase_job
    facts=setup.component_probe.observe();payload=job.request['plan']['payload']
    verification=VerificationEngine(setup.catalog).evaluate(facts,[c['id'] for c in payload['components']])
    setup._observe_job_result=lambda plan,**kwargs:(copy.deepcopy(facts),copy.deepcopy(verification))
    computer=store.records(job)['system']['result']['result']['computer']
    setup.directory.computer=lambda hostname:{'exists':True,'objects':[copy.deepcopy(computer)]}
    if fault=='computer_changed':computer['object_guid']='0'*8+'-0000-0000-0000-000000000001'
    if fault=='employee_then_timeout':
        foreign=copy.deepcopy(payload['user']);foreign['object_guid']='0'*8+'-0000-0000-0000-000000000001'
        setup.directory.user=lambda login:foreign
    if fault=='dns_blocked':facts['components']['network.final_dns']={'error_code':'final_dns_backend_unverified'}
    monkeypatch.setattr(VaultHealthChecker,'_decrypt',lambda self:'vault_krfb_desktop_password_obscured: PRIVATE-DESKTOP-SENTINEL\nvault_krfb_unattended_password_obscured: PRIVATE-UNATTENDED-SENTINEL\n')
    monkeypatch.setattr('alt_deploy.krfb_runtime.observe_vnc_policy',lambda *a,**k:{'helper_sha256':'7'*64,
        'observation':{'ready':True,'snapshot_sha256':'8'*64}})
    if fault in ('rfb_timeout','employee_then_timeout'):
        def timeout(*a,**k):
            assert fault!='employee_then_timeout','Observed employee drift must stop before RFB'
            raise ControlError('krfb_probe_timeout','PRIVATE-TRANSPORT-SENTINEL',4)
        monkeypatch.setattr('alt_deploy.krfb_runtime.observe_vnc_policy',timeout)
    def runner(args,**kwargs):
        request=json.loads(kwargs['input_text'])
        assert args[-1].startswith('sudo -n /usr/bin/python3 -I -B -c ')
        assert set(request)=={'schema_version','machine_uuid','hostname','login','source_sha256','policy_sha256',
                              'policy_helper_sha256','configuration','autostart'}
        value={'disposition':'apply','needs_reload':False,'home_sha256':'3'*64,'certificates_quiet':True,
            'target_mutators_quiet':True,'certificates_sha256':'5'*64,
            'certificate_helper_sha256':hashlib.sha256((setup.settings.ansible_project_dir/'roles/government_ca/files/import_user_certificates.py').read_bytes()).hexdigest(),
            'policy':{'snapshot_sha256':'8'*64},
            'snapshot':{'uid':facts['user']['uid'],'gid':facts['user']['gid'],'boot_id':facts['machine']['boot_id'],
                        'session_sha256':'1'*64,'snapshot_sha256':'2'*64},
            'configuration_template_sha256':hashlib.sha256(request['configuration'].encode()).hexdigest(),
            'autostart_template_sha256':hashlib.sha256(request['autostart'].encode()).hexdigest()}
        if fault=='helper_changed':value['certificate_helper_sha256']='0'*64
        return 0,json.dumps({'schema_version':1,'status':'ok','observation':value}),''
    probe=WorkflowReadinessProbe(setup.settings,setup=setup,runner=runner)
    if fault!='none':
        expected={'dns_blocked':('final_dns_backend_unverified','dns'),
                  'rfb_timeout':('krfb_probe_timeout','vnc_policy'),
                  'computer_changed':('workflow_identity_changed','directory'),
                  'helper_changed':('workflow_source_changed','helper_binding'),
                  'employee_then_timeout':('workflow_identity_changed','directory')}
        with pytest.raises(ControlError) as caught:probe.prepare(job,'user')
        code,stage=expected[fault]
        assert caught.value.code==code
        assert caught.value.details=={'readiness_stage':stage}
        assert 'SENTINEL' not in str(caught.value.to_dict())
        return
    value,private=probe.prepare(job,'user')
    assert value['status']=='ready' and value['scope']['computer_guid']==computer['object_guid']
    assert 'SENTINEL' not in json.dumps(value)
    assert 'PRIVATE-DESKTOP-SENTINEL' in private['krfb_request']['configuration']
    assert private['krfb_request']['configuration'].endswith('\n')
    assert private['verification']==verification


@pytest.mark.parametrize('fault',['none','foreign_uid','old_boot','fake_home','busy_importer','live_writer',
                                  'vnc_clients','changed_employee','changed_computer','missing_wallet','private_extra'])
def test_readiness_binds_actual_employee_session_and_quiet_target(phase_job,fault):
    from alt_deploy.setup_phase_probe import bind_readiness
    store,jobs,job,ready,identity,admissions,setup=phase_job
    payload=job.request['plan']['payload'];scope=ready['scope'];obs=ready['observation']
    facts={'machine':{'uuid':job.machine_uuid,'hostname':scope['hostname'],'boot_id':obs['boot_id']},
           'user':{'login':scope['login'],'uid':scope['uid'],'gid':scope['gid'],'home_exists':True,'home_safe':True},
           'package_manager':{k:True for k in ('processes_absent','remote_execution_absent','locks_clear','database_readable','dependencies_healthy')},'components':{}}
    wallet={'snapshot_sha256':obs['wallet_sha256'],'uid':scope['uid'],'gid':scope['gid'],'boot_id':obs['boot_id']}
    dns={'boot_id':obs['boot_id'],'backend':scope['backend'],'interface':scope['interface'],
         'connection_uuid':scope['connection_uuid'],'snapshot_sha256':obs['dns_sha256']}
    krfb={'disposition':'apply','snapshot':{'uid':scope['uid'],'gid':scope['gid'],'boot_id':obs['boot_id'],
        'session_sha256':obs['session_sha256']},'home_sha256':scope['home_sha256'],
        'certificates_quiet':True,'target_mutators_quiet':True,'certificates_sha256':obs['certificates_sha256']}
    computer=copy.deepcopy(store.records(job)['system']['result']['result']['computer'])
    user=copy.deepcopy(payload['user'])
    if fault=='foreign_uid':krfb['snapshot']['uid']+=1
    elif fault=='old_boot':wallet['boot_id']='0'*8+'-0000-0000-0000-000000000000'
    elif fault=='fake_home':facts['user']['home_safe']=False
    elif fault=='busy_importer':krfb['certificates_quiet']=False
    elif fault=='live_writer':krfb['target_mutators_quiet']=False
    elif fault=='vnc_clients':krfb['disposition']='waiting_vnc_clients'
    elif fault=='changed_employee':user['object_guid']='0'*8+'-0000-0000-0000-000000000000'
    elif fault=='changed_computer':computer['object_guid']='0'*8+'-0000-0000-0000-000000000000'
    elif fault=='missing_wallet':wallet=None
    elif fault=='private_extra':krfb['environment']={'TOKEN':'PRIVATE-SENTINEL'}
    arguments=dict(facts=facts,user=user,computer=computer,wallet=wallet,dns=dns,krfb=krfb,helpers=obs['helpers'])
    if fault=='none':
        value=bind_readiness(job,'user',store.records(job)['system']['result'],**arguments)
        assert value['status']=='ready' and value['scope']==scope
        assert 'SENTINEL' not in json.dumps(value)
    else:
        with pytest.raises(ControlError) as caught:bind_readiness(job,'user',store.records(job)['system']['result'],**arguments)
        assert 'SENTINEL' not in str(caught.value)
        codes={'busy_importer':'certificates_importer_active','live_writer':'workflow_target_processes_unverified','vnc_clients':'krfb_clients_connected'}
        if fault in codes:assert caught.value.code==codes[fault]
