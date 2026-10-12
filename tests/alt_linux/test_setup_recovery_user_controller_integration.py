from __future__ import annotations

import copy,json
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_user_authorization import scenario as gate_fixture
from test_setup_recovery_native_runtime import scenario as request_fixture


def scenario(root):
    from alt_deploy import setup_recovery_sssd_start as start,setup_recovery_native_testjoin as native_worker
    from alt_deploy import setup_recovery_user_check as worker,setup_recovery_backup as backup
    from alt_deploy.setup_recovery_user_runtime import RecoveryUserRuntime
    authority,args,gate,native,previous,native_result,attachment,protected=gate_fixture(root/'gate')
    template_runtime,reference,_,_,_,_,_,_=request_fixture(root/'template')
    template=template_runtime._context(reference['plan_id'],reference['plan_sha256'])['request']
    startup=native.authorization.startup_runtime;bound=startup._context(args[0],args[1])
    request=bound['request'];old=copy.deepcopy(request);request.clear();request.update(copy.deepcopy(template))
    base=gate._load(args[0],args[1])['base']['plan']
    request.update(plan_id=args[0],plan_sha256=args[1],plan_created_at=base['created_at'],plan_expires_at=base['expires_at'],
        approval_sha256=attachment['sha256'],effects_ledger_sha256=old['effects_ledger_sha256'],sssd_unit=old['sssd_unit'])
    def selected(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in ('computer_guid','computer_sid'):value[key]=protected['directory_result'][key]
                else:selected(item)
        elif isinstance(value,list):
            for item in value:selected(item)
    selected(request)
    request['policy_request']['kerberos_request']['import_request']['directory_result']=copy.deepcopy(protected['directory_result'])
    original=request['policy_request']['kerberos_request']['import_request']['directory_result']
    assert {key:original[key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid')}=={
        key:protected['directory_result'][key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid')}
    facts=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
    facts['tools'].update(copy.deepcopy(attachment['payload']['user_check']['dependencies']))
    rehearsal=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']
    rehearsal['backup_request']['snapshot_sha256']=digest(facts)
    request['service_request']['backup_request']=copy.deepcopy(rehearsal['backup_request'])
    request['service_request']['backup_receipt']=copy.deepcopy(rehearsal['backup_receipt'])
    state=copy.deepcopy(request['sssd_unit']);state['properties'].update(ActiveState='active',SubState='running',MainPID='123',InvocationID='a'*32)
    started=start._receipt(request,state,backup)
    intended=dict(schema_version=1,plan_id=args[0],plan_sha256=args[1],request_sha256=digest(request),
        policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
        approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
    pair=bound['pair'];attempts=native.attempts
    for suffix,value in (('.sssd-start-intent.json',intended),('.sssd-start-result.json',started)):
        private_replace(attempts._path(**pair,suffix=suffix),value)
    bound['request']=request;startup._context=lambda *a:copy.deepcopy(bound)
    postwrite=gate.postwrite
    postwrite.service_gate=SimpleNamespace(preparation=SimpleNamespace(plans=gate.preparation.plans))
    postwrite.fingerprint=gate.plans.fingerprint
    startup.policy_runtime=SimpleNamespace(kerberos_runtime=SimpleNamespace(import_runtime=SimpleNamespace(postwrite=postwrite)))
    def current(*values):
        header=native.authorization(args[0],args[1],digest(gate.plans._native_sources()),digest(request),digest(started))
        return dict(pair=pair,address='192.0.2.10',request=copy.deepcopy(request),started=copy.deepcopy(started),
            sources=gate.plans._native_sources(),authorization=header)
    native._context=current;native.settings=gate.preparation.settings
    native.settings.known_hosts_file=root/'known_hosts';native.settings.private_key_file=root/'identity'
    ctx=current();mapped={path:dict(facts['tools'][path.rsplit('/',1)[1]],package=package) for path,package in native_worker.TOOLS.items()}
    native_result=native_worker._receipt(request,started,mapped,backup)
    native_intent=dict(schema_version=1,plan_id=args[0],plan_sha256=args[1],request_sha256=digest(request),
        startup_receipt_sha256=digest(started),sources_sha256=digest(ctx['sources']),authorization_sha256=digest(ctx['authorization']))
    for suffix,value in (('.native-testjoin-intent.json',native_intent),('.native-testjoin-result.json',native_result)):
        private_replace(attempts._path(**pair,suffix=suffix),value)
    calls=[]
    def runner(command,**options):
        wire=json.loads(options['input_text']);calls.append(wire)
        selected=wire['request'];tools={key:dict(facts['tools'][key],package=package) for key,package in
            (('getent',worker.PACKAGE),('nss_sss',worker.NSS_PACKAGE))}
        result=worker._receipt(selected,dict(uid=100100,gid=100100),tools,{},backup)
        return 0,json.dumps(result),''
    runtime=RecoveryUserRuntime(native_runtime=native,authorization=authority,runner=runner)
    return runtime,args[:2],gate,calls,pair


def test_genuine_user_authorizer_and_runtime_share_protected_approval_and_native_records(tmp_path):
    runtime,args,gate,calls,pair=scenario(tmp_path)
    context=runtime._context(*args)
    from alt_deploy import setup_recovery_native_testjoin as checker,setup_recovery_sssd_start as start
    from alt_deploy import setup_recovery_backup as backup,setup_recovery_sssd_policy as policy,setup_recovery_kerberos as kerberos
    from alt_deploy import setup_recovery_services as services,setup_recovery_native as native
    checker._request(context['request']['startup_request'],context['request']['startup_receipt'],
        start=start,backup=backup,policy=policy,kerberos=kerberos,services=services,native=native)
    from alt_deploy import setup_recovery_user_wire as wire
    assert context['request']['startup_request']['source_sha256']==digest(context['sources'][:12])
    assert len(__import__('alt_deploy.setup_plans',fromlist=['canonical']).canonical(context['request']))<=wire.MAX_REQUEST_BYTES
    wire._proof(context['request'])
    wire.build('check',context['sources'],context['request'])
    result=runtime.check_once(*args)
    loaded=gate._load(*args);scope=loaded['attachment']['payload']['user_check']
    assert result['employee']==scope['employee'] and result['login_verified'] is False
    assert calls[0]['request']['approval_sha256']==loaded['attachment']['sha256']
    assert runtime.verify(*args)==result and [value['action'] for value in calls]==['check','verify']
    with pytest.raises(ControlError):runtime.check_once(*args)
    assert len(calls)==2


def test_genuine_joined_gate_rejects_employee_disabled_after_intent_before_ssh(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    runtime,args,gate,calls,pair=scenario(tmp_path);original=RecoveryControllerBackup._persist
    user=gate.postwrite.directory.user(gate._load(*args)['attachment']['payload']['user_check']['employee']['login'])
    def changed(path,value):
        result=original(path,value)
        if str(path).endswith('.user-check-intent.json'):user['state']='disabled'
        return result
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(changed))
    with pytest.raises(ControlError):runtime.check_once(*args)
    assert calls==[]
