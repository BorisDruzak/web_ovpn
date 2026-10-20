"""The complete user phase cannot fall through to the legacy opt-in role."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml
from jinja2 import Environment,StrictUndefined

from test_component_catalog import SOURCE
from test_krfb_managed_runtime import runtime_request


ROLE=SOURCE/'roles/remote_access_krfb'


def test_legacy_role_bytes_and_explicit_dispatch_are_preserved():
    legacy=(ROLE/'tasks/legacy.yml').read_bytes().replace(b'\r\n',b'\n')
    assert hashlib.sha256(legacy).hexdigest()=='1f375fe83991bebc535693db84d04a0a9f1cd5c00b8f845d31a6db132c7dc62b'
    tasks=yaml.safe_load((ROLE/'tasks/main.yml').read_text())
    assert len(tasks)==2
    assert tasks[0]['ansible.builtin.include_tasks']=='managed.yml'
    assert tasks[0]['when']=='alt_setup_workflow_context is defined'
    assert tasks[1]['ansible.builtin.include_tasks']=='legacy.yml'
    assert tasks[1]['when']=='alt_setup_workflow_context is not defined'


def test_managed_template_pins_password_authentication_and_fixed_port():
    template=(ROLE/'templates/krfbrc-managed.j2').read_text()
    result=Environment(undefined=StrictUndefined).from_string(template).render(
        vault_krfb_desktop_password_obscured='PRIVATE-DESKTOP-SENTINEL',
        vault_krfb_unattended_password_obscured='PRIVATE-UNATTENDED-SENTINEL',workstation_desktop_session='x11')
    assert '[TCP]\nuseDefaultPort=true\nport=5900' in result
    assert 'noWallet=true' in result and 'allowUnattendedAccess=true' in result
    assert 'preferredFrameBufferPlugin=xcb' in result
    # Historical template remains byte-for-byte unchanged by the new template.
    assert '[TCP]' not in (ROLE/'templates/krfbrc.j2').read_text()


@pytest.mark.parametrize('apply', [False,True])
def test_fixed_program_is_bounded_and_rejects_malformed_private_input(apply):
    from alt_deploy.krfb_program import target_program
    program=target_program(apply=apply)
    assert len(program.encode())<120000
    compile(program,'<fixed-managed-krfb>','exec')
    for private in ['{"schema_version":1,"command":"PRIVATE-SECRET-SENTINEL"}',
                    '{"schema_version":1,"schema_version":1,"secret":"PRIVATE-SECRET-SENTINEL"}',
                    'PRIVATE-SECRET-SENTINEL'*20000]:
        result=subprocess.run([sys.executable,'-I','-B','-c',program],input=private,text=True,capture_output=True,timeout=5)
        assert result.returncode==4 and result.stderr==''
        document=json.loads(result.stdout)
        assert document['status']=='blocked' and 'SENTINEL' not in result.stdout
        assert set(document)=={'schema_version','status','code'}
    with pytest.raises(ValueError):target_program(apply='arbitrary')


@pytest.mark.parametrize('case',['configured','noop','waiting','unknown','bad_context','changed_program','changed_template','missing_package'])
def test_real_ansible_managed_role_checks_claim_before_fixed_private_dispatch(tmp_path,case):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    tasks=yaml.safe_load((ROLE/'tasks/managed.yml').read_text())
    marker=tmp_path/'dispatched'
    result={'schema_version':1,'status':'ok','result':{'status':case if case in ('noop','waiting','unknown') else 'configured',
        'requires_direct_probe':case not in ('waiting','unknown'),'changed':case!='noop'}}
    program='from pathlib import Path;Path('+repr(str(marker))+').write_text("once");print('+repr(json.dumps(result))+')'
    request=runtime_request();request['context']=dict(request['context'])
    template='[TCP]\nuseDefaultPort=true\nport=5900\nPRIVATE-PASSWORD-SENTINEL\n'
    request['configuration']=template
    request['configuration_template_sha256']=hashlib.sha256(template.encode()).hexdigest()
    fake=tmp_path/'krfb'
    if case!='missing_package':fake.write_text('synthetic executable');fake.chmod(0o755)
    evidence={'schema_version':1,'program':program,'program_sha256':hashlib.sha256(program.encode()).hexdigest(),
              'request':request}
    if case=='bad_context':request['context']['phase']='system'
    if case=='changed_program':evidence['program']+=';print("PRIVATE-SECRET-SENTINEL")'
    if case=='changed_template':request['configuration_template_sha256']='0'*64
    for task in tasks:
        if 'ansible.builtin.stat' in task:task['ansible.builtin.stat']['path']=str(fake)
        if 'ansible.builtin.assert' in task:
            task['ansible.builtin.assert']['that']=[s.replace('.uid == 0','.uid == '+str(os.getuid()))
                                                  for s in task['ansible.builtin.assert']['that']]
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'alt_setup_workflow_context':request['context'],'alt_setup_krfb_runtime_evidence':evidence,
        'alt_setup_krfb_configuration':template,'alt_setup_krfb_autostart':request['autostart']}
    # Replace only template lookup with the same fixture bytes; the actual
    # Ansible assertions, private command module and outcome guard still run.
    tasks=[t for t in tasks if t.get('name')!='Render only the fixed complete-workstation KRFB templates']
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\n')
    run=subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
        env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),capture_output=True,text=True,timeout=20)
    assert (run.returncode==0) is (case in ('configured','noop')),run.stdout+run.stderr
    assert marker.exists() is (case in ('configured','noop','waiting','unknown'))
    assert 'PRIVATE-PASSWORD-SENTINEL' not in run.stdout+run.stderr
    assert 'PRIVATE-SECRET-SENTINEL' not in run.stdout+run.stderr
