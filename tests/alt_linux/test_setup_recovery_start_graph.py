from __future__ import annotations

import copy
import json
import os

import pytest


def api():
    from alt_deploy import setup_recovery_start_graph
    return setup_recovery_start_graph


def scenario(root):
    from alt_deploy import setup_recovery_probe as probe
    module=api();calls=[];states={}
    for name in ('sssd.service','smb.service','nmb.service','parent.target','shutdown.target','dependent.service','needed.service'):
        values={field:'' for field in module.PROPERTIES}
        values.update(Id=name,Names=name,LoadState='loaded',ActiveState='inactive',SubState='dead',
            FragmentPath='/usr/lib/systemd/system/'+name,NeedDaemonReload='no',Job='',
            SuccessAction='none',FailureAction='none',StartLimitAction='none',StopWhenUnneeded='no')
        if name.endswith('.service'):values.update(Restart='no',RestartMode='normal',NRestarts='0')
        states[name]=values
        path=root/values['FragmentPath'].lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b'SYNTHETIC_UNIT');path.chmod(0o644)
    states['sssd.service'].update(Requires='parent.target',Conflicts='shutdown.target',RequiredBy='dependent.service')
    states['parent.target'].update(ActiveState='active',SubState='active',Wants='needed.service')
    states['dependent.service']['Requisite']='needed.service'
    tool=root/'usr/bin/systemctl';tool.parent.mkdir(parents=True,exist_ok=True);tool.write_bytes(b'SYNTHETIC_SYSTEMCTL');tool.chmod(0o755)
    facts={'machine_uuid':'SYNTHETIC_UUID'}
    def collect():return copy.deepcopy(facts)
    def runner(command,**kwargs):
        calls.append(command)
        if command[:2]==['/usr/bin/rpm','-qf']:return 0,'systemd 258.9-alt1\n',''
        if command[:2]==['/usr/bin/systemctl','list-units']:
            return 0,json.dumps([{'unit':n,'load':v['LoadState'],'active':v['ActiveState'],'sub':v['SubState'],'description':'SYNTHETIC'}
                for n,v in states.items() if n.endswith('.device')]),''
        if command[-1]=='--property=UnitPath':return 0,'UnitPath='+' '.join(module.UNIT_PATHS)+'\n',''
        assert command[:2]==['/usr/bin/systemctl','show'] and command[-2]=='--'
        return 0,''.join(key+'='+value+'\n' for key,value in states[command[-1]].items()),''
    return dict(probe=probe,collect=collect,runner=runner,root=root,owner=os.geteuid()),states,calls,facts


def test_conservative_graph_does_not_cut_off_active_parents_or_predict_pruning(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    result=api().capture(**data)
    assert result['status']=='startup_inventory_only' and result['execution_authorized'] is False
    assert result['facts']==facts
    pairs={(item['unit'],item['job']) for item in result['possibilities']}
    assert ('needed.service','start') in pairs and ('shutdown.target','stop') in pairs
    assert ('dependent.service','try-restart') in pairs
    assert ('needed.service','verify-active') in pairs
    assert all(command[0]=='/usr/bin/rpm' or command[1] in ('show','list-units') for command in calls)


def test_native_quoted_escaped_unit_names_and_root_slice_are_preserved():
    name=r'dev-disk-by\x2duuid-example.device'
    encoded='"'+name.replace('\\','\\\\')+'" -.slice -.mount'
    assert api()._names(encoded)==[name,'-.slice','-.mount']


@pytest.mark.parametrize('value',['a.service a.service','"unfinished.service','../a.service','--evil.service','a.service\nother.service','a.service\x00','plain','"a b.service"','bad\\q.service'])
def test_unknown_or_ambiguous_unit_representation_is_refused(value):
    with pytest.raises(ValueError):api()._names(value)


@pytest.mark.parametrize('change',['job','reload','missing','unknown','duplicate','source','tool','facts','state'])
def test_drift_or_incomplete_native_capture_is_refused_without_actions(tmp_path,change):
    data,states,calls,facts=scenario(tmp_path);runner=data['runner'];shows=0
    def changed(command,**kwargs):
        nonlocal shows
        result=runner(command,**kwargs)
        if command[0]=='/usr/bin/systemctl' and command[-2]=='--':
            shows+=1
            if change=='job':states['sssd.service']['Job']='1'
            elif change=='reload':states['sssd.service']['NeedDaemonReload']='yes'
            elif change=='missing':result=(0,result[1].replace('Id=sssd.service\n',''), '')
            elif change=='unknown':result=(0,result[1]+'Unknown=anything\n','')
            elif change=='duplicate':result=(0,result[1]+'Id=sssd.service\n','')
            elif change=='source' and shows==2:(tmp_path/'usr/lib/systemd/system/sssd.service').write_bytes(b'CHANGED')
            elif change=='tool' and shows==1:(tmp_path/'usr/bin/systemctl').write_bytes(b'CHANGED')
            elif change=='facts' and shows==1:facts['machine_uuid']='CHANGED'
            elif change=='state' and shows==1:states['sssd.service']['ActiveState']='activating'
        return result
    data['runner']=changed
    with pytest.raises(ValueError):api().capture(**data)
    assert all(command[0]=='/usr/bin/rpm' or command[1] in ('show','list-units') for command in calls)


def test_graph_bounds_and_overall_deadline_refuse_capture(tmp_path,monkeypatch):
    data,states,calls,facts=scenario(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(api(),'MAX_UNITS',2)
        with pytest.raises(ValueError):api().capture(**data)
    with monkeypatch.context() as patch:
        ticks=iter([0,100])
        patch.setattr(api().time,'monotonic',lambda:next(ticks))
        with pytest.raises(ValueError):api().capture(**data)


def test_event_edges_are_distinct_from_transaction_dependencies(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['sssd.service'].update(OnFailure='needed.service',Triggers='needed.service',Upholds='needed.service')
    result=api().capture(**data)
    labels={edge['reason'] for edge in result['edges'] if edge['source']=='sssd.service' and edge['destination']=='needed.service'}
    assert {'OnFailure:event','Triggers:event','Upholds:event'}<=labels


def test_unit_command_and_environment_values_leave_only_hashes(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['sssd.service'].update(ExecStart='SYNTHETIC_SECRET',Environment='SYNTHETIC_SECRET')
    result=api().capture(**data)
    assert 'SYNTHETIC_SECRET' not in repr(result)
    assert result['units']['sssd.service']['opaque_sha256']['ExecStart']


def test_native_device_following_is_captured_as_a_separate_identity(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    for name in ('dev-sda.device','sys-devices-example.device'):
        value=copy.deepcopy(states['needed.service'])
        value.update(Id=name,Names=name,FragmentPath='',ActiveState='active',SubState='plugged')
        states[name]=value
    states['dev-sda.device']['Following']='sys-devices-example.device'
    states['parent.target']['Requires']='dev-sda.device'
    result=api().capture(**data)
    assert any(edge['source']=='dev-sda.device' and edge['destination']=='sys-devices-example.device'
               and edge['reason']=='Following:device' for edge in result['edges'])
    assert 'dev-sda.device' in result['units'] and 'sys-devices-example.device' in result['units']


def test_native_multi_command_exec_array_is_hashed_in_order(tmp_path):
    data,states,calls,facts=scenario(tmp_path);runner=data['runner']
    def multiple(command,**kwargs):
        rc,out,err=runner(command,**kwargs)
        if command[0]=='/usr/bin/systemctl' and command[-1]=='sssd.service':
            out=out.replace('ExecStartPre=\n','ExecStartPre=SYNTHETIC_FIRST\nExecStartPre=SYNTHETIC_SECOND\n')
        return rc,out,err
    data['runner']=multiple
    result=api().capture(**data)
    assert 'SYNTHETIC_FIRST' not in repr(result) and 'SYNTHETIC_SECOND' not in repr(result)


def test_device_following_family_includes_siblings_and_their_dependencies(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    for name in ('dev-first.device','dev-second.device','sys-leader.device'):
        value=copy.deepcopy(states['needed.service'])
        value.update(Id=name,Names=name,FragmentPath='',ActiveState='active',SubState='plugged')
        states[name]=value
    states['dev-first.device']['Following']='sys-leader.device'
    states['dev-second.device'].update(Following='sys-leader.device',Requires='needed.service')
    states['sssd.service']['Requires']='dev-first.device'
    result=api().capture(**data)
    pairs={(item['unit'],item['job']) for item in result['possibilities']}
    assert ('dev-second.device','start') in pairs and ('needed.service','start') in pairs
    assert any(edge['reason']=='Following:family' and edge['destination']=='dev-second.device' for edge in result['edges'])


def test_missing_optional_event_endpoint_remains_explicitly_unresolved(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['needed.service'].update(LoadState='not-found',FragmentPath='')
    (tmp_path/'usr/lib/systemd/system/needed.service').unlink()
    states['sssd.service'].update(Requires='',OnFailure='needed.service')
    states['parent.target']['Wants']=''
    result=api().capture(**data)
    assert result['execution_authorized'] is False
    assert {'unit':'needed.service','reason':'unit_not_found'} in result['unresolved']
    assert result['units']['needed.service']['properties']['LoadState']=='not-found'
    assert result['units']['needed.service']['source_resolution']=='unresolved'


def test_source_packages_are_recorded_but_do_not_authorize_hooks(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    result=api().capture(**data)
    source=result['units']['sssd.service']['sources']['/usr/lib/systemd/system/sssd.service']
    assert source['package']=='systemd 258.9-alt1'
    assert result['semantics']=='conservative_effect_inventory_without_pruning'
    assert result['execution_authorized'] is False


def test_last_package_callback_cannot_hide_an_earlier_source_change(tmp_path):
    data,states,calls,facts=scenario(tmp_path);runner=data['runner'];reads=0
    def changed(command,**kwargs):
        nonlocal reads
        result=runner(command,**kwargs)
        if command[:3]==['/usr/bin/rpm','-qf','/usr/lib/systemd/system/needed.service']:
            reads+=1
            if reads==2:(tmp_path/'usr/lib/systemd/system/sssd.service').write_bytes(b'CHANGED')
        return result
    data['runner']=changed
    with pytest.raises(ValueError):api().capture(**data)


def test_non_sssd_auto_restart_includes_its_separate_bound_dependent(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['needed.service'].update(Restart='on-abnormal',RestartMode='normal',BoundBy='dependent.service')
    states['sssd.service'].update(RequiredBy='')
    result=api().capture(**data)
    pairs={(item['unit'],item['job']) for item in result['possibilities']}
    assert ('needed.service','restart') in pairs and ('dependent.service','try-restart') in pairs
    assert any(edge['reason']=='Restart:automatic:event' and edge['source']=='needed.service' for edge in result['edges'])


@pytest.mark.parametrize('bound',['MAX_PAIRS','MAX_EDGES'])
def test_conservative_closure_refuses_job_or_edge_overflow(tmp_path,monkeypatch,bound):
    data,states,calls,facts=scenario(tmp_path)
    monkeypatch.setattr(api(),bound,1)
    with pytest.raises(ValueError):api().capture(**data)


def test_encoded_bound_includes_fact_envelope(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    facts['public_fixture']='x'*api().MAX_INVENTORY_BYTES
    with pytest.raises(ValueError):api().capture(**data)


def test_unit_aliases_normalize_edges_and_preserve_identity(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['needed.service']['Names']='needed.service alternate.service'
    states['alternate.service']=states['needed.service']
    states['parent.target']['Wants']='needed.service alternate.service'
    result=api().capture(**data)
    assert result['aliases']['alternate.service']=='needed.service'
    assert all(edge['destination']!='alternate.service' for edge in result['edges'])


def test_manager_action_is_an_unreviewed_effect_not_an_invented_unit_job(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    states['sssd.service']['FailureAction']='reboot'
    result=api().capture(**data)
    assert result['units']['sssd.service']['properties']['FailureAction']=='reboot'
    assert 'manager_actions' in result['review_requirements']
    assert not any(item['unit']=='reboot.target' for item in result['possibilities'])


def test_device_family_missing_leader_refuses_inventory(tmp_path):
    data,states,calls,facts=scenario(tmp_path)
    value=copy.deepcopy(states['needed.service'])
    value.update(Id='dev-first.device',Names='dev-first.device',FragmentPath='',Following='missing.device')
    states['dev-first.device']=value
    with pytest.raises(ValueError):api().capture(**data)
