from __future__ import annotations
import contextlib,hashlib,io,json,shlex,sys
import pytest
from alt_deploy.setup_plans import canonical


def execute(program,raw,monkeypatch):
    output=io.StringIO();namespace={}
    with monkeypatch.context() as patch,contextlib.redirect_stdout(output):
        patch.setattr(sys,'stdin',type('Input',(),{'buffer':io.BytesIO(raw)})())
        try: exec(compile(program,'<fixed-bundle>','exec'),namespace);rc=0
        except SystemExit as error: rc=error.code
    return rc,output.getvalue(),namespace

def test_bootstrap_carries_source_only_on_stdin(monkeypatch):
    from alt_deploy.setup_recovery_source_stdin import build_source_stdin
    source="import json,sys\nprint(json.loads(sys.stdin.buffer.read())['request']['value'])\n"
    wire={'request':{'value':'fixture-only'}}
    script,encoded=build_source_stdin(source,wire)
    assert source not in script and 'fixture-only' not in script
    assert len(shlex.quote(script).encode()) < 8192
    assert execute(script,encoded.encode(),monkeypatch)[:2]==(0,'fixture-only\n')

@pytest.mark.parametrize('change',['source','request','duplicate','nested_duplicate','trailing','nonfinite'])
def test_invalid_frames_execute_no_worker_source(monkeypatch,change):
    from alt_deploy.setup_recovery_source_stdin import build_source_stdin
    source='WORKER_EXECUTED=True\n'
    wire={'request':{'value':1}}
    script,encoded=build_source_stdin(source,wire)
    frame=json.loads(encoded)
    if change=='source':frame['_worker']+='tamper';raw=canonical(frame)
    elif change=='request':frame['request']['value']=2;raw=canonical(frame)
    elif change=='duplicate':raw=encoded[:-1].encode()+b',"_worker":"WORKER_EXECUTED=True"}'
    elif change=='nested_duplicate':raw=encoded.replace('"value":1','"value":1,"value":1').encode()
    elif change=='nonfinite':raw=encoded.replace('"value":1','"value":NaN').encode()
    else:raw=encoded.encode()+b' {}'
    # Rebind only the envelope SHA to exercise inner duplicate/source/request
    # validation too; retained worker and request hashes remain unchanged.
    from alt_deploy.setup_recovery_source_stdin import _script
    script=_script(hashlib.sha256(raw).hexdigest(),hashlib.sha256(source.encode()).hexdigest(),
        hashlib.sha256(canonical(wire)).hexdigest(),tuple(sorted(wire)))
    rc,output,namespace=execute(script,raw,monkeypatch)
    assert rc==1 and 'WORKER_EXECUTED' not in namespace
    assert json.loads(output)=={'schema_version':1,'error_code':'recovery_source_stdin_invalid'}

@pytest.mark.parametrize('change',['source_size','request_size','nonstring','reserved'])
def test_source_and_request_bounds_enforced_before_transport(change):
    from alt_deploy.setup_recovery_source_stdin import build_source_stdin
    source='pass';wire={'request':{}}
    if change=='source_size':source=' '*131073
    elif change=='request_size':wire['request']={'value':'x'*131073}
    elif change=='nonstring':source=b'pass'
    else:wire['_worker']='injected'
    with pytest.raises(ValueError):build_source_stdin(source,wire)

@pytest.mark.parametrize('kind',['import','kerberos','policy'])
def test_actual_generated_workers_fit_small_argv_and_bundle_limits(tmp_path,kind):
    from alt_deploy.setup_recovery_source_stdin import build_source_stdin
    if kind=='import':
        from test_setup_recovery_import_runtime import scenario
        runtime,*_=scenario(tmp_path);action='install'
    elif kind=='kerberos':
        from test_setup_recovery_kerberos_runtime import scenario
        runtime,*_=scenario(tmp_path);action='prove'
    else:
        from test_setup_recovery_sssd_policy_runtime import scenario
        runtime,*_=scenario(tmp_path);action='install'
    context=runtime._context('plan','a'*64)
    from alt_deploy.setup_plans import digest
    wire={key:context[key] for key in ('request','service_request','service_receipt')}
    hashes={key:digest(value) for key,value in wire.items()}
    if kind=='import':wire['password']='fixture-password-only'
    source=runtime._script(action,context['sources'],context['request']['source_sha256'],hashes)
    script,encoded=build_source_stdin(source,wire)
    assert len(source.encode())<=131072
    assert len(encoded.encode())<=1048576
    assert len(shlex.quote(script).encode())<8192

def test_string_wire_compatibility_uses_original_request_stdin(monkeypatch):
    from alt_deploy.setup_recovery_source_stdin import build
    source="import json,sys\nprint(json.loads(sys.stdin.buffer.read())['request']['value'])\n"
    script,encoded=build(source,'{"request":{"value":"private-fixture"}}')
    assert execute(script,encoded.encode(),monkeypatch)[:2]==(0,'private-fixture\n')

@pytest.mark.parametrize('wire',['{"request":{},"request":{}}','{"request":{"value":1,"value":1}}','{"request":NaN}','{}','[]'])
def test_string_wire_rejects_ambiguous_or_invalid_input(wire):
    from alt_deploy.setup_recovery_source_stdin import build
    with pytest.raises(ValueError):build('pass',wire)

def test_generic_protected_wire_preserves_backup_document_stdin(monkeypatch):
    from alt_deploy.setup_recovery_source_stdin import build_source_stdin
    script,encoded=build_source_stdin("import json,sys\nprint(json.loads(sys.stdin.buffer.read())['backup_request']['value'])\n",{'backup_request':{'value':'fixture-backup'}})
    assert execute(script,encoded.encode(),monkeypatch)[:2]==(0,'fixture-backup\n')

@pytest.mark.parametrize('kind',['backup','rehearsal','services'])
def test_prewrite_real_transport_never_embeds_worker_source_in_argv(tmp_path,kind):
    if kind=='backup':
        from test_setup_recovery_backup_runtime import scenario
        from test_setup_recovery_state import RUN,GUID
        runtime,machine,facts,calls,*_=scenario(tmp_path)
        runtime.create_backup(machine,RUN,GUID,facts)
    elif kind=='rehearsal':
        from test_setup_recovery_rehearsal_runtime import scenario
        from test_setup_recovery_state import RUN,GUID
        runtime,machine,request,calls,*_=scenario(tmp_path)
        runtime.create_rehearsal(machine,RUN,GUID,request['backup_request'],request['backup_receipt'],request['metadata'])
    else:
        from test_setup_recovery_services_runtime import scenario
        from test_setup_recovery_state import RUN,GUID
        runtime,machine,bound,receipt,snapshot,calls,*_=scenario(tmp_path)
        runtime.capture_services(machine,RUN,GUID,bound,receipt)
    command,options=calls[0]
    assert len(command[-1].encode()) <8192
    assert '_worker' in json.loads(options['input_text'])
    assert len(options['input_text'].encode())<=1048576
