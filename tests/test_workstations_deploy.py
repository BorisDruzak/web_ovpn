import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module():
    path = ROOT / 'deploy' / 'workstations_deployment.py'
    spec = importlib.util.spec_from_file_location('workstations_deployment', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def test_disabled_readiness_does_not_touch_gateway_or_database():
    deploy = module()
    assert deploy.readiness(settings=SimpleNamespace(workstations_enabled=False), schema_check=lambda: pytest.fail('database touched'), client=None) == {'status': 'disabled'}


def test_readiness_requires_schema_and_complete_both_directory_sources():
    deploy = module()
    calls = []
    class Client:
        def with_deadline(self, deadline): return self
        def call(self, operation, parameters, **kwargs):
            calls.append((operation, parameters))
            if operation == 'status': return {'observer_configured': True, 'execution_mode': 'sequential'}
            return {'schema_version': 1, 'complete': parameters['source'] == 'ad'}
    with pytest.raises(deploy.DeploymentError, match='workstations_readiness_incomplete'):
        deploy.readiness(settings=SimpleNamespace(workstations_enabled=True), schema_check=lambda: None, client=Client())
    assert calls == [('status', {}), ('directory.snapshot', {'source': 'ad'}), ('directory.snapshot', {'source': 'dns'})]
    calls.clear()
    with pytest.raises(deploy.DeploymentError, match='workstations_schema_not_ready'):
        deploy.readiness(settings=SimpleNamespace(workstations_enabled=True), schema_check=lambda: (_ for _ in ()).throw(RuntimeError('private-marker')), client=Client())
    assert not calls


def test_readiness_hides_gateway_details_and_refuses_missing_observer():
    deploy = module()
    class Client:
        def with_deadline(self, deadline): return self
        def call(self, *args, **kwargs): raise RuntimeError('private-marker')
    with pytest.raises(deploy.DeploymentError, match='^workstations_gateway_not_ready$'):
        deploy.readiness(settings=SimpleNamespace(workstations_enabled=True), schema_check=lambda: None, client=Client())


def test_credential_provisioning_is_hashed_scoped_idempotent_and_collision_safe(tmp_path):
    deploy = module()
    registry, token, receipt = (tmp_path / name for name in ('registry', 'token', 'receipt'))
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    gid = os.getgid() if hasattr(os, 'getgid') else 0
    kwargs = dict(registry=registry, token_output=token, receipt=receipt, actor='synthetic-read', grants=['workstations:read'], uid=uid, gid=gid)
    deploy.provision_credential(**kwargs)
    original = token.read_bytes()
    assert original.strip() and original.strip().decode() not in registry.read_text() + receipt.read_text()
    assert json.loads(registry.read_text())[0]['grants'] == ['workstations:read']
    assert json.loads(receipt.read_text())['owned_paths'] == [str(token), str(registry)]
    deploy.provision_credential(**kwargs)
    assert token.read_bytes() == original and len(json.loads(registry.read_text())) == 1
    with pytest.raises(deploy.DeploymentError): deploy.provision_credential(**dict(kwargs, grants=['workstations:apply']))
    assert token.read_bytes() == original
    with pytest.raises(deploy.DeploymentError): deploy.provision_credential(**dict(kwargs, actor='other'))
    assert len(json.loads(registry.read_text())) == 1


def test_credential_provisioning_rejects_legacy_grants_and_symlinks(tmp_path):
    deploy = module()
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    gid = os.getgid() if hasattr(os, 'getgid') else 0
    kwargs = dict(registry=tmp_path/'registry', token_output=tmp_path/'token', receipt=tmp_path/'receipt', actor='synthetic', grants=['vpn:manage'], uid=uid, gid=gid)
    with pytest.raises(deploy.DeploymentError): deploy.provision_credential(**kwargs)
    assert not list(tmp_path.iterdir())
    if os.name == 'nt': return
    (tmp_path/'elsewhere').write_text('unrelated')
    (tmp_path/'registry').symlink_to(tmp_path/'elsewhere')
    with pytest.raises(deploy.DeploymentError): deploy.provision_credential(**dict(kwargs, grants=['workstations:read']))
    assert (tmp_path/'elsewhere').read_text() == 'unrelated' and not (tmp_path/'token').exists()


def test_existing_enrollment_cannot_overwrite_an_unrelated_receipt(tmp_path):
    deploy = module()
    uid = os.getuid() if hasattr(os, 'getuid') else 0
    gid = os.getgid() if hasattr(os, 'getgid') else 0
    kwargs = dict(registry=tmp_path/'registry', token_output=tmp_path/'token', receipt=tmp_path/'receipt', actor='synthetic', grants=['workstations:read'], uid=uid, gid=gid)
    deploy.provision_credential(**kwargs)
    kwargs['receipt'].write_text(json.dumps({'actor': 'unrelated'}))
    with pytest.raises(deploy.DeploymentError, match='workstations_credential_collision'):
        deploy.provision_credential(**kwargs)
    assert json.loads(kwargs['receipt'].read_text()) == {'actor': 'unrelated'}


def test_installer_quiesces_workstation_timer_before_source_replacement_and_gates_start():
    script = (ROOT/'deploy/install-openvpn-web.sh').read_text()
    assert script.index('workstations_quiesce\n') < script.index('sudo_cmd rm -rf')
    assert 'workstations_gate' in script and 'workstations-reconcile.timer' in script
    library = (ROOT/'deploy/install-workstations-web-lib.sh').read_text()
    assert library.index('workstations_deployment.py') < library.index('enable --now workstations-reconcile.timer')
    assert '--env-file "$ENV_PATH"' in library
    assert 'WORKSTATIONS_ENABLED=1' not in script + library


@pytest.mark.skipif(os.name == 'nt', reason='Actual Bash harness runs on Linux')
@pytest.mark.parametrize('load,active,after,success', [('not-found', 'active', 'inactive', True), ('loaded', 'active', 'active', False), ('unknown', 'inactive', 'inactive', False)])
def test_timer_quiescence_checks_running_units_even_without_unit_files(load, active, after, success):
    library = ROOT/'deploy/install-workstations-web-lib.sh'
    harness = '''set -eu
declare -A state=([workstations-reconcile.timer]=ACTIVE [workstations-reconcile.service]=ACTIVE)
sudo_cmd() {
 local unit="${@: -1}"
 if [[ "$*" == *LoadState* ]]; then echo LOAD; return 0; fi
 if [[ "$*" == *ActiveState* ]]; then echo "${state[$unit]}"; return 0; fi
 if [[ "$*" == *stop* ]]; then state[$unit]=AFTER; fi
}
source LIBRARY
workstations_quiesce
[[ "${state[workstations-reconcile.timer]}" == inactive ]]
[[ "${state[workstations-reconcile.service]}" == inactive ]]
'''.replace('ACTIVE', active).replace('LOAD', load).replace('AFTER', after).replace('LIBRARY', str(library))
    result = subprocess.run(['bash', '-c', harness], capture_output=True, text=True)
    assert (result.returncode == 0) == success


@pytest.mark.skipif(os.name == 'nt', reason='Actual Bash harness runs on Linux')
@pytest.mark.parametrize('status,enabled,success', [(0, True, True), (77, False, True), (1, False, False)])
def test_activation_runs_readiness_after_stopping_timer(status, enabled, success):
    library = ROOT/'deploy/install-workstations-web-lib.sh'
    harness = '''set -eu
APP=/opt/openvpn-web
ENV_PATH=/etc/openvpn-web/openvpn-web.env
sudo_cmd() {
 if [[ "$*" == *LoadState* ]]; then echo loaded; return 0; fi
 if [[ "$*" == *ActiveState* ]]; then echo inactive; return 0; fi
 if [[ "$*" == *workstations_deployment.py* ]]; then return STATUS; fi
 printf '%s\\n' "$*"
}
source LIBRARY
workstations_gate
'''.replace('STATUS', str(status)).replace('LIBRARY', str(library))
    result = subprocess.run(['bash', '-c', harness], capture_output=True, text=True)
    assert (result.returncode == 0) == success
    assert 'disable --now workstations-reconcile.timer' in result.stdout
    assert ('enable --now workstations-reconcile.timer' in result.stdout) == enabled
