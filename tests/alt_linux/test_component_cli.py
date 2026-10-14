"""Published inspection needs neither AD credentials nor a live workstation."""
import io
import json

import pytest

from alt_deploy import cli, setup_cli
from alt_deploy.config import Settings
from test_component_verification import CATALOG, UUID
from test_component_setup import component_service
from test_component_catalog import project


@pytest.mark.parametrize('area', ['components', 'profiles'])
def test_catalog_inspection_is_versioned_and_never_constructs_setup(area, monkeypatch):
    settings = Settings.from_env()
    from dataclasses import replace
    settings = replace(settings, ansible_project_dir=CATALOG)
    def forbidden(*args, **kwargs): raise AssertionError('Inspection must not contact AD')
    monkeypatch.setattr(setup_cli, 'SetupService', forbidden)
    output = io.StringIO()
    assert cli.main(['--json', 'setup', area, 'list'], settings=settings, stdout=output) == 0
    payload = json.loads(output.getvalue())
    assert payload['schema_version'] == 2
    assert payload['operation'] == area+'_list'
    assert len(payload[area]) == (13 if area == 'components' else 4)


def test_component_plan_verify_dispatch_and_no_arbitrary_override(monkeypatch):
    from alt_deploy import component_setup
    calls = []
    class Service:
        def __init__(self, settings): pass
        def plan(self, machine, component):
            calls.append(('plan', machine, component))
            return {'schema_version': 2, 'operation': 'component_plan', 'status': 'ok'}
        def verify(self, machine, component):
            calls.append(('verify', machine, component))
            return {'schema_version': 2, 'operation': 'component_verification', 'status': 'ok'}
    monkeypatch.setattr(component_setup, 'ComponentSetupService', Service)
    for action in ('plan', 'verify'):
        args = ['setup', 'component', action, '--machine', 'uuid', '--component', 'software.onlyoffice']
        assert setup_cli.handle(cli.build_parser().parse_args(args), object())['schema_version'] == 2
        for tail in (['--role', 'domain_join'], ['--vars-file', 'arbitrary'], ['--comp', 'anything']):
            with pytest.raises(SystemExit): cli.build_parser().parse_args(args+tail)
    assert calls == [('plan', 'uuid', 'software.onlyoffice'), ('verify', 'uuid', 'software.onlyoffice')]


def _functional_cli(component_service, monkeypatch):
    from alt_deploy import component_setup
    service = component_service[0]
    plan = service.plan(UUID, 'software.directum')
    monkeypatch.setattr(component_setup, 'ComponentSetupService', lambda settings: service)
    def forbidden(*args, **kwargs):
        raise AssertionError('Acceptance must not enter the full Setup service')
    monkeypatch.setattr(setup_cli, 'SetupService', forbidden)
    return service, plan


def test_functional_accept_cli_records_real_service_receipt(component_service, monkeypatch):
    service, plan = _functional_cli(component_service, monkeypatch)
    output = io.StringIO()
    assert cli.main(['--json', 'setup', 'component', 'accept', plan['plan_id'], '--confirm-sha256', plan['sha256'],
                     '--confirm-functional'], settings=service.settings, stdout=output) == 0
    payload = json.loads(output.getvalue())
    assert payload['schema_version'] == 2 and payload['operation'] == 'component_acceptance'
    assert payload['component_id'] == 'software.directum' and payload['acceptance_status'] == 'accepted'
    records = list((service.settings.state_root/'setup-functional-acceptance').glob('*.json'))
    assert len(records) == 1
    receipt = json.loads(records[0].read_text())
    assert receipt['plan_id'] == plan['plan_id'] and receipt['plan_sha256'] == plan['sha256']
    assert receipt['confirmed_functional'] is True


@pytest.mark.parametrize('change,code', [('sha', 'setup_plan_mismatch'),
                                        ('expired', 'setup_plan_expired'),
                                        ('facts', 'component_plan_drift')])
def test_functional_accept_cli_preserves_plan_guards(component_service, monkeypatch, change, code):
    from datetime import timedelta
    service, plan = _functional_cli(component_service, monkeypatch)
    sha = plan['sha256']
    if change == 'sha': sha = 'f'*64
    elif change == 'expired': component_service[5][0] += timedelta(minutes=31)
    else: component_service[4]['components']['software.directum']['executable'] = False
    output = io.StringIO()
    assert cli.main(['--json', 'setup', 'component', 'accept', plan['plan_id'], '--confirm-sha256', sha,
                     '--confirm-functional'], settings=service.settings, stdout=output) != 0
    assert json.loads(output.getvalue())['error']['code'] == code
    assert not list((service.settings.state_root/'setup-functional-acceptance').glob('*.json'))


def test_functional_accept_cli_requires_human_confirmation(capsys):
    with pytest.raises(SystemExit) as error:
        cli.build_parser().parse_args(['setup', 'component', 'accept', 'setup-component-'+'a'*64,
                                       '--confirm-sha256', 'a'*64])
    assert error.value.code == 2
    assert '--confirm-functional' in capsys.readouterr().err
