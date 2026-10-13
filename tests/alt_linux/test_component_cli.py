"""Published inspection needs neither AD credentials nor a live workstation."""
import io
import json

import pytest

from alt_deploy import cli, setup_cli
from alt_deploy.config import Settings
from test_component_verification import CATALOG


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
