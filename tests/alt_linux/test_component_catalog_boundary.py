"""Protected adapter and bounded parser admission cannot be weakened by metadata."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.errors import ControlError
from test_component_catalog import project, edit


def test_domain_identity_cannot_be_reclassified_as_ordinary_role(project):
    def change(catalog):
        domain = next(c for c in catalog['components'] if c['id'] == 'domain.ready')
        domain['execution'].pop('adapter')
        domain['execution'].update(role='workstation_base', operation='configure', retry_policy='idempotent')
    edit(project, change)
    with pytest.raises(ControlError):
        ComponentCatalog.load(project)


def test_aliases_oversized_and_nested_catalogs_reject(project):
    path = project / 'group_vars/software_catalog.yml'
    for raw in ('value: &x []\nsetup_catalog: *x\n',
                'value: ' + '['*40 + '1' + ']'*40 + '\n',
                '# bounded\n' + ' '*524289):
        path.write_text(raw, encoding='utf-8')
        with pytest.raises(ControlError):
            ComponentCatalog.load(project)
