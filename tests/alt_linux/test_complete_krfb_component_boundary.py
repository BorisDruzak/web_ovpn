"""The direct managed preset cannot downgrade through legacy component apply."""
import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read,private_replace
from test_component_setup import component_service
from test_component_catalog import project


def test_canonical_direct_krfb_requires_its_original_managed_phase(component_service):
    service,setup,machine,*_=component_service
    path=setup.assignments.root/(machine.uuid+'.json')
    value=private_read(path);value.update(software_profile='workstation-full-v1',remote_access_profile='krfb')
    private_replace(path,value)
    with pytest.raises(ControlError) as caught:service.plan(machine.uuid,'remote.krfb')
    assert caught.value.code=='full_workflow_required'
