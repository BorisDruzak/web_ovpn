"""Human acceptance is explicit and bound to a fresh technical snapshot."""
import pytest

from alt_deploy.errors import ControlError
from test_component_setup import component_service
from test_component_catalog import project
from test_component_verification import UUID


def test_functional_acceptance_requires_explicit_confirmation_and_current_noop(component_service):
    service, _, _, _, observed, *_ = component_service
    component = 'software.directum'
    # The fixture has a correctly installed Directum component.
    plan = service.plan(UUID, component)
    assert plan['payload']['action'] == 'noop'
    assert service.verify(UUID, component)['components'][component]['acceptance_status'] == 'functional_verification_required'
    with pytest.raises(ControlError):
        service.accept(plan['plan_id'], plan['sha256'], confirmed=False)
    accepted = service.accept(plan['plan_id'], plan['sha256'], confirmed=True)
    assert accepted['acceptance_status'] == 'accepted'
    assert service.verify(UUID, component)['components'][component]['acceptance_status'] == 'accepted'
    observed['components'][component]['executable'] = False
    assert service.verify(UUID, component)['components'][component]['acceptance_status'] != 'accepted'


def test_acceptance_never_applies_missing_software_or_accepts_nonfunctional_component(component_service):
    service, _, _, _, observed, *_ = component_service
    plan = service.plan(UUID, 'system.base')
    with pytest.raises(ControlError):
        service.accept(plan['plan_id'], plan['sha256'], confirmed=True)
    observed['components']['software.directum']['packages'] = []
    plan = service.plan(UUID, 'software.directum')
    with pytest.raises(ControlError):
        service.accept(plan['plan_id'], plan['sha256'], confirmed=True)
