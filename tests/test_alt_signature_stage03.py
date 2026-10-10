"""Stage-03 signature selection, early failure gates and trust ordering."""
from copy import deepcopy

import pytest
import yaml

from test_alt_component_preflight_contract import ROOT, preflight


SIGNATURE = ["cryptopro", "cryptopro_cades", "gosuslugi_plugin"]


@pytest.fixture
def catalog():
    return yaml.safe_load((ROOT / "group_vars/software_catalog.yml").read_text())["software_catalog"]


@pytest.mark.parametrize("component", SIGNATURE)
@pytest.mark.parametrize("state", [
    {"exists": False}, {"isreg": False}, {"islnk": True}, {"checksum": "0" * 64},
])
def test_bad_signature_archive_stops_before_any_install(catalog, component, state):
    # Exercise the shipped gates; a later missing artifact must stop the entire
    # selected profile, before even its first application can be installed.
    assert component in catalog
    with pytest.raises(AssertionError):
        preflight(catalog, artifacts={component: state})


@pytest.mark.parametrize("component", SIGNATURE)
@pytest.mark.parametrize("field,value", [
    ("artifact_path", "/tmp/unapproved.archive"), ("sha256", "0" * 64),
    ("package_evr", "unapproved-version"), ("enabled", False),
])
def test_signature_catalog_override_is_rejected(catalog, component, field, value):
    bad = deepcopy(catalog)
    assert component in bad
    bad[component][field] = value
    with pytest.raises(AssertionError):
        preflight(bad)


@pytest.mark.parametrize("license_value", [None, "", "   ", False, 123])
def test_license_presence_is_required_only_for_core_apps(catalog, license_value):
    with pytest.raises(AssertionError):
        preflight(catalog, license_value=license_value)
    assert preflight({}, software_profile="base", license_value=license_value) == []


def test_signature_roles_run_after_browser_and_before_government_import():
    tasks = yaml.safe_load((ROOT / "roles/standard_software/tasks/main.yml").read_text())
    include = next(t for t in tasks if "ansible.builtin.include_role" in t)
    mapping = include["vars"]["software_component_role_map"]
    assert [mapping[k] for k in SIGNATURE] == ["software_" + k for k in SIGNATURE]
    phase = yaml.safe_load((ROOT / "playbooks/tasks/configure_critical_phase.yml").read_text())
    roles = [t["ansible.builtin.include_role"]["name"] for t in phase[1]["block"] if "ansible.builtin.include_role" in t]
    assert roles.index("standard_software") < roles.index("government_ca") < roles.index("domain_verify")


@pytest.mark.parametrize("component", SIGNATURE)
def test_signature_results_are_failed_until_existing_role_verifies(component):
    tasks = yaml.safe_load((ROOT / f"roles/software_{component}/tasks/main.yml").read_text())
    assert tasks[0]["ansible.builtin.set_fact"][f"software_{component}_verified"] is False
    final = tasks[-1]["ansible.builtin.set_fact"]
    assert final[f"software_{component}_verified"] is True
    assert "configure_result" in final
    assert "'status': 'failed'" in tasks[0]["ansible.builtin.set_fact"]["configure_result"]
    assert "'status': 'ok'" in final["configure_result"]


def test_license_preflight_is_not_logged():
    tasks = yaml.safe_load((ROOT / "playbooks/tasks/configure_component_preflight.yml").read_text())
    gate = next(t for t in tasks if "license" in t["name"].lower())
    assert gate["no_log"] is True
    assert gate["when"] == "software_profile == 'core-apps'"
