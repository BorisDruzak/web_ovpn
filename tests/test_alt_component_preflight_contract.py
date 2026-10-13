"""Evaluate the shipped preflight expressions with synthetic, read-only results."""
from copy import deepcopy
from pathlib import Path
import re
import sys

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1] / "deploy/alt-linux/ansible"
sys.path.insert(0, str(ROOT.parent/'control'))
from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.setup_execution import catalog_selection


def environment():
    env = NativeEnvironment(undefined=StrictUndefined)
    env.tests["match"] = lambda value, pattern: isinstance(value, str) and bool(re.match(pattern, value))
    env.filters["bool"] = bool
    env.filters['alt_setup_selection'] = lambda document, profile, component='': catalog_selection(
        ComponentCatalog(ROOT, document), profile=profile, component_id=component)
    return env


def preflight(catalog, *, metadata=None, artifacts=None, license_value="synthetic-license", software_profile="core-apps"):
    """Run only the actual preflight task expressions; never invoke commands."""
    env = environment()
    context = {"software_catalog": catalog, "software_profile": software_profile, "remote_access_profile": "none", "vault_cryptopro_license": license_value}
    tasks = yaml.safe_load((ROOT / "playbooks/tasks/configure_component_preflight.yml").read_text())
    reads = []
    for task in tasks:
        loop = env.from_string(task["loop"]).render(**context) if "loop" in task else [None]
        results = []
        for item in loop:
            variables = dict(context)
            loop_var = task.get("loop_control", {}).get("loop_var", "item")
            variables[loop_var] = item
            if "when" in task and not env.compile_expression(task["when"])(**variables):
                results.append({"skipped": True, loop_var: item})
                continue
            if "ansible.builtin.include_vars" in task:
                context[task["ansible.builtin.include_vars"]["name"]] = yaml.safe_load((ROOT / "group_vars/software_catalog.yml").read_text())
            elif "ansible.builtin.set_fact" in task:
                for key, value in task["ansible.builtin.set_fact"].items():
                    context[key] = env.from_string(value).render(**variables) if isinstance(value, str) else value
            elif "ansible.builtin.assert" in task:
                for expression in task["ansible.builtin.assert"]["that"]:
                    assert env.compile_expression(expression)(**variables), task["name"]
            elif "ansible.builtin.stat" in task:
                assert task["delegate_to"] == "localhost"
                reads.append(item)
                state = {"exists": True, "isreg": True, "islnk": False, "checksum": catalog[item]["sha256"]}
                state.update((artifacts or {}).get(item, {}))
                results.append({loop_var: item, "stat": state})
            elif "ansible.builtin.command" in task:
                assert task["delegate_to"] == "localhost"
                assert task["changed_when"] is False
                argv = task["ansible.builtin.command"]["argv"]
                assert argv[:3] == ["rpm", "-qp", "--queryformat"]
                entry = catalog[item]
                output = f"{entry['package_name']}|{entry['package_evr']}|{entry['architecture']}|{entry.get('package_epoch', '(none)')}"
                output = (metadata or {}).get(item, output)
                results.append({loop_var: item, "rc": 0, "stdout": output})
            else:
                raise AssertionError(f"Unexpected preflight operation: {task['name']}")
        if "register" in task:
            context[task["register"]] = {"results": results}
    assert context["configure_component_preflight_passed"] is True
    return reads


@pytest.fixture
def catalog():
    return yaml.safe_load((ROOT / "group_vars/software_catalog.yml").read_text())["software_catalog"]


def test_valid_aggregate_preflight_and_base_without_artifact_reads(catalog):
    assert preflight(catalog) == ["browser", "onlyoffice", "directum", "cryptopro", "cryptopro_cades", "gosuslugi_plugin"]
    assert preflight({}, software_profile="base") == []


def test_actual_pinned_onlyoffice_epoch_passes_both_identity_gates(catalog):
    output = "onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64|100"
    assert preflight(catalog, metadata={"onlyoffice": output}) == ["browser", "onlyoffice", "directum", "cryptopro", "cryptopro_cades", "gosuslugi_plugin"]
    tasks = yaml.safe_load((ROOT / "roles/software_onlyoffice/tasks/main.yml").read_text())
    block = next(task["block"] for task in tasks if "block" in task)
    gate = next(task for task in block if task["name"] == "Require the exact controller onlyoffice RPM identity")
    for expression in gate["ansible.builtin.assert"]["that"]:
        assert environment().compile_expression(expression)(software_catalog=catalog, software_onlyoffice_controller_metadata={"stdout": output})


@pytest.mark.parametrize("session,plugin", [("x11", "xcb"), ("wayland", "pw")])
def test_krfb_framebuffer_matches_managed_desktop_session(session, plugin):
    template = (ROOT / "roles/remote_access_krfb/templates/krfbrc.j2").read_text()
    output = environment().from_string(template).render(
        workstation_desktop_session=session,
        vault_krfb_desktop_password_obscured="test", vault_krfb_unattended_password_obscured="test",
    )
    assert f"preferredFrameBufferPlugin={plugin}" in output


@pytest.mark.parametrize("field,value", [
    ("package_name", "other-package"), ("package_evr", "other-version"),
    ("architecture", "aarch64"), ("artifact_path", "/tmp/unapproved.rpm"),
    ("executable", "/bin/sh"), ("source", "alt-repository"),
    ("package_epoch", 0),
])
def test_invalid_later_rpm_catalog_fails_before_component_execution(catalog, field, value):
    bad_catalog = deepcopy(catalog)
    bad_catalog["onlyoffice"][field] = value
    executed = []
    with pytest.raises(AssertionError):
        preflight(bad_catalog)
        executed.append("browser")
    assert executed == []


@pytest.mark.parametrize("output", [
    "other-package|9.4.0-epm1.repacked.130|x86_64|(none)",
    "onlyoffice-desktopeditors|other-version|x86_64|(none)",
    "onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|aarch64|(none)",
    "onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64|1",
    "onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64|0",
    "onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64|(none)",
])
def test_invalid_later_rpm_bytes_identity_fails_before_component_execution(catalog, output):
    executed = []
    with pytest.raises(AssertionError):
        preflight(catalog, metadata={"onlyoffice": output})
        executed.append("browser")
    assert executed == []


@pytest.mark.parametrize("field,value", [
    ("packages", ["other-package"]), ("packages", "nextcloud-client"),
    ("executable", "/bin/sh"), ("source", "rpm"),
])
def test_invalid_last_repository_component_fails_before_component_execution(catalog, field, value):
    catalog["nextcloud_desktop"][field] = value
    executed = []
    with pytest.raises(AssertionError):
        preflight(catalog)
        executed.append("browser")
    assert executed == []


@pytest.mark.parametrize("assigned,resolved,accepted", [
    ("pilot.user", "pilot.user@sosnadmin.local", True),
    ("Pilot.User@SOSNADMIN.LOCAL", "pilot.user@sosnadmin.local", True),
    ("osn-admin", "osn-admin", False),
    ("osn-admin", "osn-admin@sosnadmin.local", False),
    ("pilot.user", "pilot.user", True),
    ("pilot.user", "other@sosnadmin.local", False),
    ("pilot.user", "pilot.user@other.local", False),
])
def test_krfb_requires_sssd_qualified_identity_before_mutation(assigned, resolved, accepted):
    tasks = yaml.safe_load((ROOT / "roles/remote_access_krfb/tasks/main.yml").read_text())
    normalize = next(task for task in tasks if task["name"] == "Normalize the assigned user to the fixed domain UPN")
    env = environment()
    upn = env.from_string(normalize["ansible.builtin.set_fact"]["krfb_assigned_upn"]).render(assigned_domain_user=assigned)
    lookup = next(task for task in tasks if task["name"] == "Resolve the assigned domain user")
    assert lookup["ansible.builtin.command"]["argv"] == ["getent", "-s", "sss", "passwd", "{{ krfb_assigned_upn }}"]
    gate = next(task for task in tasks if task["name"] == "Require a safe resolved user identity and home path")
    fields = [resolved, "*", "1001", "1001", "", "/home/pilot.user", "/bin/bash"]
    checks = [env.compile_expression(expression)(krfb_account_fields=fields, krfb_assigned_upn=upn) for expression in gate["ansible.builtin.assert"]["that"]]
    assert all(checks) is accepted
    mutations = [i for i, task in enumerate(tasks) if any(key in task for key in ("ansible.builtin.package", "ansible.builtin.file", "ansible.builtin.template"))]
    assert tasks.index(gate) < min(mutations)
    assert normalize["no_log"] and lookup["no_log"] and gate["no_log"]
