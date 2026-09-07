"""Evaluate the shipped preflight expressions with synthetic, read-only results."""
from copy import deepcopy
from pathlib import Path
import re

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1] / "deploy/alt-linux/ansible"


def environment():
    env = NativeEnvironment(undefined=StrictUndefined)
    env.tests["match"] = lambda value, pattern: isinstance(value, str) and bool(re.match(pattern, value))
    env.filters["bool"] = bool
    return env


def preflight(catalog, *, metadata=None, software_profile="core-apps"):
    """Run only the actual preflight task expressions; never invoke commands."""
    env = environment()
    context = {"software_catalog": catalog, "software_profile": software_profile, "remote_access_profile": "none"}
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
            if "ansible.builtin.set_fact" in task:
                for key, value in task["ansible.builtin.set_fact"].items():
                    context[key] = env.from_string(value).render(**variables) if isinstance(value, str) else value
            elif "ansible.builtin.assert" in task:
                for expression in task["ansible.builtin.assert"]["that"]:
                    assert env.compile_expression(expression)(**variables), task["name"]
            elif "ansible.builtin.stat" in task:
                assert task["delegate_to"] == "localhost"
                reads.append(item)
                results.append({loop_var: item, "stat": {"exists": True, "isreg": True, "islnk": False, "checksum": catalog[item]["sha256"]}})
            elif "ansible.builtin.command" in task:
                assert task["delegate_to"] == "localhost"
                assert task["changed_when"] is False
                argv = task["ansible.builtin.command"]["argv"]
                assert argv[:3] == ["rpm", "-qp", "--queryformat"]
                entry = catalog[item]
                output = f"{entry['package_name']}|{entry['package_evr']}|{entry['architecture']}|(none)"
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
    assert preflight(catalog) == ["browser", "onlyoffice"]
    assert preflight({}, software_profile="base") == []


@pytest.mark.parametrize("field,value", [
    ("package_name", "other-package"), ("package_evr", "other-version"),
    ("architecture", "aarch64"), ("artifact_path", "/tmp/unapproved.rpm"),
    ("executable", "/bin/sh"), ("source", "alt-repository"),
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
    ("pilot.user", "pilot.user", False),
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
