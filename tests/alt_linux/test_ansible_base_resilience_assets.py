from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined


ROOT = Path(__file__).resolve().parents[2] / "deploy/alt-linux/ansible"


def role(name):
    return yaml.safe_load((ROOT / "roles" / name / "tasks/main.yml").read_text(encoding="utf-8"))


def variables():
    return yaml.safe_load((ROOT / "group_vars/all.yml").read_text(encoding="utf-8"))


def flatten(tasks):
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            yield from flatten(task.get(section, []))


def environment():
    env = Environment(undefined=StrictUndefined)
    env.filters["regex_search"] = lambda value, pattern: re.search(pattern, value)
    env.filters["bool"] = bool
    env.tests["succeeded"] = lambda result: not result.get("failed", False)
    env.tests["changed"] = lambda result: result.get("changed", False)
    env.tests["match"] = lambda value, pattern: bool(re.match(pattern, value))
    return env


def evaluate(expression, values):
    if isinstance(expression, bool):
        return expression
    if isinstance(expression, list):
        return all(evaluate(item, values) for item in expression)
    return environment().compile_expression(expression)(**values)


def task_values(task, result):
    values = variables() | {task["register"]: result}
    for key, value in task.get("vars", {}).items():
        values[key] = environment().from_string(value).render(values)
    return values


def test_retry_policies_have_finite_positive_budgets_and_preserve_dns():
    config = variables()
    for prefix in ("alt_transient", "alt_service", "alt_ntp", "alt_package_lock"):
        assert 1 < config.get(f"{prefix}_retry_attempts", 0) <= 24
        assert 0 < config.get(f"{prefix}_retry_delay", 0) <= 5
    assert config.get("alt_domain_join_max_attempts") == 2
    assert config["ad_dns_servers"] == ["192.168.100.11"]


@pytest.mark.parametrize("message, expected", [
    ("Cannot contact any KDC for requested realm", True),
    ("Cannot contact any KDC for realm", True),
    ("ldap_sasl_interactive_bind: Can't contact LDAP server (-1)", True),
    ("Connection timed out", True),
    ("Preauthentication failed", False),
    ("Client not found in Kerberos database", False),
    ("Insufficient access", False),
])
def test_domain_transient_policy_does_not_retry_credentials_or_access(message, expected):
    pattern = variables().get("alt_domain_transient_pattern")
    assert pattern is not None
    assert bool(re.search(pattern, message)) is expected


@pytest.mark.parametrize("register, good, bad, budget", [
    ("manual_preflight_ntp", "yes", "no", "alt_ntp"),
    ("manual_preflight_ldap_srv", "0 100 389 dc.example.test.", "", "alt_transient"),
    ("manual_preflight_kerberos_srv", "0 100 88 dc.example.test.", "", "alt_transient"),
])
def test_preflight_polls_until_time_and_dns_are_healthy(register, good, bad, budget):
    task = next(t for t in role("manual_preflight") if t.get("register") == register)
    assert "until" in task
    for stdout, rc, expected in [(good, 0, True), (bad, 0, False), (good, 1, False)]:
        assert bool(evaluate(task["until"], {register: {"stdout": stdout, "rc": rc}})) is expected
    assert budget + "_retry_attempts" in task["retries"]
    assert budget + "_retry_delay" in task["delay"]


@pytest.mark.parametrize("role_name", ["prejoin_upgrade", "workstation_base", "alt_group_policy_prerequisites"])
@pytest.mark.parametrize("message, attempt, failed, stop", [
    ("", 1, False, True),
    ("Could not get lock /var/lib/rpm/.rpm.lock", 1, True, False),
    ("Temporary failure resolving repo.example.test", 1, True, False),
    ("Temporary failure resolving repo.example.test", 4, True, True),
    ("Signature verification failed", 1, True, True),
    ("Hash Sum mismatch", 1, True, True),
    ("Unmet dependencies", 1, True, True),
    ("Temporary failure resolving repo.example.test; Signature verification failed", 1, True, True),
    ("Unknown package manager error", 1, True, True),
])
def test_packages_retry_only_recognized_transient_failures(role_name, message, attempt, failed, stop):
    tasks = [t for t in flatten(role(role_name)) if "ansible.builtin.package" in t
             or t.get("ansible.builtin.command", {}).get("argv", [None])[0] == "apt-get"]
    assert tasks
    for task in tasks:
        assert "until" in task
        result = {"stdout": "", "stderr": message, "msg": "", "rc": int(failed),
                  "failed": failed, "attempts": attempt}
        assert bool(evaluate(task["until"], task_values(task, result))) is stop
        assert "alt_package_lock_retry_attempts" in task["retries"]
        assert "alt_package_lock_retry_delay" in task["delay"]


def test_apt_metadata_partial_failure_is_not_reported_as_success():
    task = next(t for t in role("prejoin_upgrade")
                if t.get("ansible.builtin.command", {}).get("argv") == ["apt-get", "update"])
    assert "failed_when" in task
    for message, expected in [("", False), ("Temporary failure resolving repo.example.test", True),
                              ("Some index files failed to download", True), ("Signature verification failed", True)]:
        result = {"stdout": "", "stderr": message, "msg": "", "rc": 0}
        assert bool(evaluate(task["failed_when"], task_values(task, result))) is expected


def test_upgrade_reboot_fact_tracks_completed_upgrade_without_rebooting():
    tasks = list(flatten(role("prejoin_upgrade")))
    assert not any("ansible.builtin.reboot" in task for task in tasks)
    facts = [t["ansible.builtin.set_fact"]["prejoin_upgrade_reboot_required"] for t in tasks
             if "prejoin_upgrade_reboot_required" in t.get("ansible.builtin.set_fact", {})]
    assert facts and facts[0] is False
    assert any("prejoin_upgrade_reboot_required" in t.get("ansible.builtin.set_fact", {})
               and "prejoin_upgrade_dist_upgrade is changed" in t.get("when", []) for t in tasks)
    joined = next(t["ansible.builtin.set_fact"]["prejoin_upgrade_already_joined"] for t in tasks
                  if "prejoin_upgrade_already_joined" in t.get("ansible.builtin.set_fact", {}))
    # This folded scalar reaches Ansible's backslash escaping before Jinja.
    # Enforce an escape-free guard so ordinary Jinja cannot hide the original
    # double-escaped regex bug. Render the full template, not a stripped expression.
    assert "\\" not in joined
    for stdout, expected in [
        ("AD example.test", "True"), (" ad\texample.test\n", "True"),
        ("local", "False"), ("", "False"), ("AD", "False"),
    ]:
        rendered = environment().from_string(joined).render(
            prejoin_upgrade_auth_status={"stdout": stdout}
        )
        assert rendered == expected


def test_resolver_guards_reject_links_and_non_root_files_before_writes():
    tasks = role("workstation_network")
    guards = [t for t in tasks if "ansible.builtin.assert" in t]
    assert guards
    file_guard = next((t for t in guards if "workstation_network_active_resolver" in str(t)), None)
    assert file_guard is not None
    safe = {"exists": True, "isreg": True, "islnk": False, "uid": 0}
    values = {"workstation_network_active_resolver": {"stat": safe},
              "workstation_network_persistent_resolver": {"stat": safe}}
    conditions = file_guard["ansible.builtin.assert"]["that"]
    assert evaluate(conditions, values)
    for field in ["workstation_network_active_resolver", "workstation_network_persistent_resolver"]:
        for override in [{"islnk": True}, {"isreg": False}, {"uid": 1000}]:
            assert not evaluate(conditions, values | {field: {"stat": safe | override}})
    assert evaluate(conditions, values | {"workstation_network_persistent_resolver": {"stat": {"exists": False}}})
    stats = [t["ansible.builtin.stat"] for t in tasks if "ansible.builtin.stat" in t]
    assert len(stats) >= 3 and all(t.get("follow") is False for t in stats)
    assert all("ansible.builtin.copy" not in t for t in tasks[:tasks.index(file_guard)])


def test_resolver_transaction_backs_up_both_files_validates_system_dns_and_rolls_back():
    transaction = next((t for t in role("workstation_network") if "rescue" in t), None)
    assert transaction is not None
    writes = [t for t in transaction["block"] if "ansible.builtin.copy" in t]
    assert len(writes) == 2
    assert all(t["ansible.builtin.copy"].get("backup") is True for t in writes)
    assert any(t["ansible.builtin.copy"]["dest"] == "/etc/resolv.conf" for t in writes)
    checks = [t for t in transaction["block"] if "ansible.builtin.command" in t]
    assert len(checks) == 2
    assert {t["ansible.builtin.command"]["argv"][1] for t in checks} == {
        "_ldap._tcp.{{ ad_domain }}", "_kerberos._tcp.{{ ad_domain }}"}
    for task in checks:
        assert task["ansible.builtin.command"]["argv"][0] == "dig"
        assert not any(arg.startswith("@") for arg in task["ansible.builtin.command"]["argv"])
        assert not evaluate(task["until"], {task["register"]: {"rc": 0, "stdout": ""}})
    restores = [t for t in transaction["rescue"] if "ansible.builtin.copy" in t]
    assert len(restores) == 2
    for task in restores:
        assert task["ansible.builtin.copy"]["remote_src"] is True
        assert task["ansible.builtin.copy"]["mode"] == "preserve"
        assert "backup_file" in task["ansible.builtin.copy"]["src"]
        assert "backup_file is defined" in str(task["when"])
    deletes = [t for t in transaction["rescue"]
               if t.get("ansible.builtin.file", {}).get("state") == "absent"]
    assert len(deletes) == 1
    assert deletes[0]["ansible.builtin.file"]["path"] != "/etc/resolv.conf"
    assert "not workstation_network_persistent_resolver.stat.exists" in deletes[0]["when"]
    assert any("is changed" in condition for condition in deletes[0]["when"])
    assert "ansible.builtin.fail" in transaction["rescue"][-1]


def test_group_policy_proves_setup_exists_and_success_before_publishing():
    tasks = role("alt_group_policy_client")
    commands = [t for t in tasks if "ansible.builtin.command" in t]
    assert commands[0]["ansible.builtin.command"]["argv"] == ["sh", "-c", "command -v gpupdate-setup"]
    setup = next(t for t in commands if t["ansible.builtin.command"]["argv"] == ["gpupdate-setup", "enable"])
    update = next(t for t in commands if t["ansible.builtin.command"]["argv"][0] == "gpupdate")
    assert "until" in update
    assert evaluate(update["until"], {update["register"]: {"rc": 0}})
    transient = {"rc": 1, "stderr": "Connection timed out"}
    assert not evaluate(update["until"], task_values(update, transient))
    assert "alt_transient_retry_attempts" in update["retries"]
    guards = [t for t in tasks if "ansible.builtin.assert" in t]
    assert any(setup["register"] + ".rc == 0" in str(t) for t in guards)
    assert tasks.index(update) < len(tasks) - 1
    assert tasks[-1]["ansible.builtin.set_fact"]["alt_group_policy_machine_updated"] is True


@pytest.mark.parametrize("message, stop", [
    ("Connection timed out", False),
    ("Can't contact LDAP server", False),
    ("Temporary failure in name resolution", False),
    ("Access denied", True),
    ("Invalid credentials", True),
    ("Unknown gpupdate failure", True),
    ("Access denied; Connection timed out", True),
])
def test_group_policy_retries_only_recognized_transient_failures(message, stop):
    task = next(t for t in role("alt_group_policy_client")
                if t.get("ansible.builtin.command", {}).get("argv", [None])[0] == "gpupdate")
    result = {"rc": 1, "stdout": "", "stderr": message, "msg": ""}
    assert bool(evaluate(task["until"], task_values(task, result))) is stop
    # A stop decision on an error must preserve command failure.
    assert task.get("failed_when") is not False


@pytest.mark.parametrize("kind, path", [
    ("active", "/etc/resolv.conf"),
    ("persistent", "/etc/net/ifaces/{{ workstation_network_interface }}/resolv.conf"),
])
def test_resolver_rollback_restores_metadata_without_a_content_backup(kind, path):
    transaction = next(t for t in role("workstation_network") if "rescue" in t)
    restore = next((t for t in transaction["rescue"]
                    if t.get("ansible.builtin.file", {}).get("state") == "file"
                    and t["ansible.builtin.file"]["path"] == path), None)
    assert restore is not None
    arguments = restore["ansible.builtin.file"]
    assert arguments["follow"] is False
    stat_register = "workstation_network_" + kind + "_resolver"
    write_register = "workstation_network_" + kind + "_write"
    before = {"exists": True, "uid": 0, "gid": 42, "mode": "0640"}
    values = {stat_register: {"stat": before}, write_register: {"changed": True}}
    # No backup_file key: copy changes only metadata when bytes already match.
    assert evaluate(restore["when"], values)
    for parameter, expected in [("owner", "0"), ("group", "42"), ("mode", "0640")]:
        assert environment().from_string(arguments[parameter]).render(values) == expected
    assert not evaluate(restore["when"], values | {
        stat_register: {"stat": {"exists": False}}
    })
    assert not evaluate(restore["when"], values | {
        write_register: {"changed": False}
    })
