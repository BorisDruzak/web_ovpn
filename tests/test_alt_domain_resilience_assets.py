from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1] / "deploy/alt-linux/ansible"


def load(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def role(name):
    path = ROOT / "roles" / name / "tasks/main.yml"
    assert path.exists(), f"Missing required role: {name}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def flatten(tasks, inherited=None):
    for task in tasks:
        effective = (inherited or {}) | task
        effective["vars"] = (inherited or {}).get("vars", {}) | task.get("vars", {})
        effective["when"] = (inherited or {}).get("when", []) + (
            task.get("when", []) if isinstance(task.get("when", []), list)
            else [task["when"]]
        )
        yield effective
        for section in ("tasks", "block", "rescue", "always"):
            yield from flatten(task.get(section, []), {
                key: effective[key] for key in ("no_log", "vars", "when", "environment")
                if key in effective
            })


def env():
    environment = NativeEnvironment(undefined=StrictUndefined)
    environment.filters["regex_search"] = lambda value, pattern: re.search(pattern, value)
    environment.filters["bool"] = bool
    environment.filters["combine"] = lambda left, right: left | right
    environment.tests["search"] = lambda value, pattern: bool(re.search(pattern, value))
    environment.tests["match"] = lambda value, pattern: bool(re.match(pattern, value))
    return environment


def evaluate(expression, values):
    if isinstance(expression, bool):
        return expression
    if isinstance(expression, list):
        return all(evaluate(item, values) for item in expression)
    return env().compile_expression(expression)(**values)


def task_values(task, values=None):
    context = load("group_vars/all.yml") | (values or {})
    for key, value in task.get("vars", {}).items():
        context[key] = env().from_string(value).render(context)
    return context


def by_register(name, register):
    task = next((task for task in flatten(role(name)) if task.get("register") == register), None)
    assert task is not None, f"Missing command result: {register}"
    return task


def fact(name, fact_name):
    tasks = [task for task in flatten(role(name))
             if fact_name in task.get("ansible.builtin.set_fact", {})]
    assert tasks, f"Missing outcome fact: {fact_name}"
    return tasks[-1]


@pytest.mark.parametrize("register", ["domain_join_ticket", "domain_join_computer_lookup", "domain_join_retry_lookup"])
@pytest.mark.parametrize("message, rc, stop", [
    ("", 0, True),
    ("Cannot contact any KDC for requested realm", 1, False),
    ("Can't contact LDAP server", 1, False),
    ("Connection timed out", 1, False),
    ("Preauthentication failed", 1, True),
    ("Client not found in Kerberos database", 1, True),
    ("Invalid credentials", 1, True),
    ("Insufficient access", 1, True),
    ("Unknown failure", 1, True),
    ("Invalid credentials; Connection timed out", 1, True),
])
def test_ticket_and_ldap_retry_only_recognized_transients(register, message, rc, stop):
    task = by_register("domain_join", register)
    assert "until" in task
    result = {"rc": rc, "stdout": "", "stderr": message}
    values = task_values(task, {register: result})
    assert bool(evaluate(task["until"], values)) is stop
    assert task.get("failed_when") is not False
    assert env().from_string(task["retries"]).render(values) == 3
    assert env().from_string(task["delay"]).render(values) == 5
    assert task["no_log"] is True
    assert task["environment"]["LC_ALL"] == "C"


@pytest.mark.parametrize("register", ["domain_join_computer_lookup", "domain_join_retry_lookup"])
def test_computer_lookup_proves_absence_across_domain_not_only_target_ou(register):
    task = by_register("domain_join", register)
    argv = task["ansible.builtin.command"]["argv"]
    values = {"ad_domain": "example.test", "computer_ou": "OU=Workstations,DC=example,DC=test"}
    assert env().from_string(argv[argv.index("-b") + 1]).render(values) == "DC=example,DC=test"
    assert argv[argv.index("-s") + 1] == "sub"
    assert "(sAMAccountName={{ final_hostname }}$)" in argv


@pytest.mark.parametrize("stdout, exists", [("", False), ("dn: CN=PC,OU=Other,DC=example,DC=test", True), ("dn:: Q049UEM=", True)])
def test_initial_lookup_rejects_existing_plain_or_base64_computer_dn(stdout, exists):
    task = fact("domain_join", "domain_join_computer_exists")
    value = task["ansible.builtin.set_fact"]["domain_join_computer_exists"]
    assert env().from_string(value).render(domain_join_computer_lookup={"rc": 0, "stdout": stdout}) is exists


def test_first_join_has_explicit_absence_gate_and_never_uses_blind_retries():
    task = by_register("domain_join", "domain_join_command")
    assert "until" not in task and "retries" not in task
    for lookup_rc, exists, allowed in [(0, False, True), (0, True, False), (1, False, False)]:
        values = {"domain_join_already_joined": False, "domain_join_computer_exists": exists,
                  "domain_join_computer_lookup": {"rc": lookup_rc}}
        assert bool(evaluate(task["when"], values)) is allowed
    assert task["failed_when"] is False  # The following trust check reconciles ambiguous writes.


@pytest.mark.parametrize("join_rc, trust_rc, message, limit, allowed", [
    (1, 1, "Connection timed out", 2, True),
    (1, 1, "Cannot contact any KDC", 2, True),
    (1, 0, "Connection timed out", 2, False),
    (0, 1, "", 2, False),
    (1, 1, "Connection timed out", 1, False),
    (1, 1, "Access denied", 2, False),
    (1, 1, "Unknown failure", 2, False),
    (1, 1, "Access denied; Connection timed out", 2, False),
])
def test_join_retry_requires_transient_failure_and_failed_trust_reconciliation(join_rc, trust_rc, message, limit, allowed):
    task = fact("domain_join", "domain_join_retry_allowed")
    values = task_values(task, {
        "domain_join_command": {"rc": join_rc, "stdout": "", "stderr": message},
        "domain_join_reconcile": {"rc": trust_rc}, "alt_domain_join_max_attempts": limit,
    })
    assert env().from_string(task["ansible.builtin.set_fact"]["domain_join_retry_allowed"]).render(values) is allowed


@pytest.mark.parametrize("lookup_rc, stdout, allowed", [
    (0, "", True), (0, "dn: CN=PC", False), (0, "dn:: Q049UEM=", False),
    (1, "", False), (32, "", False),
])
def test_only_second_join_is_gated_by_successful_post_failure_ldap_absence(lookup_rc, stdout, allowed):
    tasks = list(flatten(role("domain_join")))
    writes = [task for task in tasks if task.get("ansible.builtin.command", {}).get("argv", [])[:3] == ["system-auth", "write", "ad"]]
    assert len(writes) == 2
    retry = by_register("domain_join", "domain_join_retry_command")
    assert "until" not in retry and "retries" not in retry
    assert bool(evaluate(retry["when"], {
        "domain_join_already_joined": False, "domain_join_retry_allowed": True,
        "domain_join_retry_lookup": {"rc": lookup_rc, "stdout": stdout},
    })) is allowed
    registers = [task.get("register") for task in tasks]
    assert registers.index("domain_join_command") < registers.index("domain_join_reconcile") < registers.index("domain_join_retry_lookup") < registers.index("domain_join_retry_command")
    assert by_register("domain_join", "domain_join_reconcile")["ansible.builtin.command"]["argv"] == ["net", "ads", "testjoin"]


def test_domain_join_credentials_and_trust_checks_remain_secret_and_cleanup_is_unconditional():
    tasks = list(flatten(role("domain_join")))
    for task in tasks:
        argv = task.get("ansible.builtin.command", {}).get("argv", [])
        if argv and (argv[0] in ["kinit", "kdestroy", "ldapsearch", "net"] or argv[:3] == ["system-auth", "write", "ad"]):
            assert task.get("no_log") is True
            assert not any("password" in argument.lower() for argument in argv)
    block = next(task for task in role("domain_join") if "always" in task)
    assert block["always"][-1]["ansible.builtin.command"]["argv"] == ["kdestroy"]
    assert block["always"][-1]["failed_when"] is False


@pytest.mark.parametrize("register", ["domain_join_testjoin", "domain_join_reconcile", "domain_join_retry_reconcile"])
@pytest.mark.parametrize("rc, message, attempt, stop", [
    (0, "", 1, True), (1, "Connection timed out", 1, False),
    (1, "Connection timed out", 4, True), (1, "Invalid credentials", 1, True),
    (1, "Unknown failure", 1, True),
    (1, "Cannot contact any KDC", 1, False),
    (1, "Invalid credentials; Connection timed out", 1, True),
])
def test_trust_reconciliation_retries_reads_but_retains_last_failure_for_safe_join_decision(register, rc, message, attempt, stop):
    task = by_register("domain_join", register)
    assert "until" in task
    values = task_values(task, {register: {"rc": rc, "stderr": message, "attempts": attempt}})
    assert bool(evaluate(task["until"], values)) is stop
    assert task["failed_when"] is False
    assert env().from_string(task["retries"]).render(values) == 3
    assert task["no_log"] is True
    assert task["environment"]["LC_ALL"] == "C"


def test_initial_trust_probe_finishes_before_deciding_whether_to_skip_join():
    tasks = list(flatten(role("domain_join")))
    probe = by_register("domain_join", "domain_join_testjoin")
    assert "until" in probe
    decision = fact("domain_join", "domain_join_already_joined")
    assert tasks.index(probe) < tasks.index(decision)
    template = decision["ansible.builtin.set_fact"]["domain_join_already_joined"]
    assert env().from_string(template).render(domain_join_testjoin={"rc": 0}) is True
    assert env().from_string(template).render(domain_join_testjoin={"rc": 1}) is False
    assert probe["failed_when"] is False
    values = task_values(probe, {"domain_join_testjoin": {"rc": 1, "stderr": "", "attempts": 1}})
    assert env().from_string(probe["delay"]).render(values) == 5


def test_login_baseline_owns_pam_write_and_precedes_software_remote_and_verification():
    baseline = role("domain_login_baseline")
    assert any(task.get("ansible.builtin.lineinfile", {}).get("path") == "/etc/pam.d/system-auth-sss-only" for task in baseline)
    verify = list(flatten(role("domain_verify")))
    assert not any("ansible.builtin.lineinfile" in task for task in verify)
    phase = load("playbooks/tasks/configure_critical_phase.yml")
    names = [task["ansible.builtin.include_role"]["name"] for task in flatten(phase) if "ansible.builtin.include_role" in task]
    assert names == ["manual_preflight", "workstation_identity", "prejoin_upgrade", "workstation_base",
                     "alt_group_policy_prerequisites", "workstation_network", "domain_join",
                     "alt_group_policy_client", "domain_login_baseline", "standard_software",
                     "remote_access_krfb", "domain_verify"]
    krfb = next(task for task in flatten(phase)
                if task.get("ansible.builtin.include_role", {}).get("name") == "remote_access_krfb")
    assert krfb["when"] == ["remote_access_profile == 'krfb'"]
    assert names.index("standard_software") < names.index("remote_access_krfb") < names.index("domain_verify")


@pytest.mark.parametrize("line", [
    "session required pam_mkhomedir.so skel=/etc/skel umask=0022",
    "session\trequired\tpam_mkhomedir.so umask=0077",
])
def test_login_baseline_replaces_existing_pam_rule_with_python_compatible_pattern(line):
    arguments = next(task["ansible.builtin.lineinfile"] for task in role("domain_login_baseline")
                     if "ansible.builtin.lineinfile" in task)
    assert re.search(arguments["regexp"], line)


@pytest.mark.parametrize("status, allowed", [
    ("AD example.test", True), ("ad\texample.test", True),
    ("AD other.test", False), ("AD badexample.test", False), ("local", True),
])
def test_domain_conflict_guard_handles_spaces_tabs_and_exact_domain(status, allowed):
    task = next(task for task in role("domain_join")
                if task.get("name") == "Reject a different Active Directory domain")
    assert bool(evaluate(task["ansible.builtin.assert"]["that"], {
        "domain_join_status": {"stdout": status}, "ad_domain": "example.test"
    })) is allowed


def test_domain_verification_publishes_actual_partial_facts_even_on_failure():
    task = fact("domain_verify", "domain_verification")
    verification = task["ansible.builtin.set_fact"]["domain_verification"]
    values = {"domain_verify_join": {"rc": 0}, "domain_verify_sssd": {"rc": 3, "stdout": "inactive"}}
    rendered = {key: env().from_string(value).render(values) for key, value in verification.items()}
    assert rendered == {"domain_join": True, "sssd": False, "domain_user_lookup": False, "home_creation": False}
    container = next(task for task in role("domain_verify") if "always" in task)
    assert any("domain_verification" in task.get("ansible.builtin.set_fact", {}) for task in container["always"])


@pytest.mark.parametrize("register", ["domain_verify_join", "domain_verify_sssd", "domain_verify_user"])
def test_domain_verification_has_bounded_readiness_checks(register):
    task = by_register("domain_verify", register)
    assert "until" in task and "retries" in task and "delay" in task
    failure_rc = {"domain_verify_join": 1, "domain_verify_sssd": 3, "domain_verify_user": 2}[register]
    for rc, stdout, ready in [(0, "active", True), (failure_rc, "inactive", False)]:
        values = task_values(task, {register: {"rc": rc, "stdout": stdout, "stderr": "Connection timed out"}})
        assert bool(evaluate(task["until"], values)) is ready
    assert env().from_string(task["retries"]).render(load("group_vars/all.yml")) <= 11


@pytest.mark.parametrize("register, result", [
    ("domain_verify_join", {"rc": 1, "stderr": "Invalid credentials; Connection timed out"}),
    ("domain_verify_join", {"rc": 1, "stderr": "Unknown error"}),
    ("domain_verify_sssd", {"rc": 4, "stdout": "unknown"}),
    ("domain_verify_user", {"rc": 1, "stderr": "Unknown database"}),
])
def test_verification_stops_on_fatal_and_unknown_failures(register, result):
    task = by_register("domain_verify", register)
    assert evaluate(task["until"], task_values(task, {register: result}))
    assert task.get("failed_when") is not False


@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize("upgrade, joined, expected", [(False, False, False), (True, False, True), (False, True, True), (True, True, True)])
def test_finalizer_preserves_reboot_facts_and_verification_for_success_and_failure(failed, upgrade, joined, expected):
    phase = load("playbooks/tasks/configure_critical_phase.yml")[1]
    section = phase["rescue"] if failed else phase["block"]
    task = next(task for task in section if task.get("name") == ("Build failed configure result" if failed else "Finalize successful configure result"))
    rendered = env().from_string(task["ansible.builtin.set_fact"]["configure_result"]).render(
        configure_result={"phase": "domain_core_verify", "components": {}, "verification": {}}, prejoin_upgrade_reboot_required=upgrade,
        domain_join_reboot_required=joined, domain_join_recovered=True,
        domain_verification={"domain_join": True, "sssd": False, "domain_user_lookup": False, "home_creation": True},
        alt_group_policy_machine_updated=True,
    )
    assert rendered["reboot_required"] is expected
    assert rendered["recovered"] is True
    assert rendered["verification"] == {"domain_join": True, "sssd": False, "domain_user_lookup": False, "home_creation": True, "group_policy": True}
    if failed:
        assert list(section[-2])[-1] == "ansible.builtin.include_tasks"
        assert "ansible.builtin.fail" in section[-1]


def test_stage03_roles_and_playbooks_never_reboot_or_delete_domain_accounts():
    paths = [*(ROOT / "roles").glob("*/tasks/*.yml"), *(ROOT / "playbooks").rglob("*.yml")]
    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert "ansible.builtin.reboot" not in content
        for task in flatten(yaml.safe_load(content)):
            argv = task.get("ansible.builtin.command", {}).get("argv", [])
            assert not (argv and argv[0] in ["reboot", "shutdown", "ldapdelete"])
            assert argv[:3] != ["net", "ads", "leave"]


@pytest.mark.parametrize("failed", [False, True])
def test_component_finalizer_preserves_partial_results_and_redacts_failure_details(failed):
    result = {"phase": "components", "components": {}, "verification": {}, "error": None}
    for component in ["browser", "onlyoffice"]:
        tasks = role("software_" + component)
        result = env().from_string(tasks[0]["ansible.builtin.set_fact"]["configure_result"]).render(
            configure_result=result
        )
        if component == "browser" or not failed:
            result = env().from_string(tasks[-1]["ansible.builtin.set_fact"]["configure_result"]).render(
                configure_result=result
            )
    phase = load("playbooks/tasks/configure_critical_phase.yml")[1]
    section = phase["rescue"] if failed else phase["block"]
    name = "Build failed configure result" if failed else "Finalize successful configure result"
    task = next(task for task in section if task["name"] == name)
    rendered = env().from_string(task["ansible.builtin.set_fact"]["configure_result"]).render(
        configure_result=result,
        ansible_failed_result={"stdout": "private package output", "stderr": "private artifact path"},
        domain_verification={"domain_join": True},
    )
    assert rendered["components"]["browser"] == {"status": "ok", "verified": True}
    assert rendered["components"]["onlyoffice"] == {
        "status": "failed" if failed else "ok", "verified": not failed,
    }
    assert rendered["verification"] == {
        "software_browser": True, "software_onlyoffice": not failed,
        "domain_join": True, "group_policy": False,
    }
    assert "private" not in str(rendered)
    assert rendered["status"] == ("failed" if failed else "successful")
    assert rendered["error"] == ({
        "code": "configure_critical_phase_failed", "class": "fatal-invariant",
        "safe_message": "Critical phase configuration failed",
    } if failed else None)


def test_base_software_profile_selects_no_roles_and_does_not_change_result():
    selection = load("playbooks/tasks/configure_component_preflight.yml")[0]
    selected = env().from_string(selection["ansible.builtin.set_fact"]["selected_software_components"]).render(
        software_profile="base"
    )
    assert selected == []
    tasks = role("standard_software")
    values = {"software_profile": "base", "selected_software_components": selected,
              "configure_component_preflight_passed": True}
    assert evaluate(tasks[0]["ansible.builtin.assert"]["that"], values)
    for task in tasks:
        if "ansible.builtin.set_fact" in task:
            assert not evaluate(task["when"], values)
        if "ansible.builtin.include_role" in task:
            assert env().from_string(task["loop"]).render(values) == []
