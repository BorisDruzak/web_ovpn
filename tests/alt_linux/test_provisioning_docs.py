from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
DESIGN_DOC = Path(
    "docs/superpowers/specs/"
    "2026-07-16-alt-workstation-provisioning-mvp-design.md"
)
PLAN_DOC = Path(
    "docs/superpowers/plans/"
    "2026-07-16-alt-workstation-provisioning-mvp.md"
)
CONTEXT_DOC = Path("docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md")
README_DOC = Path("deploy/alt-linux/README.md")
PROVISIONING_DOCS = (DESIGN_DOC, PLAN_DOC)


def read(relative_path: Path) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_provisioning_docs_do_not_use_dotted_employee_logins() -> None:
    violations: list[str] = []
    for relative_path in PROVISIONING_DOCS:
        lines = read(relative_path).splitlines()
        for line_number, line in enumerate(lines, start=1):
            normalized = line.casefold()
            if "i.ivanov" in line or "test.user" in line:
                violations.append(f"{relative_path}:{line_number}: {line.strip()}")
            if "LOGIN_RE" in line and "[a-z0-9._-]" in line:
                violations.append(
                    f"{relative_path}:{line_number}: login regex permits dots"
                )
            if (
                "`.`" in line
                and (
                    "allowed login characters" in normalized
                    or (
                        "employee_login" in normalized
                        and "may contain only" in normalized
                    )
                )
            ):
                violations.append(
                    f"{relative_path}:{line_number}: login rules permit dots"
                )
    assert not violations, "\n".join(violations)


def test_design_doc_does_not_present_sddm_as_current_behavior() -> None:
    assert "sddm" not in read(DESIGN_DOC).casefold()


def test_implementation_plan_does_not_present_sddm_as_current_behavior() -> None:
    assert "sddm" not in read(PLAN_DOC).casefold()


def test_historical_docs_record_the_verified_runtime_contract() -> None:
    required = (
        "ProxyCommand=none",
        "vars_files",
        "`assigned`",
        "`LC_ALL=C`",
        "is not allowed to run sudo",
        "job-20260717T112903Z-71b5afe0",
        "53b03180-5d78-11f0-bd95-f027db877a00",
    )
    for relative_path in PROVISIONING_DOCS:
        content = read(relative_path)
        missing = [fragment for fragment in required if fragment not in content]
        assert not missing, f"{relative_path}: missing {missing}"


def test_deploy_readme_identifies_current_control_plane_context() -> None:
    content = read(README_DOC)
    required = (
        "# ALT Workstation Provisioning",
        "ALT_WORKSTATION_PROVISIONING_CONTEXT.md",
        "ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md",
        "LightDM",
        "AccountsService",
        "192.168.100.17",
        "192.168.100.30",
    )
    missing = [fragment for fragment in required if fragment not in content]
    assert not missing, f"README missing: {missing}"


def test_deploy_readme_documents_installation_and_safe_vault_handling() -> None:
    content = read(README_DOC)
    required = (
        "## Controller prerequisites",
        "sudo bash deploy/alt-linux/install-control-plane.sh",
        "`ansible-playbook`",
        "`ansible-vault`",
        "`systemd-run`",
        "`ssh-keyscan`",
        "`mkpasswd`",
        "tests/alt_linux",
        "01-preflight.yml",
        "02-provision-account.yml",
        "## Vault setup and validation",
        "/home/altserver/ansible/group_vars/vault.yml",
        "/home/altserver/.ansible-vault-pass",
        "vault.yml.example",
        "vault_employee_password_hash",
        "ansible-vault encrypt",
        "chmod 0600",
        "workstationctl --json vault check",
        "vault_unhealthy",
        "Never print",
    )
    missing = [fragment for fragment in required if fragment not in content]
    assert not missing, f"README missing: {missing}"

    forbidden = (
        "cat /home/altserver/.ansible-vault-pass",
        "cat /home/altserver/ansible/group_vars/vault.yml",
        "StrictHostKeyChecking=no",
    )
    unsafe = [fragment for fragment in forbidden if fragment in content]
    assert not unsafe, f"README contains unsafe commands: {unsafe}"


def test_deploy_readme_documents_current_cli_and_request_contract() -> None:
    content = read(README_DOC)
    required = (
        "workstationctl --json machines list",
        "workstationctl --json machines show <uuid>",
        "workstationctl --json preflight <uuid>",
        "workstationctl --json vault check",
        "workstationctl --json controller permissions",
        "workstationctl --json provision preview <uuid>",
        "workstationctl --json provision start <uuid>",
        "workstationctl --json jobs status <job_id>",
        "workstationctl --json jobs log <job_id>",
        "workstationctl --json jobs reconcile",
        '"employee_login": "i-ivanov"',
        '"profile": "standard"',
        "`provision start` requires root",
        "machine_already_assigned",
    )
    missing = [fragment for fragment in required if fragment not in content]
    assert not missing, f"README missing: {missing}"


def test_deploy_readme_documents_state_paths_and_recovery() -> None:
    content = read(README_DOC)
    required = (
        "/var/lib/alt-deploy/jobs/<job_id>/",
        "/var/lib/alt-deploy/assignments/<uuid>.json",
        "/srv/alt-deploy/registration/",
        "/var/lib/alt-workstation/assignment.json",
        "systemctl status alt-deploy-process.path",
        "journalctl -u alt-deploy-process.service",
        "StrictHostKeyChecking=yes",
        "ProxyCommand=none",
        "Do not delete assignment JSON manually",
    )
    missing = [fragment for fragment in required if fragment not in content]
    assert not missing, f"README missing: {missing}"
    assert not re.search(r"employee_login[^\n]*\.", content)


def test_deploy_readme_documents_controller_permission_contract() -> None:
    content = read(README_DOC)
    required = (
        "## Controller state permissions",
        "/var/lib/alt-deploy` | `altserver` | `altserver` | `0700`",
        "/srv/alt-deploy/registration` | `altserver` | `altserver` | `0700`",
        "/home/altserver/.ssh` | `altserver` | `altserver` | `0700`",
        "workstationctl --json controller permissions",
        "workstationctl --json controller permissions repair",
        "controller_permissions_unhealthy",
        "controller_permissions_repair_blocked",
        "controller_permissions_repair_failed",
        "symbolic links",
        "does not create a missing Vault file",
        "requires root",
    )
    missing = [fragment for fragment in required if fragment not in content]
    assert not missing, f"README permission contract missing: {missing}"


def test_recovery_docs_record_phase_2_1_contract() -> None:
    required = (
        "workstationctl --json jobs reconcile",
        "workstationctl.lock",
        "still_running",
        "queued_recoverable",
        "worker_not_started",
        "worker_lost",
        "result_recovered",
        "result_rejected",
        "invalid_provision_result",
        "automatic boot service",
    )

    for relative_path in (README_DOC, CONTEXT_DOC):
        content = " ".join(read(relative_path).split())
        missing = [fragment for fragment in required if fragment not in content]
        assert not missing, f"{relative_path}: recovery docs missing {missing}"
