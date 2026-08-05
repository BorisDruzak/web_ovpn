from __future__ import annotations

import re
from pathlib import Path

import pytest

ALT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
)
BOOTSTRAP = ALT_ROOT / "bootstrap" / "bootstrap.sh"
HELPER = ALT_ROOT / "bootstrap" / "alt-bootstrap-register"
BASE_MUTATION_PATTERNS = {
    "package management": r"(?m)^\s*(?:apt-get|apt|dnf|yum|zypper|apk|rpm|dpkg)\b",
    "account/group management": r"(?m)^\s*(?:useradd|adduser|usermod|userdel|groupadd|addgroup|groupmod|gpasswd)\b",
    "SSH configuration": r"(?m)^\s*(?:install_authorized_key\b|(?:install|mkdir|chmod|chown)\b[^\n]*(?:/etc/ssh|\.ssh)|(?:sshd|ssh-keygen)\b|(?:sed|tee|cat)\b[^\n]*/etc/ssh)",
    "sudo configuration": r"(?m)^\s*(?:(?:install|mkdir|chmod|chown|sed|tee|cat)\b[^\n]*(?:sudoers|/etc/sudo)|(?:visudo|sudo)\b)",
    "service control": r"(?m)^\s*(?:systemctl|service|rc-service)\b",
}
REGISTRATION_MUTATION_PATTERNS = {
    **BASE_MUTATION_PATTERNS,
    "direct Ansible": r"(?m)^\s*ansible(?:-playbook|-galaxy|-pull)?\b",
    "domain join": r"(?m)^\s*(?:system-auth\s+write\s+ad|realm\s+join|net\s+ads\s+join)\b",
    "Vault credential action": r"(?m)^\s*(?:ansible-)?vault\s+(?:read|write|kv|get|login|view|decrypt)\b|^\s*(?:export\s+)?VAULT_[A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET)\s*=",
}
BASE_MUTATION_EXAMPLES = (
    ("package management", "apt-get update"),
    ("account/group management", "useradd temporary-user"),
    ("SSH configuration", "install -d /etc/ssh"),
    ("sudo configuration", "visudo -cf /etc/sudoers"),
    ("service control", "systemctl restart sshd"),
)
HELPER_MUTATION_EXAMPLES = (
    *BASE_MUTATION_EXAMPLES,
    ("direct Ansible", "ansible-playbook workstation.yml"),
    ("domain join", "realm join example.test"),
    ("Vault credential action", "vault kv get secret/host"),
)


def function_body(source: str, name: str) -> str:
    """Return a shell function body while keeping source-order assertions readable."""
    start = source.index(f"{name}() {{")
    body_start = source.index("\n", start) + 1
    body_end = source.index("\n}\n", body_start)
    return source[body_start:body_end]


def top_level_executable_source(source: str) -> str:
    """Remove shell function bodies and retain every top-level executable line."""
    return re.sub(r"(?ms)^\w+\(\) \{\n.*?^}\n", "", source)


def normalize_shell_commands(source: str) -> str:
    """Join backslash continuations so action matchers see complete commands."""
    return re.sub(r"\\\n\s*", " ", source)


def assert_completed_bootstrap_skips_base_setup(source: str) -> None:
    main = normalize_shell_commands(top_level_executable_source(source))
    marker_branch_start = main.index('if [[ -f "${MARKER}" ]]; then')
    early_exit = main.index("    exit 0", marker_branch_start)

    assert marker_branch_start < early_exit
    for mutation_class, pattern in BASE_MUTATION_PATTERNS.items():
        mutations = list(re.finditer(pattern, main))
        assert mutations, mutation_class
        assert all(early_exit < mutation.start() for mutation in mutations), mutation_class


def assert_registration_source_has_no_mutations(source: str) -> None:
    source = normalize_shell_commands(source)
    for mutation_class, pattern in REGISTRATION_MUTATION_PATTERNS.items():
        assert not re.search(pattern, source), mutation_class


def test_register_helper_source_exists_and_is_strict() -> None:
    assert HELPER.is_file()
    source = HELPER.read_text(encoding="utf-8")
    assert source.startswith("#!/bin/bash\n")
    assert "set -Eeuo pipefail" in source


def test_register_helper_contains_no_base_or_configuration_mutations() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert_registration_source_has_no_mutations(source)


@pytest.mark.parametrize(("mutation_class", "mutation"), HELPER_MUTATION_EXAMPLES)
def test_register_helper_contract_rejects_mutation(
    mutation_class: str,
    mutation: str,
) -> None:
    source = HELPER.read_text(encoding="utf-8")
    mutated_source = source.replace(
        "REGISTER_URL=",
        f"{mutation}\n\nREGISTER_URL=",
        1,
    )

    with pytest.raises(AssertionError, match=mutation_class):
        assert_registration_source_has_no_mutations(mutated_source)


def test_bootstrap_installs_helper_before_invocation() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert "REGISTER_HELPER_URL" in source
    assert "REGISTER_HELPER_TARGET" in source
    install_position = source.index("install_registration_helper")
    invoke_position = source.index(
        '"${REGISTER_HELPER_TARGET}"',
        install_position,
    )
    marker_position = source.index(
        'touch "${REGISTER_MARKER}"',
        invoke_position,
    )
    assert install_position < invoke_position < marker_position


def test_initial_bootstrap_completes_base_before_registration() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    completion_position = source.rindex('touch "${MARKER}"')
    registration_position = source.rindex("register_machine")

    assert completion_position < registration_position


def test_bootstrap_has_no_embedded_registration_post() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert "--data \"$payload\"" not in source
    assert "payload=$(printf" not in source
    assert "REGISTER_URL=" not in source


def test_bootstrap_remains_non_secret_and_registration_only() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'ANSIBLE_USER="ansible"' in source
    assert 'touch "${MARKER}"' in source
    completed_marker_branch = '''if [[ -f "${MARKER}" ]]; then
    echo "Bootstrap already completed"

    if [[ ! -f "${REGISTER_MARKER}" ]]; then
        register_machine
    else
        echo "Machine already registered"
    fi

    exit 0
fi'''
    assert completed_marker_branch in source
    for forbidden in (
        "ansible-playbook",
        "system-auth write ad",
        "vault_ad_join_password",
        "vault.yml",
        "domain_join",
    ):
        assert forbidden not in source


def test_completed_bootstrap_exits_before_every_base_setup_mutation() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert_completed_bootstrap_skips_base_setup(source)


@pytest.mark.parametrize(("mutation_class", "mutation"), BASE_MUTATION_EXAMPLES)
def test_completed_bootstrap_contract_rejects_pre_entrypoint_mutation(
    mutation_class: str,
    mutation: str,
) -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    mutated_source = source.replace(
        'echo "=== Bootstrap started: $(date) ==="',
        f'{mutation}\n\necho "=== Bootstrap started: $(date) ==="',
        1,
    )

    with pytest.raises(AssertionError, match=mutation_class):
        assert_completed_bootstrap_skips_base_setup(mutated_source)


def test_register_machine_contains_only_registration_operations() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    register_body = function_body(source, "register_machine")

    assert "install_registration_helper" in register_body
    assert '"${REGISTER_HELPER_TARGET}"' in register_body
    assert 'touch "${REGISTER_MARKER}"' in register_body
    assert_registration_source_has_no_mutations(register_body)
