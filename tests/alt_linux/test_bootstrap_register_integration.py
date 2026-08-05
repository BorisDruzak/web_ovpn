from __future__ import annotations

from pathlib import Path

import pytest

ALT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
)
BOOTSTRAP = ALT_ROOT / "bootstrap" / "bootstrap.sh"
HELPER = ALT_ROOT / "bootstrap" / "alt-bootstrap-register"
BASE_SETUP_MUTATIONS = (
    "apt-get update",
    "apt-get install -y",
    "useradd ",
    "usermod -aG wheel",
    '"/home/${ANSIBLE_USER}/.ssh"',
    "install_authorized_key",
    'cat > "/etc/sudoers.d/90-${ANSIBLE_USER}"',
    "chmod 0440",
    "visudo -cf",
    'systemctl enable --now sshd',
)
REGISTRATION_FORBIDDEN_MUTATIONS = (
    "apt-get",
    "useradd",
    "usermod",
    "groupadd",
    "adduser",
    "addgroup",
    "install_authorized_key",
    "/etc/ssh",
    ".ssh",
    "/etc/sudoers.d/",
    "sudo",
    "visudo",
    "systemctl",
    "ansible",
    "domain",
    "vault",
)


def function_body(source: str, name: str) -> str:
    """Return a shell function body while keeping source-order assertions readable."""
    start = source.index(f"{name}() {{")
    body_start = source.index("\n", start) + 1
    body_end = source.index("\n}\n", body_start)
    return source[body_start:body_end]


def bootstrap_main(source: str) -> str:
    """Return the executable bootstrap section, excluding function definitions."""
    return source[source.index('echo "=== Bootstrap started: $(date) ==="') :]


def assert_completed_bootstrap_skips_base_setup(source: str) -> None:
    main = bootstrap_main(source)
    marker_branch_start = main.index('if [[ -f "${MARKER}" ]]; then')
    early_exit = main.index("    exit 0", marker_branch_start)

    assert marker_branch_start < early_exit
    for base_setup in BASE_SETUP_MUTATIONS:
        mutation_position = main.index(base_setup)
        assert early_exit < mutation_position, base_setup


def assert_registration_source_has_no_base_or_configuration_mutations(
    source: str,
) -> None:
    source = source.lower()
    for forbidden in REGISTRATION_FORBIDDEN_MUTATIONS:
        assert forbidden not in source, forbidden


def test_register_helper_source_exists_and_is_strict() -> None:
    assert HELPER.is_file()
    source = HELPER.read_text(encoding="utf-8")
    assert source.startswith("#!/bin/bash\n")
    assert "set -Eeuo pipefail" in source


def test_register_helper_contains_no_base_or_configuration_mutations() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert_registration_source_has_no_base_or_configuration_mutations(source)


def test_register_helper_contract_rejects_package_mutation() -> None:
    source = HELPER.read_text(encoding="utf-8")
    mutated_source = source.replace(
        "REGISTER_URL=",
        "apt-get update\n\nREGISTER_URL=",
        1,
    )

    with pytest.raises(AssertionError, match="apt-get"):
        assert_registration_source_has_no_base_or_configuration_mutations(
            mutated_source,
        )


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


def test_completed_bootstrap_contract_rejects_pre_marker_package_mutation() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    mutated_source = source.replace(
        'if [[ -f "${MARKER}" ]]; then',
        'apt-get update\n\nif [[ -f "${MARKER}" ]]; then',
        1,
    )

    with pytest.raises(AssertionError, match="apt-get update"):
        assert_completed_bootstrap_skips_base_setup(mutated_source)


def test_register_machine_contains_only_registration_operations() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    register_body = function_body(source, "register_machine")

    assert "install_registration_helper" in register_body
    assert '"${REGISTER_HELPER_TARGET}"' in register_body
    assert 'touch "${REGISTER_MARKER}"' in register_body
    assert_registration_source_has_no_base_or_configuration_mutations(register_body)
