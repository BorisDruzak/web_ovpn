from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest

ALT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
)
BOOTSTRAP = ALT_ROOT / "bootstrap" / "bootstrap.sh"
HELPER = ALT_ROOT / "bootstrap" / "alt-bootstrap-register"
PACKAGE_COMMANDS = frozenset(
    {"apt-get", "apt", "dnf", "yum", "zypper", "apk", "rpm", "dpkg"}
)
ACCOUNT_COMMANDS = frozenset(
    {
        "useradd",
        "adduser",
        "usermod",
        "userdel",
        "groupadd",
        "addgroup",
        "groupmod",
        "gpasswd",
    }
)
FILESYSTEM_MUTATORS = frozenset(
    {"install", "mkdir", "chmod", "chown", "sed", "tee", "cat"}
)
SERVICE_COMMANDS = frozenset({"systemctl", "service", "rc-service"})
ANSIBLE_COMMANDS = frozenset(
    {"ansible", "ansible-playbook", "ansible-galaxy", "ansible-pull"}
)
VAULT_COMMANDS = frozenset({"vault", "ansible-vault"})
VAULT_ACTIONS = frozenset(
    {"read", "write", "kv", "get", "login", "view", "decrypt"}
)
BASE_MUTATION_CLASSES = (
    "package management",
    "account/group management",
    "SSH configuration",
    "sudo configuration",
    "service control",
)
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
VAULT_SECRET_RE = re.compile(
    r"^VAULT_[A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET)$"
)
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
WRAPPED_BASE_MUTATION_EXAMPLES = (
    ("package management", "/usr/bin/apt-get update"),
    ("account/group management", "/usr/sbin/useradd temporary-user"),
    ("SSH configuration", "/usr/bin/install -d /etc/ssh"),
    ("sudo configuration", "/usr/sbin/visudo -cf /etc/sudoers"),
    ("service control", "/usr/bin/systemctl restart sshd"),
)
WRAPPED_HELPER_MUTATION_EXAMPLES = (
    *WRAPPED_BASE_MUTATION_EXAMPLES,
    ("direct Ansible", "/usr/bin/ansible-playbook workstation.yml"),
    ("domain join", "/usr/bin/realm join example.test"),
    ("Vault credential action", "/usr/bin/vault kv get secret/host"),
    ("Vault credential action", "/usr/bin/curl https://vault.example.test"),
)
HARMLESS_REGISTRATION_SOURCE_EXAMPLES = (
    '# apt = apt-get update\n# service = systemctl restart sshd',
    'echo "ansible = ansible-playbook is controller-only"',
    """cat <<'NOTES'
apt = apt-get update
service = systemctl restart sshd
ansible = ansible-playbook workstation.yml
realm join is controller-only
VAULT_TOKEN=controller-only
NOTES""",
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


@dataclass(frozen=True)
class ShellCommand:
    position: int
    executable: str | None
    arguments: tuple[str, ...]
    assignments: tuple[str, ...]


def _heredoc_redirects(line: str) -> list[tuple[str, bool]]:
    """Find unquoted heredoc redirects in one physical shell line."""
    redirects: list[tuple[str, bool]] = []
    index = 0
    quote: str | None = None
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"':
                index += 1
            index += 1
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        if not line.startswith("<<", index) or line.startswith("<<<", index):
            index += 1
            continue

        cursor = index + 2
        strip_tabs = cursor < len(line) and line[cursor] == "-"
        if strip_tabs:
            cursor += 1
        while cursor < len(line) and line[cursor] in " \t":
            cursor += 1
        if cursor >= len(line):
            break

        if line[cursor] in "'\"":
            delimiter_quote = line[cursor]
            cursor += 1
            end = line.find(delimiter_quote, cursor)
            if end == -1:
                break
            delimiter = line[cursor:end]
            index = end + 1
        else:
            end = cursor
            while end < len(line) and line[end] not in " \t\r\n;&|<>()":
                end += 1
            delimiter = line[cursor:end]
            index = end
        if delimiter:
            redirects.append((delimiter, strip_tabs))
    return redirects


def _without_heredoc_bodies(source: str) -> str:
    """Blank heredoc payloads while preserving command-line source positions."""
    pending: list[tuple[str, bool]] = []
    output: list[str] = []
    for line in source.splitlines(keepends=True):
        if pending:
            delimiter, strip_tabs = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == delimiter:
                pending.pop(0)
                output.append(line)
            else:
                output.append("\n" if line.endswith("\n") else "")
            continue
        output.append(line)
        pending.extend(_heredoc_redirects(line))
    return "".join(output)


def normalize_shell_commands(source: str) -> str:
    """Remove heredoc prose and join backslash command continuations."""
    return re.sub(r"\\\n\s*", " ", _without_heredoc_bodies(source))


def _command_segments(line: str) -> list[list[str]]:
    lexer = shlex.shlex(
        line,
        posix=True,
        punctuation_chars="();<>|&",
    )
    lexer.commenters = "#"
    lexer.whitespace_split = True
    segments: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token and all(char in ";&|()" for char in token):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _is_assignment(token: str) -> bool:
    return ASSIGNMENT_RE.match(token) is not None


def _skip_options(
    tokens: list[str],
    index: int,
    options_with_values: frozenset[str],
) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token == "-" or not token.startswith("-"):
            return index
        index += 2 if token in options_with_values else 1
    return index


def _parse_command(tokens: list[str], position: int) -> ShellCommand | None:
    index = 0
    assignments: list[str] = []
    while index < len(tokens) and tokens[index] in {
        "if",
        "elif",
        "while",
        "until",
        "then",
        "else",
        "do",
        "!",
    }:
        index += 1
    while index < len(tokens) and _is_assignment(tokens[index]):
        assignments.append(tokens[index])
        index += 1

    while index < len(tokens):
        executable = tokens[index].replace("\\", "/").rsplit("/", 1)[-1]
        if executable == "command":
            index += 1
            if index < len(tokens) and tokens[index] in {"-v", "-V"}:
                break
            index = _skip_options(tokens, index, frozenset())
        elif executable == "env":
            index += 1
            index = _skip_options(
                tokens,
                index,
                frozenset({"-u", "--unset", "-C", "--chdir"}),
            )
            while index < len(tokens) and _is_assignment(tokens[index]):
                assignments.append(tokens[index])
                index += 1
        elif executable == "sudo":
            index += 1
            index = _skip_options(
                tokens,
                index,
                frozenset(
                    {
                        "-u",
                        "--user",
                        "-g",
                        "--group",
                        "-h",
                        "--host",
                        "-p",
                        "--prompt",
                        "-C",
                        "--close-from",
                        "-T",
                        "--command-timeout",
                        "-R",
                        "--chroot",
                        "-D",
                        "--chdir",
                    }
                ),
            )
            while index < len(tokens) and _is_assignment(tokens[index]):
                assignments.append(tokens[index])
                index += 1
        else:
            arguments = tuple(tokens[index + 1 :])
            if executable in {"export", "readonly", "local"}:
                assignments.extend(
                    token for token in arguments if _is_assignment(token)
                )
            return ShellCommand(
                position,
                executable,
                arguments,
                tuple(assignments),
            )
    if assignments:
        return ShellCommand(position, None, (), tuple(assignments))
    return None


def shell_commands(source: str) -> list[ShellCommand]:
    """Parse the controlled scripts' command statements, not general shell syntax.

    This deliberately handles this contract's one-line statements, continuations,
    heredocs, and common execution wrappers. It does not interpret eval strings,
    aliases, or dynamically constructed command names.
    """
    source = normalize_shell_commands(source)
    commands: list[ShellCommand] = []
    position = 0
    for line in source.splitlines(keepends=True):
        for segment in _command_segments(line):
            command = _parse_command(segment, position)
            if command is not None:
                commands.append(command)
        position += len(line)
    return commands


def _has_argument_path(command: ShellCommand, fragments: tuple[str, ...]) -> bool:
    return any(
        fragment in argument
        for argument in command.arguments
        for fragment in fragments
    )


def _mutation_class(
    command: ShellCommand,
    *,
    registration: bool,
) -> str | None:
    executable = command.executable
    arguments = command.arguments
    if executable in PACKAGE_COMMANDS:
        return "package management"
    if executable in ACCOUNT_COMMANDS:
        return "account/group management"
    if executable in {"install_authorized_key", "sshd", "ssh-keygen"} or (
        executable in FILESYSTEM_MUTATORS
        and _has_argument_path(command, ("/etc/ssh", ".ssh"))
    ):
        return "SSH configuration"
    if executable == "visudo" or (
        executable in FILESYSTEM_MUTATORS
        and _has_argument_path(command, ("sudoers", "/etc/sudo"))
    ):
        return "sudo configuration"
    if executable in SERVICE_COMMANDS:
        return "service control"
    if not registration:
        return None
    if executable in ANSIBLE_COMMANDS:
        return "direct Ansible"
    if (
        executable == "system-auth"
        and arguments[:2] == ("write", "ad")
    ) or (
        executable == "realm" and arguments[:1] == ("join",)
    ) or (
        executable == "net" and arguments[:2] == ("ads", "join")
    ):
        return "domain join"
    if executable in VAULT_COMMANDS and arguments[:1] in {
        (action,) for action in VAULT_ACTIONS
    }:
        return "Vault credential action"
    for assignment in command.assignments:
        name = assignment.split("=", 1)[0].removesuffix("+")
        if VAULT_SECRET_RE.fullmatch(name):
            return "Vault credential action"
    return None


def shell_mutations(
    source: str,
    *,
    registration: bool,
) -> list[tuple[str, int]]:
    mutations: list[tuple[str, int]] = []
    for command in shell_commands(source):
        mutation_class = _mutation_class(command, registration=registration)
        if mutation_class is not None:
            mutations.append((mutation_class, command.position))
    return mutations


def assert_completed_bootstrap_reconciles_technical_access(source: str) -> None:
    main = normalize_shell_commands(top_level_executable_source(source))
    marker_branch_start = main.index('if [[ -f "${MARKER}" ]]; then')
    marker_branch_end = main.index("\nfi\n", marker_branch_start) + len("\nfi\n")
    technical_key_position = main.index(
        "if ! install_authorized_key",
        marker_branch_start,
    )
    deferred_exit_position = main.index(
        "exit 0",
        technical_key_position,
    )
    registration_position = main.rindex("register_machine")

    assert marker_branch_start < registration_position
    assert "Bootstrap marker exists; reconciling technical access" in main
    assert "exit 0" not in main[marker_branch_start:marker_branch_end]
    assert marker_branch_start < technical_key_position < deferred_exit_position


def assert_registration_source_has_no_mutations(source: str) -> None:
    mutations = shell_mutations(source, registration=True)
    assert not mutations, mutations[0][0]


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


@pytest.mark.parametrize(
    ("mutation_class", "mutation"),
    WRAPPED_HELPER_MUTATION_EXAMPLES,
)
def test_register_helper_contract_rejects_wrapped_mutation(
    mutation_class: str,
    mutation: str,
) -> None:
    assignments = (
        "VAULT_TOKEN=secret "
        if mutation_class == "Vault credential action" and "curl" in mutation
        else "LC_ALL=C "
    )
    wrapped_mutation = (
        f"if ! command env {assignments}sudo --user root --non-interactive -- "
        f"{mutation}; then :; fi"
    )

    with pytest.raises(AssertionError, match=mutation_class):
        assert_registration_source_has_no_mutations(wrapped_mutation)


@pytest.mark.parametrize("source", HARMLESS_REGISTRATION_SOURCE_EXAMPLES)
def test_register_helper_contract_accepts_non_command_text(source: str) -> None:
    assert_registration_source_has_no_mutations(source)


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
    assert "Bootstrap marker exists; reconciling technical access before registration" in source
    for forbidden in (
        "ansible-playbook",
        "system-auth write ad",
        "vault_ad_join_password",
        "vault.yml",
        "domain_join",
    ):
        assert forbidden not in source


def test_bootstrap_defers_registration_without_losing_technical_access() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'usermod -aG wheel "${LOCAL_ADMIN}"' in source
    assert 'RETRY_SERVICE="/etc/systemd/system/alt-bootstrap-register-retry.service"' in source
    assert 'RETRY_TIMER="/etc/systemd/system/alt-bootstrap-register-retry.timer"' in source
    assert 'OnUnitActiveSec=5min' in source
    assert 'ExecStart=/usr/local/sbin/alt-bootstrap' in source
    assert 'write_state "registration_deferred"' in source


def test_bootstrap_recovers_only_existing_networkmanager_profile() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert "recover_existing_networkmanager_profile()" in source
    assert "nmcli -t -f NAME connection show --active" in source
    assert 'nmcli connection up id "${profile}"' in source
    assert "network_ready()" in source
    assert "recover_existing_networkmanager_profile || true" in source


def test_completed_bootstrap_reconciles_every_owned_technical_artifact() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert_completed_bootstrap_reconciles_technical_access(source)


@pytest.mark.parametrize(("mutation_class", "mutation"), BASE_MUTATION_EXAMPLES)
def test_completed_bootstrap_contract_rejects_marker_early_exit(
    mutation_class: str,
    mutation: str,
) -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    mutated_source = source.replace(
        'echo "Bootstrap marker exists; reconciling technical access before registration"',
        'echo "Bootstrap marker exists; reconciling technical access before registration"\n    exit 0',
        1,
    )

    with pytest.raises(AssertionError):
        assert_completed_bootstrap_reconciles_technical_access(mutated_source)


@pytest.mark.parametrize(
    ("mutation_class", "mutation"),
    WRAPPED_BASE_MUTATION_EXAMPLES,
)
def test_completed_bootstrap_contract_rejects_wrapped_marker_early_exit(
    mutation_class: str,
    mutation: str,
) -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    mutated_source = source.replace(
        'echo "Bootstrap marker exists; reconciling technical access before registration"',
        'echo "Bootstrap marker exists; reconciling technical access before registration"\n    exit 0',
        1,
    )

    with pytest.raises(AssertionError):
        assert_completed_bootstrap_reconciles_technical_access(mutated_source)


def test_register_machine_contains_only_registration_operations() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")
    register_body = function_body(source, "register_machine")

    assert "install_registration_helper" in register_body
    assert '"${REGISTER_HELPER_TARGET}"' in register_body
    assert 'touch "${REGISTER_MARKER}"' in register_body
    assert_registration_source_has_no_mutations(register_body)
