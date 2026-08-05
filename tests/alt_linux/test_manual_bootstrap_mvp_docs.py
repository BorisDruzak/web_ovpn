import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "runbooks" / "alt-manual-bootstrap-mvp.md"

FORBIDDEN_INSTRUCTION_PATTERNS = {
    "Vault credential reference": re.compile(r"(?i)\bvault\b"),
    "direct Ansible execution": re.compile(
        r"(?im)^\s*(?:sudo\s+)?(?:"
        r"ansible-(?:playbook|pull|galaxy)\b"
        r"|ansible[\t ]+(?:\S+[\t ]+--?[A-Za-z][\w-]*|--\S+)"
        r")",
    ),
    "password-bearing command": re.compile(
        r"(?ix)"
        r"\bsshpass\s+-p\s+\S+"
        r"|--ask-pass\b"
        r"|\bsudo\s+-S\b"
        r"|\b\w*password\w*\s*=\s*\S+",
    ),
    "managed installation mutation": re.compile(
        r"(?ix)"
        r"\b(?:rebuild|modify|remaster|update|change)\s+(?:the\s+)?managed\s+ISO\b"
        r"|\b(?:modify|change|update)\s+(?:the\s+)?boot\s+menus?\b"
        r"|\b(?:modify|change|update)\s+(?:the\s+)?(?:autoinstall\.scm|install-agent)\b",
    ),
}


def assert_manual_mvp_contract(text: str) -> None:
    for required in (
        "curl --noproxy '*' -fsS",
        "sudo env no_proxy=192.168.100.17",
        "http://192.168.100.17:8087/bootstrap/bootstrap.sh",
        "Domain join and software installation are controller-only.",
        "managed ISO",
        "ai curl=",
    ):
        assert required in text

    for category, pattern in FORBIDDEN_INSTRUCTION_PATTERNS.items():
        match = pattern.search(text)
        assert match is None, f"{category} is forbidden: {match.group()!r}"


def test_manual_mvp_runbook_preserves_the_controller_boundary() -> None:
    assert_manual_mvp_contract(RUNBOOK.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "safe_explanation",
    (
        "Ansible execution remains controller-only.",
        "This pilot does not replace managed ISO workflows.",
    ),
)
def test_manual_mvp_contract_allows_safe_boundary_explanations(
    safe_explanation: str,
) -> None:
    assert_manual_mvp_contract(
        RUNBOOK.read_text(encoding="utf-8") + f"\n{safe_explanation}\n",
    )


@pytest.mark.parametrize(
    ("unsafe_instruction", "expected_category"),
    (
        ("ansible\tall -m ping", "direct Ansible execution"),
        ("sshpass -p secret ssh host", "password-bearing command"),
        ("--ask-pass", "password-bearing command"),
        ("update the managed ISO", "managed installation mutation"),
    ),
)
def test_manual_mvp_contract_rejects_unsafe_instruction_mutations(
    unsafe_instruction: str,
    expected_category: str,
) -> None:
    assert FORBIDDEN_INSTRUCTION_PATTERNS[expected_category].search(
        unsafe_instruction,
    )

    with pytest.raises(AssertionError):
        assert_manual_mvp_contract(
            RUNBOOK.read_text(encoding="utf-8") + f"\n{unsafe_instruction}\n",
        )


@pytest.mark.parametrize(
    "unsafe_instruction",
    (
        "Vault secret usage",
        "Ansible all -m ping",
        "ansible all --module-name ping",
    ),
)
def test_manual_mvp_contract_rejects_regression_bypasses(
    unsafe_instruction: str,
) -> None:
    with pytest.raises(AssertionError):
        assert_manual_mvp_contract(
            RUNBOOK.read_text(encoding="utf-8") + f"\n{unsafe_instruction}\n",
        )
