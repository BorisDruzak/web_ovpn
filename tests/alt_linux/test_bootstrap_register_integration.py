from __future__ import annotations

from pathlib import Path

ALT_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
)
BOOTSTRAP = ALT_ROOT / "bootstrap" / "bootstrap.sh"
HELPER = ALT_ROOT / "bootstrap" / "alt-bootstrap-register"


def test_register_helper_source_exists_and_is_strict() -> None:
    assert HELPER.is_file()
    source = HELPER.read_text(encoding="utf-8")
    assert source.startswith("#!/bin/bash\n")
    assert "set -Eeuo pipefail" in source


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
