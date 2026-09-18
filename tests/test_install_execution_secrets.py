from __future__ import annotations

from pathlib import Path
import importlib.util
import os
import sys

import pytest


CONTROL_ROOT = Path(__file__).resolve().parents[1] / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.vault import extract_execution_password_hashes


def test_execution_vault_requires_two_distinct_yescrypt_hashes() -> None:
    values = extract_execution_password_hashes(
        "vault_install_root_password_hash: $y$j9T$root$abcdefghijklmnopqrstuv\n"
        "vault_install_admin_password_hash: $y$j9T$admin$abcdefghijklmnopqrstuv\n"
    )

    assert set(values) == {"root_yescrypt_hash", "admin_yescrypt_hash"}
    assert values["root_yescrypt_hash"] != values["admin_yescrypt_hash"]


@pytest.mark.parametrize("content", [
    "vault_install_root_password_hash: $y$j9T$same$abcdefghijklmnopqrstuv\n"
    "vault_install_admin_password_hash: $y$j9T$same$abcdefghijklmnopqrstuv\n",
    "vault_install_root_password_hash: bad\n"
    "vault_install_admin_password_hash: $y$j9T$admin$abcdefghijklmnopqrstuv\n",
    "vault_install_admin_password_hash: $y$j9T$admin$abcdefghijklmnopqrstuv\n",
])
def test_execution_vault_rejects_missing_invalid_or_shared_hashes(content: str) -> None:
    with pytest.raises(ValueError, match="execution password"):
        extract_execution_password_hashes(content)


def test_endpoint_environment_is_data_not_shell_and_does_not_emit_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", os.environ.copy())
    path = Path(__file__).resolve().parents[1] / "deploy" / "verify_endpoint_platform.py"
    spec = importlib.util.spec_from_file_location("endpoint_secret_verifier", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    env = tmp_path / "environment"
    env.write_text("APP_SECRET_KEY=sensitive-secret\nENDPOINT_PLATFORM_ENABLED=0\nENDPOINT_PLATFORM_BASE_URL='$(echo sensitive-token)'\n")
    monkeypatch.setattr(verifier, "validate_file_metadata", lambda *args, **kwargs: None)
    monkeypatch.setenv("ENDPOINT_PLATFORM_TIMEOUT_SECONDS", "999")
    verifier.load_environment(env, 123)
    assert os.environ["ENDPOINT_PLATFORM_BASE_URL"] == "$(echo sensitive-token)"
    assert "ENDPOINT_PLATFORM_TIMEOUT_SECONDS" not in os.environ
    output = capsys.readouterr()
    assert output.out == output.err == ""
