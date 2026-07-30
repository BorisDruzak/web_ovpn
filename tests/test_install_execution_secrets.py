from __future__ import annotations

from pathlib import Path
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
