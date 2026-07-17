from __future__ import annotations

import io
import json
from pathlib import Path

from alt_deploy.cli import main
from alt_deploy.config import Settings


EXPECTED_CHECKS = {
    "vault_file_exists": True,
    "password_file_exists": True,
    "vault_file_owner": True,
    "password_file_owner": True,
    "vault_file_mode": True,
    "password_file_mode": True,
    "vault_header": True,
    "decryptable": True,
    "variable_present": True,
    "yescrypt_format": True,
}


def test_vault_check_reports_healthy_without_exposing_secret(
    monkeypatch,
    tmp_path: Path,
) -> None:
    ansible_project = tmp_path / "ansible"
    group_vars = ansible_project / "group_vars"
    group_vars.mkdir(parents=True)

    vault_file = group_vars / "vault.yml"
    vault_file.write_text(
        "$ANSIBLE_VAULT;1.1;AES256\nfixture-ciphertext\n",
        encoding="utf-8",
    )
    vault_file.chmod(0o600)

    password_file = tmp_path / ".ansible-vault-pass"
    password_file.write_text("fixture-password\n", encoding="utf-8")
    password_file.chmod(0o600)

    ansible_vault = tmp_path / "ansible-vault"
    ansible_vault.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"vault_employee_password_hash: '\\$y\\$fixture'\"\n",
        encoding="utf-8",
    )
    ansible_vault.chmod(0o755)

    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_PROJECT",
        str(ansible_project),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(ansible_vault),
    )

    stdout = io.StringIO()
    rc = main(
        ["--json", "vault", "check"],
        settings=Settings.from_env(),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload == {
        "status": "ok",
        "vault": {
            "status": "ok",
            "checks": EXPECTED_CHECKS,
        },
    }

    serialized = stdout.getvalue()
    assert "$y$fixture" not in serialized
    assert "vault_employee_password_hash" not in serialized
    assert "fixture-password" not in serialized
