from __future__ import annotations

from pathlib import Path

from support.backup_sandbox import BackupSandbox


def test_secret_identities_use_canonical_controller_paths(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets()

    identities = {
        item.kind: item.path
        for item in sandbox.secret_provider().capture()
    }

    assert identities == {
        "vault": "/home/altserver/ansible/group_vars/vault.yml",
        "vault_password": "/home/altserver/.ansible-vault-pass",
        "ssh_private_key": "/home/altserver/.ssh/id_ed25519",
    }
