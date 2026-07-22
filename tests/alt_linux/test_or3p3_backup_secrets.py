from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import asdict
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from support.backup_sandbox import BackupSandbox


def test_vault_password_identity_is_hmac_not_plain_hash(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets(vault_password=b"fixture-password\n")
    provider = sandbox.secret_provider()

    identities = {item.kind: item for item in provider.capture()}

    assert identities["vault_password"].identity.startswith(
        "hmac-sha256:"
    )
    assert hashlib.sha256(b"fixture-password\n").hexdigest() not in (
        identities["vault_password"].identity
    )


def test_ssh_identity_uses_public_fingerprint(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets()
    sandbox.fake_ssh_fingerprint("SHA256:test-public-fingerprint")

    identities = {
        item.kind: item
        for item in sandbox.secret_provider().capture()
    }

    assert identities["ssh_private_key"].identity == (
        "ssh-public-fingerprint:SHA256:test-public-fingerprint"
    )


def test_existing_fingerprint_key_is_never_replaced(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    key_path = sandbox.settings.fingerprint_key
    key_path.parent.mkdir(parents=True)
    key_path.write_bytes(b"x" * 32)
    key_path.chmod(0o600)

    assert sandbox.fingerprint_store().ensure() == b"x" * 32
    assert key_path.read_bytes() == b"x" * 32


def test_new_fingerprint_key_is_private_and_exact_length(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)

    key = sandbox.fingerprint_store().ensure()

    assert len(key) == 32
    assert stat.S_IMODE(
        sandbox.settings.fingerprint_key.stat().st_mode
    ) == 0o600


def test_invalid_vault_header_fails_closed(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets(vault=b"not-vault\n")
    sandbox.fake_ssh_fingerprint("SHA256:test-public-fingerprint")

    with pytest.raises(BackupError) as error:
        sandbox.secret_provider().capture()

    assert error.value.code == "backup_secret_invalid"


def test_secret_identity_mismatch_is_detected(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets()
    sandbox.fake_ssh_fingerprint("SHA256:test-public-fingerprint")
    provider = sandbox.secret_provider()
    expected = provider.capture()

    sandbox.settings.vault_password_file.write_bytes(b"changed\n")

    with pytest.raises(BackupError) as error:
        provider.assert_matches(expected)

    assert error.value.code == "restore_secret_mismatch"


def test_assert_matches_never_recreates_missing_fingerprint_key(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_secrets()
    provider = sandbox.secret_provider()
    expected = provider.capture()
    key_path = sandbox.settings.fingerprint_key
    key_path.unlink()

    with pytest.raises(BackupError) as error:
        provider.assert_matches(expected)

    assert error.value.code == "restore_secret_mismatch"
    assert not key_path.exists()


def test_serialized_identities_never_contain_raw_secret_bytes(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    private_key = b"private-key-fixture-never-log\n"
    password = b"vault-password-fixture-never-log\n"
    sandbox.seed_secrets(
        vault_password=password,
        ssh_private_key=private_key,
    )
    sandbox.fake_ssh_fingerprint("SHA256:test-public-fingerprint")

    serialized = json.dumps(
        [asdict(item) for item in sandbox.secret_provider().capture()],
        ensure_ascii=False,
    ).encode("utf-8")

    assert private_key.strip() not in serialized
    assert password.strip() not in serialized
