from __future__ import annotations

import stat
from pathlib import Path

from alt_deploy.jsonio import read_json
from support.controller_sandbox import make_controller_sandbox
from support.payloads import provision_request


def test_sandbox_configures_vault_boundary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()

    assert set(assets) == {
        "vault_file",
        "password_file",
        "ansible_vault",
    }
    assert assets["vault_file"].read_text(encoding="utf-8").startswith(
        "$ANSIBLE_VAULT;"
    )
    assert stat.S_IMODE(assets["vault_file"].stat().st_mode) == 0o600
    assert stat.S_IMODE(assets["password_file"].stat().st_mode) == 0o600
    assert assets["ansible_vault"].stat().st_mode & 0o111

    for path in assets.values():
        path.relative_to(sandbox.root)
        assert path.is_file()


def test_sandbox_writes_provision_request(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    request_path = sandbox.write_provision_request()

    assert request_path.relative_to(sandbox.root)
    assert read_json(request_path) == provision_request()
