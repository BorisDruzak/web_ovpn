from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

CONTROL_ROOT = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "alt-linux"
    / "control"
)

sys.path.insert(0, str(CONTROL_ROOT))


@pytest.fixture(autouse=True)
def provide_portable_altserver_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provide the controller service account on non-ALT test runners."""
    import alt_deploy.provision as provision_module

    real_getpwnam = provision_module.pwd.getpwnam

    def getpwnam(username: str) -> object:
        if username == "altserver":
            return types.SimpleNamespace(
                pw_uid=os.getuid(),
                pw_gid=os.getgid(),
            )
        return real_getpwnam(username)

    monkeypatch.setattr(
        provision_module.pwd,
        "getpwnam",
        getpwnam,
    )
