from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "install-control-plane.sh"
)


def test_installer_prepares_private_registration_root() -> None:
    installer_text = INSTALLER.read_text(encoding="utf-8")

    private_directories_block = (
        "install -d -o altserver -g altserver -m 0700"
    )
    assert private_directories_block in installer_text
    assert "/srv/alt-deploy/registration" in installer_text
