from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER_LIBRARY = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "install-control-plane-lib.sh"
)


def test_installer_prepares_private_registration_tree() -> None:
    installer_text = INSTALLER_LIBRARY.read_text(encoding="utf-8")

    assert "install -d -o altserver -g altserver -m 0700" in installer_text
    for path in (
        "/srv/alt-deploy/registration",
        "/srv/alt-deploy/registration/pending",
        "/srv/alt-deploy/registration/ready",
        "/srv/alt-deploy/registration/failed",
    ):
        assert path in installer_text
