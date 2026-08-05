from __future__ import annotations

from pathlib import Path


BOOTSTRAP = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "alt-linux"
    / "bootstrap"
    / "bootstrap.sh"
)


def test_manual_bootstrap_has_a_pinned_public_key_and_root_gate() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'DEPLOY_HOST="${ALT_DEPLOY_HOST:-192.168.100.17}"' in source
    assert "ALT_ANSIBLE_AUTHORIZED_KEY_SHA256" in source
    assert "SHA256:60+ctiToYXkwE+H5LfV2hD/MZqRFiato7Q1RcQRlTmM" in source
    assert 'if [[ $(id -u) -ne 0 ]]; then' in source


def test_manual_bootstrap_validates_key_and_ansible_sudo() -> None:
    source = BOOTSTRAP.read_text(encoding="utf-8")

    assert 'ssh-keygen -lf "${temporary}" -E sha256' in source
    assert 'visudo -cf' in source
    assert 'sudo -n -u "${ANSIBLE_USER}" true' in source
    assert 'ALT\\ Workstation\\ K\\ 11\\.' in source
