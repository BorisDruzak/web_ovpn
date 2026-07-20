from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_netctl_collect_service_runs_as_dedicated_user():
    unit = (ROOT / "deploy" / "netctl-collect.service").read_text(encoding="utf-8")

    assert "User=netctl" in unit
    assert "Group=netctl" in unit
    assert "ExecStart=/usr/local/sbin/netctl --json collect all" in unit


def test_sudoers_runs_netctl_as_dedicated_user_not_root():
    sudoers = (ROOT / "deploy" / "sudoers-openvpn-web").read_text(encoding="utf-8")

    assert "openvpn-web ALL=(netctl) NOPASSWD: /usr/local/sbin/netctl *" in sudoers
    assert "openvpn-web ALL=(root) NOPASSWD: /usr/local/sbin/netctl *" not in sudoers


def test_installer_creates_netctl_user_and_locks_permissions():
    installer = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert "useradd --system --home /var/lib/netctl --shell /usr/sbin/nologin --gid netctl netctl" in installer
    assert "groupadd --system netctl" in installer
    assert "chown -R netctl:netctl /var/lib/netctl" in installer
    assert "chown root:netctl /etc/netctl/secrets.env" in installer
    assert "chmod 0640 /etc/netctl/secrets.env" in installer
    assert "NETCTL_SUDO_USER=netctl" in installer


def test_installer_runs_venv_commands_by_absolute_path_after_app_permissions_change():
    installer = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert 'cd "$APP"' not in installer
    assert 'python3 -m venv "$APP/.venv"' in installer
    assert '"$APP/.venv/bin/python" -m pip install --upgrade pip' in installer
    assert '"$APP/.venv/bin/pip" install -r "$APP/requirements.txt"' in installer
