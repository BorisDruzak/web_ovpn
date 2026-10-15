from __future__ import annotations

import base64
import struct

import pytest

from alt_deploy.errors import ControlError


def key(byte):
    raw = struct.pack('!I', 11) + b'ssh-ed25519' + struct.pack('!I', 32) + bytes([byte]) * 32
    return 'ssh-ed25519 ' + base64.b64encode(raw).decode()


def config():
    return {'client_address': '192.0.2.10', 'read_public_key': key(1), 'execute_public_key': key(2)}


def test_gateway_key_options_bind_scopes_and_disable_interactive_features():
    from alt_deploy.gateway_install import render_configuration
    result = render_configuration(config(), authorized_key_files=('.ssh/authorized_keys', '.ssh/authorized_keys2'))
    read, execute = result['authorized_keys'].splitlines()
    assert 'restrict,' in read and 'from="192.0.2.10"' in read
    assert '--scope read' in read and '--scope execute' in execute
    assert '/opt/alt-deploy-control/alt-workstations-gateway' in read
    assert 'Match User altserver' in result['sshd_config']
    assert '.ssh/authorized_keys .ssh/authorized_keys2 /etc/alt-deploy/workstations-authorized-keys' in result['sshd_config']
    assert 'sudo' not in result['authorized_keys']  # Native service identity; no new privilege hop.


@pytest.mark.parametrize('changes', [{'client_address': '0.0.0.0/0'}, {'read_public_key': 'ssh-rsa invalid'},
    {'read_public_key': key(1) + '\ncommand="bad"'}, {'execute_public_key': key(1)}, {'command': 'arbitrary'}])
def test_gateway_enrollment_refuses_wide_source_or_key_injection(changes):
    from alt_deploy.gateway_install import render_configuration
    document = dict(config(), **changes)
    with pytest.raises(ControlError):
        render_configuration(document, authorized_key_files=('.ssh/authorized_keys',))


def test_gateway_install_preserves_existing_authentication_policy():
    from alt_deploy.gateway_install import render_configuration
    result = render_configuration(config(), authorized_key_files=('/etc/ssh/existing/%u',))
    assert '/etc/ssh/existing/%u' in result['sshd_config']
    assert 'PasswordAuthentication' not in result['sshd_config']
    assert 'PermitRootLogin' not in result['sshd_config']
    assert 'ForceCommand' not in result['sshd_config']  # Forced command is per key.


def test_guarded_installer_places_gateway_inside_backed_up_runtime(tmp_path):
    import stat
    from support.installer_sandbox import ALT_ROOT, InstallerSandbox
    sandbox = InstallerSandbox.create(tmp_path)
    protected = sandbox.protected_snapshot()
    result = sandbox.run_library()
    assert result.returncode == 0, result.stderr
    target = sandbox.destination('/opt/alt-deploy-control/alt-workstations-gateway')
    assert target.read_bytes() == (ALT_ROOT / 'control/alt-workstations-gateway').read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    after = sandbox.protected_snapshot()
    assert {name: after[name] for name in protected} == protected
