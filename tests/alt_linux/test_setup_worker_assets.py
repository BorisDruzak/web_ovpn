"""Packaged service and source scripts are verified without controller installation."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]/'deploy/alt-linux'


def test_worker_assets_and_installer_publish_the_same_entrypoint():
    wrapper = (ROOT/'control/alt-setup-worker').read_text()
    unit = (ROOT/'systemd/alt-setup-worker.service').read_text()
    installer = (ROOT/'install-control-plane-lib.sh').read_text()
    assert wrapper.startswith('#!/usr/bin/python3\n')
    assert 'from alt_deploy.setup_worker import main' in wrapper
    assert 'User=altserver' in unit and 'Group=altserver' in unit
    assert 'ExecStart=/usr/local/libexec/alt-setup-worker' in unit
    assert 'KillMode=control-group' in unit and 'Restart=on-failure' in unit
    assert 'Requires=alt-deploy-guard.service' in unit
    assert (ROOT/'backup/alt-deploy-guard.service').is_file()
    assert '/usr/local/libexec/alt-setup-worker' in installer
    assert 'stop_if_loaded alt-setup-worker.service' in installer
    assert 'systemctl enable --now alt-setup-worker.service' in installer
    assert '${ansible_root}/callback_plugins' in installer
    assert '${ansible_root}/filter_plugins' in installer
    for name in ('install-control-plane.sh', 'install-control-plane-lib.sh', 'install-control-plane-args.sh'):
        result = subprocess.run(['bash', '-n', str(ROOT/name)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr


def test_systemd_analyze_verifies_service_in_an_isolated_root(tmp_path):
    analyzer = shutil.which('systemd-analyze')
    if not analyzer: pytest.skip('systemd-analyze is unavailable')
    unit_dir = tmp_path/'etc/systemd/system'
    unit_dir.mkdir(parents=True)
    shutil.copyfile(ROOT/'systemd/alt-setup-worker.service', unit_dir/'alt-setup-worker.service')
    shutil.copyfile(ROOT/'backup/alt-deploy-guard.service', unit_dir/'alt-deploy-guard.service')
    for name in ('sysinit.target', 'basic.target', 'shutdown.target', 'network-online.target', 'multi-user.target'):
        (unit_dir/name).write_text('[Unit]\nDescription=Synthetic dependency\nDefaultDependencies=no\n')
    (unit_dir/'system.slice').write_text('[Unit]\nDescription=Synthetic slice\nDefaultDependencies=no\n[Slice]\n')
    executable = tmp_path/'usr/local/libexec/alt-setup-worker'
    executable.parent.mkdir(parents=True)
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    backup_helper = tmp_path/'usr/local/sbin/alt-deploy-backup'
    backup_helper.parent.mkdir(parents=True)
    backup_helper.write_text('#!/bin/sh\nexit 0\n')
    backup_helper.chmod(0o755)
    result = subprocess.run([analyzer, '--root='+str(tmp_path), 'verify', '/etc/systemd/system/alt-setup-worker.service'],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout+result.stderr
