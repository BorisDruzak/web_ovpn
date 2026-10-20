"""Incomplete release assets must fail before any controller mutation."""
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import pytest

from support.installer_sandbox import ALT_ROOT,InstallerSandbox


ASSETS=(
    'control/alt_deploy/setup_phase_execution.py',
    'ansible/playbooks/05-setup-workflow-phase.yml',
    'ansible/roles/government_ca/tasks/user_finalize.yml',
    'ansible/roles/kwallet_empty_name_repair/files/repair_empty_wallet.py',
    'ansible/roles/workstation_final_dns/files/finalize_dns.py',
    'ansible/roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2',
)


@pytest.mark.parametrize('relative',ASSETS)
@pytest.mark.parametrize('unsafe',['missing','symlink'])
def test_source_layout_rejects_missing_or_linked_workflow_asset(tmp_path,relative,unsafe):
    library=ALT_ROOT/'install-control-plane-lib.sh'
    body=library.read_text().split('validate_source_layout() {',1)[1].split('run_source_cli()',1)[0]
    mirror=tmp_path/'release'
    for name in set(re.findall(r'"\$\{ALT_ROOT\}/([^"\n]+)"',body))|set(ASSETS):
        source=ALT_ROOT/name;target=mirror/name
        if source.is_dir():target.mkdir(parents=True,exist_ok=True)
        else:target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
    target=mirror/relative;target.unlink()
    if unsafe=='symlink':target.symlink_to(ALT_ROOT/relative)
    result=subprocess.run(['bash','-c','set -eu; source "$1"; ALT_ROOT="$2"; validate_source_layout',
                           'fixture',str(library),str(mirror)],capture_output=True,text=True)
    assert result.returncode!=0
    assert relative in result.stderr


def test_installer_creates_private_phase_authority_roots(tmp_path):
    sandbox=InstallerSandbox.create(tmp_path)
    result=sandbox.run_library()
    assert result.returncode==0,result.stderr
    for name in ('setup-phase-tickets','setup-phase-claims','setup-phase-results','setup-phase-admissions'):
        path=sandbox.destination('/var/lib/alt-deploy/'+name)
        assert path.is_dir() and stat.S_IMODE(path.stat().st_mode)==0o700
        assert path.stat().st_uid==os.getuid()
