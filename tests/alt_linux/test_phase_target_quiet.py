"""A root receipt proves birth identity; a dead parent is insufficient."""
import json
import os
from pathlib import Path

import pytest

from alt_deploy.setup_phase_target import mutators_quiet


BOOT='11111111-2222-3333-4444-555555555555'


def record(path,value):
    path.write_text(json.dumps(value));path.chmod(0o600)


@pytest.mark.parametrize('kind',['alt-kwallet-empty-name-repair','alt-krfb-user-runtime','alt-workstation-final-dns'])
@pytest.mark.parametrize('fault',['dead','live_helper','orphan_writer','reused_pid','old_boot','unsafe','missing_identity'])
def test_recorded_target_mutator_survives_parent_exit(tmp_path,kind,fault):
    proc=tmp_path/'proc/sys/kernel/random';proc.mkdir(parents=True)
    (proc/'boot_id').write_text(BOOT)
    namespace=tmp_path/'var/lib'/kind;namespace.mkdir(parents=True,mode=0o700)
    directory=namespace/('a'*64);directory.mkdir(mode=0o700)
    helper={'pid':321,'start_ticks':123};boot=BOOT
    if fault=='old_boot':boot='99999999-2222-3333-4444-555555555555'
    if kind=='alt-workstation-final-dns':
        record(directory/'invocation.json',dict(helper,boot_id=boot))
    else:record(directory/'manifest.json',{'boot_id':boot,'helper':helper})
    if fault=='orphan_writer':record(directory/'writer.json',{'boot_id':boot,'child':{'pid':322,'start_ticks':456,'parent_pid':1}})
    if fault in ('live_helper','orphan_writer','reused_pid','old_boot'):
        pid=322 if fault=='orphan_writer' else 321;birth=456 if fault=='orphan_writer' else 124 if fault=='reused_pid' else 123
        target=tmp_path/'proc'/str(pid);target.mkdir()
        fields=['S']+['1']*18+[str(birth)]
        (target/'stat').write_text(str(pid)+' (python3) '+' '.join(fields))
    if fault=='unsafe':directory.chmod(0o755)
    if fault=='missing_identity':
        record(directory/('invocation.json' if kind=='alt-workstation-final-dns' else 'manifest.json'),{})
    if fault in ('unsafe','missing_identity'):
        with pytest.raises(ValueError):mutators_quiet(root=tmp_path)
    else:assert mutators_quiet(root=tmp_path) is (fault not in ('live_helper','orphan_writer'))


@pytest.mark.parametrize('argv,quiet',[
    (['/usr/bin/python3','/usr/local/libexec/alt-government-ca-user-import.py'],False),
    (['/usr/bin/certutil','-A','-n','synthetic'],False),
    (['/opt/cprocsp/bin/amd64/certmgr','-install','-store','uRoot'],False),
    (['/usr/bin/certutil','-L'],True),
    (['/opt/cprocsp/bin/amd64/certmgr','-list'],True),
    (['/usr/bin/yandex-browser-stable'],True)])
def test_orphan_certificate_writers_are_observed_without_stopping_apps(tmp_path,argv,quiet):
    boot=tmp_path/'proc/sys/kernel/random';boot.mkdir(parents=True);(boot/'boot_id').write_text(BOOT)
    process=tmp_path/'proc/321';process.mkdir();(process/'cmdline').write_bytes(b'\0'.join(s.encode() for s in argv)+b'\0')
    before=(process/'cmdline').read_bytes()
    assert mutators_quiet(root=tmp_path) is quiet
    assert (process/'cmdline').read_bytes()==before
