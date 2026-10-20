"""First-login import and the worker must serialize the selected user's NSS."""
import importlib.util
import multiprocessing
import os

import pytest

from test_component_catalog import SOURCE


def importer():
    spec=importlib.util.spec_from_file_location('locked_ca_import',SOURCE/'roles/government_ca/files/import_user_certificates.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def test_selected_user_import_lock_is_private_and_shared_by_real_processes(tmp_path):
    module=importer();home=tmp_path/'home';home.mkdir(mode=0o700)
    read,write=multiprocessing.get_context('fork').Pipe(duplex=False)
    def concurrent():
        try:
            with module.user_import_lock(home):write.send('entered')
        except ValueError:write.send('busy')
    with module.user_import_lock(home):
        process=multiprocessing.get_context('fork').Process(target=concurrent);process.start()
        assert read.poll(3) and read.recv()=='busy';process.join(3);assert process.exitcode==0
    path=home/'.local/state/alt-government-ca/import.lock'
    assert path.stat().st_mode&0o777==0o600
    before=path.read_bytes()
    with module.user_import_lock(home):pass
    assert path.read_bytes()==before==b''


@pytest.mark.parametrize('fault',['symlink','hardlink','writable','foreign_directory'])
def test_import_lock_never_repairs_an_unowned_collision(tmp_path,fault):
    module=importer();home=tmp_path/'home';home.mkdir(mode=0o700)
    directory=home/'.local/state/alt-government-ca';directory.mkdir(mode=0o700,parents=True)
    path=directory/'import.lock';outside=tmp_path/'outside';outside.write_text('preserve');outside.chmod(0o600)
    if fault=='symlink':path.symlink_to(outside)
    elif fault=='hardlink':os.link(outside,path)
    else:path.write_bytes(b'');path.chmod(0o666 if fault=='writable' else 0o600)
    if fault=='foreign_directory':directory.chmod(0o777)
    with pytest.raises((ValueError,OSError)):
        with module.user_import_lock(home):pytest.fail('Unsafe lock was accepted')
    assert outside.read_text()=='preserve'
