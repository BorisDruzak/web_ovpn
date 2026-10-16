"""The approved standalone browser RPM must not enable its update repository."""
from pathlib import Path
import os
import runpy
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == 'win32', reason='POSIX ownership and symlink policy')

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/software_browser/files/disable_vendor_repository.py'
ACTIVE = 'rpm [yandex-browser] https://repo.yandex.ru/yandex-browser/alt x86_64 yandex-browser\n'


def fixture(tmp_path, content=ACTIVE):
    directory = tmp_path/'etc/apt/sources.list.d'
    directory.mkdir(parents=True)
    target = directory/'yandex-browser.list'
    target.write_text(content)
    target.chmod(0o644)
    neighbor = directory/'alt.list'
    neighbor.write_text('published p11 fixture\n')
    return target, neighbor, runpy.run_path(str(SOURCE))['disable']


def test_disables_only_exact_vendor_entry_and_is_idempotent(tmp_path):
    target, neighbor, disable = fixture(tmp_path)
    assert disable(root=tmp_path, owner=os.getuid()) is True
    assert target.read_text() == '# Disabled by managed browser artifact policy: ' + ACTIVE
    assert neighbor.read_text() == 'published p11 fixture\n'
    assert disable(root=tmp_path, owner=os.getuid()) is False


@pytest.mark.parametrize('kind', ['content', 'symlink', 'parent_symlink', 'writable', 'owner'])
def test_unsafe_or_unexpected_source_is_unchanged(tmp_path, kind):
    target, neighbor, disable = fixture(tmp_path)
    if kind == 'content': target.write_text(ACTIVE+'rpm unapproved additional source\n')
    elif kind == 'symlink': target.unlink(); target.symlink_to(neighbor)
    elif kind == 'parent_symlink':
        directory = target.parent; directory.rename(directory.with_name('original'))
        directory.symlink_to(directory.with_name('original'), target_is_directory=True)
    elif kind == 'writable': target.chmod(0o666)
    before = target.read_bytes()
    with pytest.raises(ValueError):
        disable(root=tmp_path, owner=os.getuid()+1 if kind == 'owner' else os.getuid())
    assert target.read_bytes() == before
    assert neighbor.read_text() == 'published p11 fixture\n'


def test_absent_vendor_source_is_not_created(tmp_path):
    _, _, disable = fixture(tmp_path)
    target = tmp_path/'etc/apt/sources.list.d/yandex-browser.list';target.unlink()
    assert disable(root=tmp_path, owner=os.getuid()) is False
    assert not target.exists()
