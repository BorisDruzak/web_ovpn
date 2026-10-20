"""Only the confirmed empty-name wallet defect permits the bounded repair."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat

import pytest

from test_component_catalog import SOURCE
from test_user_session import graphical,discover


def helper():
    import sys
    spec=importlib.util.spec_from_file_location('fixed_wallet_repair',
        SOURCE/'roles/kwallet_empty_name_repair/files/repair_empty_wallet.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


@pytest.fixture
def wallet(graphical):
    f=graphical;home=f['root']/f['home'].lstrip('/')
    directory=home/'.local/share/kwalletd';directory.mkdir(mode=0o700,parents=True)
    config=home/'.config/kwalletrc';config.parent.mkdir(mode=0o700,exist_ok=True)
    config.write_bytes(b'# employee preference\n[Unrelated]\nDefault Wallet=keep-me\n[Wallet]\nDefault Wallet=\nFirst Use=false\nEnabled=true\n')
    config.chmod(0o600)
    for name,data in {'.kwl':b'PRIVATE-WALLET-CONTENT-SENTINEL','.salt':b'PRIVATE-SALT-SENTINEL',
                      '_attributes.json':b'{"PRIVATE-METADATA-SENTINEL":42}',
                      'other-wallet.kwl':b'PRESERVE-OTHER-WALLET'}.items():
        (directory/name).write_bytes(data);(directory/name).chmod(0o600)
    (directory/'.salt').chmod(0o400)
    return dict(f,directory=directory,config=config,context=discover(f))


def files(root):
    return {p.relative_to(root).as_posix():(p.read_bytes(),stat.S_IMODE(p.stat().st_mode),p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def inspect(module,f,name='recovered-wallet'):
    return module.inspect_wallet(f['context'],name,root=f['root'])


def test_confirmed_defect_is_readonly_and_keeps_private_bytes_out_of_observation(wallet):
    m=helper();f=wallet;before=files(f['root'])
    result=inspect(m,f)
    assert result.disposition=='repair' and result.wallet_name=='recovered-wallet'
    assert set(result.files)=={'.kwl','.salt','_attributes.json','other-wallet.kwl'}
    assert len(result.snapshot_sha256)==64
    assert 'SENTINEL' not in repr(result) and 'SESSION-' not in repr(result)
    assert files(f['root'])==before


@pytest.mark.parametrize('case',['absent','already_fixed','different_healthy_wallet'])
def test_healthy_wallet_is_a_true_noop_without_backup_or_changes(wallet,case):
    m=helper();f=wallet
    for name in ('.kwl','.salt','_attributes.json'):(f['directory']/name).unlink()
    if case=='absent':f['config'].unlink()
    else:
        f['config'].write_bytes(b'[Wallet]\nDefault Wallet='+
            (b'recovered-wallet' if case=='already_fixed' else b'other-wallet')+b'\nFirst Use=false\n')
    before=files(f['root'])
    result=inspect(m,f)
    assert result.disposition=='noop'
    assert files(f['root'])==before


@pytest.mark.parametrize('fault',['missing_kwl','missing_salt','missing_metadata','wrong_default','first_use',
    'duplicate_key','symlink','hardlink','world_readable','foreign_uid','target_collision','target_symlink'])
def test_unconfirmed_unsafe_or_conflicted_wallet_is_never_modified(wallet,fault):
    m=helper();f=wallet;context=f['context']
    if fault.startswith('missing_'):
        (f['directory']/{'missing_kwl':'.kwl','missing_salt':'.salt','missing_metadata':'_attributes.json'}[fault]).unlink()
    elif fault=='wrong_default':f['config'].write_bytes(f['config'].read_bytes().replace(b'Default Wallet=\n',b'Default Wallet=other-wallet\n'))
    elif fault=='first_use':f['config'].write_bytes(f['config'].read_bytes().replace(b'First Use=false',b'First Use=true'))
    elif fault=='duplicate_key':f['config'].write_bytes(f['config'].read_bytes()+b'Default Wallet=another\n')
    elif fault=='symlink':
        (f['directory']/'.kwl').unlink();(f['directory']/'.kwl').symlink_to(f['directory']/'other-wallet.kwl')
    elif fault=='hardlink':os.link(f['directory']/'.kwl',f['directory']/'additional-link')
    elif fault=='world_readable':(f['directory']/'.kwl').chmod(0o644)
    elif fault=='foreign_uid':
        from dataclasses import replace
        context=replace(context,uid=context.uid+1)
    elif fault=='target_collision':(f['directory']/'recovered-wallet.kwl').write_bytes(b'FOREIGN-TARGET-SENTINEL')
    elif fault=='target_symlink':(f['directory']/'recovered-wallet.kwl').symlink_to(f['directory']/'other-wallet.kwl')
    before=files(f['root'])
    with pytest.raises(m.WalletError) as caught:m.inspect_wallet(context,'recovered-wallet',root=f['root'])
    assert 'SENTINEL' not in str(caught.value) and files(f['root'])==before


@pytest.mark.parametrize('name',['','../wallet','/tmp/wallet','.','..','recovered/wallet','wallet\nInjected=true','-wallet','x'*65])
def test_wallet_basename_cannot_select_an_arbitrary_path(wallet,name):
    m=helper();before=files(wallet['root'])
    with pytest.raises(m.WalletError):inspect(m,wallet,name)
    assert files(wallet['root'])==before


@pytest.mark.parametrize('newline',[b'\n',b'\r\n'])
def test_configuration_edit_changes_only_the_empty_default_wallet_value(wallet,newline):
    m=helper();f=wallet
    original=f['config'].read_bytes().replace(b'\n',newline)
    result=m.repair_configuration(original,'custom-wallet')
    assert result==original.replace(b'Default Wallet='+newline,b'Default Wallet=custom-wallet'+newline)
    assert b'Default Wallet=keep-me' in result and b'First Use=false' in result
    with pytest.raises(m.WalletError):m.repair_configuration(result,'different-wallet')


def test_file_hash_drift_during_read_is_not_accepted_as_defect_evidence(wallet,monkeypatch):
    m=helper();f=wallet;original=m.os.read;changed=False
    def read(fd,count):
        nonlocal changed
        data=original(fd,count)
        try:selected=os.readlink('/proc/self/fd/'+str(fd))==str(f['directory']/'.kwl')
        except OSError:selected=False
        if selected and not changed:
            changed=True;(f['directory']/'.kwl').write_bytes(b'CONCURRENT-USER-EDIT')
        return data
    monkeypatch.setattr(m.os,'read',read)
    with pytest.raises(m.WalletError):inspect(m,f)
    assert changed is True
