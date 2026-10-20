"""Inspect only the confirmed empty-name KDE wallet defect; private data stays local."""
from __future__ import annotations

from dataclasses import dataclass,field
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from alt_deploy.user_session import SessionContext,SessionError,_inside


class WalletError(Exception):
    pass


SOURCES=('.kwl','.salt','_attributes.json')


@dataclass(frozen=True)
class WalletEvidence:
    disposition: str
    wallet_name: str
    snapshot_sha256: str
    configuration: bytes | None = field(repr=False)
    configuration_state: dict | None = field(repr=False)
    files: dict = field(repr=False)
    context: SessionContext = field(repr=False)


def validate_wallet_name(name):
    if not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name):
        raise WalletError('kwallet_name_unverified')
    return name


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _user_directory(path,context,*,closed=False):
    info=path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=context.uid or info.st_gid!=context.gid
            or info.st_mode & 0o022 or closed and stat.S_IMODE(info.st_mode)!=0o700):
        raise WalletError('kwallet_ownership_unverified')


def _file(path,context,*,limit=67108864):
    try:
        before=path.lstat()
    except FileNotFoundError:return None
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=context.uid or before.st_gid!=context.gid
            or stat.S_IMODE(before.st_mode) not in (0o400,0o600) or before.st_nlink!=1
            or before.st_size>limit):raise WalletError('kwallet_ownership_unverified')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(descriptor)
        chunks=[];size=0
        while True:
            block=os.read(descriptor,min(1048576,limit+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
            if size>limit:raise WalletError('kwallet_evidence_unverified')
        after=os.fstat(descriptor)
    finally:os.close(descriptor)
    if not _identity(before)==_identity(opened)==_identity(after)==_identity(path.lstat()):
        raise WalletError('kwallet_evidence_changed')
    data=b''.join(chunks)
    if len(data)!=after.st_size:raise WalletError('kwallet_evidence_changed')
    return {'data':data,'sha256':hashlib.sha256(data).hexdigest(),
            'identity':_identity(after),'mode':stat.S_IMODE(after.st_mode)}


def _configuration(data):
    if data is None:return None
    if b'\0' in data:raise ValueError
    parser=configparser.ConfigParser(interpolation=None,strict=True,default_section='\0')
    parser.optionxform=str
    parser.read_string(data.decode('utf-8'))
    return parser


def _confirmed(parser):
    return (parser is not None and parser.has_section('Wallet')
        and parser.get('Wallet','Default Wallet',fallback=None)==''
        and parser.get('Wallet','First Use',fallback=None)=='false')


def repair_configuration(data,name):
    """Change only the empty default in the real Wallet group, preserving bytes."""
    try:
        validate_wallet_name(name)
        if not _confirmed(_configuration(data)):raise ValueError
        lines=[];active=None;changed=0
        for line in data.decode('utf-8').splitlines(keepends=True):
            core=line.rstrip('\r\n');ending=line[len(core):]
            header=re.fullmatch(r'\[(.+)\]\s*',core.strip())
            if header:active=header[1]
            key,separator,_=core.partition('=')
            if active=='Wallet' and separator and key.strip()=='Default Wallet':
                line=key+'='+name+ending;changed+=1
            lines.append(line)
        result=''.join(lines).encode('utf-8')
        if changed!=1 or _configuration(result).get('Wallet','Default Wallet')!=name:raise ValueError
        return result
    except (ValueError,TypeError,AttributeError,UnicodeError,configparser.Error):
        raise WalletError('kwallet_configuration_unverified') from None


def _evidence(context,name,configuration,files,disposition):
    # Bind the real session privately, including its complete inherited context.
    # Never serialize this dataclass or its files; expose only explicit hashes.
    private={'uid':context.uid,'gid':context.gid,'home':context.home,'session':context.session_id,
        'pid':context.pid,'start':context.start_ticks,'launcher':context.launcher_pid,
        'launcher_start':context.launcher_start_ticks,'environment':context.environment,
        'limits':context.limits,'groups':context.groups}
    proof={'wallet_name':name,'session':private,'configuration':None if configuration is None else
        {key:value for key,value in configuration.items() if key!='data'},
        'files':{key:{k:v for k,v in value.items() if k!='data'} for key,value in files.items()}}
    digest=hashlib.sha256(json.dumps(proof,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return WalletEvidence(disposition,name,digest,configuration['data'] if configuration else None,
                          configuration,files,context)


def inspect_wallet(context,wallet_name='recovered-wallet',*,root=Path('/')):
    """Read-only conditional evidence; healthy users need no backup or file write."""
    try:
        validate_wallet_name(wallet_name)
        if not isinstance(context,SessionContext) or context.uid<=0 or context.gid<=0:raise ValueError
        root=Path(root)
        home=_inside(root,context.home);_user_directory(home,context)
        configuration_path=_inside(root,context.home+'/.config/kwalletrc')
        configuration=_file(configuration_path,context,limit=131072)
        if configuration_path.parent.exists():_user_directory(configuration_path.parent,context)
        parser=_configuration(configuration['data'] if configuration else None)
        directory=_inside(root,context.home+'/.local/share/kwalletd')
        if not directory.exists():return _evidence(context,wallet_name,configuration,{},'noop')
        # Reject links even when they point to an otherwise owned wallet.
        candidates=[_inside(root,context.home+'/.local/share/kwalletd/'+name) for name in SOURCES]
        present=[p.exists() for p in candidates]
        if not any(present):return _evidence(context,wallet_name,configuration,{},'noop')
        if not all(present) or not _confirmed(parser):raise WalletError('kwallet_empty_name_evidence_incomplete')
        _user_directory(directory,context,closed=True)
        for parent in (directory.parent,directory.parent.parent):_user_directory(parent,context)
        for suffix in ('.kwl','.salt','_attributes.json'):
            target=_inside(root,context.home+'/.local/share/kwalletd/'+wallet_name+suffix)
            if target.exists():raise WalletError('kwallet_target_collision')
        paths=list(directory.iterdir())
        if len(paths)>1024:raise ValueError
        files={};size=0
        for path in sorted(paths):
            value=_file(_inside(root,context.home+'/.local/share/kwalletd/'+path.name),context)
            if value is None:raise WalletError('kwallet_evidence_changed')
            size+=len(value['data'])
            if size>268435456:raise ValueError
            files[path.name]=value
        if {p.name for p in directory.iterdir()}!=set(files):raise WalletError('kwallet_evidence_changed')
        for name,value in files.items():
            if _identity((directory/name).lstat())!=value['identity']:raise WalletError('kwallet_evidence_changed')
        if _identity(configuration_path.lstat())!=configuration['identity']:raise WalletError('kwallet_evidence_changed')
        repair_configuration(configuration['data'],wallet_name)
        return _evidence(context,wallet_name,configuration,files,'repair')
    except WalletError:raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,configparser.Error,SessionError):
        raise WalletError('kwallet_evidence_unverified') from None
