"""Deterministic fixed wallet asset and a separate read-only candidate entry."""
from pathlib import Path

from .component_catalog import _regular


def target_program(project,*,observer=False):
    if type(observer) is not bool:raise ValueError('Unsupported wallet program')
    modules=[('user_session',Path(__file__).with_name('user_session.py')),
             ('wallet_codes',Path(__file__).with_name('wallet_codes.py')),
             ('wallet_repair',Path(project)/'roles/kwallet_empty_name_repair/files/repair_empty_wallet.py')]
    program="#!/usr/bin/python3\nimport sys,types,json,os\np=types.ModuleType('alt_deploy');p.__path__=[];sys.modules['alt_deploy']=p\n"
    for name,path in modules:
        _regular(path)
        program+=("m=types.ModuleType('alt_deploy."+name+"');m.__file__=sys.argv[0];sys.modules[m.__name__]=m;exec(compile("
                  +repr(path.read_text(encoding='utf-8'))+",'<published-"+name+">','exec'),m.__dict__)\n")
    if observer:
        program+='''try:
    if os.geteuid()!=0:raise m.WalletError('kwallet_privilege_required')
    raw=sys.stdin.read(8193)
    if len(raw.encode())>8192:raise ValueError
    request=json.loads(raw,object_pairs_hook=m.unique)
    print(json.dumps({'schema_version':1,'status':'ok','observation':m.observe_candidate(request)}))
except Exception as error:
    code=str(error) if isinstance(error,(m.WalletError,m.SessionError)) else ''
    if code not in m.WALLET_CODES:code='kwallet_target_unverified'
    print(json.dumps({'schema_version':1,'status':'blocked','code':code}))
    raise SystemExit(4)
'''
    else:program+='raise SystemExit(m.main())\n'
    if len(program.encode())>=120000:raise ValueError('Published wallet program exceeds transport limit')
    return program
