"""Bundle only fixed published DNS code; observation has its own entry point."""
from pathlib import Path

from .component_catalog import _regular


def target_program(project,*,observer=False):
    if type(observer) is not bool:raise ValueError('Unsupported final DNS program')
    modules=[('final_dns_policy',Path(__file__).with_name('final_dns_policy.py')),
             ('final_dns',Path(project)/'roles/workstation_final_dns/files/finalize_dns.py')]
    program="#!/usr/bin/python3\nimport sys,types,json,os\np=types.ModuleType('alt_deploy');p.__path__=[];sys.modules['alt_deploy']=p\n"
    for name,path in modules:
        _regular(path)
        program+=("m=types.ModuleType('alt_deploy."+name+"');m.__file__=sys.argv[0];sys.modules[m.__name__]=m;exec(compile("
                  +repr(path.read_text(encoding='utf-8'))+",'<published-"+name+">','exec'),m.__dict__)\n")
    if observer:
        # The expected installed helper is the other fixed bundle, not this
        # temporary receiver. Its digest binds observations to published source.
        import hashlib
        expected=hashlib.sha256(target_program(project).encode()).hexdigest()
        program+='''try:
    if os.geteuid()!=0:raise m.DnsError('final_dns_ownership_unverified')
    raw=sys.stdin.read(8193)
    if len(raw.encode())>8192:raise ValueError
    request=json.loads(raw,object_pairs_hook=m.unique)
    print(json.dumps({'schema_version':1,'status':'ok','helper_sha256':EXPECTED,
                      'observation':m.observe(request).public}))
except Exception as error:
    code=str(error) if isinstance(error,m.DnsError) and str(error) in m.CODES else 'final_dns_request_unverified'
    print(json.dumps({'schema_version':1,'status':'blocked','code':code}));raise SystemExit(4)
'''.replace('EXPECTED',repr(expected))
    else:program+='raise SystemExit(m.main())\n'
    if len(program.encode())>=120000:raise ValueError('Final DNS helper exceeds transport limit')
    return program
