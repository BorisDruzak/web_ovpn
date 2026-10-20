"""Build only the fixed published read-only or claimed KRFB target program."""
from pathlib import Path

from .component_catalog import _regular


TARGET_CODES = frozenset({
    'graphical_session_unavailable','graphical_session_ambiguous','krfb_clients_connected',
    'krfb_graphical_session_unverified','krfb_machine_unverified','krfb_user_identity_unverified',
    'krfb_configuration_unverified','krfb_autostart_unverified','krfb_listener_unverified',
    'krfb_process_unverified','krfb_vnc_policy_unverified','krfb_runtime_request_unverified',
    'krfb_runtime_readiness_unverified','krfb_runtime_readiness_changed','krfb_runtime_claim_consumed',
    'krfb_runtime_backup_unverified','krfb_runtime_busy','krfb_runtime_lock_unverified',
    'krfb_runtime_outcome_unverified','krfb_runtime_write_unverified','krfb_runtime_launch_unverified',
})


def target_program(*,apply=False,phase_observer=False):
    """Program bytes contain published source only; private values use stdin.

    Called by native phase preparation, never by a public command selector.
    Source/template hashes must be covered by the immutable phase claim before
    the resulting program is dispatched through the existing trusted transport.
    """
    if type(apply) is not bool or type(phase_observer) is not bool or apply and phase_observer:raise ValueError('Unsupported KRFB program')
    program="import sys,types,json,os,hashlib\np=types.ModuleType('alt_deploy');p.__path__=[];sys.modules['alt_deploy']=p\n"
    names=('user_session','krfb_user_session','krfb_managed_runtime')+ (('setup_phase_target',) if phase_observer else ())
    for name in names:
        source=Path(__file__).with_name(name+'.py');_regular(source)
        program+=("m=types.ModuleType('alt_deploy."+name+"');sys.modules[m.__name__]=m;exec(compile("
                  +repr(source.read_text(encoding='utf-8'))+",'<published-"+name+">','exec'),m.__dict__)\n")
    if phase_observer:program+="m=sys.modules['alt_deploy.krfb_managed_runtime']\n"
    program+='''
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError
        result[key]=value
    return result
try:
    raw=sys.stdin.read(262145)
    if len(raw.encode())>262144 or os.geteuid()!=0:raise ValueError
    request=json.loads(raw,object_pairs_hook=unique)
'''
    if apply:
        program+="    result=m.ensure_session(request)\n    print(json.dumps({'schema_version':1,'status':'ok','result':result}))\n"
    else:
        # Never serialize the assessment dataclass: it contains the real GUI
        # environment, protected configuration and process-private evidence.
        program+='''    value=m.assess_runtime(request)
    observation={'disposition':value.disposition,'needs_reload':value.needs_reload,
        'snapshot':value.snapshot,'policy':value.policy,
        'configuration_template_sha256':hashlib.sha256(request['configuration'].encode()).hexdigest(),
        'autostart_template_sha256':hashlib.sha256(request['autostart'].encode()).hexdigest()}
'''
        if phase_observer:program+="    observation.update(sys.modules['alt_deploy.setup_phase_target'].user_state(value.context))\n"
        program+="    print(json.dumps({'schema_version':1,'status':'ok','observation':observation}))\n"
    program+='''except Exception as error:
    code=str(error) if isinstance(error,m.KRFBSessionError) else ''
    if code not in '''+repr(tuple(sorted(TARGET_CODES)))+''':code='krfb_runtime_request_unverified'
    print(json.dumps({'schema_version':1,'status':'blocked','code':code}))
    raise SystemExit(4)
'''
    if len(program.encode())>=120000:raise ValueError('Published KRFB program exceeds transport limit')
    return program
