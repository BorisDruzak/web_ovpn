"""Fixed read-only eligibility; private templates never enter phase tickets."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shlex

from .ad_directory import fail
from .component_verification import package_health_ready
from .full_workflow import archived_workflow
from .setup_phases import WorkflowPhaseStore,validate_ready
from .setup_plans import digest
from .setup_waiting import WAIT_CODES


def observe_mutators(settings,machine,*,runner=None):
    """A fixed, GUI-independent receiver used only by native closure checks."""
    try:
        from .component_catalog import _regular
        from .ad_transport import bounded_run
        from .target_transport import ssh_prefix
        from .kwallet_runtime import unique
        import re
        source=Path(__file__).with_name('setup_phase_target.py');_regular(source)
        body=source.read_text(encoding='utf-8')
        program='import json,os,sys,socket,hashlib\nfrom pathlib import Path\n'+body+'''
try:
    raw=sys.stdin.read(4097)
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError
            value[key]=item
        return value
    request=json.loads(raw,object_pairs_hook=unique)
    if os.geteuid()!=0 or len(raw.encode())>4096 or set(request)!={'machine_uuid','hostname'}:raise ValueError
    uuid=Path('/sys/devices/virtual/dmi/id/product_uuid').read_text().strip().lower()
    hostname=socket.gethostname().split('.')[0].lower()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if request!={'machine_uuid':uuid,'hostname':hostname}:raise ValueError
    quiet=mutators_quiet()
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:raise ValueError
    print(json.dumps({'schema_version':1,'machine_uuid':uuid,'hostname':hostname,'boot_id':boot,'quiet':quiet}))
except Exception:
    print('{"schema_version":1,"status":"blocked","code":"workflow_target_processes_unverified"}')
    raise SystemExit(4)
'''
        if len(program.encode())>65536:raise ValueError
        args=ssh_prefix(settings,machine)+['sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(program)]
        rc,raw,_=(runner or bounded_run)(args,input_text=json.dumps({'machine_uuid':machine.uuid,'hostname':machine.hostname}),
            timeout=60,max_bytes=4096,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        value=json.loads(raw,object_pairs_hook=unique)
        if (rc or set(value)!={'schema_version','machine_uuid','hostname','boot_id','quiet'}
                or type(value['schema_version']) is not int or value['schema_version']!=1
                or value['machine_uuid']!=machine.uuid or value['hostname']!=machine.hostname
                or type(value['quiet']) is not bool or not isinstance(value['boot_id'],str)
                or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])):raise ValueError
        return value
    except Exception:raise fail('workflow_target_processes_unverified','Target helper and writer exit evidence is unavailable') from None


def bind_readiness(job,phase,system,*,facts,user,computer,wallet,dns,krfb,helpers):
    """Retain identity and digests only, never the private preparation bundle."""
    try:
        payload=job.request['plan']['payload'];workflow=archived_workflow(payload)
        if not package_health_ready(facts):raise fail('workflow_package_manager_busy','Package manager readiness is unavailable')
        if isinstance(krfb,dict):
            if krfb.get('certificates_quiet') is False:raise fail('certificates_importer_active','Selected-user certificate import is active')
            if krfb.get('target_mutators_quiet') is False:raise fail('workflow_target_processes_unverified','A previous target writer has not stopped')
            if krfb.get('disposition')=='waiting_vnc_clients':raise fail('krfb_clients_connected','Connected VNC clients must finish before a required reload')
        fields={'disposition','snapshot','home_sha256','certificates_quiet','target_mutators_quiet','certificates_sha256'}
        if (not isinstance(krfb,dict) or not fields<=set(krfb)<=fields|{'needs_reload','policy',
                'configuration_template_sha256','autostart_template_sha256','certificate_helper_sha256'}
                or user!=payload['user'] or computer!=system['result']['computer']
                or facts['machine']['uuid']!=job.machine_uuid or facts['machine']['hostname']!=payload['machine']['hostname']
                or facts['user']['home_exists'] is not True or facts['user']['home_safe'] is not True
                or facts['user']['login']!=user['login'] or not package_health_ready(facts)
                or krfb['certificates_quiet'] is not True or krfb['target_mutators_quiet'] is not True
                or krfb['disposition'] not in ('noop','apply')):raise ValueError
        session=krfb['snapshot'];boot=facts['machine']['boot_id']
        for value in (wallet,dns,session):
            if not isinstance(value,dict) or value['boot_id']!=boot:raise ValueError
        if any(value[key]!=facts['user'][key] for value in (wallet,session) for key in ('uid','gid')):raise ValueError
        scope={'machine_uuid':job.machine_uuid,'hostname':payload['machine']['hostname'],'ip':payload['machine']['ip'],
            'registration_sha256':payload['machine']['registration_sha256'],'ssh_binding':copy.deepcopy(payload['ssh_binding']),
            'login':user['login'],'upn':user['upn'],'user_guid':user['object_guid'],'user_sid':user['object_sid'],
            'uid':session['uid'],'gid':session['gid'],'home_sha256':krfb['home_sha256'],
            'computer_guid':computer['object_guid'],'computer_sid':computer['object_sid'],
            'ou_guid':payload['ou_identity']['object_guid'],'ou_dn':payload['computer_ou'],
            **{k:dns[k] for k in ('connection_uuid','interface','backend')}}
        ready={'schema_version':1,'status':'ready','job_id':job.job_id,'phase':phase,
            'source_sha256':payload['source_sha256'],'catalog_sha256':payload['catalog_sha256'],
            'workflow_policy_sha256':workflow['policy_sha256'],'scope':scope,
            'observation':{'boot_id':boot,'session_sha256':session['session_sha256'],
                'wallet_sha256':wallet['snapshot_sha256'],'krfb_sha256':digest(krfb),'dns_sha256':dns['snapshot_sha256'],
                'certificates_sha256':krfb['certificates_sha256'],'package_health_sha256':digest(facts['package_manager']),
                'helpers':copy.deepcopy(helpers)}}
        return validate_ready(job,phase,ready,system)
    except Exception as error:
        code=getattr(error,'code','')
        raise fail(code if code in WAIT_CODES else 'workflow_readiness_unverified','Fresh selected-user phase evidence is unavailable') from None


class WorkflowReadinessProbe:
    def __init__(self,settings,*,setup=None,runner=None):
        from .setup import SetupService
        from .ad_transport import bounded_run
        self.settings=settings;self.setup=setup or SetupService(settings);self.runner=runner or bounded_run

    def observe(self,job,phase):
        ready,_=self.prepare(job,phase)
        return ready

    def prepare(self,job,phase):
        """The worker re-reads this after claiming; no saved SSH environment."""
        stage='authority'
        try:
            from .krfb_runtime import observe_vnc_policy,DIRECT_POLICY
            from .krfb_program import target_program
            from .kwallet_runtime import specification
            from .final_dns_program import target_program as dns_program
            from .target_transport import ssh_prefix
            from .vault import VaultHealthChecker,KRFB_DESKTOP_PASSWORD_VARIABLE,KRFB_UNATTENDED_PASSWORD_VARIABLE
            from .component_catalog import _StrictLoader,_regular
            from jinja2 import Environment,StrictUndefined
            import yaml
            payload=job.request['plan']['payload'];workflow=archived_workflow(payload)
            records=WorkflowPhaseStore(self.settings).records(job);system=records['system']['result']
            if system is None or phase not in ('user','final_dns'):raise ValueError
            # This existing collector binds registration, exact AD employee,
            # machine trust, current source/catalog and pinned SSH identities.
            stage='components'
            facts,verification=self.setup._observe_job_result(job.request['plan'],own_job_id=job.job_id)
            stage='directory'
            machine=self.setup.machines.resolve(job.machine_uuid);user=self.setup.directory.user(payload['user']['login'])
            if user!=payload['user']:raise fail('workflow_identity_changed','The selected employee identity differs')
            ous=[o for o in self.setup.directory.ous() if o['dn'].casefold()==payload['computer_ou'].casefold()]
            computer=self.setup.directory.computer(machine.hostname)
            if (len(ous)!=1 or ous[0]!=payload['ou_identity'] or payload['computer_ou'] not in self.setup.approved_ous
                    or len(computer['objects'])!=1):raise fail('workflow_identity_changed','The selected directory identities differ')
            obj=computer['objects'][0];current_computer={k:obj[k] for k in ('object_guid','object_sid','dn','dns_hostname')}
            if current_computer!=system['result']['computer']:raise fail('workflow_identity_changed','The selected computer identity differs')
            stage='policy'
            if VaultHealthChecker(self.settings).full_workflow_policy()!=workflow['policy']['final_dns']:
                raise fail('workflow_source_changed','The protected resolver policy differs')
            stage='wallet'
            wallet_fact=facts['components']['desktop.kwallet_repair']
            if wallet_fact.get('error_code') in WAIT_CODES:raise fail(wallet_fact['error_code'],'Selected-user wallet readiness is unavailable')
            wallet=wallet_fact['wallet_readiness']
            stage='dns'
            dns_fact=facts['components']['network.final_dns']
            if dns_fact.get('error_code') in WAIT_CODES:raise fail(dns_fact['error_code'],'Resolver readiness is unavailable')
            dns=dns_fact['final_dns']
            stage='vnc_policy'
            policy=observe_vnc_policy(self.settings,machine,DIRECT_POLICY,runner=self.runner,
                expected_source=payload['source_sha256'],expected_ssh_binding=payload['ssh_binding'],
                expected_boot_id=facts['machine']['boot_id'])
            if policy['observation']['ready'] is not True:raise ValueError
            stage='templates'
            checker=VaultHealthChecker(self.settings)
            values=yaml.load(checker._decrypt(),Loader=_StrictLoader)
            private_values={name:values[name] for name in (KRFB_DESKTOP_PASSWORD_VARIABLE,KRFB_UNATTENDED_PASSWORD_VARIABLE)}
            # Fixed published templates, strict variables and LF bytes match
            # the role's actual Ansible template lookup (including final LF).
            env=Environment(undefined=StrictUndefined,keep_trailing_newline=True)
            role=self.settings.ansible_project_dir/'roles/remote_access_krfb/templates'
            def render(name):
                path=role/name;_regular(path)
                return env.from_string(path.read_text(encoding='utf-8')).render(**private_values,workstation_desktop_session='x11')
            request={'schema_version':1,'machine_uuid':machine.uuid,'hostname':machine.hostname,'login':user['login'],
                'source_sha256':payload['source_sha256'],'policy_sha256':digest(DIRECT_POLICY),
                'policy_helper_sha256':policy['helper_sha256'],'configuration':render('krfbrc-managed.j2'),
                'autostart':render('org.sosn.krfb.desktop.j2')}
            program=target_program(phase_observer=True)
            args=ssh_prefix(self.settings,machine)+['sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(program)]
            stage='graphical_session'
            rc,raw,_=self.runner(args,input_text=json.dumps(request),timeout=90,max_bytes=65536,
                environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            from .krfb_runtime import _unique_object
            reply=json.loads(raw,object_pairs_hook=_unique_object)
            if (rc==4 and set(reply)=={'schema_version','status','code'} and type(reply['schema_version']) is int
                    and reply['schema_version']==1 and reply['status']=='blocked' and reply['code'] in WAIT_CODES):
                raise fail(reply['code'],'Selected-user graphical readiness is unavailable')
            if rc or set(reply)!={'schema_version','status','observation'} or reply['status']!='ok':raise ValueError
            krfb=reply['observation']
            stage='helper_binding'
            certificate_helper=self.settings.ansible_project_dir/'roles/government_ca/files/import_user_certificates.py'
            _regular(certificate_helper)
            helpers={'wallet':specification(self.settings.ansible_project_dir)['helper_sha256'],
                'krfb':hashlib.sha256(target_program(apply=True).encode()).hexdigest(),
                'dns':hashlib.sha256(dns_program(self.settings.ansible_project_dir).encode()).hexdigest(),
                'vnc_policy':policy['helper_sha256'],'certificates':hashlib.sha256(certificate_helper.read_bytes()).hexdigest()}
            if krfb['certificate_helper_sha256']!=helpers['certificates']:raise fail('workflow_source_changed','The installed certificate helper differs')
            stage='binding'
            ready=bind_readiness(job,phase,system,facts=facts,user=user,computer=current_computer,
                wallet=wallet,dns=dns['observation'],krfb=krfb,helpers=helpers)
            return ready,{'krfb_request':request,'krfb_observation':krfb,'wallet':wallet,'dns':dns,
                          'private_krfb_variables':private_values,'facts':facts,'verification':verification}
        except Exception as error:
            code=getattr(error,'code','')
            if code=='setup_post_verification_failed':code='workflow_identity_changed'
            from .errors import ControlError
            raise ControlError(code if code in WAIT_CODES else 'workflow_readiness_unverified',
                'Fresh phase identity, session or target readiness is unavailable',4,
                {'readiness_stage':stage}) from None
