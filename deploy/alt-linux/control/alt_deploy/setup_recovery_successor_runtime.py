"""Fixed source-bound, strictly read-only successor admission observations."""
from __future__ import annotations
import ipaddress,shlex
from pathlib import Path
from .ad_directory import fail
from .setup_plans import canonical,decode_state_bytes
from .setup_recovery_runtime import _read_source
from .setup_recovery_source_stdin import build_source_stdin,MAX_REPLY_BYTES
from .setup_recovery_process import bounded_bundle_run
from .controller_readiness import ControllerReadinessChecker

class RecoverySuccessorRuntime:
    def __init__(self,settings,*,runner=None,readiness=None):
        self.settings=settings;self.runner=runner or bounded_bundle_run
        self.readiness=readiness or ControllerReadinessChecker(settings).check

    def _source(self,name):
        path=Path(__file__).with_name(name)
        return _read_source(path,owner=Path(__file__).lstat().st_uid)

    def _run(self,command,wire):
        rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=wire,timeout=150)
        if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>MAX_REPLY_BYTES:raise ValueError
        return decode_state_bytes(out.encode())

    def inspect(self,machine,pair):
        try:
            request=dict(schema_version=1,pair=pair,machine_uuid=machine.uuid,hostname=machine.hostname)
            source=self._source('setup_recovery_successor_probe.py')
            script,wire=build_source_stdin(source,dict(request=request))
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+str(ipaddress.ip_address(machine.ip)),'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            result=self._run(command,wire)
            if canonical(result)!=canonical(dict(request,footprints_absent=True,no_active_recovery=True)):raise ValueError
            return result
        except Exception:raise fail('recovery_successor_inspection_refused','Fixed selected-workstation absence and process proof must verify') from None

    def controller(self,*,approved_at,finished_at):
        try:
            source=self._source('setup_recovery_successor_capacity.py')
            script,wire=build_source_stdin(source,dict(request=dict(approved_at=approved_at,finished_at=finished_at)))
            result=self._run(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c',script],wire)
            if set(result)!={'schema_version','native_guard','no_active_recovery','capacity','backup_audit'}:raise ValueError
            ready=self.readiness()
            if ready.get('ready') is not True or ready.get('failed_checks') or not ready.get('checks') or any(value is not True for value in ready['checks'].values()):raise ValueError
            return dict(result,readiness=True)
        except Exception:raise fail('recovery_successor_controller_refused','Current native guard, protected backup audit, capacity and readiness must verify') from None
