"""Fixed read-only corrective admission and bound archival root observations."""
from __future__ import annotations
from .ad_directory import fail
from .setup_plans import canonical
from .setup_recovery_source_stdin import build_source_stdin
from .setup_recovery_successor_runtime import RecoverySuccessorRuntime

class RecoveryRehearsalSuccessorRuntime(RecoverySuccessorRuntime):
    def _root(self,request):
        source=self._source('setup_recovery_rehearsal_probe.py')
        script,wire=build_source_stdin(source,dict(request=request))
        return self._run(['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c',script],wire)

    def controller(self,*,approved_at,finished_at):
        try:
            result=self._root(dict(kind='inspect',approved_at=approved_at,finished_at=finished_at))
            if set(result)!={'schema_version','native_guard','no_active_recovery','capacity','backup_audit','retained'}:raise ValueError
            ready=self.readiness()
            if ready.get('ready') is not True or ready.get('failed_checks') or not ready.get('checks') or any(v is not True for v in ready['checks'].values()):raise ValueError
            return dict(result,readiness=True)
        except Exception:raise fail('recovery_rehearsal_controller_refused','Fixed locale, archival backup, guard, capacity and readiness must verify') from None

    def bound(self,retained,*,approved_at,finished_at,operation_sha256):
        try:
            result=self._root(dict(kind='bound',retained=retained,approved_at=approved_at,finished_at=finished_at,operation_sha256=operation_sha256))
            expected=dict(schema_version=1,retained_evidence_unchanged=True,protected_metadata_sha256=retained['protected_metadata_sha256'])
            if canonical(result)!=canonical(expected):raise ValueError
            return result
        except Exception:raise fail('recovery_rehearsal_evidence_changed','Bound native backup, retained tree and tools must remain unchanged') from None
