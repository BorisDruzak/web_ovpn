"""Read-only selected-user gate, bound to the genuine confirmed native chain."""
from __future__ import annotations

import copy

from .ad_directory import fail
from .setup_plans import canonical,digest,private_read
from .setup_recovery_native_authorization import RecoveryNativeAuthorization


def _same(left,right):return canonical(left)==canonical(right)


def native_records(runtime,context,plan_id,sha):
    pair=context['pair'];request=context['request'];started=context['started']
    failed=runtime.attempts._path(**pair,suffix='.native-testjoin-failed.json')
    intent_path=runtime.attempts._path(**pair,suffix='.native-testjoin-intent.json')
    result_path=runtime.attempts._path(**pair,suffix='.native-testjoin-result.json')
    intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(request),
        startup_receipt_sha256=digest(started),sources_sha256=digest(context['sources']),
        authorization_sha256=digest(context['authorization']))
    if failed.exists() or failed.is_symlink() or not _same(private_read(intent_path),intended):raise ValueError
    result=private_read(result_path);runtime._receipt(request,started,result)
    if (failed.exists() or failed.is_symlink() or not _same(private_read(intent_path),intended)
            or not _same(private_read(result_path),result)):raise ValueError
    return result


class RecoveryUserAuthorization:
    def __init__(self,*,native_runtime):
        if (not isinstance(native_runtime.authorization,RecoveryNativeAuthorization)
                or native_runtime.startup_runtime is not native_runtime.authorization.startup_runtime):
            raise ValueError('Same genuine native authorization/runtime chain required')
        self.native_runtime=native_runtime;self.native_authorization=native_runtime.authorization
        self.gate=self.native_authorization.startup_authorization

    def __call__(self,plan_id,sha,source_sha,request_sha,started_sha,native_sha):
        try:
            runtime=self.native_runtime;gate=self.gate;plans=gate.plans
            if runtime.authorization is not self.native_authorization or runtime.startup_runtime is not self.native_authorization.startup_runtime:raise ValueError
            loaded=copy.deepcopy(gate._load(plan_id,sha));approved=loaded['attachment']['payload']
            if approved['scope']!='one_fixed_sssd_start_native_and_user_check_with_retained_temporary_policy':raise ValueError
            scope=approved['user_check'];sources=plans._user_sources()
            if digest(sources)!=source_sha or scope['source_sha256']!=source_sha:raise ValueError
            protected=copy.deepcopy(gate.postwrite._protected(plan_id,sha)[0])
            context=copy.deepcopy(runtime._context(plan_id,sha));result=native_records(runtime,context,plan_id,sha)
            facts=context['request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
            if (context['sources']!=sources[:-1] or context['pair']!=gate._pair(loaded['base']['plan'])
                    or context['authorization']['approval_sha256']!=loaded['attachment']['sha256']
                    or context['request']['approval_sha256']!=loaded['attachment']['sha256']
                    or digest(context['request'])!=request_sha or digest(context['started'])!=started_sha or digest(result)!=native_sha
                    or not _same({key:facts['tools'][key] for key in scope['dependencies']},scope['dependencies'])):raise ValueError
            if not _same(runtime._context(plan_id,sha),context):raise ValueError
            # Finish directory/context callbacks with local protected rereads.
            if (runtime.authorization is not self.native_authorization
                    or runtime.startup_runtime is not self.native_authorization.startup_runtime
                    or not _same(gate.postwrite._protected(plan_id,sha)[0],protected)
                    or not _same(gate._load(plan_id,sha),loaded) or plans._user_sources()!=sources
                    or not _same(native_records(runtime,context,plan_id,sha),result)):raise ValueError
            gate._bound(loaded['base']['plan'],gate._expected(loaded))
            return copy.deepcopy(dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=source_sha,
                startup_request_sha256=request_sha,startup_receipt_sha256=started_sha,native_receipt_sha256=native_sha,
                employee=scope['employee'],user_scope_sha256=digest(scope),approval_sha256=loaded['attachment']['sha256']))
        except Exception:
            raise fail('recovery_user_approval_invalid','Explicit user scope, fresh employee and retained native/startup evidence must remain bound') from None
