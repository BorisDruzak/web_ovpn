"""Read-only native gate for an explicitly approved startup/native attachment.

Called under the controller lifecycle lock. No separate implicit permission,
Vault opening, SSH, directory write, service action or binding mutation exists.
"""
from __future__ import annotations

import copy

from .ad_directory import fail
from .setup_plans import canonical,digest,private_read


def _same(left,right):return canonical(left)==canonical(right)


class RecoveryNativeAuthorization:
    def __init__(self,*,startup_authorization,startup_runtime):
        if startup_runtime.authorization is not startup_authorization:raise ValueError('Same exact startup gate required')
        self.startup_authorization=startup_authorization;self.startup_runtime=startup_runtime

    def _records(self,plan_id,sha,context,request_sha,receipt_sha):
        gate=self.startup_authorization;request=context['request'];pair=context['pair']
        intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(request),
            policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
            approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
        intent_path=gate.preparation.attempts._path(**pair,suffix='.sssd-start-intent.json')
        result_path=gate.preparation.attempts._path(**pair,suffix='.sssd-start-result.json')
        result=private_read(result_path);self.startup_runtime._receipt(request,result)
        if (digest(request)!=request_sha or digest(result)!=receipt_sha
                or not _same(private_read(intent_path),intended)):raise ValueError
        return result

    def __call__(self,plan_id,sha,source_sha,request_sha,receipt_sha):
        try:
            gate=self.startup_authorization;plans=gate.plans
            loaded=copy.deepcopy(gate._load(plan_id,sha));approved=loaded['attachment']['payload']
            if (approved['scope']!='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy'
                    or approved['native_check']['source_sha256']!=source_sha):raise ValueError
            sources=plans._native_sources()
            if digest(sources)!=source_sha:raise ValueError
            startup=gate(plan_id,sha,digest(sources[:-1]))
            context=copy.deepcopy(self.startup_runtime._context(plan_id,sha));request=context['request']
            protected=context['policy_context']['kerberos_context']['import_context']['protected']
            original=request['policy_request']['kerberos_request']['import_request']['directory_result']
            plan=loaded['base']['plan'];pair=gate._pair(plan)
            if (context['pair']!=pair or context['sources']!=sources[:-1]
                    or not _same(context['authorization'],startup)
                    or not _same(protected['payload'],plan['payload'])
                    or not _same(original,protected['directory_result'])
                    or any(original[key]!=plan['payload'][key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid'))):raise ValueError
            result=self._records(plan_id,sha,context,request_sha,receipt_sha)
            if (not _same(gate(plan_id,sha,digest(sources[:-1])),startup)
                    or not _same(self.startup_runtime._context(plan_id,sha),context)):raise ValueError
            if (plans._native_sources()!=sources or not _same(gate._load(plan_id,sha),loaded)
                    or not _same(gate.postwrite._protected(plan_id,sha)[0],protected)
                    or not _same(self._records(plan_id,sha,context,request_sha,receipt_sha),result)):raise ValueError
            gate._bound(plan,gate._expected(loaded))
            return dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=source_sha,
                startup_request_sha256=request_sha,startup_receipt_sha256=receipt_sha,
                startup_approval_sha256=startup['approval_sha256'],effects_ledger_sha256=startup['effects_ledger_sha256'],
                approval_sha256=gate.confirmed_startup_sha)
        except Exception:
            raise fail('recovery_native_approval_invalid','Explicit native scope, exact approval pair and retained startup must remain bound') from None
