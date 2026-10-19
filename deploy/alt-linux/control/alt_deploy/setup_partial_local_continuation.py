"""One additive ordinary Setup successor after verified local recovery."""
from .setup_partial_local_state import PartialLocalStore, claim_key, assert_no_pending, denied
from .setup_partial_local_runtime import PartialLocalRuntime, validate_local_after
from .setup_plans import digest

PROOFS = ('prejoin_retry', 'recovery_resolution', 'partial_local_resolution')


def load_resolution(settings, reference, *, archival, runtime=None):
    try:
        if set(reference) != {'job_id', 'failed_run_id', 'configuration_run_id', 'recovery_plan_id',
                              'recovery_sha256', 'result_sha256', 'history_sha256'}: raise denied()
        store = PartialLocalStore(settings)
        plan = store.load(reference['recovery_plan_id'], reference['recovery_sha256'], archival=True)
        payload = plan['payload']
        claim = store._claim(store.claims/(claim_key(payload)+'.json'))
        result = store.result_for(claim)
        if result is None or result['status'] != 'successful': raise denied()
        expected = {k: payload[k] for k in ('job_id', 'failed_run_id', 'configuration_run_id', 'history_sha256')}
        expected.update(recovery_plan_id=plan['plan_id'], recovery_sha256=plan['sha256'], result_sha256=digest(result))
        if reference != expected or claim['plan_id'] != plan['plan_id'] or claim['plan_sha256'] != plan['sha256']: raise denied()
        closed = store.load_closed(payload['history_sha256'])
        document = {'plan': plan, 'claim': claim, 'result': result, 'closed': closed}
        if not archival:
            runtime = runtime or PartialLocalRuntime(settings)
            if runtime.source() != payload['source_sha256']: raise denied()
            after = validate_local_after(payload, runtime.verify(plan, result['target']))
            if digest(after['partial_local']['native']) != result['target']['after_sha256']: raise denied()
            document['after'] = after
        return document
    except Exception: raise denied() from None


def validate_resolution(settings, reference, binding, *, live=None, runtime=None):
    document = load_resolution(settings, reference, archival=False, runtime=runtime)
    if binding != document['closed']['binding']: raise denied()
    if live is not None: validate_continuity(document, live)
    return document


def validate_continuity(document, live):
    fresh = document['after']
    if (any(live[k] != fresh[k] for k in ('machine', 'user', 'ou_identity', 'computer', 'observed', 'ssh_binding'))
            or live['component_observed']['machine']['boot_id'] != fresh['boot_id']
            or live['component_observed']['user'] != fresh['user_runtime']): raise denied()


class PartialLocalContinuation:
    def __init__(self, settings, *, setup=None, runtime=None, clock=None):
        from .setup import SetupService
        self.settings = settings
        self.setup = setup or SetupService(settings, clock=clock)
        self.runtime = runtime or PartialLocalRuntime(settings)
        self.setup.partial_runtime = self.runtime
        self.store = PartialLocalStore(settings, clock=clock or self.setup.clock)

    def plan(self, recovery_plan_id):
        from .locks import exclusive_lock
        with exclusive_lock(self.settings.lock_file):
            assert_no_pending(self.settings)
            recovery = self.store.load(recovery_plan_id, recovery_plan_id.removeprefix('partial-local-'), archival=True)
            payload = recovery['payload']
            claim = self.store._claim(self.store.claims/(claim_key(payload)+'.json'))
            result = self.store.result_for(claim)
            if result is None or result['status'] != 'successful': raise denied()
            reference = {k: payload[k] for k in ('job_id', 'failed_run_id', 'configuration_run_id', 'history_sha256')}
            reference.update(recovery_plan_id=recovery_plan_id, recovery_sha256=recovery['sha256'], result_sha256=digest(result))
            document = load_resolution(self.settings, reference, archival=True)
            original = document['closed']['original']
            snapshot = self.setup._snapshot(original['machine']['uuid'], original['user']['login'], original['computer_ou'],
                original['request']['software_profile'], original['request']['remote_access_profile'],
                partial_local_resolution=reference)
            return self.setup.plans.create(snapshot)
