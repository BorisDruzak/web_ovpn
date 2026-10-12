"""Fresh ordinary Setup plans gated by genuine recovery terminal resolution."""
from __future__ import annotations
from .locking import exclusive_lock
from .setup import SetupService, computer_matches, observed_computer_matches
from .ad_directory import DOMAIN, fail
import base64
from .setup_plans import digest, decode_state_bytes
from .setup_recovery_resolution import RecoveryResolutionStore

def validate_continuity(document, user, ou, observed, computer, machine):
    pinned = document['identity']
    terminal = document['terminal']
    objects = computer.get('objects', [])
    if (machine.uuid != pinned['machine_uuid'] or machine.hostname != pinned['hostname']
            or user.get('object_guid') != pinned['employee_guid'] or user.get('object_sid') != pinned['employee_sid']
            or user.get('state') != 'enabled' or user.get('login') != pinned['login']
            or user.get('upn') != pinned['login'] + '@' + DOMAIN
            or ou != decode_state_bytes(
                base64.b64decode(document['evidence']['files']['plan']['bytes_b64']))['payload']['ou_identity']
            or observed.get('uuid') != machine.uuid or observed.get('hostname') != machine.hostname
            or observed.get('domain') != DOMAIN or observed.get('trust') is not True
            or observed.get('sssd') is not True or observed.get('user_lookup') is not True
            or observed.get('local_duplicate') is not False or len(objects) != 1
            or objects[0].get('object_guid') != terminal['computer_guid']
            or objects[0].get('object_sid') != terminal['computer_sid']
            or not computer_matches(objects[0],machine.hostname,pinned['computer_ou'])
            or not observed_computer_matches(observed,objects[0],machine.hostname)):
        raise fail('recovery_continuation_identity_drift', 'Fresh domain trust and original immutable identities are required')

class RecoveryContinuationService:
    def __init__(self, settings, *, setup=None, terminal_verifier=None, **setup_options):
        self.settings = settings
        self.setup = setup or SetupService(settings, **setup_options)
        self.resolutions = RecoveryResolutionStore(settings, terminal_verifier=terminal_verifier, clock=self.setup.clock)
        self.setup.recovery_resolutions = self.resolutions

    def plan(self, failed_run_id, computer_guid):
        with exclusive_lock(self.settings.lock_file):
            document = self.resolutions.prepare(failed_run_id, computer_guid)
            identity = document['identity']
            reference = dict(document['pair'], resolution_sha256=digest(document))
            # Snapshot verifies the exact original failed binding plus fresh AD/trust.
            machine = self.setup.machines.resolve(identity['machine_uuid'])
            user = self.setup.directory.user(identity['login'])
            ous = [ou for ou in self.setup.directory.ous() if ou['dn'] == identity['computer_ou']]
            if len(ous) != 1:
                raise fail('recovery_continuation_identity_drift','Original computer OU must remain unique')
            validate_continuity(document,user,ous[0],self.setup.probe(machine,user),
                self.setup.directory.computer(machine.hostname),machine)
            self.resolutions.retain(document)
            payload = self.setup._snapshot(identity['machine_uuid'], identity['login'], identity['computer_ou'],
                identity['software_profile'], identity['remote_access_profile'], recovery_resolution=reference)
            return self.setup.plans.create(payload)
