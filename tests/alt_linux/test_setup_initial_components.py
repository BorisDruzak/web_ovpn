"""All published components use fresh evidence and profile-specific desired state."""
import copy

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import desired_queries
from alt_deploy.component_verification import VerificationEngine
from test_component_catalog import SOURCE, project
from test_component_verification import evidence
from test_component_setup import component_service


CATALOG = ComponentCatalog.load(SOURCE)


@pytest.mark.parametrize('identifier', [c['id'] for c in CATALOG.components()])
@pytest.mark.parametrize('state', ['healthy', 'drift', 'missing_fact', 'malformed'])
def test_every_initial_component_detects_drift(identifier, state):
    facts = evidence(CATALOG)
    fact = facts['components'][identifier]
    if state == 'drift':
        if 'packages' in fact: fact['executable'] = False
        else: fact['checks']['ready'] = False
        # Typed observations must describe an actual drift. A contradictory
        # ready boolean with healthy signed metadata is unknown, not drifted.
        if identifier=='desktop.kwallet_repair':
            from alt_deploy.kwallet_runtime import canonical
            import hashlib
            value=fact['wallet_readiness'];value['disposition']='repair'
            value['snapshot_sha256']=hashlib.sha256(canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()
        elif identifier=='network.final_dns':
            from alt_deploy.final_dns_runtime import canonical
            import hashlib
            value=fact['final_dns']['observation'];value['servers']=['192.0.2.11']
            value['snapshot_sha256']=hashlib.sha256(canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()
    elif state == 'missing_fact': del facts['components'][identifier]
    elif state == 'malformed': fact['checks']['ready'] = 'true'
    result = VerificationEngine(CATALOG).evaluate(facts, [identifier])
    assert result['components'][identifier]['status'] == {
        'healthy': 'compliant', 'drift': 'drifted', 'missing_fact': 'unknown', 'malformed': 'unknown'}[state]


@pytest.mark.parametrize('profile,crypto', [('core-apps', True), ('office-standard-v1', False), ('office-signature-v1', True)])
def test_office_standard_shortcuts_do_not_require_cryptopro(profile, crypto):
    selected = CATALOG.ordered(['desktop.shortcuts'], os_id='alt-kworkstation-11')
    query = next(q for q in desired_queries(SOURCE, CATALOG, selected, profile_id=profile) if q['id'] == 'desktop.shortcuts')
    assert ('cptools.desktop' in query['entries']) is crypto
    assert 'onlyoffice-desktopeditors.desktop' in query['entries']
    defaults = yaml.safe_load((SOURCE/'roles/desktop_shortcuts/defaults/main.yml').read_text())
    assert set(query['entries']) <= set(defaults['desktop_shortcuts_component_entries'].values())


def test_existing_plasma_keyboard_is_applied_from_published_template():
    helper = (SOURCE/'roles/plasma_baseline/files/apply_desktop_defaults.py').read_text()
    assert 'keyboard_settings' in helper and 'kxkbrc' in helper
    tasks = yaml.safe_load((SOURCE/'roles/plasma_baseline/tasks/main.yml').read_text())
    keyboard = next(t for t in tasks if t.get('name') == 'Merge published keyboard defaults into the existing domain profile')
    assert 'kxkbrc.j2' in keyboard['ansible.builtin.command']['argv'][-1]


def test_full_verification_exposes_actual_components_without_blocking_partial_component_install(component_service):
    service, setup, machine, user, facts, _, _ = component_service
    setup.component_probe = service.probe
    facts['components']['software.onlyoffice'].update(packages=[], executable=False)
    result = setup.verify(machine.uuid)
    assert result['status'] == 'degraded'
    assert result['component_verification']['components']['software.onlyoffice']['status'] == 'missing'
    assert service.plan(machine.uuid, 'software.onlyoffice')['payload']['action'] == 'install'


def test_krfb_confirmation_is_bound_to_durable_plan_without_inheriting_cli_environment(component_service, monkeypatch):
    from alt_deploy.configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
    from alt_deploy.setup_execution import SetupExecutionEngine
    from alt_deploy.setup_jobs import SetupJobRepository
    from alt_deploy.setup_worker import SetupWorker
    service, setup, machine, *_ = component_service
    monkeypatch.delenv(KRFB_NETWORK_CONFIRMATION_VARIABLE, raising=False)
    assert service.plan(machine.uuid, 'remote.krfb')['payload']['action'] == 'blocked'
    monkeypatch.setenv(KRFB_NETWORK_CONFIRMATION_VARIABLE, 'true')
    plan = service.plan(machine.uuid, 'remote.krfb')
    assert plan['payload']['network_restriction_confirmed'] is True
    job_id = service.apply(plan['plan_id'], plan['sha256'])['job_id']
    monkeypatch.delenv(KRFB_NETWORK_CONFIRMATION_VARIABLE)
    jobs = SetupJobRepository(setup.settings, clock=service.clock)
    engine = SetupExecutionEngine(setup.settings, components=service, jobs=jobs)
    assert SetupWorker(setup.settings, engine=engine, clock=service.clock).run_once()['status'] == 'successful'
    import os
    assert KRFB_NETWORK_CONFIRMATION_VARIABLE not in os.environ


def test_component_verify_does_not_require_installation_artifacts_or_vault(component_service):
    service, _, machine, _, facts, *_ = component_service
    facts['components']['software.onlyoffice'].update(packages=[], executable=False)
    machine.active_job = {'job_id': 'another-operation'}
    service.preflight = lambda *a: pytest.fail('Read-only verify must not check installation secrets/artifacts')
    assert service.verify(machine.uuid, 'software.onlyoffice')['components']['software.onlyoffice']['status'] == 'missing'


def test_pending_reboot_is_not_hidden_by_installed_components():
    facts = evidence(CATALOG)
    old_boot = facts['machine']['boot_id']
    result = VerificationEngine(CATALOG).evaluate(facts, ['software.onlyoffice'], reboot_required=True, original_boot_id=old_boot)
    assert result['overall_status'] == 'waiting_reboot' and result['reboot_required'] is True
    facts['machine']['boot_id'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    assert VerificationEngine(CATALOG).evaluate(facts, ['software.onlyoffice'], reboot_required=True,
        original_boot_id=old_boot)['overall_status'] == 'successful'
    assert VerificationEngine(CATALOG).evaluate(facts, ['software.onlyoffice'], reboot_required=True)['overall_status'] == 'unknown_requires_review'


@pytest.mark.parametrize('fault', ['healthy', 'expired', 'trust', 'nss', 'system_anchor', 'import_helper', 'required_csp_missing'])
def test_certificates_use_current_system_user_trust_and_pinned_helper(tmp_path, fault):
    import os
    import sqlite3
    import ssl
    from alt_deploy.component_probe_script import certificates_ready
    query = desired_queries(SOURCE, CATALOG, [CATALOG.component('certificates.government')])[0]
    if fault=='required_csp_missing':query['require_cryptopro']=True
    certs = query['certificates']
    public = tmp_path/'usr/local/share/alt-government-ca'
    public.mkdir(parents=True)
    roots = []
    for entry in certs:
        payload = (SOURCE/'files/government_ca'/entry['filename']).read_bytes()
        (public/entry['filename']).write_bytes(payload)
        if entry['kind'] == 'root': roots.append(payload.decode())
    bundle = tmp_path/'etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    bundle.parent.mkdir(parents=True)
    bundle.write_text(''.join(roots[1:] if fault == 'system_anchor' else roots))
    for target, source in [('/usr/local/libexec/alt-government-ca-user-import.py', 'import_user_certificates.py'),
                            ('/etc/xdg/autostart/alt-government-ca.desktop', 'alt-government-ca.desktop')]:
        path = tmp_path/target.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((SOURCE/'roles/government_ca/files'/source).read_bytes())
        path.chmod(query['installed_files'][target]['mode'])
    if fault == 'import_helper': (tmp_path/'usr/local/libexec/alt-government-ca-user-import.py').write_text('altered public helper')
    database = tmp_path/'home/synthetic/.pki/nssdb/cert9.db'
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE nssPublic (a3 BLOB, a11 BLOB)')
        for entry in certs:
            if entry['gost']: continue
            der = ssl.PEM_cert_to_DER_cert((public/entry['filename']).read_text())
            db.execute('INSERT INTO nssPublic VALUES (?, ?)',
                (('ALT Government CA '+entry['filename']).encode(), b'wrong' if fault == 'nss' else der))
    def call(args):
        if args[0] == 'openssl': return (1 if fault == 'expired' else 0), ''
        assert 'certutil' in args
        return 0, '\n'.join('ALT Government CA '+e['filename']+' '+
            ('u,,' if fault == 'trust' else 'C,,' if e['kind'] == 'root' else ',,') for e in certs if not e['gost'])
    before = {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert certificates_ready(tmp_path, query, '/home/synthetic', 'synthetic', os.getuid(), call) is (fault == 'healthy')
    assert before == {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
