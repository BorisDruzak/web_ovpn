"""Only real successful full/scoped executions can advance release evidence."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT/'deploy/alt-linux/release_verification.py'
ROLE = 'deploy/alt-linux/ansible/roles/'
DIRECTUM = ROLE+'software_directum/tasks/main.yml'
VK = ROLE+'software_vkworkspace/tasks/main.yml'


def module():
    spec = importlib.util.spec_from_file_location('release_verification', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def setup(tmp_path):
    m = module()
    source = tmp_path/'source'
    source.mkdir()
    paths = set(m.policy.full_targets()) | set(m.policy.MANDATORY) | set(m.policy.CRITICAL)
    for group in m.policy.GROUPS.values():
        paths.update(group['tests'])
        for role in group['roles']:
            paths.add(ROLE+role+'/tasks/main.yml')
    for path in paths:
        p = source/path
        if path == 'tests/alt_linux':
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('[]\n' if path.startswith(ROLE) else 'baseline\n')
    return m, source, tmp_path/'cache', {'python': '3.12', 'runtime': 'unchanged'}


def run(setup, execute=lambda targets: 0, **kwargs):
    m, source, cache, env = setup
    return m.verify_release(source, cache, env, execute, owner=os.getuid(), now=kwargs.pop('now', 1000), **kwargs)


def change(setup, path, value='changed\n'):
    p = setup[1]/path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('# '+value.replace('\n', ' ')+'\n[]\n' if path.startswith(ROLE) and path.endswith('.yml') else value)


def test_first_full_then_each_component_uses_last_verified_snapshot(setup):
    calls = []
    first = run(setup, lambda t: calls.append(t) or 0)
    assert first['mode'] == 'full'
    change(setup, DIRECTUM)
    second = run(setup, lambda t: calls.append(t) or 0, now=1001)
    assert second['mode'] == 'selective' and second['components'] == ['directum']
    change(setup, VK)
    third = run(setup, lambda t: calls.append(t) or 0, now=1002)
    assert third['components'] == ['vkworkspace']
    assert 'tests/alt_linux' in calls[0]
    assert 'tests/alt_linux' not in calls[1] + calls[2]
    assert second['foundation'] == third['foundation']


def test_selected_receipt_resumes_after_baseline_promotion_but_not_as_full(setup):
    run(setup)
    change(setup, DIRECTUM)
    passed = run(setup, now=1001)
    resumed = run(setup, lambda _: pytest.fail('must reuse'), resume=True, now=1002)
    assert resumed['verification'] == 'reused' and resumed['proof'] == passed['proof']
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('forced full must refuse selected proof'), resume=True, full=True, now=1003)


@pytest.mark.parametrize('fault', ['core', 'unknown', 'policy', 'environment', 'delete', 'permissions'])
def test_shared_and_uncertain_changes_force_full(setup, fault):
    run(setup)
    if fault == 'core': change(setup, 'deploy/alt-linux/control/alt_deploy/setup.py')
    elif fault == 'unknown': change(setup, 'unknown.py')
    elif fault == 'policy': change(setup, 'deploy/alt-linux/verification_policy.py')
    elif fault == 'environment': setup[3]['runtime'] = 'different'
    elif fault == 'delete': (setup[1]/DIRECTUM).unlink()
    else: (setup[1]/DIRECTUM).chmod(0o600)
    assert run(setup, now=1001)['mode'] == 'full'


def test_old_legacy_receipt_cannot_create_a_selective_baseline(setup):
    cache = setup[2];cache.mkdir(mode=0o700)
    p = cache/'legacy.json';p.write_text('{"schema":1,"result":"passed"}');p.chmod(0o600)
    change(setup, DIRECTUM)
    assert run(setup)['mode'] == 'full'


def test_new_failed_candidate_preserves_parent_and_retry_stays_scoped(setup):
    run(setup)
    change(setup, DIRECTUM, 'bad\n')
    with pytest.raises(ValueError, match='verification_failed'):
        run(setup, lambda _: 1, now=1001)
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('no failed receipt'), resume=True, now=1002)
    change(setup, DIRECTUM, 'fixed\n')
    assert run(setup, now=1003)['components'] == ['directum']


def test_contradictory_failure_of_trusted_snapshot_revokes_foundation_family(setup):
    run(setup)
    change(setup, DIRECTUM)
    run(setup, now=1001)
    with pytest.raises(ValueError):
        run(setup, lambda _: 1, now=1002)
    change(setup, VK)
    assert run(setup, now=1003)['mode'] == 'full'


@pytest.mark.parametrize('fault', ['source', 'environment'])
def test_input_change_during_tests_never_promotes_failed_snapshot(setup, fault):
    run(setup)
    change(setup, DIRECTUM)
    def mutate(targets):
        if fault == 'source': change(setup, VK)
        else: setup[3]['runtime'] = 'changed during execution'
        return 0
    with pytest.raises(ValueError, match='verification_inputs_changed'):
        run(setup, mutate, now=1001)
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('changed input has no receipt'), resume=True, now=1002)


def test_baseline_lifetime_and_exact_resume_expiry_are_separate(setup):
    run(setup)
    later = 1000 + 10*24*3600
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('expired resume'), resume=True, now=later)
    change(setup, DIRECTUM)
    assert run(setup, now=later)['mode'] == 'selective'


def test_plan_is_read_only_and_has_no_test_execution(setup):
    plan = run(setup, lambda _: pytest.fail('plan cannot run tests'), plan_only=True)
    assert plan['mode'] == 'full' and plan['verification'] == 'planned'
    assert not setup[2].exists()
    run(setup)
    change(setup, DIRECTUM)
    before = {str(p): p.read_bytes() for p in setup[2].rglob('*') if p.is_file()}
    assert run(setup, lambda _: pytest.fail('plan cannot run tests'), plan_only=True)['components'] == ['directum']
    assert before == {str(p): p.read_bytes() for p in setup[2].rglob('*') if p.is_file()}


def test_corrupt_baseline_requires_full_and_symlink_cache_refuses_before_tests(setup):
    run(setup)
    pointer = setup[2]/'release-baseline.json'
    pointer.write_text('{}')
    change(setup, DIRECTUM)
    assert run(setup, now=1001)['mode'] == 'full'
    data = pointer.read_text();pointer.unlink()
    target = setup[2]/'other';target.write_text(data);target.chmod(0o600)
    pointer.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        run(setup, lambda _: pytest.fail('unsafe cache'), now=1002)


def test_native_lock_excludes_concurrent_legacy_and_new_verifiers(setup):
    import fcntl
    cache = setup[2];cache.mkdir(mode=0o700)
    fd = os.open(cache/'.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            run(setup, lambda _: pytest.fail('concurrent tests'))
    finally:
        os.close(fd)


@pytest.mark.parametrize('kind', ['snapshot', 'family'])
def test_null_revocation_marker_cannot_restore_an_old_pass(setup, kind):
    result = run(setup)
    m, _, cache, _ = setup
    node = json.loads((cache/'.release-proofs'/(result['proof']+'.json')).read_text())
    identity = {k: node[k] for k in m.IDENTITY}
    name = 'release-blocked-'+m.gate.digest(identity) if kind == 'snapshot' else 'release-family-blocked-'+result['proof']
    path = cache/(name+'.json');path.write_text('null');path.chmod(0o600)
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('revoked evidence must refuse'), resume=True, now=1001)


def test_plan_refuses_symlinked_proof_directory(setup):
    run(setup)
    proofs = setup[2]/'.release-proofs'
    renamed = setup[2]/'renamed-proofs'
    proofs.rename(renamed);proofs.symlink_to(renamed, target_is_directory=True)
    with pytest.raises(ValueError, match='verification_path_unsafe'):
        run(setup, lambda _: pytest.fail('unsafe cache'), plan_only=True, now=1001)


def test_resume_rechecks_environment_after_reading_proof(setup, monkeypatch):
    run(setup)
    m = setup[0]
    original = m.EvidenceStore.lookup
    def drift(store, identity, now):
        result = original(store, identity, now)
        setup[3]['runtime'] = 'drift during receipt validation'
        return result
    monkeypatch.setattr(m.EvidenceStore, 'lookup', drift)
    with pytest.raises(ValueError, match='verification_inputs_changed'):
        run(setup, lambda _: pytest.fail('resume cannot run tests'), resume=True, now=1001)


def test_noncanonical_source_names_refuse_before_execution(setup):
    run(setup)
    change(setup, ROLE+'software_directum/files/bad\\name.py')
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('invalid manifest must refuse'), now=1001)


@pytest.mark.parametrize('kind,expected', [('environment', 'environment_changed'), ('policy', 'selection_policy_changed')])
def test_plan_explains_why_full_is_required(setup, kind, expected):
    run(setup)
    if kind == 'environment': setup[3]['runtime'] = 'new runtime'
    else: change(setup, 'deploy/alt-linux/verification_policy.py')
    value = run(setup, lambda _: pytest.fail('plan is read only'), plan_only=True, now=1001)
    assert value['mode'] == 'full' and value['reason'] == expected


def test_full_recheck_uses_new_foundation_even_if_clock_has_not_advanced(setup):
    first = run(setup, full=True)
    with pytest.raises(ValueError):
        run(setup, lambda _: 1, full=True)
    second = run(setup, full=True)
    assert second['proof'] != first['proof']
    assert run(setup, lambda _: pytest.fail('new full proof is reusable'), resume=True)['proof'] == second['proof']


def test_missing_old_receipt_does_not_hide_revocation_from_deep_descendants(setup):
    run(setup, now=1000)
    vk_original = (setup[1]/VK).read_text()
    change(setup, DIRECTUM, 'A\n')
    a = run(setup, now=1001)
    a_node = json.loads((setup[2]/'.release-proofs'/(a['proof']+'.json')).read_text())
    change(setup, VK, 'B\n');run(setup, now=1002)
    change(setup, VK, 'C\n');run(setup, now=1003)
    c_contents = (setup[1]/VK).read_text()
    a_identity = {k: a_node[k] for k in setup[0].IDENTITY}
    (setup[2]/('release-'+setup[0].gate.digest(a_identity)+'.json')).unlink()
    (setup[1]/VK).write_text(vk_original)  # Exact source A again, index missing.
    with pytest.raises(ValueError):
        run(setup, lambda _: 1, now=1004)
    (setup[1]/VK).write_text(c_contents)
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('descendant of revoked proof'), resume=True, now=1005)


def test_lexical_parent_segments_cannot_bypass_cache_source_overlap(setup):
    m, source, _, env = setup
    child = source/'child';child.mkdir()
    with pytest.raises(ValueError, match='verification_cache_source_overlap'):
        m.verify_release(child/'..', source/'.pytest_cache', env,
                         lambda _: pytest.fail('overlapping cache'), owner=os.getuid(), now=1000)


def test_directory_permissions_are_bound_to_exact_receipt_and_force_full(setup):
    run(setup)
    (setup[1]/ROLE/'software_directum').chmod(0o750)
    with pytest.raises(ValueError):
        run(setup, lambda _: pytest.fail('directory drift invalidates resume'), resume=True, now=1001)
    assert run(setup, now=1002)['mode'] == 'full'
