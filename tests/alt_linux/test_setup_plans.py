from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy.errors import ControlError

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def store(tmp_path, clock=lambda: NOW):
    from alt_deploy.setup_plans import SetupPlanStore
    return SetupPlanStore(tmp_path, clock=clock)


def test_plans_bind_all_content_and_are_deterministic(tmp_path):
    plans = store(tmp_path)
    first = plans.create({'machine_uuid': 'synthetic', 'login': 'user', 'ou': 'synthetic'})
    again = plans.create({'ou': 'synthetic', 'login': 'user', 'machine_uuid': 'synthetic'})
    assert first == again
    assert plans.load(first['plan_id'], first['sha256']) == first
    assert first['expires_at'] > first['created_at']
    assert (tmp_path / 'setup-plans' / (first['plan_id'] + '.json')).stat().st_mode & 0o077 == 0 if sys.platform != 'win32' else True


def test_plan_tamper_expiry_sha_and_traversal_rejected(tmp_path):
    plans = store(tmp_path)
    plan = plans.create({'machine_uuid': 'synthetic'})
    with pytest.raises(ControlError) as caught:
        plans.load(plan['plan_id'], 'a' * 64)
    assert caught.value.code == 'setup_plan_mismatch'
    expired = store(tmp_path, clock=lambda: NOW + timedelta(hours=1))
    with pytest.raises(ControlError) as caught:
        expired.load(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_expired'
    with pytest.raises(ControlError):
        plans.load('../../private', plan['sha256'])
    path = tmp_path / 'setup-plans' / (plan['plan_id'] + '.json')
    document = json.loads(path.read_text())
    document['payload']['machine_uuid'] = 'other'
    path.write_text(json.dumps(document))
    with pytest.raises(ControlError) as caught:
        plans.load(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_invalid'


def test_plan_metadata_tamper_is_detected(tmp_path):
    plans = store(tmp_path)
    plan = plans.create({'machine_uuid': 'synthetic'})
    path = tmp_path / 'setup-plans' / (plan['plan_id'] + '.json')
    document = json.loads(path.read_text())
    document['expires_at'] = '2099-01-01T00:00:00+00:00'
    path.write_text(json.dumps(document))
    with pytest.raises(ControlError):
        plans.load(plan['plan_id'], plan['sha256'])


def test_plan_symlink_rejected(tmp_path):
    if sys.platform == 'win32':
        pytest.skip('controller POSIX no-follow contract')
    plans = store(tmp_path)
    plan = plans.create({'machine_uuid': 'synthetic'})
    path = tmp_path / 'setup-plans' / (plan['plan_id'] + '.json')
    target = path.with_suffix('.saved')
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ControlError):
        plans.load(plan['plan_id'], plan['sha256'])
