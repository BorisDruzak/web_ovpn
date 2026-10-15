from __future__ import annotations

import copy
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.inventory.models import (InventoryAsset, InventoryAssetType, InventoryNetctlBinding,
    InventoryExternalBindingStatus as LinkStatus, InventoryNetworkProjectionVersion)
from test_inventory_netctl_sync import _snapshot_page

NOW = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)
MACHINE, USER, COMPUTER = [str(uuid.UUID(int=n)) for n in (1001, 1002, 1003)]
MAC = '02:00:00:00:00:11'


@pytest.fixture
def database(tmp_path):
    from app.workstations.schema import ensure_schema
    from app.workstations import models
    engine = create_engine('sqlite:///' + str(tmp_path / 'reconcile.sqlite'))
    Base.metadata.create_all(engine)
    ensure_schema(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        db.add(InventoryNetworkProjectionVersion(id=1, version=1))
        db.commit()
    yield factory
    engine.dispose()


def source(**content):
    return dict(schema_version=1, complete=True, generation=hashlib.sha256(repr(content).encode()).hexdigest(),
                generated_at=NOW.isoformat(), **content)


class Client:
    def __init__(self):
        self.failure = None
        self.ad = source(users=[{'object_guid': USER, 'object_sid': 'S-1-5-21-1', 'login': 'synthetic',
            'upn': 'synthetic@example.invalid', 'display_name': 'Synthetic Person', 'department': 'Test', 'state': 'enabled'}],
            computers=[{'object_guid': COMPUTER, 'object_sid': 'S-1-5-21-2', 'login': 'desktop-example$',
                        'dns_hostname': 'desktop-example.example.invalid', 'state': 'enabled'}])
        self.dns = source(records=[{'name': 'desktop-example.example.invalid', 'zone': 'example.invalid', 'type': 'A',
                                   'value': '192.0.2.17', 'ttl': 3600, 'timestamp': 0}], findings=[])
        self.machines = [{'uuid': MACHINE, 'hostname': 'desktop-example', 'mac': MAC,
                          'registration_state': 'ready', 'domain_assignment': None}]
    def call(self, operation, parameters, **kwargs):
        if operation == 'machines.list':
            return {'machines': copy.deepcopy(self.machines), 'total': len(self.machines), 'next_offset': len(self.machines), 'generation': 'c' * 64}
        if operation == 'directory.snapshot':
            if self.failure == parameters['source']:
                raise RuntimeError('private source diagnostic')
            return copy.deepcopy(self.ad if parameters['source'] == 'ad' else self.dns)
        raise AssertionError('Unexpected controller operation')


def network(hosts=None, **changes):
    rows = hosts if hosts is not None else [{'device_key': 'mac:' + MAC, 'mac': MAC, 'ip': '192.0.2.17', 'hostname': 'desktop-example'}]
    return _snapshot_page(hosts=rows, generated_at=NOW.isoformat(), **changes)


def run(database, tmp_path, *, client=None, payload=None, clock=lambda: NOW, before_publish=None):
    from app.workstations.reconcile import reconcile_once
    return reconcile_once(client=client or Client(), netctl_call=lambda args, timeout=None: payload or network(),
        session_factory=database, clock=clock, lock_path=tmp_path / 'worker' / 'reconcile.lock', before_publish=before_publish)


def test_coherent_reconciliation_retains_candidates_without_inventing_employee_assignment(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    result = run(database, tmp_path)
    assert result['status'] == 'success'
    with database() as db:
        snapshot = db.get(SourceSnapshot, 'reconciliation')
        device = snapshot.data_json['devices'][0]
        assert device['machine_uuid'] == MACHINE
        assert device['ad_computer_state'] == 'candidate'
        assert device['assigned_user'] is None
        assert device['inventory_asset_id'] is None


def test_partial_source_failure_retains_last_complete_view_and_logs_safe_code(database, tmp_path):
    from app.workstations.models import SourceRun, SourceSnapshot
    assert run(database, tmp_path)['status'] == 'success'
    with database() as db:
        old = copy.deepcopy(db.get(SourceSnapshot, 'reconciliation').data_json)
    client = Client()
    client.failure = 'dns'
    assert run(database, tmp_path, client=client)['status'] == 'degraded'
    with database() as db:
        assert db.get(SourceSnapshot, 'reconciliation').data_json == old
        failures = list(db.scalars(select(SourceRun).where(SourceRun.status == 'error')))
        assert failures and all('private' not in str(row.error_code) for row in failures)


@pytest.mark.parametrize('value', [(NOW + timedelta(seconds=1)).isoformat(), NOW.replace(tzinfo=None).isoformat(),
                                  (NOW - timedelta(minutes=16)).isoformat()])
def test_future_naive_or_stale_source_cannot_publish_success(database, tmp_path, value):
    client = Client()
    client.ad['generated_at'] = value
    assert run(database, tmp_path, client=client)['status'] == 'degraded'


def test_truncated_source_never_becomes_a_complete_snapshot(database, tmp_path):
    client = Client()
    client.ad['complete'] = False
    assert run(database, tmp_path, client=client)['status'] == 'degraded'


def test_duplicate_mac_is_a_conflict_even_when_one_observation_is_malformed(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    host = network()['hosts'][0]
    result = run(database, tmp_path, payload=network([host, {**host, 'hostname': None, 'ip': 'invalid'}]))
    assert result['status'] == 'success'
    with database() as db:
        data = db.get(SourceSnapshot, 'reconciliation').data_json
        assert any(row['code'] == 'network_identity_ambiguous' for row in data['findings'])


def test_two_interfaces_use_one_confirmed_inventory_card_without_ownership_mutation(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    other = '02:00:00:00:00:12'
    with database() as db:
        card = InventoryAsset(asset_type=InventoryAssetType.PC, custom_name='Synthetic workstation', assigned_person_name='Manual owner')
        db.add(card); db.flush()
        card_id = card.id
        for mac in (MAC, other):
            db.add(InventoryNetctlBinding(asset_id=card.id, network_key='mac:' + mac, status=LinkStatus.CONFIRMED,
                                         created_by='synthetic', confirmed_by='synthetic'))
        db.commit()
    payload = network([*network()['hosts'], {'device_key': 'mac:' + other, 'mac': other, 'ip': '192.0.2.18', 'hostname': 'desktop-example'}])
    assert run(database, tmp_path, payload=payload)['status'] == 'success'
    with database() as db:
        rows = db.get(SourceSnapshot, 'reconciliation').data_json['devices']
        assert len(rows) == 1 and rows[0]['inventory_asset_id'] == card_id
        assert len(rows[0]['network_keys']) == 2
        assert db.get(InventoryAsset, card_id).assigned_person_name == 'Manual owner'
        assert db.get(InventoryAsset, card_id).manual_revision == 1


def test_inventory_revision_race_discards_coherent_publication(database, tmp_path):
    from app.workstations.models import SourceSnapshot
    def change():
        with database() as db:
            db.get(InventoryNetworkProjectionVersion, 1).version += 1
            db.commit()
    assert run(database, tmp_path, before_publish=change)['status'] == 'degraded'
    with database() as db:
        assert db.get(SourceSnapshot, 'reconciliation') is None


def test_worker_lock_prevents_overlapping_run(database, tmp_path):
    from app.workstations.reconcile import reconciliation_lock
    lock = tmp_path / 'worker' / 'reconcile.lock'
    with reconciliation_lock(lock) as acquired:
        assert acquired
        assert run(database, tmp_path)['status'] == 'busy'


@pytest.mark.parametrize('change', ['generation', 'empty', 'total'])
def test_last_registry_page_must_match_complete_generation(change):
    from app.workstations.sources import read_controller, SourceError
    class Pages:
        def call(self, operation, parameters, **kwargs):
            offset = parameters['offset']
            return {'machines': [{'uuid': str(uuid.UUID(int=i + 1))} for i in range(offset, 100 if not offset else 101)]
                    if not offset or change != 'empty' else [],
                    'generation': ('a' if not offset or change != 'generation' else 'b') * 64,
                    'total': 101 if not offset or change != 'total' else 102,
                    'next_offset': 100 if not offset else 101}
    with pytest.raises(SourceError):
        read_controller(Pages(), NOW)
