"""Synthetic acceptance for full-card creation with one explicit Netctl relation."""
from sqlalchemy import select
import pytest

from tests.test_inventory_web import _client, _csrf, _draft_id

KEY = 'mac:02:00:00:00:00:71'


def setup_form(tmp_path, monkeypatch, asset_type='PC'):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post('/inventory/locations', data={'csrf_token':csrf,'name':'Synthetic network creation'})
    monkeypatch.setattr('app.inventory.network_links.read_runtime_identity', lambda key:
        (KEY, {'device_key':KEY,'mac':KEY[4:],'ip':'192.0.2.71','hostname':'synthetic-create',
            'last_seen_at':'2026-09-26T12:00:00Z','status':'unknown'}))
    page = client.get('/inventory/assets/new', params={'asset_type':asset_type,'network_key':KEY})
    return client, page


@pytest.mark.parametrize('asset_type,field', [('PC','cpu_model'),('MONITOR','diagonal_inches'),
    ('PRINTER','page_counter'),('PHONE','extension'),('UPS','power_va'),('OTHER','description')])
def test_network_creation_uses_full_owned_form_and_atomic_binding(tmp_path, monkeypatch,asset_type,field):
    client, page = setup_form(tmp_path, monkeypatch,asset_type)
    assert page.status_code == 200
    assert f'name="{field}"' in page.text
    assert 'name="network_confirmation"' in page.text
    draft = _draft_id(page.text)
    response = client.post('/inventory/assets', data={'csrf_token':_csrf(page.text),
        'draft_id':draft,'asset_type':asset_type,'custom_name':'Synthetic new physical PC',
        'ram_gb':'16','mac_address':KEY[4:],'network_confirmation':'1',
        'network_reason':'Compared physical label and existing inventory candidates'}, follow_redirects=False)
    assert response.status_code == 303
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding, InventoryFormDraft
    with get_sessionmaker()() as db:
        asset = db.scalar(select(InventoryAsset))
        binding = db.scalar(select(InventoryNetctlBinding))
        assert asset.custom_name == 'Synthetic new physical PC'
        assert asset.asset_type.value == asset_type
        assert binding.asset_id == asset.id and binding.network_key == KEY
        assert binding.status.value == 'confirmed'
        assert db.get(InventoryFormDraft,draft) is None


@pytest.mark.parametrize('failure', ['confirmation','offline','audit'])
def test_network_creation_failure_rolls_back_all_and_retains_owned_input(tmp_path,monkeypatch,failure):
    client, page = setup_form(tmp_path,monkeypatch)
    draft = _draft_id(page.text)
    if failure == 'offline':
        from app.inventory.netctl_bindings import NetctlBindingConflict
        def unavailable(key):
            raise NetctlBindingConflict('Synthetic source unavailable')
        monkeypatch.setattr('app.inventory.network_links.read_runtime_identity',unavailable)
    if failure == 'audit':
        original = __import__('app.inventory.web',fromlist=['write_audit']).write_audit
        def broken_audit(*args,**kwargs):
            if args[3] == 'inventory-netctl-confirm':
                raise RuntimeError('Synthetic audit failure')
            return original(*args,**kwargs)
        monkeypatch.setattr('app.inventory.web.write_audit',broken_audit)
    response = client.post('/inventory/assets', data={'csrf_token':_csrf(page.text),
        'draft_id':draft,'asset_type':'PC','custom_name':'Retained synthetic input','ram_gb':'16',
        'network_confirmation':'' if failure == 'confirmation' else '1',
        'network_reason':'Retained comparison reason'},follow_redirects=False)
    assert response.status_code == 303
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryNetctlBinding, InventoryFormDraft
    with get_sessionmaker()() as db:
        assert db.scalar(select(InventoryAsset)) is None
        assert db.scalar(select(InventoryNetctlBinding)) is None
        saved = db.get(InventoryFormDraft,draft)
        assert saved.fields_json['custom_name'] == 'Retained synthetic input'
        assert saved.fields_json['network_reason'] == 'Retained comparison reason'
        assert saved.flow_json['network_creation']['network_key'] == KEY
    restored = client.get(response.headers['location'])
    assert 'Retained synthetic input' in restored.text
    assert 'name="network_confirmation"' in restored.text


def test_network_context_cannot_be_replaced_by_lookup_or_autosave(tmp_path,monkeypatch):
    client,page = setup_form(tmp_path,monkeypatch)
    draft = _draft_id(page.text)
    for action in ('lookup','manual'):
        response = client.post('/inventory/assets/new/'+action, data={'csrf_token':_csrf(page.text),
            'draft_id':draft,'asset_type':'PC','identifier':'192.0.2.99'},follow_redirects=False)
        assert response.status_code == 409
    response = client.post('/inventory/drafts/'+draft,headers={'X-CSRF-Token':_csrf(page.text)},
        json={'draft_revision':1,'fields':{'network_key':'mac:02:00:00:00:00:99'}})
    assert response.status_code == 400
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryFormDraft
    with get_sessionmaker()() as db:
        assert db.get(InventoryFormDraft,draft).flow_json['network_creation']['network_key'] == KEY


def test_source_revalidation_does_not_hold_database_writer_lock(tmp_path,monkeypatch):
    client,page = setup_form(tmp_path,monkeypatch)
    from sqlalchemy import text
    from app.db import get_sessionmaker
    original = __import__('app.inventory.network_links',fromlist=['read_runtime_identity']).read_runtime_identity
    def inspect_with_independent_writer(key):
        with get_sessionmaker()() as other:
            other.execute(text('PRAGMA busy_timeout=1'))
            other.execute(text('UPDATE inventory_locations SET name=name'))
            other.commit()
        return original(key)
    monkeypatch.setattr('app.inventory.network_links.read_runtime_identity',inspect_with_independent_writer)
    response = client.post('/inventory/assets',data={'csrf_token':_csrf(page.text),'draft_id':_draft_id(page.text),
        'asset_type':'PC','custom_name':'Synthetic unlocked source','network_confirmation':'1',
        'network_reason':'Independent source comparison'},follow_redirects=False)
    assert response.status_code == 303
    from app.inventory.models import InventoryAsset
    with get_sessionmaker()() as db:
        assert db.scalar(select(InventoryAsset)).custom_name == 'Synthetic unlocked source'
