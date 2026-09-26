"""Whole published-snapshot filtering through the real read-only CLI boundary."""
import json
import subprocess
import sys

from tests.test_inventory_api import _client


def test_ssr_and_refresh_filter_all_pages_via_stdin_projection(tmp_path,monkeypatch):
    client,headers = _client(tmp_path,monkeypatch)
    from netctl.db import connect
    from netctl.host_snapshot import refresh_host_snapshot
    source_path = tmp_path/'filtered-source.sqlite'
    source = connect(f'sqlite:///{source_path.as_posix()}')
    for number in range(1,231):
        source.execute("INSERT INTO network_hosts(ip,device_key,category,status,last_seen_at,tags_json) VALUES (?,?,'unknown','seen','2026-09-26T12:00:00Z','{}')",
            (f'192.0.2.{number}',f'mac:02:00:00:00:00:{number:02X}'))
    source.commit()
    refresh_host_snapshot(source,now='2026-09-26T12:00:00Z')
    source.close()
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset,InventoryNetctlBinding,InventoryExternalBindingStatus as Status
    with get_sessionmaker()() as db:
        card = InventoryAsset(asset_type='PC',custom_name='Synthetic multi-interface physical card')
        db.add(card)
        db.flush()
        for number in range(101,231):
            db.add(InventoryNetctlBinding(asset_id=card.id,network_key=f'mac:02:00:00:00:00:{number:02X}',
                status=Status.CONFIRMED if number<=210 else Status.CANDIDATE,
                evidence_json={'ambiguous':number>220},created_by='synthetic'))
        db.commit()
        card_id = card.id
    calls = []
    def cli(args,**kwargs):
        calls.append((args,kwargs.get('input_payload')))
        result = subprocess.run([sys.executable,'-m','netctl.cli','--json','--db',f'sqlite:///{source_path.as_posix()}',*args],
            input=kwargs.get('input_payload'),capture_output=True,text=True,timeout=10)
        assert result.returncode == 0,result.stderr
        return json.loads(result.stdout)
    monkeypatch.setattr('app.api.run_netctl',cli)
    monkeypatch.setattr('app.main.run_netctl',cli)
    url = '/api/v1/network/hosts?status=all&seen_within=all&inventory_link=linked&page=2&limit=100'
    response = client.get(url)
    assert response.status_code == 200,response.text
    data = response.json()['data']
    assert data['pagination'] == {'page':2,'limit':100,'total':110,'pages':2}
    assert [row['ip'] for row in data['hosts']] == [f'192.0.2.{number}' for number in range(201,211)]
    assert all(row['inventory']['state']=='linked' for row in data['hosts'])
    page = client.get(url.replace('/api/v1',''))
    assert page.status_code == 200
    assert 'value="linked" selected' in page.text and '192.0.2.201' in page.text
    assert '192.0.2.101</td>' not in page.text
    for selected,count in [('unlinked',100),('candidates',10),('conflicts',10)]:
        result = client.get('/api/v1/network/hosts',params={'status':'all','seen_within':'all','inventory_link':selected,'page':99,'limit':25})
        assert result.status_code == 200,result.text
        assert result.json()['data']['pagination']['total'] == count
    assert all('mac:' not in ' '.join(args) for args,_ in calls)
    assert all('Synthetic multi-interface' not in payload for _,payload in calls)
    before = len(calls)
    assert client.get('/api/v1/network/hosts?inventory_link=invalid').status_code == 422
    assert client.get('/network/hosts?inventory_link=invalid').status_code == 422
    assert len(calls) == before
    monkeypatch.setattr('app.api.run_netctl',lambda *args,**kwargs:{'hosts':[]})
    assert client.get(url).status_code == 502  # Old CLI cannot silently ignore selection.
    def concurrent_change(args,**kwargs):
        result = cli(args,**kwargs)
        with get_sessionmaker()() as db:
            db.get(InventoryAsset,card_id).custom_name = 'Synthetic concurrent change'
            db.commit()
        return result
    monkeypatch.setattr('app.api.run_netctl',concurrent_change)
    assert client.get(url).status_code == 409  # Count and projected card cannot mix revisions.
