"""Navigation context accepts local list URLs, never arbitrary redirects."""
import pytest
from urllib.parse import parse_qs, urlsplit

@pytest.mark.parametrize('candidate', [
    'https://evil.invalid/network/hosts', '//evil.invalid/network/hosts',
    '/\\evil.invalid/network/hosts', '/%2f%2fevil.invalid', '/network/hosts%0d%0aLocation:evil',
    '/logout', '/network/hosts/192.0.2.1', '/inventory/assets/new',
    '/network/hosts#fragment', ' /network/hosts', '/network/hosts?x=1\x00',
])
def test_unsafe_return_is_rejected(candidate):
    from app.navigation import safe_return_url
    assert safe_return_url(candidate, '/inventory') == '/inventory'


def test_return_preserves_only_supported_list_context():
    from app.navigation import safe_return_url
    result = safe_return_url('/network/hosts?q=printer&page=3&limit=25&inventory_link=candidates&csrf_token=secret&description=card&return_url=https://evil.invalid')
    assert urlsplit(result).path == '/network/hosts'
    assert parse_qs(urlsplit(result).query) == {'q':['printer'], 'page':['3'], 'limit':['25'], 'inventory_link':['candidates']}


def test_location_return_is_allowlisted():
    from app.navigation import safe_return_url
    path='/inventory/locations/11111111-1111-4111-8111-111111111111'
    assert safe_return_url(path) == path
    assert safe_return_url(path+'/delete') == '/network/hosts'

def test_list_card_back_preserves_page_and_active_navigation(tmp_path, monkeypatch):
    from tests.test_inventory_api import _client
    client, headers = _client(tmp_path, monkeypatch)
    import app.main
    def synthetic(request,args):
        if args[:2] == ['context-view','asset']:
            return {'context':{'asset':{'asset_key':'mac:02:00:00:00:00:24','manual_name':'Synthetic'}}},None
        return {'hosts':[{'ip':'192.0.2.24','mac':'02:00:00:00:00:24','device_key':'mac:02:00:00:00:00:24','status':'seen','category':'unknown'}],
            'snapshot':{'snapshot_id':1,'generated_at':'2026-09-26T10:00:00Z','total_hosts':80},
            'pagination':{'page':3,'limit':25,'total':80,'pages':4}},None
    monkeypatch.setattr(app.main,'net_cli_call',synthetic)
    page=client.get('/network/hosts?category=unknown&status=all&seen_within=all&page=3&limit=25')
    assert page.status_code == 200
    for group in ['VPN','Сеть и диагностика','Инвентаризация','Обслуживание']:
        assert f'<summary>{group}</summary>' in page.text
    assert 'href="/network/hosts" class="active" aria-current="page"' in page.text
    assert 'href="/network/hosts?inventory_link=all"' in page.text
    assert client.get('/network/hosts?inventory_link=all').status_code == 200
    import re, html
    card_url=html.unescape(re.search(r'class="button small secondary" href="([^"]+)"',page.text).group(1))
    detail=client.get(card_url)
    backlink=html.unescape(re.search(r'href="([^"]+)">Назад к списку',detail.text).group(1))
    assert parse_qs(urlsplit(backlink).query)['page']==['3']
    assert parse_qs(urlsplit(backlink).query)['category']==['unknown']
    assert 'href="/network/hosts" class="active" aria-current="page"' in detail.text
    malicious=client.get('/network/assets/mac:02:00:00:00:00:24?return_url=https://evil.invalid')
    assert 'href="/network/hosts">Назад к списку' in malicious.text
    assert 'href="https://evil.invalid"' not in malicious.text


def test_inventory_draft_retains_safe_list_context_after_save(tmp_path,monkeypatch):
    from tests.test_inventory_api import _client
    from tests.test_inventory_web import _draft_id
    client,headers=_client(tmp_path,monkeypatch)
    asset=client.post('/api/v1/inventory/assets',headers=headers,json={'asset_type':'PC'}).json()['data']
    context='/network/hosts?status=all&page=3&limit=25'
    from urllib.parse import urlencode
    path=f"/inventory/assets/{asset['id']}"
    page=client.get(path+'?'+urlencode({'return_url':context}))
    assert 'return_url=' in str(page.url)
    assert 'page%3D3' in str(page.url)
    assert 'href="/network/hosts?status=all&amp;page=3&amp;limit=25">Назад к списку' in page.text
    response=client.post(path,data={'csrf_token':headers['X-CSRF-Token'],'draft_id':_draft_id(page.text),'expected_revision':asset['manual_revision'],'custom_name':'Saved'},follow_redirects=False)
    assert response.status_code==303
    assert response.headers['location']==context


def test_non_admin_navigation_keeps_admin_actions_hidden(tmp_path,monkeypatch):
    from tests.test_inventory_api import _client
    from app.db import get_sessionmaker
    from app.models import WebUser
    from sqlalchemy import select
    client,_=_client(tmp_path,monkeypatch)
    with get_sessionmaker()() as db:
        db.scalar(select(WebUser)).is_admin=False
        db.commit()
    page=client.get('/inventory')
    assert 'href="/admin/users"' not in page.text
    assert 'href="/inventory/deleted"' not in page.text
    assert client.get('/inventory/deleted').status_code == 403
    with get_sessionmaker()() as db:
        db.scalar(select(WebUser)).permissions_json='["inventory:delete"]'
        db.commit()
    assert 'href="/inventory/deleted"' in client.get('/inventory').text
    assert client.get('/inventory/deleted').status_code == 200
    assert page.status_code==200
    assert client.get('/admin/users').status_code==403


def test_saved_settings_strip_card_values_and_unsupported_fields():
    import json, subprocess, shutil
    node=shutil.which('node')
    if not node: pytest.skip('Node unavailable')
    result=subprocess.run([node,'-e',"const {sanitizeState}=require('./app/static/network-hosts-views.js'); console.log(JSON.stringify(sanitizeState({mode:'diagnostic',token:'secret',views:[{name:'Work',filters:{q:'private search',csrf_token:'secret',description:'card',page:'42',limit:'25',status:'seen',inventory_link:'candidates',has_mac:'yes'}}]})));"],capture_output=True,text=True,check=True)
    state=json.loads(result.stdout)
    assert state=={'mode':'diagnostic','views':[{'name':'Work','filters':{'status':'seen','has_mac':'yes','limit':'25','inventory_link':'candidates'},'mode':'operational'}]}

@pytest.mark.parametrize('value',['all','linked','unlinked','candidates','conflicts'])
def test_saved_view_supports_reserved_inventory_link_values(value):
    import json, subprocess, shutil
    node=shutil.which('node')
    if not node: pytest.skip('Node unavailable')
    script="const {sanitizeFilters}=require('./app/static/network-hosts-views.js'); console.log(JSON.stringify(sanitizeFilters({inventory_link:process.argv[1]})));"
    result=subprocess.run([node,'-e',script,value],capture_output=True,text=True,check=True)
    assert json.loads(result.stdout)=={'inventory_link':value}


def test_availability_labels_preserve_unknown_and_passive_meanings():
    from app.main import availability_status_label, availability_reason_label
    assert availability_status_label({'availability':{'state':'seen','passive_evidence':['mikrotik_arp']}})=='Наблюдался · ARP'
    assert availability_status_label({'availability':{'state':'online'}})=='Неизвестно'
    assert availability_status_label({'availability':{'state':'unknown'}})=='Неизвестно'
    assert availability_status_label({'availability':{'state':'stale'}})=='данные устарели'
    assert availability_reason_label(None)==''
