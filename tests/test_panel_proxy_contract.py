"""Exercise the shipped service's trust boundary with pinned Uvicorn."""
import asyncio
from pathlib import Path
import shlex

import pytest
from uvicorn import Config


@pytest.mark.parametrize('peer,scheme,client',[
    ('203.0.113.8','http',('203.0.113.8',54321)),
    ('127.0.0.1','https',('198.51.100.9',0)),
])
def test_deployed_proxy_contract_ignores_untrusted_forwarded_headers(monkeypatch,peer,scheme,client):
    unit = Path('deploy/openvpn-web.service').read_text(encoding='utf-8')
    command = shlex.split(next(line.removeprefix('ExecStart=') for line in unit.splitlines() if line.startswith('ExecStart=')))
    assert '--proxy-headers' in command
    allowed = command[command.index('--forwarded-allow-ips')+1]
    assert allowed == '127.0.0.1'
    nginx = Path('deploy/nginx-openvpn-web.conf').read_text(encoding='utf-8')
    assert 'proxy_pass http://127.0.0.1:8088;' in nginx
    monkeypatch.setenv('FORWARDED_ALLOW_IPS','*')
    captured = []
    async def app(scope,receive,send):
        captured.append((scope['scheme'],scope['client']))
    config = Config(app,proxy_headers=True,forwarded_allow_ips=allowed,log_config=None)
    config.load()
    async def noop(*args):
        pass
    scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'GET',
        'scheme':'http','path':'/','raw_path':b'/','query_string':b'',
        'client':(peer,54321),'server':('127.0.0.1',8088),
        'headers':[(b'x-forwarded-proto',b'https'),(b'x-forwarded-for',b'198.51.100.9')]}
    asyncio.run(config.loaded_app(scope,noop,noop))
    assert captured == [(scheme,client)]
