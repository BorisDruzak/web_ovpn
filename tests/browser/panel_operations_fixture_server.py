"""T01 loopback fixture; every external CLI function is replaced or forbidden."""
import argparse
import os
import threading
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8879)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    os.environ.update(DATABASE_URL=f"sqlite:///{(args.output.resolve() / 'synthetic.sqlite').as_posix()}",
        APP_SECRET_KEY='synthetic-operation-browser', ADMIN_USERNAME='synthetic',
        ADMIN_PASSWORD='synthetic-operation-browser', ENDPOINT_PLATFORM_ENABLED='false',
        OUT_DIR=str(args.output.resolve()), SHARE_OUT_DIR=str(args.output.resolve()),
        ARCHIVE_DIR=str(args.output.resolve()))
    from app.db import reset_engine_cache
    reset_engine_cache()
    import app.main as panel
    import app.api
    import app.auto_sync
    import app.vpnctl_client
    import app.netctl_client
    from app.panel_operations import phase
    entered = threading.Event()
    release = threading.Event()
    calls = []
    def forbidden(*args, **kwargs):
        raise RuntimeError('External CLI forbidden in T01 browser fixture')
    def vpn(args, *positional, **kwargs):
        if args == ['sync']:
            calls.append('sync')
            entered.set()
            if not release.wait(120):
                phase('vpnctl:sync','unknown')
                return {'status':'error'}
            phase('vpnctl:sync','succeeded')
            return {'status':'ok','imported_or_updated':1}
        if args == ['profiles']:
            return {'profiles':[]}
        if args == ['list']:
            return {'clients':[]}
        if args == ['web-summary']:
            return {'status':'ok','data':{}}
        return forbidden()
    app.vpnctl_client.run_vpnctl = forbidden
    app.netctl_client.run_netctl = forbidden
    panel.run_vpnctl = vpn
    panel.run_netctl = forbidden
    app.api.run_vpnctl = vpn
    app.api.run_netctl = forbidden
    app.auto_sync.run_vpnctl = vpn
    @panel.app.get('/__fixture/state')
    def state():
        return {'entered':entered.is_set(),'calls':len(calls)}
    @panel.app.post('/__fixture/release')
    def finish():
        release.set()
        return {'released':True}
    import uvicorn
    uvicorn.run(panel.app,host='127.0.0.1',port=args.port)


if __name__ == '__main__':
    main()
