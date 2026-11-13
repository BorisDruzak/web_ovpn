from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError

from app.infrastructure_collect import build_graph
from app.infrastructure_map import _map_statuses, _public_node, _public_service_check


def test_pbs_storage_checks_keep_node_failures_distinct_from_missing_evidence():
    from app.infrastructure_backup import read_pbs_storage_checks

    def get(path):
        node = path.split('/')[1]
        assert path == f'nodes/{node}/storage/pbs/status'
        if node == 'pve1':
            return {'type': 'pbs', 'enabled': 1, 'active': 1, 'total': 500, 'avail': 150, 'used': 350}
        if node == 'pve2':
            return {'type': 'pbs', 'enabled': 1, 'active': 0}
        if node == 'pve3':
            raise HTTPError(path, 403, 'Forbidden', {}, None)
        return {'type': 'lvm', 'enabled': 1, 'active': 1}

    now = datetime.now(timezone.utc)
    checks = read_pbs_storage_checks(get, ['pve1', 'pve2', 'pve3', 'pve4'], 'pbs')
    checked = {node: _public_service_check(check, now + timedelta(seconds=1)) for node, check in checks.items()}
    assert checked['pve1']['state'] == 'reachable'
    assert checked['pve1']['pbsStorage'] == {'id': 'pbs', 'node': 'pve1', 'totalBytes': 500,
                                            'usedBytes': 350, 'availableBytes': 150}
    assert checked['pve2']['state'] == 'unreachable'
    assert checked['pve2']['reason'] == 'pbs_storage_inactive'
    assert checked['pve3']['state'] == 'unknown'
    assert checked['pve3']['reason'] == 'pbs_storage_permission'
    assert checked['pve4']['state'] == 'unknown'
    assert _public_service_check(checks['pve1'], now + timedelta(hours=1))['state'] == 'unknown'

    now += timedelta(seconds=1)
    graph = build_graph({'devices': [{'id': 'pbs', 'name': 'PBS', 'kind': 'backup_server'}]}, {}, {},
                        {'cluster': [], 'nodes': [{'node': node, 'status': 'online'} for node in checks],
                         'guests': [], 'at': now.isoformat(), 'pbsStorageChecks': checks},
                        {'proxmox_backup_monitor': {'asset': 'pbs', 'storage': 'pbs', 'max_age_hours': {'102': 24}}}, now)
    nodes = {node['id']: _public_node(node, now) for node in graph['nodes']}
    _map_statuses(nodes, graph['links'])
    assert [check['pbsStorage']['node'] for check in nodes['pbs']['serviceChecks']] == list(checks)
    assert nodes['pve2']['serviceChecks'] == [checked['pve2']]
    assert nodes['pve2']['mapStatus'] == 'warn'
    assert nodes['pve3']['mapStatus'] == 'unknown'
