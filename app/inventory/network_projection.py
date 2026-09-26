"""One local projection for network SSR, refresh and selection consumers."""
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, text,case,func,cast,String,LargeBinary

from ..config import get_settings
from .models import (InventoryAsset, InventoryLocation, InventoryNetctlBinding,
    InventoryExternalBinding, InventoryExternalBindingStatus as Status, InventoryEndpointState,
    InventoryEndpointSyncControl, InventoryNetworkProjectionVersion)
from .endpoint import STATE_MAX_AGE, endpoint_profile_freshness


def relation_state(rows):
    confirmed = sum(status == Status.CONFIRMED for status,evidence in rows)
    candidates = [(status,evidence) for status,evidence in rows if status == Status.CANDIDATE]
    ambiguous = confirmed>1 or any(evidence.get('ambiguous') for _,evidence in candidates)
    return 'ambiguous' if ambiguous else 'linked' if confirmed else 'candidate' if candidates else 'unlinked'


def projection_epoch(db):
    return db.scalar(select(InventoryNetworkProjectionVersion.version).where(
        InventoryNetworkProjectionVersion.id == 1)) or 0


def filter_projection(db):
    """Complete bounded local relation selection, without card or agent details."""
    from netctl.inventory_projection import validate_projection
    from fastapi import HTTPException
    epoch = projection_epoch(db)
    groups = defaultdict(list)
    count = 0
    ambiguous_value = InventoryNetctlBinding.evidence_json['ambiguous'].as_boolean()
    # Keep malformed nested evidence off the wire too. Unknown non-boolean
    # evidence is conservatively a conflict; ordinary missing/false is not.
    ambiguous_flag = case((ambiguous_value.is_(None),False),(ambiguous_value.is_(False),False),else_=True)
    statement = select(InventoryNetctlBinding.network_key,
        InventoryNetctlBinding.status,ambiguous_flag.label('ambiguous'))
    statement = statement\
        .join(InventoryAsset,InventoryAsset.id == InventoryNetctlBinding.asset_id)
    statement = statement.where(InventoryNetctlBinding.ended_at.is_(None),
        InventoryNetctlBinding.status.in_([Status.CONFIRMED,Status.CANDIDATE])).limit(100_001)
    bounded = statement.subquery()
    key_bytes = (func.length(cast(bounded.c.network_key,LargeBinary)) if db.bind.dialect.name == 'sqlite'
        else func.octet_length(cast(bounded.c.network_key,String)))
    total,max_key = db.execute(select(func.count(),func.max(key_bytes)).select_from(bounded)).one()
    if total>100000 or (max_key or 0)>255:
        raise HTTPException(422,'Проекция связей превышает бюджет выборки')
    for key,status,ambiguous in db.execute(statement.execution_options(yield_per=1000)):
        count += 1
        if count>100_000:
            raise HTTPException(422,'Состояния связей превышают бюджет выборки; сузить результат по странице нельзя')
        groups[key].append((status,{'ambiguous':ambiguous}))
    value = {'schema_version':1,'revision':epoch,'states':{key:relation_state(rows) for key,rows in groups.items()}}
    try:
        validate_projection(value)
    except ValueError as exc:
        raise HTTPException(422,'Проекция связей некорректна или превышает бюджет выборки') from exc
    if projection_epoch(db) != epoch:
        raise HTTPException(409,'Связи изменились во время подготовки выборки. Повторите запрос')
    return value


def filter_input(db, filters):
    from fastapi import HTTPException
    from netctl.inventory_projection import FILTERS
    selected = filters.get('inventory_link') or 'all'
    if selected not in FILTERS:
        raise HTTPException(422,'Некорректный фильтр связи с инвентаризацией')
    return None if selected == 'all' else filter_projection(db)


def verify_filter_result(db, projection, data):
    from fastapi import HTTPException
    if projection is None:
        return
    if data.get('inventory_projection_revision') != projection['revision']:
        raise HTTPException(502,'Источник не подтвердил применение проекции связей')
    if projection_epoch(db) != projection['revision']:
        raise HTTPException(409,'Связи изменились во время чтения снимка. Повторите запрос')


def _time(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def projection_version(db, *, now=None):
    """Include local decisions and source freshness independently of Netctl."""
    values = [projection_epoch(db)]
    values.extend([get_settings().endpoint_platform_enabled,
        int((now or datetime.now(timezone.utc)).timestamp()) // 30])
    return hashlib.sha256(json.dumps(values,default=str).encode()).hexdigest()[:24]


def migrate_network_projection(engine):
    """A cheap durable epoch changes in the same transaction as local facts."""
    if engine.dialect.name != 'sqlite':
        return
    with engine.begin() as connection:
        connection.execute(text('INSERT OR IGNORE INTO inventory_network_projection_version(id,version) VALUES(1,1)'))
        fields = {
            'inventory_assets': ('manual_revision','deleted_at'),
            'inventory_locations': ('name',),
            'inventory_netctl_bindings': ('status','evidence_json','observation_json','observed_snapshot_id','observed_at','ended_at'),
            'inventory_external_bindings': ('asset_id','source','external_id','status','ended_at'),
            'inventory_endpoint_state': ('asset_id','endpoint_device_id','online','last_seen_at','last_success_at','unavailable_since','safe_context_json'),
            'inventory_endpoint_sync_control': ('last_presence_sync_at','last_full_sync_at','last_safe_error_code'),
        }
        for table, columns in fields.items():
            for operation in ('INSERT','UPDATE','DELETE'):
                name = f'{table}_network_projection_{operation.lower()}'
                condition = 'WHEN ' + ' OR '.join(f'OLD.{column} IS NOT NEW.{column}' for column in columns) if operation == 'UPDATE' else ''
                connection.execute(text(f'DROP TRIGGER IF EXISTS {name}'))
                connection.execute(text(f'''CREATE TRIGGER {name}
                    AFTER {operation} ON {table} {condition}
                    BEGIN UPDATE inventory_network_projection_version SET version=version+1 WHERE id=1; END'''))


def attach_network_projection(db, hosts, *, now=None):
    """Batch local reads only; no collection, SDK call or per-row request."""
    now = _time(now or datetime.now(timezone.utc))
    keys = {str(host.get('device_key') or '') for host in hosts}
    relations = defaultdict(list)
    if keys:
        for binding, asset, location in db.execute(select(InventoryNetctlBinding,InventoryAsset,InventoryLocation)
            .join(InventoryAsset,InventoryAsset.id == InventoryNetctlBinding.asset_id)
            .outerjoin(InventoryLocation,InventoryLocation.id == InventoryAsset.location_id)
            .where(InventoryNetctlBinding.network_key.in_(keys),InventoryNetctlBinding.ended_at.is_(None))):
            relations[binding.network_key].append((binding,asset,location))
    asset_ids = {asset.id for rows in relations.values() for _,asset,_ in rows}
    endpoints = defaultdict(list)
    if asset_ids:
        for binding, state in db.execute(select(InventoryExternalBinding,InventoryEndpointState)
            .outerjoin(InventoryEndpointState,InventoryEndpointState.binding_id == InventoryExternalBinding.id)
            .where(InventoryExternalBinding.asset_id.in_(asset_ids),InventoryExternalBinding.source == 'endpoint_platform',
                InventoryExternalBinding.ended_at.is_(None))):
            endpoints[binding.asset_id].append((binding,state))
    enabled = get_settings().endpoint_platform_enabled
    control = db.get(InventoryEndpointSyncControl,1)
    source_error = bool(control and control.last_safe_error_code)
    for host in hosts:
        rows = relations.get(str(host.get('device_key') or ''),[])
        confirmed = [row for row in rows if row[0].status == Status.CONFIRMED]
        candidates = [row for row in rows if row[0].status == Status.CANDIDATE]
        state = relation_state([(row[0].status,row[0].evidence_json) for row in rows])
        ambiguous = state == 'ambiguous'
        inventory = {'state':state,
            'candidate_count':len(candidates),'asset':None}
        endpoint = {'state':'disabled' if not enabled else 'unknown', 'freshness':'unknown',
            'device_id':None,'device_display_name':None,'evidence_kind':None}
        if confirmed and not ambiguous:
            relation,asset,location = confirmed[0]
            inventory['asset'] = {'id':asset.id,'name':asset.custom_name or asset.model or asset.id,
                'inventory_number':asset.inventory_number,'location':location.name if location else None,
                'assigned_person_name':asset.assigned_person_name,'manual_revision':asset.manual_revision}
            inventory['binding_id'] = relation.id
            active = [(binding,state) for binding,state in endpoints[asset.id] if binding.status == Status.CONFIRMED]
            if len(active)>1:
                endpoint['state'] = 'ambiguous' if enabled else 'disabled'
            elif active:
                binding,state = active[0]
                endpoint.update(device_id=binding.external_id,evidence_kind='inventory_confirmed_binding')
                endpoint['state'] = 'confirmed' if enabled else 'disabled'
                if state is not None and state.asset_id == asset.id and state.endpoint_device_id == binding.external_id:
                    checked = _time(state.last_success_at)
                    endpoint['freshness'] = 'unavailable' if source_error or state.unavailable_since else 'unknown' if checked is None else 'fresh' if timedelta(0) <= now-checked <= STATE_MAX_AGE else 'stale'
                    baseline = endpoint_profile_freshness(state,now).get('baseline_v1')
                    if baseline and not source_error:
                        endpoint['freshness'] = baseline['status']
                    endpoint['online'] = state.online
                    endpoint['gateway_last_seen_at'] = state.last_seen_at.isoformat() if state.last_seen_at else None
            elif enabled:
                endpoint['state'] = 'candidate' if any(binding.status == Status.CANDIDATE for binding,_ in endpoints[asset.id]) else 'unbound'
        elif enabled:
            endpoint['state'] = 'ambiguous' if ambiguous else 'candidate' if candidates else 'unbound'
        host['inventory'], host['endpoint_agent'] = inventory, endpoint
    return projection_version(db,now=now)
