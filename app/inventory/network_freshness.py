"""Bounded saved Netctl facts; never probe or collect from a card read."""
from datetime import datetime, timedelta, timezone

from types import SimpleNamespace
from sqlalchemy import select, func, cast, LargeBinary, Text
from .models import InventoryIdentifierSyncRun, InventoryNetctlBinding

MAX_LINKS = 100
MAX_OBSERVATION_BYTES = 1024 * 1024
MAX_AGE = timedelta(minutes=20)
SOURCE_LABELS = {'available':'Сохранённый снимок актуален','stale':'Сохранённый источник устарел',
    'unavailable':'Синхронизация Netctl не удалась; показаны сохранённые наблюдения',
    'disabled':'Источник Netctl отключён; показаны сохранённые наблюдения',
    'unknown':'Актуальность источника Netctl неизвестна'}
PRESENCE_LABELS = {'current':'Есть в последнем сохранённом снимке','missing':'Нет в последнем сохранённом снимке; связь сохранена',
    'unknown':'Присутствие в текущем снимке неизвестно','historical':'Историческая связь; наблюдение сохранено'}
AVAILABILITY_LABELS = {'online':'Доступен по активной проверке','seen':'Наблюдался; доступность не доказана',
    'offline':'Не ответил на активную проверку','stale':'Данные доступности устарели',
    'not_monitored':'Не мониторится','connected':'VPN подключён','unknown':'Доступность неизвестна'}


def _utc(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z','+00:00')) if isinstance(value,str) else value
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError,AttributeError,TypeError):
        return None


def _fresh(value,now):
    checked=_utc(value)
    return checked is not None and timedelta(0) <= now-checked <= MAX_AGE


def card_network_projection(db,asset_id,*,enabled,now=None):
    now=_utc(now) or datetime.now(timezone.utc)
    # SAVEPOINT establishes one physical SQLite read view for all four bounded reads.
    # It never upgrades/commits the caller's writes or changes global sessions.
    connection=db.connection()
    sqlite=connection.dialect.name=='sqlite'
    if sqlite:
        connection.exec_driver_sql('SAVEPOINT card_network_projection')
    try:
        with db.no_autoflush:
            latest=db.scalar(select(InventoryIdentifierSyncRun).order_by(
                InventoryIdentifierSyncRun.started_at.desc(),InventoryIdentifierSyncRun.id.desc()).limit(1))
            success=db.scalar(select(InventoryIdentifierSyncRun).where(InventoryIdentifierSyncRun.status=='success')
                .order_by(InventoryIdentifierSyncRun.snapshot_generated_at.desc(),InventoryIdentifierSyncRun.snapshot_id.desc(),InventoryIdentifierSyncRun.id.desc()).limit(1))
            order=(InventoryNetctlBinding.ended_at.is_(None).desc(),InventoryNetctlBinding.created_at.desc(),InventoryNetctlBinding.id.desc())
            selection=select(InventoryNetctlBinding.id).where(InventoryNetctlBinding.asset_id==asset_id).order_by(*order).limit(MAX_LINKS+1)
            size=func.length(cast(InventoryNetctlBinding.observation_json,LargeBinary)) if sqlite else func.octet_length(cast(InventoryNetctlBinding.observation_json,Text))
            payload_bytes=db.scalar(select(func.coalesce(func.sum(size),0)).where(InventoryNetctlBinding.id.in_(selection)))
            details_limited=payload_bytes>MAX_OBSERVATION_BYTES
            names=('id','network_key','status','created_at','created_by','confirmed_at','confirmed_by','confirmation_reason','ended_at','ended_by','end_reason','observed_snapshot_id','observed_at')
            fields=[getattr(InventoryNetctlBinding,name) for name in names]
            if not details_limited:
                fields.append(InventoryNetctlBinding.observation_json)
            rows=db.execute(select(*fields).where(InventoryNetctlBinding.id.in_(selection)).order_by(*order)).all()
            bindings=[SimpleNamespace(**dict(row._mapping),**({'observation_json':{}} if details_limited else {})) for row in rows]
        source=source_projection(latest,success,enabled=enabled,now=now)
        views=[observation_projection(binding,source,now=now) for binding in bindings[:MAX_LINKS]]
        return {'source':source,'links':views,'truncated':len(bindings)>MAX_LINKS,'details_limited':details_limited}
    finally:
        if sqlite:
            connection.exec_driver_sql('RELEASE SAVEPOINT card_network_projection')


def source_projection(latest,success,*,enabled,now):
    source_state='unknown'
    if not enabled:
        source_state='disabled'
    elif latest is not None and latest.failure_reason=='stale netctl snapshot':
        source_state='stale'
    elif latest is not None and latest.status=='failed':
        source_state='unavailable'
    elif success is not None:
        source_state='available' if _fresh(success.snapshot_generated_at,now) else 'stale'
    source={'state':source_state,'label':SOURCE_LABELS[source_state],
        'snapshot_id':success.snapshot_id if success else None,
        'generated_at':_utc(success.snapshot_generated_at) if success else None,
        'last_attempt_at':_utc(latest.finished_at) if latest else None}
    return source


def observation_projection(binding,source,*,now):
    from .netctl_bindings import saved_observation
    observation=saved_observation(binding.observation_json) if isinstance(binding.observation_json,dict) and binding.observation_json else {}
    presence='unknown'
    if binding.ended_at is not None:
        presence='historical'
    elif source['state']=='available' and source['snapshot_id'] is not None and binding.observed_snapshot_id>0:
        if binding.observed_snapshot_id==source['snapshot_id']:
            presence='current'
        elif binding.observed_snapshot_id<source['snapshot_id']:
            presence='missing'
    availability=observation.get('availability') if isinstance(observation.get('availability'),dict) else {}
    state=availability.get('state') or (observation.get('status') if observation.get('status') in {'seen','connected'} else 'unknown')
    if state=='online' and availability.get('active_method') not in {'icmp','tcp'}:
        state='unknown'
    if state not in AVAILABILITY_LABELS:
        state='unknown'
    observed=observation.get('last_seen_at')
    freshness='unknown' if _utc(observed) is None else 'fresh' if _fresh(observed,now) else 'stale'
    return {'binding':binding,'observation':observation,'presence':presence,
        'presence_label':PRESENCE_LABELS[presence], 'freshness':freshness,
        'availability':state,'availability_label':AVAILABILITY_LABELS[state],
        'sources':observation.get('sources') or [],'observed_at':observed}
