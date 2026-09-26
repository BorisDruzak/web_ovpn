"""Owned export orchestration: source snapshot plus a separate local read view."""
import copy
import json
from datetime import datetime,timezone

from fastapi import HTTPException
from sqlalchemy import select,func,cast,String,JSON,LargeBinary

from .db import get_sessionmaker
from .netctl_client import run_netctl,NetctlError
from .network_xlsx import network_workbook
from .xlsx_export import ExportLimit
from .inventory import models as m
from .inventory.network_projection import filter_input,verify_filter_result,projection_epoch,attach_network_projection


def _begin(db):
    connection = db.connection()
    if connection.dialect.name == 'sqlite':
        connection.exec_driver_sql('BEGIN')
    elif connection.dialect.name == 'postgresql':
        connection.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        connection.exec_driver_sql("SET LOCAL statement_timeout = '20s'")
    else:
        raise ExportLimit('База данных не поддерживает согласованный экспорт')


def _projection_budget(db,keys):
    relation_assets = select(m.InventoryNetctlBinding.asset_id).join(m.InventoryAsset,
        m.InventoryAsset.id == m.InventoryNetctlBinding.asset_id).where(m.InventoryNetctlBinding.network_key.in_(keys),
        m.InventoryNetctlBinding.ended_at.is_(None),m.InventoryAsset.deleted_at.is_(None))
    locations = select(m.InventoryAsset.location_id).where(m.InventoryAsset.id.in_(relation_assets))
    statements = [select(m.InventoryNetctlBinding).where(m.InventoryNetctlBinding.network_key.in_(keys),m.InventoryNetctlBinding.ended_at.is_(None)),
        select(m.InventoryAsset).where(m.InventoryAsset.id.in_(relation_assets)),
        select(m.InventoryLocation).where(m.InventoryLocation.id.in_(locations)),
        select(m.InventoryExternalBinding).where(m.InventoryExternalBinding.asset_id.in_(relation_assets),m.InventoryExternalBinding.ended_at.is_(None)),
        select(m.InventoryEndpointState).where(m.InventoryEndpointState.asset_id.in_(relation_assets))]
    size = rows = 0
    sqlite = db.bind.dialect.name == 'sqlite'
    for statement in statements:
        query = statement.limit(100001).subquery()
        lengths = [func.coalesce(func.length(cast(cast(c,String),LargeBinary)) if sqlite else func.octet_length(cast(c,String)),0)
            for c in query.c if isinstance(c.type,(String,JSON))]
        count,total = db.execute(select(func.count(),func.coalesce(func.sum(sum(lengths)),0)).select_from(query)).one()
        rows += count
        size += total
        if rows>100000 or size>16*1024*1024:
            raise ExportLimit('Связанные данные превышают бюджет Excel. Сузьте фильтры')


def network_export_workbook(filters):
    factory = get_sessionmaker()
    with factory() as db:
        _begin(db)
        projection = filter_input(db,filters)
        epoch = projection_epoch(db)
        db.rollback()
    from .api import host_snapshot_args
    args = host_snapshot_args(filters,1,100)
    # Keep the exact supported list-filter encoding; pagination is not exported.
    args = ['hosts','export']+args[2:-4]
    options = {'input_payload':json.dumps(projection,separators=(',',':'))} if projection is not None else {}
    try:
        source = run_netctl(args,timeout=20,**options)
    except NetctlError as exc:
        code = None
        try:
            code = json.loads(exc.stdout or '{}').get('message')
        except (TypeError,ValueError):
            pass
        messages = {'host_snapshot_absent':'Снимок ещё не опубликован. Повторите позже',
            'host_export_row_budget':'Выборка превышает 10000 устройств. Сузьте фильтры',
            'host_export_byte_budget':'Данные снимка превышают бюджет Excel. Сузьте фильтры'}
        raise HTTPException(422 if code in messages else 502,detail=messages.get(code,'Не удалось прочитать полный снимок сети')) from None
    enriched_at = datetime.now(timezone.utc)
    hosts = copy.deepcopy(source.get('hosts',[]))
    with factory() as db:
        _begin(db)
        if projection_epoch(db) != epoch:
            raise HTTPException(409,detail='Связи изменились во время экспорта. Повторите запрос')
        verify_filter_result(db,projection,source)
        _projection_budget(db,{str(host.get('device_key') or '') for host in hosts})
        attach_network_projection(db,hosts,now=enriched_at)
        db.rollback()
    # A fresh read detects changes committed while enrichment was being read.
    with factory() as db:
        if projection_epoch(db) != epoch:
            raise HTTPException(409,detail='Связи изменились во время экспорта. Повторите запрос')
    try:
        return network_workbook(source,hosts,filters=filters,inventory_epoch=epoch,enriched_at=enriched_at)
    except ValueError:
        raise HTTPException(502,detail='Источник вернул неполную или несогласованную выборку') from None
