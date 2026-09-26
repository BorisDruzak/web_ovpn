"""Complete bounded inventory reads; never contact providers or mutate cards."""
from datetime import datetime,timezone
from enum import Enum
import json
import time

from sqlalchemy import select,or_,func,cast,String,JSON,LargeBinary

from ..xlsx_export import workbook_bytes,ExportLimit
from . import models as m
from .endpoint import _safe_fields,endpoint_profile_freshness

MAX_SOURCE_ROWS = 50_000
MAX_ASSETS = 10_000
MAX_READ_SECONDS = 20
MAX_SOURCE_BYTES = 16 * 1024 * 1024

DETAILS = (
    (m.InventoryPCDetails,('os_name','os_version','cpu_model','cpu_generation','ram_type','ram_gb','storage_type','storage_gb')),
    (m.InventoryMonitorDetails,('diagonal_inches',)),
    (m.InventoryPrinterDetails,('connection_type','page_counter')),
    (m.InventoryPhoneDetails,('extension',)),
    (m.InventoryUPSDetails,('power_va','battery_replaced_at')),
)
ASSET_FIELDS = ('id','asset_type','location_id','custom_name','manufacturer','model','serial_number',
    'inventory_number','status','assigned_person_name','login_name','description','last_verified_at',
    'manual_revision','created_at','updated_at','deleted_at','deleted_by','deletion_reason','restored_at','restored_by')
ASSET_HEADERS = ('ID','Тип','ID помещения','Название','Производитель','Модель','Серийный номер',
    'Инвентарный номер','Состояние','Ответственный','Логин','Описание','Последняя проверка UTC',
    'Ручная ревизия','Создано UTC','Изменено UTC','Удалено UTC','Кем удалено','Причина удаления','Восстановлено UTC','Кем восстановлено',
    'Помещение','Ручные MAC','Ручные IP','Ручные hostname','ОС','Версия ОС','CPU','Поколение CPU','Тип RAM','RAM ГБ',
    'Тип диска','Диск ГБ','Диагональ','Подключение принтера','Счётчик страниц','Добавочный номер','Мощность ВА','Замена батареи')


def _value(value):
    return value.value if isinstance(value,Enum) else value


def _values(row,fields):
    return [_value(getattr(row,field)) for field in fields]


def _safe_json(data,keys):
    # Explicit producer-owned fields only. No unrestricted source/context dump.
    return json.dumps({key:data[key] for key in keys if key in (data or {})},ensure_ascii=False,sort_keys=True)


def inventory_workbook(factory,*,location_id=None,deleted=False):
    """Read one database snapshot, close it, then serialize all selected facts.

    Callers enforce inventory:read/export and inventory:delete for deleted=True.
    A fresh owned Session is essential: SQLite SELECT alone does not begin a
    physical read transaction under legacy sqlite3 transaction control.
    """
    started = time.monotonic()
    exported_at = datetime.now(timezone.utc)
    with factory() as db:
        connection = db.connection()
        dialect = connection.dialect.name
        if dialect == 'sqlite':
            connection.exec_driver_sql('BEGIN')
        elif dialect == 'postgresql':
            connection.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            connection.exec_driver_sql("SET LOCAL statement_timeout = '20s'")
        else:
            raise ExportLimit('База данных не поддерживает согласованный экспорт')
        seen = 0
        source_bytes = 0
        def read(statement,limit=MAX_SOURCE_ROWS):
            nonlocal seen,source_bytes
            # SQL checks source Text/JSON size before decoding or ORM loading.
            # Checking only the serialized workbook is too late for large rows.
            bounded = statement.limit(limit+1).subquery()
            lengths = [func.coalesce(func.length(cast(cast(column,String),LargeBinary)) if dialect == 'sqlite'
                else func.octet_length(cast(column,String)),0)
                for column in bounded.c if isinstance(column.type,(String,JSON))]
            size = sum(lengths) if lengths else 0
            count,total = db.execute(select(func.count(),func.coalesce(func.sum(size),0)).select_from(bounded)
                .execution_options(inventory_history=True)).one()
            seen += count
            source_bytes += total
            if count>limit or seen>MAX_SOURCE_ROWS or source_bytes>MAX_SOURCE_BYTES or time.monotonic()-started>MAX_READ_SECONDS:
                raise ExportLimit('Выборка превышает бюджет Excel. Сузьте охват экспорта')
            result = []
            for row in db.scalars(statement.execution_options(inventory_history=True,yield_per=1).limit(limit+1)):
                if time.monotonic()-started>MAX_READ_SECONDS:
                    raise ExportLimit('Чтение превысило бюджет Excel. Сузьте охват экспорта')
                result.append(row)
            return result
        selection = select(m.InventoryAsset).where(
            m.InventoryAsset.deleted_at.is_not(None) if deleted else m.InventoryAsset.deleted_at.is_(None))
        if location_id is not None:
            selection = selection.where(m.InventoryAsset.location_id == location_id)
        assets = read(selection.order_by(m.InventoryAsset.id),MAX_ASSETS)
        ids = [row.id for row in assets]
        selected = set(ids)
        def attached(model):
            return read(select(model).where(model.asset_id.in_(ids)).order_by(model.asset_id))
        identifiers = attached(m.InventoryAssetIdentifier)
        details = {model:{row.asset_id:row for row in attached(model)} for model,_ in DETAILS}
        locations = read(select(m.InventoryLocation).where(m.InventoryLocation.id.in_(
            {row.location_id for row in assets if row.location_id})))
        names = {row.id:row.name for row in locations}
        relations = read(select(m.InventoryAssetRelation).where(or_(
            m.InventoryAssetRelation.parent_asset_id.in_(ids),m.InventoryAssetRelation.child_asset_id.in_(ids)))
            .order_by(m.InventoryAssetRelation.id))
        outside_ids = {value for row in relations for value in (row.parent_asset_id,row.child_asset_id)}-selected
        if len(outside_ids)>MAX_ASSETS:
            raise ExportLimit('Связи вне выборки превышают бюджет Excel')
        outside = read(select(m.InventoryAsset).where(m.InventoryAsset.id.in_(outside_ids),
            m.InventoryAsset.deleted_at.is_(None)))
        visible = {row.id:row for row in assets+outside}
        def scope_label(asset_id):
            if asset_id in selected:
                return 'в выборке'
            return 'вне выборки' if asset_id in visible else 'вне выборки; карточка недоступна'
        device_rows = []
        manual = {}
        for identifier in identifiers:
            if identifier.is_current and identifier.source == m.InventoryObservationSource.MANUAL:
                manual.setdefault((identifier.asset_id,identifier.identifier_type),[]).append(identifier.value)
        for asset in assets:
            row = _values(asset,ASSET_FIELDS)+[names.get(asset.location_id)]
            row += ['; '.join(sorted(manual.get((asset.id,kind),[]))) or None
                for kind in (m.InventoryIdentifierType.MAC,m.InventoryIdentifierType.IP,m.InventoryIdentifierType.HOSTNAME)]
            for model,fields in DETAILS:
                detail = details[model].get(asset.id)
                row += _values(detail,fields) if detail else [None]*len(fields)
            device_rows.append(row)
        relation_rows = [[row.id,row.parent_asset_id,scope_label(row.parent_asset_id),
            visible[row.parent_asset_id].custom_name if row.parent_asset_id in visible else None,
            row.child_asset_id,scope_label(row.child_asset_id),
            visible[row.child_asset_id].custom_name if row.child_asset_id in visible else None,
            row.relation_type,row.created_at,row.created_by,row.ended_at,row.note] for row in relations]
        network_rows = []
        for row in attached(m.InventoryNetctlBinding):
            observation = row.observation_json or {}
            network_rows.append([row.id,row.asset_id,'netctl',row.network_key,_value(row.status),
                row.created_at,row.created_by,row.confirmed_at,row.confirmed_by,row.confirmation_reason,
                row.ended_at,row.ended_by,row.end_reason,row.observed_snapshot_id,row.observed_at,
                observation.get('ip'),observation.get('hostname'),observation.get('online'),None,None,None,
                _safe_json(row.evidence_json,('material','ambiguous','manual_comparison')),
                observation.get('mac') or row.network_key.removeprefix('mac:'),None,None,None,None,None,None])
        endpoint_states = {row.binding_id:row for row in attached(m.InventoryEndpointState)}
        for row in attached(m.InventoryExternalBinding):
            state = endpoint_states.get(row.id)
            observed = _safe_fields(state.safe_context_json) if state else {}
            network_rows.append([row.id,row.asset_id,row.source,row.external_id,_value(row.status),
                row.created_at,row.created_by,row.last_verified_at,None,row.binding_method,
                row.ended_at,None,None,state.network_snapshot_id if state else None,
                state.last_checked_at if state else None,observed.get('ip'),observed.get('hostname'),state.online if state else None,
                state.last_success_at if state else None,state.unavailable_since if state else None,
                state.agent_version if state else None,
                _safe_json(row.evidence_json,('material','current','replaces_binding_id','reconnects_binding_id','reconnected_binding_id')),
                observed.get('mac'),json.dumps(endpoint_profile_freshness(state,exported_at),ensure_ascii=False) if state else None,
                state.baseline_snapshot_id if state else None,state.health_snapshot_id if state else None,
                state.inventory_snapshot_id if state else None,state.session_snapshot_id if state else None,
                state.refreshed_at if state else None])
        checks = attached(m.InventoryCheck)
        photos = attached(m.InventoryAssetPhoto)
        observations = attached(m.InventoryObservation)
        observation_rows = [_values(row,('id','asset_id','source','observed_at','binding_id','endpoint_device_id','profile','snapshot_id','semantic_hash','collected_at'))+
            [json.dumps(_safe_fields(row.data_json),ensure_ascii=False),
             _safe_json(row.data_json,('kind','action','actor','timestamp','field','old_value','new_value','endpoint_value','endpoint_observed_at','reason'))]
            for row in observations]
        versions = read(select(m.InventoryNetworkProjectionVersion),1)
        inventory_epoch = versions[0].version if versions else None
        latest_run = select(m.InventoryIdentifierSyncRun.id).order_by(
            m.InventoryIdentifierSyncRun.started_at.desc(),m.InventoryIdentifierSyncRun.id).limit(1).scalar_subquery()
        sync_runs = read(select(m.InventoryIdentifierSyncRun).where(m.InventoryIdentifierSyncRun.id == latest_run),1)
        source_snapshot = sync_runs[0].snapshot_id if sync_runs else None
        source_generated = sync_runs[0].snapshot_generated_at if sync_runs else None
        source_sync_status = sync_runs[0].status if sync_runs else None
        identifier_rows = [_values(row,('id','asset_id','identifier_type','value','source','is_current','first_seen_at','last_seen_at')) for row in identifiers]
        check_rows = [_values(row,('id','asset_id','session_id','location_id','checked_at','checked_by','result','notes')) for row in checks]
        photo_rows = [_values(row,('id','asset_id','photo_type','original_filename','mime_type','size_bytes','created_at','created_by')) for row in photos]
        # Materialized scalar rows survive rollback/close; no provider refresh.
        db.rollback()
    counts = {'assets':len(device_rows),'relations':len(relation_rows),'bindings':len(network_rows),
        'identifiers':len(identifier_rows),'checks':len(check_rows),'photos':len(photo_rows),'observations':len(observation_rows)}
    parameters = [['Сформировано UTC',exported_at],['Часовой пояс','UTC'],['Охват','помещение' if location_id else 'все карточки'],
        ['ID помещения',location_id],['Удалённые карточки',deleted],['История связей и идентификаторов',True],
        ['Согласованность','один локальный снимок БД; без запросов к источникам'],
        ['Фото','метаданные; содержимое и пути файлов не включены'],
        ['Ревизия локальной проекции',inventory_epoch],['Снимок последней попытки Netctl синхронизации',source_snapshot],
        ['Время снимка последней попытки UTC',source_generated],['Результат последней попытки синхронизации',source_sync_status],
        ['Наблюдения','последние сохранённые состояния привязок; свежесть не обновляется экспортом']]
    parameters += [[key,value] for key,value in counts.items()]
    payload = workbook_bytes([
        ('Устройства',ASSET_HEADERS,device_rows),
        ('Связи рабочего места',('ID связи','Родитель ID','Охват родителя','Название родителя','Устройство ID','Охват устройства','Название устройства','Тип связи','Создано UTC','Кем создано','Завершено UTC','Примечание'),relation_rows),
        ('Сетевые привязки',('ID связи','Карточка ID','Источник','Ключ источника','Состояние','Создано UTC','Кем создано','Подтверждено UTC','Кем подтверждено','Причина или метод','Завершено UTC','Кем завершено','Причина завершения','Снимок источника','Наблюдалось UTC','IP','Hostname','Online','Последний успех UTC','Недоступен с UTC','Версия агента','Доказательства','MAC','Свежесть профилей','Baseline снимок','Health снимок','Inventory снимок','Session снимок','Обновлено UTC'),network_rows),
        ('Идентификаторы',('ID','Карточка ID','Тип','Значение','Источник','Текущий','Первое наблюдение UTC','Последнее наблюдение UTC'),identifier_rows),
        ('Проверки',('ID','Карточка ID','Сессия ID','Помещение ID','Проверено UTC','Кем проверено','Результат','Примечание'),check_rows),
        ('Фото',('ID','Карточка ID','Тип','Исходное имя','MIME','Байт','Создано UTC','Кем создано'),photo_rows),
        ('Наблюдения',('ID','Карточка ID','Источник','Наблюдалось UTC','Привязка ID','Endpoint ID','Профиль','Снимок','Semantic hash','Собрано UTC','Безопасные поля','Решение оператора'),observation_rows),
        ('Параметры',('Параметр','Значение'),parameters),
    ])
    return payload,counts
