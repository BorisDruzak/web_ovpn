"""Network workbook projection; callers own authorization and local enrichment reads."""
from datetime import datetime, timezone
from .xlsx_export import workbook_bytes

FILTER_KEYS = {'q','category','status','source','network','has_hostname','has_mac','seen_within','inventory_link'}


def _date(value):
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return str(value)  # Preserve malformed source evidence honestly.


def _sources(value):
    return ', '.join(str(item) for item in value) if isinstance(value,list) else str(value or '')


def network_workbook(snapshot_result, enriched_hosts, *, filters, inventory_epoch, enriched_at):
    """Export every interface; fail if enrichment lost or reordered a source row.

    No SDK/network call, database write, permissions decision or shared transaction
    is performed here. Upstream passes only locally authorized projection fields.
    """
    hosts = snapshot_result['hosts']
    snapshot = snapshot_result['snapshot']
    if not snapshot.get('snapshot_id') or len(hosts) != snapshot_result['total'] or len(hosts)>10_000:
        raise ValueError('Incomplete or absent published network snapshot')
    if len(enriched_hosts) != len(hosts) or any((a.get('ip'),a.get('device_key')) != (b.get('ip'),b.get('device_key')) for a,b in zip(hosts,enriched_hosts)):
        raise ValueError('Enrichment does not match the full network selection')
    revision = snapshot_result.get('inventory_projection_revision')
    if revision is not None and revision != inventory_epoch:
        raise ValueError('Inventory projection changed during export')
    counts = {'hosts':len(hosts),'linked':0,'unlinked':0}
    source_rows=[];relation_rows=[]
    for host,enriched in zip(hosts,enriched_hosts):
        availability=host.get('availability') or {}
        inventory=enriched.get('inventory') or {'state':'unlinked'}
        asset=inventory.get('asset') or {}
        endpoint=enriched.get('endpoint_agent') or {}
        state=inventory.get('state') or 'unlinked'
        counts[state]=counts.get(state,0)+1
        source_rows.append([host.get('device_key'),host.get('ip'),host.get('mac'),host.get('hostname'),host.get('manual_name'),host.get('display_name'),host.get('device_type'),host.get('category'),host.get('status'),_date(host.get('last_seen_at')),_sources(host.get('sources')),host.get('last_source'),availability.get('state'),availability.get('reason'),availability.get('active_method'),_sources(availability.get('passive_evidence')),_date(availability.get('checked_at')),snapshot['snapshot_id'],bool(snapshot.get('stale')),availability.get('run_status'),availability.get('cidr'),availability.get('check_origin'),_sources(host.get('tags')),_date(host.get('first_seen_at')),host.get('openvpn_connected')])
        relation_rows.append([host.get('device_key'),host.get('ip'),host.get('mac'),state,inventory.get('binding_id'),inventory.get('candidate_count'),asset.get('id'),asset.get('name'),asset.get('inventory_number'),asset.get('location'),asset.get('manual_revision'),endpoint.get('state') or 'unknown',endpoint.get('freshness') or 'unknown',endpoint.get('device_id'),endpoint.get('online'),_date(endpoint.get('gateway_last_seen_at')),endpoint.get('evidence_kind')])
    parameters=[['Версия снимка Netctl',snapshot['snapshot_id']],['Время публикации Netctl UTC',_date(snapshot.get('generated_at'))],['Снимок устарел',bool(snapshot.get('stale'))],['Строк в опубликованном снимке',snapshot.get('total_hosts')],['Строк в выборке',len(hosts)],['Ревизия фильтра связей',revision],['Локальная ревизия инвентаризации',inventory_epoch],['Время обогащения UTC',_date(enriched_at)],['Согласованность','Один опубликованный снимок Netctl и отдельное согласованное локальное чтение инвентаризации; общей распределённой транзакции нет']]
    parameters.extend([f'Фильтр: {key}',filters[key]] for key in sorted(FILTER_KEYS) if key in filters)
    parameters.extend([f'Связность: {key}',value] for key,value in counts.items() if key!='hosts')
    sheets=[('Снимок',['Устойчивый ключ','IP','MAC','Имя источника','Ручное имя сети','Отображаемое имя','Тип','Категория','Статус','Последнее наблюдение UTC','Источники','Последний источник','Доступность','Причина','Активная проверка','Пассивное наблюдение','Проверено UTC','Версия снимка','Снимок устарел','Результат проверки','Сегмент проверки','Происхождение проверки','Теги','Первое наблюдение UTC','VPN подключён'],source_rows),('Связи с инвентаризацией',['Устойчивый ключ','IP','MAC','Состояние связи','ID связи','Кандидатов','Inventory ID','Карточка','Инвентарный номер','Локация','Ручная ревизия','Агент: состояние','Агент: актуальность','Endpoint ID','Агент онлайн','Агент наблюдался UTC','Основание агента'],relation_rows),('Параметры',['Параметр','Значение'],parameters)]
    return workbook_bytes(sheets),counts
