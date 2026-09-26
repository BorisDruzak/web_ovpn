from sqlalchemy import event

from tests.test_inventory_api import _client


def test_enriched_page_uses_constant_queries_as_page_size_grows(tmp_path,monkeypatch):
    _client(tmp_path,monkeypatch)
    from app.db import get_engine,get_sessionmaker
    from app.inventory.models import InventoryAsset,InventoryAssetType,InventoryNetctlBinding,InventoryExternalBindingStatus
    from app.inventory.network_projection import attach_network_projection
    hosts = [{'ip':f'10.0.{n//256}.{n%256}','device_key':f'mac:02:00:00:00:{n//256:02X}:{n%256:02X}'} for n in range(250)]
    with get_sessionmaker()() as db:
        card = InventoryAsset(asset_type=InventoryAssetType.PC,custom_name='Synthetic multi-interface card')
        db.add(card)
        db.flush()
        db.add_all([InventoryNetctlBinding(asset_id=card.id,network_key=host['device_key'],
            status=InventoryExternalBindingStatus.CONFIRMED,created_by='synthetic') for host in hosts])
        db.commit()
    counts = []
    for size in (25,250):
        statements = []
        def observe(conn,cursor,statement,parameters,context,executemany):
            statements.append(statement)
        event.listen(get_engine(),'before_cursor_execute',observe)
        try:
            with get_sessionmaker()() as db:
                selected = [dict(host) for host in hosts[:size]]
                attach_network_projection(db,selected)
                assert len(selected) == size and all(host['inventory']['state']=='linked' for host in selected)
        finally:
            event.remove(get_engine(),'before_cursor_execute',observe)
        counts.append(len(statements))
    assert counts[0] == counts[1] and counts[1]<=5,counts
