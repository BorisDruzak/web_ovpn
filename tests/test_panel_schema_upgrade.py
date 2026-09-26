"""Upgrade a synthetic pre-spec schema with populated canonical relationships."""
from sqlalchemy import select,inspect,text

from tests.test_inventory_lifecycle import workplace


def test_upgrade_twice_preserves_accounts_endpoint_and_peripherals_then_lifecycle(tmp_path,monkeypatch):
    _,_,data = workplace(tmp_path,monkeypatch)
    from app.db import get_engine,get_sessionmaker,init_db
    from app.models import WebUser
    from app.inventory.models import (InventoryAsset,InventoryExternalBinding,
        InventoryExternalBindingStatus,InventoryAssetRelation)
    from app.inventory.lifecycle import soft_delete,restore,historical_asset
    pc_id = data['pc']['id']
    with get_sessionmaker()() as db:
        account = db.scalar(select(WebUser))
        previous = (account.id,account.password_hash,account.is_admin,account.is_network_admin)
        children = set(db.scalars(select(InventoryAssetRelation.child_asset_id).where(InventoryAssetRelation.parent_asset_id==pc_id)))
        assert len(children) == 3
        binding = InventoryExternalBinding(asset_id=pc_id,source='endpoint_platform',external_id='synthetic-upgrade-device',
            status=InventoryExternalBindingStatus.CONFIRMED,binding_method='manual',confidence=100,created_by='synthetic')
        db.add(binding)
        db.commit()
        binding_id = binding.id
    engine = get_engine()
    with engine.begin() as connection:
        # Reconstruct the additive boundaries, keeping all pre-existing facts.
        for name in list(connection.scalars(text("SELECT name FROM sqlite_master WHERE type='trigger'"))):
            connection.exec_driver_sql('DROP TRIGGER "'+name.replace('"','""')+'"')
        connection.exec_driver_sql('DROP INDEX ix_inventory_assets_deleted_at')
        for column in ('manual_revision','deleted_at','deleted_by','deletion_reason','restored_at','restored_by'):
            connection.exec_driver_sql(f'ALTER TABLE inventory_assets DROP COLUMN {column}')
        connection.exec_driver_sql('ALTER TABLE web_users DROP COLUMN permissions_json')
        for table in ('inventory_form_drafts','inventory_netctl_bindings','inventory_network_projection_version','panel_operations'):
            connection.exec_driver_sql(f'DROP TABLE {table}')
    init_db()
    init_db()
    schema = inspect(engine)
    assert {'inventory_form_drafts','inventory_netctl_bindings','panel_operations'} <= set(schema.get_table_names())
    assert 'ix_inventory_assets_deleted_at' in {row['name'] for row in schema.get_indexes('inventory_assets')}
    assert any(row.get('unique') for row in schema.get_indexes('inventory_netctl_bindings'))
    with get_sessionmaker()() as db:
        account = db.get(WebUser,previous[0])
        assert (account.id,account.password_hash,account.is_admin,account.is_network_admin) == previous
        assert account.permissions_json == '[]'
        pc = db.get(InventoryAsset,pc_id)
        assert pc.custom_name == 'Synthetic PC' and pc.manual_revision == 1
        assert db.get(InventoryExternalBinding,binding_id).ended_at is None
        assert set(db.scalars(select(InventoryAssetRelation.child_asset_id).where(InventoryAssetRelation.parent_asset_id==pc_id))) == children
        soft_delete(db,pc_id,expected_revision=pc.manual_revision,actor='synthetic',reason='Upgrade lifecycle acceptance')
        db.commit()
    with get_sessionmaker()() as db:
        deleted = historical_asset(db,pc_id)
        assert db.get(InventoryExternalBinding,binding_id).ended_at is not None
        assert all(db.get(InventoryAsset,child_id).deleted_at is None for child_id in children)
        restore(db,pc_id,expected_revision=deleted.manual_revision,actor='synthetic')
        db.commit()
    with get_sessionmaker()() as db:
        pc = db.get(InventoryAsset,pc_id)
        assert pc.custom_name == 'Synthetic PC' and pc.deleted_at is None
        assert db.get(InventoryExternalBinding,binding_id).ended_at is not None
        assert not list(db.scalars(select(InventoryAssetRelation).where(
            InventoryAssetRelation.parent_asset_id==pc_id,InventoryAssetRelation.ended_at.is_(None))))
