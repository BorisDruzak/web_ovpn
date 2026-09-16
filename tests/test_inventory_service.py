from __future__ import annotations

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory.sqlite'}")
    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as session:
        yield session


@pytest.mark.parametrize("child_type", ["MONITOR", "PRINTER", "PHONE", "UPS", "OTHER"])
def test_pc_can_attach_each_allowed_child_type(db, child_type):
    """A hierarchy regression must never reject a valid PC workstation device."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService

    service = InventoryService()
    location = service.create_location(db, name="Бухгалтерия")
    pc = service.create_asset(db, InventoryAssetType.PC, location_id=location.id)
    child = service.create_asset(db, InventoryAssetType(child_type), location_id=location.id)

    relation = service.attach_existing_asset(db, pc.id, child.id, actor="admin")

    assert relation.parent_asset_id == pc.id
    assert relation.child_asset_id == child.id
    assert relation.ended_at is None


def test_relation_rejects_pc_child_and_leaf_parent(db):
    """Allowing a PC child or leaf parent would create an unsupported recursive tree."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService, InventoryValidationError

    service = InventoryService()
    location = service.create_location(db, name="214")
    pc_one = service.create_asset(db, InventoryAssetType.PC, location_id=location.id)
    pc_two = service.create_asset(db, InventoryAssetType.PC, location_id=location.id)
    monitor = service.create_asset(db, InventoryAssetType.MONITOR, location_id=location.id)

    with pytest.raises(InventoryValidationError, match="PC cannot be a related device"):
        service.attach_existing_asset(db, pc_one.id, pc_two.id, actor="admin")
    with pytest.raises(InventoryValidationError, match="only PC can have related devices"):
        service.attach_existing_asset(db, monitor.id, pc_one.id, actor="admin")


def test_detach_preserves_child_and_returns_it_to_location_tree(db):
    """Ending a relation must not delete the child or make it disappear from its location."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService

    service = InventoryService()
    location = service.create_location(db, name="Архив")
    pc = service.create_asset(db, InventoryAssetType.PC, location_id=location.id, custom_name="ARCH-PC")
    monitor = service.create_asset(
        db, InventoryAssetType.MONITOR, location_id=location.id, custom_name="AOC 24B2X"
    )
    relation = service.attach_existing_asset(db, pc.id, monitor.id, actor="admin")

    service.detach_relation(db, relation.id)
    tree = service.location_tree(db, location.id)

    assert monitor.id in {asset.id for asset in tree["top_level_assets"]}
    assert tree["related_by_parent"] == {}
    assert db.get(type(monitor), monitor.id).location_id == location.id


def test_attach_rejects_different_locations(db):
    """A relationship across locations would make the displayed physical tree ambiguous."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService, InventoryValidationError

    service = InventoryService()
    first = service.create_location(db, name="214")
    second = service.create_location(db, name="215")
    pc = service.create_asset(db, InventoryAssetType.PC, location_id=first.id)
    monitor = service.create_asset(db, InventoryAssetType.MONITOR, location_id=second.id)

    with pytest.raises(InventoryValidationError, match="same location"):
        service.attach_existing_asset(db, pc.id, monitor.id, actor="admin")
