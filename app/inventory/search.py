"""Read-only inventory search with Unicode matching, independent of DB collation."""
from collections import defaultdict
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import InventoryAsset, InventoryAssetIdentifier, InventoryLocation


PAGE_SIZE = 50
SEARCH_FIELDS = (
    "custom_name", "manufacturer", "model", "serial_number", "inventory_number",
    "assigned_person_name", "login_name", "description",
)
_MAC = re.compile(r"(?:[0-9a-f]{12}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4})\Z")


def _normalize(value: object) -> str:
    return str(value or "").casefold().replace("ё", "е")


def _matches(values: list[str], terms: list[str]) -> bool:
    text = "\n".join(_normalize(value) for value in values)
    # Keep %, _ and other punctuation literal; canonicalize complete MAC addresses.
    macs = {re.sub(r"[:.\-]", "", _normalize(value)) for value in values
        if _MAC.fullmatch(_normalize(value))}
    return all(term in text or (_MAC.fullmatch(term) and re.sub(r"[:.\-]", "", term) in macs)
        for term in terms)


def search_inventory(db: Session, query: str, page: int = 1) -> dict:
    query = " ".join(query[:255].split())
    locations = sorted(db.scalars(select(InventoryLocation)),
        key=lambda item: (_normalize(item.name), item.id))
    result = {"q": query, "locations": locations, "search_results": [],
        "search_total": 0, "page": 1, "pages": 1}
    if not query:
        return result

    terms = _normalize(query).split()
    by_location = {item.id: item for item in locations}
    result["locations"] = [item for item in locations if _matches([item.name, item.comment], terms)]
    identifiers = defaultdict(list)
    # Three batched reads: no per-card queries or external network calls. Python
    # casefold is required because SQLite lower/LIKE do not fold Russian text.
    for item in db.scalars(select(InventoryAssetIdentifier).join(
        InventoryAsset, InventoryAsset.id == InventoryAssetIdentifier.asset_id).where(
        InventoryAssetIdentifier.is_current.is_(True), InventoryAsset.deleted_at.is_(None))):
        identifiers[item.asset_id].append(item.value)
    matches = []
    for asset in db.scalars(select(InventoryAsset).where(InventoryAsset.deleted_at.is_(None))):
        location = by_location.get(asset.location_id)
        values = [getattr(asset, field) for field in SEARCH_FIELDS]
        values.extend(identifiers[asset.id])
        if location:
            values.extend([location.name, location.comment])
        if _matches(values, terms):
            matches.append({"asset": asset, "location": location,
                "identifiers": sorted(set(identifiers[asset.id]), key=_normalize)})
    matches.sort(key=lambda row: (_normalize(row["location"].name if row["location"] else ""),
        _normalize(row["asset"].custom_name or row["asset"].model), row["asset"].id))
    pages = max(1, (len(matches) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(1, page), pages)
    result.update(search_results=matches[(page - 1) * PAGE_SIZE:page * PAGE_SIZE],
        search_total=len(matches), page=page, pages=pages)
    return result
