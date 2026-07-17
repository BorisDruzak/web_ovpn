from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

from .context import canonical_entity_hash


@dataclass(frozen=True)
class SnapshotEntity:
    """Canonical payload plus materialized-snapshot storage lifecycle."""

    payload: dict[str, Any]
    lifecycle: Literal["active", "retired"] = "active"


SnapshotValue: TypeAlias = dict[str, Any] | SnapshotEntity
Snapshot: TypeAlias = dict[str, dict[str, SnapshotValue]]


def diff_snapshots(
    base: Snapshot,
    candidate: Snapshot,
) -> list[dict[str, str | None]]:
    """Return a deterministic structural diff keyed by entity type and stable ID.

    Raw mappings are active canonical payloads. Materialized rows use
    ``SnapshotEntity`` so storage lifecycle remains separate from payload keys.
    """
    changes: list[dict[str, str | None]] = []
    entity_types = sorted(set(base) | set(candidate))
    for entity_type in entity_types:
        before_entities = base.get(entity_type, {})
        after_entities = candidate.get(entity_type, {})
        for stable_id in sorted(set(before_entities) | set(after_entities)):
            before = _active_payload(before_entities.get(stable_id))
            after = _active_payload(after_entities.get(stable_id))
            before_hash = canonical_entity_hash(before) if before is not None else None
            after_hash = canonical_entity_hash(after) if after is not None else None
            if before is None and after is None:
                change = "unchanged"
            elif before is None:
                change = "added"
            elif after is None:
                change = "removed"
            elif before_hash == after_hash:
                change = "unchanged"
            else:
                change = "changed"
            changes.append(
                {
                    "entity_type": entity_type,
                    "stable_id": stable_id,
                    "change": change,
                    "before_hash": before_hash,
                    "after_hash": after_hash,
                }
            )
    return changes


def _active_payload(entity: SnapshotValue | None) -> dict[str, Any] | None:
    if isinstance(entity, SnapshotEntity):
        return entity.payload if entity.lifecycle == "active" else None
    return entity
