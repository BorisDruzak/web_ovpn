from __future__ import annotations

from typing import Any

from .context import canonical_entity_hash


def diff_snapshots(
    base: dict[str, dict[str, dict[str, Any]]],
    candidate: dict[str, dict[str, dict[str, Any]]],
) -> list[dict[str, str | None]]:
    """Return a deterministic structural diff keyed by entity type and stable ID.

    Snapshot rows marked ``retired`` represent absence from the intended active
    configuration.  They are therefore compared as absent while still emitting
    their union key, which makes two retired rows unchanged.
    """
    changes: list[dict[str, str | None]] = []
    entity_types = sorted(set(base) | set(candidate))
    for entity_type in entity_types:
        before_entities = base.get(entity_type, {})
        after_entities = candidate.get(entity_type, {})
        for stable_id in sorted(set(before_entities) | set(after_entities)):
            before = _active_entity(before_entities.get(stable_id))
            after = _active_entity(after_entities.get(stable_id))
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


def _active_entity(entity: dict[str, Any] | None) -> dict[str, Any] | None:
    if entity is None or entity.get("lifecycle") == "retired":
        return None
    return entity
