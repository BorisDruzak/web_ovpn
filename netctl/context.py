import hashlib
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry
from referencing.exceptions import NoSuchResource
import yaml


COUNT_FIELDS = (
    "sites",
    "locations",
    "segments",
    "devices",
    "services",
    "links",
    "features",
    "risks",
)

IMPORT_COLLECTIONS: dict[str, tuple[str, str]] = {
    "sites": ("intent_sites", "site"),
    "locations": ("intent_locations", "location"),
    "segments": ("intent_segments", "segment"),
    "devices": ("intent_assets", "asset"),
    "services": ("intent_services", "service"),
    "links": ("intent_links", "link"),
}

RELATION_ALIASES: dict[str, str] = {
    "connected_to": "CONNECTED_TO",
}

RELATION_TYPES: frozenset[str] = frozenset(
    {
        "CONNECTED_TO",
        "MEMBER_OF",
        "ROUTED_VIA",
        "RUNS_ON",
        "USED_BY",
        "LOCATED_AT",
        "CAN_ACCESS",
        "AFFECTED_BY",
        "RESOLVED_BY",
        *RELATION_ALIASES,
    }
)


def load_context(path: Path) -> dict[str, Any]:
    return load_context_bytes(path.read_bytes())


def load_context_bytes(raw_bytes: bytes) -> dict[str, Any]:
    document = yaml.safe_load(raw_bytes)
    if not isinstance(document, dict):
        raise ValueError("context YAML must contain an object")
    return document


def load_schema(path: Path) -> dict[str, Any]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("context schema must contain an object")
    return schema


def _reject_external_retrieval(uri: str) -> None:
    raise NoSuchResource(ref=uri)


def _external_reference_errors(value: Any, path: str = "") -> list[dict[str, str]]:
    if isinstance(value, dict):
        errors = []
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key in {"$ref", "$dynamicRef", "$recursiveRef"} and isinstance(item, str) and not item.startswith("#"):
                errors.append(
                    {
                        "path": child_path,
                        "message": f"external schema references are not allowed: {item}",
                    }
                )
            else:
                errors.extend(_external_reference_errors(item, child_path))
        return errors
    if isinstance(value, list):
        errors = []
        for index, item in enumerate(value):
            errors.extend(_external_reference_errors(item, f"{path}.{index}" if path else str(index)))
        return errors
    return []


def validate_context(document: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, str]]:
    reference_errors = _external_reference_errors(schema)
    if reference_errors:
        return sorted(reference_errors, key=lambda error: (error["path"], error["message"]))

    try:
        schema_errors = sorted(
            Draft202012Validator(schema, registry=Registry(retrieve=_reject_external_retrieval)).iter_errors(document),
            key=lambda error: tuple(error.absolute_path),
        )
    except Exception as exc:
        return [{"path": "$ref", "message": f"schema reference resolution failed: {exc}"}]
    errors = [
        {
            "path": _validation_error_path(error),
            "message": error.message,
        }
        for error in schema_errors
    ]

    for collection, items in document.items():
        if not isinstance(items, list):
            continue
        seen_ids: set[str] = set()
        for index, item in enumerate(items):
            item_id = item.get("id") if isinstance(item, dict) else None
            if not isinstance(item_id, str):
                continue
            if item_id in seen_ids:
                errors.append(
                    {
                        "path": f"{collection}.{index}.id",
                        "message": f"duplicate id '{item_id}'",
                    }
                )
            seen_ids.add(item_id)

    return sorted(errors, key=lambda error: (error["path"], error["message"]))


def validate_import_semantics(document: dict[str, Any]) -> list[dict[str, str]]:
    """Return deterministic errors for import-specific context constraints."""
    errors: list[dict[str, str]] = []
    device_ids = _valid_entity_ids(document.get("devices"))

    for collection in IMPORT_COLLECTIONS:
        items = document.get(collection)
        if not isinstance(items, list):
            continue
        seen_ids: set[str] = set()
        for index, entity in enumerate(items):
            path = f"{collection}.{index}"
            entity_id = entity.get("id") if isinstance(entity, dict) else None
            if not _is_nonblank_string(entity_id):
                errors.append({"path": f"{path}.id", "message": "id must be a non-blank string"})
            elif entity_id in seen_ids:
                errors.append({"path": f"{path}.id", "message": f"duplicate id '{entity_id}'"})
            else:
                seen_ids.add(entity_id)

            if collection == "links" and isinstance(entity, dict):
                errors.extend(_link_semantic_errors(entity, path, device_ids))

    return sorted(errors, key=lambda error: (error["path"], error["message"]))


def canonical_entity_json(entity: dict[str, Any]) -> str:
    return json.dumps(
        entity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_canonical_json_scalar,
    )


def _canonical_json_scalar(value: Any) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def canonical_entity_hash(entity: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_entity_json(entity).encode("utf-8")).hexdigest()


def normalise_relation_type(relation: str) -> str:
    """Map an accepted context relation to its queryable SQLite value."""
    return RELATION_ALIASES.get(relation, relation)


def normalise_import_entities(document: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Build a stable entity-type/stable-id view of the import collections."""
    normalised: dict[str, dict[str, dict[str, Any]]] = {}
    for collection, (_table, entity_type) in IMPORT_COLLECTIONS.items():
        items = document.get(collection)
        if not isinstance(items, list):
            normalised[entity_type] = {}
            continue
        entities = [
            entity
            for entity in items
            if isinstance(entity, dict) and _is_nonblank_string(entity.get("id"))
        ]
        normalised[entity_type] = {
            entity["id"]: entity
            for entity in sorted(entities, key=lambda entity: entity["id"])
        }
    return normalised


def _link_semantic_errors(link: dict[str, Any], path: str, device_ids: set[str]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    relation = link.get("relation")
    if not isinstance(relation, str) or relation not in RELATION_TYPES:
        errors.append({"path": f"{path}.relation", "message": f"unsupported relation {relation!r}"})

    if "confidence" in link:
        confidence = link["confidence"]
        if type(confidence) is not int or not 0 <= confidence <= 100:
            errors.append(
                {
                    "path": f"{path}.confidence",
                    "message": "confidence must be an integer from 0 to 100",
                }
            )

    for endpoint_name in ("endpoint_a", "endpoint_b"):
        endpoint_path = f"{path}.{endpoint_name}"
        endpoint = link.get(endpoint_name)
        if not isinstance(endpoint, dict):
            errors.append({"path": endpoint_path, "message": "endpoint must be an object"})
            continue

        device = endpoint.get("device")
        device_path = f"{endpoint_path}.device"
        if not _is_nonblank_string(device):
            errors.append({"path": device_path, "message": "device must be a non-blank string"})
        elif device not in device_ids:
            errors.append({"path": device_path, "message": f"unknown device '{device}'"})

        if "interface" in endpoint and not _is_nonblank_string(endpoint["interface"]):
            errors.append(
                {
                    "path": f"{endpoint_path}.interface",
                    "message": "interface must be a non-blank string when present",
                }
            )
    return errors


def _valid_entity_ids(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        entity["id"]
        for entity in value
        if isinstance(entity, dict) and _is_nonblank_string(entity.get("id"))
    }


def _is_nonblank_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validation_error_path(error: Any) -> str:
    path = list(error.absolute_path)
    if error.validator == "required" and isinstance(error.instance, dict):
        missing_property = next(
            (name for name in error.validator_value if name not in error.instance),
            None,
        )
        if missing_property is not None:
            path.append(missing_property)
    return ".".join(str(part) for part in path)


def context_summary(document: dict[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return {
        "context_id": str(metadata.get("context_id") or ""),
        "schema_version": str(document.get("schema_version") or ""),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "counts": {
            name: len(document.get(name, [])) if isinstance(document.get(name), list) else 0
            for name in COUNT_FIELDS
        },
    }
