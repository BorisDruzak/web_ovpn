import hashlib
import json
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
