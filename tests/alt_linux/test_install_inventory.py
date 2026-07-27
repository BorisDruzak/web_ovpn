from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ALT_CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"

if str(ALT_CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(ALT_CONTROL_ROOT))

from alt_deploy.install_inventory import (
    InventoryError,
    canonical_inventory_bytes,
    inventory_sha256,
    parse_inventory,
)


def load_install_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


@pytest.fixture
def valid_inventory_payload() -> dict[str, object]:
    return load_install_fixture("inventory-valid.json")


def test_inventory_v1_preserves_valid_machine_and_canonical_hash(
    valid_inventory_payload: dict[str, object],
) -> None:
    inventory = parse_inventory(valid_inventory_payload)

    assert inventory.machine.firmware == "uefi"
    assert inventory.machine.memory_bytes == 8_589_934_592
    assert canonical_inventory_bytes(inventory).startswith(b'{"agent":')
    assert inventory_sha256(inventory) == inventory_sha256(
        parse_inventory(inventory.to_dict())
    )


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({}, "inventory_missing_field"),
        ({"schema_version": 2}, "inventory_schema_unsupported"),
        ([], "inventory_type_invalid"),
    ],
)
def test_inventory_v1_rejects_invalid_top_level(
    payload: object,
    code: str,
) -> None:
    with pytest.raises(InventoryError, match=code):
        parse_inventory(payload)


def test_inventory_v1_rejects_agent_supplied_source_ip() -> None:
    with pytest.raises(InventoryError, match="inventory_unknown_field"):
        parse_inventory(load_install_fixture("inventory-unknown-field.json"))


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda payload: payload["machine"].__setitem__("extra", "no"),
            "inventory_unknown_field",
        ),
        (
            lambda payload: payload["interfaces"][0].__setitem__("extra", "no"),
            "inventory_unknown_field",
        ),
        (
            lambda payload: payload["disks"][0].__setitem__("path", "/dev/loop0"),
            "inventory_value_invalid",
        ),
        (
            lambda payload: payload["machine"].__setitem__("memory_bytes", True),
            "inventory_type_invalid",
        ),
        (
            lambda payload: payload.__setitem__("interfaces", [
                payload["interfaces"][0] for _ in range(17)
            ]),
            "inventory_limit_exceeded",
        ),
    ],
)
def test_inventory_v1_rejects_nested_untrusted_values(
    valid_inventory_payload: dict[str, object],
    mutate: object,
    code: str,
) -> None:
    payload = deepcopy(valid_inventory_payload)
    mutate(payload)

    with pytest.raises(InventoryError, match=code):
        parse_inventory(payload)


def test_inventory_v1_is_frozen_after_validation(
    valid_inventory_payload: dict[str, object],
) -> None:
    inventory = parse_inventory(valid_inventory_payload)

    with pytest.raises(AttributeError):
        inventory.machine.firmware = "bios"  # type: ignore[misc]
