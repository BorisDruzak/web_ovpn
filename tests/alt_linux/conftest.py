from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ALT_CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"

if str(ALT_CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(ALT_CONTROL_ROOT))


def load_install_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


@pytest.fixture
def valid_inventory_payload() -> dict[str, object]:
    return load_install_fixture("inventory-valid.json")
