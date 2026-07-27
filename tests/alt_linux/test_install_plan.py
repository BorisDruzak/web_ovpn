from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
PROFILE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import inventory_sha256, parse_inventory
from alt_deploy.install_plan import (
    OperatorSelection,
    PlanError,
    PlanRequest,
    build_install_plan,
    plan_sha256,
)
from alt_deploy.install_policy import evaluate_policy, load_profile


def _inventory() -> object:
    return parse_inventory(json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8")))


def _context() -> tuple[object, object, object]:
    inventory = _inventory()
    profile = load_profile(PROFILE_ROOT, "standard-office", 1)
    return inventory, profile, evaluate_policy(inventory, profile)


def _request() -> PlanRequest:
    return PlanRequest(
        session_id="install-20260727-0001",
        revision=1,
        temporary_hostname="alt-install-0001",
        approved_at="2026-07-27T12:00:00+00:00",
        expires_at="2026-07-27T13:00:00+00:00",
    )


def _selection(evaluation: object) -> OperatorSelection:
    return OperatorSelection(
        disk_path=evaluation.eligible_disk.path,
        disk_fingerprint=disk_fingerprint(evaluation.eligible_disk),
        interface_name=evaluation.route_interface.name,
        interface_mac=evaluation.route_interface.mac,
    )


def test_install_plan_binds_inventory_disk_and_network_identity() -> None:
    inventory, profile, evaluation = _context()
    plan = build_install_plan(inventory, profile, evaluation, _selection(evaluation), _request())

    assert plan.inventory_sha256 == inventory_sha256(inventory)
    assert plan.target_disk["fingerprint"].startswith("sha256:")
    assert plan.network_interface == {"name": "enp6s18", "mac": "52:54:00:12:34:57"}
    assert "plan_hash" not in plan.to_dict()


def test_disk_fingerprint_changes_when_identity_changes() -> None:
    _inventory_value, _profile, evaluation = _context()
    original = disk_fingerprint(evaluation.eligible_disk)
    changed = evaluation.eligible_disk.__class__(
        **(evaluation.eligible_disk.to_dict() | {"model": "Changed model"})
    )

    assert original != disk_fingerprint(changed)


def test_plan_rejects_selection_outside_policy_candidate() -> None:
    inventory, profile, evaluation = _context()
    selection = _selection(evaluation).__class__(
        disk_path="/dev/vdb",
        disk_fingerprint=_selection(evaluation).disk_fingerprint,
        interface_name=_selection(evaluation).interface_name,
        interface_mac=_selection(evaluation).interface_mac,
    )

    with pytest.raises(PlanError, match="selection_disk_mismatch"):
        build_install_plan(inventory, profile, evaluation, selection, _request())


@pytest.mark.parametrize(
    ("approved_at", "expires_at", "code"),
    [
        ("2026-07-27T12:00:00", "2026-07-27T13:00:00+00:00", "plan_timestamp_invalid"),
        ("2026-07-27T13:00:00+00:00", "2026-07-27T12:00:00+00:00", "plan_expiry_invalid"),
    ],
)
def test_plan_rejects_unsafe_time_boundary(
    approved_at: str,
    expires_at: str,
    code: str,
) -> None:
    inventory, profile, evaluation = _context()
    request = _request().__class__(
        session_id="install-20260727-0001",
        revision=1,
        temporary_hostname="alt-install-0001",
        approved_at=approved_at,
        expires_at=expires_at,
    )

    with pytest.raises(PlanError, match=code):
        build_install_plan(inventory, profile, evaluation, _selection(evaluation), request)


def test_plan_is_frozen_and_digest_is_stable() -> None:
    inventory, profile, evaluation = _context()
    plan = build_install_plan(inventory, profile, evaluation, _selection(evaluation), _request())

    assert plan_sha256(plan) == plan_sha256(plan)
    with pytest.raises(FrozenInstanceError):
        plan.revision = 2  # type: ignore[misc]
