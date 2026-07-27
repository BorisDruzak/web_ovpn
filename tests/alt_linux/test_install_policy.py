from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
PROFILE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_policy import PolicyError, evaluate_policy, load_profile


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _profile() -> object:
    return load_profile(PROFILE_ROOT, "standard-office", 1)


@pytest.mark.parametrize(
    "fixture_name",
    [
        "inventory-disk-50g.json",
        "inventory-disk-100g.json",
        "inventory-disk-200g-no-serial-wwn.json",
    ],
)
def test_standard_office_accepts_exactly_one_eligible_disk(
    fixture_name: str,
) -> None:
    evaluation = evaluate_policy(parse_inventory(_fixture(fixture_name)), _profile())

    assert evaluation.eligible_disk.path == "/dev/vda"
    assert evaluation.route_interface.route_to_controller is True


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda payload: payload["disks"][0].__setitem__("size_bytes", 34_359_738_368), "disk_too_small"),
        (lambda payload: payload.__setitem__("disks", []), "disk_missing"),
        (lambda payload: payload["disks"].append(deepcopy(payload["disks"][0]) | {"path": "/dev/vdb"}), "disk_ambiguous"),
        (lambda payload: payload["machine"].__setitem__("firmware", "bios"), "unsupported_firmware"),
        (lambda payload: payload["machine"].__setitem__("cpu_arch", "aarch64"), "unsupported_architecture"),
        (lambda payload: payload["agent"].__setitem__("iso_id", "wrong-iso"), "iso_id_mismatch"),
        (lambda payload: payload["agent"].__setitem__("iso_sha256", "b" * 64), "iso_sha256_mismatch"),
        (lambda payload: payload["agent"].__setitem__("iso_sha256", "c" * 64), "iso_sha256_mismatch"),
        (lambda payload: payload["boot_media"].__setitem__("path", "/dev/vda"), "disk_is_boot_media"),
        (lambda payload: payload["disks"][0].__setitem__("removable", True), "disk_removable"),
        (lambda payload: payload["interfaces"][0].__setitem__("route_to_controller", False), "network_missing"),
        (lambda payload: payload["interfaces"].append(deepcopy(payload["interfaces"][0]) | {"name": "enp2s0", "mac": "52:54:00:12:34:59"}), "network_ambiguous"),
    ],
)
def test_standard_office_rejects_unsafe_install_choices(
    mutate: object,
    code: str,
) -> None:
    payload = deepcopy(_fixture("inventory-disk-100g.json"))
    mutate(payload)

    with pytest.raises(PolicyError, match=code):
        evaluate_policy(parse_inventory(payload), _profile())


def test_profile_selection_rejects_unknown_id_and_version() -> None:
    with pytest.raises(PolicyError, match="unknown_profile"):
        load_profile(PROFILE_ROOT, "other-profile", 1)
    with pytest.raises(PolicyError, match="unsupported_profile_version"):
        load_profile(PROFILE_ROOT, "standard-office", 2)
