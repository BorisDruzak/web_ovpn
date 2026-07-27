from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
PROFILE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
GOLDEN_PATH = (
    REPO_ROOT
    / "deploy"
    / "alt-linux"
    / "install-agent"
    / "helper"
    / "testdata"
    / "v1"
    / "golden.json"
)
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import (
    canonical_inventory_bytes,
    inventory_sha256,
    parse_inventory,
)
from alt_deploy.install_plan import (
    OperatorSelection,
    PlanRequest,
    build_install_plan,
    canonical_plan_bytes,
    plan_sha256,
)
from alt_deploy.install_policy import evaluate_policy, load_profile
from alt_deploy.install_session_signing import (
    public_key_metadata,
    sign_plan_bytes,
)


def _golden() -> dict[str, object]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _plan(
    fixture_name: str,
    *,
    session_id: str,
    hostname: str,
) -> tuple[object, object, bytes]:
    inventory = parse_inventory(
        json.loads((FIXTURE_ROOT / fixture_name).read_text(encoding="utf-8"))
    )
    profile = load_profile(PROFILE_ROOT, "standard-office", 1)
    evaluation = evaluate_policy(inventory, profile)
    selection = OperatorSelection(
        disk_path=evaluation.eligible_disk.path,
        disk_fingerprint=disk_fingerprint(evaluation.eligible_disk),
        interface_name=evaluation.route_interface.name,
        interface_mac=evaluation.route_interface.mac,
    )
    plan = build_install_plan(
        inventory,
        profile,
        evaluation,
        selection,
        PlanRequest(
            session_id=session_id,
            revision=1,
            temporary_hostname=hostname,
            approved_at="2026-07-27T12:00:00+00:00",
            expires_at="2026-07-27T13:00:00+00:00",
        ),
    )
    return inventory, plan, canonical_plan_bytes(plan)


def test_go_golden_vector_is_exact_pr3_canonical_and_ed25519_contract() -> None:
    golden = _golden()
    inventory, plan, plan_bytes = _plan(
        "inventory-disk-100g.json",
        session_id="install-20260727T120000Z-a1b2c3d4",
        hostname="alt-install-a1b2c3d4",
    )
    inventory_bytes = canonical_inventory_bytes(inventory)
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = public_key_metadata(private_key.public_key())
    signature = {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": public_key["key_id"],
        "signed_file": "plan.json",
        "plan_sha256": plan_sha256(plan),
        "signature_b64": base64.b64encode(
            sign_plan_bytes(private_key, plan_bytes)
        ).decode("ascii"),
        "created_at": "2026-07-27T12:00:00+00:00",
    }

    assert base64.b64encode(inventory_bytes).decode("ascii") == golden[
        "inventory_canonical_b64"
    ]
    assert inventory_sha256(inventory) == golden["inventory_sha256"]
    assert disk_fingerprint(inventory.disks[0]) == golden["disk_fingerprint"]
    assert base64.b64encode(plan_bytes).decode("ascii") == golden[
        "plan_canonical_b64"
    ]
    assert plan_sha256(plan) == golden["plan_sha256"]
    assert public_key == golden["public_key"]
    assert signature == golden["signature"]
    assert golden["source_iso"] == {
        "schema_version": 1,
        "iso_id": plan.iso_id,
        "iso_sha256": plan.iso_sha256,
    }


def test_go_weak_disk_vector_preserves_pr3_compatibility_identity() -> None:
    golden = _golden()
    inventory, plan, plan_bytes = _plan(
        "inventory-disk-200g-no-serial-wwn.json",
        session_id="install-20260727T120000Z-weak0001",
        hostname="alt-install-weak0001",
    )

    assert inventory.disks[0].serial is None
    assert inventory.disks[0].wwn is None
    assert base64.b64encode(canonical_inventory_bytes(inventory)).decode(
        "ascii"
    ) == golden["weak_inventory_canonical_b64"]
    assert base64.b64encode(plan_bytes).decode("ascii") == golden[
        "weak_plan_canonical_b64"
    ]
    assert disk_fingerprint(inventory.disks[0]) == golden[
        "weak_disk_fingerprint"
    ]
