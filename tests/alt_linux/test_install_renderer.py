from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
PROFILE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"
TEMPLATE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "templates"
SNAPSHOT_PATH = REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "snapshots" / "standard-office-v1.sha256sums"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_plan import OperatorSelection, PlanRequest, build_install_plan
from alt_deploy.install_policy import evaluate_policy, load_profile
from alt_deploy.install_renderer import (
    RenderError,
    RendererSecrets,
    render_install_bundle,
    write_install_bundle,
)


def _plan() -> object:
    inventory = parse_inventory(json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8")))
    profile = load_profile(PROFILE_ROOT, "standard-office", 1)
    evaluation = evaluate_policy(inventory, profile)
    selection = OperatorSelection(
        disk_path=evaluation.eligible_disk.path,
        disk_fingerprint=disk_fingerprint(evaluation.eligible_disk),
        interface_name=evaluation.route_interface.name,
        interface_mac=evaluation.route_interface.mac,
    )
    request = PlanRequest(
        session_id="install-20260727-0001",
        revision=1,
        temporary_hostname="alt-install-0001",
        approved_at="2026-07-27T12:00:00+00:00",
        expires_at="2026-07-27T13:00:00+00:00",
    )
    return build_install_plan(inventory, profile, evaluation, selection, request)


def _secrets() -> object:
    return RendererSecrets(
        root_yescrypt_hash="$y$j9T$synthetic-root$abcdefghijklmnopqrstuv",
        admin_yescrypt_hash="$y$j9T$synthetic-admin$abcdefghijklmnopqrstuv",
    )


def test_renderer_returns_repeatable_utf8_artifacts() -> None:
    first = render_install_bundle(_plan(), _secrets(), TEMPLATE_ROOT)
    second = render_install_bundle(_plan(), _secrets(), TEMPLATE_ROOT)

    assert first.files == second.files
    assert tuple(first.files) == ("autoinstall.scm", "vm-profile.scm", "sha256sums")
    assert first.files["autoinstall.scm"].endswith(b"\n")
    assert b"enp6s18" in first.files["autoinstall.scm"]
    assert b"plan_hash" not in first.files["autoinstall.scm"]
    assert first.files["sha256sums"].splitlines()[0].endswith(b"  autoinstall.scm")
    assert first.files["sha256sums"].splitlines()[1].endswith(b"  vm-profile.scm")
    assert first.files["sha256sums"] == SNAPSHOT_PATH.read_bytes()


def test_renderer_writes_only_declared_bundle_files(tmp_path: Path) -> None:
    (tmp_path / "portable-ansible-vault").write_text("unrelated", encoding="utf-8")
    destination = tmp_path / "bundle"
    destination.mkdir()
    bundle = render_install_bundle(_plan(), _secrets(), TEMPLATE_ROOT)
    write_install_bundle(bundle, destination)

    assert sorted(path.name for path in destination.iterdir()) == [
        "autoinstall.scm",
        "sha256sums",
        "vm-profile.scm",
    ]
    assert (destination / "sha256sums").read_bytes() == bundle.files["sha256sums"]


@pytest.mark.parametrize(
    ("plan", "secrets", "code"),
    [
        ({"target_disk": "/dev/vda"}, _secrets(), "plan_type_invalid"),
        (_plan(), RendererSecrets(root_yescrypt_hash="not-a-hash", admin_yescrypt_hash="not-a-hash"), "secret_invalid"),
    ],
)
def test_renderer_rejects_unvalidated_inputs(
    plan: object,
    secrets: object,
    code: str,
) -> None:
    with pytest.raises(RenderError, match=code):
        render_install_bundle(plan, secrets, TEMPLATE_ROOT)
