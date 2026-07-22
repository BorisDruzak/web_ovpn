from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from alt_deploy_backup import __version__
from alt_deploy_backup.components import component_specs
from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.manifest import (
    BackupManifest,
    ComponentRecord,
    ControllerRecord,
    PathRecord,
    PreflightRecord,
    RehearsalEvidence,
    VerificationEvidence,
    parse_manifest,
    parse_rehearsal_evidence,
    parse_verification_evidence,
)
from alt_deploy_backup.secrets import SecretIdentity
from alt_deploy_backup.systemd import UnitState
from support.backup_sandbox import BackupSandbox


BACKUP_ID = "backup-20260722T120000Z-a1b2c3d4"
COMPONENT_HASH = "1" * 64
MANIFEST_HASH = "2" * 64
VERIFICATION_HASH = "3" * 64


def _path(path: str) -> PathRecord:
    return PathRecord(
        absolute_path=path,
        present=True,
        uid=0,
        gid=0,
        owner="root",
        group="root",
        mode=0o755,
        kind="directory",
    )


def _component(
    name: str,
    filename: str,
    namespace: str,
    path: str,
) -> ComponentRecord:
    return ComponentRecord(
        name=name,
        filename=filename,
        namespace=namespace,
        size_bytes=1024,
        sha256=COMPONENT_HASH,
        paths=(_path(path),),
        archive_format="tar.zst",
    )


def valid_manifest() -> BackupManifest:
    components = (
        _component("runtime", "runtime.tar.zst", "runtime", "/opt/alt-deploy-control"),
        _component("systemd", "systemd.tar.zst", "systemd", "/etc/systemd/system/alt-deploy-http.service"),
        _component("ansible", "ansible.tar.zst", "ansible", "/home/altserver/ansible"),
        _component("controller_state", "controller-state.tar.zst", "controller-state", "/var/lib/alt-deploy"),
        _component("registration_state", "registration-state.tar.zst", "registration-state", "/srv/alt-deploy/registration"),
        _component("deployment_assets", "deployment-assets.tar.zst", "deployment-assets", "/srv/alt-deploy/bootstrap"),
    )
    units = (
        UnitState("alt-deploy-http.service", "loaded", "enabled", "active", "running", False),
        UnitState("alt-deploy-register.service", "loaded", "enabled", "active", "running", False),
        UnitState("alt-deploy-process.path", "loaded", "enabled", "active", "waiting", False),
        UnitState("alt-deploy-process.service", "loaded", "static", "inactive", "dead", False),
    )
    secrets = (
        SecretIdentity("/home/altserver/ansible/group_vars/vault.yml", "vault", 1000, 1000, "altserver", "altserver", 0o600, 128, "sha256:" + "4" * 64),
        SecretIdentity("/home/altserver/.ansible-vault-pass", "vault_password", 1000, 1000, "altserver", "altserver", 0o600, 20, "hmac-sha256:" + "5" * 64),
        SecretIdentity("/home/altserver/.ssh/id_ed25519", "ssh_private_key", 1000, 1000, "altserver", "altserver", 0o600, 512, "ssh-public-fingerprint:SHA256:fixture"),
    )
    return BackupManifest(
        schema_version=1,
        utility_version=__version__,
        backup_id=BACKUP_ID,
        created_at="2026-07-22T12:00:00+00:00",
        controller=ControllerRecord(
            hostname="alt-controller",
            machine_id="fixture-machine-id",
            os_id="altlinux",
            os_version_id="11.2",
            os_pretty_name="ALT Workstation K 11.2",
            repository_commit="a" * 40,
        ),
        components=components,
        systemd_units=units,
        secret_identities=secrets,
        preflight=PreflightRecord(
            active_jobs_empty=True,
            transient_units_empty=True,
            pending_registration_empty=True,
            processor_inactive=True,
            secrets_valid=True,
            sources_safe=True,
            disk_space_sufficient=True,
        ),
        restore_order=tuple(component.name for component in components),
    )


def test_component_set_and_order_are_exact(tmp_path: Path) -> None:
    settings = BackupSandbox.create(tmp_path).settings

    specs = component_specs(settings)

    assert [spec.filename for spec in specs] == [
        "runtime.tar.zst",
        "systemd.tar.zst",
        "ansible.tar.zst",
        "controller-state.tar.zst",
        "registration-state.tar.zst",
        "deployment-assets.tar.zst",
    ]
    assert settings.vault_file in specs[2].excludes
    assert all(
        settings.fingerprint_key not in spec.paths
        for spec in specs
    )


def test_manifest_round_trip_is_byte_schema_stable() -> None:
    manifest = valid_manifest()

    parsed = parse_manifest(manifest.to_bytes())

    assert parsed.to_dict() == manifest.to_dict()
    assert parsed.to_bytes().endswith(b"\n")


def test_manifest_rejects_unknown_top_level_key() -> None:
    payload = valid_manifest().to_dict()
    payload["unexpected"] = True

    with pytest.raises(BackupError) as error:
        parse_manifest(json.dumps(payload).encode("utf-8"))

    assert error.value.code == "backup_manifest_invalid"


def test_manifest_rejects_invalid_restore_order() -> None:
    manifest = valid_manifest()
    invalid = replace(
        manifest,
        restore_order=tuple(reversed(manifest.restore_order)),
    )

    with pytest.raises(BackupError) as error:
        parse_manifest(invalid.to_bytes())

    assert error.value.code == "backup_manifest_invalid"


def test_manifest_rejects_non_utc_timestamp() -> None:
    invalid = replace(
        valid_manifest(),
        created_at="2026-07-22T15:00:00+03:00",
    )

    with pytest.raises(BackupError) as error:
        parse_manifest(invalid.to_bytes())

    assert error.value.code == "backup_manifest_invalid"


def test_manifest_rejects_invalid_backup_id() -> None:
    invalid = replace(valid_manifest(), backup_id="../escape")

    with pytest.raises(BackupError) as error:
        parse_manifest(invalid.to_bytes())

    assert error.value.code == "backup_manifest_invalid"


def test_verification_and_rehearsal_evidence_are_strict() -> None:
    manifest = valid_manifest()
    component_hashes = {
        component.filename: component.sha256
        for component in manifest.components
    }
    verification = VerificationEvidence(
        schema_version=1,
        utility_version=__version__,
        backup_id=BACKUP_ID,
        completed_at="2026-07-22T12:01:00+00:00",
        manifest_sha256=MANIFEST_HASH,
        component_hashes=component_hashes,
        secret_identities=manifest.secret_identities,
        passed_checks=("manifest", "components", "secrets"),
        status="ok",
    )
    rehearsal = RehearsalEvidence(
        schema_version=1,
        utility_version=__version__,
        backup_id=BACKUP_ID,
        completed_at="2026-07-22T12:02:00+00:00",
        manifest_sha256=MANIFEST_HASH,
        verification_sha256=VERIFICATION_HASH,
        secret_identities=manifest.secret_identities,
        passed_checks=("extract", "python", "ansible"),
        status="ok",
    )

    assert parse_verification_evidence(
        verification.to_bytes()
    ).to_dict() == verification.to_dict()
    assert parse_rehearsal_evidence(
        rehearsal.to_bytes()
    ).to_dict() == rehearsal.to_dict()

    payload = verification.to_dict()
    payload["secret"] = "must-fail"
    with pytest.raises(BackupError):
        parse_verification_evidence(
            json.dumps(payload).encode("utf-8")
        )
