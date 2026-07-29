from __future__ import annotations

# ruff: noqa: E402

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_execution import (
    ExecutionAuthorizationService,
    ReleaseArchiveSource,
)
from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_session_approval import InstallSessionApprovalService
from alt_deploy.install_session_keys import ensure_install_session_keypair
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService
from alt_deploy import install_renderer as renderer_module
from alt_deploy import install_execution as execution_module
from alt_deploy.install_renderer import RendererSecrets


def _approved_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Settings, InstallSessionRepository, str, dict[str, object], str]:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock")
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY",
        str(tmp_path / "secrets" / "plan.pem"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SIGNING_PUBLIC_KEY",
        str(tmp_path / "etc" / "plan.pub"),
    )
    settings = Settings.from_env()
    ensure_install_session_keypair(settings, euid=lambda: 0)
    repository = InstallSessionRepository(settings)
    inventory_payload = json.loads(
        (FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8")
    )
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-29T12:00:00+00:00",
        session_id_factory=lambda: "install-20260729T120000Z-a1b2c3d4",
    ).create(
        inventory_payload,
        source_ip="192.168.100.10",
        create_nonce="A" * 43,
    )
    inventory = parse_inventory(inventory_payload)
    approved = InstallSessionApprovalService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-29T12:01:00+00:00",
        euid=lambda: 0,
    ).approve(
        created.session_id,
        inventory_sha256=repository.load_status(created.session_id)[
            "inventory_sha256"
        ],
        disk_fingerprint_value=disk_fingerprint(inventory.disks[0]),
        reason="Approve disposable execution fixture",
    )
    status = repository.load_status(created.session_id)
    status["agent_status"] = {
        "agent_version": "2.0.0",
        "boot_id": status["agent_boot_id"],
        "reported_stage": "preflight_ready",
        "schema_version": 1,
        "sent_at": "2026-07-29T12:01:30+00:00",
        "sequence": 5,
    }
    repository.replace_status(created.session_id, status)
    plan_bytes = repository.read_revision_file(created.session_id, "plan.json")
    return (
        settings,
        repository,
        created.session_id,
        approved,
        hashlib.sha256(plan_bytes).hexdigest(),
    )


def _release_archive(
    path: Path,
    members: tuple[tuple[str, bytes | None], ...],
) -> ReleaseArchiveSource:
    with tarfile.open(path, "w") as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            if content is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.mode = 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    content = path.read_bytes()
    return ReleaseArchiveSource(
        path=path,
        sha256=hashlib.sha256(content).hexdigest(),
        members=tuple(name for name, _ in members),
    )


def _release_archives(tmp_path: Path) -> dict[str, ReleaseArchiveSource]:
    return {
        "pkg-groups.tar": _release_archive(
            tmp_path / "pkg-groups.tar",
            (("groups.json", b'{"groups":["base"]}\n'),),
        ),
        "install-scripts.tar": _release_archive(
            tmp_path / "install-scripts.tar",
            (("preinstall.d", None), ("postinstall.d", None)),
        ),
    }


def _renderer_secrets() -> RendererSecrets:
    return RendererSecrets(
        root_yescrypt_hash=(
            "$y$j9T$execution-root$abcdefghijklmnopqrstuv"
        ),
        admin_yescrypt_hash=(
            "$y$j9T$execution-admin$abcdefghijklmnopqrstuv"
        ),
    )


def _execution_service(
    settings: Settings,
    repository: InstallSessionRepository,
    tmp_path: Path,
    *,
    clock: object = lambda: "2026-07-29T12:02:00+00:00",
    euid: object = lambda: 0,
) -> ExecutionAuthorizationService:
    return ExecutionAuthorizationService(
        settings,
        repository=repository,
        clock=clock,
        euid=euid,
        release_archives=_release_archives(tmp_path),
        secrets_provider=_renderer_secrets,
    )


def _authorize(
    service: ExecutionAuthorizationService,
    repository: InstallSessionRepository,
    session_id: str,
    approved: dict[str, object],
    plan_sha256: str,
) -> object:
    plan = json.loads(repository.read_revision_file(session_id, "plan.json"))
    return service.authorize(
        session_id,
        plan_sha256=plan_sha256,
        inventory_sha256=approved["inventory_sha256"],
        disk_fingerprint_value=plan["target_disk"]["fingerprint"],
        confirm_target="/dev/vda",
        reason="Authorize exactly this disposable target",
    )


def test_authorize_publishes_the_immutable_execution_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    result = _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )

    execution = settings.install_sessions_dir / session_id / "execution-0001"
    assert result.manifest.target_disk == "/dev/vda"
    assert execution.is_dir()
    assert {path.name for path in execution.iterdir()} == {
        "execution-manifest.json",
        "execution-manifest-signature.json",
        "execution-digests.json",
        "autoinstall.scm",
        "vm-profile.scm",
        "pkg-groups.tar",
        "install-scripts.tar",
    }
    if os.name != "nt":
        assert all(
            stat.S_ISREG(path.lstat().st_mode)
            and stat.S_IMODE(path.lstat().st_mode) == 0o600
            for path in execution.iterdir()
        )


def test_execution_reconstructs_only_a_strict_canonical_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, repository, session_id, _, _ = _approved_session(tmp_path, monkeypatch)
    parser = getattr(renderer_module, "parse_execution_plan_bytes", None)
    assert callable(parser), "strict renderer plan parser is missing"
    raw = repository.read_revision_file(session_id, "plan.json")

    typed = parser(raw)

    assert typed.target_disk["path"] == "/dev/vda"
    malformed = json.loads(raw)
    malformed["unexpected"] = True
    malformed_raw = json.dumps(
        malformed, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    with pytest.raises(renderer_module.RenderError, match="plan_invalid"):
        parser(malformed_raw)


def test_execution_requires_release_held_archive_identity() -> None:
    source_type = getattr(execution_module, "ReleaseArchiveSource", None)
    assert callable(source_type), "release-held archive input contract is missing"

    source = source_type(
        path=Path("pkg-groups.tar"),
        sha256="a" * 64,
        members=("groups.json",),
    )

    assert source.sha256 == "a" * 64
    assert source.members == ("groups.json",)


def test_claim_is_single_use_and_preserves_root_plan_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    service = _execution_service(settings, repository, tmp_path)
    _authorize(service, repository, session_id, approved, plan_sha256)

    claimed = service.claim(session_id)

    assert claimed["state"] == "plan_published"
    assert claimed["execution"]["state"] == "claimed"
    with pytest.raises(ControlError, match="execution"):
        service.claim(session_id)


def test_cancel_before_authorize_is_terminal_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    service = _execution_service(settings, repository, tmp_path)

    cancelled = service.cancel(
        session_id, reason="Operator withdrew execution authorization"
    )

    assert cancelled["state"] == "plan_published"
    assert cancelled["execution"]["state"] == "cancelled"
    assert not repository.has_execution_publication(session_id)
    with pytest.raises(ControlError, match="execution"):
        _authorize(
            service, repository, session_id, approved, plan_sha256
        )


def test_claim_marks_an_expired_authorization_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )
    expired_service = _execution_service(
        settings,
        repository,
        tmp_path,
        clock=lambda: "2026-07-29T12:07:00+00:00",
    )

    with pytest.raises(ControlError, match="expired"):
        expired_service.claim(session_id)

    status = repository.load_status(session_id)
    assert status["state"] == "plan_published"
    assert status["execution"]["state"] == "expired"
    assert repository.has_execution_publication(session_id)


def test_repository_rejects_extra_or_tampered_execution_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )
    execution = settings.install_sessions_dir / session_id / "execution-0001"
    assert b"install-plan" in repository.read_execution_file(
        session_id, "autoinstall.scm"
    )
    (execution / "unexpected").write_bytes(b"x")
    with pytest.raises(ControlError, match="filenames"):
        repository.read_execution_file(session_id, "autoinstall.scm")
    (execution / "unexpected").unlink()
    (execution / "vm-profile.scm").write_bytes(b"tampered\n")
    with pytest.raises(ControlError, match="digest"):
        repository.read_execution_file(session_id, "vm-profile.scm")


def test_authorize_rejects_an_archive_with_an_extra_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    archives = _release_archives(tmp_path)
    package_path = tmp_path / "pkg-extra.tar"
    complete = _release_archive(
        package_path,
        (
            ("groups.json", b'{"groups":["base"]}\n'),
            ("unexpected", b"must-not-be-accepted\n"),
        ),
    )
    archives["pkg-groups.tar"] = ReleaseArchiveSource(
        path=complete.path,
        sha256=complete.sha256,
        members=("groups.json",),
    )
    service = ExecutionAuthorizationService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-29T12:02:00+00:00",
        euid=lambda: 0,
        release_archives=archives,
        secrets_provider=_renderer_secrets,
    )

    with pytest.raises(ControlError, match="archive"):
        _authorize(service, repository, session_id, approved, plan_sha256)

    assert not repository.has_execution_publication(session_id)
    assert "execution" not in repository.load_status(session_id)


def test_authorize_rejects_stale_preflight_and_non_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    status = repository.load_status(session_id)
    status["agent_status"]["sent_at"] = "2026-07-29T11:55:00+00:00"
    repository.replace_status(session_id, status)
    with pytest.raises(ControlError, match="stale"):
        _authorize(
            _execution_service(settings, repository, tmp_path),
            repository,
            session_id,
            approved,
            plan_sha256,
        )
    with pytest.raises(ControlError, match="root"):
        _authorize(
            _execution_service(
                settings, repository, tmp_path, euid=lambda: 1000
            ),
            repository,
            session_id,
            approved,
            plan_sha256,
        )


def test_yescrypt_values_exist_only_inside_autoinstall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    result = _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )
    root_hash = _renderer_secrets().root_yescrypt_hash.encode()
    admin_hash = _renderer_secrets().admin_yescrypt_hash.encode()
    assert root_hash in repository.read_execution_file(
        session_id, "autoinstall.scm"
    )
    assert admin_hash in repository.read_execution_file(
        session_id, "autoinstall.scm"
    )
    for name in (
        "vm-profile.scm",
        "pkg-groups.tar",
        "install-scripts.tar",
        "execution-manifest.json",
        "execution-manifest-signature.json",
    ):
        content = repository.read_execution_file(session_id, name)
        assert root_hash not in content
        assert admin_hash not in content
    serialized = json.dumps(
        {
            "status": repository.load_status(session_id),
            "manifest": result.manifest.to_dict(),
        },
        sort_keys=True,
    )
    assert root_hash.decode() not in serialized
    assert admin_hash.decode() not in serialized


def test_repository_forbids_mutating_execution_binding_or_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )
    status = repository.load_status(session_id)
    status["execution"]["unexpected"] = True
    with pytest.raises(ControlError, match="fields"):
        repository.replace_status(
            session_id, status, allow_execution=True
        )
    status = repository.load_status(session_id)
    status["execution"]["state"] = "claimed"
    status["execution"]["claimed_at"] = "2026-07-29T12:03:00+00:00"
    status["execution"]["target_disk"] = "/dev/vdb"
    with pytest.raises(ControlError, match="transition"):
        repository.replace_status(
            session_id, status, allow_execution=True
        )
    service = _execution_service(settings, repository, tmp_path)
    service.claim(session_id)
    status = repository.load_status(session_id)
    status["execution"]["state"] = "handoff_started"
    status["execution"]["handoff_started_at"] = (
        "2026-07-29T12:03:00+00:00"
    )
    status["execution"]["claimed_at"] = "2026-07-29T12:02:30+00:00"
    with pytest.raises(ControlError, match="transition"):
        repository.replace_status(
            session_id, status, allow_execution=True
        )


def test_authorization_reason_cannot_serialize_a_yescrypt_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    plan = json.loads(repository.read_revision_file(session_id, "plan.json"))
    secret = _renderer_secrets().root_yescrypt_hash
    service = _execution_service(settings, repository, tmp_path)

    with pytest.raises(ControlError, match="reason"):
        service.authorize(
            session_id,
            plan_sha256=plan_sha256,
            inventory_sha256=approved["inventory_sha256"],
            disk_fingerprint_value=plan["target_disk"]["fingerprint"],
            confirm_target="/dev/vda",
            reason=secret,
        )

    assert secret not in json.dumps(repository.load_status(session_id))


def test_authorize_verifies_the_approved_plan_signature_before_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, _ = _approved_session(
        tmp_path, monkeypatch
    )
    plan_path = (
        settings.install_sessions_dir
        / session_id
        / "revision-0001"
        / "plan.json"
    )
    plan = json.loads(plan_path.read_bytes())
    plan["temporary_hostname"] = "alt-install-tampered"
    tampered = json.dumps(
        plan, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    plan_path.write_bytes(tampered)

    with pytest.raises(ControlError, match="signature"):
        _authorize(
            _execution_service(settings, repository, tmp_path),
            repository,
            session_id,
            approved,
            hashlib.sha256(tampered).hexdigest(),
        )

    assert not repository.has_execution_publication(session_id)


@pytest.mark.parametrize(
    ("terminal_state", "timestamp_field", "failure_code"),
    [
        ("installed", "installed_at", None),
        ("failed", "failed_at", "installer_failed"),
    ],
)
def test_execution_status_accepts_only_contiguous_terminal_progression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: str,
    timestamp_field: str,
    failure_code: str | None,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    service = _execution_service(settings, repository, tmp_path)
    _authorize(
        service, repository, session_id, approved, plan_sha256
    )
    service.claim(session_id)
    for state, field, timestamp in (
        (
            "handoff_started",
            "handoff_started_at",
            "2026-07-29T12:03:00+00:00",
        ),
        (
            "installer_started",
            "installer_started_at",
            "2026-07-29T12:04:00+00:00",
        ),
        (terminal_state, timestamp_field, "2026-07-29T12:05:00+00:00"),
    ):
        status = repository.load_status(session_id)
        status["execution"]["state"] = state
        status["execution"][field] = timestamp
        if state == "failed":
            status["execution"]["failure_code"] = failure_code
        repository.replace_status(
            session_id, status, allow_execution=True
        )

    terminal = repository.load_status(session_id)
    assert terminal["execution"]["state"] == terminal_state
    terminal["execution"]["state"] = "cancelled"
    terminal["execution"]["cancelled_at"] = "2026-07-29T12:06:00+00:00"
    terminal["execution"]["cancel_reason"] = "Too late"
    with pytest.raises(ControlError):
        repository.replace_status(
            session_id, terminal, allow_execution=True
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_repository_refuses_a_symlink_inside_execution_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    _authorize(
        _execution_service(settings, repository, tmp_path),
        repository,
        session_id,
        approved,
        plan_sha256,
    )
    execution = settings.install_sessions_dir / session_id / "execution-0001"
    victim = execution / "vm-profile.scm"
    victim.unlink()
    victim.symlink_to(execution / "autoinstall.scm")

    with pytest.raises(ControlError, match="non-regular"):
        repository.read_execution_file(session_id, "vm-profile.scm")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_authorize_refuses_a_symlinked_release_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    archives = _release_archives(tmp_path)
    source = archives["pkg-groups.tar"]
    link = tmp_path / "pkg-groups-link.tar"
    link.symlink_to(source.path)
    archives["pkg-groups.tar"] = ReleaseArchiveSource(
        path=link,
        sha256=source.sha256,
        members=source.members,
    )
    service = ExecutionAuthorizationService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-29T12:02:00+00:00",
        euid=lambda: 0,
        release_archives=archives,
        secrets_provider=_renderer_secrets,
    )

    with pytest.raises(ControlError, match="archive"):
        _authorize(service, repository, session_id, approved, plan_sha256)


@pytest.mark.skipif(os.name == "nt", reason="flock is POSIX-only")
def test_concurrent_authorization_publishes_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch
    )
    service = _execution_service(settings, repository, tmp_path)

    def attempt() -> str:
        try:
            _authorize(
                service, repository, session_id, approved, plan_sha256
            )
        except ControlError as exc:
            return exc.code
        return "authorized"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == [
        "authorized",
        "execution_already_authorized",
    ]
