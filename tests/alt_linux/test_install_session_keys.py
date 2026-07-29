from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from alt_deploy.config import Settings
from alt_deploy.install_session_keys import ensure_install_session_keypair
from alt_deploy.install_session_signing import (
    load_private_signer,
    load_public_verifier,
    public_key_metadata,
)


def settings_for_keys(tmp_path: Path) -> Settings:
    return replace(
        Settings.from_env(),
        install_signing_private_key=tmp_path / "secrets" / "install-plan-ed25519.pem",
        install_signing_public_key=tmp_path / "etc" / "install-plan-ed25519.pub",
    )


def write_complete_pair(
    settings: Settings,
    *,
    private: Ed25519PrivateKey,
    public: object,
) -> None:
    settings.install_signing_private_key.parent.mkdir()
    settings.install_signing_public_key.parent.mkdir()
    settings.install_signing_private_key.parent.chmod(0o700)
    settings.install_signing_public_key.parent.chmod(0o755)
    settings.install_signing_private_key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings.install_signing_private_key.chmod(0o600)
    settings.install_signing_public_key.write_bytes(
        json.dumps(
            public_key_metadata(public), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )
    settings.install_signing_public_key.chmod(0o644)


def test_ensure_keypair_creates_matching_metadata(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)

    metadata = ensure_install_session_keypair(settings, euid=lambda: 0)

    if os.name != "nt":
        assert stat.S_IMODE(settings.install_signing_private_key.stat().st_mode) == 0o600
        assert stat.S_IMODE(settings.install_signing_public_key.stat().st_mode) == 0o644
    assert public_key_metadata(
        load_private_signer(settings.install_signing_private_key).public_key()
    ) == metadata
    assert public_key_metadata(
        load_public_verifier(settings.install_signing_public_key)
    ) == metadata
    assert settings.install_signing_public_key.read_bytes() == (
        json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def test_existing_matching_pair_is_retained(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)
    first = ensure_install_session_keypair(settings, euid=lambda: 0)
    before = (
        settings.install_signing_private_key.read_bytes(),
        settings.install_signing_public_key.read_bytes(),
    )
    second = ensure_install_session_keypair(settings, euid=lambda: 0)

    assert second == first
    assert before == (
        settings.install_signing_private_key.read_bytes(),
        settings.install_signing_public_key.read_bytes(),
    )


def test_existing_pair_with_noncanonical_public_json_is_rejected_without_rewrite(
    tmp_path: Path,
) -> None:
    settings = settings_for_keys(tmp_path)
    metadata = ensure_install_session_keypair(settings, euid=lambda: 0)
    settings.install_signing_public_key.write_bytes(
        json.dumps(metadata, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    before = settings.install_signing_public_key.read_bytes()

    with pytest.raises(ValueError, match="canonical"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert settings.install_signing_public_key.read_bytes() == before


def test_existing_pair_with_symlinked_private_parent_is_rejected(
    tmp_path: Path,
) -> None:
    settings = settings_for_keys(tmp_path)
    private = Ed25519PrivateKey.generate()
    real_private_directory = tmp_path / "real-secrets"
    real_private_directory.mkdir()
    settings.install_signing_public_key.parent.mkdir()
    real_private_directory.chmod(0o700)
    settings.install_signing_public_key.parent.chmod(0o755)
    real_private_key = real_private_directory / settings.install_signing_private_key.name
    real_private_key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    real_private_key.chmod(0o600)
    settings.install_signing_public_key.write_bytes(
        json.dumps(
            public_key_metadata(private.public_key()),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    settings.install_signing_public_key.chmod(0o644)
    try:
        settings.install_signing_private_key.parent.symlink_to(
            real_private_directory, target_is_directory=True
        )
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        ensure_install_session_keypair(settings, euid=lambda: 0)


def test_existing_pair_with_unsafe_private_directory_metadata_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import alt_deploy.install_session_keys as keys

    settings = settings_for_keys(tmp_path)
    private = Ed25519PrivateKey.generate()
    write_complete_pair(settings, private=private, public=private.public_key())
    settings.install_signing_private_key.parent.chmod(0o755)
    monkeypatch.setattr(keys.os, "name", "posix")
    monkeypatch.setattr(keys, "load_private_signer", lambda path: private)
    monkeypatch.setattr(keys, "load_public_verifier", lambda path: private.public_key())

    with pytest.raises(ValueError, match="directory"):
        ensure_install_session_keypair(settings, euid=lambda: 0)


@pytest.mark.parametrize(
    ("loader", "mode"),
    (("private", 0o600), ("public", 0o644)),
)
def test_signing_loaders_allow_runner_owned_keys_outside_actual_root_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader: str,
    mode: int,
) -> None:
    import alt_deploy.install_session_signing as signing

    private = Ed25519PrivateKey.generate()
    path = tmp_path / ("private.pem" if loader == "private" else "public.json")
    if loader == "private":
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        load = load_private_signer
    else:
        path.write_bytes(
            json.dumps(
                public_key_metadata(private.public_key()),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        load = load_public_verifier
    path.chmod(mode)
    real_fstat = signing.os.fstat

    def runner_owned_fstat(descriptor: int) -> object:
        metadata = real_fstat(descriptor)
        return types.SimpleNamespace(
            st_mode=stat.S_IFREG | mode,
            st_uid=1001,
            st_gid=1001,
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(signing.os, "name", "posix")
    monkeypatch.setattr(signing.os, "geteuid", lambda: 1001, raising=False)
    monkeypatch.setattr(signing.os, "fstat", runner_owned_fstat)

    assert load(path)


@pytest.mark.parametrize(
    ("loader", "mode"),
    (("private", 0o600), ("public", 0o644)),
)
def test_signing_loaders_reject_non_root_group(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    loader: str,
    mode: int,
) -> None:
    import alt_deploy.install_session_signing as signing

    private = Ed25519PrivateKey.generate()
    path = tmp_path / ("private.pem" if loader == "private" else "public.json")
    if loader == "private":
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        load = load_private_signer
    else:
        path.write_bytes(
            json.dumps(
                public_key_metadata(private.public_key()),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        load = load_public_verifier
    path.chmod(mode)
    real_fstat = signing.os.fstat

    def non_root_group_fstat(descriptor: int) -> object:
        metadata = real_fstat(descriptor)
        return types.SimpleNamespace(
            st_mode=stat.S_IFREG | mode,
            st_uid=0,
            st_gid=123,
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(signing.os, "name", "posix")
    monkeypatch.setattr(signing.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(signing.os, "fstat", non_root_group_fstat)

    with pytest.raises(ValueError, match="ownership"):
        load(path)


def test_mismatched_pair_is_rejected_without_replacement(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)
    write_complete_pair(
        settings,
        private=Ed25519PrivateKey.generate(),
        public=Ed25519PrivateKey.generate().public_key(),
    )
    before = (
        settings.install_signing_private_key.read_bytes(),
        settings.install_signing_public_key.read_bytes(),
    )

    with pytest.raises(ValueError, match="matching"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert before == (
        settings.install_signing_private_key.read_bytes(),
        settings.install_signing_public_key.read_bytes(),
    )


@pytest.mark.parametrize("present", ("private", "public"))
def test_missing_half_pair_is_rejected_without_replacement(
    tmp_path: Path, present: str
) -> None:
    settings = settings_for_keys(tmp_path)
    private = Ed25519PrivateKey.generate()
    if present == "private":
        settings.install_signing_private_key.parent.mkdir()
        settings.install_signing_private_key.parent.chmod(0o700)
        settings.install_signing_private_key.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        settings.install_signing_private_key.chmod(0o600)
        existing = settings.install_signing_private_key
    else:
        settings.install_signing_public_key.parent.mkdir()
        settings.install_signing_public_key.parent.chmod(0o755)
        settings.install_signing_public_key.write_text(
            json.dumps(public_key_metadata(private.public_key())), encoding="utf-8"
        )
        settings.install_signing_public_key.chmod(0o644)
        existing = settings.install_signing_public_key
    before = existing.read_bytes()

    with pytest.raises(ValueError, match="incomplete"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert existing.read_bytes() == before


def test_symlink_target_is_rejected_without_replacement(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)
    target = tmp_path / "target.pem"
    target.write_text("not a signing key", encoding="utf-8")
    settings.install_signing_private_key.parent.mkdir()
    try:
        settings.install_signing_private_key.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    before = target.read_bytes()

    with pytest.raises(ValueError):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert target.read_bytes() == before
    assert settings.install_signing_private_key.is_symlink()


def test_bad_private_key_mode_is_rejected_without_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import alt_deploy.install_session_signing as signing

    settings = settings_for_keys(tmp_path)
    private = Ed25519PrivateKey.generate()
    write_complete_pair(settings, private=private, public=private.public_key())
    settings.install_signing_private_key.chmod(0o644)
    before = settings.install_signing_private_key.read_bytes()
    monkeypatch.setattr(signing.os, "name", "posix")

    with pytest.raises(ValueError, match="permissions"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert settings.install_signing_private_key.read_bytes() == before


def test_non_ed25519_private_pem_is_rejected_without_replacement(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)
    public = Ed25519PrivateKey.generate().public_key()
    settings.install_signing_private_key.parent.mkdir()
    settings.install_signing_public_key.parent.mkdir()
    settings.install_signing_private_key.parent.chmod(0o700)
    settings.install_signing_public_key.parent.chmod(0o755)
    settings.install_signing_private_key.write_bytes(
        generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings.install_signing_private_key.chmod(0o600)
    settings.install_signing_public_key.write_text(
        json.dumps(public_key_metadata(public)), encoding="utf-8"
    )
    settings.install_signing_public_key.chmod(0o644)
    before = settings.install_signing_private_key.read_bytes()

    with pytest.raises(ValueError, match="algorithm"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert settings.install_signing_private_key.read_bytes() == before


def test_malformed_public_json_is_rejected_without_replacement(tmp_path: Path) -> None:
    settings = settings_for_keys(tmp_path)
    private = Ed25519PrivateKey.generate()
    settings.install_signing_private_key.parent.mkdir()
    settings.install_signing_public_key.parent.mkdir()
    settings.install_signing_private_key.parent.chmod(0o700)
    settings.install_signing_public_key.parent.chmod(0o755)
    settings.install_signing_private_key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings.install_signing_private_key.chmod(0o600)
    settings.install_signing_public_key.write_text("{", encoding="utf-8")
    settings.install_signing_public_key.chmod(0o644)
    before = settings.install_signing_public_key.read_bytes()

    with pytest.raises(ValueError, match="JSON"):
        ensure_install_session_keypair(settings, euid=lambda: 0)

    assert settings.install_signing_public_key.read_bytes() == before


def test_non_root_invocation_is_rejected_before_creating_material(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import alt_deploy.install_session_keys as keys

    settings = settings_for_keys(tmp_path)
    monkeypatch.setattr(keys.os, "name", "posix")

    with pytest.raises(ValueError, match="requires root"):
        ensure_install_session_keypair(settings, euid=lambda: 1000)

    assert not settings.install_signing_private_key.exists()
    assert not settings.install_signing_public_key.exists()


def test_initializer_cli_prints_only_public_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = settings_for_keys(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "install_session_key_init", API_ROOT / "install_session_key_init.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.Settings, "from_env", lambda: settings)

    assert module.main() == 0

    output = capsys.readouterr()
    assert json.loads(output.out) == public_key_metadata(
        load_public_verifier(settings.install_signing_public_key)
    )
    assert settings.install_signing_private_key.read_text(encoding="utf-8") not in (
        output.out + output.err
    )
