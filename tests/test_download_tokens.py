from datetime import datetime, timedelta, timezone

import pytest


def test_download_token_is_hashed_and_one_time(tmp_path, monkeypatch):
    db_path = tmp_path / "web.sqlite"
    allowed = tmp_path / "out"
    allowed.mkdir()
    ovpn = allowed / "client.ovpn"
    ovpn.write_text("client-config", encoding="utf-8")

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("OUT_DIR", str(allowed))
    monkeypatch.setenv("SHARE_OUT_DIR", str(allowed))
    monkeypatch.setenv("ARCHIVE_DIR", str(allowed))

    from app.db import init_db, reset_engine_cache
    from app.download_tokens import consume_download_token, create_download_token

    reset_engine_cache()
    init_db()
    token, record = create_download_token(
        client_name="client",
        file_path=ovpn,
        file_type="ovpn",
        created_by="admin",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )

    assert token not in record.token_hash
    consumed = consume_download_token(token)
    assert consumed.client_name == "client"
    assert consume_download_token(token) is None


def test_allowed_file_rejects_paths_outside_configured_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "out"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    good = allowed / "client.ovpn"
    bad = denied / "client.ovpn"
    good.write_text("ok", encoding="utf-8")
    bad.write_text("bad", encoding="utf-8")

    monkeypatch.setenv("OUT_DIR", str(allowed))
    monkeypatch.setenv("SHARE_OUT_DIR", str(allowed))
    monkeypatch.setenv("ARCHIVE_DIR", str(allowed))

    from app.download_tokens import assert_allowed_file

    assert assert_allowed_file(good) == good.resolve()
    with pytest.raises(ValueError):
        assert_allowed_file(bad)
