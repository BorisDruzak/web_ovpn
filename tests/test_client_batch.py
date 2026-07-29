import zipfile
from pathlib import Path

import pytest


def test_names_from_text_and_csv_are_normalized_and_deduplicated():
    from app.client_batch import parse_batch_client_names

    assert parse_batch_client_names(
        "anna, bob\nanna ", b"client_name\ncarol\nbob\n"
    ) == ["anna", "bob", "carol"]


def test_csv_rejects_per_client_profile_override():
    from app.client_batch import ClientBatchInputError, parse_batch_client_names

    with pytest.raises(ClientBatchInputError, match="profile"):
        parse_batch_client_names("", b"client_name,profile\nalice,directum\n")


def test_zip_contains_only_requested_ovpn_files(tmp_path):
    from app.client_batch import create_batch_zip

    out = tmp_path / "out"
    out.mkdir()
    (out / "anna.ovpn").write_text("anna\n", encoding="utf-8")
    (out / "bob.ovpn").write_text("bob\n", encoding="utf-8")
    archive = create_batch_zip([out / "anna.ovpn", out / "bob.ovpn"], tmp_path / "batches", out)

    with zipfile.ZipFile(archive) as result:
        assert result.namelist() == ["anna.ovpn", "bob.ovpn"]
