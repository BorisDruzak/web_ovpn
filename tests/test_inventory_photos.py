from __future__ import annotations

import base64

import pytest


PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL3NwAAAABJRU5ErkJggg=="
)


def test_storage_uses_generated_name_and_validates_real_image_bytes(tmp_path):
    """Trusting a browser filename or MIME field would allow non-image storage and traversal."""
    from app.inventory.storage import InventoryPhotoStorage

    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=4096)
    stored = storage.save("../../serial.png", "image/png", PNG_BYTES)

    assert stored.mime_type == "image/png"
    assert stored.original_filename == "serial.png"
    assert stored.storage_path.endswith(".png")
    assert (tmp_path / "photos" / stored.storage_path).read_bytes() == PNG_BYTES
    assert ".." not in stored.storage_path


def test_storage_rejects_unknown_image_content(tmp_path):
    """An unknown signature must leave no untrusted file in the photo root."""
    from app.inventory.storage import InventoryPhotoError, InventoryPhotoStorage

    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=4096)

    with pytest.raises(InventoryPhotoError, match="image"):
        storage.save("image.png", "image/png", b"not an image")

    assert not (tmp_path / "photos").exists() or list((tmp_path / "photos").iterdir()) == []


def test_storage_rejects_oversize_and_cleanup_removes_created_file(tmp_path):
    """Oversize uploads and failed transactions must not consume persistent disk space."""
    from app.inventory.storage import InventoryPhotoError, InventoryPhotoStorage

    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=len(PNG_BYTES) - 1)
    with pytest.raises(InventoryPhotoError, match="size"):
        storage.save("image.png", "image/png", PNG_BYTES)

    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=4096)
    stored = storage.save("image.png", "image/png", PNG_BYTES)
    storage.cleanup_many((stored,))

    assert not (tmp_path / "photos" / stored.storage_path).exists()
