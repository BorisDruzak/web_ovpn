from __future__ import annotations

import base64

import pytest

from app.inventory.storage import InventoryPhotoError, InventoryPhotoStorage


PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL3NwAAAABJRU5ErkJggg=="
)
JPEG_BYTES = b"\xff\xd8\xff\xe0camera-jpeg"
WEBP_BYTES = b"RIFF\x04\x00\x00\x00WEBPVP8 "


@pytest.mark.parametrize(
    ("content", "reported_mime", "expected_mime"),
    [
        (PNG_BYTES, "application/octet-stream", "image/png"),
        (JPEG_BYTES, "", "image/jpeg"),
        (WEBP_BYTES, "image/jpeg", "image/webp"),
    ],
)
def test_photo_storage_uses_signature_not_browser_mime(tmp_path, content, reported_mime, expected_mime):
    """A mobile browser MIME mistake must not reject a known camera image signature."""
    stored = InventoryPhotoStorage(tmp_path, max_bytes=1024).save("camera-image", reported_mime, content)

    assert stored.mime_type == expected_mime


@pytest.mark.parametrize(
    ("content", "max_bytes", "message"),
    [
        (b"not an image", 1024, "image content is invalid"),
        (PNG_BYTES, len(PNG_BYTES) - 1, "image size exceeds the limit"),
    ],
)
def test_photo_storage_rejects_unknown_or_oversize_content_without_creating_a_file(tmp_path, content, max_bytes, message):
    """Removing browser-MIME validation must not weaken content or size validation."""
    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=max_bytes)

    with pytest.raises(InventoryPhotoError, match=message):
        storage.save("camera-image", "application/octet-stream", content)

    assert not storage.root.exists()


def test_photo_storage_keeps_paths_safe_and_cleanup_removes_saved_file(tmp_path):
    """A browser filename cannot escape the photo root, and rollback cleanup removes the generated file."""
    storage = InventoryPhotoStorage(tmp_path / "photos", max_bytes=1024)
    stored = storage.save("../../camera.png", "", PNG_BYTES)

    assert stored.original_filename == "camera.png"
    with pytest.raises(InventoryPhotoError, match="path"):
        storage.path_for("../outside.png")

    storage.cleanup_many((stored,))

    assert not (storage.root / stored.storage_path).exists()
