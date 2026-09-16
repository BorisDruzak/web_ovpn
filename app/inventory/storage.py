from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


class InventoryPhotoError(ValueError):
    """An upload does not meet inventory image storage policy."""


@dataclass(frozen=True)
class StoredPhoto:
    storage_path: str
    original_filename: str
    mime_type: str
    size_bytes: int


_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (b"RIFF", "image/webp", ".webp"),
)


class InventoryPhotoStorage:
    def __init__(self, root: Path, *, max_bytes: int) -> None:
        self.root = root.resolve()
        self.max_bytes = max_bytes

    def save(self, original_filename: str, declared_mime: str, content: bytes) -> StoredPhoto:
        if not content or len(content) > self.max_bytes:
            raise InventoryPhotoError("image size exceeds the limit")
        mime_type, suffix = self._detect_image(content)
        if declared_mime.strip().lower() != mime_type:
            raise InventoryPhotoError("image MIME type is invalid")
        self.root.mkdir(parents=True, exist_ok=True)
        storage_path = f"{uuid4()}{suffix}"
        target = self._resolve(storage_path)
        try:
            target.write_bytes(content)
        except OSError as exc:
            raise InventoryPhotoError("image storage is unavailable") from exc
        return StoredPhoto(
            storage_path=storage_path,
            original_filename=self._safe_original_name(original_filename),
            mime_type=mime_type,
            size_bytes=len(content),
        )

    def delete(self, stored: StoredPhoto) -> None:
        try:
            self._resolve(stored.storage_path).unlink(missing_ok=True)
        except OSError as exc:
            raise InventoryPhotoError("image deletion failed") from exc

    def cleanup_many(self, stored: tuple[StoredPhoto, ...] | list[StoredPhoto]) -> None:
        for item in stored:
            try:
                self.delete(item)
            except InventoryPhotoError:
                continue

    def path_for(self, storage_path: str) -> Path:
        return self._resolve(storage_path)

    def _resolve(self, storage_path: str) -> Path:
        candidate = (self.root / storage_path).resolve()
        if candidate.parent != self.root:
            raise InventoryPhotoError("image storage path is invalid")
        return candidate

    @staticmethod
    def _safe_original_name(value: str) -> str:
        name = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
        return name[:255] or "image"

    @staticmethod
    def _detect_image(content: bytes) -> tuple[str, str]:
        if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
            return "image/webp", ".webp"
        for signature, mime_type, suffix in _IMAGE_SIGNATURES[:2]:
            if content.startswith(signature):
                return mime_type, suffix
        raise InventoryPhotoError("image content is invalid")
