from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from ..normalizer import normalize_mac


DEFAULT_OUI_PATH = Path("/usr/share/nmap/nmap-mac-prefixes")
_HEX_PREFIX = re.compile(r"[0-9A-Fa-f]{6,12}\Z")


@lru_cache(maxsize=16)
def _load_prefixes(path_text: str) -> tuple[tuple[str, str], ...]:
    path = Path(path_text)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()
    prefixes: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2 or _HEX_PREFIX.fullmatch(parts[0]) is None:
            continue
        vendor = " ".join(parts[1].split())
        if vendor:
            prefixes.setdefault(parts[0].upper(), vendor[:256])
    return tuple(
        sorted(prefixes.items(), key=lambda item: (-len(item[0]), item[0]))
    )


class OUIDatabase:
    """Lazy, read-only, in-memory view of a local Nmap MAC prefix file."""

    def __init__(self, path: str | Path = DEFAULT_OUI_PATH) -> None:
        self.path = Path(path)

    def lookup(self, mac: object) -> str:
        normalized = normalize_mac(mac)
        if normalized is None:
            return ""
        compact = normalized.replace(":", "")
        for prefix, vendor in _load_prefixes(str(self.path)):
            if compact.startswith(prefix):
                return vendor
        return ""
