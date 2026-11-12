"""Read Helpdesk account linkage by exact inventory employee UUID."""

from dataclasses import dataclass
import json
from pathlib import Path
import ssl
from time import monotonic
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx

from ..config import get_settings

STATUS_PATH = "/api/internal/inventory/v1/helpdesk-account-status"
BATCH_SIZE = 250
MAX_RESPONSE_BYTES = 128 * 1024


@dataclass(frozen=True)
class AccountLink:
    person_id: str
    user_login: str


def _origin() -> str | None:
    try:
        raw = get_settings().helpdesk_inventory_status_base_url
        url = urlsplit(raw)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.path not in {"", "/"} or url.query or url.fragment
                or "\\" in url.netloc or any(ch.isspace() for ch in url.netloc)):
            return None
        return f"https://{url.netloc}"
    except ValueError:
        return None


def profile_url(link: AccountLink) -> str | None:
    origin = _origin()
    return f"{origin}/app/admin/users?{urlencode({'person': link.person_id})}" if origin else None


def _decode(raw: bytes, expected: set[str]) -> dict[str, AccountLink]:
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != {"linked"} or not isinstance(payload["linked"], list):
        raise ValueError("Invalid account status response")
    linked = {}
    for row in payload["linked"]:
        if not isinstance(row, dict) or set(row) != {"inventory_person_id", "person_id", "user_login"}:
            raise ValueError("Invalid account link")
        inventory_id, person_id, login = row["inventory_person_id"], row["person_id"], row["user_login"]
        if (not isinstance(inventory_id, str) or inventory_id not in expected or inventory_id in linked
                or not isinstance(person_id, str) or str(UUID(person_id)) != person_id
                or not isinstance(login, str) or not 1 <= len(login) <= 100 or not login.isprintable()):
            raise ValueError("Invalid account link")
        linked[inventory_id] = AccountLink(person_id, login)
    return linked


def read_links(person_ids: list[str]) -> dict[str, AccountLink] | None:
    """Return confirmed links, or None if any part of the lookup is unavailable."""
    if not person_ids:
        return {}
    settings = get_settings()
    origin = _origin()
    token_file = settings.helpdesk_inventory_status_token_file
    if not origin or not token_file:
        return None
    deadline = monotonic() + 4
    linked = {}
    try:
        with Path(token_file).open(encoding="ascii") as handle:
            token = handle.read(4097).strip()
        if not 32 <= len(token) <= 4096 or not token.isprintable() or any(ch.isspace() for ch in token):
            return None
        context = ssl.create_default_context(cafile=settings.helpdesk_inventory_status_ca_file or None)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "Accept-Encoding": "identity"}
        with httpx.Client(verify=context, follow_redirects=False, trust_env=False, headers=headers) as client:
            for offset in range(0, len(person_ids), BATCH_SIZE):
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return None
                batch = person_ids[offset:offset + BATCH_SIZE]
                with client.stream("POST", origin + STATUS_PATH, json={"inventory_person_ids": batch},
                                   timeout=min(remaining, 1.5)) as response:
                    if (response.status_code != 200
                            or response.headers.get("content-type", "").split(";")[0].strip() != "application/json"
                            or response.headers.get("content-encoding", "identity").lower() != "identity"):
                        return None
                    raw = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        raw.extend(chunk)
                        if len(raw) > MAX_RESPONSE_BYTES or monotonic() > deadline:
                            return None
                linked.update(_decode(raw, set(batch)))
    except (httpx.HTTPError, httpx.InvalidURL, OSError, ValueError):
        return None
    return linked
