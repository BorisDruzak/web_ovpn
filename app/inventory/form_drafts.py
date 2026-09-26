"""Owned, expiring form processes. Cookies never carry card values."""
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException, Request
from sqlalchemy import delete, select, update

from ..models import utcnow
from .models import InventoryFormDraft

TTL = timedelta(hours=48)
MAX_DRAFT_BYTES = 2 * 1024 * 1024


def with_draft(url: str, identifier: str) -> str:
    parts = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != "draft_id"]
    query.append(("draft_id", identifier))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def owned(db, user, identifier: str, *, purpose: str | None = None):
    draft = db.get(InventoryFormDraft, identifier)
    if draft is None or draft.owner_id != user.id:
        raise HTTPException(404, "Черновик не найден")
    if draft.expires_at <= utcnow():
        raise HTTPException(410, "Срок хранения черновика истёк. Начните новую карточку.")
    if purpose is not None and draft.purpose != purpose:
        raise HTTPException(400, "Черновик относится к другой карточке")
    return draft


def get_process(request: Request, db, user, purpose: str, *, base_revision: int | None = None):
    identifier = request.query_params.get("draft_id")
    if identifier:
        draft = owned(db, user, identifier, purpose=purpose)
        created = False
    else:
        # At most 100 expired documents per new process; bounded cleanup only.
        cleanup_expired(db)
        draft = InventoryFormDraft(owner_id=user.id, purpose=purpose, base_revision=base_revision,
            expires_at=utcnow() + TTL)
        db.add(draft)
        db.commit()
        created = True
    request.state.form_draft = draft
    # Remove legacy signed-cookie card/lookup payloads on the first new flow.
    for key in list(request.session):
        if key.startswith(("inventory_new_asset_", "inventory_asset_edit_draft:", "inventory_lookup_")):
            request.session.pop(key, None)
    return draft, created


async def posted_process(request: Request, db, user, purpose: str):
    form = await request.form()
    identifier = str(form.get("draft_id") or "")
    if not identifier:
        raise HTTPException(428, "Откройте форму заново: требуется идентификатор черновика")
    draft = owned(db, user, identifier, purpose=purpose)
    request.state.form_draft = draft
    return draft


def claim_for_save(db, draft):
    # The UPDATE acquires the outer write transaction before any card write.
    # A concurrent second sender waits; after the winner consumes this draft it
    # matches zero rows and cannot create a second card.
    claimed = db.execute(update(InventoryFormDraft).where(
        InventoryFormDraft.id == draft.id, InventoryFormDraft.owner_id == draft.owner_id,
        InventoryFormDraft.expires_at > utcnow(),
    ).values(revision=InventoryFormDraft.revision + 1).execution_options(synchronize_session=False))
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Этот процесс заполнения уже завершён или истёк. Откройте карточку заново.")
    db.refresh(draft)


def retain(db, draft, fields):
    values = dict(fields)
    if draft.purpose.startswith("inventory_asset_edit_draft:"):
        values["expected_revision"] = str(draft.base_revision)
    draft.fields_json = values
    draft.updated_at = utcnow()
    draft.revision += 1
    db.commit()


def cleanup_expired(db, *, batch_size: int = 100) -> int:
    limit = min(max(int(batch_size), 1), 100)
    expired = list(db.scalars(select(InventoryFormDraft.id).where(InventoryFormDraft.expires_at <= utcnow()).limit(limit)))
    if expired:
        db.execute(delete(InventoryFormDraft).where(InventoryFormDraft.id.in_(expired)))
    return len(expired)


if __name__ == "__main__":
    # One bounded pass against the configured existing DB. No network commands,
    # user bootstrap, card deletion or schema creation occurs here.
    from ..db import session_scope
    with session_scope() as session:
        removed = cleanup_expired(session)
    print(f"Expired form drafts removed: {removed}")
