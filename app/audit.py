from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from .models import WebAuditLog, WebUser


def write_audit(
    db: Session,
    request: Request,
    actor: WebUser | str | None,
    action: str,
    result: str,
    message: str = "",
    target_client: str | None = None,
) -> None:
    if isinstance(actor, WebUser):
        actor_name = actor.username
    else:
        actor_name = actor or "anonymous"
    db.add(
        WebAuditLog(
            actor=actor_name,
            action=action,
            target_client=target_client,
            result=result,
            message=message[:4000],
            request_id=str(getattr(request.state, "request_id", "")),
            ip_address=request.client.host if request.client else "",
        )
    )
    db.commit()
