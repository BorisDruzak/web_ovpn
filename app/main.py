from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .audit import write_audit
from .api import router as api_router
from .auth import authenticate_user, csrf_token, current_user, require_user, verify_csrf
from .auto_sync import force_client_sync, maybe_client_sync
from .config import get_settings
from .db import get_db, init_db
from .download_tokens import assert_allowed_file, consume_download_token
from .models import (
    ServerDraft,
    ServerDraftCheckOutbox,
    ServerDraftCleanupOutbox,
    WebAuditLog,
    WebUser,
    utcnow,
)
from .netctl_client import NetctlError, run_netctl
from .network_observer import CATEGORY_LABELS, DEVICE_TYPE_LABELS, NETWORK_FILTERS, SOURCE_LABELS, filter_unified_hosts, merge_unified_hosts
from .routeros_backups import list_routeros_backups
from .server_drafts import create_draft_request, make_draft_request, observer_public_key, read_public_result
from .vpnctl_client import VpnctlError, run_vpnctl

CLIENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SOURCE_RE = re.compile(r"^[A-Za-z0-9._-]+$")
BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="OpenVPN Web Manager")
app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().app_secret_key,
    session_cookie=get_settings().session_cookie_name,
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(api_router)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def status_class(value: Any) -> str:
    raw = str(value or "").lower()
    if raw in {"active", "connected", "valid", "ok", "true"}:
        return "ok"
    if raw in {"disabled", "warning"}:
        return "warn"
    if raw in {"deleted", "revoked", "error", "failed", "inactive"}:
        return "bad"
    return "muted"


def format_bytes(value: Any) -> str:
    try:
        number = int(value or 0)
    except (TypeError, ValueError):
        return "-"
    units = ["B", "KB", "MB", "GB"]
    size = float(number)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{number} B"


templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["category_labels"] = CATEGORY_LABELS
templates.env.globals["device_type_labels"] = DEVICE_TYPE_LABELS
templates.env.globals["source_labels"] = SOURCE_LABELS
templates.env.filters["status_class"] = status_class
templates.env.filters["format_bytes"] = format_bytes


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request.state.request_id = uuid.uuid4().hex[:16]
    return await call_next(request)


def add_flash(request: Request, category: str, message: str) -> None:
    flashes = list(request.session.get("flashes", []))
    flashes.append({"category": category, "message": message})
    request.session["flashes"] = flashes[-5:]


def pop_flashes(request: Request) -> list[dict[str, str]]:
    flashes = list(request.session.get("flashes", []))
    request.session["flashes"] = []
    return flashes


def render(
    request: Request,
    template: str,
    context: dict[str, Any],
    db: Session,
    status_code: int = 200,
) -> HTMLResponse:
    user = current_user(request, db)
    context.update(
        {
            "request": request,
            "user": user,
            "flashes": pop_flashes(request),
            "settings": get_settings(),
        }
    )
    return templates.TemplateResponse(template, context, status_code=status_code)


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def server_draft_or_404(db: Session, draft_id: str) -> ServerDraft:
    try:
        draft = db.get(ServerDraft, str(uuid.UUID(draft_id)))
    except ValueError as exc:
        raise HTTPException(status_code=404) from exc
    if draft is None:
        raise HTTPException(status_code=404)
    return draft


def queue_server_draft(
    draft: ServerDraft,
    action: str,
    expected_fingerprint: str | None = None,
    pin_generation: str | None = None,
) -> Path:
    request = make_draft_request(
        draft.id, draft.host, draft.ssh_user, draft.port, action, expected_fingerprint, pin_generation
    )
    return create_draft_request(get_settings().server_draft_queue_dir, request)


def publish_cleanup_outbox(db: Session) -> list[ServerDraftCleanupOutbox]:
    """Publish committed cleanup intents and leave failed attempts retryable.

    The only worker-visible operation happens here, after the deletion and
    outbox record have committed.  Re-publishing is safe because cleanup queue
    publication is exclusive and returns the existing terminal reservation.
    """
    pending = list(
        db.scalars(
            select(ServerDraftCleanupOutbox)
            .where(ServerDraftCleanupOutbox.status == "pending")
            .order_by(ServerDraftCleanupOutbox.id)
        )
    )
    for intent in pending:
        intent.attempts += 1
        try:
            request = make_draft_request(intent.draft_id, "cleanup", "cleanup", 22, "cleanup")
            create_draft_request(get_settings().server_draft_queue_dir, request)
        except (OSError, ValueError):
            intent.last_error = "queue unavailable"
        else:
            intent.status = "published"
            intent.last_error = ""
            intent.published_at = utcnow()
        try:
            db.commit()
        except SQLAlchemyError:
            # The existing durable intent remains pending if this status update
            # cannot commit.  Its idempotent queue publication can be retried.
            db.rollback()
    return pending


def publish_check_outbox(db: Session) -> list[ServerDraftCheckOutbox]:
    """Publish committed check intents and keep failed attempts retryable."""
    pending = list(
        db.scalars(
            select(ServerDraftCheckOutbox)
            .where(ServerDraftCheckOutbox.status == "pending")
            .order_by(ServerDraftCheckOutbox.id)
        )
    )
    for intent in pending:
        intent.attempts += 1
        draft = db.get(ServerDraft, intent.draft_id)
        if draft is None:
            intent.status = "cancelled"
            intent.last_error = "draft unavailable"
        else:
            try:
                queue_server_draft(draft, "check", pin_generation=intent.pin_generation)
            except (OSError, ValueError):
                intent.last_error = "queue unavailable"
            else:
                intent.status = "published"
                intent.last_error = ""
                intent.published_at = utcnow()
        try:
            db.commit()
        except SQLAlchemyError:
            # The durable queued audit/intent stays pending. Re-publication is
            # safe because the worker consumes each pin generation at most once.
            db.rollback()
    return pending


def add_server_draft_check_intent(
    db: Session,
    request: Request,
    user: WebUser,
    draft_id: str,
    pin_generation: str,
) -> None:
    """Stage the durable outbox row and queued audit in one DB transaction."""
    db.add(ServerDraftCheckOutbox(draft_id=draft_id, pin_generation=pin_generation))
    db.add(
        WebAuditLog(
            actor=user.username,
            action="server-draft-check",
            target_client=draft_id,
            result="queued",
            message=f"pin-generation:{pin_generation}",
            request_id=str(getattr(request.state, "request_id", "")),
            ip_address=request.client.host if request.client else "",
        )
    )


def has_server_draft_audit(
    db: Session, draft_id: str, action: str, pin_generation: str
) -> bool:
    statement = select(WebAuditLog.id).where(
        WebAuditLog.action == action,
        WebAuditLog.result == "ok",
        WebAuditLog.target_client == draft_id,
        WebAuditLog.message == f"pin-generation:{pin_generation}",
    )
    return db.scalar(statement) is not None


def has_server_draft_check_intent(
    db: Session, draft_id: str, pin_generation: str
) -> bool:
    statement = select(ServerDraftCheckOutbox.id).where(
        ServerDraftCheckOutbox.draft_id == draft_id,
        ServerDraftCheckOutbox.pin_generation == pin_generation,
    )
    return db.scalar(statement) is not None


def is_server_draft_queued(draft_id: str) -> bool:
    queue_dir = get_settings().server_draft_queue_dir
    return any(
        (queue_dir / name).is_file()
        for name in (
            f"{draft_id}.json",
            f".{draft_id}.json.claim",
            f"{draft_id}.cleanup.json",
            f".{draft_id}.cleanup.json.claim",
            f"{draft_id}.deleted",
        )
    )


def is_confirmed_server_draft(
    db: Session, draft_id: str, result: dict[str, str]
) -> tuple[bool, str | None]:
    pin_generation = result.get("pin_generation") if result.get("status") == "ok" else None
    confirmed = bool(
        pin_generation
        and result.get("fingerprint")
        and result.get("checked_at")
        and has_server_draft_audit(db, draft_id, "server-draft-confirm", pin_generation)
    )
    return confirmed, pin_generation


def require_client_name(client: str) -> str:
    if not CLIENT_RE.match(client or ""):
        raise HTTPException(status_code=400, detail="Недопустимое имя клиента")
    return client


def require_source_name(source: str) -> str:
    if not SOURCE_RE.match(source or ""):
        raise HTTPException(status_code=400, detail="Недопустимое имя источника")
    return source


@app.get("/network/server-drafts", response_class=HTMLResponse)
def server_drafts_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    rows = []
    for draft in db.scalars(select(ServerDraft).order_by(ServerDraft.created_at.desc())):
        result = read_public_result(get_settings().server_draft_results_dir, draft.id)
        confirmed, pin_generation = is_confirmed_server_draft(db, draft.id, result)
        queued = is_server_draft_queued(draft.id)
        check_queued = bool(
            pin_generation
            and has_server_draft_check_intent(db, draft.id, pin_generation)
        )
        rows.append(
            {
                "draft": draft,
                "result": result,
                "confirmed": confirmed,
                "can_confirm": (
                    result.get("status") == "pending" and bool(result.get("fingerprint")) and not queued
                ),
                "can_check": confirmed and not queued and not check_queued,
                "can_scan": not result.get("fingerprint") and not confirmed and not queued,
            }
        )
    cleanup_outbox = list(
        db.scalars(
            select(ServerDraftCleanupOutbox)
            .where(ServerDraftCleanupOutbox.status == "pending")
            .order_by(ServerDraftCleanupOutbox.created_at)
        )
    )
    check_outbox = list(
        db.scalars(
            select(ServerDraftCheckOutbox)
            .where(ServerDraftCheckOutbox.status == "pending")
            .order_by(ServerDraftCheckOutbox.created_at)
        )
    )
    return render(
        request,
        "server_drafts.html",
        {"drafts": rows, "cleanup_outbox": cleanup_outbox, "check_outbox": check_outbox},
        db,
    )


@app.get("/network/server-drafts/new", response_class=HTMLResponse)
def server_draft_new_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return render(request, "server_draft_new.html", {}, db)


@app.get("/network/server-drafts/public-key")
def server_draft_public_key(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    try:
        key = observer_public_key(get_settings().observer_public_key_path)
    except ValueError:
        raise HTTPException(status_code=404, detail="Observer public key is unavailable") from None
    return PlainTextResponse(key, headers={"Content-Disposition": 'attachment; filename="openvpm-observer.pub"'})


@app.post("/network/server-drafts/new")
async def server_draft_create(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    name = str(form.get("name") or "").strip()
    host = str(form.get("host") or "").strip()
    ssh_user = str(form.get("ssh_user") or "").strip()
    try:
        port = int(str(form.get("port") or "22"))
        if not 1 <= len(name) <= 120 or "\n" in name or "\r" in name:
            raise ValueError("name is invalid")
        draft = ServerDraft(id=str(uuid.uuid4()), name=name, host=host, ssh_user=ssh_user, port=port)
        make_draft_request(draft.id, draft.host, draft.ssh_user, draft.port, "scan")
    except (TypeError, ValueError):
        write_audit(db, request, user, "server-draft-create", "error", "invalid request")
        add_flash(request, "bad", "Проверьте параметры тестового сервера")
        return redirect("/network/server-drafts/new")
    db.add(draft)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        try:
            write_audit(db, request, user, "server-draft-create", "error", "persistence unavailable")
        except SQLAlchemyError:
            db.rollback()
        add_flash(request, "bad", "Не удалось сохранить тестовый сервер")
        return redirect("/network/server-drafts/new")
    try:
        queue_server_draft(draft, "scan")
    except (OSError, ValueError):
        write_audit(db, request, user, "server-draft-create", "error", "queue unavailable", target_client=draft.id)
        add_flash(request, "bad", "Сервер сохранен, но проверка не поставлена в очередь")
        return redirect("/network/server-drafts")
    write_audit(db, request, user, "server-draft-create", "ok", "queued", target_client=draft.id)
    add_flash(request, "ok", "Проверка сервера поставлена в очередь")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/{draft_id}/scan")
async def server_draft_scan(draft_id: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    draft = server_draft_or_404(db, draft_id)
    result = read_public_result(get_settings().server_draft_results_dir, draft.id)
    if result.get("fingerprint"):
        write_audit(db, request, user, "server-draft-scan", "error", "invalid state", target_client=draft.id)
        add_flash(request, "bad", "Сначала завершите текущую проверку отпечатка")
        return redirect("/network/server-drafts")
    try:
        queue_server_draft(draft, "scan")
    except (OSError, ValueError):
        write_audit(db, request, user, "server-draft-scan", "error", "invalid request", target_client=draft.id)
        add_flash(request, "bad", "Не удалось поставить проверку в очередь")
    else:
        write_audit(db, request, user, "server-draft-scan", "ok", "queued", target_client=draft.id)
        add_flash(request, "ok", "Проверка сервера поставлена в очередь")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/{draft_id}/confirm")
async def server_draft_confirm(draft_id: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    draft = server_draft_or_404(db, draft_id)
    result = read_public_result(get_settings().server_draft_results_dir, draft.id)
    fingerprint = result.get("fingerprint") if result.get("status") == "pending" else None
    if not fingerprint:
        write_audit(db, request, user, "server-draft-confirm", "error", "not confirmable", target_client=draft.id)
        add_flash(request, "bad", "Нет подтверждаемого отпечатка")
        return redirect("/network/server-drafts")
    try:
        pin_generation = str(uuid.uuid4())
        queue_server_draft(draft, "confirm", fingerprint, pin_generation)
    except (OSError, ValueError):
        write_audit(db, request, user, "server-draft-confirm", "error", "not confirmable", target_client=draft.id)
        add_flash(request, "bad", "Нет подтверждаемого отпечатка")
    else:
        write_audit(
            db, request, user, "server-draft-confirm", "ok",
            f"pin-generation:{pin_generation}", target_client=draft.id,
        )
        add_flash(request, "ok", "Отпечаток подтвержден и поставлен в очередь")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/{draft_id}/check")
async def server_draft_check(draft_id: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    draft = server_draft_or_404(db, draft_id)
    result = read_public_result(get_settings().server_draft_results_dir, draft.id)
    confirmed, pin_generation = is_confirmed_server_draft(db, draft.id, result)
    already_checked = bool(
        pin_generation
        and has_server_draft_check_intent(db, draft.id, pin_generation)
    )
    if not confirmed or not pin_generation or already_checked:
        write_audit(db, request, user, "server-draft-check", "error", "not confirmed", target_client=draft.id)
        add_flash(request, "bad", "Сначала подтвердите найденный отпечаток")
        return redirect("/network/server-drafts")
    try:
        add_server_draft_check_intent(db, request, user, draft.id, pin_generation)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        add_flash(request, "bad", "Не удалось надежно зафиксировать SSH-проверку")
        return redirect("/network/server-drafts")
    published = publish_check_outbox(db)
    intent = next(
        (
            item
            for item in published
            if item.draft_id == draft.id and item.pin_generation == pin_generation
        ),
        None,
    )
    if intent is not None and intent.status == "published":
        add_flash(request, "ok", "SSH-проверка поставлена в очередь")
    else:
        add_flash(request, "bad", "SSH-проверка зафиксирована, но публикация ожидает повтора")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/{draft_id}/delete")
async def server_draft_delete(draft_id: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    draft = server_draft_or_404(db, draft_id)
    draft_id = draft.id
    for check_intent in db.scalars(
        select(ServerDraftCheckOutbox).where(
            ServerDraftCheckOutbox.draft_id == draft_id,
            ServerDraftCheckOutbox.status == "pending",
        )
    ):
        check_intent.status = "cancelled"
        check_intent.last_error = "draft deleted"
    db.delete(draft)
    db.add(ServerDraftCleanupOutbox(draft_id=draft_id))
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        write_audit(db, request, user, "server-draft-delete", "error", "persistence unavailable", target_client=draft_id)
        add_flash(request, "bad", "Не удалось удалить тестовый сервер")
        return redirect("/network/server-drafts")
    published = publish_cleanup_outbox(db)
    if any(intent.draft_id == draft_id and intent.status == "published" for intent in published):
        write_audit(db, request, user, "server-draft-delete", "ok", "cleanup published", target_client=draft_id)
        add_flash(request, "ok", "Тестовый сервер удален")
    else:
        write_audit(db, request, user, "server-draft-delete", "error", "cleanup pending", target_client=draft_id)
        add_flash(request, "bad", "Тестовый сервер удален, очистка ожидает повторной отправки")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/check-retry")
async def server_draft_check_retry(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    pending = publish_check_outbox(db)
    if any(intent.status == "pending" for intent in pending):
        write_audit(db, request, user, "server-draft-check-retry", "error", "check pending")
        add_flash(request, "bad", "Не удалось повторно опубликовать SSH-проверку")
    else:
        write_audit(db, request, user, "server-draft-check-retry", "ok", "check published")
        add_flash(request, "ok", "SSH-проверка повторно опубликована")
    return redirect("/network/server-drafts")


@app.post("/network/server-drafts/cleanup-retry")
async def server_draft_cleanup_retry(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    pending = publish_cleanup_outbox(db)
    if any(intent.status == "pending" for intent in pending):
        write_audit(db, request, user, "server-draft-cleanup-retry", "error", "cleanup pending")
        add_flash(request, "bad", "Не удалось повторно отправить очистку")
    else:
        write_audit(db, request, user, "server-draft-cleanup-retry", "ok", "cleanup published")
        add_flash(request, "ok", "Очистка повторно отправлена")
    return redirect("/network/server-drafts")


def cli_call(request: Request, args: list[str], timeout: int | None = None) -> tuple[dict[str, Any], str | None]:
    try:
        return run_vpnctl(args, timeout=timeout), None
    except VpnctlError as exc:
        message = exc.message
        if exc.stderr:
            message = f"{message}: {exc.stderr.strip()[:500]}"
        return {}, message


def net_cli_call(request: Request, args: list[str], timeout: int | None = None) -> tuple[dict[str, Any], str | None]:
    try:
        return run_netctl(args, timeout=timeout), None
    except NetctlError as exc:
        message = exc.message
        if exc.stderr:
            message = f"{message}: {exc.stderr.strip()[:500]}"
        elif exc.stdout:
            message = f"{message}: {exc.stdout.strip()[:500]}"
        return {}, message


def list_from(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key, [])
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def profiles_list(data: dict[str, Any]) -> list[dict[str, Any]]:
    profiles = data.get("profiles", [])
    if isinstance(profiles, dict):
        return [{"name": key, "description": str(value)} for key, value in profiles.items()]
    if isinstance(profiles, list):
        return [item for item in profiles if isinstance(item, dict)]
    return []


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if current_user(request, db):
        return redirect("/")
    return render(request, "login.html", {}, db)


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    await verify_csrf(request)
    form = await request.form()
    user = authenticate_user(db, str(form.get("username") or ""), str(form.get("password") or ""))
    if user is None:
        add_flash(request, "bad", "Неверный логин или пароль")
        write_audit(db, request, form.get("username") or "anonymous", "login", "error", "bad credentials")
        return redirect("/login")
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    write_audit(db, request, user, "login", "ok")
    return redirect("/")


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await verify_csrf(request)
    actor = current_user(request, db)
    if actor:
        write_audit(db, request, actor, "logout", "ok")
    request.session.clear()
    return redirect("/login")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    status, status_error = cli_call(request, ["status"])
    clients_data, clients_error = cli_call(request, ["list"])
    connected_data, connected_error = cli_call(request, ["connected"])
    errors = [err for err in [status_error, clients_error, connected_error] if err]
    clients = list_from(clients_data, "clients")
    connected = list_from(connected_data, "connected")
    return render(
        request,
        "dashboard.html",
        {"status": status, "clients_count": len(clients), "connected_count": len(connected), "errors": errors},
        db,
    )


@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    sync_error = maybe_client_sync(db, request, user, "clients page")
    data, error = cli_call(request, ["list"])
    profiles_data, _ = cli_call(request, ["profiles"])
    rows = list_from(data, "clients")
    query = (request.query_params.get("q") or "").lower()
    profile = request.query_params.get("profile") or ""
    status = request.query_params.get("status") or ""
    connected = request.query_params.get("connected") or ""
    if query:
        rows = [row for row in rows if query in str(row.get("name", "")).lower()]
    if profile:
        rows = [row for row in rows if (row.get("profile") or row.get("detected_profile") or "") == profile]
    if status:
        rows = [row for row in rows if str(row.get("status") or "") == status]
    if connected == "yes":
        rows = [row for row in rows if row.get("connected")]
    if connected == "no":
        rows = [row for row in rows if not row.get("connected")]
    return render(
        request,
        "clients.html",
        {"clients": rows, "profiles": profiles_list(profiles_data), "error": error or sync_error},
        db,
    )


@app.post("/clients/sync")
async def clients_sync(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    data, error = force_client_sync(db, request, user, "manual button", action="manual-sync")
    if error:
        add_flash(request, "bad", error)
    else:
        count = data.get("imported_or_updated", 0)
        add_flash(request, "ok", f"Синхронизация выполнена: {count}")
    return redirect("/clients")


@app.get("/clients/new", response_class=HTMLResponse)
def new_client_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    profiles_data, error = cli_call(request, ["profiles"])
    return render(request, "client_new.html", {"profiles": profiles_list(profiles_data), "error": error}, db)


@app.post("/clients/new", response_class=HTMLResponse)
async def new_client_action(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    action = str(form.get("action") or "preview")
    client = require_client_name(str(form.get("client") or "").strip())
    profile = str(form.get("profile") or "").strip()
    vpn_ip = str(form.get("vpn_ip") or "").strip()
    client_type = str(form.get("client_type") or "user").strip()
    remote_lan_cidr = str(form.get("remote_lan_cidr") or "").strip()
    create_server_route = bool(form.get("create_server_route"))
    comment = str(form.get("comment") or "").strip()
    profiles_data, profiles_error = cli_call(request, ["profiles"])
    args = [action, client, profile]
    if vpn_ip:
        args.append(vpn_ip)
    args.extend(["--client-type", client_type])
    if remote_lan_cidr:
        args.extend(["--remote-lan", remote_lan_cidr])
    if create_server_route:
        args.append("--create-server-route")
    if action == "generate":
        args.extend(["--comment", comment])
    if action not in {"preview", "generate"}:
        raise HTTPException(status_code=400, detail="Недопустимое действие")
    result, error = cli_call(request, args, timeout=180 if action == "generate" else 60)
    sync_error = None
    if action == "generate" and not error:
        _, sync_error = force_client_sync(db, request, user, f"after generate {client}", action="auto-sync")
        if sync_error:
            add_flash(request, "bad", f"Профиль создан, но автосинхронизация не прошла: {sync_error}")
        else:
            add_flash(request, "ok", "Профиль создан, реестр синхронизирован автоматически")
    write_audit(
        db,
        request,
        user,
        f"client-{action}",
        "error" if error else "ok",
        error or f"profile={profile} vpn_ip={vpn_ip}",
        target_client=client,
    )
    return render(
        request,
        "client_new.html",
        {
            "profiles": profiles_list(profiles_data),
            "error": error or profiles_error or sync_error,
            "result": result,
            "form_values": {
                "client": client,
                "profile": profile,
                "vpn_ip": vpn_ip,
                "client_type": client_type,
                "remote_lan_cidr": remote_lan_cidr,
                "create_server_route": create_server_route,
                "comment": comment,
            },
        },
        db,
    )


@app.get("/clients/{client}", response_class=HTMLResponse)
def client_detail(client: str, request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    client = require_client_name(client)
    data, error = cli_call(request, ["inspect", client])
    connected = data.get("connected") if isinstance(data.get("connected"), dict) else {}
    ccd = data.get("ccd") if isinstance(data.get("ccd"), dict) else {}
    registry = data.get("registry") if isinstance(data.get("registry"), dict) else {}
    effective_vpn_ip = connected.get("virtual_address") or ccd.get("vpn_ip") or registry.get("vpn_ip") or ""
    return render(
        request,
        "client_detail.html",
        {"client": client, "detail": data, "error": error, "effective_vpn_ip": effective_vpn_ip},
        db,
    )


@app.get("/clients/{client}/edit", response_class=HTMLResponse)
def client_edit_page(client: str, request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    client = require_client_name(client)
    config, config_error = cli_call(request, ["config-view", client])
    templates_data, templates_error = cli_call(request, ["network-templates", "list"])
    networks_data, networks_error = cli_call(request, ["networks", "list"])
    return render(
        request,
        "client_edit.html",
        {
            "client": client,
            "config": config,
            "network_templates": templates_data.get("templates", []),
            "networks": networks_data.get("networks", []),
            "error": config_error or templates_error or networks_error,
        },
        db,
    )


def confirm_client_form(form: Any, client: str) -> bool:
    return str(form.get("confirm_name") or "") == client


def refresh_client_routes_after_access_change(
    request: Request,
    db: Session,
    user: WebUser,
    client: str,
    reason: str,
) -> str | None:
    data, error = cli_call(request, ["reconnect-client", client, "--reason", reason], timeout=60)
    status = data.get("status") if data else None
    write_audit(db, request, user, "reconnect-client", "error" if error else "ok", error or reason, target_client=client)
    if error:
        return error
    if status == "not_configured":
        return "OpenVPN management недоступен, клиент получит новые маршруты при следующем подключении"
    if status == "not_connected":
        return "Клиент сейчас не подключён, новые маршруты будут применены при следующем подключении"
    return None


@app.post("/clients/{client}/edit/template")
async def client_edit_template(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, применение шаблона отменено")
        return redirect(f"/clients/{client}/edit")
    template = str(form.get("template") or "").strip()
    vpn_ip = str(form.get("vpn_ip") or "").strip()
    reason = str(form.get("reason") or "network template applied from web UI").strip()
    args = ["client-template-apply", client, template]
    if vpn_ip:
        args.append(vpn_ip)
    args.extend(["--reason", reason])
    _, error = cli_call(request, args, timeout=180)
    write_audit(db, request, user, "network-template-apply", "error" if error else "ok", error or reason, target_client=client)
    if not error:
        _, sync_error = force_client_sync(db, request, user, f"after network template apply {client}", action="auto-sync")
        error = sync_error
    reconnect_warning = None
    if not error:
        reconnect_warning = refresh_client_routes_after_access_change(
            request,
            db,
            user,
            client,
            "route refresh after network template apply",
        )
    add_flash(
        request,
        "bad" if error else "ok",
        error or reconnect_warning or "Шаблон сетей применён, клиент переподключён для обновления маршрутов",
    )
    return redirect(f"/clients/{client}/edit")


@app.post("/clients/{client}/edit/networks")
async def client_edit_networks(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, применение сетей отменено")
        return redirect(f"/clients/{client}/edit")
    reason = str(form.get("reason") or "selected networks applied from web UI").strip()
    vpn_ip = str(form.get("vpn_ip") or "").strip()
    cidrs = [str(value) for value in form.getlist("cidr") if str(value).strip()]
    args = ["client-networks-apply", client]
    for cidr in cidrs:
        args.extend(["--cidr", cidr])
    if vpn_ip:
        args.append(vpn_ip)
    if form.get("dns") == "1":
        args.append("--dns")
    args.extend(["--reason", reason])
    _, error = cli_call(request, args, timeout=180)
    write_audit(db, request, user, "networks-apply", "error" if error else "ok", error or reason, target_client=client)
    if not error:
        _, sync_error = force_client_sync(db, request, user, f"after networks apply {client}", action="auto-sync")
        error = sync_error
    reconnect_warning = None
    if not error:
        reconnect_warning = refresh_client_routes_after_access_change(
            request,
            db,
            user,
            client,
            "route refresh after selected networks apply",
        )
    add_flash(
        request,
        "bad" if error else "ok",
        error or reconnect_warning or "Сети применены, клиент переподключён для обновления маршрутов",
    )
    return redirect(f"/clients/{client}/edit")


@app.post("/clients/{client}/edit/ovpn")
async def client_edit_ovpn(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, изменение OVPN отменено")
        return redirect(f"/clients/{client}/edit")
    reason = str(form.get("reason") or "ovpn edit from web UI").strip()
    content = str(form.get("content") or "")
    _, error = cli_call(request, ["ovpn-update", client, "--content", content, "--reason", reason], timeout=180)
    write_audit(db, request, user, "ovpn-update", "error" if error else "ok", error or reason, target_client=client)
    if not error:
        _, sync_error = force_client_sync(db, request, user, f"after OVPN update {client}", action="auto-sync")
        error = sync_error
    add_flash(request, "bad" if error else "ok", error or "OVPN сохранён, реестр синхронизирован")
    return redirect(f"/clients/{client}/edit")


@app.post("/clients/{client}/reconnect")
async def reconnect_client_route(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, переподключение отменено")
        return redirect(f"/clients/{client}")
    reason = str(form.get("reason") or "route refresh from web UI").strip()
    data, error = cli_call(request, ["reconnect-client", client, "--reason", reason], timeout=60)
    status = data.get("status") if data else None
    write_audit(db, request, user, "reconnect-client", "error" if error else "ok", error or reason, target_client=client)
    if error:
        add_flash(request, "bad", error)
    elif status == "ok":
        add_flash(request, "ok", "Клиент отключён через management и получит маршруты при переподключении")
    elif status == "not_connected":
        add_flash(request, "ok", "Клиент сейчас не подключён")
    elif status == "not_configured":
        add_flash(request, "bad", "OpenVPN management не настроен, точечное переподключение недоступно")
    else:
        add_flash(request, "bad", data.get("message") or "Не удалось подтвердить переподключение")
    return redirect(f"/clients/{client}")


@app.post("/clients/{client}/kill-session")
async def kill_client_session_route(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, отключение сессии отменено")
        return redirect(f"/clients/{client}")
    data, error = cli_call(request, ["management", "kill", client], timeout=60)
    write_audit(db, request, user, "management-kill", "error" if error else "ok", error or "client session kill", target_client=client)
    if error:
        add_flash(request, "bad", error)
    elif data.get("killed"):
        add_flash(request, "ok", "Активная сессия клиента отключена")
    else:
        add_flash(request, "ok", "Клиент сейчас не подключен")
    return redirect(f"/clients/{client}")


def file_path_from_inspect(detail: dict[str, Any], file_type: str) -> str:
    files = detail.get("files") if isinstance(detail, dict) else None
    if not isinstance(files, dict) or file_type not in {"ovpn", "bat"}:
        raise ValueError("Файл не найден в inspect")
    item = files.get(file_type) or {}
    if not item.get("exists"):
        raise ValueError("Файл отсутствует")
    return str(item.get("path") or "")


def should_repair_missing_ovpn(detail: dict[str, Any], file_type: str) -> bool:
    if file_type != "ovpn" or not isinstance(detail, dict):
        return False
    files = detail.get("files")
    if not isinstance(files, dict):
        return False
    ovpn = files.get("ovpn") or {}
    if ovpn.get("exists"):
        return False
    registry = detail.get("registry") or {}
    registry_status = str(registry.get("status") or "").lower() if isinstance(registry, dict) else ""
    if registry_status in {"revoked", "disabled", "deleted"}:
        return False
    return str(detail.get("cert_status") or "").lower() == "valid"


def repair_missing_ovpn_for_download(
    request: Request,
    db: Session,
    user: WebUser,
    client: str,
    file_type: str,
    detail: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    if not should_repair_missing_ovpn(detail, file_type):
        return detail, None
    repaired, repair_error = cli_call(
        request,
        ["repair-artifacts", client, "--reason", "download-link auto repair"],
        timeout=180,
    )
    write_audit(
        db,
        request,
        user,
        "repair-artifacts",
        "error" if repair_error else "ok",
        repair_error or ",".join(repaired.get("actions", [])),
        target_client=client,
    )
    if repair_error:
        return detail, repair_error
    refreshed, inspect_error = cli_call(request, ["inspect", client])
    return refreshed or detail, inspect_error


@app.post("/clients/{client}/download-link")
async def download_link(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    file_type = str(form.get("file_type") or "ovpn")
    detail, error = cli_call(request, ["inspect", client])
    if error:
        add_flash(request, "bad", error)
        write_audit(db, request, user, "download-file", "error", error, target_client=client)
        return redirect(f"/clients/{client}")
    detail, repair_error = repair_missing_ovpn_for_download(request, db, user, client, file_type, detail)
    if repair_error:
        add_flash(request, "bad", repair_error)
        write_audit(db, request, user, "download-file", "error", repair_error, target_client=client)
        return redirect(f"/clients/{client}")
    try:
        file_path = assert_allowed_file(file_path_from_inspect(detail, file_type))
    except ValueError as exc:
        add_flash(request, "bad", str(exc))
        write_audit(db, request, user, "download-file", "error", str(exc), target_client=client)
        return redirect(f"/clients/{client}")
    write_audit(db, request, user, "download-file", "ok", f"file_type={file_type}", target_client=client)
    return FileResponse(file_path, filename=file_path.name, media_type="application/octet-stream")


@app.get("/download/{token}")
def download(token: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    record = consume_download_token(token)
    if record is None:
        write_audit(db, request, user, "download", "error", "invalid or expired token")
        raise HTTPException(status_code=404, detail="Ссылка недействительна или истекла")
    try:
        path = assert_allowed_file(record.file_path)
    except ValueError as exc:
        write_audit(db, request, user, "download", "error", str(exc), target_client=record.client_name)
        raise HTTPException(status_code=404, detail="Файл недоступен") from exc
    write_audit(db, request, user, "download", "ok", record.file_type, target_client=record.client_name)
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@app.post("/clients/{client}/disable")
async def disable_client(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if str(form.get("confirm_name") or "") != client:
        add_flash(request, "bad", "Имя клиента не совпало, действие отменено")
        return redirect(f"/clients/{client}")
    reason = str(form.get("reason") or "disabled from web UI")
    _, error = cli_call(request, ["disable", client, "--reason", reason, "--kill-active"], timeout=180)
    write_audit(db, request, user, "disable", "error" if error else "ok", error or reason, target_client=client)
    if not error:
        _, sync_error = force_client_sync(db, request, user, f"after disable {client}", action="auto-sync")
        error = sync_error
    add_flash(request, "bad" if error else "ok", error or "Доступ отключён")
    return redirect(f"/clients/{client}")


@app.get("/connections", response_class=HTMLResponse)
def connections(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    data, error = cli_call(request, ["connected", "--source", "auto"])
    rows = list_from(data, "connected")
    for row in rows:
        row.pop("connected_since", None)
    return render(request, "connections.html", {"connections": rows, "source": data.get("source"), "error": error}, db)


@app.post("/connections/{client}/kill")
async def connection_kill(client: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    client = require_client_name(client)
    if not confirm_client_form(form, client):
        add_flash(request, "bad", "Имя клиента не совпало, отключение сессии отменено")
        return redirect("/connections")
    data, error = cli_call(request, ["management", "kill", client], timeout=60)
    write_audit(db, request, user, "management-kill", "error" if error else "ok", error or "connection page kill", target_client=client)
    if error:
        add_flash(request, "bad", error)
    elif data.get("killed"):
        add_flash(request, "ok", f"Сессия отключена: {client}")
    else:
        add_flash(request, "ok", f"Клиент не подключен: {client}")
    return redirect("/connections")


@app.get("/settings/openvpn", response_class=HTMLResponse)
def openvpn_settings(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    server_config, config_error = cli_call(request, ["server-config", "inspect"])
    status, status_error = cli_call(request, ["status"])
    management, management_error = cli_call(request, ["management", "test"])
    validation, validation_error = cli_call(request, ["validate-network-plan"])
    return render(
        request,
        "settings_openvpn.html",
        {
            "server_config": server_config,
            "services": status.get("services", {}),
            "management": management,
            "validation": validation,
            "addressing": validation.get("addressing", {}),
            "error": config_error or status_error or management_error or validation_error,
        },
        db,
    )


@app.post("/settings/openvpn/validate-network-plan")
async def openvpn_settings_validate_network_plan(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    data, error = cli_call(request, ["validate-network-plan"], timeout=60)
    write_audit(db, request, user, "openvpn-validate-network-plan", "error" if error else "ok", error or data.get("status", ""))
    if error:
        add_flash(request, "bad", error)
    else:
        add_flash(request, "ok" if data.get("status") == "ok" else "bad", f"Проверка сети: {data.get('status')}")
    return redirect("/settings/openvpn")


@app.post("/settings/openvpn/status-interval")
async def openvpn_settings_status_interval(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    try:
        interval = int(str(form.get("status_interval_seconds") or "10"))
    except ValueError:
        add_flash(request, "bad", "Период обновления должен быть числом")
        return redirect("/settings/openvpn")
    if interval < 5 or interval > 300:
        add_flash(request, "bad", "Период обновления должен быть от 5 до 300 секунд")
        return redirect("/settings/openvpn")
    _, error = cli_call(
        request,
        ["server-config", "apply", "--status-interval", str(interval), "--status-version", "2", "--restart"],
        timeout=180,
    )
    write_audit(db, request, user, "openvpn-settings-status-interval", "error" if error else "ok", error or str(interval))
    add_flash(request, "bad" if error else "ok", error or "Период обновления сохранен и применен")
    return redirect("/settings/openvpn")


@app.post("/settings/openvpn/management-enable")
async def openvpn_settings_management_enable(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    _, error = cli_call(
        request,
        [
            "server-config",
            "apply",
            "--enable-management",
            "--management-socket",
            "/run/openvpn/server.sock",
            "--management-client-group",
            "openvpn-web",
            "--management-log-cache",
            "300",
            "--restart",
        ],
        timeout=180,
    )
    write_audit(db, request, user, "openvpn-settings-management-enable", "error" if error else "ok", error or "enable management")
    add_flash(request, "bad" if error else "ok", error or "Management Interface включен")
    return redirect("/settings/openvpn")


@app.post("/settings/openvpn/management-test")
async def openvpn_settings_management_test(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    data, error = cli_call(request, ["management", "test"], timeout=60)
    write_audit(db, request, user, "openvpn-settings-management-test", "error" if error else "ok", error or str(data.get("available")))
    if error:
        add_flash(request, "bad", error)
    else:
        add_flash(request, "ok" if data.get("available") else "bad", "Management Interface доступен" if data.get("available") else "Management Interface недоступен")
    return redirect("/settings/openvpn")


@app.post("/settings/openvpn/restart")
async def openvpn_settings_restart(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    _, error = cli_call(request, ["server-config", "restart-openvpn"], timeout=180)
    write_audit(db, request, user, "openvpn-settings-restart", "error" if error else "ok", error or "restart")
    add_flash(request, "bad" if error else "ok", error or "OpenVPN перезапущен")
    return redirect("/settings/openvpn")


@app.get("/vipnet-nets", response_class=HTMLResponse)
def vipnet_nets_legacy(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return redirect("/networks")


@app.get("/networks", response_class=HTMLResponse)
def networks(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    nets, nets_error = cli_call(request, ["networks", "list"])
    nat, nat_error = cli_call(request, ["nat-status"])
    return render(
        request,
        "networks.html",
        {
            "networks": nets.get("networks", []),
            "nat": nat,
            "error": nets_error or nat_error,
        },
        db,
    )


@app.post("/networks/add")
async def network_add(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    cidr = str(form.get("cidr") or "").strip()
    tag = str(form.get("tag") or "default").strip()
    comment = str(form.get("comment") or "").strip()
    try:
        cidr = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError as exc:
        add_flash(request, "bad", f"Некорректный CIDR: {exc}")
        return redirect("/networks")
    args = ["networks", "add", cidr, "--tag", tag]
    if comment:
        args.extend(["--comment", comment])
    args.append("--nat" if form.get("nat") == "1" else "--no-nat")
    if form.get("restart_nat") == "1":
        args.append("--restart-nat")
    _, error = cli_call(request, args, timeout=180)
    write_audit(db, request, user, "network-add", "error" if error else "ok", error or cidr)
    add_flash(request, "bad" if error else "ok", error or f"Сеть добавлена: {cidr}")
    return redirect("/networks")


@app.post("/networks/remove")
async def network_remove(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    cidr = str(form.get("cidr") or "").strip()
    args = ["networks", "remove", cidr]
    if form.get("restart_nat") == "1":
        args.append("--restart-nat")
    _, error = cli_call(request, args, timeout=180)
    write_audit(db, request, user, "network-remove", "error" if error else "ok", error or cidr)
    add_flash(request, "bad" if error else "ok", error or f"Сеть удалена: {cidr}")
    return redirect("/networks")


@app.post("/vipnet-nets/add")
async def vipnet_add_legacy(request: Request, db: Session = Depends(get_db)):
    return redirect("/networks")


@app.post("/vipnet-nets/remove")
async def vipnet_remove_legacy(request: Request, db: Session = Depends(get_db)):
    return redirect("/networks")


@app.get("/network-templates", response_class=HTMLResponse)
def network_templates(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    data, error = cli_call(request, ["network-templates", "list"])
    return render(
        request,
        "network_templates.html",
        {
            "templates": data.get("templates", []),
            "networks": data.get("networks", []),
            "error": error,
        },
        db,
    )


@app.post("/network-templates/add")
async def network_template_add(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    name = str(form.get("name") or "").strip()
    description = str(form.get("description") or "").strip()
    cidrs = [str(value) for value in form.getlist("cidr") if str(value).strip()]
    args = ["network-templates", "add", name, "--description", description]
    for cidr in cidrs:
        args.extend(["--cidr", cidr])
    if form.get("dns") == "1":
        args.append("--dns")
    _, error = cli_call(request, args, timeout=180)
    write_audit(db, request, user, "network-template-add", "error" if error else "ok", error or name)
    add_flash(request, "bad" if error else "ok", error or f"Шаблон добавлен: {name}")
    return redirect("/network-templates")


@app.post("/network-templates/remove")
async def network_template_remove(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    name = str(form.get("name") or "").strip()
    _, error = cli_call(request, ["network-templates", "remove", name], timeout=180)
    write_audit(db, request, user, "network-template-remove", "error" if error else "ok", error or name)
    add_flash(request, "bad" if error else "ok", error or f"Шаблон удалён: {name}")
    return redirect("/network-templates")


@app.get("/network", response_class=HTMLResponse)
def network_root(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return redirect("/network/dashboard")


@app.get("/network/runtime-health")
def network_runtime_health(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    try:
        return run_vpnctl(["runtime-health"], timeout=15)
    except VpnctlError as exc:
        raise HTTPException(status_code=502, detail=str(exc.message)) from exc


@app.get("/network/dashboard", response_class=HTMLResponse)
def network_dashboard(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    dashboard_data, dashboard_error = net_cli_call(request, ["dashboard"])
    connected_data, connected_error = cli_call(request, ["connected", "--source", "auto"])
    summary = dashboard_data.get("summary", {})
    summary["vpn_connected"] = len(list_from(connected_data, "connected"))
    return render(
        request,
        "network_dashboard.html",
        {"summary": summary, "sources": dashboard_data.get("sources", []), "error": dashboard_error or connected_error},
        db,
    )


def unified_network_rows(request: Request) -> tuple[list[dict[str, Any]], str | None]:
    hosts_data, hosts_error = net_cli_call(request, ["hosts", "list"])
    connected_data, connected_error = cli_call(request, ["connected", "--source", "auto"])
    clients_data, clients_error = cli_call(request, ["list"])
    rows = merge_unified_hosts(
        list_from(hosts_data, "hosts"),
        list_from(connected_data, "connected"),
        list_from(clients_data, "clients"),
    )
    return rows, hosts_error or connected_error or clients_error


@app.get("/network/hosts", response_class=HTMLResponse)
def network_hosts(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    rows, error = unified_network_rows(request)
    filters = {
        "q": request.query_params.get("q") or "",
        "category": request.query_params.get("category") or "all",
        "status": request.query_params.get("status") or "all",
        "source": request.query_params.get("source") or "all",
        "network": request.query_params.get("network") or "all",
        "has_hostname": request.query_params.get("has_hostname") or "",
        "has_mac": request.query_params.get("has_mac") or "",
    }
    rows = filter_unified_hosts(rows, filters)
    sources_data, sources_error = net_cli_call(request, ["sources", "list"])
    return render(
        request,
        "network_hosts.html",
        {
            "hosts": rows,
            "filters": filters,
            "sources": sources_data.get("sources", []),
            "network_filters": NETWORK_FILTERS,
            "error": error or sources_error,
        },
        db,
    )


@app.get("/network/hosts/{ip}", response_class=HTMLResponse)
def network_host_detail(ip: str, request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    data, error = net_cli_call(request, ["hosts", "inspect", ip])
    rows, unified_error = unified_network_rows(request)
    vpn_row = next((row for row in rows if row.get("ip") == ip), None)
    return render(
        request,
        "network_host_detail.html",
        {"ip": ip, "detail": data, "host": data.get("host") or vpn_row or {}, "vpn_row": vpn_row, "error": error or unified_error},
        db,
    )


@app.get("/network/sources", response_class=HTMLResponse)
def network_sources(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    data, error = net_cli_call(request, ["sources", "list"])
    return render(request, "network_sources.html", {"sources": data.get("sources", []), "error": error}, db)


@app.get("/network/sources/new", response_class=HTMLResponse)
def network_source_new_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return render(request, "network_source_new.html", {"form_values": {}, "error": None}, db)


@app.post("/network/sources/new")
async def network_source_new(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    source = require_source_name(str(form.get("name") or "").strip())
    args = [
        "sources",
        "add-mikrotik",
        source,
        "--host",
        str(form.get("host") or "").strip(),
        "--port",
        str(form.get("port") or "8729").strip(),
        "--username",
        str(form.get("username") or "").strip(),
        "--secret-ref",
        str(form.get("secret_ref") or source).strip(),
        "--site",
        str(form.get("site") or "main").strip(),
        "--role",
        str(form.get("role") or "core-router").strip(),
    ]
    if form.get("tls") == "1":
        args.append("--tls")
    if form.get("verify_tls") == "1":
        args.append("--verify-tls")
    _, error = net_cli_call(request, args, timeout=60)
    write_audit(db, request, user, "network-source-add", "error" if error else "ok", error or source)
    if error:
        return render(request, "network_source_new.html", {"form_values": dict(form), "error": error}, db, status_code=400)
    add_flash(request, "ok", f"Источник добавлен: {source}. Пароль должен быть в /etc/netctl/secrets.env")
    return redirect("/network/sources")


@app.post("/network/sources/{source}/test")
async def network_source_test(source: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    source = require_source_name(source)
    _, error = net_cli_call(request, ["sources", "test", source], timeout=60)
    write_audit(db, request, user, "network-source-test", "error" if error else "ok", error or source)
    add_flash(request, "bad" if error else "ok", error or f"Источник доступен: {source}")
    return redirect("/network/sources")


@app.post("/network/sources/{source}/collect")
async def network_source_collect(source: str, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    source = require_source_name(source)
    data, error = net_cli_call(request, ["collect", source], timeout=180)
    write_audit(db, request, user, "network-source-collect", "error" if error else "ok", error or str(data.get("summary", {})))
    add_flash(request, "bad" if error else "ok", error or f"Сбор выполнен: {source}")
    return redirect("/network/sources")


@app.get("/network/interfaces", response_class=HTMLResponse)
def network_interfaces(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    source = request.query_params.get("source") or ""
    args = ["interfaces", "list"]
    if source:
        args.extend(["--source", require_source_name(source)])
    data, error = net_cli_call(request, args)
    sources_data, sources_error = net_cli_call(request, ["sources", "list"])
    return render(
        request,
        "network_interfaces.html",
        {"interfaces": data.get("interfaces", []), "sources": sources_data.get("sources", []), "selected_source": source, "error": error or sources_error},
        db,
    )


@app.get("/network/routes", response_class=HTMLResponse)
def network_routes(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    source = request.query_params.get("source") or ""
    args = ["routes", "list"]
    if source:
        args.extend(["--source", require_source_name(source)])
    data, error = net_cli_call(request, args)
    sources_data, sources_error = net_cli_call(request, ["sources", "list"])
    return render(
        request,
        "network_routes.html",
        {"routes": data.get("routes", []), "sources": sources_data.get("sources", []), "selected_source": source, "error": error or sources_error},
        db,
    )


@app.get("/network/ipsec", response_class=HTMLResponse)
def network_ipsec(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    source = request.query_params.get("source") or ""
    args = ["ipsec", "status"]
    if source:
        args.extend(["--source", require_source_name(source)])
    data, error = net_cli_call(request, args, timeout=60)
    sources_data, sources_error = net_cli_call(request, ["sources", "list"])
    return render(
        request,
        "network_ipsec.html",
        {
            "summary": data.get("summary", {}),
            "site_checks": data.get("site_checks", []),
            "ipsec_sources": data.get("sources", []),
            "sources": sources_data.get("sources", []),
            "selected_source": source,
            "error": error or sources_error,
        },
        db,
    )


@app.get("/network/backups", response_class=HTMLResponse)
def network_backups(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    settings = get_settings()
    backups, error = list_routeros_backups(settings.routeros_backup_dir)
    return render(
        request,
        "network_backups.html",
        {"backups": backups, "backup_dir": settings.routeros_backup_dir, "error": error},
        db,
    )


@app.get("/network/collect", response_class=HTMLResponse)
def network_collect_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    sources_data, sources_error = net_cli_call(request, ["sources", "list"])
    logs_data, logs_error = net_cli_call(request, ["logs", "-n", "30"])
    return render(
        request,
        "network_collect.html",
        {"sources": sources_data.get("sources", []), "events": logs_data.get("events", []), "error": sources_error or logs_error},
        db,
    )


@app.post("/network/collect")
async def network_collect_action(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    await verify_csrf(request)
    form = await request.form()
    source = str(form.get("source") or "all").strip()
    if source != "all":
        source = require_source_name(source)
    _, error = net_cli_call(request, ["collect", source], timeout=180)
    write_audit(db, request, user, "network-collect", "error" if error else "ok", error or source)
    add_flash(request, "bad" if error else "ok", error or f"Сбор выполнен: {source}")
    return redirect("/network/collect")


@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    lines = int(request.query_params.get("n") or 80)
    if lines not in {30, 80, 150}:
        lines = 80
    data, error = cli_call(request, ["logs", "-n", str(lines)])
    return render(request, "logs.html", {"logs": data, "lines": lines, "error": error}, db)
