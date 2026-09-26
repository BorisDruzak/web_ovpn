"""Explicit route adapter for CLI-bearing browser mutation handlers."""
from __future__ import annotations

import asyncio
import copy
import io
import json
from functools import wraps

from fastapi import BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData, UploadFile

from .auth import require_user, verify_csrf
from .db import get_sessionmaker
from .panel_operations import register
from .permissions import required_permission

# Existing handlers perform operation-specific validation/confirmation before
# calling their first CLI, and preserve the existing audits inside the executor.
LONG_BROWSER_HANDLERS = frozenset({
    "clients_sync", "new_client_action", "client_edit_template", "client_edit_networks",
    "client_edit_ovpn", "reconnect_client_route", "kill_client_session_route",
    "download_link", "disable_client", "connection_kill",
    "openvpn_settings_status_interval", "openvpn_settings_management_enable",
    "openvpn_settings_restart", "network_add", "network_remove",
    "vipnet_add_legacy", "vipnet_remove_legacy", "network_template_add",
    "network_template_remove", "network_monitoring_update", "network_asset_fingerprint_ensure",
    "network_asset_name_update", "network_host_availability_check", "network_host_observation_refresh",
    "network_host_force_monitor", "network_host_force_monitor_disable", "network_source_new",
    "network_source_collect", "network_collect_action",
})
SHORT_BROWSER_HANDLERS = frozenset({
    "openvpn_settings_validate_network_plan", "openvpn_settings_management_test", "network_source_test",
    "server_draft_create", "server_draft_scan", "server_draft_confirm_transactional",
    "server_draft_confirm_retry", "server_draft_check", "server_draft_delete",
    "server_draft_check_retry", "server_draft_cleanup_retry",
})


async def snapshot(request: Request):
    form = await request.form()
    items = []
    parameters = []
    for name, value in form.multi_items():
        if isinstance(value, UploadFile):
            content = await value.read(2 * 1024 * 1024 + 1)
            if len(content) > 2 * 1024 * 1024:
                raise HTTPException(413, "Файл операции превышает 2 MiB")
            await value.seek(0)
            items.append((name, UploadFile(io.BytesIO(content), filename=value.filename, headers=value.headers)))
            import hashlib
            parameters.append((name, value.filename, hashlib.sha256(content).hexdigest()))
        else:
            items.append((name, value))
            if name != "csrf_token":
                parameters.append((name, str(value)))
    scope = dict(request.scope)
    scope["session"] = copy.deepcopy(request.session)
    scope["state"] = dict(request.scope.get("state", {}))
    clone = Request(scope)
    clone._form = FormData(items)
    clone._body = b""
    # Target path/query and all submitted values participate. Nothing is stored
    # except the keyed digest, so content, credentials and tokens stay in memory.
    canonical = json.dumps([request.url.path, str(request.url.query), sorted(parameters)],
                           ensure_ascii=False, separators=(",", ":")).encode()
    intent = json.dumps([request.url.path, str(request.url.query),
        sorted(item for item in parameters if item[0] != "operation_key")],
        ensure_ascii=False, separators=(",", ":")).encode()
    return clone, canonical, intent


def install_browser_operations(app) -> None:
    for route in app.routes:
        original = getattr(getattr(route, "dependant", None), "call", None)
        if original is None or original.__name__ not in LONG_BROWSER_HANDLERS | SHORT_BROWSER_HANDLERS:
            continue
        short = original.__name__ in SHORT_BROWSER_HANDLERS

        @wraps(original)
        async def execute_route(_handler=original, _short=short, **kwargs):
            request = kwargs["request"]
            user = require_user(request, kwargs["db"])
            await verify_csrf(request)
            clone, canonical, intent = await snapshot(request)
            factory = get_sessionmaker()
            arguments = {key: value for key, value in kwargs.items() if key not in {"db", "request"}}

            def execute():
                with factory() as owned_db:
                    try:
                        async def invoke():
                            owned_arguments = dict(arguments)
                            tasks = None
                            if "background_tasks" in owned_arguments:
                                tasks = BackgroundTasks()
                                owned_arguments["background_tasks"] = tasks
                            response = await _handler(request=clone, db=owned_db, **owned_arguments)
                            # FastAPI's request-attached queue cannot outlive the
                            # owned execution. Complete these effects before its
                            # durable result, with the operation ContextVars.
                            if tasks is not None:
                                await tasks()
                            response._panel_flashes = list(clone.session.get("flashes", []))
                            return response
                        return asyncio.run(invoke())
                    finally:
                        for _, item in clone._form.multi_items():
                            if isinstance(item, UploadFile):
                                item.file.close()

            if _short or (_handler.__name__ == "new_client_action" and clone._form.get("action", "preview") == "preview"
                and clone._form.get("access_mode", "template") != "custom"):
                # Await only a complete bounded path running in one worker with
                # its own Session; nested CLI/filesystem helpers run there too.
                response = await run_in_threadpool(execute)
                request.session.update(clone.session)
                return response
            operation, created = await run_in_threadpool(register, "user:" + user.username,
                _handler.__name__, required_permission(request.url.path, request.method), canonical, execute,
                factory=factory, intent=intent)
            if not created:
                for _, item in clone._form.multi_items():
                    if isinstance(item, UploadFile):
                        item.file.close()
            if _handler.__name__ == "new_client_action" and clone._form.get("action", "preview") == "preview":
                from .panel_operations import execution_future
                future = execution_future(operation["id"])
                if future is None:
                    return RedirectResponse(operation["status_url"], status_code=303)
                response = await asyncio.shield(asyncio.wrap_future(future))
                request.session.update(clone.session)
                response.headers["X-Operation-ID"] = operation["id"]
                response.headers["Location"] = operation["status_url"]
                return response
            if _handler.__name__ == "network_asset_fingerprint_ensure":
                return JSONResponse({"status": "scheduled", "operation": operation}, status_code=202,
                    headers={"X-Operation-ID": operation["id"], "Location": operation["status_url"]})
            return RedirectResponse(operation["status_url"], status_code=303,
                headers={"X-Operation-ID": operation["id"]})

        route.dependant.call = execute_route


# Existing synchronous API routes already run outside the event loop. Register
# long effects durably too, preserving the first-call legacy response by default.
# Prefer: respond-async requests receive a 202 status resource immediately.
LONG_API_HANDLERS = frozenset({
    "api_clients_sync", "api_client_generate", "api_client_disable", "api_client_networks_apply",
    "api_client_network_template_apply", "api_client_ovpn_update", "api_client_reconnect",
    "api_client_kill_session", "api_network_add", "api_network_remove",
    "api_network_template_add", "api_network_template_remove", "api_vipnet_add", "api_vipnet_remove",
    "api_openvpn_status_interval", "api_openvpn_management_enable", "api_context_user_create",
    "api_context_user_bind_asset", "api_context_user_retire_binding", "api_context_network_session_create",
    "api_context_network_session_close", "api_site_route_add", "api_site_route_remove",
})


def install_api_operations(app) -> None:
    from fastapi.responses import JSONResponse
    from .panel_operations import execution_future, forget_future
    for route in app.routes:
        original = getattr(getattr(route, "dependant", None), "call", None)
        if original is None or original.__name__ not in LONG_API_HANDLERS:
            continue

        @wraps(original)
        async def execute_api(_handler=original, **kwargs):
            request = kwargs["request"]
            # FastAPI has resolved the existing bearer/capability dependency.
            owner = "service:" + kwargs["actor"]
            arguments = {key: value for key, value in kwargs.items() if key not in {"db", "request"}}
            serializable = {key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                            for key, value in arguments.items()}
            canonical = json.dumps([request.url.path, str(request.url.query), serializable,
                request.headers.get("Idempotency-Key", "")], sort_keys=True, separators=(",", ":")).encode()
            intent = json.dumps([request.url.path, str(request.url.query), serializable],
                sort_keys=True, separators=(",", ":")).encode()
            scope = dict(request.scope)
            scope["state"] = dict(request.scope.get("state", {}))
            clone = Request(scope)
            factory = get_sessionmaker()

            def execute():
                with factory() as owned_db:
                    return _handler(request=clone, db=owned_db, **arguments)

            operation, created = await run_in_threadpool(register, owner,
                _handler.__name__, required_permission(request.url.path, request.method), canonical, execute,
                factory=factory, intent=intent)
            headers = {"X-Operation-ID": operation["id"],
                       "Location": "/api/v1/operations/" + operation["id"]}
            operation["status_url"] = headers["Location"]
            if created and "respond-async" not in request.headers.get("Prefer", ""):
                future = execution_future(operation["id"])
                try:
                    response = await asyncio.shield(asyncio.wrap_future(future))
                    if isinstance(response, dict):
                        return JSONResponse(response, headers=headers)
                    if response is None:
                        return JSONResponse({"status":"accepted", "operation":operation}, status_code=202, headers=headers)
                    for name, value in headers.items():
                        response.headers[name] = value
                    return response
                except HTTPException as exc:
                    if exc.status_code >= 500:
                        raise HTTPException(exc.status_code,
                            "Внешняя операция не завершена; проверьте её состояние", headers=headers) from None
                    raise
                finally:
                    forget_future(operation["id"])
            return JSONResponse({"status":"accepted", "operation":operation}, status_code=202, headers=headers)

        route.dependant.call = execute_api
        from starlette.routing import request_response
        route.app = request_response(route.get_route_handler())
