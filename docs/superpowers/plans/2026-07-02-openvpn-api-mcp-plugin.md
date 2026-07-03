# OpenVPN API MCP Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe JSON API, a local MCP server, and a local Codex plugin so Codex can manage OpenVPN through the existing web service.

**Architecture:** Codex talks to a local stdio MCP server. The MCP server calls `openvpn-web` HTTP API using a bearer token. The API reuses existing FastAPI service functions and still performs all OpenVPN changes only through `vpnctl --json`.

**Tech Stack:** FastAPI, SQLAlchemy, pytest, Python stdlib MCP JSON-RPC over stdio, Codex local plugin manifest.

---

### Task 1: API Auth And Routes

**Files:**
- Modify: `app/config.py`
- Create: `app/api.py`
- Modify: `app/main.py`
- Modify: `deploy/install-openvpn-web.sh`
- Test: `tests/test_api_routes.py`

- [ ] Add tests for bearer-token rejection, status/list success, client disable with `confirm_client` and `reason`, and absence of any API delete route.
- [ ] Implement API token hash verification using `OPENVPN_WEB_API_TOKEN_HASH`.
- [ ] Add `/api/v1/status`, `/api/v1/profiles`, `/api/v1/clients`, `/api/v1/clients/{client}`, `/api/v1/clients/{client}/preview`, `/api/v1/clients/{client}/generate`, `/api/v1/clients/{client}/disable`, `/api/v1/connections`, `/api/v1/vipnet-nets`, `/api/v1/vipnet-nets/add`, `/api/v1/vipnet-nets/remove`, `/api/v1/nat-status`, and `/api/v1/logs`.
- [ ] Generate API token and hash during install when the env file is absent or missing the hash.

### Task 2: Local MCP Server

**Files:**
- Create: `mcp/openvpn_mcp_server.py`
- Create: `tests/test_mcp_server.py`

- [ ] Add JSON-RPC tests for `tools/list`, `openvpn_status`, and `openvpn_disable_client`.
- [ ] Implement stdio MCP server with tools that call the HTTP API.
- [ ] Do not implement a client delete tool.

### Task 3: Codex Local Plugin

**Files:**
- Create or update: `C:\Users\admin-2\plugins\openvpn-control`
- Update marketplace: `C:\Users\admin-2\.agents\plugins\marketplace.json`

- [ ] Scaffold plugin with `.codex-plugin/plugin.json`, `.mcp.json`, `scripts/openvpn_mcp_server.py`, and `skills/openvpn-control/SKILL.md`.
- [ ] Configure MCP env values for `OPENVPN_WEB_BASE_URL` and `OPENVPN_WEB_API_TOKEN`.
- [ ] Validate plugin with plugin-creator validator.

### Task 4: Deploy And Verify

**Files:**
- Deploy to `/opt/openvpn-web`

- [ ] Run local and remote `pytest`.
- [ ] Restart `openvpn-web.service`.
- [ ] Run API smoke through curl.
- [ ] Run MCP smoke locally against the deployed API.
- [ ] Confirm plugin exists in personal marketplace.
