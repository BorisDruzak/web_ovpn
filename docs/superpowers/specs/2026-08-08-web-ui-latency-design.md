# Web UI Latency Design

## Goal

Reduce the time to initial HTML for the OpenVPN dashboard and clients page without changing authentication, CSRF, mutation semantics, OpenVPN configuration, or the FastAPI + Jinja architecture.

## Scope

- `GET /clients` never runs `vpnctl sync`; explicit and mutation-triggered synchronization remains unchanged.
- `GET /` renders immediately without calling `vpnctl` or `netctl`.
- A session-authenticated `GET /dashboard/data` returns a sanitized dashboard snapshot.
- The dashboard snapshot uses one read-only `vpnctl web-summary` invocation, bounded to five seconds, and a process-local single-flight TTL cache.
- The clients page has bounded read timeouts and a cached profiles lookup.
- CLI timing logs and dashboard `Server-Timing` identify slow read operations without exposing sensitive command arguments or output.
- Runtime-health polling does not overlap, pauses in hidden tabs, and uses cancellation timeouts.
- Nginx serves static assets directly with non-immutable, short browser caching.

## Data Flow

`GET /` authenticates through the existing session, renders metric placeholders, and returns HTML. Browser JavaScript then requests `/dashboard/data` with same-origin credentials. The endpoint authenticates through `require_user`, reads a global snapshot cache, and either returns a fresh/last-good response or coalesces concurrent collection into one `vpnctl web-summary` invocation. A command error or timeout never replaces a last-good result; it produces `stale: true` and a sanitized error code.

`vpnctl web-summary` is read-only. It returns only `openvpn`, `nat`, `clients_count`, and `connected_count`, combining existing service status and client-list logic in one process. It is the sole live command for an uncached dashboard refresh.

## Cache Contract

The cache uses `time.monotonic()` and a `threading.Condition`. It stores JSON-compatible snapshot data, generated time, and a five-second expiry. Exactly one caller may refresh a key; concurrent callers receive the last-good snapshot as stale when one exists, otherwise wait for the bounded first refresh. Failed refreshes preserve last-good data. This is intentionally per process; multi-worker deployment would have one cache per worker.

Profiles are cached for 300 seconds. Client-list caching is deferred unless post-change timing shows a need.

## Failure and Security Behavior

Interactive reads use explicit five-second timeouts. Dashboard HTML remains usable even if data collection fails. Dashboard JSON never returns command stdout or stderr. Request IDs are logged with command name, duration, and outcome, but no secrets, raw configuration, or full CLI arguments. Session authentication remains the only browser authorization mechanism; the bearer API token is not used in browser code.

## Verification

Regression tests prove no `sync` on GET clients and preserve the explicit POST sync. Slow fake CLI tests prove initial dashboard HTML does not invoke live CLI. Data-layer tests cover success, cache hit/expiry, timeout/error fallback, and concurrent single-flight collection. Browser-facing tests cover placeholder hydration and polling controls. Local and deploy-host timings are recorded before and after; deployment modifies only application and Nginx service files and performs no network configuration writes.
