# Panel navigation and list preferences (T10)

The server-rendered shell retains all existing pages under VPN, network/diagnostics,
inventory and maintenance groups. Current groups open automatically; list and runtime
asset cards share the network devices active entry. Inventory network selection starts
at the real device list, where a stable-key row supplies comparison navigation.
Deleted inventory navigation follows the existing inventory:delete capability; user
administration remains administrator-only. Hidden links do not replace route checks.

## Return context boundary

`app.navigation.safe_return_url` permits known local GET list routes and inventory
location UUID paths only. It rejects schemes, authorities, fragments, backslashes,
control characters, encoded unsafe destinations and unknown paths; query keys and
values are bounded. List links pass safe filter/page context to cards. The owned
inventory edit process retains only this validated return context, including after
validation errors/reload, and successful save returns to that list. No authorization
or external redirect is inferred from a supplied URL.

## Preferences

The hosts table defaults to seven operational columns. All 15 columns remain in the
DOM and can be shown in diagnostic mode. Mode and up to ten named views persist in
origin-local storage under a per-user ID key. Only supported select-filter settings
and the mode are saved: category, status, observation period, source, network, presence
of hostname/MAC and page size. Search text, page number, card inputs, credentials,
tokens and arbitrary query parameters are excluded. Saved views reset pagination to
page 1. Storage denial/corruption leaves the table usable and displays honest feedback.

The preference allowlist reserves inventory_link = all|linked|unlinked|candidates|
conflicts. Apply includes this field only when the actual supported select exists.
Root T13 commit 20a49e1 adds that select/filter; this isolated branch is based on
4164452 and does not duplicate the core filter implementation. Integration must repeat
a saved-view smoke against the actual T13 control before claiming that combined gate.

## Accessibility and state meanings

Native details/summary groups, labelled filter fields, aria-current, a skip link and
visible focus support keyboard navigation. The mobile menu blocks background focus,
wraps Tab through exposed controls, closes with Escape and restores focus. Operational
and diagnostic mode buttons expose aria-pressed; table overflow is confined to its
scroll container on mobile.

Server and dynamic rows use matching Russian availability labels. Passive seen means
observed, not proven reachable. Unknown and stale states remain distinct from a
negative result. API enum values and filtering semantics are unchanged.

## Verification boundary

All checks use synthetic SQLite fixtures or loopback-only browser fixtures. The
browser fixture blocks external CLI execution. No production reads, deployment,
exports or external writes are performed. Screenshots stay in ignored isolated
output/playwright/panel-navigation; tests/browser/panel_navigation.js records the
repeatable Playwright MCP flow. The Browser plugin was unavailable; the existing
Playwright MCP and playwright-interactive skill were used.

GitNexus query located network_hosts/API snapshot paths before source exploration;
list_repos confirmed the indexed web_ovpn baseline fab1cac1, separately from local
4164452 and this branch diff. Dynamic Jinja/context and refresh relationships were
verified in source and tests. Context7 /mdn/content documented localStorage persistence
and SecurityError behavior; no dependency or schema changes are required.
## Executed checks

- `python -m pytest tests/test_inventory_web.py tests/test_inventory_network_links_web.py tests/test_inventory_lifecycle.py tests/test_web_network_observer.py tests/test_panel_navigation.py -q --disable-warnings --tb=short`: 148 passed before the two final navigation review fixes.
- `python -m pytest tests/test_panel_navigation.py tests/test_panel_permissions.py tests/test_inventory_revision.py tests/test_inventory_form_drafts.py -q --disable-warnings --tb=short`: 51 passed after those fixes.
- `python -m pytest tests/test_routes_smoke.py -q --disable-warnings --tb=short`: 12 passed after those fixes.
- `node --check` on app.js, network-hosts-refresh.js and network-hosts-views.js: passed. Python compileall for navigation/main/inventory web/browser fixture: passed. `git diff --check`: passed.
- Actual Playwright MCP replay of `tests/browser/panel_navigation.js`: page-2 card/Back and history preserved; 7/15 columns and reload persistence; save/apply/delete with search excluded; six SSR/dynamic status labels equal; mobile card action, keyboard menu/focus/Escape, blocked-storage fallback passed; no body overflow and zero new console errors.

Independent review verified both corrected findings (device selection navigation no longer returns 422; deleted navigation follows capability) and reported no remaining P1/P2. Existing route authorization remains enforced. Screenshots and fixture runtime are local QA outputs, excluded from Git.
