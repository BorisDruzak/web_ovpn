# Full synthetic E3 browser journey

Run a fresh synthetic fixture with Endpoint disabled:

```powershell
python -m tests.browser.inventory_fixture_server --output output/playwright/e3-fresh --port 8868
```

Navigate the browser to that loopback fixture and execute `tests/browser/inventory_e3_journey.js` through Playwright MCP. The callback accepts only ports 8868 and 8874 and uses the current origin. Downloads are deliberately saved under this isolated managed worktree's ignored `output/playwright/e3/` directory; adjust that artifact path before using another checkout.

The journey searches the saved list, creates and confirms a full PC, selects the existing card through comparison, explicitly reconsiders its ended first association, and opens the relation in both directions (network card → comparison → Inventory card, Inventory card → network card). It adds a monitor and UPS via the ordinary related-device picker, saves an edit, and downloads Inventory XLSX before deletion. Deletion must hide only the PC, leave both peripheral IDs in their location, and retain the Netctl source device. Restore must preserve the PC ID and edit while leaving historical bindings ended. A final explicit comparison/relink is required.

Repeat uses the second saved interface with live runtime inspection unavailable. The fixture-only control route records a failed sync attempt while preserving the published saved list. Card/edit/export/delete/restore remain usable. The unavailable comparison returns an expected 503 without a confirm action; recovery permits explicit relink. The fixture control exists only inside the test server entry point, never normal application startup. It cannot run external CLI calls. Confirmation while offline is never forced.

Validate the synthetic DB and both downloaded workbooks read-only:

```powershell
python -m tests.browser.verify_inventory_e3 --fixture output/playwright/e3-fresh --artifacts output/playwright/e3
```

The verifier checks the exact same PC/peripheral IDs in SQLite and XLSX, ended workplace relations, one new confirmed Netctl relation, retained source devices, 8 workbook sheets, 35 binding columns, source availability metadata, and absence of formulas. It accepts only an E3 fixture directory containing its fixture marker.

## Evidence, 2026-09-26

Actual Playwright MCP execution against pinned synthetic server port8868: both journeys PASS; no page exceptions. Expected unavailable-comparison 503 and unrelated favicon404 resource messages were observed; no claim of zero HTTP errors. Read-only verifier PASS for both downloads. Available workbook:15582bytes; unavailable:17243bytes. This proves browser navigation and parsed artifacts, not manual Excel desktop compatibility, production deployment, or external provider readiness.

The final run used root XLSX commits4bc6274 and64ba512 plus saved-freshness4abc987. Earlier attempts exposed harness issues (URL global unavailable, network card relation reached through comparison, explicit reconsider checkbox required); the final script includes these actual UI requirements.

Actual final fixture: `output/playwright/e3-v3`; downloaded artifacts: `output/playwright/e3`. Read-only evidence command: `python -m tests.browser.verify_inventory_e3 --fixture output/playwright/e3-v3 --artifacts output/playwright/e3`.

Related pinned regressions: network creation, lifecycle and Inventory export web — 29 passed. Independent read-only E3 source/artifact review found no P1/P2; verifier independently passed both journeys.
