# Full synthetic E3 browser journey

Run a fresh synthetic fixture with Endpoint disabled:

```powershell
python -m tests.browser.inventory_fixture_server --output output/playwright/e3-fresh --port 8868
```

Navigate the browser to that loopback fixture and execute `tests/browser/inventory_e3_journey.js` through Playwright MCP. The callback accepts only ports 8868 and 8874 and uses the current origin. Downloads are deliberately saved under this isolated managed worktree's ignored `output/playwright/e3-v7/` directory; adjust that artifact path before using another checkout.

The journey searches the saved list, creates and confirms a full PC, selects the existing card through comparison, explicitly reconsiders its ended first association, and opens the relation in both directions (network card → comparison → Inventory card, Inventory card → network card). It adds a monitor and UPS via the ordinary related-device picker, saves an edit, and downloads Inventory XLSX before deletion. Deletion must hide only the PC, leave both peripheral IDs in their location, and retain the Netctl source device. Restore must preserve the PC ID and edit while leaving historical bindings ended. A final explicit comparison/relink is required.

Repeat uses the second saved interface with live runtime inspection unavailable. The fixture-only control route records a failed sync attempt while preserving the published saved list. Card/edit/export/delete/restore remain usable. The unavailable comparison renders an HTTP200 page with the explicit unavailable alert and without a confirm action; recovery permits explicit relink. The fixture control exists only inside the test server entry point, never normal application startup. It cannot run external CLI calls. Confirmation while offline is never forced.

Validate the synthetic DB and both downloaded workbooks read-only:

```powershell
python -m tests.browser.verify_inventory_e3 --fixture output/playwright/e3-fresh --artifacts output/playwright/e3-v7
```

The verifier checks the exact same PC/peripheral IDs in SQLite and XLSX, ended workplace relations, one new confirmed Netctl relation, retained source devices, 8 workbook sheets, 13 workplace-relation columns, 35 binding columns, source availability metadata, and absence of formulas. It accepts only an E3 fixture directory containing its fixture marker.

## Evidence

The earlier e3-v3 run is invalidated: repeated available controls attempted to insert the same unique successful snapshot, and ignored HTTP responses masked recovery failures. The unavailable stub also raised the wrong exception type. The corrected fixture reuses the actual published successful snapshot, refreshes its attempt timestamps, and raises the normal NetctlError for unavailable live inspection. The browser checks every control response, rejects every HTTP5xx, verifies the explicit HTTP200 unavailable alert/no-confirm flow, and checks the recovered card reports an available saved source.

Final corrected run used a fresh pinned fixture at `output/playwright/e3-v7` on port 8868, with root XLSX relation-state commit 8430edd. Both full journeys passed with `pageErrors=[]` and `serverFailures=[]`. Every fixture control returned HTTP200 (four calls); the persisted latest sync attempt is successful, its snapshot has exactly one successful row, and the prior failed attempt remains recorded. The browser asserted the recovered card source is available. Server log `output/playwright/e3-v7-server.log` contains no HTTP5xx, traceback, or IntegrityError. The unavailable comparison is an HTTP200 error page with the exact unavailable-source alert and no confirm action.

Read-only final artifact/DB check passed:

```powershell
python -m tests.browser.verify_inventory_e3 --fixture output/playwright/e3-v7 --artifacts output/playwright/e3-v7
```

- `available.xlsx`: 15624 bytes, SHA256 `c7ad42ef18f39a70c4d861a781fdcf52d6b7f581bdfb1e2b804f1575136b3e84`.
- `unavailable.xlsx`: 17282 bytes, SHA256 `50bd857d4912bf632ddc4f0cf2bf158c251f4cbf6841f53cf44bd4d477794513`.

Both files have the exact eight expected sheets, 13 workplace-relation columns and 35 binding columns, the same PC/peripheral IDs as the restored SQLite cards, correct source state metadata, and no formulas. Earlier artifacts remain under `output/playwright/e3`; do not use them as final acceptance evidence. This does not claim manual Excel desktop compatibility, production deployment, or external provider readiness.
