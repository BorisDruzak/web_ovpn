# Historical Identity Findings Acknowledgement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Move reviewed legacy identity-conflict provenance out of the open operational inbox without deleting it or suppressing future runtime conflicts.

**Architecture:** Add an additive SQLite migration version 4. Its exact predicate acknowledges only open rows created by migration 3 (\`historical_identity_conflict\` plus a \`legacy-identity-conflict:\` key); it neither changes evidence fields nor touches current runtime findings. Existing read-only status/findings queries already filter by lifecycle status and therefore need no API or UI change.

**Tech Stack:** Python 3, SQLite, pytest, existing \`netctl\` migration registry and CLI/runbook conventions.

## Global Constraints

- Never delete \`runtime_identity_findings\` rows or runtime observations.
- Do not alter \`first_seen_at\`, \`last_seen_at\`, \`details_json\`, asset/source references, collection logic, or network-device configuration.
- Acknowledge only \`status = 'open'\`, \`finding_type = 'historical_identity_conflict'\`, and \`finding_key GLOB 'legacy-identity-conflict:*'\`.
- Leave \`mac_identity_collision\`, \`unresolved_ip_only_runtime\`, \`duplicate_current_ip\`, and \`ip-moved:\` findings unchanged.
- Use the existing migration transaction/savepoint and migration ledger; do not add a standalone production SQL script.
- Back up the SQLite database before the production migration and verify with the read-only CLI.

---

## File structure

- \`netctl/migrations.py\`: owns schema versions and the one-way acknowledgement migration.
- \`tests/test_netctl_runtime_assets.py\`: owns migration lifecycle, exact-predicate, and rollback regression tests.
- \`docs/runbooks/netctl-runtime-live-observations-deploy.md\`: owns operator backup, application, and before/after verification commands.
- \`docs/verification/netctl-live-context-readiness.md\`: owns sanitized production findings status and the acknowledgement decision.

### Task 1: Add the exact, ledgered SQLite migration

**Files:**
- Modify: \`netctl/migrations.py:1046-1050\`
- Test: \`tests/test_netctl_runtime_assets.py:1722-1778, 2063-2148\`
- Test: \`tests/test_netctl_cli.py\`

**Interfaces:**
- Consumes: \`MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...]\` and \`apply_migrations(conn)\`.
- Produces: \`_migration_4(conn: sqlite3.Connection) -> None\` and migration ledger version \`4\`.

- [ ] **Step 1: Write failing migration and CLI regression tests**

Add a test that creates migration-3 finding rows with this fixture data, invokes \`_migration_4(conn)\`, and asserts the exact statuses and unchanged evidence:

\`\`\`python
rows = [
    ("legacy-identity-conflict:1", "historical_identity_conflict", "open", '{"origin":"migration"}'),
    ("ip-moved:1:192.0.2.10:1:2", "historical_identity_conflict", "open", '{"origin":"live"}'),
    ("mac-site-collision:1:00:11:22:33:44:55", "mac_identity_collision", "open", '{}'),
    ("unresolved-ip-only:1:192.0.2.11", "unresolved_ip_only_runtime", "open", '{}'),
    ("legacy-identity-conflict:2", "historical_identity_conflict", "resolved", '{}'),
]
\`\`\`

Assert that only the first row becomes \`acknowledged\`; all other statuses, both JSON payloads, and the first row's timestamps are unchanged.

Add a CLI test using the same migration-3 fixture that asserts the default
command is an operational inbox after v4 is applied:

\`\`\`python
code, payload = run_cli("--json", "runtime-assets", "findings")
assert code == 0
assert {item["finding_type"] for item in payload["findings"]} == {
    "historical_identity_conflict",
    "mac_identity_collision", "unresolved_ip_only_runtime"
}
\`\`\`

Also assert \`--status acknowledged\` returns the preserved
\`legacy-identity-conflict:\` row and its \`details\` object.
The full fixture must include an open \`ip-moved:\` row: it proves that a
current movement remains visible while migration-era provenance is
acknowledged.

- [ ] **Step 2: Run test to verify it fails**

Run:

\`\`\`powershell
python -m pytest tests/test_netctl_runtime_assets.py -k migration_4_acknowledges_only_legacy_identity_conflicts -v
python -m pytest tests/test_netctl_cli.py -k acknowledged_legacy_findings -v
\`\`\`

Expected: both commands FAIL because migration version 4 is not defined or the
legacy finding has not been acknowledged.

- [ ] **Step 3: Implement the minimal version-4 migration**

Immediately before \`MIGRATIONS\`, add:

\`\`\`python
def _migration_4(conn: sqlite3.Connection) -> None:
    """Acknowledge reviewed migration-3 provenance without deleting it."""
    conn.execute(
        """
        UPDATE runtime_identity_findings
        SET status = 'acknowledged'
        WHERE status = 'open'
          AND finding_type = 'historical_identity_conflict'
          AND finding_key GLOB 'legacy-identity-conflict:*'
        """
    )
\`\`\`

Extend the registry exactly as follows:

\`\`\`python
MIGRATIONS = (
    (1, _migration_1),
    (2, _migration_2),
    (3, _migration_3),
    (4, _migration_4),
)
\`\`\`

- [ ] **Step 4: Prove migration lifecycle and rollback behavior**

Add two tests:

\`\`\`python
def test_migration_4_is_applied_once_and_reopen_is_idempotent(
    pr_1b_database: str,
) -> None:
    # Seed a version-3 database with a legacy finding, call connect twice,
    # then assert ledger [1, 2, 3, 4], acknowledged status, and one row.

def test_migration_4_failure_rolls_back_status_and_ledger(
    pr_1b_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Patch MIGRATIONS so version 4 acknowledges then raises RuntimeError.
    # Assert the database retains status='open' and no version-4 ledger row.
\`\`\`

Use the existing migration-3 savepoint rollback test as the transaction fixture pattern. The failure test must reopen the database before assertions.

- [ ] **Step 5: Run focused tests**

Run:

\`\`\`powershell
python -m pytest tests/test_netctl_runtime_assets.py -k "migration_4 or migration_3_is_applied_once or migration_3_rollback" -v
python -m pytest tests/test_netctl_runtime_writer.py -k "historical or collision or ip_only" -v
\`\`\`

Expected: all selected tests PASS.

- [ ] **Step 6: Commit the migration and tests**

\`\`\`powershell
git add netctl/migrations.py tests/test_netctl_runtime_assets.py tests/test_netctl_cli.py
git commit -m "feat(netctl): acknowledge reviewed legacy identity findings"
\`\`\`

### Task 2: Document and verify the operational transition

**Files:**
- Modify: \`docs/runbooks/netctl-runtime-live-observations-deploy.md:129-147\`
- Modify: \`docs/verification/netctl-live-context-readiness.md:53-75\`

**Interfaces:**
- Consumes: the existing read-only commands \`netctl --json runtime-assets status\` and \`netctl --json runtime-assets findings --status <lifecycle>\`.
- Produces: a reproducible backup/rollback checklist and sanitized readiness evidence that distinguishes acknowledged provenance from open findings.

- [ ] **Step 1: Update the deployment runbook**

Replace the manual-review-only wording with a migration-4 operation that:

\`\`\`bash
backup_dir="/var/backups/netctl/findings-ack-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 "$backup_dir"
sudo cp --preserve=mode,timestamps /var/lib/netctl/netctl.sqlite "$backup_dir/netctl-before-v4.sqlite"
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status open
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status acknowledged
\`\`\`

State explicitly that normal application startup applies ledgered migration 4, that acknowledged rows remain accessible, and that rollback restores the pre-v4 backup only while services are stopped and after operator approval.

- [ ] **Step 2: Update sanitized readiness evidence**

Change the findings table to record three distinct states:

\`\`\`text
Acknowledged historical-identity findings | 46,271
Open MAC-identity-collision findings      | 5
Open IP-only findings                     | 1
\`\`\`

Explain that acknowledgement is a reviewed provenance classification, not automatic remediation or deletion. Do not include raw host, IP, MAC, credential, or database-row data.

- [ ] **Step 3: Run documentation and CLI checks**

Run:

\`\`\`powershell
python -m pytest tests/test_netctl_cli.py -k "runtime_assets or findings" -v
git diff --check
\`\`\`

Expected: all selected tests PASS and no whitespace errors.

- [ ] **Step 4: Commit documentation**

\`\`\`powershell
git add docs/runbooks/netctl-runtime-live-observations-deploy.md docs/verification/netctl-live-context-readiness.md
git commit -m "docs(netctl): record historical findings acknowledgement"
\`\`\`

### Task 3: Review, regression, and controlled production application

**Files:**
- Verify: \`netctl/migrations.py\`
- Verify: \`tests/test_netctl_runtime_assets.py\`
- Verify: \`tests/test_netctl_runtime_writer.py\`
- Verify: \`tests/test_netctl_cli.py\`
- Verify: \`docs/runbooks/netctl-runtime-live-observations-deploy.md\`

**Interfaces:**
- Consumes: committed migration 4 and deployment runbook.
- Produces: independent review evidence, a complete local regression result, and a production before/after status record.

- [ ] **Step 1: Perform independent migration-predicate review**

Review the committed diff against these invariants:

\`\`\`text
only open + historical_identity_conflict + legacy-identity-conflict:* changes;
no DELETE statement exists;
ip-moved: remains open;
MAC collision and IP-only rows remain open;
details_json and timestamps are not changed;
version 4 is in the ordered migration registry.
\`\`\`

Record any blocking finding before production work.

- [ ] **Step 2: Run full local regression**

Run:

\`\`\`powershell
python -m pytest -q
git diff --check
git status --short
\`\`\`

Expected: complete suite PASS, whitespace check clean, and no uncommitted tracked changes.

- [ ] **Step 3: Publish the reviewed branch**

Run:

\`\`\`powershell
git push origin HEAD:main
\`\`\`

Expected: fast-forward of \`origin/main\`; do not overwrite the user's divergent local checkout.

- [ ] **Step 4: Back up and deploy to production**

Follow Task 2's runbook commands on \`ui-vpn-deploy\`. First record:

\`\`\`bash
systemctl is-active openvpn-web.service
systemctl is-active netctl-collect.timer
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status
\`\`\`

Deploy the verified application archive, start the normal service so migration 4 is applied through the established migration path, and do not change any network device configuration.

- [ ] **Step 5: Verify production state and rollback boundary**

Run:

\`\`\`bash
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status open
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status acknowledged
systemctl is-active openvpn-web.service
systemctl is-active netctl-collect.timer
\`\`\`

Expected: migration ledger includes \`4\`; 46,271 legacy rows are acknowledged and queryable; MAC collisions and the IP-only finding remain open; services are active. If any invariant fails, stop the application change and restore the exact pre-v4 SQLite backup using the runbook rather than editing findings with ad-hoc SQL.
