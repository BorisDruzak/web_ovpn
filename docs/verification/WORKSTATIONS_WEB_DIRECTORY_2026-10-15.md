# Workstations web/directory verification — 2026-10-15

## Acceptance states

Implementation and the independent whole-branch correction pass are complete.
Code under verification: `6e63ef02c662b1ca68d9e5b3207783fed2ccc0c6`.
Full Linux regression, publication CI and guarded installed acceptance are
separate gates; results below are updated only after the corresponding command.
No real workstation join, reboot or employee creation is part of this rollout.

## Verification performed

- Combined corrected boundary suites: **158 passed**, 171 warnings, 26.92s.
  Command: `python -m pytest tests/test_workstations_api.py tests/test_workstations_permissions.py tests/test_workstations_journal.py tests/test_workstations_web.py tests/test_workstations_links.py tests/test_workstations_reconcile.py tests/alt_linux/test_workstations_gateway.py tests/alt_linux/test_directory_dns.py tests/alt_linux/test_directory_observer.py -q`.
- `node --test tests/workstations.test.js`: **7 passed**.
- `node --check app/static/workstations.js` and
  `node --check tests/browser/workstations_journey.js`: passed.
- `powershell.exe -NoProfile -NonInteractive -File tests/powershell/test_directory_observer_policy.ps1`:
  **27 passed synthetic checks**, zero infrastructure calls; actual Windows
  PowerShell parser and native C# compilation executed. This is not live ACL proof.
- Final corrected-source real Chromium journey: **passed**, desktop 1360×900 and
  mobile 390×844; one explicit apply and one explicit verification against the
  synthetic loopback controller; 205 events over pages 0/100/200; 200 journal rows;
  reload resumed the original job, manual inventory owner unchanged, zero console
  or HTTP errors. Journal completeness was visible. No production target changed.
- Task 9 MCP suite: **62 passed**, including real HTTP scope/redirect checks and
  stdio initialize/tools-list/21-tool calls. API/permission regression: 82 passed.
- Task 10 packaging/installer regression: **124 passed, 1 skipped** (PowerShell
  parser unavailable on Linux). Actual Windows execution above covers that platform.
- `git diff --check`: passed before each correction commit.

Full Linux command: `python -m pytest tests -q`, Python 3.12.7, exact repository
requirements, ansible-core 2.18.6 and fakeroot, isolated temporary source and venv.
The earlier pre-correction run was cancelled after review and is not acceptance.
Final run: **6019 passed, 90 skipped, 1 failed**, 1592.47s. The only failure
was `test_management_kill_command`: the executor basetemp made its AF_UNIX path
122 bytes (Linux limit 107), so its synthetic server could not bind. The private
harness now uses a shorter basetemp; the entire `tests/test_vpnctl_management.py`
file then passed **9/9** on the same immutable source. No product change was
needed. Do not relabel the original run as wholly passing. Fresh full CI on the
publication commit is required before installation; consult that commit’s
GitHub Actions checks for the exact-source result. The subsequently authorized
bootstrap-only privilege exception passed 27 actual Windows policy checks and
14 Linux provisioning/deployment tests (one expected platform skip).

## Independent review and architectural checks

One fresh-context whole-branch review covered the approved spec/plan and
`e325e87e38f31dad3b7519d7f08129f2c43d07ec..5fcb09d2a90bbf45cd52a44c61fa789f32731e5c`.
Seven important findings were reproduced RED and corrected GREEN in one pass:
original admission-receipt recovery; BASE tokenGroups reads; verified-alias link
history; native device/component journals and apply association; visible component
blockers; retained comparison freshness; wildcard DNS evidence. No minor findings
were deferred. Review was not substituted for live directory or installed proof.

GitNexus indexed baseline matched origin/main at e325e87; local feature commits
were accounted for separately. Context/impact covered MCP dispatch, saved Netctl
snapshot consumption, SetupService and API CSRF. Dynamic source/tests confirm the
panel invokes the existing controller services and local inventory/Endpoint
projection. No new Endpoint SDK method or provider contract was added. No manual
central reindex or group synchronization was performed.

## Recorded implementation rulings

Each row gives the chosen rule and its practical cost if wrong.

| Decision | Reason / cost if wrong |
| --- | --- |
| Keep approved docs and stage implementation in its own branch/worktree | Preserve user main; integration needs a fast-forward check. |
| Call native component admission directly | It already returns a durable job; incorrect assumption would surface as a bounded operation timeout. |
| Linux tests use isolated normal-user source/venv | No production code/state changes; environment differences require exact-source CI. |
| Extend shared LDIF parser with optional bounds | Avoid duplicate parser; legacy exact-user regression catches compatibility errors. |
| Install pinned dependencies only in the test venv | System interpreter lacked pysnmp; costs temporary disk/time. |
| Disable MSYS path conversion only for task helpers | Preserve remote /tmp arguments; wrong setting fails test invocation. |
| Compare no-write tests against fixture-created baseline | Existing fixture creates its Vault helper; wrong baseline causes a false test failure. |
| Distinguish retained UNKNOWN from candidate-specific queue admission | Existing native reviewed successors remain usable; wrong classification blocks rather than replays. |
| Reap bounded transport children on BaseException | Signals use TimeoutError; wrong cleanup leaves a child and fails the regression. |
| Focused RED/GREEN per task, full expensive suite before publication | Honor original task; missed integration defect is caught by final full suite/CI. |
| Two restricted keys on existing service identity | Native services require its UID; wrong restriction fails enrollment checks, no generic sudo grant. |
| Put launcher inside the already backed-up runtime root | Keep rollback coverage; wrong manifest blocks guarded installation. |
| Registry generation covers all pages and safe assignments | Coherent source publication; wrong generation makes reconciliation unavailable. |
| Add fixed binary GUID identity lookup | Recheck SID/state without arbitrary LDAP; failed lookup blocks confirmation. |
| Retain full bounded stage detail and paged native chronology | Summary is insufficient evidence; timeout reports incomplete evidence. |
| Bind previews/publication to relationship revision | Prevent confirm/end ABA and stale ownership; costs a refresh on contention. |
| Keep browser fixture proof distinct from installed proof | Avoid overstated acceptance; installed gate remains pending. |
| Use signed/sealed ADSI and actual LSA privilege evidence | No ADWS requirement or global policy change; unresolved privilege blocks readiness. |
| Separate root-managed workstation credential directory | Preserve unrelated legacy credentials; path adjustment may be needed on rollout. |
| Recover only original matching successful admission receipt | Preserve historical UNKNOWN and never replay apply; missing proof remains uncertain. |
| Resolve DN then BASE-read tokenGroups | Constructed directory attribute; failure blocks bootstrap. |
| Fold only unambiguous physical aliases | DNS/IP cannot prove identity; some history may stay separate. |
| Native journals join exact job/plan identity and disclose failures | Filtered summaries must include execution evidence; source failure remains explicit. |
| Block component confirmation on blocked/unknown action or failed preflight | Native rejection alone gives poor feedback; operator may need a fresh plan. |
| Share source coherence between display and confirmation | Failed/running refresh immediately stales retained data; costs a refresh. |
| Accept wildcard DNS owners without treating them as host identity | Valid DNS must not abort a source; unsupported types stay excluded. |
| Leave live rights, installed transport, CI and target acceptance as separate gates | Reviewer cannot infer runtime evidence; release remains pending until measured. |
| Repeat actual desktop/mobile journey on corrected source | Browser artifacts prove the rendered flow; remaining visual gaps stay explicit. |
| Preserve raw-log/recovery/rejoin/reboot boundaries | New interface is not an administration shell; native procedure remains necessary. |
| Cancel superseded full suite and run corrected immutable code | Prevent stale acceptance; costs test runtime. |
| Explicit inherited machine-join exception | Operator authorized the measured standard Authenticated Users privilege; identity retains this ability and is reported as not fully read-only. |
| Shorten the private AF_UNIX test harness path and require exact-source full CI | Original full run stays recorded as failed; an order-dependent regression would block deployment in CI. |
| Retain the baseline MCP panel URL default | Added-line scan matched existing behavior, not a new topology declaration; explicit base URL remains configurable. |

## Installed rollout gates

Read-only preflight confirmed the existing web service is active and controller
permissions/runtime/API/static/systemd/Ansible syntax checks pass. Ordinary
controller readiness still reports retained unresolved history. The existing
panel database was read without modification: 34 tables, zero workstation tables;
the integration is disabled before deployment. A fresh native
maintenance plan was prepared; its exact-SHA confirmation succeeded within TTL. Fresh backup create and verify
succeeded; rehearsal/guarded installation remain separately measured gates. No historical UNKNOWN or lease was erased.

A protected administrative bootstrap was found and verified without directory
writes. Domain machine quota plus an inherited machine-join privilege were found;
the operator explicitly accepted that standard inherited privilege as an exception.
The protected bootstrap opts in and records actual effective assignees; strict
mode still rejects it, as do direct/other-group grants or unknown evidence.
No observer account/ACL or DNS mutation has been made. Strict readiness remains
blocked until actual effective-right/read checks succeed.
No privileged runtime fallback is configured.

Controller/panel installation, active reconciliation, actual scoped MCP access,
plugin cache refresh and production browser acceptance remain pending. The new
server/skill source is reproducible; currently loaded chat tools are a separate
capability inventory. Do not treat isolated stdio discovery as a chat refresh.

Private logs, receipts, source snapshots, credential metadata and screenshots
remain outside Git. They are not included in this report.

## Source commit registry

Every entry lists the exact logical commit and its owned files. Verification
commands and per-task RED/GREEN outcomes are recorded above and in the private
execution ledger; these entries are source publication evidence only.

- `6e9fd42cd6495c0ac12373e4605839dc7189b3e4` — `docs(workstations): define web directory and MCP integration`. Files: `docs/superpowers/specs/2026-10-15-workstations-web-directory-design.md`.
- `f7d384b386560d413bbb9d7559343fc101f19978` — `docs(workstations): outline implementation and guarded rollout`. Files: `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `docs/superpowers/specs/2026-10-15-workstations-web-directory-design.md`.
- `3e1c26746aa58e96f6aae1c9c32d64ae5d796f74` — `feat(workstations): add restricted paged directory observer`. Files: `deploy/alt-linux/control/alt_deploy/ad_directory.py`, `deploy/alt-linux/control/alt_deploy/ad_transport.py`, `deploy/alt-linux/control/alt_deploy/directory_observer.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `docs/superpowers/specs/2026-10-15-workstations-web-directory-design.md`, `tests/alt_linux/test_directory_observer.py`.
- `ebd0fe1a076dabe59ca0e5d174abc80315810767` — `feat(workstations): collect read-only directory DNS evidence`. Files: `deploy/alt-linux/control/alt_deploy/directory_dns.py`, `deploy/alt-linux/control/alt_deploy/directory_observer.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_directory_dns.py`.
- `16247959f76c1d50cacd77d38c1a9dc06f14585d` — `feat(workstations): expose guarded controller gateway`. Files: `deploy/alt-linux/control/alt-workstations-gateway`, `deploy/alt-linux/control/alt_deploy/ad_transport.py`, `deploy/alt-linux/control/alt_deploy/workstations_gateway.py`, `deploy/alt-linux/control/alt_deploy/workstations_projection.py`, `deploy/alt-linux/control/alt_deploy/workstations_receipts.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_workstations_gateway.py`, `tests/alt_linux/test_workstations_receipts.py`.
- `12e3b6315ce76677d7232ad385578d0353065c61` — `feat(workstations): add restricted controller transport`. Files: `app/config.py`, `app/workstations/__init__.py`, `app/workstations/client.py`, `deploy/alt-linux/control/alt-workstations-gateway`, `deploy/alt-linux/control/alt_deploy/gateway_install.py`, `deploy/alt-linux/install-control-plane-lib.sh`, `deploy/alt-linux/install-workstations-gateway.sh`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_workstations_gateway_install.py`, `tests/test_workstations_client.py`.
- `dff566fc10c585259ebe635d85f7a51948c65406` — `feat(workstations): reconcile directory DNS and inventory evidence`. Files: `app/config.py`, `app/db.py`, `app/workstations/client.py`, `app/workstations/models.py`, `app/workstations/projection.py`, `app/workstations/reconcile.py`, `app/workstations/schema.py`, `app/workstations/sources.py`, `deploy/alt-linux/control/alt_deploy/workstations_gateway.py`, `deploy/alt-linux/control/alt_deploy/workstations_projection.py`, `deploy/workstations-reconcile.service`, `deploy/workstations-reconcile.timer`, `tests/alt_linux/test_workstations_gateway.py`, `tests/test_workstations_client.py`, `tests/test_workstations_reconcile.py`, `tests/test_workstations_schema.py`.
- `c8e14ed86d154eb3fd2bc9eb6457bd8ad40d91d3` — `feat(workstations): confirm employee device links with evidence`. Files: `app/workstations/client.py`, `app/workstations/links.py`, `deploy/alt-linux/control/alt_deploy/directory_observer.py`, `deploy/alt-linux/control/alt_deploy/workstations_gateway.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_directory_observer.py`, `tests/test_workstations_links.py`.
- `c3d05949d60eab008f576d9ea9cc3196bfa7bed6` — `feat(workstations): add authorized operations and audit API`. Files: `app/auth.py`, `app/config.py`, `app/db.py`, `app/main.py`, `app/permissions.py`, `app/workstations/api.py`, `app/workstations/journal.py`, `app/workstations/service.py`, `deploy/alt-linux/control/alt_deploy/workstations_gateway.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_workstations_gateway.py`, `tests/test_workstations_api.py`, `tests/test_workstations_journal.py`, `tests/test_workstations_permissions.py`.
- `5239df572d0b0dd02589e0c1869f3a45a42cb6c1` — `fix(workstations): bind previews to relationship history`. Files: `app/workstations/api.py`, `app/workstations/links.py`, `app/workstations/projection.py`, `app/workstations/reconcile.py`, `tests/test_workstations_links.py`, `tests/test_workstations_reconcile.py`.
- `3f5d5bd722b148a18bc7f31a6ecec34bd966ec6e` — `feat(workstations): add setup and reconciliation web interface`. Files: `app/main.py`, `app/static/workstations.css`, `app/static/workstations.js`, `app/templates/base.html`, `app/templates/inventory_asset_form.html`, `app/templates/network_asset_detail.html`, `app/templates/workstations.html`, `app/templates/workstations_base.html`, `app/templates/workstations_device.html`, `app/templates/workstations_employee.html`, `app/templates/workstations_job.html`, `app/templates/workstations_plan.html`, `app/templates/workstations_reconcile.html`, `app/templates/workstations_sources.html`, `app/workstations/web.py`, `deploy/alt-linux/control/alt_deploy/workstations_gateway.py`, `deploy/alt-linux/control/alt_deploy/workstations_projection.py`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `tests/alt_linux/test_workstations_gateway.py`, `tests/browser/workstations_fixture_server.py`, `tests/browser/workstations_journey.js`, `tests/test_workstations_web.py`, `tests/workstations.test.js`.
- `9e34ef95785f6362a61c5e7b239d3c25f78afbd8` — `feat(mcp): expose workstation setup and directory reconciliation`. Files: `app/workstations/service.py`, `docs/runbooks/workstations-mcp.md`, `mcp/openvpn_mcp_server.py`, `mcp/skills/openvpn-control/SKILL.md`, `tests/test_mcp_server.py`, `tests/test_workstations_api.py`.
- `5fcb09d2a90bbf45cd52a44c61fa789f32731e5c` — `feat(workstations): package restricted integration deployment`. Files: `app/config.py`, `deploy/alt-linux/directory-observer.json.sample`, `deploy/alt-linux/install-control-plane-lib.sh`, `deploy/alt-linux/provision-directory-observer.ps1`, `deploy/install-openvpn-web.sh`, `deploy/install-workstations-web-lib.sh`, `deploy/workstations.env.sample`, `deploy/workstations_deployment.py`, `docs/runbooks/workstations.md`, `tests/alt_linux/test_directory_observer_provisioning.py`, `tests/powershell/test_directory_observer_policy.ps1`, `tests/test_workstations_deploy.py`.
- `5801b3d539aba6c6da129aac706b2faf8ff06b6d` — `fix(workstations): read observer memberships with base scope`. Files: `deploy/alt-linux/provision-directory-observer.ps1`, `tests/powershell/test_directory_observer_policy.ps1`.
- `2c15f2956d209e9e4c707f9a5938619249042711` — `fix(workstations): retain wildcard DNS evidence`. Files: `deploy/alt-linux/control/alt_deploy/directory_dns.py`, `tests/alt_linux/test_directory_dns.py`.
- `6e63ef02c662b1ca68d9e5b3207783fed2ccc0c6` — `fix(workstations): preserve execution evidence and plan blockers`. Files: `app/static/workstations.js`, `app/templates/workstations_plan.html`, `app/templates/workstations_sources.html`, `app/workstations/api.py`, `app/workstations/journal.py`, `app/workstations/links.py`, `app/workstations/projection.py`, `app/workstations/service.py`, `app/workstations/sources.py`, `deploy/alt-linux/control/alt_deploy/workstations_projection.py`, `tests/alt_linux/test_workstations_gateway.py`, `tests/browser/workstations_journey.js`, `tests/test_workstations_api.py`, `tests/test_workstations_journal.py`, `tests/test_workstations_web.py`, `tests/workstations.test.js`.

- `e292af68b6b2fa653df91a0eb2740a13366f906b` — `feat(workstations): record approved inherited join exception`. Files: `deploy/alt-linux/provision-directory-observer.ps1`, `docs/runbooks/workstations.md`, `docs/superpowers/specs/2026-10-15-workstations-web-directory-design.md`, `tests/powershell/test_directory_observer_policy.ps1`.
