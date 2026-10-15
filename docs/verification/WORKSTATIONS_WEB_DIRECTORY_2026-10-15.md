# Workstations web/directory verification — 2026-10-15

## Acceptance states

Implementation and the independent whole-branch correction pass are complete.
Published runtime source: `5cbc0795dd1c17b8366c0bce12c49cc4d7acf419`.
Full Linux regression, publication CI and guarded installed acceptance are
separate gates; results below are updated only after the corresponding command.
No real workstation join, reboot or employee creation is part of this rollout.

## Verification performed

- Latest combined boundary suites: **166 passed**, 171 warnings, 28.27s.
  Command: `python -m pytest tests/test_workstations_api.py tests/test_workstations_permissions.py tests/test_workstations_journal.py tests/test_workstations_web.py tests/test_workstations_links.py tests/test_workstations_reconcile.py tests/alt_linux/test_workstations_gateway.py tests/alt_linux/test_directory_dns.py tests/alt_linux/test_directory_observer.py -q`.
- `node --test tests/workstations.test.js`: **8 passed**.
- `node --check app/static/workstations.js` and
  `node --check tests/browser/workstations_journey.js`: passed.
- `powershell.exe -NoProfile -NonInteractive -File tests/powershell/test_directory_observer_policy.ps1`:
  **46 passed checks** (28 before the later protected-DACL regression), zero
  infrastructure calls; actual Windows PowerShell
  parser, native C# compilation and real unbound ADSI adapter executed. The live
  bootstrap separately verified the same protected identity and 830 objects.
  The adapter regression reproduced shadowing of the CLR `Options` property by
  PowerShell's ADSI attribute adapter; selecting `psbase.Options` fixed it.
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
needed. Do not relabel the original run as wholly passing. Exact publication CI
subsequently passed **6020/90 skipped** for both `71b129d` and `c446029`.
Latest [full CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38777106454)
on `5cbc0795dd1c17b8366c0bce12c49cc4d7acf419` passed **6028 tests, 90 skipped**,
3478 warnings, 1597.27s. The retained full output and exit-code artifact were
downloaded and checked against that exact commit before dispatching installation.
Focused runtime-identity and ISO-contract checks also passed. Windows bootstrap
checks above and Linux provisioning/deployment **14 passed, 1 platform skip**
cover the separately authorized inherited privilege exception and adapter fix.

Live DNS exposed a valid UTF-8 owner and two absolute owners outside their zones.
New parser/reconciliation cases reproduced four failures before the fix; the new
UI diagnostic test also failed first. The passing suites above cover UTF-8 octet
limits, absolute-owner authority, explicit malformed-record findings and exclusion
from device identity. Complete page enumeration remains mandatory; query, zone
identity and budget failures still make a source unavailable.

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
The final automatic index matched published `5cbc079` (2026-10-15 17:29 UTC).
DNS-name impact identified five direct call sites, including collection,
counted-name decoding and resolver diagnostics. Dynamic gateway dispatch and
panel projection were checked against source and the 166-test boundary run.

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
| Discover current employee/computer read containers independently of Setup OUs | Reconciliation covers the directory without broadening Setup admission; new root-level objects can require an explicit read-base addition. |
| Exclude reserved root-hints/trust-anchor containers from device-name zones | They are outside device DNS comparison; service records there remain unmodified and unexamined. |
| Honor the operator's deferred Codex plugin refresh | Canonical server/skill/config and live stdio proof remain required; the current chat retains its old tool inventory until the operator reconnects it. |
| Use root-managed controller staging and test its source CLI before full installation | Native validator ancestry checks rejected `/tmp` before any rollout transaction; a wrong staging path fails closed and costs verification time. |
| Retain malformed DNS records as findings, not device identity | Section 4 requires distinct malformed-record findings; unresolved records stay visible and excluded while valid UTF-8 evidence remains usable. |

## Installed rollout acceptance

The panel is installed and accepted at its existing `/workstations` entrance.
The guarded controller installer completed with **3265 passed, 2 skipped** in
1067.38 seconds. **216 mapped controller/Ansible files** and **1390 panel source
files** were compared against published release `5cbc079`; all matched. The later
`a207670` changes only the administrator Windows bootstrap and its synthetic
policy test; controller, application, JS, Ansible and runtime contracts are
byte-identical to that fully tested installed runtime. Its actual Windows suite
passed 46 checks and focused Linux packaging tests passed 14/1. The broader
[additional a207670 CI run](https://github.com/BorisDruzak/web_ovpn/actions/runs/38788840631)
was still running when this acceptance report was prepared; it is not reported
as passed. The accepted complete runtime CI is
[5cbc079, 6028 passed/90 skipped](https://github.com/BorisDruzak/web_ovpn/actions/runs/38777106454).

Native guard returned `control_plane_allowed`. Fresh controller backup creation,
verification and rehearsal passed all 11 rehearsal checks under the confirmed
review. A protected panel source/units/environment/SQLite backup was also verified.
Original UNKNOWN records, leases and all registered machines' active markers are
unchanged; the plan-preview machine's existing employee assignment is unchanged.
No actual workstation apply, domain join, recovery or reboot ran for this rollout.

The integration identity passed a final read-only same-SID check across **830
object checks**. The operator-approved standard inherited machine-join exception
remains explicit: `effective_readonly=false`, `directory_dns_readonly=true`.
There is no administrative runtime credential fallback. Observer secrets/config
are separate in the protected Vault; unrelated values, including join credentials,
were preserved. No employee or DNS records were created/modified by the rollout.

A late repeated check exposed 18 protected-object DACLs restored to the standard
AdminSDHolder permissions (11 users, 7 groups). The previous proof incorrectly
required its own explicit deny even when the observer had no delegated write
right. The corrected Windows-only bootstrap requires a complete canonical,
protected DACL, adminCount=1, known non-observer owner/object SID, zero effective
write attributes/children/security rights, and no applicable write/reset grant.
Only the standard Everyone User-Change-Password ACE is classified by its actual
protocol semantics: changing a target password requires that target's current
password; administrative reset is a separate right and remains rejected. It never
accepts this proof for the observer itself. AdminSDHolder/domain policy and all
ACLs remained unchanged during this final check. Synthetic regression failed
first, then **46 Windows checks** and **14 Linux tests (1 platform skip)** passed.
See [Microsoft protected objects](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
and [MS-ADTS password semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2).

All four latest installed collections are complete and successful: **11 controller
registrations, 368 AD objects (209 users/159 computers), 220 valid DNS records and
470 current network observations**. The latest reconciliation contains **394
devices** and **2 malformed DNS findings**, visibly excluded from identity matching.
Network observations changed during acceptance (initially 192 observations/327
reconciled devices); these are sampled counts, not fixed catalog sizes.

The five-minute reconciliation timer and web service are enabled and active;
the last reconciliation oneshot exited successfully. In the inspected 45-minute
bounded journal there was **one upstream Netctl command failure**, correctly
published as a degraded source, followed by **six complete scheduled runs**.
Its exact upstream cause was not proven; no collector change or hidden retry was
introduced. Retained data stays visibly stale/unavailable and cannot confirm a
fresh binding while a source is incomplete. No unhandled application traceback
was found. Existing network-service failures were already present in the
pre-deployment baseline; this report does not declare that collector repaired.

SQLite changed from **34 to 40 tables**, exactly the six workstation tables.
All **255 manual inventory assignment rows** retain their original digest.
All 13 existing archived systemd unit files/enablement states, unrelated
configuration keys, environment ownership/mode and the VPN daemon PID/start time
were preserved. Actual forced-command SSH checks confirmed source-bound keys,
pinned host identity, read/execute separation and no arbitrary shell. HTTP tests
confirmed operator/reader reads, reader write denial (403) and anonymous denial
(401), without a target mutation.

The real installed-browser journey passed existing operator login, login and
full-name search, explicit employee selection, disabled employee creation, a real
immutable component-plan preview on an already assigned idle test machine,
retained UNKNOWN status/four stages/**448 native events**, desktop/mobile layout,
all four sources, both malformed-DNS cards and inventory/network links. **Zero
apply calls, browser errors or HTTP errors** occurred in the successful journey.
The original UNKNOWN VM correctly rejected a new component plan; it was not
cleared or recovered for the UI demonstration. Private screenshots were inspected.
A minor remains: the mobile component-verification table wraps evidence text
heavily at 390px; there is no horizontal overflow or lost data.

The canonical existing OpenVPN Control server/skill is version **0.2.0**. Actual
stdio discovery exposed **21 workstation tools** and **10 real scoped API calls**
passed, including all 448 retained events. The operator explicitly deferred the
Codex plugin update/reconnect; current-chat tool inventory is therefore still
old. Source/server acceptance does not imply the app cache was refreshed.
Private credentials, raw receipts/logs and screenshots remain outside Git.

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

- `71b129d23071cf7cca10f0b9aa0a36aae41cfcd2` — `docs(workstations): record integration verification and rollout gates`. Files: `README.md`, `deploy/alt-linux/README.md`, `docs/ALT_SETUP_OPERATOR_GUIDE.md`, `docs/superpowers/plans/2026-10-15-workstations-web-directory.md`, `docs/verification/WORKSTATIONS_WEB_DIRECTORY_2026-10-15.md`.
- `c446029bc8fd568170a1436afa3d0780f64128ea` — `fix(workstations): select CLR options for directory ACL writes`. Files: `deploy/alt-linux/provision-directory-observer.ps1`, `tests/powershell/test_directory_observer_policy.ps1`.
- `5cbc0795dd1c17b8366c0bce12c49cc4d7acf419` — `fix(workstations): retain malformed DNS findings and UTF-8 names`. Files: `app/static/workstations.js`, `app/workstations/projection.py`, `deploy/alt-linux/control/alt_deploy/directory_dns.py`, `docs/runbooks/workstations.md`, `tests/alt_linux/test_directory_dns.py`, `tests/test_workstations_reconcile.py`, `tests/workstations.test.js`.

- `a207670ce5b82e39f2ae651b3adc09a248b7f44c` — `fix(workstations): verify SDProp-restored observer permissions`. Files: `deploy/alt-linux/provision-directory-observer.ps1`, `tests/powershell/test_directory_observer_policy.ps1`. Verification: actual Windows policy 46 passed; Linux provisioning/deployment 14 passed, 1 platform skip; read-only live same-SID check 830 objects passed. No runtime byte changes.
