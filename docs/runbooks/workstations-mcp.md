# Workstations through OpenVPN Control MCP

The existing stdio server `mcp/openvpn_mcp_server.py` exposes 21
`openvpn_workstations_*` tools. The existing VPN/network tools and their legacy
credential behavior are unchanged. Directory information is not added to the
general diagnostic snapshot. Employee creation, raw commands, LDAP filters,
rejoin, reboot and UNKNOWN recovery are not tools.

## Credentials and discovery

Configure `OPENVPN_WORKSTATIONS_API_TOKEN_FILE` separately from the legacy
OpenVPN token. It points to a protected local regular file containing one
scoped workstation token, never a repository file or command-line argument.
On Unix it must be owned by root or the current user and inaccessible to group
and others. On Windows provision it with an owner-only ACL. The panel stores
only its hash, actor and explicit grants in `WORKSTATIONS_API_CREDENTIALS_FILE`.
Missing credentials fail closed; there is no legacy-token fallback.

Use the existing `OPENVPN_WEB_BASE_URL`, with no embedded credentials, path,
query or fragment. Workstation HTTP requests refuse redirects, bound responses
to 20 MiB and return fixed public error codes. A timeout is missing outcome
evidence, not proof that a mutation failed. A read credential cannot plan,
apply, confirm links or diagnose.

The reproducible skill source is `mcp/skills/openvpn-control/SKILL.md`. Sync the
server and skill into the existing local plugin source, preserving its local
`.mcp.json` and secrets. Update the same plugin through Codex Settings when its
cached skill needs refreshing; do not create another MCP integration or patch
generated plugin caches. A new stdio `initialize`/`tools/list` result proves
server discovery, independently of tools already loaded in a running chat.
Do not claim a running chat refreshed until its actual tool inventory confirms
that. Server version is 0.2.0.

## Tool contracts

All names below have the `openvpn_workstations_` prefix. Input schemas reject
extra fields and bound pagination. Read the server schemas for exact formats.

| Tools | Existing API and required permission |
| --- | --- |
| `status` | `/status`; coarse observer summary |
| `devices`, `catalog`, `search_users`, `jobs`, `job_status`, `job_events`, `findings`, `sources` | corresponding fixed read routes; `workstations:read` |
| `plan`, `component_plan` | `/plans`, `/component-plans`; `workstations:plan` |
| `apply`, `cancel` | native plan/job routes; `workstations:apply` |
| `link_preview`, `link_confirm`, `link_end` | fixed link routes; `workstations:link` |
| `verify`, `reconcile`, `journal` | fixed diagnostic routes; `workstations:diagnose` |
| `operation`, `reconcile_status` | original receipt; original owner and current original action grant |

All routes are under `/api/v1/workstations`. `devices(device_key=...)` reads a
single device; omit pagination in this form. `journal(export=true)` uses the
same authorized fields and cursor as the normal journal. Filters include
device, job, component, stage and severity. Continue cursors to obtain a complete
log. Job events use monotonic `after` sequences; detect duplicates and gaps.

## Protected operator sequence

Read sources, devices, findings and catalog before selecting a PC. Stale,
incomplete or conflicting source evidence cannot authorize a link. Reconcile
with a retained request UUID and watch the original operation. Hostname/IP/DNS
matches remain candidates. Use the inventory comparison UI for unconfirmed
inventory associations; manual ownership fields are not overwritten.

Search employees by FIO/login. Show homonyms and explicitly select GUID/SID,
login/UPN, department and enabled state. For a link, preview the selected user,
optional computer GUID, exact device key and complete `source_revision`.
Read the preview receipt, then confirm its `preview_id`, exact
`expected_revision` and reason. A fresh identity read rechecks stable SID,
state and protected assignment. Ending a link also needs revision/reason and
retains history. One employee may have several PCs.

Plan with the selected existing identity and approved OU/profile IDs.
Component plans use the existing native assignment. Review the returned plan,
scope, warnings, deferred actions and TTL. Apply with its exact `plan_id`,
`sha256`, `kind` and a new retained `request_id`; native guards remain binding.
Setup executes one PC globally at a time while operators may read concurrently.
Follow the original operation and job, including stage history, event pages,
queue position, technical outcome and functional acceptance requirements.
Reads never trigger verification; verification is an explicit operation.

Retain every mutation's request UUID **before** sending it. If the first reply
is lost, `operation(operation_id=<original request_id>)` reads its receipt;
the returned panel operation ID is also accepted. It never submits work.
Do not send a replacement apply or new request ID to resolve uncertainty.
UNKNOWN, denied/missing receipts and missing jobs require reporting the original
IDs and missing evidence. They do not prove that nothing ran. Cancellation
needs the native SHA and cannot release UNKNOWN. First login and reboot remain
explicit human stages; this integration does not perform a reboot.

Existing authorization for a concrete scope remains valid; this guide adds no
new approval ceremony. Native exact-SHA/TTL, owner and permission checks still
apply. Keep credentials, employee results and raw logs out of unrelated reports.
