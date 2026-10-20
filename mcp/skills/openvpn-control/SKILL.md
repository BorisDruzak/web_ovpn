---
name: openvpn-control
description: Use when managing OpenVPN Web Manager, workstation Setup, AD employee search, explicit device links, or AD/DNS/network/inventory reconciliation through the existing openvpn-control MCP server.
---

# OpenVPN Control

Use the `openvpn-control` MCP tools for OpenVPN management tasks.

## Workstations: search, select, preview, confirm, watch

Workstation tools use a separate scoped API credential. A legacy OpenVPN token grants no workstation rights. Read tool schemas for exact required fields; do not substitute SSH, raw LDAP or Ansible commands for a denied operation.

| Purpose | Tools |
| --- | --- |
| Availability and evidence | `openvpn_workstations_status`, `devices`, `catalog`, `sources`, `findings` |
| Existing employees | `openvpn_workstations_search_users` |
| Explicit relationship | `openvpn_workstations_link_preview`, `link_confirm`, `link_end` |
| Protected plan | `openvpn_workstations_plan`, `component_plan`, `apply` |
| Original operation and job | `openvpn_workstations_operation`, `jobs`, `job_status`, `job_events`, `verify`, `cancel` |
| Comparison and audit | `openvpn_workstations_reconcile`, `reconcile_status`, `journal` |

In this table every shortened name has the `openvpn_workstations_` prefix. Employee creation is unavailable, including through MCP.

Example: to prepare an office workstation for an existing employee:

1. Read status, devices, catalog and sources. Setup executes globally one PC at a time; several operators may read concurrently. Reconciliation has its own singleton guard and reads sources without changing them. If evidence is stale, incomplete or conflicted, run `reconcile` with a new `request_id` and watch `reconcile_status`; inspect sources/findings. Hostname, IP and DNS matches are candidates, not proof of ownership.
2. `search_users(query=<FIO or login>)`. Show homonyms with login, UPN, department and state. Obtain an explicit choice of the existing employee's GUID/SID; never select the first match. Disabled/deleted/ambiguous identities cannot be confirmed.
3. For an explicit link, use `link_preview(request_id, device_key, user_guid, computer_guid, source_revision)` from the fresh complete devices result. Read its result through `operation`. Confirm the reviewed `preview_id` with its exact `expected_revision` and a non-empty reason using a new `request_id`. Fresh GUID/SID/state and protected native assignment are rechecked. Preview expiry, changed evidence or conflicting links require a fresh preview. `link_end` also needs exact revision and reason; history remains. Manual inventory owner fields are preserved; uncertain inventory associations use the existing inventory comparison UI.
4. `plan(request_id, machine_uuid, user_login, user_guid, user_sid, ou_id, software_profile, remote_access_profile)` uses the selected identity and approved catalog IDs. Ordinary Setup uses **`software_profile=workstation-full-v1`, `remote_access_profile=krfb`**: one complete preset, including signing software, VK WorkSpace, certificates, conditional empty-name KWallet repair and direct KRFB. If this preset is absent, report an unavailable/outdated controller; never downgrade to a legacy profile. Old catalog/API profiles remain compatible with history. `component_plan` uses the existing native assignment; direct KRFB and final DNS cannot be routed through an old component path. Read the original operation to obtain the actual plan.
5. Review the concrete plan, scope, warnings and TTL. `apply` requires a new retained `request_id` plus exact `plan_id`, `sha256` and `kind` (`full_setup` or `component`). Use the authorization already provided for that scope; this skill adds no extra approval requirement. Never invent a confirmation SHA or relax a native guard.
6. Read `operation` until its result identifies the original job; then `job_status` and `job_events(after=<last sequence>, limit=...)`. The original job has `system`, `user`, `final_dns` phases. After an actual required reboot and genuine graphical login by the selected employee, the worker automatically admits each later phase once; status/verify never dispatch it. Report `workflow.phase`, phase outcomes and `waiting_reason`; active VNC clients or a certificate importer may require waiting. No new Setup/join is needed. Drain event pages, deduplicate sequences and report gaps. `journal` retains its filters/cursor/export. Technical verification and user functional acceptance remain separate; reboot is not exposed here.

Direct VNC uses `<workstation-address>:5900`, mandatory separate KRFB password and the selected employee's existing desktop. SSH tunneling is optional; there is no desktop before actual graphical login. Passwords stay in protected Vault and are never plan/log fields. Before all other user-stage effects, KRFB refuses a required reload while a viewer is connected. Final DNS is last and uses the exact protected resolver list displayed in the plan. `rolled_back_verified` is degraded finalization, uncertainty is UNKNOWN; neither permits replay. System CA trust follows CSP installation; selected-user NSS/CryptoPro stores are finalized after login and independently verified, including the organization root for the cloud. Do not close employee applications to force readiness.

Retain each mutating call's `request_id` before sending it. If its initial reply is lost, call `operation(operation_id=<that original request_id>)`; if known, the returned panel `operation_id` also works. This is a read-only receipt lookup with the same actor and action grant. Never create a new apply/request because of a lost response or urgency. UNKNOWN means keep UNKNOWN and report the original IDs and missing evidence; no repeat apply, join, reboot, claim release or recovery. A 404, denied lookup or missing job is not proof that nothing ran. `cancel` requires the native exact SHA and cannot clear UNKNOWN.

Do not paste employee search results, credentials or full logs into unrelated diagnostics. `openvpn_diagnostic_snapshot` remains the existing coarse VPN/network diagnostic and does not include directory data.

## Rules

- Use MCP/API first. Do not SSH to the server or call `vpnctl` directly unless the MCP/API layer is unavailable or the user explicitly asks for server diagnostics.
- For diagnostics of OpenVPN, client routes, Network Observer, MikroTik/RouterOS sources, IPsec site-to-site, RouterOS backups, and network collection logs, use the read-only MCP tools first.
- Prefer `openvpn_diagnostic_snapshot` for a quick health picture, then drill down with `openvpn_network_ipsec`, `openvpn_network_dashboard`, `openvpn_network_hosts`, `openvpn_network_routes`, `openvpn_network_sources`, `openvpn_routeros_backups`, and `openvpn_network_logs`.
- Use direct SSH, Winbox, `vpnctl`, or `netctl` only after the MCP/API result is missing, stale, contradictory, or too low-level for the requested change.
- Client deletion is intentionally not exposed through MCP. To remove access, use `openvpn_disable_client`.
- `openvpn_disable_client` requires both `confirm_client` equal to the exact client name and a non-empty `reason`.
- CCD must not be changed by pasting raw text through MCP. Use `openvpn_apply_network_template` or `openvpn_apply_networks` so routes are generated from the network catalog.
- Config-changing client tools require `confirm_client` and `reason`: `openvpn_apply_network_template`, `openvpn_apply_networks`, `openvpn_reconnect_client`, and `openvpn_update_ovpn`.
- Treat `openvpn_view_config` and `openvpn_update_ovpn` results as sensitive because OVPN content can contain private client material. Do not paste full config contents back to the user unless explicitly requested.
- Prefer read-only tools first: `openvpn_status`, `openvpn_list_clients`, `openvpn_inspect_client`, `openvpn_connections`, `openvpn_networks`, and `openvpn_network_templates`.
- For profile creation, run `openvpn_preview_client` before `openvpn_generate_client`.
- Report the API/MCP result plainly and include any `status`, `client`, `profile`, `vpn_ip`, and error details returned by the tool.

## Tool Map

- `openvpn_status`: service and NAT status.
- `openvpn_profiles`: available profile types.
- `openvpn_list_clients`: registered clients.
- `openvpn_inspect_client`: one client detail.
- `openvpn_preview_client`: dry-run profile generation.
- `openvpn_generate_client`: generate or update profile.
- `openvpn_disable_client`: disable client access with confirmation and reason.
- `openvpn_view_config`: read raw OVPN and CCD content.
- `openvpn_networks`: tagged network catalog.
- `openvpn_network_add`: add or update a CIDR with a tag and NAT/ViPNet flag.
- `openvpn_network_templates`: route templates built from catalog networks.
- `openvpn_network_template_add`: create a custom template from catalog CIDRs.
- `openvpn_apply_network_template`: rewrite CCD from a network template with confirmation and reason.
- `openvpn_apply_networks`: rewrite CCD from selected catalog CIDRs with confirmation and reason.
- `openvpn_reconnect_client`: request selective client disconnect through OpenVPN management when configured.
- `openvpn_update_ovpn`: replace OVPN content with confirmation and reason.
- `openvpn_connections`: current connections.
- `openvpn_nat_status`: NAT counters.
- `openvpn_network_dashboard`: Network Observer dashboard summary and source health.
- `openvpn_network_hosts`: observed network hosts with optional filters.
- `openvpn_network_host_detail`: one observed host by IP address.
- `openvpn_network_sources`: configured Network Observer sources.
- `openvpn_network_interfaces`: observed router interfaces, optionally by source.
- `openvpn_network_routes`: observed router routes, optionally by source.
- `openvpn_network_observations`: raw observations for one host or all hosts.
- `openvpn_network_ipsec`: IPsec peers, policies, SAs and bidirectional site checks.
- `openvpn_routeros_backups`: RouterOS backup/export inventory.
- `openvpn_network_logs`: recent Network Observer collection logs.
- `openvpn_diagnostic_snapshot`: read-only aggregate health snapshot for OpenVPN, management, connections, NAT, Network Observer, IPsec, backups and logs.
- `openvpn_logs`: service and operation logs.
