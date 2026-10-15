# Workstations: web setup, AD/DNS reconciliation and MCP

Status: specification and implementation plan approved by the operator on
2026-10-15. Implementation is in progress; deployed acceptance remains pending.

## 1. Outcome and scope

Add a separate **Рабочие места** navigation item to the existing web panel.
Operators can find an existing AD employee by name or login, select a registered
ALT workstation, review a protected setup/component plan, submit it to the
existing worker, and follow its stages and errors across reconnects.

The same section reconciles AD computers, AD-integrated DNS, observed network
devices and physical-inventory cards. It shows confirmed employee/device links,
candidate matches, discrepancies, source failures and freshness. These functions
are available through the existing OpenVPN Control MCP and its existing skill.

Employee creation is deliberately a disabled interface affordance with an
explanation. There is no employee-creation API, hidden enabled form or MCP tool.
Creating one restricted integration account during deployment is a different,
explicitly requested administrative task; it is never a runtime web capability.

The requested deployment target is the existing panel, not a separate app.
Keep its FastAPI/Jinja2 design, authentication, CSRF protection, audit and inventory
relations. Do not add router, DHCP, DNS-record or employee-account writes.

Assumptions made explicit:

- Devices may register concurrently. Mutating Setup jobs keep the existing global
  serialization and show their queue position/blocker. Parallel joins require a
  separate scheduler/locking change and are outside this design.
- A DNS name or IP address does not prove physical-device identity or ownership.
- One employee may have several devices. A physical device has at most one active
  assigned employee in this feature; changes preserve relationship history.
- Automatic reconciliation updates observations and findings, not manually entered
  inventory ownership, confirmed bindings, AD objects or DNS records.

## 2. Verified baseline

Inspection started from clean, synchronized main
`e325e87e38f31dad3b7519d7f08129f2c43d07ec`.

- The panel runs FastAPI 0.115.6, SQLAlchemy 2.0.36 and Jinja2 3.1.5.
  `app/main.py` includes inventory routes and `app/templates/base.html` owns
  navigation. Both the deployed web service and inventory Netctl timer responded
  active during inspection.
- `MachineRepository` exposes registered UUID/MAC identity. `SetupService`,
  `ComponentSetupService`, `SetupJobsService` and `SetupEventStore` provide the
  canonical planning, admission, execution and safe-event contracts. There is
  currently no web adapter for them.
- `ADDirectory.user()` is an exact-login lookup, not a display-name search.
  Existing LDAP reads succeeded. The configured credential source is currently
  `join-vault`; neither read-only credential field is populated. This must change
  for the new background integration.
- `DomainAssignmentStore` is the protected source for execution assignments.
  The new UI must not rewrite it or silently reassign an already configured PC.
- Inventory already has confirmed Netctl bindings, revisions, conflict handling,
  safe source observations and per-source freshness. Reuse these relationships.
- `mcp/openvpn_mcp_server.py` is the repository MCP source. The installed local
  plugin has a separate source tree with scripts and an OpenVPN Control skill;
  updating repository code alone does not update the installed plugin.
- A browser visit reached the existing login page. Authenticated browser
  acceptance of the new flow remains an implementation/rollout requirement.

Do not treat these observations as proof that a future release is deployed.
Published code, installed controller, installed panel, plugin tool discovery and
real workstation acceptance are separate verification results.

## 3. Architecture and alternatives

Use a small web adapter and a **fixed-operation controller gateway over SSH**.
The panel calls it through a dedicated key with a forced command and restricted
SSH options. Request/response bodies are versioned JSON on stdin/stdout. The
gateway invokes the canonical Python services as the controller service user.
No operator-supplied command, executable, environment, file path or Python import
is accepted. The gateway does not run as root and cannot invoke maintenance,
recovery, reboot, user creation or arbitrary Ansible entry points.

This approach reuses SSH host authentication and avoids an additional listening
controller HTTP endpoint. Alternative private HTTPS/mTLS is valid but introduces
a listener and certificate lifecycle. Copying controller state or running a
second Setup worker inside the web process would duplicate execution ownership
and is rejected.

The transport has separate read and execution credentials. Read scope allows
catalog, registry, directory, assignment, status and event projections. Execution
scope additionally allows plan creation, exact-plan submission, explicit
verification and cancellation of an unclaimed job. Forced-command restrictions,
strict host-key checking, bounded JSON and per-operation validation are checked
on the controller as well as in the panel. A web role cannot select another key
or widen its credential scope. Provision controller keys through protected
deployment inputs; do not give the panel the controller's administration key.

Reads return bounded allowlisted projections, never the raw contents of
`request.json`, registration records, private plans, Vault, stderr or job folders.
The gateway includes a request ID and authenticated gateway scope in its audit.
The panel records the initiating user separately; a caller-supplied actor string
does not authorize an operation.

Long plan/verification requests use the panel's durable operation mechanism and
return an operation ID promptly. Target mutation always returns the canonical
Setup job ID and is executed by the existing systemd worker. Web restarts and
browser disconnects do not stop or restart a job.

## 4. Restricted AD/DNS integration

Provision a dedicated service account with a generated secret stored only in the
protected controller Vault. Runtime uses `readonly-vault` with Kerberos GSSAPI
sealing or the existing certificate-verified TLS modes. Keep join credentials
available only to the existing guarded join path. Credential failure must not
fall back to join credentials or anonymous LDAP.
Use a separate observer configuration with an enforced read-only credential
source; preserve existing controller configuration compatibility during migration.

Delegate only directory listing/required-property reads on configured employee
and computer containers and required AD-integrated DNS zone containers, including
the configured application partitions. Discover actual zones and inherited ACLs
before applying narrowly scoped read grants. Do not add the account to DNSAdmins,
Account Operators or domain administrative groups. Do not change global domain
policy or remove existing principals' ACLs. Inspect effective membership/ACLs;
the absence of a write operation in the adapter alone is not proof of least
privilege. Provisioning needs a protected administrative bootstrap identity;
the current join identity is not assumed to have account/ACL administration.

Include inherited Authenticated Users rights, DNS child creation and domain
machine-account creation rights in the privilege review. If necessary, apply
principal-specific restrictions to the integration account on the approved data
containers; retain other principals' permissions and domain policy. Merely naming
the account read-only or omitting privileged group membership is insufficient.

The deployment must prove required reads and check effective write privileges
without attempting destructive changes on real objects. If administrative access
is unavailable, report that precise deployment dependency; do not substitute a
privileged runtime identity or claim directory integration is accepted.

Extend read-only directory access with two distinct surfaces:

1. Bounded employee search by escaped login, UPN, display name and FIO tokens.
   Require at least two characters for a name query; cap input at 160 characters,
   return at most 50 rows, and explicitly report truncation. Display name, login,
   department and account state disambiguate homonyms. Selection carries GUID/SID;
   planning re-resolves the exact identity and account usability.
2. Scheduled paged reads of configured computer containers and DNS zone records.
   The configured service account reads only the attributes required for matching
   and status. No arbitrary LDAP filter, base, attribute list or zone is supplied
   by browser/MCP clients. Read forward A/AAAA/CNAME and reverse PTR records;
   retain unsupported record counts and skip unrelated record types.

Directory collection must not reuse the exact-user adapter's 256-result limit
as though it represented an entire directory. Use explicit paging with complete
result validation, a 10,000-object/16-MiB source budget, and a two-minute total
deadline. Exceeding a budget or losing a page produces an incomplete run and
preserves the previous complete snapshot with an unavailable/stale indication.
Do not publish truncated data as successful or interpret absence as deletion.

AD-integrated DNS objects and their ACLs are separate from DNS query results.
Use LDAP zone enumeration for a complete approved-zone list; bounded A/AAAA/PTR
queries to the configured resolver can independently check resolution. DNS timeout,
NXDOMAIN, no reverse zone, multiple answers, aliases and malformed records remain
distinct findings. Unsupported/non-AD-integrated zones are explicitly unavailable
for full enumeration; never enable zone transfer or DNS writes as a workaround.

AD DNS storage/ACL behavior is described in Microsoft's
[AD-integrated DNS documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/active-directory-integrated-dns-zones)
and [DNS zone documentation](https://learn.microsoft.com/en-us/windows-server/networking/dns/zone-types).
Binary record decoding must follow the documented directory
[`dnsRecord` format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8),
with bounded fixtures for A/AAAA/CNAME/PTR; do not assume ordinary DNS wire data.

## 5. Identity, reconciliation and persistence

Keep three different facts visible: an employee assigned by an operator, an AD
computer object, and current network/DNS observations. `managedBy`, inventory
`login_name` and a matching display name are useful evidence, not automatic
confirmation of device ownership or a rewrite of protected Setup assignments.

Use the following matching order and preserve evidence for every edge:

| Relationship | Confirmed identity | Candidate evidence only |
| --- | --- | --- |
| Registered ALT PC to network device | Unique current canonical MAC from registration and a non-provisional, non-conflicting Netctl identity | IP, hostname, stale MAC observation |
| Network device to inventory | Existing confirmed `InventoryNetctlBinding` | Unique current MAC may propose a candidate using existing inventory rules |
| PC to AD computer | Fresh controller-verified computer GUID/SID bound to registered UUID; otherwise explicit operator confirmation | AD `dNSHostName`, A/PTR and network hostname/IP agreement |
| Employee to device | Explicit operator selection of stable employee GUID/SID, or compatible existing protected assignment | FIO, `managedBy`, inventory text login/name |

An automatically observed unique MAC edge is a matching result, not a silent
confirmation of an inventory relation. The existing explicit inventory confirmation
and revision rules continue to apply. Duplicate MACs, reused hostnames/IPs,
provisional keys, conflicting GUIDs, disabled users, deleted inventory cards and
changed inventory revisions prevent confirmation.

Add local `workstation_*` tables for source-run/snapshot metadata, normalized
directory/DNS observations, explicit directory/device links, discrepancy state
and local request receipts. Store stable references to existing inventory cards
and network keys, without cloning inventory cards or Netctl assets. One logical
device may have several network interfaces. Relationship edits use optimistic
revision checks and retain ended relationships, actor, time, reason and evidence
revision. Protected controller domain assignments remain controller-owned and
take precedence over incompatible portal link requests.

Directory snapshots contain personal data: restrict local database/snapshot and
backup access to their service/administration identities. Do not put snapshots,
real directory identities, credentials or environment topology in Git, plugin
instructions or exported general diagnostics.

Every snapshot has source ID, completion status, observation time, generation,
counts and safe error code. Reconcile against one coherent set of source
generations plus the inventory projection revision. If inventory relations change
during publication, do not publish mixed results. Portal reconciliation uses
Netctl CLI/API and existing inventory projections, never Netctl's SQLite tables.
Endpoint integration is read through existing local inventory projections; no new
Endpoint API or cross-repository contract is required by this design.

Run collection/reconciliation every five minutes with a singleton worker lock and
no overlapping runs. Initial source-specific freshness limit is fifteen minutes;
show last attempt and last successful observation independently. A failed source
does not erase valid links or hide other source results. Retain the last complete
observation snapshot plus run history and changed findings; bound routine run/log
retention to thirty days without deleting Setup history or relationship audit.

Findings include missing/stale DNS, forward/reverse disagreement, AD-only or
network-only devices, inventory absent/unconfirmed, ambiguous identity, employee
conflict, disabled/deleted employee, unavailable source and collection budget
exceeded. Operators can inspect evidence, acknowledge a finding with a reason,
or use existing comparison/confirmation flows. Acknowledgement does not turn a
conflict into a confirmed binding or make a stale source fresh.

## 6. Web flow

The separate navigation item opens `/workstations` with views for **Устройства**,
**Задания**, **Сверка AD/DNS**, and **Источники и ошибки**. Reuse existing styles
and responsive table/card patterns. Links from network-device and inventory-PC
details open this section with the exact stable device/card selection.

The setup wizard has explicit stages:

1. Select a registered ready ALT PC; show identity and existing assignments.
2. Search and explicitly select an existing AD employee.
3. Choose an approved OU, published software profile/components and remote-access
   option. Default remote access to none; retain native additional KRFB gates.
4. Build a read-only protected plan. Show differences, blocking checks, selected
   identities, affected components, expiry and confirmation binding.
5. Confirm this displayed plan and queue it once. Expiry, source drift, changed
   GUID/SID, changed assignment or admission conflict requires a fresh plan.
6. Follow queue/preflight/domain/software/verification stages and required human
   actions. Show technical verification separately from functional acceptance.

The plan page can expose its exact native SHA as part of the authenticated
confirmation workflow; never include it in general logs or exported diagnostics.
Double clicks and transport loss resolve through the same request receipt and
native single-use plan claim. Never automatically retry an apply after a timeout;
query its receipt/job first and show an uncertain outcome if it cannot be proven.

An individual approved component uses the same component plan/apply/verify path.
The UI cannot upload a role, arbitrary YAML/playbook or command. Adding components
continues through Git, catalog validation and guarded controller deployment.

The employee picker includes an inactive **Создать пользователя** control and
the explanation **Создание пользователей пока недоступно**. It sends no request.

## 7. Progress, logs and errors

Persist and display all published safe stage transitions and component task events,
not just the current status. Show current stage, completed stages, timestamps,
duration, changed/no-op result, verification result and required operator action.
Do not invent a percentage for work whose duration/task count is unknown.

Poll status/events using sequence cursors, initially every two seconds while
visible/active, with bounded backoff on failure. Resume from the last sequence
after reload; deduplicate events, handle pagination and explicitly show gaps or
unavailable evidence. Polling is read-only and never performs AD/SSH verification.
Manual verification is an explicit operation with its own progress/result.

Correlate request ID, operation ID, job ID, component, safe task ID, stage, attempt,
timestamp and allowlisted error code across panel, gateway, controller and worker.
Classify errors as validation, authorization, source/transport, preflight,
execution, verification or uncertain outcome. Give a concrete next action and
an evidence reference; unknown outcomes stay UNKNOWN and require native review.

The web journal provides the full chronological **sanitized** history, filtering by
device/job/component/stage/severity, and paged download with matching access
control. Existing protected raw Ansible logs remain on the controller. Do not
expose arbitrary raw stdout/stderr, LDAP DNs, task arguments, secrets, Vault values,
SSH material, private file paths or traceback locals. This preserves the current
`SetupEventStore` contract while meeting the request for complete event/error
visibility. A diagnostics permission may expose additional reviewed safe details,
not arbitrary files. Errors in collection/export/audit publication are themselves
visible and cannot be reported as success.

## 8. Authorization and public API

Add explicit `workstations:read`, `workstations:plan`, `workstations:apply`,
`workstations:link` and `workstations:diagnose` permissions. Existing observer
access remains available for the non-sensitive summary. Employee directory,
assignment details and journal views require an explicit grant or administration:
do not inherit the current generic `:read` shortcut for directory personal data.
Link confirmation also requires existing inventory write rights when it modifies
an inventory relation. Do not grant execution rights to the legacy MCP token by
changing its default permission list.

Browser operations use existing sessions and CSRF. API/MCP uses explicitly
provisioned permission-scoped credentials. Directory results use private/no-store
responses. Every action, denial and failure has a bounded safe audit record.
Never log query bodies containing names or directory results by default.

The adapter API prefix is `/api/v1/workstations`. Operation families are:

- `GET /status`, `/devices`, `/devices/{id}`, `/catalog`, `/sources`, `/findings`;
- `POST /directory/search` for bounded employee search with no-store responses;
- `POST /links/preview`, `/links/confirm`, `/links/{id}/end` with revisions;
- `POST /plans`, `/component-plans`, `/plans/{id}/apply` using protected IDs/SHA;
- `GET /operations/{id}` for a durable planning/verification operation result;
- `GET /jobs`, `/jobs/{id}`, `/jobs/{id}/events` with bounded pagination;
- `POST /jobs/{id}/verify`, `/jobs/{id}/cancel` with native limitations;
- `POST /reconcile` to request one bounded collection run, and
  `GET /reconcile/{id}` to read its durable result;
- `GET /journal` and `/journal/export` with the same field/access restrictions.

Plans, receipts, links and jobs use different typed IDs. A device key is not an
IP address. Validate all IDs/limits before transport, reject extra request fields,
and use deterministic safe error envelopes and correlation IDs. Gateway operation
names are an allowlist mapping to service calls, not URLs converted to CLI strings.

## 9. Existing MCP and skill

Extend the existing `openvpn_*` tool namespace with workstation status/device and
catalog reads, employee search, link preview/confirmation, setup/component plan,
apply, job status/events/verify/cancel, reconciliation, findings and safe journal.
Each tool calls the panel API and receives the same authorization, validation and
audit behavior as the browser. Do not put an SSH or directory implementation in
the MCP server.

Read tools remain separately usable from mutations. Link changes require exact
identity/revision and reason; apply requires the exact protected plan binding.
Tools do not auto-confirm UNKNOWN review, reboot, recovery or employee creation.
There is no generic command, raw-log-path or arbitrary LDAP tool.

Update the canonical local OpenVPN Control plugin source, its MCP script and its
existing skill; synchronize the installed plugin using supported local plugin
mechanisms. Keep repository MCP and installed script content/version aligned.
Verify live tool discovery after reconnect, not just the server's local TOOLS dict.
If the running chat cannot reload tools dynamically, explicitly distinguish the
verified new server tool inventory from this chat's still-old loaded tool list.

The skill explains the employee-search/selection, preview/plan/confirm/status
sequence, read-only reconciliation, identity/conflict rules, safe logging and
UNKNOWN stopping condition. Existing VPN/network tools and their restrictions
remain covered. No credentials or environment-specific identities enter the skill.

## 10. Verification and rollout acceptance

Implementation is accepted only with evidence for the complete flow:

1. Unit/API tests cover login/FIO homonyms, LDAP escaping/paging/size limits,
   disabled accounts, DNS binary records and aliases, partial source failure,
   stale timestamps, duplicate identities, revision races and no silent rebind.
2. Gateway/transport tests reject unknown operations, shell fragments, arbitrary
   paths, oversized input/output, wrong scope and host-key errors. Plan timeout,
   lost apply response and repeated submit prove no duplicate execution.
3. Native plan SHA/TTL, user/computer GUID/SID, approved OU, immutable source,
   assignments, UNKNOWN, reboot and single-use claim tests remain green.
4. Web tests cover RBAC for observers/operators/MCP, CSRF, no-store directory
   responses, error redaction, audit and export. Browser checks cover a real
   employee search/selection, plan preview, source findings, job stages, polling
   reconnection, errors and the disabled creation control, including mobile size.
5. MCP contract tests verify schemas and API mapping. A running installed server
   must advertise the tools and return real bounded read results.
6. Restricted account/ACL evidence confirms the configured scope and required AD
   and DNS reads. A scheduled run must reconcile a complete source set with actual
   inventory relations; a failed source is visibly degraded without deleting data.
7. Publish verified source to main. Roll out controller changes through native
   backup/guarded deployment, retaining historical UNKNOWN records. Deploy panel,
   additive schema changes, restricted transport credentials and timer without
   interrupting unrelated VPN/network configuration. Verify installed hashes,
   services, schema readiness, source freshness and web/MCP behavior separately.
8. Use read-only plan/verify and existing retained jobs for production acceptance.
   A new mutating workstation test uses an explicitly authorized test target and
   its exact native plan, rather than replaying a historical UNKNOWN or performing
   a domain rejoin solely to demonstrate UI progress.

Rollback restores the prior panel/controller release with additive tables retained
and disables the new reconciliation timer/gateway key. It does not roll back or
delete genuine completed workstation jobs, AD objects, DNS records or inventory
history. Do not weaken controller backup/maintenance checks to make rollout pass.

## 11. Delivery boundaries

Implementation order is controller gateway and safe projections; restricted
directory/DNS collection; reconciliation/schema and explicit links; authenticated
API and navigation/wizard/job views; MCP/skill; then integration verification and
guarded rollout. These form one operator-facing feature with independent test
boundaries, not separate applications or competing sources of truth.

Before code work, review this written design. The subsequent implementation plan
must contain concrete files, migrations, checks and rollout commands based on this
approved contract. Creating the AD integration identity requires protected bootstrap
access; authenticated browser acceptance requires a valid operator session. Those
are deployment prerequisites, not reasons to implement an insecure fallback.
