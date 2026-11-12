# Helpdesk inventory integration (staging)

web_ovpn owns the employee UUID and the explicit assignment of inventory PCs. It
does not infer assignments from legacy free text, AD, hostname or IP. Existing
inventory cards, Endpoint mappings, and workstation directory links remain
available independently. Two employees can have the same name.

The inventory menu opens **Employees and devices** at `/inventory/people`.
An operator can find employees by name or department, add or edit a profile,
search for a PC, and assign it as primary or shared. The same flow opens from
an existing PC card with that PC selected. The employee card displays the
current Endpoint presence and the reason recorded for completed assignments.
The directory counts employees in each filter across the search results before
pagination. Use the filters to find employees without assigned PCs, missing agents,
offline agents, unavailable presence data, or bindings that require review.
The connected filter requires every assigned PC to have a confirmed online agent.
Page access uses `workstations:link`, and writes require the session CSRF token.

Operator endpoints under `/api/v1/inventory/people` require an authenticated web
session with `workstations:link` (or an administrator). Writes also require the
session's `X-CSRF-Token`. The collection supports bounded name/department search
and pagination. Create an employee with `full_name` and `department`, then
`PUT /{person_id}/assignments/{asset_id}` with `{"role":"primary"}` or
`{"role":"shared"}`. Repeating an unchanged assignment returns the same ID.
At most one active primary per PC is allowed; a conflict returns 409 without
changing the previous assignment. To transfer a primary or change a role,
`POST /{person_id}/assignments/{assignment_id}/end` with a reason, then create
the new assignment. A deleted PC's assignments end permanently; restoring the
card does not reassign it.

Helpdesk reads `GET /api/internal/helpdesk/v1/inventory/people/{person_id}`
using a dedicated bearer token. Configure only its SHA-256 digest on web_ovpn
via `HELPDESK_INVENTORY_TOKEN_HASH`. An unset digest disables the read API.
Configure trusted HTTPS for remote traffic. The service credential cannot
search the directory, create people, assign devices or authorize diagnostics.
There is no anonymous employee search.

For the reverse, read-only account status lookup, configure
`HELPDESK_INVENTORY_STATUS_BASE_URL` with the Helpdesk HTTPS origin,
`HELPDESK_INVENTORY_STATUS_TOKEN_FILE` with a restricted file containing a
separate bearer secret, and optionally `HELPDESK_INVENTORY_STATUS_CA_FILE`.
Helpdesk receives only the digest through `HELPDESK_INVENTORY_STATUS_TOKEN_HASH`.
The client sends at most 250 exact inventory employee UUIDs per
`POST /api/internal/inventory/v1/helpdesk-account-status`. The list and
no-account filter count the search results before pagination. A failed lookup
shows unknown status and cannot place a person in the no-account filter.
The employee card shows the verified Helpdesk login and opens its admin
profile, which still requires the operator's own Helpdesk session and rights.

The response contains employee UUID, name and department, profile timestamp,
observation timestamp, and active assignments. Each assignment includes its
UUID and creation time, the inventory asset UUID, role, display name, OS,
inventory number, and a confirmed Endpoint UUID and binding UUID/version if
available. A proposed Endpoint association is marked for review and never
supplied as a confirmed UUID. Presence is `online`, `offline`,
`not_detected` (no confirmed UUID), or `unknown` (no trustworthy current
status). An offline response requires a recent successful presence observation.
A UUID remains valid as an inventory association even when presence is unknown.
The response is display data; diagnostics still require Helpdesk's own policy.

The current change adds two tables on the application's normal schema
initialization. There is no automatic employee import or migration from legacy
text. Verify with synthetic people and a separate SQLite database; the
production web installer is not the staging procedure.

## Endpoint Agent installation and linking

Open **Привязать Endpoint Agent** from the assigned PC on the employee card.
The inventory card shows saved candidates, their exact evidence and the
existing confirm/reject workflow. Its server endpoint still checks current
card revision and rejects conflicting links.

Open **Установить Endpoint Agent** from the PC card. For Windows, the action
opens the Enrollment console at the configured HTTPS Endpoint origin. Use
the existing verified Setup package that embeds the MSI. The handoff carries
no enrollment credentials and the browser sends no remote command.

For ALT, the page offers **Подготовить план установки** when the controller
publishes `software.endpoint_agent` and the PC has one ready, unambiguous
machine in a fresh reconciliation. The request sends the inventory asset
UUID in the path. The server resolves the machine UUID, confirms the
published component and prepares the existing component plan. Before
applying, the server checks the same asset-to-machine identity again. Apply
uses the existing exact plan SHA, permission, queue and job status.

Publishing the ALT component against a verified staging artifact and issuing
a one-time installation assignment tied to the asset remain staging work.
An install plan or successful local package exit provides no proof of
registration or heartbeat. Verify both through Endpoint before treating an
installation as complete.
