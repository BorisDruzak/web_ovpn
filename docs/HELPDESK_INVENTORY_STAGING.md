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
Operators can enter an optional work email and telephone. These fields are
available on the employee detail and its operator write endpoints. Existing
operator updates that omit contact fields preserve the saved values. The
Helpdesk service response and employee directory summaries omit contacts.
A confirmed Endpoint UUID opens its exact console device card at the configured
HTTPS Endpoint origin, which requires its own authenticated session.
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

The application's normal schema initialization creates the employee and assignment
tables and adds nullable work contact columns to existing employee tables.
There is no automatic employee import or migration from legacy
text. Verify with synthetic people and a separate SQLite database; the
production web installer is not the staging procedure.

## Endpoint Agent installation and linking

Open **Привязать Endpoint Agent** from the assigned PC on the employee card.
The inventory card shows saved candidates, their exact evidence and the
existing confirm/reject workflow. Its server endpoint still checks current
card revision and rejects conflicting links.

Open **Установить Endpoint Agent** from the PC card. For Windows staging,
the page offers the exact signed Setup release and a private assignment
download. Prepare the compatible signed Setup/MSI pair and register the
release in the staging Endpoint console before setting
`ENDPOINT_PLATFORM_WINDOWS_INVENTORY_SETUP_RELEASE` to its release UUID.
The panel requires the fixed staging Endpoint origin and an installation
service principal with `enrollment.installation-assignments.issue` and
`enrollment.installation-receipts.read`. Issuance and lookup must use the
same principal. The regular enrollment-console link remains available in
environments without a configured Windows inventory release.
The exact release download requires Endpoint console administrator access.
Preparing an assignment requires both `workstations:apply` and
`inventory:write` in the panel.

On the selected Windows PC, run the signed Setup's read-only
`--inventory-fingerprint` mode, then submit its fingerprint from that
inventory card with the operator confirmation. The panel checks the exact
card revision, reserves the request and issues the installation assignment.
An exact retry by its original operator returns the same assignment and
expiration. The panel polls an uncertain issue and permits a new request
after expiry is established. Conflicts require review. Keep the panel
application secret stable while assignments are open so it can reconstruct
their IDs. The private download contains the assignment ID and fingerprint.
Place the downloaded file in an administrator-controlled directory with a protected
SYSTEM/Administrators-only ACL, then invoke the same signed Setup with
`--inventory-assignment-file <absolute-local-path>`. The native Setup and
Endpoint campaign remain responsible for approval and installation. The
panel waits for the verified receipt before confirming the binding.

For ALT, the page offers **Подготовить план установки** when the controller
publishes `software.endpoint_agent` and the PC has one ready, unambiguous
machine in a fresh reconciliation. The request sends the inventory asset
UUID in the path. The server resolves the machine UUID, confirms the
published component and prepares the existing component plan. Before
applying, the server checks the same asset-to-machine identity again. Apply
uses the existing exact plan SHA, permission, queue and job status.

The standalone ALT catalog entry pins the signed Endpoint 3.2.183 native
kit. Before staging publication, put the exact reviewed
`endpoint-alt-pilot-3.2.183-1.tar.gz` in the controller artifact path declared
in the catalog. Verify its detached signature and the release manifest with
the independently trusted publisher key. The controller checks the digest
before workstation contact and the role checks it again on the target before
extraction. The existing native coordinator installs the two RPMs together.

The panel generates a private installation ID in the form
`inventory-<asset-uuid>-<controller-machine-uuid>-<32 lowercase hex digits>`.
Repeating the same request reuses its ID. The controller includes it in the
confirmed plan SHA and checks it at apply. The plan expires after 30 minutes.
The ID correlates the installation with its inventory asset and carries no
Endpoint enrollment authorization.

The target needs the protected staging CA and the exact approved staging
drop-in before apply. The role creates a root-owned configuration in an empty
slot and checks that any existing protected configuration carries the exact
installation ID and staging origin. Existing or partially installed packages
require review. The role invokes native Setup once and keeps its local
receipts. A locally installed pair requires verification through Endpoint
registration and heartbeat.

Endpoint issues a hardware-bound assignment with a 30-minute lifetime.
The panel retains the approved card revision, controller machine and
network keys with the original apply request. The inventory sync reads the
provider receipt with SDK 0.2.1 and a separate
`ENDPOINT_PLATFORM_INSTALLATION_TOKEN_FILE` credential with scope
`enrollment.installation-receipts.read`. Use the same Endpoint service client
identity as the assignment issuer, with separate credentials for the two
scopes. The ID and token stay on the server.

A confirmed receipt with a fresh heartbeat creates one audited binding
after a fresh recheck of the approved card and controller target. The
inventory sync recovers uncertain controller admission through the original
read-only receipt. During an unresolved directed installation, matching MAC
observations stay as candidates. Existing manual decisions and conflicting
bindings require operator review.

On ALT, the role extracts the original runtime from the verified core RPM
in private temporary storage. The runtime's `--print-hardware-fingerprint`
mode derives the expected value on the approved workstation over the same
pinned SSH connection. The role gives that value to the controller issuer
over protected task input. Endpoint must acknowledge a live assignment
before the role writes the agent configuration or invokes native Setup.
The coordinator receives the same explicit staging markers as the approved
systemd drop-in.

Before enabling the role on staging, prepare a root-managed Python 3.12+
virtual environment at `/opt/alt-deploy-endpoint-sdk`. Verify and install
the SDK wheel selected by `deploy/endpoint-platform-client.lock` with its
dependencies. Install the staging CA at
`/etc/alt-deploy-endpoint/staging-ca.pem` and the issuance token at
`/etc/alt-deploy-endpoint/staging-assignments.token`. The token needs scope
`enrollment.installation-assignments.issue`, owner/group `root:altserver`
and mode `0640`. The CA is root-owned with mode `0644` or `0640`
for group `altserver`. The issuer uses the fixed staging Endpoint origin.
The plan checks the issuer's local SDK and credential files before it
can be applied. The workstation needs `rpm2cpio`, `cpio` and `timeout`
for the probe. The assignment must still cover the native coordinator's
120-second enrollment notification budget. Retained identity or unfinished
enrollment requires native recovery. The role cleans up its private
temporary directory on exit.

The signed Windows Setup/MSI build, exact release registration and
integrated staging verification are deployment gates.
