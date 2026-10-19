# Complete workstation workflow

Status: proposed design for operator review; product changes are not implemented.

## Agreed outcome

The ordinary web wizard offers one complete workstation set. It includes every
currently approved office/signature component, KRFB and VK WorkSpace. KRFB is
included automatically, rather than offered as a second profile choice. After
installation and the selected employee's first graphical login, the workstation
switches to the operator-selected final DNS resolver. The existing explicit
employee/OU selection, concrete plan confirmation and background job remain.

This follows the operator's explicit request to complete the current workstation
before changing the controller. On that workstation, the additional signature
components and KRFB have been installed and checked. VK WorkSpace has also been
installed from the selected RPM, started in the real employee session and given
a desktop launcher. The requested final resolver is active and persistent;
machine-keytab Kerberos, AD discovery and external DNS passed afterward. These
operational results do not mean the future automatic workflow is implemented.

## Existing behavior and defect boundary

- The published catalog has several historical software profiles. The web wizard
  presents all of them, including an office set without signature software.
- KRFB currently requires a controller process environment confirmation of port
  restriction and a real, correctly owned employee home. The file/configuration
  role does not reload an earlier user-launched KRFB process.
- Waiting-job verification is explicitly read-only. It observes the first login
  but does not execute deferred user components. Merely changing the default
  profile or setting a global confirmation flag cannot deliver automatic KRFB
  installation on a clean workstation safely.
- The network role writes the configured domain DNS before join. There is no
  separate final-DNS component. NetworkManager's etcnet backend can reject
  connection modification; the current workstation required updating the etcnet
  resolver, reloading profiles and reapplying the active device.
- VK WorkSpace is not yet a published component.

## Canonical full profile and compatibility

Introduce `workstation-full-v1` as the one ordinary web/MCP workflow preset.
Preserve `base`, `core-apps`, `office-standard-v1` and `office-signature-v1`
definitions, API compatibility and all archived requests/results. Do not rewrite
existing assignments or describe an earlier nine-component job as a complete
new-profile installation.

The new profile contains the existing system, domain, Plasma, browser, office,
Nextcloud, web-access agent, CSP, CAdES, GosPlugin, certificates, shortcuts and
KRFB components. It additionally contains `software.vkworkspace`, a managed VNC
network-guard stage and final-DNS stage. Component declarations, dependencies,
role mapping and verification remain in the existing published registry. Fixed
supported recipes may be extended; operators cannot supply arbitrary roles,
commands, artifact paths or YAML.

The wizard displays the complete component list and the remote-access/DNS
changes before confirmation. It removes the ordinary software-profile and
remote-profile choices for this preset. The individual-component operation
remains available. Legacy API requests retain their existing meanings and guards.
MCP and the existing skill document the same canonical preset and waiting stages.

## Approved VK WorkSpace artifact

Register an immutable RPM artifact and normal idempotent software component:

- Package: `vkworkspace`, `26.4.0.141207-1.el8`, `x86_64`.
- Source: `https://hb.bizmrg.com/vkteams-www/linux/x64/vkworkspace.rpm`, linked by
  the vendor's [download page](https://vkworkspace.kz/download/).
- SHA-256: `386b314d8a31ec06330e60ea842268304c98e39be343fb95ea5907a8d896cdc9`.
- Controller artifact location is fixed beneath the existing protected artifact
  root, rather than an employee's Downloads directory.
- Verify the exact package identity, hash, installed executable and desktop
  launcher. Preflight accounts for the approximately 1.17 GB installed size and
  the actual planned transaction. Preserve user application data; never use
  vendor uninstall as an automatic rollback.

The actual pilot's RPM simulation and installation succeeded with one new
package and no upgrades/removals. The selected file matched the official HTTPS
download byte for byte. The installed files verified and a real mapped X11
window appeared. This establishes installation/startup, not authentication to a
corporate workspace or application business acceptance. RPM signature-verifier
incompatibility on the pilot is recorded separately from valid payload digests
and the independent official-source hash comparison.

## Managed VNC restriction

The new profile explicitly authorizes a host-only VNC restriction before KRFB can
listen. Establish it before the first employee login, then independently verify
the actual kernel rules immediately before configuring/starting KRFB.

The policy rejects non-loopback TCP port 5900 for IPv4 and IPv6, allowing access
through SSH. It owns one dedicated table/chain and persistent startup service.
It must not flush the ruleset, edit unrelated firewall tables, open LAN access,
change routing or modify network infrastructure. Refuse an ownership collision
with an existing table/service. The firewall remains effective across reboot and
before graphical applications start. Unsupported or conflicting firewall
management blocks this stage with a concrete error.

The concrete restriction and its installation are included in the original
plan. Intent to install the guard is distinct from proof that it is effective.
Replace the new profile's dependence on a global environment flag with fresh
per-target evidence bound to machine identity, boot, source and approved policy.
Never manufacture the old confirmation flag or treat its presence as kernel
evidence. Preserve the legacy opt-in contract for old API/profile requests.

## Worker-owned first-login phase

The new profile's original plan covers a second, bounded user phase. Before a
real selected-employee graphical login, show `waiting_first_login`; do not create
a synthetic home, log in with employee credentials or share the greeter.

Readiness requires the same enabled employee GUID/SID, domain computer identity,
fresh trusted SSH, a real graphical session for that employee, and the existing
safe home/parent ownership checks. For this profile, the worker detects that
readiness and executes only the declared user phase. It must never dispatch the
full Setup or join again. Its plan/source/identity and network evidence must
still match. Changed or unprovable evidence prevents execution.

Use a distinct durable, exclusive phase claim and recorded stage transitions
within the original job. A restart or lost reply must not replay a consumed
phase. Uncertain application preserves UNKNOWN and original receipts. An old
waiting job without the new explicit phase contract is never picked up by this
mechanism. Preserve the existing lifecycle lock, global single-PC execution and
fair queue handling; waiting for human login must not block other eligible PCs.

Keep ordinary status polling and existing verification read-only. A web view or
verification click must not become the hidden executor. Worker execution and its
errors/events remain visible in the same job. Bound every phase's execution time
in the original plan; initial SHA/TTL confirmation remains mandatory.

Configure KRFB only for the selected employee, using protected existing Vault
passwords and package-owned launchers. If an earlier KRFB process predates the
new configuration, distinguish it from an active VNC session: preserve connected
clients, report a waiting/operator action if necessary, and reload only a proven
safe instance. Never terminate the KDE, RDP or employee session to reload KRFB.
Verify actual SSH-tunnel authentication/framebuffer delivery and rejection of
direct network access without logging passwords or retaining desktop images.
Pre-login remote control and temporary XRDP are outside this new profile.

## Final DNS stage

Keep the existing domain-DNS prerequisites during join and installation. After
all required system/software/user stages are technically verified, apply the
operator-selected final DNS policy as the last mutating component. The reviewed
plan names the final resolver and relevant client changes; it does not change
the DNS server or its forwarding configuration.

Detect the actual supported resolver backend. On NetworkManager/Etcnet, preserve
the connection UUID, addressing, routes and unrelated options; back up and update
the persistent interface resolver, reload profiles, then reapply only the active
device. Do not assume that `nmcli connection modify` can persist an Etcnet
profile. Do not bring the connection down or reboot the workstation. Support
other already supported backend variants only with explicit tested detection;
unknown ownership/backend combinations fail closed.

Before and after applying, verify AD LDAP/Kerberos discovery, relevant controller
addresses and approved external-name resolution. Independently obtain a machine
Kerberos ticket through the final active resolver, using the existing keytab and
an ephemeral protected cache, without changing domain identity or employee
credentials. Verify persistent and active DNS against the planned policy and
retain a private backup and sanitized result.

If the final policy cannot be verified, restore only the owned DNS configuration
and independently verify restoration. A proven rollback records an explicit
failed/degraded finalization stage; it does not justify repeating join or earlier
software stages. Lost access or an unproven outcome remains UNKNOWN. DNS
finalization must not silently overwrite an unrelated concurrent configuration
change. It must remain observable after a real test reboot without replaying
installation.

## UI, MCP, logs and acceptance

Show the canonical full set, network restriction, first-login user phase and
final DNS stage in the plan and progress view. Include their exact failures and
sanitized complete event stream. Preserve cursor/gap reporting, immutable
historical events and the distinction between installation, technical checks and
real signing/application acceptance. A success label requires every required
technical stage, including final DNS and KRFB, to pass; a running process or a
package alone is insufficient.

Keep employee creation disabled. Preserve AD/DNS/inventory reconciliation and
explicit device links. Do not change old UNKNOWN entries, replay old jobs, reset
computer accounts or release consumed recovery claims.

## Verification and deployment boundary

Use meaningful RED/GREEN tests for canonical profile selection, artifact
validation, backend-specific DNS, guard ownership, per-target proof, real-login
eligibility, phase claims, crash/lost-reply handling, queue isolation and legacy
compatibility. Exercise the real browser plan/progress flow.

Rehearse the entire new profile on an isolated clean ALT clone, with a fresh
snapshot and distinct machine/domain identity. Include reboot, actual employee
login, KRFB and final DNS persistence. Reboot/login on a real workstation retain
their separately agreed operational boundaries. Do not reinstall the current
pilot or replay its successful Setup for release testing.

Publish verified changes normally to main and perform guarded deployment only
with fresh controller backup/verify/rehearse, current maintenance coverage and
native exact-SHA/TTL requirements. Existing expired approvals cannot authorize a
different native review. Verify installed source hashes and compare historical
baselines after deployment. No permission to alter unrelated network or AD
policy is implied by this design.

The implementation plan and its execution method are reviewed after this written
design is approved. No source implementation or new-profile deployment is claimed
by this proposed document.
