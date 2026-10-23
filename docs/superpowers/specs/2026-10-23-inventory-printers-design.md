# Inventory-selected network printers: first increment

## Agreed scope

Build a standalone inventory-aware planner and Ansible playbook, then test them
on an ALT virtual machine. The user selected this increment on 2026-10-23;
integration into the general workstation Setup follows after this experiment.
Select network Kyocera printers from the same inventory location as an explicitly
selected PC. Query each candidate through the existing bounded, read-only netctl
SNMP operation before selecting a driver. Also research an official Pantum
BM5100FDW Linux driver; do not enable Pantum auto-installation in this increment.

## Approaches

1. Standalone planner plus idempotent Ansible role: selected by the user. Keeps
   inventory selection testable and permits native VM acceptance before Setup
   integration. Requires an explicit invocation for one PC.
2. Immediate general-Setup integration: postponed by the user until the standalone
   playbook has been tested. Would change controller plans, catalog and gateways.
3. Pure driverless discovery: useful when supported, but cannot replace the
   inventory-location and SNMP checks. This increment uses exact model PPDs from
   an explicit curated driver directory; driverless capability can be reported
   during research without adding a second untested installation path.

## Selection and identity

- Input: one existing, non-deleted inventory PC asset ID. Its location must exist.
  Use stable IDs, never match location names, employee text, hostname or IP to
  infer the selected PC.
- Bind the plan to both an explicitly supplied, independently verified target
  machine UUID and the selected PC's current inventory MAC identifiers. Require
  at least one valid unicast MAC unique to that PC among active cards. Before any
  changes, the target must have that UUID and at least one of those MACs. This
  prevents applying a different real PC's location plan to an unrelated target.
  For the isolated VM test only, create a temporary fixture PC with the actual
  verified VM MAC and copy the selected printer's location into that fixture;
  retain the production PC ID solely as provenance, never as target identity.
- Read production inventory without changing cards, relationships or schema.
  Only non-deleted PRINTER cards explicitly marked network and IN_USE, in the
  same location ID, are candidates. Other makes and USB printers are excluded.
- Each candidate needs one distinct canonical current IPv4. Repeated identical
  identifier rows are deduplicated; an IP belonging to another active asset or
  several distinct IPs blocks that candidate. An unknown status is reported.
- Query netctl printer inspect-ip, never perform a subnet scan. Bound candidate
  count and probe duration. A found response alone is insufficient: require an
  exact supported Kyocera model in SNMP and corroborate stored serial/MAC when
  available. Conflicting model/identity, timeout, missing driver and incomplete
  evidence yield explicit skipped/unknown reasons, never a guessed installation.
- Normalize harmless case, punctuation, ECOSYS prefix and known manufacturer
  spelling variants; preserve model suffixes (dn/cdn/cdw). M5526 is not M5526cdw.
- Produce a bounded JSON plan with timestamp/expiry, selected PC/location IDs,
  source fingerprint, queue names derived from printer asset IDs, target IP,
  normalized model, SNMP evidence and curated driver SHA256. Include excluded
  candidates with reasons. Do not serialize credentials, employee names or raw
  SNMP output. A plan with unknown/conflicting selected candidates is not applied
  silently; operator-visible readiness distinguishes a complete plan from a
  partial one. Revalidate inventory and SNMP when exporting runnable variables.

## Driver artifacts

- Keep PPD/RPM binaries outside Git. A small versioned manifest records exact
  supported model, filename, SHA256 and provenance. Import only selected PPDs
  from an explicit trusted source directory, verifying header/model and hash.
- First supported Kyocera models are those with an exact suitable PPD available:
  M2030dn, M2040dn, M2540dn, M4125idn, M5526cdw as verified during implementation.
  Reject vendor PPDs requiring unavailable executable filters or unsafe helper
  paths. Do not pick the first similarly named file or language variant.
- For Pantum record the official download URL, archive hash, package/PPD contents,
  filter dependencies and ALT compatibility status; finding a PPD does not prove
  installation or printing. No vendor installer is run during research.

## Standalone execution boundary

- New playbook uses only its printer role; no domain, DNS, firewall, reboot,
  general Setup stages, global cups configuration, queue pruning or default
  printer selection. It installs required distribution CUPS packages if missing
  and starts/enables CUPS only when needed for the selected queues.
- The role verifies the exact target machine UUID supplied at invocation and
  validates the complete variable document before changing queues. Plan lifetime,
  hashes, model/PPD identity and IP/queue-name bounds are checked.
- The role creates only its own stable `inv_kyocera_` queues using local CUPS,
  `printer-is-shared=false`, an exact PPD and socket://IPv4:9100 transport.
  Ownership markers prevent takeover of a pre-existing unmanaged queue with the
  same name. Existing foreign queues and the default remain unchanged.
- Compare desired URI, driver and managed options with actual state. Second run
  must report changed=0. Drift repair affects only owned queues and must not
  interrupt queued jobs; fail with a clear reason if a repair would do so.
- Use argv-based subprocesses/Ansible command invocation, bounded timeouts and
  root-owned private staging/receipt files. Never pass community strings to the
  VM, logs or command lines. No physical print job is submitted automatically.

## VM acceptance and evidence

- Candidate VM: existing dedicated ALT test VM 133, alt-t2-pc133. Verify actual
  UUID, live network identity and host key through the trusted hypervisor guest
  agent. A changed controller known-host entry is not overwritten: use a dedicated
  host-key file pinned to this verified VM for the isolated experiment.
- Preserve existing VM queues and relevant files; create a pre-test snapshot.
  Do not restore, reboot or replay historical UNKNOWN Setup jobs.
- Use a temporary test inventory fixture containing a VM PC and a copy of one
  chosen production printer/location, with provenance recorded. Do not move a
  production card or claim that the VM is already bound in production inventory.
- Execute real SNMP selection against the chosen printer, syntax/check validation,
  first apply, second apply and owned-queue drift/error cases. Verify URI, PPD,
  acceptance/enabled state, non-sharing, conversion/filter availability, unchanged
  foreign queues/default and zero physical job submissions. Queue creation and
  filter validation are technical acceptance; physical output remains untested.
- Unit tests cover same-location isolation, unknowns/conflicts, stale/tampered
  plans, exact model suffixes, missing filters and ownership/idempotence boundaries.

## Builder decisions

Reuse Python/SQLAlchemy models, netctl CLI and ansible-core 2.18.6. No new Python
runtime dependency is needed. Expose a small command-line planner/exporter rather
than a new web page in this increment. Keep private acceptance data outside Git;
commit source, tests, operator instructions and a sanitized result report only.

## Verified implementation decisions

- Strict native conformance enabled only M2030dn; all four other initial PPD
  candidates were rejected and are recorded in `rejected_drivers.json`. The test
  printer was changed to the user's permitted choice of a listed M2030dn.
- Preserve existing CUPS enablement; start the scheduler when required, without
  changing an existing manual/socket activation policy.
- Use the local CUPS Unix socket for peer-authenticated administration.
- Keep one invocation per target; concurrent invocations and fleet scheduling
  are not provided by this standalone first increment.
- Report post-mutation uncertainty as UNKNOWN. The full production location
  remains blocked on incomplete inventory; only the isolated fixture was applied.
