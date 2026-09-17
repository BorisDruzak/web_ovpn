# Inventory Netctl identifier synchronization

## Goal

Keep inventory cards current from the Network Observer snapshot without changing
any inventory properties except the network identifiers `IP`, `MAC`, and
`hostname`.  The immediate user-visible outcome is automatic refresh of IP and
hostname for cards whose MAC address uniquely identifies the observed device.

## Scope and non-goals

In scope:

- Read the published Netctl host snapshot after collection.
- Reconcile inventory IP and hostname for an unambiguous MAC match.
- Preserve identifier history, record a run result, and make failures visible
  in the system journal.
- Run outside browser requests and outside the interactive inventory flow.

Out of scope:

- Any change to asset type, location, relations, status, people, hardware,
  photos, printer SNMP fields, or other card values.
- Creating cards from Network Observer data.
- Matching a card by IP or hostname alone, or inferring a MAC onto a card that
  does not already have one.
- A new inventory UI, a manual sync button, or automatic Nmap execution.

## Options considered

1. Synchronize when an inventory card is opened.  This makes page reads write
   to the database and can block the mobile workflow; rejected.
2. Have the Netctl collector write directly into the inventory database.  It
   mixes the `netctl` and `openvpn-web` privilege boundaries and makes a
   collection failure harder to isolate; rejected.
3. A separate, unprivileged `openvpn-web` one-shot service that reads the
   already-published snapshot through the existing Netctl command boundary.
   It runs on an offset five-minute timer and only processes an unseen,
   non-stale snapshot.  This is the selected approach.

The timer offset means collection owns publication of the snapshot.  The
synchronizer never starts a collection, availability check, snapshot refresh,
Nmap, or SNMP job.

## Components

### Snapshot reader

`app/inventory/netctl_sync.py` will invoke the same Netctl command integration
used by inventory lookup to page through `netctl hosts list --status current`.
It will retain the snapshot id, generation time, stale flag, and host records.
Only a complete, non-stale snapshot newer than the last successful run is
eligible.  A command error, malformed page, changed snapshot id during
pagination, or stale snapshot results in a skipped/failed run with no card
mutation.

### Reconciliation service

`InventoryService` will receive a dedicated reconciliation operation rather
than reuse `sync_identifiers`, because that form-oriented method deactivates
all current values not submitted in a form.

For every active inventory MAC identifier and current Netctl host:

1. Normalize MAC values with the existing identifier rules.
2. Match only when exactly one inventory asset and exactly one Netctl host have
   that MAC.
3. If Netctl provides a non-empty IP and/or hostname, replace the active value
   of that type on the card with the observed value, marking superseded values
   as historical.  The new current identifier has source `NETCTL` and the
   observation timestamp.
4. Do not clear an IP or hostname when Netctl omits it.
5. Do not replace, remove, or add a MAC automatically.  The MAC remains the
   hardware anchor and must be corrected by an operator if it is wrong.

Cards without a current MAC, duplicate inventory MACs, duplicate Netctl MACs,
or invalid data are skipped.  This prevents a DHCP lease or an ambiguous name
from moving an identity between cards.  Previous manually entered IP and
hostname values remain in the identifier history, even when a newer Netctl
value becomes current.

### Run ledger and execution

Add an inventory-owned run ledger with the snapshot id, generated time, start
and finish times, result (`success`, `skipped`, or `failed`), and counters for
matched, updated, and skipped cards.  Store a failure reason without host
payloads or secrets.  The ledger provides idempotence: the same snapshot is
never reconciled twice successfully.

Add `deploy/inventory-netctl-sync.service` and
`deploy/inventory-netctl-sync.timer`.  The service runs as `openvpn-web`, loads
the protected application environment, and calls a narrow command-line entry
point.  Its five-minute schedule is offset from `netctl-collect.timer`.
`openvpn-web` keeps using its existing allowlisted Netctl invocation; it never
opens the Netctl SQLite database directly.  A oneshot service, timeout, and
systemd serialization prevent overlapping runs.  The installer copies,
verifies, and enables both unit files alongside the current Netctl timers.

## Failure handling and observability

- Snapshot unavailable, stale, incomplete, or already processed: exit cleanly
  with a skipped ledger entry and a concise structured journal line.
- A host/card ambiguity: skip only that match; continue the rest of the
  snapshot; increment the appropriate counter.
- A database or Netctl command failure: transaction rollback, failed ledger
  entry where possible, non-zero service exit, and no partial identifier set.
- The UI continues to work when synchronization is unavailable because card
  editing and lookup have no dependency on the timer.

## Testing and rollout

Automated tests will cover normalization, exact matching, IP/hostname updates,
history preservation, omitted values, ambiguous matches, stale and repeated
snapshots, pagination consistency, transaction rollback, CLI exit behavior,
and installer/systemd contracts.

Production rollout will back up the inventory database before migration, then
install the code and units, run the synchronizer once explicitly, and verify:

1. the Netctl snapshot is valid and fresh;
2. the systemd unit succeeds and records one ledger row;
3. only eligible cards change IP/hostname;
4. no MAC changes occur;
5. the web service and inventory pages remain healthy.

Rollback consists of disabling the new timer and restoring the database backup
if required; it does not alter Netctl collection state.

## Acceptance criteria

- A card with a unique current MAC receives a changed IP and hostname from a
  newer current Netctl snapshot without opening or saving the card.
- A card with no MAC or any ambiguous match is untouched.
- The synchronizer never starts Nmap, SNMP, Netctl collection, availability
  probing, or snapshot refresh.
- A stale, malformed, or repeated snapshot cannot modify a card.
- Form saves continue to use their existing validation and do not lose data.
- The production timer runs after Netctl collection on its normal schedule and
  exposes actionable service/ledger diagnostics.
