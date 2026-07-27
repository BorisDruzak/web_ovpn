# Server Health Web Page Design

## Purpose

Expose the existing read-only server health snapshot in the OpenVPN web panel
on a dedicated page. Operators must be able to see which registered server
roles are healthy, why a role is degraded, and whether the information is
current. The page must not trigger remote probes and must not expose target
addresses, SSH users, credentials, key material, or raw command output.

## Current state and problem

`server-observer.timer` runs the gateway collector every five minutes. The
collector writes its redacted result to
`/var/lib/openvpn-web/server-observer/latest.json`; VPN-path evaluation already
uses that snapshot as evidence. The web panel currently has only a static
Server Health card on the network dashboard and no Server Health route or API.

The production collector is currently failing and the last snapshot is stale.
The CLI deliberately reports only `collector failed`, so an operator cannot
distinguish configuration, SSH, remote probe, snapshot-write, or unexpected
collector failures. A stale snapshot must therefore never be represented as
current health.

## Scope

This change consists of one user-facing feature with two delivery phases:

1. Make the collector produce a redacted, actionable failure record while
   preserving its isolated systemd execution model and atomic snapshot writes.
2. Add a dedicated authenticated Server Health page and matching API that render
   the latest snapshot, including explicit freshness and collector status.

The work is read-only with respect to monitored servers and the network. It
does not change MikroTik, OpenVPN, DNS, DHCP, IPsec, firewall rules, or target
server configuration. Runtime target configuration remains only in
`/etc/openvpn-web/server-observer.json` and is never committed.

## Page and API design

The browser route is `GET /network/server-health`; it follows the existing
network-page authentication behaviour. The API route is
`GET /api/v1/network/server-health` and uses the existing bearer-token
authentication behaviour.

The response contains only the redacted snapshot data plus page-level derived
state:

- `collected_at` and an age derived at request time;
- `freshness`: `current`, `stale`, `missing`, or `invalid`;
- collector outcome: `ok` or a safe failure class;
- summary counts for `ok`, `warn`, `critical`, and `error` target states;
- target role, status, check count, failed/warning check count, and individual
  check name, status, timestamp, and safe message.

The response must never include `host`, `address`, `ip`, `ssh_user`, command
strings, exception tracebacks, paths to private files, passwords, keys, or raw
remote stdout/stderr. Unknown keys in a snapshot are discarded rather than
passed through to the client.

The HTML page has:

1. A heading and a freshness banner showing the last update time and age.
2. A collector-status banner independent of target state. When collection has
   failed, it explains the classified failure and directs an operator to the
   server-observer service logs without rendering sensitive diagnostics.
3. Four summary counters: OK, warning, critical, and error.
4. One compact row per configured role, with role, overall status, problem
   count, and most recent observed time.
5. A disclosure control on each row. The expanded content lists the role's
   checks such as disk capacity, DirectumRX, MongoDB, RabbitMQ, Redis, IIS, and
   DNS, with the safe status message for each.

The network dashboard retains a compact Server Health card. It links to the
new page and shows the number of critical/error roles when the data is current;
otherwise it shows that the health data is stale or unavailable.

## Snapshot and failure contract

The collector keeps its existing success snapshot contract. On failure it
writes a new redacted failure snapshot atomically, rather than leaving a prior
success snapshot looking current. The failure result records:

- collection timestamp;
- `status: error`;
- a stable, allow-listed failure class;
- a short safe operator message;
- an empty target list unless individual target results were safely completed.

The allowed failure classes are `config`, `ssh`, `probe`, `snapshot_write`, and
`internal`. Classification is based on known exception and subprocess-result
boundaries, not on substring-copying exception text. Full diagnostic detail
remains only in the protected systemd journal.

The web snapshot loader validates the JSON shape, limits accepted string
lengths, validates timestamps, and derives freshness using the same configured
maximum age used by the existing path-health adapter. Missing, malformed,
future-dated, or over-age data returns a synthetic non-current result. No web
route reads or invokes SSH, shell commands, or collector configuration.

## Components and boundaries

- `app/server_observer.py` remains responsible for allow-listed remote probes
  and redaction of target results.
- `app/server_observer_cli.py` owns CLI-level exception classification and
  atomic failure snapshot writing.
- A focused snapshot-view adapter loads, validates, redacts, and summarizes
  snapshots for the web/API surface. `network_paths_adapter.py` continues to
  consume the common validated snapshot loader so freshness rules cannot drift.
- `app/api.py` exposes the redacted API response; `app/main.py` serves the
  authenticated HTML route; templates render provided data only.
- Existing deployment scripts and hardened `server-observer.service` retain
  their ownership, permissions, key isolation, and five-minute timer model.

## Error handling and operational recovery

Before changing code, reproduce the failed collection on production with the
existing read-only diagnostic workflow and inspect the protected service
journal. Correct only the proven failure cause; do not guess from the generic
message or alter target systems. After deployment, run one collector cycle,
confirm a new snapshot timestamp and expected redacted shape, verify the timer
is scheduled, and load both the authenticated page and token API.

A failure of one monitored role is displayed as that role's result and does not
erase results for other roles. A collector-level failure produces a prominent
non-current state. The UI does not infer that a stale previously-OK role is OK.

## Testing and acceptance criteria

Automated tests cover:

- valid, missing, malformed, stale, and future-dated snapshots;
- safe handling and rejection of sensitive/unknown snapshot fields;
- safe failure classification without exception or command leakage;
- authenticated and unauthenticated route/API behaviour;
- summary counts, disclosure details, dashboard link/card, and stale/failure
  banners;
- continued use of shared freshness data by VPN-path checks;
- deployment asset hardening remains intact.

Acceptance requires a successful production collection after the root cause is
corrected, a fresh redacted snapshot, active scheduled timer, working dedicated
page/API, no sensitive data in HTTP responses, and a tested rollback path using
the existing server-observer backup/rollback scripts.
