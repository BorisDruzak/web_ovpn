# Read-only MikroTik to server path visibility

## Goal

Add a read-only Network Paths section to the web panel. It shows the observable delivery path from OpenVPN through the central MikroTik to every registered Server Health role: routes, address lists, firewall evidence, collector freshness, RouterOS update posture, and target health.

The first release displays only existing Server Health roles. A later role is added through local runtime configuration, not a bespoke page or code branch.

## Safety boundary

- No change to RouterOS, OpenVPN, systemd, firewall rules, address lists, routes, client profiles, DNS, or target servers.
- No RouterOS `check-for-updates`, installation, firmware upgrade, reboot, scheduler/script modification, or arbitrary command.
- No credentials, keys, command text, or raw transport output in Git, API, or HTML.
- Topology stays local in `/etc/openvpn-web/network-paths.json`; repository files contain role-only samples.

## Collection

The existing read-only netctl RouterOS drivers will additionally collect only explicit `print` resources:

- firewall filter, NAT, and mangle rule metadata and byte/packet counters;
- address-list rows, persisted as current data rather than counted only;
- package channel/version, RouterBOOT versions, and scheduler metadata.

The collector will never read scheduler event bodies. A RouterOS snapshot older than fifteen minutes is stale. A fixed local `netctl collector-status` command reports only whether `netctl-collect.timer` is enabled/active and when it will next run.

## Path contract

Each local definition has a registered Server Health role, router source, expected OpenVPN pool, target CIDR, expected return route, and declarative policy matchers. A matcher selects a table, chain, optional action, source/destination address or list, and optional comment substring. It cannot contain a command.

For every registered role, the evaluator checks in this order:

1. OpenVPN runtime is active and uses the expected pool.
2. The configured MikroTik source is enabled, current, and its timer is active.
3. The router has the expected active return route for the OpenVPN pool.
4. Required address-list rows and policy matchers are present and enabled; counters are displayed when available.
5. The matching Server Health snapshot is current.

A missing policy matcher is `unknown`, not green. Missing route/rule evidence is `critical`; an inactive timer or unavailable collector is `error`; stale data is `stale`. A path is `ok` only when every required check is `ok`.

## Web/API

- `GET /network/paths` and role detail pages require the existing browser session.
- `GET /api/v1/network/paths` and role detail pages require the existing bearer token.
- GET requests only load/evaluate saved evidence; they do not test, collect, refresh, or change anything.
- Existing Server Health pages link to a role path. The Network navigation gains Paths.

The update posture card shows installed RouterOS version, channel, RouterBOOT current/upgrade versions, number of update schedulers, collection time, and freshness. A blank latest version means “not checked”, never “up to date”.

## Verification

Tests cover allow-listed collection, snapshot persistence, timer/stale handling, absent/disabled rules, role validation, redacted API responses, authenticated pages, and the absence of GET-side collection or device writes. Deployment verification remains read-only and does not enable the currently disabled collector timer.
