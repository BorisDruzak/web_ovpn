# Task 5 — Nmap Fingerprint Core — implementation report

## Status

Implemented and verified locally in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`.

Starting Git state:

```text
branch: codex/network-observer-enrichment-v2
HEAD: ce4b52b731ffd3aa128419002e36c96585cd3dd4
worktree: clean
```

No deployment, SSH, live Nmap scan, package installation, server change,
network-wide command, or production-network/device write was performed.

## Safety boundary

- The public command accepts only `asset_key`:
  `netctl --json fingerprint status|ensure --asset-key <asset_key>`.
- There is no public IP, hostname, CIDR, port, Nmap argument, NSE script,
  profile, subnet, or `fingerprint all` input.
- The target is resolved from an existing runtime asset and must have exactly
  one unique current safe canonical IPv4. Duplicate observations of the same
  IPv4 are allowed; valid IPv6 observations are ignored by the v1 resolver.
  Malformed values, CIDRs, hostnames, noncanonical IPv4, unspecified,
  loopback, multicast, and network/broadcast-like `.0`/`.255` addresses are
  rejected.
- The immutable `asset-fingerprint-v1` profile has a 3600-second default TTL
  and 60-second stale-running timeout. Bounded environment configuration is
  available through `NETCTL_NMAP_TTL_SECONDS` and
  `NETCTL_NMAP_STALE_RUNNING_SECONDS`; the stale timeout cannot be configured
  at or below the 30-second parent helper timeout.
- The application runner invokes only
  `/usr/bin/sudo --non-interactive
  /usr/local/libexec/netctl-nmap-fingerprint <validated-ip>` with
  `shell=False` and a 30-second timeout.
- The root-owned helper independently requires exactly one canonical IPv4,
  uses a minimal environment, suppresses Nmap stderr, has a 25-second hard
  timeout, and builds this complete fixed command itself:

```text
/usr/bin/nmap -n -Pn -sS -O --osscan-limit -sV --version-light
  --top-ports 100 --max-retries 1 --host-timeout 20s -T3 -oX - <IPv4>
```

  It contains no `-sC`, `--script`, `-A`, shell interpolation, or caller-
  supplied option path.
- Runtime sudo is narrow: `netctl` may sudo only the root-owned restricted
  helper. It is not permitted to invoke arbitrary Nmap as root.

## Implementation

### Policy, runner, and parser

- Added frozen models for the timing profile, resolved target, normalized
  port/service records, normalized OS matches/classes, and parsed run.
- Added strict asset/IPv4 resolution and bounded timing configuration.
- Added the fixed restricted-helper runner with sanitized error classes.
- Added an `xml.etree.ElementTree` parser with a 2 MiB input bound. It accepts
  at most one host and projects only:
  - run Nmap version;
  - port protocol/number/state;
  - service name/product/version/extra info/tunnel/method/confidence/CPEs;
  - OS match name/accuracy and OS class type/vendor/family/generation/
    accuracy/CPEs.
- `<script>` nodes, arbitrary XML attributes, runstats, raw XML, and raw
  parser detail are ignored and never returned by the normalized model.

### Migration 23 and persistence

- The previously current local migration was 22. Task 5 adds migration 23.
- Added `nmap_fingerprint_runs`, `nmap_fingerprint_ports`, and
  `nmap_fingerprint_os_matches` with foreign keys and status/range checks.
- A partial unique index permits only one `running` row per asset/profile.
- Only normalized scalar fields and JSON arrays of normalized CPE/OS-class
  data are stored. There are no raw XML or stderr columns.
- Successful child records and the final run state are committed in one
  transaction. Failed runs persist only allowlisted error classes and fixed
  public messages.
- No fingerprint retention policy was added in Task 5; therefore
  `netctl/retention.py` was intentionally unchanged.

### TTL, single-flight, and crash recovery

`ensure(asset_key)` uses `BEGIN IMMEDIATE` to serialize the claim decision:

1. Return the latest successful current-target result when its age is less
   than the configured TTL.
2. Return any existing nonstale per-asset run, including during target churn,
   without starting a second process.
3. Atomically mark a stale `running` row failed.
4. Insert exactly one new `running` row, commit the claim, and only then call
   the restricted helper outside the database transaction.
5. Atomically finalize the claimed row as `success` with normalized children
   or `failed` with a sanitized error.

The stale timeout is greater than both hard execution timeouts, so a crashed
web process cannot lock an asset indefinitely while an ordinary scan cannot
be reclaimed early. A late process cannot overwrite a run that was already
reclaimed because finalization updates only a still-`running` row.

### CLI and context

- Added `fingerprint status` and `fingerprint ensure`, both requiring only
  `--asset-key`.
- Status is read-only and does not start a scan. Ensure returns fresh,
  running, successful, or sanitized failed state from the store.
- Asset context exposes the stored normalized fingerprint projection only;
  inspecting a card never invokes Nmap.
- The installer applies local netctl schema migrations as the `netctl` user
  before restarting the web service. This prevents a read-only card/status
  request from reaching a pre-v23 database immediately after upgrade.

### Local deployment artifacts

- Added `deploy/netctl-nmap-fingerprint`, installed root-owned mode `0755` at
  `/usr/local/libexec/netctl-nmap-fingerprint`.
- Added `deploy/sudoers-netctl-nmap`, installed root-owned mode `0440` at
  `/etc/sudoers.d/netctl-nmap`.
- Installer checks the exact helper dependency `/usr/bin/nmap` before any
  account/application mutation and fails with an actionable message if it is
  absent.
- Installer validates the installed sudoers file with
  `visudo -cf /etc/sudoers.d/netctl-nmap`.
- No Python Nmap wrapper dependency was added.

## Files

Created:

- `netctl/nmap/__init__.py`
- `netctl/nmap/models.py`
- `netctl/nmap/policy.py`
- `netctl/nmap/runner.py`
- `netctl/nmap/parser.py`
- `netctl/nmap/store.py`
- `deploy/netctl-nmap-fingerprint`
- `deploy/sudoers-netctl-nmap`
- `tests/test_netctl_nmap_policy.py`
- `tests/test_netctl_nmap_parser.py`
- `tests/test_netctl_nmap_runner.py`
- `tests/test_netctl_nmap_store.py`
- `tests/test_netctl_nmap_cli.py`
- `.superpowers/sdd/2026-08-09-network-observer-enrichment-v2/task-5-report.md`

Modified:

- `netctl/migrations.py`
- `netctl/cli.py`
- `netctl/context_query.py`
- `deploy/install-openvpn-web.sh`
- `tests/test_deploy_netctl.py`
- `tests/test_netctl_cli.py`
- `tests/test_netctl_context_migrations.py`
- `tests/test_netctl_context_query.py`

## TDD evidence

Policy RED:

```text
pytest tests/test_netctl_nmap_policy.py -q
```

Initial result: 17 failed because `netctl.nmap` did not exist. Initial GREEN:
17 passed after the frozen profile and strict runtime-asset resolver were
implemented.

Parser RED:

```text
pytest tests/test_netctl_nmap_parser.py -q
```

Initial result: 4 failed because the parser did not exist. GREEN with policy:
21 passed after normalized port/OS parsing and sanitized rejection were added.

Runner/deploy RED:

```text
pytest tests/test_netctl_nmap_runner.py -q
```

Initial result: 7 failed because the runner/helper/sudoers artifacts did not
exist. GREEN: 7 passed after the restricted subprocess and fixed helper were
implemented. The exact `/usr/bin/nmap` preflight was then separately observed
failing before replacing a PATH-only check; the corrected deploy/security
regression group passed 24 tests.

Store/migration RED:

```text
pytest tests/test_netctl_nmap_store.py -q
```

Initial result: 8 failed because migration 23 and the store did not exist.
GREEN: 8 passed, including TTL expiry at exactly 3600 seconds, two-connection
single-flight, stale recovery, target change after a completed scan, atomic
normalized persistence, and unexpected-error sanitization.

CLI/context/config RED:

```text
pytest tests/test_netctl_nmap_cli.py -q
```

Initial result: 5 expected failures after five forbidden-input parser cases
already rejected correctly. GREEN with store: 18 passed after adding the two
commands, immutable timing configuration, failure projection, and read-only
asset context.

One expanded regression then failed only because an existing operational
summary still expected migrations 1–22. Updating that contract to the new
local migration 23 made the focused regression pass.

## Independent review

The first completed security/concurrency review found no Critical issues and
three Important issues:

1. A read-only status/card request could reach a v22 database before another
   writer happened to apply migration 23.
2. Target churn during a nonstale run could reclaim it early and start a
   second Nmap process.
3. One valid current IPv4 plus valid current IPv6 was rejected.

All three were reproduced together before fixes:

```text
3 failed
```

GREEN after install-time migration, target-churn single-flight preservation,
and IPv6 filtering:

```text
3 passed
```

Re-review confirmed the migration and single-flight fixes, then identified
one remaining Important distinction: only valid IPv6 may be ignored; a CIDR,
hostname, malformed/noncanonical IPv4, or unsafe `.0`/`.255` observation next
to a valid IPv4 must still reject the target. A parameterized RED produced
4 failures; the tightened resolver produced 22 passing policy tests.

Final independent re-review verdict: all Important issues addressed; no
remaining Critical or Important findings; `Ready`.

## Verification

Fresh expanded Task 5 and adjacent regression suite:

```text
pytest tests/test_netctl_nmap_policy.py tests/test_netctl_nmap_parser.py \
  tests/test_netctl_nmap_runner.py tests/test_netctl_nmap_store.py \
  tests/test_netctl_nmap_cli.py tests/test_netctl_context_migrations.py \
  tests/test_netctl_context_query.py tests/test_netctl_cli.py \
  tests/test_deploy_netctl.py tests/test_netctl_deploy_security.py \
  tests/test_deploy_credential_safety.py -q
```

Result: 182 passed, 1 skipped, 0 failed in 37.36 seconds.

Fresh full suite:

```text
pytest -q
```

Result: 1528 passed, 11 skipped, 0 failed in 259.77 seconds. Existing
FastAPI/Starlette/pytest-asyncio deprecation warnings remain.

Static verification used:

```text
python -m compileall -q netctl <Task 5 test files>
python -m py_compile deploy/netctl-nmap-fingerprint
bash -n deploy/install-openvpn-web.sh
git diff --check
```

All returned exit 0. `visudo` is not available in the local Windows
environment; WSL and Docker are also unavailable. Therefore no local
`visudo -cf` execution was fabricated. The exact restricted sudoers contract
is covered by tests, and the installer performs the required
`visudo -cf /etc/sudoers.d/netctl-nmap` before continuing on the deployment
host. The deployment host was intentionally not contacted.

## Scope boundary

This change implements only Task 5. It does not make Nmap a discovery source,
scan a subnet or asset collection, accept browser-supplied scan settings, add
NSE, retain raw XML/stderr, run the web service as root, grant arbitrary Nmap
sudo, change retention, deploy code, install Nmap, or modify network/device
configuration.
