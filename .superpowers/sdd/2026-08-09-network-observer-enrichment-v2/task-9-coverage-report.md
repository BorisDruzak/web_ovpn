# Task 9 coverage-gap closure report

Date: 2026-08-09

Worktree: `C:\Users\admin-2\Documents\ui_vpn\.worktrees\network-observer-enrichment-v2`

## Scope

Closed only the four explicit gaps recorded in `task-9-report.md`. Changes are
limited to tests and this report; no production code, deployment, or production
network action was performed.

## Coverage added

1. Optional LLDP enrichment now explicitly exercises
   `UNSUPPORTED_NO_SUCH_OBJECT` and asserts that the normalized core neighbor and
   aggregate `lldp_remote` success remain intact.
2. The LLDP/FDB mismatch case explicitly proves that LLDP child A remains the
   published downstream child, FDB child B remains visible in subtree evidence,
   and the contradictory FDB link is suppressed.
3. Nmap parser XML fixtures now cover Windows OS, a RouterOS network device, and
   service-only RTSP output with no OS match.
4. The web background-failure test now runs a failed Nmap ensure, then performs an
   authenticated asset-card GET and asserts HTTP 200 plus rendered attachment card
   content.

## TDD evidence

- LLDP optional outcome: the new unsupported parameter initially failed because
  the fixture still returned `AUTH_OR_VIEW_FAILURE`; parameterizing that optional
  response made both cases pass.
- LLDP/FDB mismatch: the strengthened test initially failed with both signals
  pointing to child B; changing only the LLDP fixture to child A made the
  precedence and dual-evidence assertions pass.
- Nmap XML: all three new tests initially failed against the existing Linux XML;
  adding the three dedicated XML fixtures made them pass.
- Web failure isolation: the card assertion initially failed after the broad
  failing double also blocked context-view; narrowing the double to fingerprint
  ensure and authenticating the request made the post-failure card assertion pass.

## Verification

| Command | Result |
|---|---|
| `pytest tests/test_netctl_snmp_parsers.py -q` | 60 passed |
| `pytest tests/test_netctl_fdb_subtree.py -q` | 10 passed |
| `pytest tests/test_netctl_nmap_parser.py -q` | 7 passed |
| `pytest tests/test_web_network_observer.py -q` | 62 passed, 18,104 warnings |
| `pytest -q` | 1,587 passed, 11 skipped, 38,904 warnings in 258.93s |

The warnings are the existing pytest-asyncio fixture-loop warning plus FastAPI,
Starlette, startup-event, and `TemplateResponse` deprecations. No warning was
introduced as a test failure, and the previously incomplete full-suite gate now
has a fresh exit code 0.
