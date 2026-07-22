# Collection Lock Recovery Design

## Goal

Recover safely from an orphaned Network Observer collection lock after an
abrupt process termination, while never allowing two live collections to run
at the same time.

## Design

The lock payload will contain the process ID and its Linux process start-time
token. On acquisition, a pre-existing lock is inspected before it is removed:

- if the recorded process exists and has the same start-time token, acquisition
  fails with `collection already running`;
- if the process is absent or its start-time token differs, the lock is stale
  and is reclaimed before one bounded retry of exclusive creation;
- a legacy PID-only payload is treated as live when that PID exists, and stale
  only when it does not;
- malformed payloads are never silently trusted as a live collection; they are
  reclaimed through the same bounded retry path.

The existing context-manager cleanup remains unchanged for normal exits. The
new recovery path only handles lock files left behind when cleanup was skipped,
such as a service SIGTERM.

## Safety and Errors

- No router, OpenVPN, source, secret, or timer configuration changes are part
  of this change.
- A process ID alone is insufficient for a newly written lock: the start-time
  token prevents PID reuse from being mistaken for a live owner.
- Reclaim performs one retry only. If another live collector wins the race, the
  normal `collection already running` error is returned.

## Tests

Tests will cover a matching live owner, an absent owner, PID reuse with a
different start-time token, legacy PID-only payloads, malformed payloads, and
the race-safe exclusive-create retry. Existing normal cleanup behavior remains
covered.
