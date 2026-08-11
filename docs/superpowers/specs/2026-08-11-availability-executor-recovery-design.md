# Availability Executor Recovery Design

**Date:** 2026-08-11

## Goal

Keep an intermittent active-probe worker failure from making the monitored
CIDR stale when the same bounded probes can complete on a retry, and make the
underlying failure diagnosable without exposing command output or network
details through the web/API.

## Evidence

On the deployed server, `netctl availability collect` repeatedly persisted
`executor_error` for `10.83.1.0/24` with eight targets and zero completed
results. The identical targets completed individually and concurrently when
run as the `netctl` user. The collection and availability service units use
the same `CollectLock`; a failed availability run was followed by rejected
collection attempts reporting `collection already running`.

The public CLI intentionally returns only the sanitized `executor_error`.
The original worker exception is discarded in `_collect_bucket`, so the
service journal cannot distinguish a ping invocation error from a TCP socket
or executor failure.

## Scope

Included:

- Retain the current atomic CIDR semantics: an unrecoverable probe error must
  never publish partial negative results.
- Retry a failed parallel bucket once sequentially, using the same bounded
  ICMP/TCP probe functions and target set.
- Preserve a safe public `executor_error` while logging only an error class
  and probe phase to the service logger.
- Make lock cleanup explicit and regression-tested after failed availability
  commands.
- Verify the deployed timers, successful consecutive collections, absence of
  a stale lock, and one availability run after deployment.

Excluded:

- Changes to router, switch, OpenVPN, DNS, firewall, or endpoint
  configuration.
- Suppressing availability monitoring or treating a persistent local probe
  infrastructure error as an offline host.
- Returning raw process stderr, command arguments, target lists, credentials,
  or socket errors from Netctl's public CLI/API.

## Design

`_collect_bucket` continues to submit no more than 64 target jobs and applies
the existing 90-second deadline to its parallel pass. It will retain the
first sanitized failure class and phase internally. If any worker raises,
the function performs one sequential retry over the complete bucket with the
same deadline budget. A fully successful retry returns the complete results;
an error or deadline on the retry retains the atomic failed-CIDR behaviour.

The retry does not weaken an individual negative result: a normal ICMP/TCP
negative result remains `unreachable`. Only an unexpected executor exception
triggers retry. The internal diagnostic is emitted through Python logging as
an allow-listed error class (`ping`, `tcp`, `future`, `deadline`) and phase
(`parallel` or `sequential`), never the exception message or target address.

`CollectLock.__exit__` will retain its ownership check and remove the owned
lock even when a command returns a failed availability payload. A regression
test will exercise the real context manager around a failed availability
collection and assert that a subsequent collector can acquire the lock.

## Acceptance Criteria

- A simulated one-time worker exception is recovered by sequential retry and
  yields a complete successful CIDR run.
- A second failure remains a failed run with public `executor_error`; no
  partial results become current.
- The journal receives only allow-listed diagnostic fields.
- A failed availability collection releases its lock so a following
  `collect all` can acquire it.
- Targeted availability and CLI tests pass locally.
- On the deployed server, two timer-driven `collect all --reconcile` runs
  finish successfully and leave no lock; the availability failure is either
  recovered or reported with the new diagnostic class.
