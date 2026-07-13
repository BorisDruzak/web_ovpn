# Netctl Context Core Design

## Purpose

Add a small, read-only bridge from the canonical network context in
`BorisDruzak/network_configuration` to the existing `netctl` command-line
tool. The feature validates a user-supplied context YAML against a local JSON
Schema, summarises it, and records the last successful validation in the local
SQLite database.

The canonical sources are:

- `https://github.com/BorisDruzak/network_configuration/config/network-context.yaml`
- `https://github.com/BorisDruzak/network_configuration/schemas/network-context.schema.json`
- `https://github.com/BorisDruzak/network_configuration/blob/main/docs/runbooks/step-03-web-ovpn-context-core.md`

## Scope and safety boundary

This change is local and read-only with respect to the network. It does not
contact or modify MikroTik, OpenVPN, DNS, DHCP, switches, firewalls, or any
other production-network component. It adds no API route or UI page, and it
does not import devices, links, or IP addresses into existing host tables.

## Components and data flow

1. `netctl/context.py` loads YAML bytes from an explicit path and JSON Schema
   from a local path. It validates the decoded document and returns structured
   validation errors, SHA-256 of the raw YAML, schema version, context ID, and
   counts of top-level object collections.
2. `netctl/cli.py` exposes `context validate` and `context status` under the
   existing JSON CLI. Schema discovery checks `--schema`, a sibling
   `network_configuration/schemas/network-context.schema.json`, and
   `NETCTL_CONTEXT_SCHEMA` in that order. It never retrieves a schema over the
   network.
3. `netctl/db.py` creates `context_revisions` with `CREATE TABLE IF NOT
   EXISTS`. A successful validation inserts or reuses the unique
   `(context_id, sha256)` revision. Failed validation is returned to the caller
   but is not stored as an active revision.
4. `tests/test_netctl_context.py` uses temporary YAML, schema, and SQLite files
   only. No test needs live network access.

## CLI contract

`netctl --json context validate --path PATH [--schema PATH] [--git-sha SHA]`
returns status `ok`, a `context` object, and an empty `errors` list on success.
It returns a non-zero exit code and structured `errors` for invalid, missing,
or unreadable context/schema input.

`netctl --json context status [--path PATH] [--schema PATH] [--git-sha SHA]`
returns the most recent successful revision. Its optional path/schema/git SHA
arguments are accepted for a consistent interface but do not validate or write
the supplied context.

## Error handling

- File and YAML/JSON parsing errors become JSON error responses; they do not
  raise a traceback through the CLI.
- JSON Schema violations are normalised to objects with a location path and
  human-readable message, sorted deterministically.
- A missing schema reports a clear JSON error after all three local resolution
  options have been exhausted.
- Revalidating identical content is idempotent because the revision table has a
  unique `context_id, sha256` key.

## Verification

Tests cover valid context, malformed or duplicate objects, missing required
fields, missing YAML/schema files, stable SHA-256, idempotent revisions, and
latest-successful status. Final acceptance additionally runs the full pytest
suite and both CLI commands against the canonical repository files, including
one disposable invalid-copy command that must exit non-zero.
