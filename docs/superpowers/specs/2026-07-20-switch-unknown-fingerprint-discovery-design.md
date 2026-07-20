# Unknown switch fingerprint discovery design

## Goal

Show a newly reachable but unrecognized SNMP switch as a safe candidate in the
web panel, without allowing it to produce FDB, VLAN, port-topology, or network
configuration changes until a reviewed profile matcher exists.

## Probe and storage boundary

The existing read-only SNMP transport performs a discovery probe containing only
system identity (`sysDescr`, `sysObjectID`) and capability outcomes.  When no
vendor profile matches, the probe stores a bounded fingerprint observation with
status `unknown`.  It stores no community, endpoint, raw varbind, MAC/FDB row,
or switch configuration data.  It never issues SNMP SET.

Known fingerprints continue through the existing vendor-profile path.  An
unknown fingerprint never falls back to generic FDB normalization and never
writes current switch state.  The source remains disabled unless an operator
uses the existing separate manual-collection procedure.

## Web interface

The Network Sources page exposes a compact Unknown fingerprints section.  Each
entry shows source name, sanitized system identity, observed time, fingerprint
digest, capability outcome summary, and the state `requires_profile`.  It
contains no action that enables a source, writes a switch, or assigns a profile.

## Promotion path

An engineer adds a tested exact matcher in code from the observed fingerprint,
with a fixture and negative tests.  The next read-only probe then reports the
known profile.  There is no UI action for accepting a fingerprint automatically.

## Tests and rollout

Tests cover unknown probe persistence, bounded/sanitized source-test output,
absence of FDB/current-state writes, known-profile non-regression, and the web
section rendering.  Deploy with all SNMP sources and the collection timer
disabled.  Validate an unknown source only with `sources test`; manual FDB
collection remains separately approved.
