# Inventory collection reliability implementation plan

> **Execution:** implement in the repository's clean `main` checkout, test
> each change before deployment, then verify the production route and one
> bounded live Nmap probe.

1. Add failing tests for exact, recent stale-host fallback and for rejecting
   old/fuzzy stale results.  Implement the bounded fallback in
   `app/inventory/lookup.py`.
2. Add failing tests for a successful availability run publishing the snapshot
   before its collection lock is released.  Keep that guarantee in the CLI and
   deploy systemd ordering that prevents reconcile/availability overlap.
3. Add failing tests for the Nmap fixed profile's deadline and its sanitized
   timeout classification.  Tighten the profile so a filtered host yields a
   bounded result rather than blocking inventory creation.
4. Extend the existing PySNMP transport to select SNMPv1 or SNMPv2c without
   allowing a community outside the protected secret resolver.  Add a
   printer-only read-only collector for system identity, serial number and page
   counter using numeric OIDs, with tests for response and timeout outcomes.
5. Map verified collection fields into the editable inventory prefill; retain
   user edits and never infer model/serial when the protocol did not supply it.
6. Render network identifiers only for PC, printer, phone and Other forms;
   add template-level regression tests.  Repair wrong asset-detail mappings
   idempotently at application startup and test the known cross-type case.
7. Run focused pytest suites, full relevant tests, static diff checks and
   browser-level smoke checks.  Deploy, verify systemd snapshot behaviour,
   Nmap on `.150`, and a read-only SNMP v1/v2c probe only through the protected
   runtime secret configuration.
