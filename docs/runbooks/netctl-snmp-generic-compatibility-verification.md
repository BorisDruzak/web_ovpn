# Netctl generic SNMP compatibility verification

Use this runbook after a reviewed collector release adds or changes a generic
SNMP compatibility fallback. It is an operator verification procedure, not
authorization to add, enable, alter, or schedule a source. SNMP SET, switch
configuration, source configuration changes, and timer enablement are out of
scope.

Use approved deployment records for the source name and access material. Do not
put addresses, device names, communities, credentials, MAC addresses, raw SNMP
responses, or FDB inventory in this runbook or its evidence.

## Evidence hierarchy

Treat the following evidence in order. Do not use a later result to excuse a
failed earlier gate.

1. **Individual source test:** proves the bounded read-only snapshot can be
   collected and reports its detected profile, aggregate port/FDB counts, and
   capability outcomes.
2. **Persisted inspection:** proves the individual manual collection was stored
   as expected by checking source status, capability history, and paginated FDB
   state for that source.
3. **One controlled all-source cycle:** proves that the same compatibility path
   behaves correctly when `collect all` isolates sources. It is allowed once,
   only after every enabled source passes the individual gates.

For a generic compatible device, capability warnings can be expected for an
unimplemented optional MIB or a Q-BRIDGE table that is empty or unsupported
when the legacy FDB fallback succeeds. They are evidence to review, not a
reason to override the gate. Stop for required-system, interface, bridge-port,
or final-FDB failures; parser errors; transport or authentication failures; an
unexpected profile; or an empty/partial result that cannot be explained by the
approved change record. A fallback is successful only when the final FDB
capability and the stored result agree with the source-test summary.

## Preconditions and timer gate

Choose the source name from the approved record without printing its endpoint
or secret. Disable the recurring collector before any manual command, and
leave it disabled throughout this procedure and after it finishes.

```bash
source_name='approved-source-name'
sudo systemctl disable --now netctl-collect.timer
sudo systemctl stop netctl-collect.service
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test "$(systemctl is-active netctl-collect.timer)" = inactive
```

If the timer cannot be confirmed disabled and inactive, stop. Do not test or
collect a source while a scheduled collection can overlap.

## 1. Test each source individually

Run this gate separately for each approved enabled SNMP source. The source test
is read-only and returns a bounded snapshot summary; retain only the source
name, timestamp, profile ID/fingerprint, aggregate counts, and capability
outcomes.

```bash
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test "$(systemctl is-active netctl-collect.timer)" = inactive
sudo -u netctl /usr/local/sbin/netctl --json sources test "$source_name"
```

Confirm the profile is expected and required capabilities succeeded. Review
warnings against the hierarchy above. Do not change a profile hint, source
enablement flag, timeout, retries, or credentials to make a test pass. Stop on
any source-test failure.

## 2. Inspect the persisted individual collection

Only after the source test passes, run one manual collection for that source.
Then inspect its stored snapshot indicators, capability records, and FDB page.
The pagination limit keeps the interactive response bounded; do not export or
retain the returned FDB rows.

```bash
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test "$(systemctl is-active netctl-collect.timer)" = inactive
sudo -u netctl /usr/local/sbin/netctl --json collect "$source_name"
sudo -u netctl /usr/local/sbin/netctl --json switches status
sudo -u netctl /usr/local/sbin/netctl --json switches capabilities \
  --source "$source_name" --limit 100
sudo -u netctl /usr/local/sbin/netctl --json switches fdb \
  --source "$source_name" --limit 100 --offset 0
```

The status, source-test summary, final-FDB capability, and FDB page must be
consistent. A compatibility warning is acceptable only if the final FDB result
is successful and the expected aggregate FDB count is persisted. Record
sanitized aggregate counts and capability outcomes, never the FDB rows.

Repeat sections 1 and 2 for every enabled source. If any source is unrelated
and fails, keep the timer disabled, do not run the all-source cycle, and report
that independent failure without changing the source.

## 3. Run one controlled all-source cycle

Run this once only after all individual sources pass. The timer remains
disabled: this is a deliberate foreground collection, not a resumption of
recurring collection.

```bash
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test "$(systemctl is-active netctl-collect.timer)" = inactive
sudo -u netctl /usr/local/sbin/netctl --json collect all
sudo -u netctl /usr/local/sbin/netctl --json switches status
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test "$(systemctl is-active netctl-collect.timer)" = inactive
```

Verify the all-source result preserves the successful individual outcomes and
isolates any reported source failure. Do not retry by enabling the timer. Keep
the timer disabled, capture only sanitized run IDs, aggregate counts,
capability outcomes, and source-level statuses, then escalate any discrepancy
for review.
