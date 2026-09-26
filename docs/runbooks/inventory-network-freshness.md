# Saved Netctl observations on Inventory cards

Inventory reads only saved local observations. Opening a card never probes Netctl or Endpoint and never writes provider state. A missing device or unavailable source does not end or transfer its confirmed binding.

The card distinguishes source freshness (available, stale, unavailable, disabled, unknown), presence in the latest successful saved snapshot (current, missing, unknown, historical), and the reachability recorded in the observation. Passive `seen` is not active reachability; legacy `online` without an ICMP/TCP method is unknown. Missing and unavailable retain the last IP/hostname/time without claiming those values are current. Ended bindings remain historical after deletion, restore, or reassignment.

Source and observation timestamps use UTC. Freshness accepts ages from zero through 20 minutes; future or malformed timestamps cannot establish freshness. Legacy snapshot version zero cannot establish current presence. A rejected stale snapshot is labelled stale even though its sync attempt failed.

Saved facts use an explicit bounded allowlist: public identity fields, sources, and availability state/method/time/origin. Arbitrary diagnostics and private fields are omitted, including when reading older JSON. Background snapshot refresh does not increment the card manual revision.

The SQLite card projection holds a physical SAVEPOINT across four bounded SELECTs, keeping sync metadata and binding observations coherent while another worker publishes a snapshot. It returns at most 100 bindings, active first, and declares omitted history. Before decoding JSON it measures the selected payload: above 1 MiB it retains binding metadata but omits observation details with an explicit warning. Other database backends require the caller to provide an appropriate repeatable-read transaction; SQLite coherence is the verified deployment contract.

`source_projection` and `observation_projection` are pure helpers for XLSX consumers. Load latest attempt and latest successful publication once inside the export transaction, then project already loaded bindings. Do not call the capped card helper per exported card. No schema migration, Endpoint write, or live collection is required.

## Verification

- Pinned Python/SQLAlchemy regression group: freshness, web, bindings, lifecycle, network links, network creation, revision, form drafts, sync: 143 passed.
- Final focused freshness file: 13 passed, including concurrent SQLite publication, four SELECTs, byte guard, stale rejection, manual revision retention, and deletion/restore/reassignment.
- Independent review of current freshness/bindings: 26 passed; no P1/P2 findings.
- Synthetic loopback browser: current saved observation, unavailable sync retaining IP, and newer snapshot disappearance retaining confirmation; mobile 390x844 had no horizontal overflow or page errors. These browser checks preceded the final pure-helper extraction and UTC normalization; final behavior is covered by the focused suite.
- No production CLI, network collection, deployment, or push was performed.
