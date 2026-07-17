# Verification — `netctl context validate/status`

Status: **implemented and verified**

Verified on: 2026-07-17

Implementation merge:

```text
a9e0ddc3fa31e4474ce5f59fb78f81edb2ce4000
Merge branch 'codex/netctl-context-core'
```

Verification PR:

```text
#6 Verify and document netctl context validate/status stage
```

## Goal

Provide a read-only local bridge from canonical `network_configuration/config/network-context.yaml` into `netctl`:

```bash
netctl --json context validate --path <network-context.yaml> --schema <schema.json> --git-sha <sha>
netctl --json context status
```

Neither command contacts or changes a network device.

## Implementation map

| Requirement | Implementation |
|---|---|
| Load local YAML | `netctl/context.py::load_context`, `load_context_bytes` |
| Load local JSON Schema | `netctl/context.py::load_schema` |
| Block network schema retrieval | `_external_reference_errors`, local `referencing.Registry` retrieval rejection |
| Draft 2020-12 validation | `Draft202012Validator` |
| Duplicate IDs inside one collection | `validate_context` |
| Stable SHA256 and object counts | `context_summary` |
| Persist successful validation | `netctl/db.py::record_context_revision` |
| Idempotent revision key | `UNIQUE(context_id, sha256)` |
| Preserve latest successful revision | `latest_context_revision` |
| CLI `validate` and `status` | `netctl/cli.py::cmd_context` |
| Pinned dependencies | `PyYAML==6.0.2`, `jsonschema==4.23.0` |
| Automated tests | `tests/test_netctl_context.py` |

## Read-only boundary

`cmd_context` uses:

```python
conn = connect(args.db)
```

It intentionally does not use `prepare_conn`, `driver_for`, `collect` or any source driver. The command only reads explicitly provided local files and writes a revision record to the selected SQLite database.

## Database contract

```sql
CREATE TABLE IF NOT EXISTS context_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    context_id TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    source_path TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    git_sha TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error_json TEXT NOT NULL DEFAULT '[]',
    counts_json TEXT NOT NULL DEFAULT '{}',
    validation_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE(context_id, sha256)
);
```

Repeated validation of the same `context_id` and content hash updates provenance and validation ordering without creating duplicate rows.

## Tested behavior

`tests/test_netctl_context.py` verifies:

```text
- stable SHA256 and collection counts;
- YAML and JSON Schema must be objects;
- missing and malformed files return errors;
- JSON Schema violations are returned with paths;
- duplicate IDs are rejected within a collection;
- same ID in different collections is allowed;
- external schema references are rejected without retrieval;
- successful revisions are idempotent;
- revalidation refreshes source path, Git SHA, counts and latest ordering;
- validate followed by status returns the same revision;
- invalid validation does not replace the last successful revision;
- validate without --path returns a JSON error;
- schema resolution stays local.
```

## Fresh CI evidence

Workflow:

```text
.github/workflows/verify-netctl-context.yml
```

Successful run:

```text
run_id: 29586418216
head_sha: 1d6cbd34bad728deca814314f3d96dc070aa5da3
context-stage: success
full-regression: success
```

Full suite result:

```text
106 passed, 89 warnings in 20.61s
exit code: 0
```

The warnings are existing deprecations in `passlib`, FastAPI startup events and Starlette template invocation; they do not fail this stage.

## Regression discovered during verification

The first full CI execution exposed four unrelated `PermissionError` failures in `tests/test_vpnctl_config_edit.py`.

Root cause:

```text
The subprocess fixture redirected REGISTRY_DB but did not redirect
NETWORKS_DB and NETWORK_TEMPLATES_DB. vpnctl.ensure_dirs() therefore
tried to create /var/lib/openvpn-client-manager on the non-root runner.
```

The test fixture now redirects all three state files into `tmp_path`. No production behavior was changed. The subsequent full suite passed.

## Manual verification commands

From a checkout containing both repositories as siblings:

```bash
cd web_ovpn
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

rm -f /tmp/netctl-context-verification.sqlite3

python -m netctl.cli --json \
  --db sqlite:////tmp/netctl-context-verification.sqlite3 \
  context validate \
  --path ../network_configuration/config/network-context.yaml \
  --schema ../network_configuration/schemas/network-context.schema.json \
  --git-sha "$(git -C ../network_configuration rev-parse HEAD)"

python -m netctl.cli --json \
  --db sqlite:////tmp/netctl-context-verification.sqlite3 \
  context status

python -m pytest -q tests/test_netctl_context.py
python -m pytest -q
```

Expected properties of the validation result:

```text
status = ok
context.context_id = sosn-admin-network
context.schema_version = current canonical schema version
context.sha256 = 64 hexadecimal characters
context.git_sha = supplied network_configuration commit SHA
context.counts = non-empty object counts
errors = []
```

## Stage decision

Phase 2 / PR 1A is complete.

Next implementation stage:

```text
PR 1B — context object import and diff
```

It will import stable sites, locations, segments, assets, services and links into dedicated runtime tables and compare imported intent revisions. SNMP collection remains a later stage and must not be mixed into PR 1B.
