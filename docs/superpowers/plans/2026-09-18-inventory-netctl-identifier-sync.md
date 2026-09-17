# Inventory Netctl Identifier Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically update only IP and hostname from a current Netctl snapshot when a card MAC has an unambiguous match.

**Architecture:** A dedicated service preserves historical values rather than using form replacement. A one-shot worker reads paginated Netctl snapshot data through `run_netctl`, writes a run ledger, and is executed by a separate offset systemd timer.

**Tech Stack:** Python 3, SQLAlchemy, SQLite, pytest, systemd.

**Spec:** `docs/superpowers/specs/2026-09-18-inventory-netctl-identifier-sync-design.md`

## Global Constraints

- Update only IP and hostname. MAC is an anchor only and is never written by the worker.
- Require exactly one current inventory asset and exactly one current Netctl host for a normalized MAC.
- Preserve replaced IP/hostname rows as inactive history, set new values to source `NETCTL`, and never clear omitted values.
- Read Netctl only through `app.netctl_client.run_netctl`; never invoke collect, refresh, availability, Nmap, or SNMP operations.
- Process only a complete, non-stale snapshot not previously successful.
- Run as `openvpn-web`, independent of card views and saves, through the current least-privilege Netctl sudo boundary.

---

## File Structure

- `app/inventory/models.py`: synchronization-attempt ledger.
- `app/inventory/service.py`: identifier reconciliation isolated from forms.
- `app/inventory/netctl_sync.py`: snapshot reader, transaction orchestration, CLI.
- `deploy/inventory-netctl-sync.service`, `deploy/inventory-netctl-sync.timer`: worker schedule.
- `deploy/install-openvpn-web.sh`, `deploy/verify_netctl_systemd.py`: deployment contract.
- `tests/test_inventory_netctl_sync.py`, `tests/test_inventory_models.py`, `tests/test_deploy_netctl.py`: tests.

### Task 1: Ledger and Safe Identifier Reconciliation

**Files:**

- Modify: `app/inventory/models.py`, `app/inventory/service.py`, `tests/test_inventory_models.py`
- Create: `tests/test_inventory_netctl_sync.py`

**Interfaces:**

- Produces `InventoryIdentifierSyncRun`, `InventoryIdentifierSyncResult`, and `InventoryService.reconcile_netctl_identifiers(db, hosts, observed_at)`.
- The `hosts` argument is mappings with optional `mac`, `ip`, `hostname`; result counters are `matched_assets`, `updated_assets`, `skipped_assets`.

- [ ] **Step 1: Write failing schema and service tests**

```python
def test_identifier_sync_schema_creates_run_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory.sqlite'}")
    reset_engine_cache()
    init_db()
    assert "inventory_identifier_sync_runs" in set(inspect(get_engine()).get_table_names())


def test_reconcile_updates_ip_and_hostname_but_not_mac(db):
    asset = _asset_with_identifiers(db, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    result = service.reconcile_netctl_identifiers(
        db, [{"mac": "aa-bb-cc-dd-ee-ff", "ip": "192.168.100.20", "hostname": "pc-01"}],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )
    assert result.updated_assets == 1
    assert _current_values(db, asset.id) == {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20", "hostname": "pc-01"}
```

Add cases for omitted observed values, invalid MACs, duplicate inventory MACs, duplicate observed MACs, and inactive history of manually entered IP.

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `python -m pytest tests/test_inventory_models.py tests/test_inventory_netctl_sync.py -q`

Expected: failure because the ledger and reconciliation operation do not exist.

- [ ] **Step 3: Implement the model and dedicated reconciliation operation**

```python
class InventoryIdentifierSyncRun(Base):
    __tablename__ = "inventory_identifier_sync_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    snapshot_id: Mapped[int | None] = mapped_column(Integer, index=True)
    snapshot_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    matched_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)
```

Build MAC maps before mutations; include only unique keys. The private replacement helper deactivates just a differing IP or hostname and adds a current `NETCTL` value. It must never invoke `sync_identifiers`. The existing `Base.metadata.create_all` creates this new independent table; add it to the schema test assertion.

- [ ] **Step 4: Run focused tests and confirm success**

Run: `python -m pytest tests/test_inventory_models.py tests/test_inventory_netctl_sync.py -q`

Expected: pass, including history and ambiguity coverage.

- [ ] **Step 5: Commit Task 1**

```bash
git add app/inventory/models.py app/inventory/service.py tests/test_inventory_models.py tests/test_inventory_netctl_sync.py
git diff --cached --check
git commit -m "feat(inventory): reconcile identifiers from Netctl"
```

### Task 2: Immutable Snapshot Reader and Worker

**Files:**

- Create: `app/inventory/netctl_sync.py`
- Modify: `tests/test_inventory_netctl_sync.py`

**Interfaces:**

- Consumes `run_netctl`, `session_scope`, and Task 1 interfaces.
- Produces `read_current_snapshot(netctl_call) -> NetctlSnapshot`, `synchronize_current_snapshot(netctl_call=run_netctl) -> SyncSummary`, and `main(argv=None) -> int`.
- Every page must have one snapshot ID/generated time and `stale is False`; read ends at `page >= pagination.pages`.

- [ ] **Step 1: Write failing worker tests**

```python
def test_worker_pages_one_current_snapshot(db):
    calls = []
    def fake_netctl(args, timeout=None):
        calls.append(args)
        return _snapshot_page(snapshot_id=7, page=int(args[-3]), pages=2)
    summary = synchronize_current_snapshot(netctl_call=fake_netctl, session_factory=lambda: db)
    assert summary.status == "success"
    assert calls == [
        ["hosts", "list", "--status=current", "--page", "1", "--limit", "250"],
        ["hosts", "list", "--status=current", "--page", "2", "--limit", "250"],
    ]
```

Add stale snapshot, repeated successful ID, malformed metadata, ID/generation change mid-page, Netctl error, and database rollback tests. Assert fake Netctl rejects collection, refresh, Nmap, SNMP, and availability arguments.

- [ ] **Step 2: Run focused test and confirm failure**

Run: `python -m pytest tests/test_inventory_netctl_sync.py -q`

Expected: failure because `app.inventory.netctl_sync` is absent.

- [ ] **Step 3: Implement strict pagination and one transaction**

```python
@dataclass(frozen=True)
class NetctlSnapshot:
    snapshot_id: int
    generated_at: datetime
    hosts: Sequence[dict[str, object]]  # All validated pages in snapshot order.


def synchronize_current_snapshot(*, netctl_call: NetctlCall = run_netctl) -> SyncSummary:
    snapshot = read_current_snapshot(netctl_call)
    with session_scope() as db:
        return _record_and_reconcile(db, snapshot)
```

Parse generation time with `datetime.fromisoformat(value.replace("Z", "+00:00"))`; reject missing or naive values. Skip stale/repeated IDs with no mutations. On error roll back writes, then write a concise failed-ledger record in a fresh transaction when possible. `main()` calls `init_db`, returns zero for success/skipped and one for failure, and logs only snapshot ID/counters.

- [ ] **Step 4: Run focused test and confirm success**

Run: `python -m pytest tests/test_inventory_netctl_sync.py -q`

Expected: pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add app/inventory/netctl_sync.py tests/test_inventory_netctl_sync.py
git diff --cached --check
git commit -m "feat(inventory): add Netctl snapshot sync worker"
```

### Task 3: Isolated Systemd Deployment

**Files:**

- Create: `deploy/inventory-netctl-sync.service`, `deploy/inventory-netctl-sync.timer`
- Modify: `deploy/install-openvpn-web.sh`, `deploy/verify_netctl_systemd.py`, `tests/test_deploy_netctl.py`

**Interfaces:**

- Produces exact worker command `/opt/openvpn-web/.venv/bin/python -m app.inventory.netctl_sync` and a persistent offset timer.
- Unit `User`/`Group` are `openvpn-web`; existing Netctl sudo allowlist remains the only Netctl access path.
- The worker requires `NoNewPrivileges=false` solely so the existing
  `sudo -n -u netctl` allowlisted Netctl command can change to that account.
  Retain `PrivateTmp=true`, `ProtectHome=true`, the protected environment file,
  the fixed entrypoint, and all other unit hardening.

- [ ] **Step 1: Write failing unit and installer tests**

```python
def test_inventory_sync_unit_uses_only_worker_entrypoint():
    verifier = runpy.run_path(str(VERIFIER))
    assert verifier["EXPECTED_EXEC_STARTS"]["inventory-netctl-sync.service"] == [
        "/opt/openvpn-web/.venv/bin/python", "-m", "app.inventory.netctl_sync"
    ]


def test_installer_enables_inventory_sync_after_verification(tmp_path):
    result, _bin_dir, calls_path, _environment = _run_installer(tmp_path)
    assert result.returncode == 0, result.stderr
    calls = calls_path.read_text(encoding="utf-8").splitlines()
    assert calls.index("daemon-reload") < calls.index("enable --now inventory-netctl-sync.timer")
```

Assert service environment file, `NoNewPrivileges=false`, `PrivateTmp=true`, `ProtectHome=true`, `TimeoutStartSec=2min`; assert timer `OnCalendar=*-*-* *:01/5:00`, `Persistent=true`, and worker `Unit`.

- [ ] **Step 2: Run deployment test and confirm failure**

Run: `python -m pytest tests/test_deploy_netctl.py -q`

Expected: failure because worker units and installer entries are absent.

- [ ] **Step 3: Implement hardened units and contracts**

```ini
[Service]
Type=oneshot
User=openvpn-web
Group=openvpn-web
WorkingDirectory=/opt/openvpn-web
EnvironmentFile=/etc/openvpn-web/openvpn-web.env
ExecStart=/opt/openvpn-web/.venv/bin/python -m app.inventory.netctl_sync
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
TimeoutStartSec=2min
```

Install `0644` units before daemon reload, extend the verifier's expected argv/properties, and enable the timer only after verifier success. Do not modify `netctl-collect.service`.

- [ ] **Step 4: Run deployment test and confirm success**

Run: `python -m pytest tests/test_deploy_netctl.py -q`

Expected: pass, including loaded-systemd and installation-order checks.

- [ ] **Step 5: Commit Task 3**

```bash
git add deploy/inventory-netctl-sync.service deploy/inventory-netctl-sync.timer deploy/install-openvpn-web.sh deploy/verify_netctl_systemd.py tests/test_deploy_netctl.py
git diff --cached --check
git commit -m "feat(inventory): schedule Netctl identifier sync"
```

### Task 4: Full Gate and Production Rollout

**Files:**

- Modify only verification-driven corrections from Tasks 1 through 3.

**Interfaces:**

- Produces verified `main` and a healthy enabled production timer.

- [ ] **Step 1: Run the complete local gate**

```bash
python -m ruff check app/inventory app/db.py tests/test_inventory_models.py tests/test_inventory_netctl_sync.py tests/test_deploy_netctl.py
python -m pytest tests/test_inventory_web.py tests/test_inventory_api.py tests/test_inventory_details.py tests/test_inventory_models.py tests/test_inventory_lookup.py tests/test_inventory_netctl_sync.py tests/test_deploy_netctl.py -q
git diff --check
```

Expected: Ruff success, all named tests pass, no whitespace errors.

- [ ] **Step 2: Publish verified main**

```bash
git status --short
git fetch origin main
git merge-base --is-ancestor origin/main HEAD
git push origin main
```

Expected: this feature is the only work ahead and the non-forced push succeeds.

- [ ] **Step 3: Back up and deploy production**

Back up the inventory DB under `/var/backups/openvpn-web/`. Stage exact changed application/unit files, preserve application ownership `openvpn-web:openvpn-web`, install root-owned units, reload systemd, and enable the timer. Never print protected environment values.

- [ ] **Step 4: Verify worker and data boundary**

Start `inventory-netctl-sync.service` once. Verify both services/timer are active, the ledger contains the snapshot/counters, no current MAC changed, deployed hashes match source, and local production `/login` returns HTTP 200.

- [ ] **Step 5: Commit verification-driven correction only if needed**

If verification finds a defect, first add a failing regression test, rerun the complete gate, make a focused conventional commit, and report final SHA, checks, worker state, snapshot ID, counters, and ambiguous skips.
