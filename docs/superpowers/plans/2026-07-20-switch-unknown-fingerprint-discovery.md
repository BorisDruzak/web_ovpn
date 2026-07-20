# Unknown Switch Fingerprint Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Persist and show safe fingerprints for unknown SNMP switches without allowing them to write FDB, VLAN, port, LLDP, STP, or counter state.

**Architecture:** Migration 8 stores one safe observation per source. A system-only discovery operation records requires_profile when no exact vendor profile matches. Existing Sources API and page render those rows without enable, collect, or profile-assignment actions.

**Tech Stack:** Python 3.12, SQLite, PySNMP, FastAPI/Jinja, pytest.

## Global Constraints

- Discovery sends SNMP GET/WALK only; never SNMP SET.
- Unknown discovery never calls FDB, VLAN, interface, bridge, LLDP, STP, or counter collectors.
- No community, secret reference, endpoint, raw varbind, MAC/FDB row, or switch configuration is stored or returned.
- Unknown rows have exact status requires_profile; no CLI/API/UI operation enables a source or assigns a profile.
- Known-profile behavior is unchanged. Production validation keeps sources and netctl-collect.timer disabled.

---

### Task 1: Add bounded unknown-fingerprint persistence

**Files:**

- Modify: netctl/migrations.py
- Create: netctl/switch_discovery_store.py
- Test: tests/test_netctl_switch_discovery_store.py

**Interfaces:**

- UnknownSwitchFingerprint(source_id, sys_object_id, sys_descr, fingerprint_sha256, capabilities_json, status, observed_at)
- record_unknown_fingerprint(conn, observation) and list_unknown_fingerprints(conn)

- [ ] **Step 1: Write failing tests**

    def test_unknown_fingerprint_upserts_one_row_per_source(tmp_path):
        conn = connect(_db_url(tmp_path / "discovery.sqlite"))
        record_unknown_fingerprint(conn, _observation(source_id=7, digest="a" * 64))
        record_unknown_fingerprint(conn, _observation(source_id=7, digest="b" * 64))
        assert [row["fingerprint_sha256"] for row in list_unknown_fingerprints(conn)] == ["b" * 64]

    def test_unknown_fingerprint_rejects_private_capability_keys(tmp_path):
        conn = connect(_db_url(tmp_path / "discovery.sqlite"))
        with pytest.raises(ValueError, match="capabilities"):
            record_unknown_fingerprint(conn, _observation(capabilities_json='[{"community":"x"}]'))

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/test_netctl_switch_discovery_store.py -q

Expected: FAIL because the store and migration do not exist.

- [ ] **Step 3: Implement migration 8 and store**

Create switch_unknown_fingerprints keyed by source_id with sys_object_id, sys_descr, fingerprint_sha256, capabilities_json, status and observed_at. Require status requires_profile; validate lowercase 64-hex digest and capability JSON rows containing only capability and outcome. Upsert by source ID and list rows joined to public source names, sorted by observed_at descending.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_switch_discovery_store.py tests/test_netctl_context_migrations.py -q

Expected: PASS.

    git add netctl/migrations.py netctl/switch_discovery_store.py tests/test_netctl_switch_discovery_store.py
    git commit -m "feat: persist unknown switch fingerprints"

### Task 2: Add system-only discovery CLI

**Files:**

- Modify: netctl/snmp/collector.py
- Modify: netctl/drivers/snmp_switch.py
- Modify: netctl/cli.py
- Test: tests/test_netctl_snmp_profiles.py
- Test: tests/test_netctl_switch_cli.py

**Interfaces:**

- collect_switch_discovery(options, transport) returns system identity and bounded capability outcomes.
- SnmpSwitchDriver.discover() returns the same structure.
- netctl --json sources discover SOURCE returns known or requires_profile.

- [ ] **Step 1: Write failing tests**

    def test_discovery_requests_only_system_capabilities():
        result = asyncio.run(collect_switch_discovery({}, _system_fixture_transport()))
        assert result.system.sys_object_id
        assert all(request.capability.startswith("sys_") for request in transport.requests)

    def test_unknown_discovery_writes_no_current_switch_state(tmp_path):
        payload = _run_cli_json(tmp_path, ["sources", "discover", "switch-unknown"])
        assert payload["status"] == "requires_profile"
        assert _count(tmp_path, "current_switch_fdb") == 0
        assert _count(tmp_path, "switch_ports") == 0

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/test_netctl_snmp_profiles.py -k discovery tests/test_netctl_switch_cli.py -k discover -q

Expected: FAIL because discovery is absent.

- [ ] **Step 3: Implement discovery**

Factor system capability requests sys_descr, sys_object_id, sys_uptime, sys_name and sys_location from collect_switch_snapshot into collect_switch_discovery; do not invoke any other collector. Add the driver method and CLI subcommand. Compute SHA-256 from sys_object_id, newline and sys_descr. A matching profile returns known; a missing or mismatched profile hint returns requires_profile and writes only the Task 1 row.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_snmp_profiles.py tests/test_netctl_switch_cli.py tests/test_netctl_switch_discovery_store.py -q

Expected: PASS.

    git add netctl/snmp/collector.py netctl/drivers/snmp_switch.py netctl/cli.py tests/test_netctl_snmp_profiles.py tests/test_netctl_switch_cli.py
    git commit -m "feat: add read-only switch discovery"

### Task 3: Show candidates through API and Sources page

**Files:**

- Modify: netctl/cli.py
- Modify: app/api.py
- Modify: app/main.py
- Modify: app/templates/network_sources.html
- Test: tests/test_netctl_switch_cli.py
- Test: tests/test_web_network_observer.py

**Interfaces:**

- netctl --json switches unknown-fingerprints returns only source, sys_object_id, sys_descr, fingerprint_sha256, capabilities, status and observed_at.
- GET /api/v1/network/switch-fingerprints exposes that list.
- network_sources.html consumes unknown_fingerprints.

- [ ] **Step 1: Write failing tests**

    def test_unknown_fingerprint_cli_has_only_safe_keys(tmp_path):
        row = _run_cli_json(tmp_path, ["switches", "unknown-fingerprints"])["fingerprints"][0]
        assert set(row) == {"source", "sys_object_id", "sys_descr", "fingerprint_sha256", "capabilities", "status", "observed_at"}

    def test_sources_page_renders_unknown_without_collect_control(client):
        response = client.get("/network/sources")
        assert "Unknown fingerprints" in response.text
        assert "requires_profile" in response.text

- [ ] **Step 2: Verify RED**

Run: python -m pytest tests/test_netctl_switch_cli.py -k unknown_fingerprint tests/test_web_network_observer.py -k unknown_fingerprint -q

Expected: FAIL because the command, API, context and template section are absent.

- [ ] **Step 3: Implement bounded presentation**

Add the CLI query, API GET route and template context. Render a separate Unknown fingerprints table with Source, System identity, Fingerprint, Capability summary, Observed and State. Do not add host, secret, enable, collect or profile-assignment controls.

- [ ] **Step 4: Verify GREEN and commit**

Run: python -m pytest tests/test_netctl_switch_cli.py tests/test_web_network_observer.py -q

Expected: PASS.

    git add netctl/cli.py app/api.py app/main.py app/templates/network_sources.html tests/test_netctl_switch_cli.py tests/test_web_network_observer.py
    git commit -m "feat: show unknown switch fingerprints"

### Task 4: Verify and release with disabled sources

**Files:**

- Modify: docs/runbooks/netctl-snmp-dgs-pilot.md
- Test: full repository suite

- [ ] **Step 1: Document the safe gate**

Document:

    sudo -u netctl /usr/local/sbin/netctl --json sources discover <disabled-source>
    sudo -u netctl /usr/local/sbin/netctl --json switches unknown-fingerprints

State that neither command enables the source/timer or writes FDB/current switch state.

- [ ] **Step 2: Verify and commit**

Run:

    python -m pytest -q
    git diff --check

Expected: all tests pass and no whitespace errors.

    git add docs/runbooks/netctl-snmp-dgs-pilot.md
    git commit -m "docs: add unknown switch discovery gate"

- [ ] **Step 3: Production validation**

Deploy only after a backup. Keep netctl-collect.timer inactive and disabled, run discovery for one disabled source, verify the source is still enabled: false, and stop if the command fails. Never run collect in this task.
