from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from netctl.config import load_config_sources
from netctl.snmp.models import (
    CapabilityResult,
    SwitchFdbEntry,
    SwitchPort,
    SwitchSnapshot,
    SwitchSystem,
)
from netctl.snmp.outcomes import SnmpOutcome


def _load_documented_source(
    example: str,
    temp_directory: Path,
) -> tuple[dict[str, Any], set[str]]:
    keys: list[str] = []
    for line in example.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert ":" in stripped, "documented source contains a non-mapping line"
        key = stripped.split(":", 1)[0].strip()
        assert key not in keys, f"documented source contains duplicate key: {key}"
        keys.append(key)

    config_path = temp_directory / "netctl.yaml"
    source_directory = temp_directory / "sources.d"
    source_directory.mkdir(parents=True)
    (source_directory / "documented-snmp.yaml").write_text(
        example.strip() + "\n",
        encoding="utf-8",
    )
    sources = load_config_sources(config_path)
    assert len(sources) == 1
    assert sources[0]["enabled"] is False, "documented source must set enabled to false"
    return sources[0], set(keys)


def test_installer_and_documented_snmp_examples_cannot_enable_or_embed_secret(
    tmp_path: Path,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    readme = (repository / "README.md").read_text(encoding="utf-8")
    installer = (repository / "deploy" / "install-openvpn-web.sh").read_text(
        encoding="utf-8"
    )
    runbook = (
        repository / "docs" / "runbooks" / "netctl-snmp-dgs-pilot.md"
    ).read_text(encoding="utf-8")
    yaml_blocks = re.findall(r"```yaml\n(.*?)```", readme, flags=re.DOTALL)
    snmp_examples = [block for block in yaml_blocks if "driver: snmp_switch" in block]

    assert len(snmp_examples) == 1
    example = snmp_examples[0]
    source, source_keys = _load_documented_source(example, tmp_path / "valid")
    assert source["driver"] == "snmp_switch"
    assert "community" not in {key.lower() for key in source_keys}
    with pytest.raises(AssertionError, match="enabled"):
        _load_documented_source(
            example.replace("enabled: false", "enabled: true"),
            tmp_path / "enabled",
        )
    with pytest.raises(AssertionError, match="duplicate key: enabled"):
        _load_documented_source(
            example.replace("enabled: false", "enabled: false\nenabled: true"),
            tmp_path / "duplicate",
        )
    assert "driver: snmp_switch" not in installer
    assert "add-snmp-switch" not in installer
    assert not re.search(
        r"NETCTL_SECRET_[A-Z0-9_]*_COMMUNITY\s*=", readme + installer + runbook
    )


def test_dgs_pilot_runbook_gates_timer_and_verifies_all_rollback_artifacts() -> None:
    repository = Path(__file__).resolve().parents[1]
    runbook = (
        repository / "docs" / "runbooks" / "netctl-snmp-dgs-pilot.md"
    ).read_text(encoding="utf-8")
    active_gate = 'test "$(systemctl is-active netctl-collect.timer)" = inactive'
    enabled_gate = 'test "$(systemctl is-enabled netctl-collect.timer)" = disabled'
    source_command = runbook.index("sources add-snmp-switch")
    manual_command = runbook.index('netctl --json collect "$pilot_source"')

    assert "sudo systemctl disable --now netctl-collect.timer" in runbook
    assert runbook.count(active_gate) >= 3
    assert runbook.count(enabled_gate) >= 3
    assert runbook.rfind(active_gate, 0, source_command) > runbook.index(
        "## 3. Stage a disabled source"
    )
    assert runbook.rfind(enabled_gate, 0, source_command) > runbook.index(
        "## 3. Stage a disabled source"
    )
    assert runbook.rfind(active_gate, 0, manual_command) > runbook.index(
        "## 4. Two controlled manual collections"
    )
    assert runbook.rfind(enabled_gate, 0, manual_command) > runbook.index(
        "## 4. Two controlled manual collections"
    )

    checksum_command = re.search(
        r'sudo sha256sum (?P<artifacts>.*?)\| sudo tee "\$checksums"',
        runbook,
        flags=re.DOTALL,
    )
    assert checksum_command is not None
    assert {
        '"$db_backup"',
        '"$app_backup"',
        '"$wrapper_backup"',
        '"$sources_backup"',
        '"$secrets_backup"',
    } <= set(re.findall(r'"\$[a-z_]+"', checksum_command.group("artifacts")))
    rollback = runbook.split("## Evidence and rollback", 1)[1]
    assert 'sudo sha256sum -c "$checksums"' in rollback
    assert 'timer_enabled_before="$(systemctl is-enabled netctl-collect.timer' in runbook
    assert 'timer_active_before="$(systemctl is-active netctl-collect.timer' in runbook
    assert "printf 'timer_enabled_before=%s\\n' \"$timer_enabled_before\"" in runbook
    assert "printf 'timer_active_before=%s\\n' \"$timer_active_before\"" in runbook
    assert 'test "$enabled_snmp_before_stage" = 0' in runbook
    assert 'test "$enabled_snmp_before_manual" = 1' in runbook
    assert 'test "$enabled_snmp_before_failure" = 1' in runbook
    assert 'test "$enabled_snmp_after_restore" = 0' in runbook
    assert runbook.count(
        'test "$(systemctl is-enabled netctl-collect.timer)" = "$timer_enabled_before"'
    ) >= 2
    assert runbook.count(
        'test "$(systemctl is-active netctl-collect.timer)" = "$timer_active_before"'
    ) >= 2


def _run_cli(args: list[str], capsys) -> tuple[int, dict[str, Any]]:
    from netctl.cli import main

    rc = main(args)
    captured = capsys.readouterr()
    assert captured.err == ""
    return rc, json.loads(captured.out)


def _base_args(config_path: Path, db_path: Path) -> list[str]:
    return [
        "--json",
        "--config",
        str(config_path),
        "--db",
        f"sqlite:///{db_path.as_posix()}",
    ]


def _snapshot(entry_count: int = 3) -> SwitchSnapshot:
    ports = tuple(
        SwitchPort(
            port_key=f"ifindex:{index}",
            if_index=index,
            bridge_port=index,
            physical_port=index,
            name=f"port-{index}",
            alias="",
            mac=None,
            admin_status="up",
            oper_status="up",
            speed_bps=1_000_000_000,
        )
        for index in range(1, entry_count + 1)
    )
    entries = tuple(
        SwitchFdbEntry(
            fdb_id=20,
            vlan_key="vid:20",
            vlan_id=20,
            mac=f"02:00:00:00:00:{index:02X}",
            port_key=f"ifindex:{index}",
            bridge_port=index,
            if_index=index,
            physical_port=index,
            port_name=f"port-{index}",
            status="learned",
        )
        for index in range(1, entry_count + 1)
    )
    return SwitchSnapshot(
        snapshot_kind="snmp_switch",
        profile_id="generic",
        profile_fingerprint="generic:v1",
        system=SwitchSystem(
            sys_descr="Synthetic switch",
            sys_object_id="1.3.6.1.4.1.99999.1",
            sys_name="switch-test",
            sys_location="lab",
            sys_uptime_ticks=123,
        ),
        ports=ports,
        fdb=entries,
        vlan_memberships=(),
        stp=None,
        lldp_neighbors=(),
        counter_samples=(),
        capabilities=(
            CapabilityResult(
                capability="fdb",
                outcome=SnmpOutcome.SUCCESS_WITH_ROWS,
                details={"raw_varbind": "must-not-be-printed"},
            ),
        ),
    )


def _snapshot_with_optional_state(entry_count: int = 3) -> SwitchSnapshot:
    snapshot = _snapshot(entry_count)
    return replace(
        snapshot,
        vlan_memberships=tuple(
            {
                "vlan_id": 20 + index,
                "port_key": f"ifindex:{index}",
                "if_index": index,
                "bridge_port": index,
                "physical_port": index,
                "port_name": f"port-{index}",
                "egress": True,
                "untagged": index % 2 == 0,
                "pvid": index == 1,
            }
            for index in range(1, entry_count + 1)
        ),
        lldp_neighbors=tuple(
            {
                "local_port_key": f"ifindex:{index}",
                "chassis_id": f"00:11:22:33:44:{index:02X}",
                "port_id": f"uplink-{index}",
                "system_name": f"neighbor-{index}",
            }
            for index in range(1, entry_count + 1)
        ),
        capabilities=(
            *snapshot.capabilities,
            CapabilityResult(
                "vlan_current_egress", SnmpOutcome.SUCCESS_WITH_ROWS
            ),
            CapabilityResult(
                "vlan_current_untagged", SnmpOutcome.SUCCESS_WITH_ROWS
            ),
            CapabilityResult("pvid", SnmpOutcome.SUCCESS_WITH_ROWS),
            CapabilityResult("lldp_remote", SnmpOutcome.SUCCESS_WITH_ROWS),
        ),
    )


class _FakeSwitchDriver:
    def __init__(self, snapshot: SwitchSnapshot | BaseException) -> None:
        self.snapshot = snapshot

    def collect(self) -> SwitchSnapshot:
        if isinstance(self.snapshot, BaseException):
            raise self.snapshot
        return self.snapshot

    def test(self) -> dict[str, Any]:
        return self.collect().to_test_summary()


def _write_switch_source(
    config_path: Path, *, name: str = "switch-test", enabled: bool = True
) -> None:
    directory = config_path.parent / "sources.d"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.yaml").write_text(
        "\n".join(
            [
                f"name: {name}",
                "driver: snmp_switch",
                "host: 192.0.2.10",
                "port: 161",
                f"secret_ref: {name.replace('-', '_')}_snmp",
                "site: test",
                "role: access-switch",
                f"enabled: {'true' if enabled else 'false'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_driver_registration_returns_thin_typed_snmp_driver() -> None:
    from netctl.drivers import SnmpSwitchDriver, driver_for

    driver = driver_for(
        {
            "name": "switch-test",
            "driver": "snmp_switch",
            "host": "192.0.2.10",
            "port": 161,
            "secret_ref": "switch_test_snmp",
            "driver_options": {},
        },
        {},
    )

    assert isinstance(driver, SnmpSwitchDriver)


def test_driver_factories_keep_legacy_and_typed_switch_contracts_separate() -> None:
    from netctl.drivers import (
        NetworkDriver,
        SnmpSwitchDriver,
        legacy_driver_for,
        snmp_driver_for,
    )

    switch = snmp_driver_for(
        {
            "name": "switch-test",
            "driver": "snmp_switch",
            "host": "192.0.2.10",
            "port": 161,
            "secret_ref": "switch_test_snmp",
            "driver_options": {},
        },
        {},
    )
    legacy = legacy_driver_for(
        {"name": "mock-test", "driver": "mock"},
        {},
    )

    assert isinstance(switch, SnmpSwitchDriver)
    assert not isinstance(switch, NetworkDriver)
    assert isinstance(legacy, NetworkDriver)
    with pytest.raises(ValueError, match="unsupported legacy driver"):
        legacy_driver_for({"driver": "snmp_switch"}, {})
    with pytest.raises(ValueError, match="unsupported switch driver"):
        snmp_driver_for({"driver": "mock"}, {})


class _LifecycleTransport:
    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


def test_real_snmp_driver_closes_transport_and_uses_safe_snapshot_serialization(
    monkeypatch,
) -> None:
    import netctl.drivers.snmp_switch as snmp_driver_module
    from netctl.drivers import SnmpSwitchDriver

    transport = _LifecycleTransport()
    snapshot = _snapshot()

    async def collect(_source, actual_transport):
        assert actual_transport is transport
        return snapshot

    monkeypatch.setattr(
        snmp_driver_module.SnmpTransport,
        "from_source",
        classmethod(lambda _cls, _source, *, secrets: transport),
    )
    monkeypatch.setattr(snmp_driver_module, "collect_switch_snapshot", collect)

    result = SnmpSwitchDriver(
        {"driver": "snmp_switch", "driver_options": {}}, {}
    ).test()

    assert transport.close_calls == 1
    assert result == snapshot.to_test_summary()
    rendered = json.dumps(result).lower()
    assert "raw_varbind" not in rendered
    assert '"details"' not in rendered
    assert "port_key" not in rendered
    assert '"fdb": [' not in rendered


def test_snmp_test_summary_is_bounded_and_contains_only_safe_aggregates() -> None:
    capabilities = tuple(
        CapabilityResult(
            capability=f"capability-{index}-" + ("x" * 500),
            outcome=SnmpOutcome.SUCCESS_EMPTY,
            error_code="private-code-" + ("x" * 500),
            error_message="private-message-" + ("x" * 500),
            details={"raw": "private-detail"},
        )
        for index in range(100)
    )
    base = _snapshot(100)
    snapshot = replace(
        base,
        profile_id="generic\n" + ("p" * 500),
        profile_fingerprint="generic:v1\r" + ("f" * 500),
        system=SwitchSystem(
            sys_descr="description\n" + ("d" * 10_000),
            sys_object_id="1.3.6.1.4.1.99999.1\r" + ("o" * 500),
            sys_name="switch\u2028" + ("n" * 500),
            sys_location="must-not-be-returned",
            sys_uptime_ticks=123,
        ),
        capabilities=capabilities,
    )

    summary = snapshot.to_test_summary()
    rendered = json.dumps(summary)

    assert set(summary) == {"profile", "system", "capabilities", "counts"}
    assert set(summary["profile"]) == {"id", "fingerprint"}
    assert set(summary["system"]) == {"sys_descr", "sys_object_id", "sys_name"}
    assert set(summary["counts"]) == {"ports", "fdb"}
    assert summary["counts"] == {"ports": 100, "fdb": 100}
    assert len(summary["capabilities"]) <= 32
    assert all(set(row) == {"capability", "outcome"} for row in summary["capabilities"])
    assert len(rendered) < 8192
    for forbidden in (
        "private-code",
        "private-message",
        "private-detail",
        "must-not-be-returned",
        "port_key",
        '"fdb": [',
        "\n",
        "\r",
        "\u2028",
    ):
        assert forbidden not in rendered


def test_real_snmp_driver_closes_transport_when_collector_raises(monkeypatch) -> None:
    import netctl.drivers.snmp_switch as snmp_driver_module
    from netctl.drivers import SnmpSwitchDriver

    transport = _LifecycleTransport()

    async def collect(_source, actual_transport):
        assert actual_transport is transport
        raise RuntimeError("synthetic collector failure")

    monkeypatch.setattr(
        snmp_driver_module.SnmpTransport,
        "from_source",
        classmethod(lambda _cls, _source, *, secrets: transport),
    )
    monkeypatch.setattr(snmp_driver_module, "collect_switch_snapshot", collect)

    with pytest.raises(RuntimeError, match="synthetic collector failure"):
        SnmpSwitchDriver(
            {"driver": "snmp_switch", "driver_options": {}}, {}
        ).collect()

    assert transport.close_calls == 1


def test_add_snmp_switch_is_disabled_and_yaml_is_secret_free(
    tmp_path: Path, capsys
) -> None:
    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "sources",
            "add-snmp-switch",
            "switch-test",
            "--host",
            "192.0.2.10",
            "--secret-ref",
            "switch_test_snmp",
            "--profile-hint",
            "generic",
        ],
        capsys,
    )

    assert rc == 0
    assert data["source"]["enabled"] is False
    yaml_text = (tmp_path / "sources.d" / "switch-test.yaml").read_text(
        encoding="utf-8"
    )
    assert "enabled: false" in yaml_text
    assert 'secret_ref: "switch_test_snmp"' in yaml_text
    assert "community" not in yaml_text.lower()
    from netctl.config import load_config_sources

    reloaded = load_config_sources(config_path)
    assert len(reloaded) == 1
    assert reloaded[0]["enabled"] is False


@pytest.mark.parametrize("runtime_asset_key", ["123", "false"])
def test_add_snmp_switch_preserves_string_scalars_across_yaml_reload(
    tmp_path: Path, capsys, runtime_asset_key: str
) -> None:
    from netctl.config import load_config_sources

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "sources",
            "add-snmp-switch",
            "switch-test",
            "--host",
            "192.0.2.10",
            "--secret-ref",
            "switch_test_snmp",
            "--runtime-asset-key",
            runtime_asset_key,
        ],
        capsys,
    )

    assert rc == 0
    assert data["source"]["driver_options"]["runtime_asset_key"] == runtime_asset_key
    reloaded = load_config_sources(config_path)
    assert reloaded[0]["driver_options"]["runtime_asset_key"] == runtime_asset_key


@pytest.mark.parametrize(
    "separator",
    ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"],
)
def test_source_yaml_rejects_every_python_line_separator(
    tmp_path: Path, separator: str
) -> None:
    from netctl.config import write_source_yaml

    with pytest.raises(ValueError, match="single line"):
        write_source_yaml(
            tmp_path / "netctl.yaml",
            {
                "name": "switch-test",
                "driver": "snmp_switch",
                "host": "192.0.2.10",
                "secret_ref": "switch_test_snmp",
                "role": f"access{separator}switch",
                "enabled": False,
            },
        )


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--host", "192.0.2.10\u2028injected"),
        ("--secret-ref", "switch_test\u2028snmp"),
        ("--site", "test\u2028injected"),
        ("--role", "access\u2028switch"),
        ("--snmp-version", "2c\u2028injected"),
        ("--profile-hint", "generic\u2028injected"),
        ("--runtime-asset-key", "asset\u2028injected"),
        ("--intent-context-id", "context\u2028injected"),
        ("--intent-stable-id", "switch\u2028injected"),
    ],
)
def test_add_snmp_switch_rejects_line_separator_in_every_yaml_string_option(
    tmp_path: Path, capsys, option: str, value: str
) -> None:
    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    args = _base_args(config_path, db_path) + [
        "sources",
        "add-snmp-switch",
        "switch-test",
        "--host",
        "192.0.2.10",
        "--secret-ref",
        "switch_test_snmp",
        option,
        value,
    ]

    rc, data = _run_cli(args, capsys)

    assert rc == 2
    assert data["status"] == "error"
    assert not (tmp_path / "sources.d" / "switch-test.yaml").exists()


def test_add_snmp_switch_rejects_line_separator_in_source_name(
    tmp_path: Path, capsys
) -> None:
    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "sources",
            "add-snmp-switch",
            "switch\u2028injected",
            "--host",
            "192.0.2.10",
            "--secret-ref",
            "switch_test_snmp",
        ],
        capsys,
    )

    assert rc == 2
    assert data["status"] == "error"
    assert not (tmp_path / "sources.d" / "switch-test.yaml").exists()


def test_add_snmp_switch_rejects_invalid_options_before_driver_dispatch(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    calls = []
    monkeypatch.setattr(cli, "driver_for", lambda *args: calls.append(args))

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "sources",
            "add-snmp-switch",
            "switch-test",
            "--host",
            "192.0.2.10",
            "--secret-ref",
            "switch_test_snmp",
            "--snmp-version",
            "3",
            "--event-retention-days",
            "0",
        ],
        capsys,
    )

    assert rc == 2
    assert data["status"] == "error"
    assert calls == []
    assert not (tmp_path / "sources.d" / "switch-test.yaml").exists()


def test_add_snmp_switch_rejects_invalid_endpoint_and_yaml_injection(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    calls = []
    monkeypatch.setattr(cli, "driver_for", lambda *args: calls.append(args))

    for extra in (
        ["--host", "", "--port", "161"],
        ["--host", "192.0.2.10", "--port", "0"],
        ["--host", "192.0.2.10\nraw_varbind: injected", "--port", "161"],
    ):
        rc, data = _run_cli(
            _base_args(config_path, db_path)
            + [
                "sources",
                "add-snmp-switch",
                "switch-test",
                *extra,
                "--secret-ref",
                "switch_test_snmp",
            ],
            capsys,
        )
        assert rc == 2
        assert data["status"] == "error"

    assert calls == []
    assert not (tmp_path / "sources.d" / "switch-test.yaml").exists()


def test_source_inspect_and_test_never_expose_secret_or_raw_capability_details(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    _write_switch_source(config_path)
    monkeypatch.setattr(
        cli, "driver_for", lambda _source, _secrets: _FakeSwitchDriver(_snapshot())
    )
    inspect_rc, inspected = _run_cli(
        _base_args(config_path, db_path)
        + ["sources", "inspect", "switch-test"],
        capsys,
    )
    test_rc, tested = _run_cli(
        _base_args(config_path, db_path) + ["sources", "test", "switch-test"],
        capsys,
    )

    assert inspect_rc == test_rc == 0
    rendered = json.dumps([inspected, tested]).lower()
    assert "resolved-secret-value" not in rendered
    assert "raw_varbind" not in rendered
    assert "must-not-be-printed" not in rendered
    assert '"details"' not in rendered
    assert "port_key" not in rendered
    assert '"fdb": [' not in rendered
    assert tested["result"]["counts"] == {"ports": 3, "fdb": 3}


def test_collect_all_isolates_failed_snmp_source_from_other_sources(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli
    from netctl.drivers.mock import MockDriver

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    _write_switch_source(config_path, name="switch-fails")
    directory = config_path.parent / "sources.d"
    (directory / "mock-ok.yaml").write_text(
        "\n".join(
            [
                "name: mock-ok",
                "driver: mock",
                "host: 192.0.2.20",
                "port: 8729",
                "secret_ref: mock-ok",
                "site: test",
                "role: router",
                "enabled: true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        cli,
        "snmp_driver_for",
        lambda _source, _secrets: _FakeSwitchDriver(
            RuntimeError("resolved-secret-value")
        ),
    )
    monkeypatch.setattr(
        cli,
        "legacy_driver_for",
        lambda source, secrets: MockDriver(source, secrets),
    )

    rc, data = _run_cli(
        _base_args(config_path, db_path) + ["collect", "all"], capsys
    )

    assert rc == 1
    by_source = {item["source"]: item for item in data["results"]}
    assert by_source["switch-fails"]["status"] == "error"
    assert "resolved-secret-value" not in json.dumps(data)
    assert by_source["mock-ok"]["status"] == "ok"
    assert by_source["mock-ok"]["summary"]["arp"] >= 1


def test_snmp_collect_dispatches_typed_snapshot_to_switch_store_only(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli
    from netctl.db import connect

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    _write_switch_source(config_path)
    monkeypatch.setattr(
        cli,
        "snmp_driver_for",
        lambda _source, _secrets: _FakeSwitchDriver(_snapshot()),
    )
    monkeypatch.setattr(
        cli,
        "save_collection",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("legacy save_collection received a switch snapshot")
        ),
    )

    rc, data = _run_cli(
        _base_args(config_path, db_path) + ["collect", "switch-test"], capsys
    )

    assert rc == 0
    assert data["status"] == "ok"
    assert data["summary"]["fdb_current"] == 3
    conn = connect(f"sqlite:///{db_path.as_posix()}")
    try:
        stored = conn.execute("SELECT COUNT(*) FROM current_switch_fdb").fetchone()[0]
    finally:
        conn.close()
    assert stored == 3


def test_switch_fdb_query_is_read_only_bounded_and_raw_free(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.switch_store import collect_and_save_switch

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    db_url = f"sqlite:///{db_path.as_posix()}"
    _write_switch_source(config_path)
    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        source = get_source(conn, "switch-test")
        assert source is not None
        result = collect_and_save_switch(
            conn,
            source,
            _FakeSwitchDriver(_snapshot(3)),
            "2026-07-19T10:00:00Z",
        )
        assert result["status"] == "success"
        before = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "switch_devices",
                "switch_collection_runs",
                "switch_capabilities",
                "switch_ports",
                "current_switch_fdb",
                "switch_fdb_events",
            )
        }
    finally:
        conn.close()

    def fail_factory(*_args):
        raise AssertionError("driver called by query")

    monkeypatch.setattr(cli, "driver_for", fail_factory)
    monkeypatch.setattr(cli, "snmp_driver_for", fail_factory)
    monkeypatch.setattr(cli, "legacy_driver_for", fail_factory)
    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "switches",
            "fdb",
            "--source",
            "switch-test",
            "--vlan",
            "20",
            "--limit",
            "2",
            "--offset",
            "0",
        ],
        capsys,
    )

    assert rc == 0
    assert len(data["fdb"]) == 2
    assert data["pagination"] == {
        "limit": 2,
        "offset": 0,
        "returned": 2,
        "has_more": True,
        "next_offset": 2,
    }
    rendered = json.dumps(data).lower()
    assert "varbind" not in rendered
    assert '"details"' not in rendered
    assert "community" not in rendered

    conn = connect(db_url)
    try:
        after = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        }
    finally:
        conn.close()
    assert after == before


@pytest.mark.parametrize(
    ("command", "result_key"),
    [("vlans", "vlans"), ("lldp", "lldp_neighbors")],
)
def test_switch_optional_query_is_read_only_source_filtered_paginated_and_raw_free(
    tmp_path: Path,
    capsys,
    monkeypatch,
    command: str,
    result_key: str,
) -> None:
    import netctl.cli as cli
    from netctl.db import connect, get_source, sync_config_sources
    from netctl.switch_store import collect_and_save_switch

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    db_url = f"sqlite:///{db_path.as_posix()}"
    _write_switch_source(config_path)
    _write_switch_source(config_path, name="switch-other")
    conn = connect(db_url)
    try:
        sync_config_sources(conn, config_path)
        for name in ("switch-test", "switch-other"):
            source = get_source(conn, name)
            assert source is not None
            result = collect_and_save_switch(
                conn,
                source,
                _FakeSwitchDriver(_snapshot_with_optional_state(3)),
                "2026-07-19T10:00:00Z",
            )
            assert result["status"] == "success"
        before_changes = conn.total_changes
    finally:
        conn.close()

    def fail_factory(*_args):
        raise AssertionError("driver called by query")

    monkeypatch.setattr(cli, "driver_for", fail_factory)
    monkeypatch.setattr(cli, "snmp_driver_for", fail_factory)
    monkeypatch.setattr(cli, "legacy_driver_for", fail_factory)
    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + [
            "switches",
            command,
            "--source",
            "switch-test",
            "--limit",
            "2",
            "--offset",
            "1",
        ],
        capsys,
    )

    assert rc == 0
    assert len(data[result_key]) == 2
    assert {row["source"] for row in data[result_key]} == {"switch-test"}
    assert data["pagination"] == {
        "limit": 2,
        "offset": 1,
        "returned": 2,
        "has_more": False,
        "next_offset": None,
    }
    rendered = json.dumps(data).lower()
    assert "varbind" not in rendered
    assert "community" not in rendered
    assert "details" not in rendered

    read_only = connect(db_url)
    try:
        assert read_only.total_changes == 0
        assert before_changes > 0
    finally:
        read_only.close()


@pytest.mark.parametrize("command", ["vlans", "lldp"])
def test_switch_optional_query_defaults_to_500_and_allows_at_most_5000(
    tmp_path: Path, capsys, command: str
) -> None:
    from netctl.db import connect

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "netctl.sqlite"
    conn = connect(f"sqlite:///{db_path.as_posix()}")
    conn.close()

    rc, data = _run_cli(
        _base_args(config_path, db_path) + ["switches", command], capsys
    )
    assert rc == 0
    assert data["pagination"]["limit"] == 500

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + ["switches", command, "--limit", "5000", "--offset", "0"],
        capsys,
    )
    assert rc == 0
    assert data["pagination"]["limit"] == 5000

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + ["switches", command, "--limit", "5001"],
        capsys,
    )
    assert rc == 2
    assert data == {
        "status": "error",
        "message": "limit must be between 1 and 5000",
    }

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + ["switches", command, "--offset", "-1"],
        capsys,
    )
    assert rc == 2
    assert data == {
        "status": "error",
        "message": "offset must be zero or greater",
    }


def test_switch_query_rejects_unbounded_pagination_before_opening_database(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import netctl.cli as cli

    config_path = tmp_path / "netctl.yaml"
    db_path = tmp_path / "missing.sqlite"
    monkeypatch.setattr(
        cli,
        "connect_read_only",
        lambda *_args: (_ for _ in ()).throw(AssertionError("database opened")),
    )

    rc, data = _run_cli(
        _base_args(config_path, db_path)
        + ["switches", "ports", "--limit", "501"],
        capsys,
    )

    assert rc == 2
    assert data == {"status": "error", "message": "limit must be between 1 and 500"}
