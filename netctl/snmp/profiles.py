from __future__ import annotations

from collections.abc import Mapping
import re

from netctl.switch_profile_hints import SUPPORTED_SNMP_PROFILE_HINTS

from .models import PortResolution, SwitchPort, SwitchSystem


_DGS_1210_52_SYSTEM_DESCRIPTION = re.compile(r"WS6-DGS-1210-52(?=$|[ /])")
_DGS_1210_52_SYS_OBJECT_ID = "1.3.6.1.4.1.171.10.153.7.1"
_DGS_1210_52_FRONT_PANEL_PORTS = range(1, 53)
_DGS_FRONT_PANEL_NAME = re.compile(r"front-([1-9][0-9]*)\Z")


class PortProfile:
    profile_id = "base"
    profile_fingerprint = "base:v1"
    qbridge_fid_mode = "mapped_only"

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        raise NotImplementedError

    def resolve_fdb_vlan(
        self,
        *,
        fdb_id: int,
        vids_by_fid: Mapping[int, set[int]],
    ) -> tuple[str, int | None]:
        if isinstance(fdb_id, bool) or not isinstance(fdb_id, int) or fdb_id <= 0:
            raise ValueError("FDB ID is invalid")
        vids = vids_by_fid.get(fdb_id, set())
        if any(
            isinstance(vid, bool) or not isinstance(vid, int) or not 1 <= vid <= 4094
            for vid in vids
        ):
            raise ValueError("VLAN ID is invalid")
        if len(vids) == 1:
            vid = next(iter(vids))
            return f"vid:{vid}", vid
        if not vids and self.qbridge_fid_mode == "proven_equals_vid":
            return f"vid:{fdb_id}", fdb_id
        return f"fid:{fdb_id}", None


class GenericProfile(PortProfile):
    profile_id = "generic"
    profile_fingerprint = "generic:v1"
    qbridge_fid_mode = "mapped_only"

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        if fdb_mode not in {"qbridge", "legacy"}:
            raise ValueError("FDB mode is unsupported")
        if (
            isinstance(raw_fdb_port, bool)
            or not isinstance(raw_fdb_port, int)
            or raw_fdb_port <= 0
        ):
            raise ValueError("FDB port is invalid")
        if_index = bridge_to_ifindex.get(raw_fdb_port)
        if if_index is None:
            raise ValueError("unknown bridge port")
        port = ports_by_ifindex.get(if_index)
        if port is None:
            raise ValueError("unknown ifIndex")
        return PortResolution(
            port_key=port.port_key,
            if_index=port.if_index,
            bridge_port=raw_fdb_port,
            physical_port=port.physical_port,
            port_name=port.name,
        )


class DgsProfile(GenericProfile):
    """DGS-specific Q-BRIDGE normalization proven by the sanitized fixture."""

    profile_id = "dgs"
    profile_fingerprint = "dgs:v1"

    @staticmethod
    def matches(system: SwitchSystem) -> bool:
        return (
            _DGS_1210_52_SYSTEM_DESCRIPTION.match(system.sys_descr) is not None
            and system.sys_object_id == _DGS_1210_52_SYS_OBJECT_ID
        )

    @staticmethod
    def _front_panel_port(port: SwitchPort) -> int | None:
        match = _DGS_FRONT_PANEL_NAME.fullmatch(port.name)
        if match is None:
            return None
        physical_port = int(match.group(1))
        if physical_port not in _DGS_1210_52_FRONT_PANEL_PORTS:
            return None
        return physical_port

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        resolution = super().resolve_fdb_port(
            raw_fdb_port=raw_fdb_port,
            fdb_mode=fdb_mode,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )
        if fdb_mode != "qbridge":
            return resolution
        port = ports_by_ifindex.get(resolution.if_index)
        if port is None:
            return resolution
        physical_port = self._front_panel_port(port)
        if physical_port != raw_fdb_port:
            return resolution
        matching_ports = [
            candidate
            for candidate in ports_by_ifindex.values()
            if self._front_panel_port(candidate) == raw_fdb_port
        ]
        if matching_ports != [port]:
            return resolution
        return PortResolution(
            port_key=resolution.port_key,
            if_index=resolution.if_index,
            bridge_port=resolution.bridge_port,
            physical_port=physical_port,
            port_name=resolution.port_name,
        )

    def resolve_fdb_vlan(
        self,
        *,
        fdb_id: int,
        vids_by_fid: Mapping[int, set[int]],
    ) -> tuple[str, int | None]:
        vlan_key, vlan_id = super().resolve_fdb_vlan(
            fdb_id=fdb_id, vids_by_fid=vids_by_fid
        )
        if vlan_id is None and not vids_by_fid.get(fdb_id) and fdb_id <= 4094:
            return f"vid:{fdb_id}", fdb_id
        return vlan_key, vlan_id


def detect_profile(
    system: SwitchSystem, *, profile_hint: str | None = None
) -> PortProfile:
    is_dgs = DgsProfile.matches(system)
    if profile_hint is not None and profile_hint not in SUPPORTED_SNMP_PROFILE_HINTS:
        raise ValueError("SNMP profile_hint is unsupported")
    if profile_hint == "dgs" and not is_dgs:
        raise ValueError("SNMP profile_hint does not match the switch")
    if profile_hint == "dgs" or (profile_hint is None and is_dgs):
        return DgsProfile()
    return GenericProfile()
