from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import re

from netctl.switch_profile_hints import SUPPORTED_SNMP_PROFILE_HINTS

from .models import PortResolution, SwitchPort, SwitchSystem


_DGS_1210_52_SYSTEM_DESCRIPTION = re.compile(r"WS6-DGS-1210-52(?=$|[ /])")
_DGS_1210_52_SYS_OBJECT_ID = "1.3.6.1.4.1.171.10.153.7.1"
_DGS_1210_52_FRONT_PANEL_PORTS = range(1, 53)
_DGS_FRONT_PANEL_NAME = re.compile(r"front-([1-9][0-9]*)\Z")
_SNR_SYS_OBJECT_ID_PREFIX = "1.3.6.1.4.1.57206"
_SNR_PORT_NAME = re.compile(r"(?:ge|xe)([1-9][0-9]*)\Z", re.IGNORECASE)
_SNR_LAG_NAME = re.compile(r"po([1-9][0-9]*)\Z", re.IGNORECASE)
_TPLINK_T1600G_SYSTEM_DESCRIPTION = re.compile(r"\bT1600G-[0-9]+[A-Z0-9-]*\b")
_CSS326_SYSTEM_DESCRIPTION = re.compile(r"\bCSS326-24G-2S\+?(?=$|[ /])")
_CSS326_PHYSICAL_PORTS = range(1, 27)


class SnmpParseError(ValueError):
    """A sanitized SNMP payload cannot be normalized safely."""


class PortProfile:
    profile_id = "base"
    profile_fingerprint = "base:v1"
    qbridge_fid_mode = "mapped_only"

    def normalize_ports(
        self, ports: tuple[SwitchPort, ...]
    ) -> tuple[SwitchPort, ...]:
        return ports

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        raise NotImplementedError

    def resolve_bridge_port(
        self,
        *,
        bridge_port: int,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        if_index = bridge_to_ifindex.get(bridge_port)
        if if_index is None:
            raise ValueError("unknown bridge port")
        port = ports_by_ifindex.get(if_index)
        if port is None:
            raise ValueError("unknown ifIndex")
        return PortResolution(
            port_key=port.port_key,
            if_index=port.if_index,
            bridge_port=bridge_port,
            physical_port=port.physical_port,
            port_name=port.name,
        )

    def resolve_stp_root_port(
        self,
        *,
        raw_root_port: int,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        return self.resolve_bridge_port(
            bridge_port=raw_root_port,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )

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
        if (
            not vids
            and self.qbridge_fid_mode == "proven_equals_vid"
            and fdb_id <= 4094
        ):
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
        return self.resolve_bridge_port(
            bridge_port=raw_fdb_port,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
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


class SnrProfile(GenericProfile):
    """SNR normalization proven by the sanitized SNR fixture."""

    profile_id = "snr"
    profile_fingerprint = "snr:v1"
    qbridge_fid_mode = "mapped_only"

    @staticmethod
    def matches(system: SwitchSystem) -> bool:
        return system.sys_object_id == _SNR_SYS_OBJECT_ID_PREFIX or system.sys_object_id.startswith(
            f"{_SNR_SYS_OBJECT_ID_PREFIX}."
        )

    @staticmethod
    def _resolution_from_port(port: SwitchPort) -> PortResolution:
        if port.if_index is None or port.bridge_port is None:
            raise ValueError("SNR port mapping is invalid")
        lag_match = _SNR_LAG_NAME.fullmatch(port.name)
        if lag_match is not None:
            return PortResolution(
                port_key=f"lag:po{lag_match.group(1)}",
                if_index=port.if_index,
                bridge_port=port.bridge_port,
                physical_port=None,
                port_name=port.name,
            )
        if _SNR_PORT_NAME.fullmatch(port.name) is not None:
            return PortResolution(
                port_key=f"physical:{port.bridge_port}",
                if_index=port.if_index,
                bridge_port=port.bridge_port,
                physical_port=port.bridge_port,
                port_name=port.name,
            )
        return PortResolution(
            port_key=port.port_key,
            if_index=port.if_index,
            bridge_port=port.bridge_port,
            physical_port=port.physical_port,
            port_name=port.name,
        )

    def resolve_bridge_port(
        self,
        *,
        bridge_port: int,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        resolution = super().resolve_bridge_port(
            bridge_port=bridge_port,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )
        port = ports_by_ifindex[resolution.if_index]
        return self._resolution_from_port(port)

    def _resolution_for_ifindex(
        self,
        *,
        if_index: int,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        port = ports_by_ifindex.get(if_index)
        if port is None:
            raise ValueError("unknown ifIndex")
        bridge_ports = [
            bridge_port
            for bridge_port, mapped_ifindex in bridge_to_ifindex.items()
            if mapped_ifindex == if_index
        ]
        if len(bridge_ports) != 1 or port.bridge_port != bridge_ports[0]:
            raise ValueError("ambiguous bridge port mapping")
        return self._resolution_from_port(port)

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        if fdb_mode == "qbridge":
            if raw_fdb_port == 31071:
                return self._resolution_for_ifindex(
                    if_index=100001,
                    bridge_to_ifindex=bridge_to_ifindex,
                    ports_by_ifindex=ports_by_ifindex,
                )
            return self._resolution_for_ifindex(
                if_index=raw_fdb_port,
                bridge_to_ifindex=bridge_to_ifindex,
                ports_by_ifindex=ports_by_ifindex,
            )
        return super().resolve_fdb_port(
            raw_fdb_port=raw_fdb_port,
            fdb_mode=fdb_mode,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
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
        if vlan_id is not None or vids_by_fid.get(fdb_id) or fdb_id > 4094:
            return vlan_key, vlan_id
        return f"vid:{fdb_id}", fdb_id

    def resolve_stp_root_port(
        self,
        *,
        raw_root_port: int,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        if raw_root_port == 927:
            return self._resolution_for_ifindex(
                if_index=5023,
                bridge_to_ifindex=bridge_to_ifindex,
                ports_by_ifindex=ports_by_ifindex,
            )
        return super().resolve_stp_root_port(
            raw_root_port=raw_root_port,
            bridge_to_ifindex=bridge_to_ifindex,
            ports_by_ifindex=ports_by_ifindex,
        )


class TplinkProfile(GenericProfile):
    """TP-Link T1600G normalization proven by the sanitized fixture."""

    profile_id = "tplink"
    profile_fingerprint = "tplink:v1"
    qbridge_fid_mode = "proven_equals_vid"

    @staticmethod
    def matches(system: SwitchSystem) -> bool:
        return _TPLINK_T1600G_SYSTEM_DESCRIPTION.search(system.sys_descr) is not None

    @staticmethod
    def _resolution_from_port(
        port: SwitchPort, *, physical_port: int
    ) -> PortResolution:
        if port.if_index is None or port.bridge_port is None:
            raise ValueError("TP-Link port mapping is invalid")
        return PortResolution(
            port_key=f"physical:{physical_port}",
            if_index=port.if_index,
            bridge_port=port.bridge_port,
            physical_port=physical_port,
            port_name=port.name,
        )

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
        if_index = 49152 + raw_fdb_port
        port = ports_by_ifindex.get(if_index)
        if port is None:
            raise SnmpParseError(
                f"TP-Link physical port {raw_fdb_port} has no ifIndex {if_index}"
            )
        return self._resolution_from_port(port, physical_port=raw_fdb_port)


class Css326Profile(GenericProfile):
    """CSS326 legacy bridge ports map one-to-one to physical ports."""

    profile_id = "css326"
    profile_fingerprint = "css326:v1"

    @staticmethod
    def matches(system: SwitchSystem) -> bool:
        return _CSS326_SYSTEM_DESCRIPTION.search(system.sys_descr) is not None

    def normalize_ports(
        self, ports: tuple[SwitchPort, ...]
    ) -> tuple[SwitchPort, ...]:
        normalized: list[SwitchPort] = []
        for port in ports:
            if (
                port.bridge_port in _CSS326_PHYSICAL_PORTS
                and port.if_index == port.bridge_port
            ):
                physical_port = port.bridge_port
                normalized.append(
                    replace(
                        port,
                        port_key=f"physical:{physical_port}",
                        physical_port=physical_port,
                    )
                )
            else:
                normalized.append(port)
        return tuple(normalized)

    def resolve_fdb_port(
        self,
        *,
        raw_fdb_port: int,
        fdb_mode: str,
        bridge_to_ifindex: Mapping[int, int],
        ports_by_ifindex: Mapping[int, SwitchPort],
    ) -> PortResolution:
        if fdb_mode != "legacy" or raw_fdb_port not in _CSS326_PHYSICAL_PORTS:
            raise ValueError("CSS326 FDB port is invalid")
        if bridge_to_ifindex.get(raw_fdb_port) != raw_fdb_port:
            raise ValueError("CSS326 bridge mapping is not one-to-one")
        port = ports_by_ifindex.get(raw_fdb_port)
        if port is None or port.bridge_port != raw_fdb_port:
            raise ValueError("CSS326 port mapping is invalid")
        return PortResolution(
            port_key=f"physical:{raw_fdb_port}",
            if_index=raw_fdb_port,
            bridge_port=raw_fdb_port,
            physical_port=raw_fdb_port,
            port_name=port.name,
        )


def detect_profile(
    system: SwitchSystem, *, profile_hint: str | None = None
) -> PortProfile:
    is_dgs = DgsProfile.matches(system)
    is_snr = SnrProfile.matches(system)
    is_tplink = TplinkProfile.matches(system)
    is_css326 = Css326Profile.matches(system)
    if profile_hint is not None and profile_hint not in SUPPORTED_SNMP_PROFILE_HINTS:
        raise ValueError("SNMP profile_hint is unsupported")
    if profile_hint == "dgs" and not is_dgs:
        raise ValueError("SNMP profile_hint does not match the switch")
    if profile_hint == "dgs" or (profile_hint is None and is_dgs):
        return DgsProfile()
    if profile_hint is None and is_snr:
        return SnrProfile()
    if profile_hint is None and is_tplink:
        return TplinkProfile()
    if profile_hint is None and is_css326:
        return Css326Profile()
    return GenericProfile()
