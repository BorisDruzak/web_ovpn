from __future__ import annotations

from collections.abc import Mapping

from .models import PortResolution, SwitchPort, SwitchSystem


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


def detect_profile(
    system: SwitchSystem, *, profile_hint: str | None = None
) -> PortProfile:
    del system
    if profile_hint not in (None, "generic"):
        raise ValueError("SNMP profile_hint is unsupported")
    return GenericProfile()
