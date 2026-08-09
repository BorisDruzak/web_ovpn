from __future__ import annotations

from dataclasses import asdict

import pytest


NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" />
        <service name="ssh" product="OpenSSH" version="9.2p1"
                 extrainfo="Ubuntu Linux" tunnel="ssl" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:9.2p1</cpe>
          <cpe> cpe:/o:canonical:ubuntu_linux </cpe>
        </service>
        <script id="ssh-hostkey" output="must never be normalized or stored" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" />
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4 - 6.5" accuracy="96" line="private-raw-detail">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux"
                 osgen="6.X" accuracy="95">
          <cpe>cpe:/o:linux:linux_kernel:6</cpe>
        </osclass>
        <osclass type="router" vendor="OpenWrt" osfamily="Linux"
                 osgen="5.X" accuracy="88">
          <cpe>cpe:/o:openwrt:openwrt</cpe>
        </osclass>
      </osmatch>
      <script id="os-script" output="must never be normalized or stored" />
    </os>
  </host>
  <runstats><finished time="ignored" summary="ignored" /></runstats>
</nmaprun>
"""

WINDOWS_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <os>
      <osmatch name="Microsoft Windows 10 1909 - 21H1" accuracy="98">
        <osclass type="general purpose" vendor="Microsoft" osfamily="Windows"
                 osgen="10" accuracy="98">
          <cpe>cpe:/o:microsoft:windows_10</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""

NETWORK_DEVICE_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <os>
      <osmatch name="MikroTik RouterOS 7.X" accuracy="97">
        <osclass type="router" vendor="MikroTik" osfamily="RouterOS"
                 osgen="7.X" accuracy="97">
          <cpe>cpe:/o:mikrotik:routeros:7</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""

SERVICE_ONLY_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <ports>
      <port protocol="tcp" portid="554">
        <state state="open" />
        <service name="rtsp" product="Hikvision IP camera rtspd"
                 method="probed" conf="10">
          <cpe>cpe:/h:hikvision:ip_camera</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_projects_only_normalized_port_fields() -> None:
    """Persisting arbitrary XML attributes or script output would leak raw scan data."""
    from netctl.nmap.parser import parse_nmap_xml

    result = parse_nmap_xml(NMAP_XML)

    assert result.nmap_version == "7.95"
    assert [asdict(port) for port in result.ports] == [
        {
            "protocol": "tcp",
            "port": 22,
            "state": "open",
            "service_name": "ssh",
            "product": "OpenSSH",
            "version": "9.2p1",
            "extra_info": "Ubuntu Linux",
            "tunnel": "ssl",
            "method": "probed",
            "confidence": 10,
            "cpes": (
                "cpe:/a:openbsd:openssh:9.2p1",
                "cpe:/o:canonical:ubuntu_linux",
            ),
        },
        {
            "protocol": "tcp",
            "port": 443,
            "state": "closed",
            "service_name": "",
            "product": "",
            "version": "",
            "extra_info": "",
            "tunnel": "",
            "method": "",
            "confidence": None,
            "cpes": (),
        },
    ]
    assert "must never" not in repr(result)
    assert "reason" not in repr(result)


def test_parse_nmap_xml_projects_os_match_and_class_fields() -> None:
    """Dropping osclass nesting would make stored OS evidence incomplete."""
    from netctl.nmap.parser import parse_nmap_xml

    result = parse_nmap_xml(NMAP_XML)

    assert [asdict(match) for match in result.os_matches] == [
        {
            "name": "Linux 5.4 - 6.5",
            "accuracy": 96,
            "classes": (
                {
                    "type": "general purpose",
                    "vendor": "Linux",
                    "osfamily": "Linux",
                    "osgen": "6.X",
                    "accuracy": 95,
                    "cpes": ("cpe:/o:linux:linux_kernel:6",),
                },
                {
                    "type": "router",
                    "vendor": "OpenWrt",
                    "osfamily": "Linux",
                    "osgen": "5.X",
                    "accuracy": 88,
                    "cpes": ("cpe:/o:openwrt:openwrt",),
                },
            ),
        }
    ]
    assert "private-raw-detail" not in repr(result)


def test_parse_nmap_xml_windows_fixture_projects_windows_os_class() -> None:
    """Dropping Windows osclass fields would remove the PC classification signal."""
    from netctl.nmap.parser import parse_nmap_xml

    result = parse_nmap_xml(WINDOWS_XML)

    assert [asdict(match) for match in result.os_matches] == [
        {
            "name": "Microsoft Windows 10 1909 - 21H1",
            "accuracy": 98,
            "classes": (
                {
                    "type": "general purpose",
                    "vendor": "Microsoft",
                    "osfamily": "Windows",
                    "osgen": "10",
                    "accuracy": 98,
                    "cpes": ("cpe:/o:microsoft:windows_10",),
                },
            ),
        }
    ]


def test_parse_nmap_xml_network_device_fixture_projects_router_os_class() -> None:
    """A router osclass must remain available to the network-device provider."""
    from netctl.nmap.parser import parse_nmap_xml

    result = parse_nmap_xml(NETWORK_DEVICE_XML)

    assert [asdict(match) for match in result.os_matches] == [
        {
            "name": "MikroTik RouterOS 7.X",
            "accuracy": 97,
            "classes": (
                {
                    "type": "router",
                    "vendor": "MikroTik",
                    "osfamily": "RouterOS",
                    "osgen": "7.X",
                    "accuracy": 97,
                    "cpes": ("cpe:/o:mikrotik:routeros:7",),
                },
            ),
        }
    ]


def test_parse_nmap_xml_service_only_fixture_preserves_services_without_os() -> None:
    """A service-only scan must not require or invent an OS match."""
    from netctl.nmap.parser import parse_nmap_xml

    result = parse_nmap_xml(SERVICE_ONLY_XML)

    assert [asdict(port) for port in result.ports] == [
        {
            "protocol": "tcp",
            "port": 554,
            "state": "open",
            "service_name": "rtsp",
            "product": "Hikvision IP camera rtspd",
            "version": "",
            "extra_info": "",
            "tunnel": "",
            "method": "probed",
            "confidence": 10,
            "cpes": ("cpe:/h:hikvision:ip_camera",),
        }
    ]
    assert result.os_matches == ()


def test_parse_nmap_xml_rejects_multiple_host_documents() -> None:
    """Accepting multiple hosts would violate the one-asset/one-IP profile."""
    from netctl.nmap.parser import NmapParseError, parse_nmap_xml

    xml = b'<nmaprun version="7.95"><host/><host/></nmaprun>'

    with pytest.raises(NmapParseError, match="one host"):
        parse_nmap_xml(xml)


def test_parse_nmap_xml_sanitizes_malformed_input_error() -> None:
    """Parser errors exposed to callers must not echo raw XML."""
    from netctl.nmap.parser import NmapParseError, parse_nmap_xml

    secret_xml = b"<nmaprun><secret-token>do-not-return"

    with pytest.raises(NmapParseError) as caught:
        parse_nmap_xml(secret_xml)

    assert str(caught.value) == "invalid Nmap XML output"
    assert "do-not-return" not in str(caught.value)
