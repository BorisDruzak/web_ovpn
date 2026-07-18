from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_policy_unit_follows_wg_lifecycle():
    text = (ROOT / "deploy" / "vpn-policy.service").read_text(encoding="utf-8")

    assert "Requires=wg-quick@wg0.service" in text
    assert "BindsTo=wg-quick@wg0.service" in text
    assert "PartOf=wg-quick@wg0.service" in text
    assert "ExecStart=/usr/local/sbin/vpn-policy.sh start" in text
    assert "ExecStop=/usr/local/sbin/vpn-policy.sh stop" in text


def test_policy_script_uses_only_managed_objects():
    text = (ROOT / "deploy" / "vpn-policy.sh").read_text(encoding="utf-8")

    assert 'PBR_IN_IF="ens18.50"' in text
    assert 'PBR_TABLE="123"' in text
    assert 'PBR_MARK="0x1"' in text
    assert "ip route replace default dev" in text
    assert "ip rule add fwmark" in text
    assert "VPN_POLICY_MARK" in text
    assert "VPN_POLICY_NAT" in text
