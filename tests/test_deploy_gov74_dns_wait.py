from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_gov74_dns_wait_script_uses_ipv4_lookup_and_bounded_logging():
    text = (ROOT / "deploy" / "gov74-wait-dns.sh").read_text(encoding="utf-8")

    assert text.startswith("#!/usr/bin/env bash\n")
    assert 'HOST="vpn-ra.gov74.ru"' in text
    assert 'getent ahostsv4 "$HOST" >/dev/null 2>&1' in text
    assert "sleep 30" in text
    assert '"$attempt" -eq 1' in text
    assert "attempt % 10" in text


def test_gov74_dns_wait_drop_in_runs_before_openconnect_without_start_timeout():
    text = (ROOT / "deploy" / "gov74-anyconnect-dns-wait.conf").read_text(
        encoding="utf-8"
    )

    assert text == (
        "[Service]\n"
        "ExecStartPre=/usr/local/sbin/gov74-wait-dns\n"
        "TimeoutStartSec=infinity\n"
    )


def test_installer_deploys_gov74_dns_wait_assets_without_restarting_tunnels():
    text = (ROOT / "deploy" / "install-openvpn-web.sh").read_text(encoding="utf-8")

    assert 'install -m 0755 "$SRC/deploy/gov74-wait-dns.sh" /usr/local/sbin/gov74-wait-dns' in text
    assert (
        'install -m 0644 "$SRC/deploy/gov74-anyconnect-dns-wait.conf" '
        '/etc/systemd/system/gov74-anyconnect.service.d/dns-wait.conf'
    ) in text
    assert "restart gov74-anyconnect.service" not in text
