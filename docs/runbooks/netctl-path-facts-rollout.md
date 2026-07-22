# Netctl path facts rollout and rollback

This feature collects only read-only RouterOS routing, firewall, address-list,
and IPsec policy facts. Path explanations are advisory forward-path results:
they never apply device configuration and do not claim reverse-path validation.

## Pre-deployment checks

Stop collection while taking a SQLite backup. Keep the application and database
release together, because this release adds migration `13` after the path-fact
schema migration `12`.

```bash
set -euo pipefail
sudo systemctl stop netctl-collect.timer netctl-collect.service openvpn-web.service
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/netctl/path-facts-$stamp"
sudo install -d -o netctl -g netctl -m 0700 "$backup_dir"
sudo -u netctl /opt/openvpn-web/.venv/bin/python - /var/lib/netctl/netctl.sqlite "$backup_dir/netctl-before.sqlite" <<'PY'
import sqlite3, sys
from pathlib import Path
source = sqlite3.connect(f"{Path(sys.argv[1]).resolve().as_uri()}?mode=ro", uri=True)
target = sqlite3.connect(sys.argv[2])
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
sudo sha256sum "$backup_dir/netctl-before.sqlite"
```

## Deploy and verify

Deploy the reviewed application release, then run one normal collection. Do
not add write privileges to the RouterOS credentials: `/ip/route`,
`/routing/rule`, `/ip/firewall/*`, and `/ip/ipsec/policy` are collected with
print operations only.

```bash
sudo /usr/local/sbin/netctl --json collect <router-source>
sudo /usr/local/sbin/netctl --json path explain \
  --asset-key 'mac:AA:BB:CC:DD:EE:FF' \
  --destination 198.51.100.25 --protocol tcp --port 443
sudo systemctl start openvpn-web.service
sudo systemctl enable --now netctl-collect.timer
```

Treat `unknown` as the safe result. It is expected when source IP context is
ambiguous, path facts are older than 15 minutes, or a required matcher cannot
be evaluated. A `partial` or `failed` fact-collection run retains the last
successful rows but must not be treated as a verified path result.

## Rollback

Stop the web application and collector first. Restore the application version
that matches the saved database before replacing the database backup, verify
integrity, then restart the normal services.

```bash
sudo systemctl stop netctl-collect.timer netctl-collect.service openvpn-web.service
sudo install -m 0640 -o netctl -g netctl "$backup_dir/netctl-before.sqlite" /var/lib/netctl/netctl.sqlite
sudo -u netctl /opt/openvpn-web/.venv/bin/python - /var/lib/netctl/netctl.sqlite <<'PY'
import sqlite3, sys
from pathlib import Path
conn = sqlite3.connect(f"{Path(sys.argv[1]).resolve().as_uri()}?mode=ro", uri=True)
try:
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
finally:
    conn.close()
PY
sudo systemctl start openvpn-web.service
sudo systemctl enable --now netctl-collect.timer
```
