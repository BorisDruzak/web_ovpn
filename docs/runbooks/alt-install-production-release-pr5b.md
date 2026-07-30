# PR5b managed ISO release on Proxmox

This runbook publishes one immutable managed ALT KWorkstation 11.4 ISO on
Proxmox node `pve2` (`10.83.1.12`).  It consumes an already merged commit and
the controller's public verification key, and targets only
`http://192.168.100.17:18090`.

## Safety boundary

This is a release-publication procedure only.  VM 114 must not be changed,
started, stopped, or attached to an ISO by this runbook; its production
listener acceptance is PR5c.  Do not change an installer target, a disk,
Alterator, `install2.target`, a controller service, or port `18089`.

The controller private key must never be copied to Proxmox, printed,
redirected, archived, or included in evidence.  Only the canonical public-key
JSON is transferred.  Never pass a PEM, credential, session, or plan path to
the release builder.

## Preconditions

Run as root on `pve2`.  Set `REPO` to a clean checkout whose `origin/main`
contains the named, already merged `COMMIT`.  The source ISO is fixed; its
digest is part of the release identity.

```bash
REPO=/srv/web_ovpn
COMMIT=<40-lowercase-hex-commit-already-merged-to-main>
RELEASE_ID="$(date -u +%Y%m%dT%H%M%SZ)-${COMMIT:0:12}"
ISO_DIR=/var/lib/vz/template/iso
SOURCE_ISO="$ISO_DIR/alt-kworkstation-11.4-install-x86_64.iso"
PUBLIC_KEY=/root/alt-install-agent-v1-public-key.json
GO=/opt/go1.22.12/bin/go

git -C "$REPO" fetch origin main
git -C "$REPO" merge-base --is-ancestor "$COMMIT" origin/main
test "$(git -C "$REPO" rev-parse --verify "$COMMIT^{commit}")" = "$COMMIT"
test "$(sha256sum "$SOURCE_ISO" | awk '{print $1}')" = 2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a
```

Fetch `PUBLIC_KEY` through the approved read-only controller operation, then
verify it is a root-owned regular file with mode `0644`.  Its content must be
the public JSON; it must not be a private key or a copied PEM.  Record only
its `key_id` in the release evidence.

## Build and publish

The command stages the named commit in a private `0700` directory under the
same ISO filesystem, builds and verifies the ISO there, and only then
publishes the ISO and sidecar with no-replace moves.  A regenerated canonical
index is atomically replaced after the sidecar is validated.

```bash
cd "$REPO"
bash deploy/alt-linux/release/build-managed-iso-release.sh \
  --source-commit "$COMMIT" \
  --source-iso "$SOURCE_ISO" \
  --public-key "$PUBLIC_KEY" \
  --release-id "$RELEASE_ID" \
  --iso-dir "$ISO_DIR" \
  --go "$GO"
```

The only expected new persistent files are:

- `alt-kworkstation-11.4-agent-v1-$RELEASE_ID.iso`;
- that ISO's `.build-manifest.json` sidecar; and
- `alt-install-agent-v1-releases.json`.

If the command fails, stop.  Do not reuse the same release ID and do not
delete or overwrite any previous ISO.  The private staging directory is
removed by the builder.

## Verification and evidence

```bash
ISO="$ISO_DIR/alt-kworkstation-11.4-agent-v1-$RELEASE_ID.iso"
SIDECAR="$ISO.build-manifest.json"
test -f "$ISO" -a -f "$SIDECAR" -a -f "$ISO_DIR/alt-install-agent-v1-releases.json"
sha256sum "$ISO"
python3 - "$SIDECAR" "$ISO_DIR/alt-install-agent-v1-releases.json" <<'PY'
import json, sys
sidecar = json.load(open(sys.argv[1], encoding="utf-8"))
index = json.load(open(sys.argv[2], encoding="utf-8"))
assert sidecar["controller_url"] == "http://192.168.100.17:18090"
assert index["schema_version"] == 1
assert any(item["managed_iso_sha256"] == sidecar["managed_iso_sha256"] for item in index["releases"])
print(sidecar["public_key_id"])
PY
```

Retain only the commit, release ID, ISO SHA-256, public key ID, sidecar/index
verification output, and command exit statuses.  Do not retain public-key
contents, private material, plans, sessions, credentials, or VM output.
