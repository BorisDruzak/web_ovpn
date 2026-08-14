# Full Yandex Browser profile migration

The controller exports a complete selected user's `~/.config/yandex-browser`
directory from an existing ALT workstation and restores it to an explicitly
selected registered workstation through Ansible.

The collector uses an interactive SSH ControlMaster connection: SSH itself
prompts for the password once, uses strict host-key checking, and the private
control socket is removed on completion. It must never pass, log, or persist a
password. If the source browser is running, it prints the user-owned processes
and waits until they are closed normally; `Ctrl+C` cancels safely. It never
sends a signal to the browser.

Archive creation streams `tar` over SSH to `zstd` on the controller. It retains
all profile data, including cookies and credential databases, and excludes only
the browser runtime entries `SingletonLock`, `SingletonSocket`, and
`SingletonCookie`. The collector writes an opaque UUID migration directory
under `/var/lib/alt-deploy/migrations/yandex`; after checksum verification it
atomically publishes `manifest.json`, `SHA256SUMS`, and `READY`.

The restore launcher lists only directories with `READY` and a valid manifest,
then invokes the fixed restore playbook with one migration ID, one inventory
target and one target user. The restore role verifies checksum, resolves the
target user, requires that their browser is closed, archives any current target
profile under `.config/yandex-browser.pre-migration-<id>`, extracts into a
same-filesystem staging directory, removes `Singleton*`, changes ownership and
atomically replaces the profile. It never deletes the pre-migration backup.

Migration archives contain sensitive user data. They are stored only in the
`altserver:altserver` 0700 migration directory; the operator is responsible for
retention and authorized access. Browser profile versions may only be restored
to the same or a newer installed browser version.
