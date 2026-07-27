# ALT install-session PR3 design

PR3 adds a controller-local authorization boundary for a future ALT installer.
An agent may create one validated install session and read only that session with
its one-time Bearer credential. The stored credential is a SHA-256 digest.

An operator previews the re-evaluated target. Root approval binds the canonical
inventory hash and disk fingerprint, creates revision 1 of `InstallPlanV1`, and
signs the exact canonical plan bytes with Ed25519. `status.json` becomes
`plan_published` only after the private revision and approval records exist.
Partial publication is removed before retry, so a failed approval remains
retryable. The design deliberately excludes agent changes, renderer secrets,
installer launch, disk writes, and a production HTTP service.
