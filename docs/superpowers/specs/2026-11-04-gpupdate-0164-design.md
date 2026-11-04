# gpupdate 0.16.4 support

The full workstation workflow upgrades p11 before domain join. The published
gpupdate/gpoa-lib 0.16.4-alt1 packages currently fail the exact 0.16.1 compatibility
gate. Support both inspected package pairs while preserving fail-closed ownership,
permission, content, package-version, busy-client and rollback checks.

Use version-specific recipes. On 0.16.4 the service XML setter still needs the
existing exact patch; KDE detection and shortcut restoration are vendor-fixed and
must remain byte-for-byte unchanged. Validate the shortcut model as well as its
frontend because `from_machine_dict` now owns restoration. Mixed package versions,
unknown versions and modified native modules remain rejected before any write.
New backup manifests bind each changed module to its package/version; old backups
retain their 0.16.1 interpretation and cannot authorize rollback after upgrade.

Alternatives considered: reapplying all 0.16.1 patches would overwrite upstream
changes; allowing arbitrary versions would discard the safety contract. Exact
version-specific recipes are the selected implementation approach.

The user authorized support and continuation on the one designated workstation.
Preserve its original UNKNOWN, claims, reservations and events. Source deployment
and any successor must pass native guarded maintenance/recovery with positive
fresh identity, AD absence/ownership and process/package evidence. Do not replay
the original job or mutate historical JSON to obtain admission. An unsupported
continuation requires a separately tested native contract, not a manual bypass.

The inspected structured failure precedes domain join and is outside the old
timeout-only continuation. Add one bounded `prejoin_local` contract: recognize
the exact compatibility assertion and its result-only rescue suffix in the
complete V2 journal, require an initial plan and failed structured network result,
and seal result/log/event bytes in the existing `prejoin_retry` proof. Archival
validation uses retained snapshots and remains valid after assignment advances.

The shared classifier lives in the trusted backup/maintenance module and is
accessed through the existing root-owned origin-checked bridge. All-closed
schema-2 controller maintenance may cover this mode only after fresh strict SSH,
native local PAM/services, administrator, clock, complete directory collision,
credential/process absence and package checks. The same fixed observer runs
again at successor planning, submission and worker preflight before mutation.
Old timeout/join/partial-AD gates keep their prior behavior. Mixed coverage with
post-login workflow failures remains unsupported and fails closed.
