# Successor recovery after a verified controller-backup preflight refusal

Status: proposed design; no successor execution is authorized by this document.

## Purpose and scope

Continue the selected test workstation recovery after the native controller
backup refused insufficient free space before any machine-password write.
Keep the failed attempt permanently closed and preserve its original bytes.
The disk-capacity blocker has been corrected separately through native backup
retention. This design does not turn a failed result into success.

This is an additive operator protocol, not a resume operation. It permits at
most one successor for this particular failure class. Postwrite failures,
ambiguous password-write outcomes and later service/import failures remain
ineligible. Existing ordinary recovery paths keep their replay exclusion.

No employee password, groups or identity may change. The same original failed
Setup, computer GUID/SID/OU, registered machine and employee remain mandatory.
Real identifiers and credentials belong only in protected runtime evidence.

## Alternatives

1. Delete or replace the original claim and rerun: rejected. This removes the
   permanent exclusion and invalidates the original evidence chain.
2. Resume the old coordinator at prepare: rejected. Old authority has expired
   and the coordinator intentionally has no replay/resume contract.
3. Create one explicitly scoped successor with independently checked admission:
   selected. It retains the predecessor, has new authority and new receipts,
   and uses the normal fixed pipeline from its beginning.

## Admission before planning a successor

A read-only admission operation must acquire the lifecycle lock and validate
the complete predecessor evidence, not just the last status label:

- Exact protected original plan/run/index/binding/configuration-result bytes.
- Exact predecessor operator envelope and its bound child plans, checked at
  their historical authorization time; this does not extend their TTL.
- Operator intent and ready, closed operator failed marker, closed coordinator
  failed marker with failed_stage=prepare and last_verified_phase=bind.
- Only the bind phase receipt exists. Preparation ready, service preparation,
  quiescence, AD-write intent/result and every subsequent phase are absent.
- Claim, sealed credential verification, preparation intent and controller
  backup intent/failed exist; controller backup receipt is absent.
- The corresponding protected native backup audit records a completed
  backup_preflight_failed create, and no successful controller preparation
  receipt exists. The generic error code is not proof that controller services
  were never stopped: independently require current readiness and native
  guard PASS. Retained capacity diagnostics identify the observed disk
  blocker; admission additionally proves the absence of workstation/AD
  mutation using the specific phase and footprint checks below. Missing,
  contradictory or incomplete evidence refuses admission.
- No recovery child or controller job remains active. Missing process
  termination proof is not equivalent to a failed receipt.
- Fresh exact AD computer/password metadata, machine authentication files,
  tool versions, registry identity and original history match the predecessor.
- Fixed workstation backup/rehearsal and service-side attempt artifacts have
  not been entered by the predecessor. Their absence is checked through a
  bounded read-only worker; no cleanup operation is part of admission.
- Native backup guard, root/command metadata, free-space threshold and current
  quiescence checks pass without creating another backup during planning.

The admission record freezes a bounded inventory of predecessor file names
and SHA-256 values, native audit proof, current identity projection, absence
proof, source fingerprint and the fresh capacity observation. It contains no
plaintext credentials or decrypted sealed payload. It is immutable and safe
to display only through a curated CLI projection.

## Explicit successor identity and storage

The successor has a fresh opaque attempt ID and a predecessor admission hash.
These are bound into the new recovery/startup/terminal/operator envelopes and
verified at every operation boundary. A permanent exclusive-create relation
allows only one successor for the predecessor, independently of plan IDs.

Original attempt paths remain at their existing locations. Successor claims,
intents, receipts and credentials live under a separate protected attempt
namespace. Routing is explicit in internal composition and fixed signed
requests; there is no mutable global pointer, environment override, arbitrary
state-root flag or fallback to another attempt's files.

All components must receive the same validated attempt context, including
planning exclusion, credential preparation, controller backup, password
provider, postwrite checks, service/startup/user/terminal guards and Setup
continuation. Mixed contexts fail before any mutation. The original status
remains directly queryable; the successor status names its predecessor.

The namespace and predecessor relation become effective only through the
dedicated successor protocol. Partial admission persistence fails closed and
cannot authorize execution. Planning retries may regenerate an unentered
successor envelope only under the same immutable successor identity; they
cannot allocate a second successor or revive any consumed intent.

## Operator interface and authority

Add a dedicated prewrite-successor planning command taking the original
failed-run/computer pair and the exact predecessor operator SHA. The CLI
selects all identities and the namespace internally; it does not accept
passwords, commands, arbitrary paths or arbitrary failed stages.

Its output presents the predecessor outcome, the concrete computer identity,
the new operator SHA, all child references, effective earliest expiry and the
single machine-password write allowance. A human must approve this concrete
new reset plan after the implementation is checked and installed. Existing
approval of an expired predecessor does not authorize the successor SHA.

The native apply path then executes the unchanged order: bind, new sealed
credential and controller/workstation backups/rehearsal, service preparation,
quiescence, GUID-only password write, import, Kerberos, temporary policy,
one SSSD start, trust/NSS and verified ordinary-policy handoff. It never opens
the predecessor's sealed password for the new attempt.

Failure after successor intent permanently excludes successor replay. There
is no automatic second successor, second reset, password rollback, restart or
cleanup. Admission/source/predecessor drift stops execution. Normal-policy
effects and any unexpected renewal remain subject to the existing UNKNOWN
boundary. Successful recovery only permits a separate fresh ordinary Setup
plan; it does not prove user GUI/password login or full acceptance.

## Verification required before live execution

1. Regression tests prove legacy attempt exclusion and status remain intact.
2. Real failed-before-write fixtures admit one successor; negative fixtures
   reject every missing/unsafe/changed predecessor record, phase or absence
   proof, expired new authority, unrelated identity, mixed namespace and
   active operation. Concurrent admission and apply preserve exclusivity.
3. Every production component and composed fixed worker is checked for the
   exact successor binding. Hostname joins and arbitrary overrides remain
   unavailable; credential transport remains sealed/bounded.
4. Successor failure leaves both evidence chains unchanged and excludes all
   replay. Tests inject failures before and after each mutation boundary.
5. Existing recovery/Setup suites, relevant full regression and protected
   root fixtures pass. An independent review checks the complete dynamic
   composition, not just indexed call paths.
6. Publish verified code, deploy the exact revision through the guarded
   installer with fresh backup/verify/rehearsal and readiness checks, then
   perform read-only successor admission/planning on the selected workstation.
7. Request confirmation of the resulting concrete live reset SHA. Execute
   only after confirmation; retain UNKNOWN and stop if any phase is unclear.

## Current delivery boundary

Only disk cleanup and read-only investigation are complete. This document is
the proposed protocol and must be reviewed before implementation planning.
There is no successor command, executable successor plan or machine reset yet.
