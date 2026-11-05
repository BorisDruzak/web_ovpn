# Gateway admission transport and no-admission review

The web client currently gives `plans.apply` 30 seconds although a protected
prejoin compatibility successor performs fresh AD/SSH/package proof before its
native job claim. Request `9ce402a3-e732-44c7-9b17-759e6cec8d43` timed out at
30 seconds; its native receipt is terminal UNKNOWN with
`full_workflow_policy_unavailable`, no native claim/job was admitted. The policy
is independently available. The gateway installs a SIGHUP handler which raises
TimeoutError; nested broad exception handling can obscure the transport cause.

Give apply the existing bounded planning transport budget of 310 seconds,
retaining the gateway's 300-second alarm, caller deadline clamping, strict SSH,
receipt identity, and uncertain-outcome semantics. Do not retry a callback.

Add an operator-only native review for an expired V2 full-setup prejoin
compatibility successor which never acquired admission. Under actual receipt
and lifecycle locks, require a terminal UNKNOWN native receipt, exact protected
intent/plan, expired original plan, a valid sealed compatibility predecessor,
no claim/job/reservation/legacy plan-run for that plan, and fresh positive native
prejoin-local proof. Pending receipts, other operations, admitted plans, unsafe
files, changed bytes, missing proof, or changed target state fail closed.

Review planning expires after 30 minutes; confirmation repeats the proof and
creates an immutable historical no-admission fact. This fact is not execution
permission. It preserves the original UNKNOWN receipt and job, forbids replay
of the old expired plan, and permits the operator to obtain a fresh plan through
the ordinary API after review. No automatic retry or generic recovery is added.

Include gateway receipts and review artifacts in conservative backup history
validation so restoration cannot discard the UNKNOWN or its reviewed fact.
Archives without those optional namespaces remain structurally readable.

Deployment uses exact published code, compatible backup validators first, a
fresh all-closed maintenance scope and backup/verify/rehearse/controller install.
The panel timeout change uses the existing deployment procedure and preserves
database, app secret, credentials, operation history and queued work.
