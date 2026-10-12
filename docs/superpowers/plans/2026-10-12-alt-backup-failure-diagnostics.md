# Approved bounded backup failure diagnostics

Human approved local implementation, synthetic checks and publication. Deployment,
native controller backup reproduction, replay and another recovery attempt remain
outside this authorization. Historical RCA stays UNKNOWN.

1. RED/GREEN strict optional component/reason/return-code/signal diagnostics,
   bounded native archive stderr/deadline and source/publication/hash failures.
   Preserve existing error code/message/exit code and successful backup behavior.
2. RED/GREEN append-only safe audit propagation and separate immutable recovery
   failure artifact. No raw stderr, command, path or secret value is exported.
   Preserve previous attempt files, exclusion and legacy closed-prefix contracts.
3. Independent review, focused/full synthetic regressions, compilation and diff
   checks; publish verified commits to main. No installed source changes.
