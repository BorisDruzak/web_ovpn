# Inventory form drafts

Every bare create/edit page starts a separate server process and redirects to a
URL containing `draft_id`. Reopening that URL resumes the same process. Opening
the bare URL in another tab creates an independent process, even for the same
card, location and type. The database holds fields, discovery results, owner and
original manual revision; signed cookies carry no card or lookup payloads.

The additive `inventory_form_drafts` table is created by the existing schema
initialization. Existing card IDs, facts and history are unchanged. Legacy form
POSTs without `draft_id` return 428: reopen the form. Foreign owners receive 404;
expired processes receive 410; a process cannot be reused for another purpose.

Drafts expire 48 hours after creation, without extending the deadline on autosave.
Starting a process removes at most 100 expired rows. For regular maintenance,
run `python -m app.inventory.form_drafts` against the configured existing database
hourly; each invocation removes at most 100 expired drafts. Large backlogs need
additional bounded passes. This command does not initialize schemas, bootstrap
users, delete cards or issue network commands. The production maintenance schedule
has not been installed by this local implementation.

Autosave debounces input for 1.5 seconds, starts no more often than every 5 seconds,
and permits one request at a time with a 10-second deadline. Fields are limited to
2 MiB and a known string-field allowlist. CSRF and ownership are required. A
conditional draft revision update prevents an old copy from overwriting a newer
one. A conflict or lost response stops autosave and keeps visible local input;
there is no blind retry with a newly fetched revision.

Reload restores acknowledged fields. Leaving with unsaved card changes prompts
the browser, including after draft restoration. Explicit discard ends the process.
Card save consumes it in the same transaction as card/details/identifiers/audit;
rollback retains input and the original manual revision. Concurrent submissions
of the same create process can create only one card. Related peripheral creation
also checks the parent revision captured when its process began. File uploads are
not retained in drafts and the form explains that they must be selected again.

Verification uses only synthetic loopback fixtures. Python lifecycle tests cover
independent forms, owner/expiry/CSRF, bounded cleanup, CAS, rollback and duplicate
submission. Node controlled timers cover request serialization, rate limits,
timeouts, conflicts and leave warnings. Browser scripts are
`tests/browser/inventory_form_drafts.js` and
`tests/browser/inventory_revision_conflict.js`. They verify two actual tabs,
long-text reload, bounded cookie, discard, restored Endpoint lock and repeated
stale card rejection. No production database was used.
