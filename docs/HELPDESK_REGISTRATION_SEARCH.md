# Helpdesk registration suggestions

The service-authenticated endpoint
`GET /api/internal/helpdesk/v1/inventory/people/registration-search?q=...`
accepts employee-name prefixes starting with one letter. It searches directory
people and names entered on unassigned, non-deleted, non-written-off PC cards.

The response contains up to five matches sorted by normalized name and
department. `refine: true` means more results exist; clients should still show
the returned matches and offer refinement. Multiple matches are not an empty
result. Each match includes `full_name`, `department` and `has_agent`.
Directory matches additionally include the private `inventory_person_id` for
the authenticated Helpdesk consumer. Card-only matches have no employee ID.
Only a current confirmed employee assignment and Endpoint binding can set
`has_agent: true`.

Helpdesk checks its own account database and marks already registered employees
as disabled suggestions. It must exclude private inventory IDs from its
anonymous registration response. Search and autofill do not approve an
employee/account link or grant access to a device.

Focused regression check: `python -m pytest -q tests/test_inventory_people.py`.
