# OR-1 implementation note

The approved design planned to migrate five representative checks inside the existing large test modules.

During connector-only implementation, GitHub Contents API could not safely patch those files because their complete contents were truncated by the connector. Replacing a partially retrieved test module would risk deleting unrelated tests.

The five contracts are therefore implemented in the self-contained module:

```text
tests/alt_linux/test_operational_reliability_scenarios.py
```

The scenario module:

- imports only production interfaces and `tests/alt_linux/support/`;
- does not import helpers from neighboring test modules;
- covers the same approved outcomes;
- leaves existing regression coverage intact;
- changes no production or Ansible behavior.

A later local-worktree cleanup may replace the duplicated legacy scenario tests after the full suite is available for direct execution. That cleanup is not required for OR-1 correctness and must not be performed without a fresh verification gate.
