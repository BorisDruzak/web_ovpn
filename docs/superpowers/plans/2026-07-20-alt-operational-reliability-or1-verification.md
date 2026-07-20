# OR-1 verification status

Дата проверки: 2026-07-20.

Проверенный code SHA:

```text
59f2b69df29a3e52a3970c0674db73fee6eb609b
```

GitHub Actions run:

```text
OR-1 branch verification
run_id: 29745447263
job_id: 88362146055
conclusion: success
```

Фактические результаты:

```text
Focused OR-1 tests:
17 passed in 0.32s

ALT Linux suite:
183 passed in 1.21s

Full repository suite:
404 passed, 89 warnings in 26.35s

git diff --check origin/main...HEAD:
PASS
```

Дополнительные штатные repository workflows на том же test-only изменении:

```text
Verify netctl context stage: PASS
Verify netctl context stage / full-regression: PASS
Verify netctl runtime identity / focused-runtime-identity: PASS
Verify netctl runtime identity / full-regression: PASS
```

После получения evidence временный workflow
`.github/workflows/or1-branch-verification.yml` удалён. Последующие изменения
затрагивают только этот временный workflow и данный verification document;
Python test tree, support package и scenario contracts после успешного run не
изменялись.
