# ALT Workstation Provisioning OR-2B1 Verification

Дата проверки: 2026-07-20.

## Статус

```text
PASS
```

## Специализированный verification gate

OR-2B1 проверен в GitHub Actions:

```text
workflow: OR-2B1 verification
run_id: 29763573629
branch_source_sha: c567393625cb930e82a5cf1d7f0374f22b941ac3
pull_request_merge_ref: 307c6b52457a6ae4422ce626540021c18947bab9
```

`pull_request_merge_ref` включает OR-2B1 branch и актуальное на момент запуска
состояние `main`.

### Focused OR-2B1

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  tests/alt_linux/test_or2b1_vault_provision_gate.py \
  tests/alt_linux/test_vault_check.py \
  tests/alt_linux/test_operational_reliability_contract.py
```

```text
46 passed in 0.52s
```

### Полный ALT Linux suite

```bash
python -m pytest -q tests/alt_linux
```

```text
237 passed in 1.63s
```

### Полный repository suite

```bash
python -m pytest -q
```

```text
780 passed, 102 warnings in 32.00s
```

Warnings являются существующими deprecation warnings FastAPI, Starlette,
Passlib и Python `crypt`; OR-2B1 не добавил новых warning classes.

### Production module compilation

```bash
python -m py_compile \
  deploy/alt-linux/control/alt_deploy/vault.py \
  deploy/alt-linux/control/alt_deploy/provision.py
```

```text
PASS
```

### Diff integrity

```bash
git diff --check origin/main...HEAD
```

```text
PASS
```

## Финальная проверка с актуальным `main`

После удаления всех временных workflows и patch helpers финальный проверенный
head:

```text
final_branch_head: ecd662b8965d50620c535933ed9da4e9cd3e89c2
final_pull_request_merge_ref: 769b33e80189d68b2122874d76ed4e75206dcff2
```

На нём успешно завершились штатные workflows:

```text
Verify netctl context stage
  run_id: 29764342134
  context-stage: success
  full-regression: success

Verify netctl runtime identity
  run_id: 29764342435
  focused-runtime-identity: success
  full-regression: success
```

Предыдущий финальный full-regression artifact на том же production/test tree:

```text
run_id: 29763898225
exit_code: 0
780 passed, 102 warnings in 33.56s
```

Таким образом изменения проверены не только на исходной базе branch, но и в
merge result с текущим `main`, который к финалу содержал дополнительные
независимые изменения.

## Доказанные контракты

- `vault check` сохраняет `vault_unhealthy`, exit code `7`.
- `provision preview/start` сохраняют `vault_not_configured`, exit code `4`.
- Все поверхности используют одну safe boolean health matrix.
- Владелец проверяется относительно `Settings.service_user`, а не caller EUID.
- Decrypt не запускается при failure existence, owner, mode или Vault header.
- Отсутствующий или неисправный Vault блокирует provisioning до `jobs.create()`.
- Не создаются job или assignment и не вызывается launcher/target boundary.
- Исправление yescrypt позволяет повторный успешный preview.
- Outcome catalog содержит 19 доказанных scenarios.

## Regression investigation

Первый полный запуск выявил восемь старых positive tests, чьи fixtures отражали
прежнюю shallow-проверку: они создавали только Vault header и password file с
mode по умолчанию, но не предоставляли decrypt executable.

Исправление выполнено только в test environment:

- portable fake `ansible-vault` добавлен autouse fixture;
- legacy Vault и password file получают mode `0600`;
- synthetic decrypted mapping содержит только test-only yescrypt placeholder.

Production health policy не ослаблялась и исключения для старых fixtures не
добавлялись.

## Безопасность

- Production Vault, password file и private key не читались.
- Controller runtime и принятая reference VM не использовались.
- В CLI JSON не попадают password, hash, decrypted text, subprocess stdout или
  subprocess stderr.
- Test fixtures содержат только синтетические значения.
- Временные Actions workflows и patch helpers удалены из финального diff.

## Изменения после проверенного source SHA

После `c567393625cb930e82a5cf1d7f0374f22b941ac3` production Python и executable
tests не изменялись. Выполнялись только:

- фиксация verification evidence;
- исправление имени legacy test module в документации;
- удаление временной CI-инфраструктуры.

Финальные штатные workflows на `ecd662b8965d50620c535933ed9da4e9cd3e89c2`
подтвердили отсутствие регрессии после этих изменений.
