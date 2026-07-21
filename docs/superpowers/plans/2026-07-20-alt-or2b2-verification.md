# ALT Workstation Provisioning OR-2B2 Verification

Дата проверки: 2026-07-20.

## Статус

```text
PASS
```

OR-2B2 проверен в GitHub Actions:

```text
workflow: OR-2B2 verification
run_id: 29772956129
branch_source_sha: c2f9dce7ba43f8f4399aa519ddafc803e8d05808
pull_request_merge_ref: 0673d9830148f32cec51643694ae95d3e30debdc
```

`pull_request_merge_ref` включает OR-2B2 branch и актуальное на момент запуска
состояние `main`.

## Результаты

### Focused OR-2B2

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b2_runtime_permissions.py \
  tests/alt_linux/test_controller_permissions.py \
  tests/alt_linux/test_operational_reliability_contract.py
```

```text
37 passed in 0.40s
```

### Полный ALT Linux suite

```bash
python -m pytest -q tests/alt_linux
```

```text
256 passed in 3.97s
```

### Полный repository suite

```bash
python -m pytest -q
```

```text
799 passed, 102 warnings in 55.40s
```

Warnings являются существующими deprecation warnings; OR-2B2 не вводит новый
класс предупреждений.

### Production module compilation

```bash
python -m py_compile \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  deploy/alt-linux/control/alt_deploy/controller_permissions.py
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

## Production scope

Изменён только:

```text
deploy/alt-linux/control/alt_deploy/ansible.py
```

`deploy/alt-linux/control/alt_deploy/controller_permissions.py` не изменялся:
существующая реализация прошла все новые audit/repair tests без ослабления
контрактов.

## Доказанные stage-helper контракты

- отсутствующий helper остаётся `provision_not_configured`, internal exit `7`;
- существующий helper без execute access возвращает тот же code/exit;
- `details.missing` и `details.not_executable` структурно разделены;
- пустые detail keys не публикуются;
- helper не попадает одновременно в missing и not-executable;
- Ansible subprocess не запускается при configuration failure;
- worker возвращает `1` и сохраняет job как `failed/connecting`;
- `finished_at` и безопасный job error записываются;
- result и assignment не создаются;
- registration record не изменяется;
- после `chmod 0755` новое job проходит реальный `AnsibleController` validation
  boundary и может завершиться успешно;
- исходное failed job не переиспользуется и остаётся failed.

## Доказанные permission контракты

- unhealthy audit возвращает `controller_permissions_unhealthy/8` и safe path
  matrix без file contents;
- owner/group mismatch детерминированно отражается в matrix;
- missing path и symlink/type mismatch обнаруживаются безопасно;
- repair без root возвращает `root_required/3` до `fchown`/`fchmod`;
- blocked repair возвращает `controller_permissions_repair_blocked/9` до
  mutation syscalls;
- race между `lstat` и `open` блокируется;
- `fchown`/`fchmod` failure возвращает
  `controller_permissions_repair_failed/10` только с
  `system_error=PermissionError`;
- текст исключения и чувствительный path marker не публикуются;
- все открытые file descriptors закрываются при execution failure;
- успешный repair возвращает exact policy-order `changed` list;
- post-repair audit успешен;
- второй repair идемпотентен и возвращает `changed=[]`;
- pre-existing sentinel job и assignment остаются byte-equivalent после audit и
  repair operations;
- transactional rollback при неожиданном syscall failure не заявляется.

## Operational outcomes

Каталог содержит ровно:

```text
5  OR-1
6  OR-2A
8  OR-2B1
2  OR-2B2 stage helper
5  OR-2B2 permissions
------------------------
26 total outcomes
```

## Безопасность

- Реальный `/usr/local/libexec/alt-job-stage` не читался и не изменялся.
- Production controller state не использовался.
- Reference VM и реальные SSH/Ansible targets не использовались.
- Vault, password files и private keys не читались.
- Все fixtures и result payloads синтетические.
- Root-owned runtime assets не добавлялись в `altserver` permission repair
  policies.
- Временный verification workflow должен быть удалён до Ready for review.
