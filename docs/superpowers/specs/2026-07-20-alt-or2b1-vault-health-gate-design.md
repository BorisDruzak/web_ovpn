# ALT Workstation Provisioning OR-2B1 — unified Vault health gate

Дата: 2026-07-20.

## 1. Контекст

OR-1 добавил общий test harness и формальный каталог operational outcomes.
OR-2A добавил безопасную классификацию SSH/preflight failures и объединён в
`main` через PR #18.

Точка отсчёта OR-2B1:

```text
main: d4be833106c2194b3a20a00069f1ae8297f02eb4
```

Авторитетный контекст этапа:

```text
docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md
```

OR-2B разделён на два независимых блока:

1. **OR-2B1** — единый Vault health gate;
2. **OR-2B2** — stage helper executable checks и controller permission
   outcomes.

Эта спецификация относится только к OR-2B1.

## 2. Текущее поведение и дефект

Команда:

```text
workstationctl --json vault check
```

проверяет:

```text
vault_file_exists
password_file_exists
vault_file_owner
password_file_owner
vault_file_mode
password_file_mode
vault_header
decryptable
variable_present
yescrypt_format
```

При нездоровом состоянии она возвращает:

```text
error.code = vault_unhealthy
exit_code = 7
```

и безопасную boolean-матрицу без password, hash или расшифрованного Vault.

Но `provision preview` и `provision start` используют отдельную
`ProvisionPlanner._validate_vault()`, которая проверяет только:

1. наличие `vault.yml`;
2. наличие `.ansible-vault-pass`;
3. наличие `$ANSIBLE_VAULT;` в первой строке.

Из-за этого preview может успешно пройти, даже когда:

- Vault password неправильный;
- `ansible-vault view` недоступен или завершается по timeout;
- ciphertext повреждён;
- `vault_employee_password_hash` отсутствует;
- hash не является yescrypt `$y$`;
- Vault или password file имеет неправильного владельца;
- режим файла не равен `0600`.

Ошибка обнаруживается позднее, после preview и потенциально после создания job.
Это нарушает fail-before-job boundary эксплуатационной надёжности.

Вторая проблема: текущий owner check сравнивает владельца с `os.geteuid()`.
`vault check` обычно запускается как `altserver`, а `provision start` — как root.
Если переиспользовать этот check без изменения, одинаковые файлы получат разные
результаты в зависимости от вызывающей учётной записи.

## 3. Принятое решение

Создать один внутренний источник истины в `VaultHealthChecker` и использовать
его на всех трёх поверхностях:

```text
vault check
provision preview
provision start
```

Публичные error codes сохраняются:

```text
vault check:
    error.code = vault_unhealthy
    exit_code = 7

provision preview/start:
    error.code = vault_not_configured
    exit_code = 4
```

Во всех случаях `error.details.checks` содержит одну и ту же безопасную
boolean-матрицу.

Owner checks сравнивают metadata не с текущим EUID, а с UID настроенного:

```text
Settings.service_user
```

По умолчанию это `altserver`. Поэтому preview от `altserver` и start от root
оценивают один и тот же controller state одинаково.

## 4. Цели

OR-2B1 должен доказать, что:

1. `vault check`, preview и start используют одну health-модель;
2. отсутствующий Vault блокирует preview/start до создания job;
3. отсутствующий password file блокирует preview/start до создания job;
4. неправильный Vault header блокирует preview/start;
5. недоступный `ansible-vault` блокирует preview/start;
6. timeout расшифровки блокирует preview/start;
7. non-zero decrypt result блокирует preview/start;
8. отсутствие обязательной переменной блокирует preview/start;
9. hash без `$y$` блокирует preview/start;
10. неправильный mode Vault или password file блокирует preview/start;
11. неправильный configured owner блокирует preview/start;
12. здоровый Vault разрешает preview;
13. после исправления Vault повторный preview проходит;
14. неуспешный start не создаёт job или assignment;
15. target не вызывается и не изменяется;
16. password, hash, decrypted text, subprocess stdout и stderr не попадают в
    CLI JSON;
17. существующие публичные error codes и exit codes сохраняются.

## 5. Не входит в OR-2B1

OR-2B1 не должен:

- менять формат Vault или генерировать новый password hash;
- ремонтировать Vault автоматически;
- изменять `.ansible-vault-pass`;
- добавлять Vault rotation;
- проверять executable-bit stage helper;
- менять `ControllerPermissionAuditor.repair()`;
- включать root-owned runtime assets в permission repair;
- менять SSH/preflight classification OR-2A;
- менять Ansible provisioning roles;
- создавать web API или web UI;
- обращаться к controller runtime или эталонной VM;
- выполнять реальное provisioning.

Stage helper и permission outcomes остаются в OR-2B2.

## 6. Архитектура

### 6.1 Единая безопасная оценка

В `deploy/alt-linux/control/alt_deploy/vault.py` выделяется внутренний метод:

```python
def _build_checks(self) -> dict[str, bool]:
    ...
```

Он возвращает ровно существующие ключи:

```text
vault_file_exists
password_file_exists
vault_file_owner
password_file_owner
vault_file_mode
password_file_mode
vault_header
decryptable
variable_present
yescrypt_format
```

Новые секретные или текстовые поля не добавляются.

Публичный `VaultHealthChecker.check()` вызывает `_build_checks()` и сохраняет
существующее поведение:

- если все значения `True`, вернуть `status=ok` и `checks`;
- иначе поднять `ControlError(code="vault_unhealthy", exit_code=7)` с
  `details={"checks": checks}`.

### 6.2 Configured owner вместо current EUID

Текущий helper `_owned_by_current_user()` заменяется логикой, которая:

1. разрешает `settings.service_user` через `pwd.getpwnam()`;
2. сравнивает `path.stat().st_uid` с UID этой учётной записи;
3. возвращает `False`, если service user отсутствует или stat не выполнен.

Метод не зависит от:

```text
os.geteuid()
```

Таким образом root не считается корректным владельцем только потому, что
`provision start` запущен от root.

Публичная матрица не получает отдельный `service_user_exists`: при отсутствии
service user оба owner checks становятся `False`. Это сохраняет существующий
набор ключей и не расширяет API без необходимости.

### 6.3 Dependency-gated decrypt

Расшифровка выполняется только если одновременно истинны структурные checks:

```text
vault_file_exists
password_file_exists
vault_file_owner
password_file_owner
vault_file_mode
password_file_mode
vault_header
```

Это обязательное правило.

Причина: root может прочитать файл `root:root 0600`, который не сможет прочитать
`altserver`. Если root попытается decrypt напрямую, `provision start` может
увидеть `decryptable=true`, тогда как `vault check` от `altserver` увидит
`decryptable=false`.

Dependency-gated decrypt делает результат детерминированным для обеих
поверхностей и не позволяет root обойти owner/mode policy.

Если структурные prerequisites не пройдены:

```text
decryptable = false
variable_present = false
yescrypt_format = false
```

Если decrypt не выполнен успешно, downstream checks также остаются `False`.

### 6.4 Безопасная расшифровка

`_decrypt()` сохраняет текущие ограничения:

```text
shell = false
capture_output = true
timeout = 30
check = false
cwd = ansible_project_dir
```

Следующие случаи дают `decryptable=false`:

- executable отсутствует;
- subprocess не запускается;
- timeout;
- return code не равен нулю.

Ни stdout, ни stderr не включаются в `checks`, `ControlError.details` или CLI
JSON.

Decrypted text существует только внутри процесса достаточно долго, чтобы
извлечь `vault_employee_password_hash`, и никогда не сохраняется на диск.

### 6.5 ProvisionPlanner использует VaultHealthChecker

Существующая дублирующая логика `ProvisionPlanner._validate_vault()` удаляется.
Вместо неё метод вызывает:

```python
VaultHealthChecker(self.settings).check()
```

Если checker поднимает `vault_unhealthy`, planner remap-ит только публичную
оболочку:

```text
code = vault_not_configured
message = Ansible Vault is not configured for workstation provisioning
exit_code = 4
details.checks = та же матрица
```

Другие неожиданные `ControlError` не поглощаются.

### 6.6 Точный контракт compatibility details

Для preview/start поле:

```text
details.checks
```

обязательно для всех Vault health failures.

Если отсутствует Vault или password file, `details` дополнительно содержит:

```text
details.missing = [<отсутствующие пути в стабильном порядке>]
```

Если оба файла существуют, но `vault_header=false`, `details` дополнительно
содержит:

```text
details.path = <vault file path>
```

Для owner, mode, decrypt, variable и yescrypt failures дополнительных полей
нет: `details` содержит только `checks`.

`checks` является авторитетным структурированным contract. Ни `missing`, ни
`path` не содержат secret value.

## 7. Data flow

### 7.1 `vault check`

```text
CLI
  -> VaultHealthChecker.check()
      -> _build_checks()
          -> safe booleans
  -> ok OR vault_unhealthy/7
```

### 7.2 `provision preview`

```text
CLI
  -> ProvisionPlanner.preview()
      -> _preview_unlocked()
          -> assignment/job/preflight validation
          -> _validate_vault()
              -> VaultHealthChecker.check()
              -> remap vault_unhealthy -> vault_not_configured/4
  -> no state mutation
```

### 7.3 `provision start`

```text
CLI root gate
  -> ProvisionPlanner.start()
      -> exclusive lock
      -> _preview_unlocked()
          -> unified Vault health gate
      -> only after success: jobs.create()
```

Следовательно любой Vault failure происходит до:

```text
jobs.create()
stage=launching
chown job files
systemd-run
Ansible target connection
assignment write
```

## 8. Failure matrix

Минимальные failure classes:

| Scenario | Authoritative false check |
|---|---|
| Vault file missing | `vault_file_exists` |
| Password file missing | `password_file_exists` |
| Invalid header | `vault_header` |
| Decrypt executable unavailable | `decryptable` |
| Decrypt timeout | `decryptable` |
| Decrypt non-zero | `decryptable` |
| Required variable missing | `variable_present` |
| Hash is not yescrypt | `yescrypt_format` |
| Vault mode invalid | `vault_file_mode` |
| Password mode invalid | `password_file_mode` |
| Vault owner invalid | `vault_file_owner` |
| Password owner invalid | `password_file_owner` |

Boolean dependencies могут приводить к дополнительным downstream `False`, но
указанный check обязан быть `False` в своём сценарии.

## 9. Operational outcomes

`tests/alt_linux/support/outcomes.py` расширяется восемью provisioning
outcomes:

```text
provision-vault-file-missing
provision-vault-password-file-missing
provision-vault-header-invalid
provision-vault-decrypt-failed
provision-vault-variable-missing
provision-vault-yescrypt-invalid
provision-vault-mode-invalid
provision-vault-owner-invalid
```

Для всех восьми:

```text
boundary: vault_gate
error_code: vault_not_configured
command_exit_code: 4
job_state: null
job_stage: null
assignment_created: false
retryable: true
failure_kind: null
```

Каталог после OR-2B1 содержит девятнадцать scenarios:

```text
5 OR-1
6 OR-2A
8 OR-2B1
```

Отдельные decrypt unavailable/timeout/non-zero tests подтверждают один outcome
`provision-vault-decrypt-failed`. Отдельные Vault/password owner и mode tests
подтверждают общие owner/mode outcomes.

`vault check` surface не получает дублирующие outcomes. Она проверяется теми же
scenario fixtures и обязана вернуть `vault_unhealthy/7` с идентичной матрицей.

## 10. Тестовая стратегия

### 10.1 Checker unit tests

Проверить `_build_checks()`/`check()` для:

- healthy Vault;
- каждого failure class;
- decrypt executable unavailable;
- timeout;
- non-zero return code;
- missing variable;
- invalid yescrypt;
- отсутствующего service user;
- неизменности owner results при смене mocked EUID root/non-root;
- отсутствия decrypt subprocess call при structural failure.

### 10.2 `vault check` CLI tests

Для каждого scenario fixture выполнить:

```text
workstationctl --json vault check
```

Проверить:

- `exit_code=7`;
- `error.code=vault_unhealthy`;
- exact `details.checks`;
- secret fixture values отсутствуют в stdout/stderr;
- decrypted hash отсутствует;
- subprocess stdout/stderr отсутствуют.

### 10.3 Preview gate tests

Для каждого operational outcome выполнить реальный CLI:

```text
workstationctl --json provision preview <uuid> --vars-file <request>
```

Проверить:

- `exit_code=4`;
- `error.code=vault_not_configured`;
- `details.checks` совпадает с `vault check` для того же state;
- `JobRepository.list()` пуст;
- assignment отсутствует;
- registration record не изменён;
- launcher/target boundary не вызван.

### 10.4 Start gate tests

Репрезентативно проверить не менее:

- decrypt failure;
- owner failure;
- mode failure.

Выполнить реальный CLI `provision start` с mocked root EUID. Поскольку failure
возникает внутри `_preview_unlocked()` до `jobs.create()`, не требуются fake
worker account, chown или launcher.

Проверить:

- `exit_code=4`;
- `vault_not_configured`;
- job не создан;
- assignment не создан;
- launcher не вызван.

### 10.5 Root/service-user consistency

Один и тот же filesystem state проверяется дважды с разными mocked EUID:

```text
0
portable non-root uid
```

`checks` должны быть byte-equivalent, потому что owner policy зависит только от
`settings.service_user`.

Owner-conflict tests не выполняют реальный `chown`: они подменяют
`pwd.getpwnam(settings.service_user)` ожидаемым несовпадающим UID. Это сохраняет
тесты переносимыми и не требует root на CI runner.

### 10.6 Retryability

На одной sandbox machine:

1. создать invalid yescrypt state;
2. убедиться, что preview возвращает `vault_not_configured`;
3. заменить fake decrypt output на корректный `$y$` hash;
4. повторить preview;
5. получить `status=ok` без job или assignment.

## 11. Файлы

### Production

Modify:

```text
deploy/alt-linux/control/alt_deploy/vault.py
deploy/alt-linux/control/alt_deploy/provision.py
```

Не изменять:

```text
deploy/alt-linux/control/alt_deploy/worker.py
deploy/alt-linux/control/alt_deploy/ansible.py
deploy/alt-linux/ansible/
```

### Test support

Modify при необходимости:

```text
tests/alt_linux/support/controller_sandbox.py
tests/alt_linux/support/outcomes.py
```

### Tests

Create:

```text
tests/alt_linux/test_or2b1_vault_gate.py
```

Modify:

```text
tests/alt_linux/test_operational_reliability_contract.py
tests/alt_linux/test_vault_check.py
```

Не выполнять unrelated refactoring существующих test modules.

## 12. Безопасность

- Используются только synthetic ciphertext, password и hash fixtures.
- Fixture password не совпадает с production secret.
- Никакой real Vault, Vault pass file или private key не читается.
- Decrypted text не включается в assertion failure messages.
- Проверки сериализованного CLI output запрещают fixture password/hash/value.
- Subprocess stderr/stdout не возвращаются пользователю.
- Тесты не обращаются к controller runtime.
- Эталонная VM не используется.
- Target SSH/Ansible не запускается.
- Repair и изменение permissions не выполняются.

## 13. Error-handling invariants

1. `vault check` сохраняет `vault_unhealthy/7`.
2. preview/start сохраняют `vault_not_configured/4`.
3. Одинаковый state даёт одинаковый `checks` независимо от caller EUID.
4. Structural failure запрещает decrypt attempt.
5. Decrypt failure не раскрывает stdout/stderr.
6. Missing variable не раскрывает другие decrypted variables.
7. Invalid hash не возвращает hash.
8. Failure происходит до создания job.
9. Failure никогда не создаёт assignment.
10. Failure не меняет registration record.
11. После исправления состояния preview retryable.
12. Healthy Vault не меняет существующий deterministic preview response.

## 14. Verification gate

Перед PR выполнить:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2b1_vault_gate.py \
  tests/alt_linux/test_vault_check.py \
  tests/alt_linux/test_operational_reliability_contract.py

.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q

python -m py_compile \
  deploy/alt-linux/control/alt_deploy/vault.py \
  deploy/alt-linux/control/alt_deploy/provision.py

git diff --check origin/main...HEAD
```

Проверки выполняются в CI или изолированном checkout. Нельзя заявлять PASS без
свежего фактического результата.

## 15. Acceptance criteria

OR-2B1 принят, когда:

- существует одна Vault health implementation;
- checker owner policy использует `settings.service_user`;
- root и service-user evaluations совпадают;
- decrypt dependency-gated структурными checks;
- `vault check` сохраняет прежний code/exit;
- preview/start сохраняют прежний code/exit;
- preview/start получают полную safe boolean-матрицу;
- все failure classes блокируются до job creation;
- assignment и target operations отсутствуют;
- healthy Vault разрешает preview;
- retryability доказана;
- outcome catalog содержит 19 scenarios;
- focused, ALT и full suites проходят;
- py_compile и diff check проходят;
- final diff не содержит секретов или временного CI workflow.
