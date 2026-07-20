# ALT Workstation Provisioning OR-2B2 — runtime helper and controller permission outcomes

Дата: 2026-07-20.

## 1. Контекст

OR-1 добавил test harness и формальный каталог operational outcomes.

OR-2A добавил классификацию SSH/preflight failures.

OR-2B1 объединил Vault health gate для:

```text
vault check
provision preview
provision start
```

и был объединён в `main` через PR #19.

Точка отсчёта OR-2B2:

```text
main: d9d2a3abeb5aeed8dad6dc525e0e7f51f858ff7a
```

OR-2B2 закрывает оставшиеся controller-side failure boundaries этапа OR-2:

1. существующий, но неисполняемый `alt-job-stage`;
2. формальные operational outcomes для controller permission audit и repair.

## 2. Текущее поведение

### 2.1 Stage helper

`AnsibleController._validate_provision_files()` проверяет следующие assets:

```text
ansible_playbook
private_key
known_hosts
provision_playbook
request_file
job_stage_helper
```

Проверка выполняется только через:

```python
path.is_file()
```

Поэтому файл:

```text
/usr/local/libexec/alt-job-stage
```

с mode `0644` проходит controller validation.

Позднее Ansible пытается выполнить helper через delegated localhost task до
выполнения `workstation_identity` role. Отказ происходит как generic Ansible
failure вместо раннего controller configuration failure.

Штатный installer уже определяет правильный runtime contract:

```text
owner: root
 group: root
  mode: 0755
```

### 2.2 Job state при worker-side configuration failure

Перед `controller.run_provision()` worker переводит job:

```text
queued/created
    -> running/validating
    -> running/connecting
```

Если `run_provision()` поднимает `ControlError`, worker:

```text
state       = failed
stage       = connecting
finished_at = utc_now()
error       = "<error code>: <message>"
return code = 1
```

Assignment не создаётся, result не записывается, target roles не выполняются.

### 2.3 Controller permissions

`ControllerPermissionAuditor` контролирует только private state сервисной
учётной записи:

```text
state_root
jobs_dir
assignments_dir
registration_root
ssh_dir
vault_file
vault_password_file
```

Все эти policies используют:

```text
Settings.service_user
Settings.service_group
```

Штатно это `altserver:altserver`.

Repair:

- требует root;
- запрещает symlink и неправильный тип;
- блокируется до мутаций при missing/unsafe path;
- повторно открывает каждый объект через `O_NOFOLLOW`;
- выполняет `fchown`/`fchmod` только на открытых descriptors;
- после изменений повторяет audit;
- при неожиданном `OSError` возвращает только имя класса системной ошибки.

## 3. Принятое решение

Использовать подход A:

1. добавить отдельную executable-проверку только для `job_stage_helper` в
   `AnsibleController._validate_provision_files()`;
2. не добавлять root-owned runtime assets в `ControllerPermissionAuditor`;
3. не менять permission repair production logic без RED-теста, доказывающего
   конкретный дефект;
4. формализовать два stage-helper outcomes и пять permission outcomes;
5. расширить общий каталог с 19 до 26 сценариев.

## 4. Почему runtime helper не включается в permission repair

`workstationctl`, `alt-provision-worker` и `alt-job-stage` устанавливаются как:

```text
root:root 0755
```

Текущий `PathPolicy` не содержит индивидуальных expected UID/GID. Auditor
вычисляет один общий UID/GID `service_user/service_group` для всех policies.

Добавление root-owned helper в текущий policy set без архитектурной переработки
может привести к ошибочному:

```text
chown altserver:altserver /usr/local/libexec/alt-job-stage
```

OR-2B2 запрещает такое расширение.

Будущая отдельная `controller runtime check` может быть спроектирована, когда
появится несколько root-owned runtime assets и будет оправдан отдельный policy
contract. В OR-2B2 это YAGNI.

## 5. Цели

OR-2B2 должен доказать, что:

1. отсутствующий stage helper продолжает давать `provision_not_configured`;
2. существующий, но неисполняемый helper также даёт
   `provision_not_configured`;
3. missing и not-executable причины различаются структурированно;
4. non-executable helper обнаруживается до запуска Ansible subprocess;
5. target roles не выполняются;
6. failed job сохраняет последнюю реальную stage `connecting`;
7. assignment и result отсутствуют;
8. после исправления helper можно создать новое job и повторить provisioning;
9. permission audit unhealthy возвращает существующий code/exit;
10. repair без root не изменяет filesystem;
11. blocked repair не выполняет частичные изменения;
12. execution failure возвращает safe system error class;
13. successful repair изменяет только известные paths и проходит повторный audit;
14. permission operations не изменяют jobs или assignments;
15. operational outcome catalog содержит ровно 26 сценариев.

## 6. Не входит в OR-2B2

OR-2B2 не должен:

- менять owner/group stage helper;
- автоматически ремонтировать stage helper;
- проверять содержимое или hash executable;
- вводить отдельную symlink-integrity policy для root-owned helper;
- менять существующую `is_file()` file-type семантику helper;
- добавлять root-owned files в `ControllerPermissionAuditor`;
- менять `PathPolicy` expected UID/GID model;
- менять installer modes;
- менять systemd units;
- менять Vault health gate OR-2B1;
- менять SSH/preflight classification OR-2A;
- менять Ansible roles или порядок provision stages;
- выполнять реальное provisioning;
- обращаться к controller runtime или reference VM;
- создавать web API или web UI.

## 7. Stage helper architecture

### 7.1 Existing required-file validation

Существующая карта required files сохраняется:

```python
required_files = {
    "ansible_playbook": settings.ansible_playbook_path,
    "private_key": settings.private_key_file,
    "known_hosts": settings.known_hosts_file,
    "provision_playbook": self.provision_playbook,
    "request_file": job.job_dir / "request.json",
    "job_stage_helper": settings.job_stage_helper_path,
}
```

Missing assets продолжают формироваться только для paths, где:

```python
not path.is_file()
```

### 7.2 Executable validation

После missing evaluation вычисляется отдельный список только для helper:

```python
not_executable = []
helper = self.settings.job_stage_helper_path

if helper.is_file() and not os.access(helper, os.X_OK):
    not_executable.append(
        {
            "name": "job_stage_helper",
            "path": str(helper),
        }
    )
```

Helper не должен одновременно попадать в `missing` и `not_executable`.

Проверка использует:

```python
os.access(path, os.X_OK)
```

потому что worker должен доказать фактическую возможность исполнения от своей
учётной записи, а не только наличие любого executable bit в metadata.

### 7.3 Error envelope

Если `missing` или `not_executable` не пусты, сохраняется существующая ошибка:

```text
code      = provision_not_configured
message   = ALT workstation provisioning is not fully configured
exit_code = 7
```

`details` формируется только из непустых lists:

```json
{
  "missing": [
    {
      "name": "job_stage_helper",
      "path": "/usr/local/libexec/alt-job-stage"
    }
  ]
}
```

или:

```json
{
  "not_executable": [
    {
      "name": "job_stage_helper",
      "path": "/usr/local/libexec/alt-job-stage"
    }
  ]
}
```

При смешанном failure допускаются оба ключа.

Пустые keys не включаются.

### 7.4 Security properties

Диагностика содержит только:

```text
asset logical name
filesystem path
```

Она не содержит file content, owner names, environment, private key или
subprocess output.

### 7.5 Worker boundary

`run_job()` уже переводит job в `connecting` до вызова `run_provision()`.

OR-2B2 не меняет этот порядок.

Stage-helper configuration failure приводит к:

```text
worker return code = 1
job.state           = failed
job.stage           = connecting
job.error           = provision_not_configured: ...
assignment          = absent
result.json         = absent
```

Внутренний `ControlError.exit_code=7` не является process return code worker.
Это различие фиксируется явно в tests и outcomes.

### 7.6 Retryability

Failed job не переиспользуется.

После исправления helper:

1. старое job остаётся `failed`;
2. active job отсутствует;
3. оператор повторяет `provision start`;
4. создаётся новое job ID;
5. новое job может завершиться успешно.

Retryability не означает автоматический rerun старого job.

## 8. Controller permission architecture

### 8.1 Production behavior

Текущие public contracts сохраняются без изменений:

```text
controller permissions:
    controller_permissions_unhealthy / 8

controller permissions repair without root:
    root_required / 3

repair blocked:
    controller_permissions_repair_blocked / 9

repair execution failure:
    controller_permissions_repair_failed / 10

successful repair:
    status=ok / 0
```

### 8.2 Audit outcome

Unhealthy audit возвращает safe matrix:

```json
{
  "paths": {
    "state_root": {
      "exists": true,
      "owner_ok": true,
      "group_ok": true,
      "mode_ok": false,
      "type_ok": true
    }
  }
}
```

Никакие file contents не возвращаются.

### 8.3 Root-required repair

При EUID != 0 repair завершается до:

```text
principal lookup
path validation
open
fchown
fchmod
```

Filesystem должен остаться byte/metadata-equivalent относительно контролируемых
mode/owner assertions.

### 8.4 Blocked repair

При missing path, symlink, неправильном type или race failure между lstat/open:

```text
controller_permissions_repair_blocked / 9
```

Repair должен завершиться до `fchown`/`fchmod` любого объекта.

Тест обязан использовать spies, доказывающие отсутствие mutation syscalls, а не
только сравнение одного path после ошибки.

### 8.5 Execution failure

Если после безопасного открытия `fchown` или `fchmod` поднимает `OSError`,
возвращается:

```json
{
  "error": {
    "code": "controller_permissions_repair_failed",
    "details": {
      "system_error": "PermissionError"
    }
  }
}
```

Разрешено только:

```text
exc.__class__.__name__
```

Запрещены:

```text
str(exc)
errno text
path contents
secret values
```

Execution failure может произойти после частичного изменения ранее обработанных
paths. OR-2B2 не заявляет transactional rollback для unexpected syscall failure.
Это существующее ограничение должно быть явно отражено в outcome evidence.

### 8.6 Successful repair

Successful repair:

- изменяет только paths с неправильным owner/group/mode;
- возвращает deterministic `changed` list в policy order;
- повторный audit возвращает `status=ok`;
- второй repair идемпотентен и возвращает `changed=[]`.

### 8.7 Jobs and assignments isolation

Permission check/repair не должны:

- создавать job;
- менять существующий job JSON;
- создавать или менять assignment;
- запускать launcher;
- запускать Ansible.

Тестовая среда должна заранее создать sentinel job и sentinel assignment,
сохранить их JSON bytes и после каждой permission operation доказать полное
равенство содержимого. Проверка только пустых каталогов недостаточна.

## 9. Operational outcomes

### 9.1 Stage helper outcomes

Добавляются:

```text
provision-stage-helper-missing
provision-stage-helper-not-executable
```

Общий contract:

```text
boundary           = worker_configuration
error_code         = provision_not_configured
command_exit_code  = 1
job_state          = failed
job_stage          = connecting
assignment_created = false
retryable          = true
failure_kind       = null
```

Обязательные evidence:

```text
structured_configuration_detail
worker_exit_one
failed_job_finished_at
connecting_stage_preserved
ansible_subprocess_not_called
no_result_created
no_assignment_created
new_job_retry_after_fix
```

### 9.2 Permission outcomes

Добавляются:

```text
controller-permissions-unhealthy
controller-permissions-repair-root-required
controller-permissions-repair-blocked
controller-permissions-repair-failed
controller-permissions-repaired
```

#### `controller-permissions-unhealthy`

```text
boundary           = permission_audit
error_code         = controller_permissions_unhealthy
command_exit_code  = 8
job_state          = null
job_stage          = null
assignment_created = false
retryable          = true
```

#### `controller-permissions-repair-root-required`

```text
boundary           = permission_repair_authorization
error_code         = root_required
command_exit_code  = 3
job_state          = null
job_stage          = null
assignment_created = false
retryable          = true
```

#### `controller-permissions-repair-blocked`

```text
boundary           = permission_repair_safety
error_code         = controller_permissions_repair_blocked
command_exit_code  = 9
job_state          = null
job_stage          = null
assignment_created = false
retryable          = true
```

#### `controller-permissions-repair-failed`

```text
boundary           = permission_repair_execution
error_code         = controller_permissions_repair_failed
command_exit_code  = 10
job_state          = null
job_stage          = null
assignment_created = false
retryable          = true
```

Required evidence обязано указывать:

```text
partial_mutation_possible
safe_system_error_class_only
file_descriptors_closed
```

Outcome не заявляет rollback.

#### `controller-permissions-repaired`

```text
boundary           = permission_repair
error_code         = null
command_exit_code  = 0
job_state          = null
job_stage          = null
assignment_created = false
retryable          = null
```

Required evidence:

```text
changed_paths_exact
post_repair_audit_ok
second_repair_idempotent
jobs_unchanged
assignments_unchanged
```

### 9.3 Catalog size

После OR-2B2:

```text
5  OR-1
6  OR-2A
8  OR-2B1
2  OR-2B2 stage helper
5  OR-2B2 permissions
------------------------
26 total outcomes
```

## 10. Test strategy

### 10.1 Stage-helper unit boundary

Новый focused module должен проверить `_validate_provision_files()` напрямую:

- helper missing -> `details.missing`;
- helper regular non-executable -> `details.not_executable`;
- helper executable -> validation passes;
- missing helper не дублируется в `not_executable`;
- empty detail keys отсутствуют;
- unrelated required-file missing сохраняет текущий behavior.

### 10.2 Worker integration

Через реальный `worker.run_job()`, реальный `AnsibleController` и sandbox
repositories проверить:

- job переходит `created -> validating -> connecting -> failed`;
- process return code равен `1`;
- error code сохраняется в job.error;
- `finished_at` заполнен;
- `subprocess.run` не вызывается после validation failure;
- result и assignment отсутствуют;
- machine registration не изменяется.

### 10.3 Retry after helper fix

На одном sandbox state:

1. создать первое job с helper `0644`;
2. выполнить worker через реальный `AnsibleController` и получить
   failed/connecting;
3. исправить helper на executable;
4. создать второе job;
5. снова использовать реальный `AnsibleController`;
6. подменить только `subprocess.run` контролируемым fake, который:
   - подтверждает, что helper уже executable;
   - записывает synthetic `provision-result.json` по path из command args;
   - возвращает `returncode=0`;
7. второе job становится successful/complete;
8. assignment ссылается на второе job;
9. первое job остаётся failed.

Тест не может использовать fake controller, который обходит
`_validate_provision_files()`.

### 10.4 Permission audit tests

Проверить:

- healthy private state;
- wrong mode;
- wrong owner/group через controlled metadata mocks;
- missing path;
- symlink/type mismatch;
- exact safe path matrix;
- secret fixture values отсутствуют в JSON;
- sentinel job и assignment остаются byte-equivalent.

### 10.5 Permission repair tests

Проверить:

- root required до mutation syscalls;
- blocked missing/symlink до mutation syscalls;
- race между lstat и open;
- `fchown` failure -> safe execution error;
- `fchmod` failure -> safe execution error;
- descriptors закрываются при failure;
- successful repair exact changed list;
- post-repair audit healthy;
- second repair `changed=[]`;
- sentinel jobs/assignments byte-equivalent.

### 10.6 Outcome contract

`tests/alt_linux/test_operational_reliability_contract.py` должен:

- содержать exact set из 26 IDs;
- разрешить новые boundaries;
- проверить точные code/exit/state/stage/retryability contracts;
- сохранить запрет secret-bearing metadata;
- сохранить fail-closed `get_outcome()`.

## 11. File map

### Production

Modify:

```text
deploy/alt-linux/control/alt_deploy/ansible.py
```

Conditional modify только при доказанном RED-дефекте:

```text
deploy/alt-linux/control/alt_deploy/controller_permissions.py
```

Не изменять:

```text
deploy/alt-linux/control/alt_deploy/provision.py
deploy/alt-linux/control/alt_deploy/vault.py
deploy/alt-linux/control/alt_deploy/worker.py
deploy/alt-linux/ansible/
deploy/alt-linux/install-control-plane.sh
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
tests/alt_linux/test_or2b2_runtime_permissions.py
```

Modify:

```text
tests/alt_linux/test_operational_reliability_contract.py
tests/alt_linux/test_controller_permissions.py
```

Не выполнять unrelated test refactoring.

## 12. Error handling invariants

1. Missing helper остаётся `provision_not_configured`.
2. Non-executable helper также `provision_not_configured`.
3. Missing и not-executable не смешиваются для одного path.
4. Worker failure сохраняет stage `connecting`.
5. Worker process return code равен `1`.
6. Assignment и result отсутствуют при stage-helper failure.
7. Permission public codes/exits не меняются.
8. Root-required и blocked repair не выполняют mutation syscalls.
9. Unexpected repair failure раскрывает только system error class.
10. Execution failure не обещает rollback.
11. Successful repair идемпотентен.
12. Permission operations не изменяют sentinel jobs/assignments.
13. Runtime root-owned assets не включаются в altserver repair policies.
14. Retry test проходит через реальную `_validate_provision_files()` boundary.

## 13. Security

- Используются только sandbox paths под `tmp_path`.
- Реальный `/usr/local/libexec/alt-job-stage` не читается и не изменяется.
- Production controller state не читается.
- Reference VM не используется.
- Ansible target connection не выполняется.
- Private keys и Vault secrets не используются.
- Diagnostic assertions запрещают file content и secret-bearing values.
- Symlink tests работают только внутри sandbox.
- Mutation failure tests используют monkeypatch/spies.

## 14. Verification gate

Перед Ready for review выполнить:

```bash
python -m pytest -q \
  tests/alt_linux/test_or2b2_runtime_permissions.py \
  tests/alt_linux/test_controller_permissions.py \
  tests/alt_linux/test_operational_reliability_contract.py

python -m pytest -q tests/alt_linux
python -m pytest -q

python -m py_compile \
  deploy/alt-linux/control/alt_deploy/ansible.py \
  deploy/alt-linux/control/alt_deploy/controller_permissions.py

git diff --check origin/main...HEAD
```

Если `controller_permissions.py` не изменён, он всё равно включается в compile
check как проверяемая production boundary.

Temporary CI workflows и patch helpers должны быть удалены до Ready for review.

## 15. Acceptance criteria

OR-2B2 принят, когда:

- non-executable helper обнаруживается до subprocess;
- details разделяют missing и not-executable;
- public `provision_not_configured/7` сохраняется;
- worker outcome `failed/connecting`, process exit `1` доказан;
- новое job после исправления helper может завершиться успешно через реальную
  validation boundary;
- пять permission outcomes доказаны executable tests;
- blocked/root-required repair не выполняют mutation syscalls;
- repair failure безопасно сообщает только класс системной ошибки;
- successful repair идемпотентен;
- permission operations изолированы от sentinel jobs/assignments;
- outcome catalog содержит ровно 26 сценариев;
- focused, ALT и full suites проходят;
- compile и diff checks проходят;
- final diff не содержит временной CI-инфраструктуры или секретов.
