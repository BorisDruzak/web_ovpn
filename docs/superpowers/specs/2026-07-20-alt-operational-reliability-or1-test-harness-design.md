# ALT Workstation Provisioning OR-1 — test harness и outcome contracts

Дата: 2026-07-20.

## 1. Контекст

Базовый ALT Workstation Provisioning объединён в `main`. Следующий этап —
эксплуатационная надёжность текущего CLI и базового provisioning-контура.
Авторитетная точка входа:

```text
docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md
```

OR-1 подготавливает общую тестовую инфраструктуру и формализует уже доказанные
operational outcomes. Изменение production behavior в этот PR не входит.

## 2. Проблема

Существующая тестовая база проверяет jobs, assignments, recovery, Vault и
provisioning, но общие helpers распределены между test modules:

- `make_settings()` и `write_machine()` находятся в `test_registry_cli.py`;
- `provision_request()` и `assignment_payload()` находятся в `test_jobs.py`;
- recovery tests импортируют helpers из нескольких других test modules;
- preview/start tests используют окружение из соседнего test module.

Тестовые файлы одновременно являются тестами и неявной библиотекой fixtures.
Это затруднит расширение failure-injection матрицы и не даёт единого контракта
между сценарием и ожидаемыми:

- `error_code`;
- command exit code;
- job `state`;
- job `stage`;
- созданием assignment;
- retryability;
- обязательным evidence.

## 3. Цель

Создать test-only foundation для OR-2 — OR-5:

1. единый isolated controller sandbox;
2. общие безопасные payload factories;
3. единый CLI JSON runner;
4. immutable operational outcome model;
5. каталог только уже доказанных outcomes;
6. контрактные тесты каталога;
7. перевод пяти репрезентативных сценариев на новый harness.

## 4. Не входит в OR-1

OR-1 не должен:

- изменять `deploy/alt-linux/control/`;
- изменять Ansible roles или playbooks;
- добавлять browser, Nextcloud, принтеры или дополнительные profiles;
- выполнять реальные SSH-подключения;
- запускать реальные systemd units;
- читать активный Vault;
- выполнять provisioning;
- обращаться к эталонной VM `192.168.101.111`;
- добавлять универсальный YAML/JSON scenario engine;
- массово переписывать существующий test suite.

## 5. Структура

```text
tests/alt_linux/support/
├── __init__.py
├── controller_sandbox.py
├── payloads.py
├── cli.py
└── outcomes.py

tests/alt_linux/
└── test_operational_reliability_contract.py
```

Небольшие helpers остаются в конкретном test module, если они нигде больше не
используются.

## 6. Компоненты

### 6.1 `controller_sandbox.py`

Отвечает только за файлово изолированный controller boundary.

```python
@dataclass(frozen=True)
class ControllerSandbox:
    settings: Settings
    root: Path


def make_controller_sandbox(tmp_path: Path) -> ControllerSandbox:
    ...
```

Sandbox должен:

- создавать `Settings` только под `tmp_path`;
- изолировать registration, state, jobs, assignments и lock;
- использовать fake executable paths для Ansible, worker и stage helper;
- не использовать `/srv`, `/var/lib`, `/home/altserver` или `/usr/local`;
- создавать только минимальные файлы, необходимые конкретному тесту;
- предоставлять helper регистрации машины в заданном состоянии;
- не подменять production behavior без явного действия теста.

Допустимые helpers:

```python
sandbox.register_machine(...)
sandbox.install_fake_stage_helper(...)
sandbox.install_fake_ansible_playbook(...)
sandbox.configure_fake_vault(...)
```

Helper не должен скрыто подготавливать unrelated controller state.

### 6.2 `payloads.py`

Содержит безопасные фабрики:

```python
machine_registration_payload(...)
provision_request(...)
assignment_payload(...)
successful_provision_result(...)
```

Требования:

- значения детерминированы;
- UUID, hostname, login и timestamps очевидно тестовые;
- нет реальных паролей, hashes, Vault values или SSH keys;
- каждая фабрика возвращает новый mapping;
- override-параметры явные и типизированные.

### 6.3 `cli.py`

Предоставляет единый запуск CLI entrypoint:

```python
@dataclass(frozen=True)
class CliResult:
    exit_code: int
    stdout: str
    stderr: str
    payload: dict[str, object]


def run_json_cli(
    args: Sequence[str],
    *,
    settings: Settings,
) -> CliResult:
    ...
```

Контракт:

- helper автоматически добавляет `--json`;
- stdout обязан содержать один валидный JSON document;
- invalid JSON вызывает assertion failure с stdout и stderr;
- helper не интерпретирует domain outcome;
- helper не скрывает exit code;
- helper не нормализует error codes и не изменяет payload.

### 6.4 `outcomes.py`

Определяет единую immutable-модель для failure и recovery outcomes:

```python
@dataclass(frozen=True)
class OperationalOutcome:
    scenario_id: str
    boundary: str
    error_code: str | None
    command_exit_code: int
    job_state: str | None
    job_stage: str | None
    assignment_created: bool
    retryable: bool | None
    required_evidence: tuple[str, ...]
```

Разрешённые OR-1 boundaries:

```text
authorization
launcher
reconciliation
result_recovery
```

Каталог:

```python
PROVEN_OPERATIONAL_OUTCOMES: tuple[OperationalOutcome, ...] = (...)
```

Он не содержит предполагаемые OR-2 outcomes, пока они не подтверждены
executable regression tests.

## 7. Первоначальный каталог

### 7.1 `provision-start-root-required`

```text
boundary: authorization
error_code: root_required
command_exit_code: 6
job_state: null
job_stage: null
assignment_created: false
retryable: null
required_evidence:
  - cli_error
  - no_job_created
  - no_assignment_created
```

Существующий domain test расширяется до CLI contract test без изменения
production behavior.

### 7.2 `provision-start-launch-failed`

```text
boundary: launcher
error_code: job_launch_failed
command_exit_code: 6
job_state: failed
job_stage: launching
assignment_created: false
retryable: null
required_evidence:
  - cli_error
  - finished_at
  - stage_history_created_launching
  - no_assignment_created
```

### 7.3 `reconcile-worker-not-started-created`

```text
boundary: reconciliation
error_code: worker_not_started
command_exit_code: 0
job_state: failed
job_stage: created
assignment_created: false
retryable: true
required_evidence:
  - reconciliation_action_queued_recoverable
  - finished_at
  - stage_preserved
  - no_assignment_created
```

Вариант с исходной стадией `launching` остаётся отдельным существующим тестом,
но в первый каталог не добавляется, чтобы не смешивать два initial states.

### 7.4 `reconcile-worker-lost-employee`

```text
boundary: reconciliation
error_code: worker_lost
command_exit_code: 0
job_state: failed
job_stage: employee
assignment_created: false
retryable: null
required_evidence:
  - reconciliation_action_worker_lost
  - last_real_stage_preserved
  - no_result_created
  - no_assignment_created
```

`retryable=null`, потому что текущий status не фиксирует явное retryability
значение; OR-1 не делает логических предположений за production contract.

### 7.5 `reconcile-result-recovered`

```text
boundary: result_recovery
error_code: null
command_exit_code: 0
job_state: successful
job_stage: complete
assignment_created: true
retryable: null
required_evidence:
  - reconciliation_action_result_recovered
  - recording_complete_transition
  - result_file_recorded
  - server_assignment_matches_result
```

## 8. Валидация outcome model

`test_operational_reliability_contract.py` проверяет:

1. `scenario_id` уникальны;
2. `scenario_id` использует lowercase kebab-case;
3. `boundary` входит в разрешённый набор;
4. `job_state` входит в `queued/running/successful/failed` или равен `None`;
5. `job_stage` входит в канонические десять стадий или равен `None`;
6. `successful` требует `stage=complete`;
7. `failed` не может иметь `stage=complete`;
8. failed outcome не может создавать assignment;
9. `required_evidence` непустой и не содержит повторов;
10. metadata не содержит secret-like names;
11. каталог содержит ровно пять утверждённых OR-1 scenarios.

Каждый из пяти мигрированных regression tests получает expected contract через
`get_outcome("<scenario-id>")` и проверяет фактически наблюдаемое состояние.
Отдельный plugin или динамический test discovery в OR-1 не создаётся.

## 9. Перевод существующих тестов

На новый harness переводятся только:

1. root requirement;
2. launch failure;
3. queued worker not started на стадии `created`;
4. running worker lost на стадии `employee`;
5. valid result recovered.

Перевод означает:

- factories из `support.payloads`;
- isolated settings из `support.controller_sandbox`;
- `run_json_cli` для CLI contracts;
- `get_outcome()` для expected contract;
- отсутствие cross-import helpers из соседних test modules для этих сценариев.

Остальные тесты могут временно использовать прежние local helpers. Полная
реорганизация suite не входит в OR-1.

## 10. Fail-fast поведение harness

Harness обязан явно падать, если:

- fake executable не создан;
- CLI stdout не является JSON;
- outcome содержит неизвестный stage/state;
- `scenario_id` повторяется;
- fixture path выходит за sandbox root;
- metadata содержит secret-like key;
- тест запрашивает неизвестный outcome.

Harness не перехватывает `ControlError`, если тест намеренно проверяет domain
exception напрямую.

## 11. Безопасность

Запрещено добавлять в fixtures или evidence:

- реальные employee passwords;
- реальные password hashes;
- содержимое Vault или Vault password;
- SSH private keys;
- реальные runtime registration/job/assignment records;
- данные эталонной VM, кроме уже опубликованных в документации.

## 12. Проверки

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_operational_reliability_contract.py

.venv/bin/python -m pytest -q \
  tests/alt_linux/test_provision_start.py \
  tests/alt_linux/test_job_reconcile.py

.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q

git diff --check
```

Ansible syntax checks не обязательны, пока diff остаётся test-only. Если
реализация затрагивает Ansible или production assets, работа останавливается и
scope повторно согласовывается.

## 13. Git workflow

- branch от актуального `origin/main`;
- design commits отделены от implementation commits;
- production behavior не меняется;
- перед PR проверяется актуальность `main`;
- force push не используется;
- PR направляется в `main`;
- merge только после полного test gate и review.

## 14. Критерии приёмки

OR-1 принят, если:

- создан `tests/alt_linux/support/` с чёткими границами;
- пять выбранных сценариев не используют соседние test modules как helper
  library;
- `OperationalOutcome` immutable;
- каталог содержит только пять доказанных outcomes;
- пять regression tests напрямую используют каталог;
- production files не изменены;
- fixtures не содержат реальные секреты или runtime state;
- focused tests проходят;
- `tests/alt_linux` проходит;
- полный pytest проходит;
- `git diff --check` проходит;
- PR содержит фактический verification output.

## 15. Последующие этапы

- OR-2: SSH, controller и Vault failures;
- OR-3: account/group/LightDM conflicts и idempotency;
- OR-4: расширенный recovery и assignment boundary;
- OR-5: acceptance на второй чистой VM.

Новый outcome добавляется только одновременно с executable regression test и
фактическим evidence.
