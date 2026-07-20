# ALT Workstation Provisioning OR-1 — test harness и failure outcome contracts

Дата: 2026-07-20.

## 1. Контекст

Базовый ALT Workstation Provisioning объединён в `main`. Следующий этап —
эксплуатационная надёжность текущего CLI и базового provisioning-контура.
Авторитетная точка входа:

```text
docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md
```

OR-1 должен подготовить общую тестовую инфраструктуру и формализовать уже
доказанные failure outcomes. Изменение production behavior в этот PR не входит.

## 2. Проблема

Текущая тестовая база проверяет важные свойства jobs, assignments, recovery,
Vault и provisioning, но общие helpers распределены между тестовыми модулями:

- `make_settings()` и `write_machine()` находятся в `test_registry_cli.py`;
- `provision_request()` и `assignment_payload()` находятся в `test_jobs.py`;
- recovery-тесты импортируют helpers из нескольких других test modules;
- preview/start tests используют окружение, определённое в соседнем тестовом
  модуле.

В результате тестовые файлы одновременно являются тестами и неявной библиотекой
fixtures. Это затруднит расширение матрицы failure injection и не даёт единого
машиночитаемого контракта между сценарием и ожидаемыми:

- `error_code`;
- CLI exit code;
- job `state`;
- job `stage`;
- созданием assignment;
- retryability;
- обязательным evidence.

## 3. Цель

Создать test-only foundation для этапов OR-2 — OR-5:

1. единый isolated controller sandbox;
2. общие безопасные payload factories;
3. единый CLI JSON runner;
4. immutable failure outcome model;
5. каталог только уже доказанных outcomes;
6. контрактные тесты каталога;
7. перевод пяти репрезентативных сценариев на новый harness.

## 4. Не входит в OR-1

OR-1 не должен:

- изменять `deploy/alt-linux/control/`;
- изменять Ansible roles или playbooks;
- добавлять browser, Nextcloud, принтеры или дополнительные profiles;
- выполнять SSH-подключения к реальным машинам;
- запускать systemd units;
- читать активный Vault;
- выполнять provisioning;
- обращаться к эталонной VM `192.168.101.111`;
- добавлять универсальный YAML/JSON scenario engine;
- массово переписывать весь существующий test suite.

## 5. Предлагаемая структура

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

Допускается сохранить небольшие специализированные helpers в конкретных test
modules, если они не используются за пределами этого модуля.

## 6. Компоненты

### 6.1 `controller_sandbox.py`

Отвечает только за файлово изолированный controller boundary.

Основной API:

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
- создавать fake executable paths для Ansible, systemd worker и stage helper;
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

Helpers должны быть узкими и детерминированными. Один helper не должен скрыто
подготавливать unrelated controller state.

### 6.2 `payloads.py`

Содержит безопасные фабрики тестовых данных:

```python
machine_registration_payload(...)
provision_request(...)
assignment_payload(...)
successful_provision_result(...)
```

Требования:

- значения детерминированы;
- UUID, hostname, login и timestamps являются тестовыми;
- нет настоящих паролей, password hashes, Vault values или SSH keys;
- фабрики возвращают новые mapping objects, чтобы тесты не делили mutable state;
- override-параметры явные и типизированные.

### 6.3 `cli.py`

Предоставляет один способ запуска CLI entrypoint в тестах:

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

- `--json` добавляется helper-ом или требуется явно — выбранный вариант должен
  быть единообразным во всех переведённых тестах;
- stdout обязан быть одним валидным JSON document;
- invalid JSON приводит к assertion failure с сохранением stdout/stderr;
- helper не интерпретирует domain outcome и не скрывает exit code;
- helper не нормализует error codes и не модифицирует payload.

Для OR-1 рекомендуется автоматически добавлять `--json`, поскольку helper
предназначен только для JSON contract tests.

### 6.4 `outcomes.py`

Определяет immutable outcome model:

```python
@dataclass(frozen=True)
class FailureOutcome:
    scenario_id: str
    boundary: str
    error_code: str | None
    exit_code: int
    job_state: str | None
    job_stage: str | None
    assignment_created: bool
    retryable: bool | None
    required_evidence: tuple[str, ...]
```

`boundary` в OR-1 ограничивается известными категориями:

```text
authorization
launcher
reconciliation
result_recovery
```

Каталог является tuple-константой:

```python
PROVEN_FAILURE_OUTCOMES: tuple[FailureOutcome, ...] = (...)
```

Каталог не должен содержать предполагаемые OR-2 outcomes, которые ещё не
подтверждены regression tests.

## 7. Первоначальный каталог outcomes

OR-1 фиксирует только существующее доказанное поведение.

### 7.1 `root_required`

```text
scenario_id: provision-start-root-required
boundary: authorization
error_code: root_required
exit_code: существующий CLI/domain contract
job_state: null
job_stage: null
assignment_created: false
retryable: null
required_evidence:
  - cli_error
  - no_job_created
  - no_assignment_created
```

Если существующий тест проверяет только domain exception, OR-1 не должен
выдумывать CLI exit code. Outcome должен отражать реально проверенный уровень,
либо тест должен быть минимально расширен до CLI contract без изменения
production behavior.

### 7.2 `job_launch_failed`

```text
scenario_id: provision-start-launch-failed
boundary: launcher
error_code: job_launch_failed
job_state: failed
job_stage: launching
assignment_created: false
retryable: null
required_evidence:
  - error_code
  - finished_at
  - stage_history_created_launching
  - no_assignment_created
```

### 7.3 `worker_not_started`

```text
scenario_id: reconcile-worker-not-started
boundary: reconciliation
error_code: worker_not_started
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

OR-1 может также фиксировать уже доказанный вариант `stage=launching`, но не
должен объединять два различающихся initial states в один двусмысленный outcome.

### 7.4 `worker_lost`

```text
scenario_id: reconcile-worker-lost
boundary: reconciliation
error_code: worker_lost
job_state: failed
job_stage: employee
assignment_created: false
retryable: false или null согласно существующему контракту
required_evidence:
  - reconciliation_action_worker_lost
  - last_real_stage_preserved
  - no_result_created
  - no_assignment_created
```

Если production status не содержит явного `retryable`, outcome использует
`None`, а не логическое предположение.

### 7.5 `result_recovered`

Это успешный recovery outcome, поэтому он может храниться в отдельной
`PROVEN_RECOVERY_OUTCOMES` либо использовать более общее имя модели
`OperationalOutcome`. Рекомендуется выбрать общее имя `OperationalOutcome`,
поскольку каталог содержит не только failures.

```text
scenario_id: reconcile-result-recovered
boundary: result_recovery
error_code: null
exit_code: 0
job_state: successful
job_stage: complete
assignment_created: true
retryable: false
required_evidence:
  - reconciliation_action_result_recovered
  - recording_complete_transition
  - result_file_recorded
  - server_assignment_matches_result
```

## 8. Валидация outcome model

`test_operational_reliability_contract.py` должен проверять:

1. `scenario_id` уникальны;
2. `scenario_id` использует lowercase kebab-case;
3. `boundary` входит в разрешённый набор;
4. `job_state` входит в `queued/running/successful/failed` или равен `None`;
5. `job_stage` входит в канонические десять стадий или равен `None`;
6. `successful` требует `stage=complete`;
7. `failed` не может иметь `stage=complete`;
8. `assignment_created=true` не допускается для failed outcome;
9. `required_evidence` непустой и не содержит повторов;
10. каталог не содержит secret-like field names;
11. каждый outcome связан минимум с одним executable regression test.

Связь с regression tests должна быть явной. Рекомендуемый простой механизм:
pytest marker или набор scenario IDs, экспортируемый тестовым модулем. Не следует
строить plugin или test discovery framework в OR-1.

## 9. Перевод существующих тестов

На новый harness переводятся только пять репрезентативных сценариев:

1. root requirement;
2. launch failure;
3. queued worker not started;
4. running worker lost;
5. valid result recovered.

Перевод означает:

- использование factories из `support.payloads`;
- использование isolated settings из `support.controller_sandbox`;
- использование `run_json_cli` там, где тест проверяет CLI;
- явную проверку outcome contract;
- удаление cross-import для этих helpers из соседних test modules.

Другие тесты могут продолжить использовать старые local helpers до следующих
узких refactor PR. OR-1 не должен превращаться в полную реорганизацию suite.

## 10. Error handling тестового harness

Harness должен fail fast:

- fake executable не создан — тест получает явную ошибку;
- CLI stdout не JSON — assertion содержит stdout и stderr;
- неизвестный stage/state в outcome — contract test падает;
- duplicate scenario ID — contract test падает;
- fixture пытается выйти за sandbox root — helper отвергает путь;
- secret-like ключ найден в outcome/evidence metadata — contract test падает.

Harness не должен перехватывать `ControlError`, если конкретный тест ожидает
проверить его напрямую.

## 11. Безопасность

Запрещено добавлять в fixtures или evidence:

- реальные employee passwords;
- реальные password hashes;
- содержимое Vault;
- Vault password;
- SSH private keys;
- реальные runtime registration/job/assignment records;
- данные эталонной VM, кроме уже опубликованного UUID/IP в документации.

Fake values должны быть очевидно тестовыми. Проверки безопасности payloads
должны продолжать использовать существующий production fail-closed contract.

## 12. Проверки

После реализации обязательно выполнить:

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

Если меняется только Python test code, Ansible syntax checks не обязательны.
Если реализация затронет Ansible assets вопреки текущему дизайну, scope должен
быть остановлен и пересмотрен до продолжения.

## 13. Git workflow

- branch создаётся от актуального `origin/main`;
- один design commit;
- implementation выполняется отдельными логическими commits;
- production behavior не изменяется;
- перед push/PR проверяется, что `main` не сдвинулся несовместимо;
- force push не используется;
- PR направляется в `main`;
- merge выполняется только после полного test gate и review.

## 14. Критерии приёмки OR-1

OR-1 принят, если:

- создан `tests/alt_linux/support/` с чёткими границами;
- test modules больше не используются как библиотека для пяти выбранных
  сценариев;
- outcome model immutable и валидируется автоматическими тестами;
- каталог содержит только доказанные outcomes;
- пять репрезентативных сценариев связаны с каталогом;
- нет production changes;
- нет реальных секретов или runtime state;
- focused tests проходят;
- `tests/alt_linux` проходит;
- полный pytest проходит;
- `git diff --check` проходит;
- PR содержит фактический verification output.

## 15. Последующие этапы

После OR-1:

- OR-2 добавляет SSH, controller и Vault failure injection через новый harness;
- OR-3 добавляет account/group/LightDM conflicts и idempotency;
- OR-4 добавляет расширенный recovery и assignment boundary;
- OR-5 проводит acceptance на второй чистой VM.

Новые outcomes добавляются только одновременно с executable regression tests и
фактическим evidence.
