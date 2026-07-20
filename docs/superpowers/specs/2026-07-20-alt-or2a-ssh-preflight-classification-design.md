# ALT Workstation Provisioning OR-2A — SSH/preflight failure classification

Дата: 2026-07-20.

## 1. Контекст

OR-1 добавил общий test harness и формальный каталог operational outcomes. Он
объединён в `main` через PR #17.

Точка отсчёта OR-2A:

```text
main: 689fb9622b85d3585382a308ebe31f59ab9da7d3
```

Авторитетный контекст этапа:

```text
docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md
```

OR-2 разделён на два независимых блока:

1. **OR-2A** — SSH и preflight failure classification;
2. **OR-2B** — Vault, stage helper и controller permission failures.

Эта спецификация относится только к OR-2A.

## 2. Текущее поведение

`AnsibleController.run_preflight()` уже использует строгий SSH-контур:

```text
StrictHostKeyChecking=yes
ProxyCommand=none
IdentitiesOnly=yes
ConnectTimeout=10
```

Публичный CLI-контракт для timeout и любого ненулевого Ansible return code
сейчас одинаков:

```text
error.code = preflight_failed
exit_code = 5
```

После ошибки CLI сохраняет её в registration record и устанавливает:

```text
machine.status = preflight_failed
```

Assignment и provision job при preflight не создаются.

Проблема: оператор и будущий ограниченный API не могут надёжно отличить
недоступный SSH, timeout, host-key mismatch, authentication failure, отсутствие
passwordless sudo и прочую ошибку Ansible без чтения неструктурированного
`stdout/stderr`.

## 3. Принятое решение

Сохранить обратную совместимость публичного error code:

```text
error.code = preflight_failed
exit_code = 5
```

и добавить безопасное структурированное поле:

```json
{
  "status": "error",
  "error": {
    "code": "preflight_failed",
    "message": "Ansible preflight failed",
    "details": {
      "failure_kind": "ssh_host_key_mismatch",
      "returncode": 4
    }
  }
}
```

OR-2A вводит ровно шесть допустимых `failure_kind`:

```text
ssh_timeout
ssh_unreachable
ssh_host_key_mismatch
ssh_authentication_failed
sudo_unavailable
ansible_failed
```

`ansible_failed` является обязательным conservative fallback. Неизвестная,
локализованная или неоднозначная диагностика не должна ошибочно получать более
конкретную категорию.

## 4. Цели

OR-2A должен доказать, что:

1. timeout получает `failure_kind=ssh_timeout`;
2. недоступный endpoint получает `ssh_unreachable`;
3. host-key mismatch получает `ssh_host_key_mismatch`;
4. отказ public-key authentication получает `ssh_authentication_failed`;
5. отсутствие passwordless sudo получает `sudo_unavailable`;
6. неизвестная Ansible/preflight ошибка получает `ansible_failed`;
7. отсутствие или повреждение result-файла получает `ansible_failed`;
8. публичный `error.code` остаётся `preflight_failed`;
9. exit code остаётся `5`;
10. машина получает `status=preflight_failed`;
11. assignment и provision job не создаются;
12. после исправления причины повторный preflight может завершиться успешно;
13. `ProxyCommand=none` и остальные строгие SSH-аргументы сохраняются.

## 5. Не входит в OR-2A

OR-2A не должен:

- менять error codes provision worker;
- классифицировать ошибки `run_provision()`;
- менять job stages или assignment boundary;
- исправлять Vault или permission audit;
- проверять executable-bit stage helper;
- менять account, group, LightDM или AccountsService roles;
- добавлять web API или web UI;
- выполнять реальные SSH-подключения;
- обращаться к эталонной VM;
- добавлять произвольные regex/правила, настраиваемые оператором;
- пытаться классифицировать каждую возможную ошибку Ansible.

Stage helper, Vault и controller permission failures остаются в OR-2B.

## 6. Архитектура

### 6.1 Internal pure classifier

В `deploy/alt-linux/control/alt_deploy/ansible.py` добавляется изолированный
внутренний pure-helper:

```python
def _classify_preflight_failure(
    *,
    stdout: str | None,
    stderr: str | None,
) -> str:
    ...
```

Helper:

- не является публичным API;
- не читает файловую систему;
- не запускает процессы;
- не меняет registration state;
- возвращает только одно значение из фиксированного allowlist;
- не возвращает произвольный текст из SSH/Ansible output;
- при отсутствии устойчивого признака возвращает `ansible_failed`.

Timeout, полученный как `subprocess.TimeoutExpired`, классифицируется напрямую
в `run_preflight()` и не передаётся в текстовый classifier.

### 6.2 Controlled Ansible marker

Для проверки passwordless sudo используется контролируемый marker в
`deploy/alt-linux/ansible/roles/preflight/tasks/main.yml`:

```text
ALT_PREFLIGHT_FAILURE:sudo_unavailable
```

Marker добавляется в `fail_msg` существующего assert, проверяющего:

```bash
sudo -n true
```

Marker является внутренним машинно-читаемым признаком. Он не меняет смысл
Ansible-проверки и не превращает playbook в публичный API.

OR-2A не добавляет markers для unsupported ALT, disk space, LightDM и других
целевых проверок: они относятся к следующим блокам и пока получают fallback
`ansible_failed`.

### 6.3 CLI persistence

CLI продолжает получать `ControlError` от `AnsibleController`, сохранять его
через `MachineRepository.persist_preflight()` и возвращать JSON.

Новый `failure_kind` должен присутствовать одновременно:

- в CLI JSON error details;
- в сохранённом `machine.preflight.error.details` registration record.

Registration record после ошибки:

```json
{
  "status": "preflight_failed",
  "preflight": {
    "status": "error",
    "error": {
      "code": "preflight_failed",
      "details": {
        "failure_kind": "ssh_unreachable"
      }
    }
  }
}
```

## 7. Классификационный приоритет

Порядок является частью контракта и должен быть детерминированным.

### 7.1 Timeout exception

Если runner поднимает `subprocess.TimeoutExpired`:

```text
failure_kind = ssh_timeout
```

Существующее поле `details.timeout` сохраняется.

### 7.2 Controlled marker

Если combined output содержит точный разрешённый marker:

```text
ALT_PREFLIGHT_FAILURE:sudo_unavailable
```

результат:

```text
failure_kind = sudo_unavailable
```

Неизвестный marker не принимается и не возвращается наружу.

### 7.3 Host-key mismatch

Проверяются устойчивые OpenSSH diagnostics, включая:

```text
REMOTE HOST IDENTIFICATION HAS CHANGED
Host key verification failed
Offending ... key in
```

Результат:

```text
failure_kind = ssh_host_key_mismatch
```

Host-key признаки имеют приоритет над общими connection/authentication
фрагментами.

### 7.4 Authentication failure

Проверяются признаки public-key authentication failure, включая:

```text
Permission denied (publickey
Authentication failed
No more authentication methods to try
```

Результат:

```text
failure_kind = ssh_authentication_failed
```

### 7.5 Textual timeout

Если процесс завершился, но OpenSSH/Ansible output содержит устойчивый timeout
признак:

```text
Connection timed out
Operation timed out
Timeout waiting for
```

результат:

```text
failure_kind = ssh_timeout
```

### 7.6 Unreachable endpoint

Проверяются только положительные признаки недоступного endpoint:

```text
Connection refused
No route to host
Network is unreachable
Connection reset by peer
Connection closed by remote host
```

Результат:

```text
failure_kind = ssh_unreachable
```

Общий текст `UNREACHABLE!` без конкретного транспортного признака недостаточен
для `ssh_unreachable` и должен дать fallback.

### 7.7 Fallback

Любая неизвестная или неоднозначная ошибка:

```text
failure_kind = ansible_failed
```

Это включает:

- unsupported ALT и другие target assertions без OR-2A marker;
- успешный return code без preflight result-файла;
- нечитаемый или malformed preflight result JSON.

## 8. Совместимость публичного контракта

OR-2A сохраняет:

- `ControlError.code = preflight_failed`;
- `ControlError.exit_code = 5`;
- существующее сообщение timeout;
- существующее сообщение ненулевого Ansible result;
- `details.timeout` для timeout exception;
- `details.returncode`, bounded `stdout` и bounded `stderr` для ненулевого
  return code;
- текущий registration workflow;
- текущие строгие SSH options.

OR-2A только добавляет:

```text
details.failure_kind
```

Поле обязательно для всех `preflight_failed`, сформированных
`AnsibleController.run_preflight()`, включая ветви:

```text
timeout exception
non-zero return code
missing result file
invalid result file
```

Ошибки конфигурации до запуска preflight сохраняют собственные коды:

```text
preflight_not_configured
machine_missing_ip
```

Они не получают `failure_kind`, потому что не являются завершившимся SSH или
Ansible preflight.

## 9. Operational outcome model

`OperationalOutcome` расширяется test-only полем в конце dataclass:

```python
failure_kind: str | None = None
```

Поле добавляется с default, поэтому существующие OR-1 constructors сохраняют
совместимость и получают `failure_kind=None`.

Для outcomes с `boundary=preflight` поле обязательно и входит в фиксированный
allowlist. Для остальных boundaries оно остаётся `None`.

`tests/alt_linux/support/outcomes.py` расширяется шестью доказанными сценариями:

```text
preflight-ssh-timeout
preflight-ssh-unreachable
preflight-ssh-host-key-mismatch
preflight-ssh-authentication-failed
preflight-sudo-unavailable
preflight-ansible-failed
```

Для всех шести outcomes:

```text
boundary: preflight
error_code: preflight_failed
command_exit_code: 5
job_state: null
job_stage: null
assignment_created: false
retryable: true
failure_kind: точное ожидаемое значение
```

Каталог после OR-2A содержит одиннадцать scenarios: пять OR-1 и шесть OR-2A.

## 10. Тестовая стратегия

### 10.1 Pure classifier tests

Отдельные параметризованные tests проверяют:

- каждый устойчивый diagnostic;
- регистр и наличие дополнительного Ansible framing;
- приоритет host-key mismatch;
- приоритет controlled marker;
- fallback для неизвестного текста;
- отсутствие классификации только по общему `UNREACHABLE!`;
- неизвестный controlled marker даёт fallback;
- возвращаемое значение всегда входит в allowlist.

### 10.2 CLI and persistence tests

Новый self-contained test module использует OR-1 sandbox и monkeypatch
`alt_deploy.ansible.subprocess.run`.

Для шести catalog scenarios выполняется реальный CLI entrypoint:

```text
workstationctl --json preflight <uuid>
```

Проверяется:

- exit code `5`;
- `error.code=preflight_failed`;
- `error.details.failure_kind == outcome.failure_kind`;
- registration record `status=preflight_failed`;
- сохранённый error details совпадает с CLI;
- `JobRepository.list()` пуст;
- assignment отсутствует.

Отдельные branch-coverage tests проверяют:

- missing result file возвращает `ansible_failed`;
- malformed result JSON возвращает `ansible_failed`.

Эти две ветви не создают дополнительные catalog scenarios: они подтверждают
обязательный fallback contract `preflight-ansible-failed`.

### 10.3 Retryability test

Один test выполняет две попытки на одной sandbox machine:

1. первая попытка возвращает `ssh_unreachable`;
2. вторая попытка создаёт корректный preflight result.

Ожидаемый финал:

```text
machine.status = awaiting_assignment
preflight.status = ok
assignment отсутствует
job отсутствует
```

Это доказывает `retryable=true`, а не только декларирует его в каталоге.

### 10.4 Strict SSH regression

Существующая проверка strict SSH arguments сохраняется. Дополнительно OR-2A
scenario tests подтверждают, что command содержит:

```text
StrictHostKeyChecking=yes
ProxyCommand=none
IdentitiesOnly=yes
ConnectTimeout=10
```

## 11. Файлы

### Production

Modify:

```text
deploy/alt-linux/control/alt_deploy/ansible.py
deploy/alt-linux/ansible/roles/preflight/tasks/main.yml
```

### Test support

Modify при необходимости только для явной подготовки preflight boundary:

```text
tests/alt_linux/support/controller_sandbox.py
tests/alt_linux/support/outcomes.py
```

### Tests

Create:

```text
tests/alt_linux/test_or2a_preflight_failures.py
```

Modify:

```text
tests/alt_linux/test_operational_reliability_contract.py
```

Не изменять unrelated test modules ради общего refactoring.

## 12. Безопасность

- Никакие реальные SSH private keys не добавляются в fixtures.
- Никакие реальные known-host entries не добавляются в fixtures.
- Тесты используют documentation-range IP и синтетические diagnostics.
- Classifier возвращает allowlisted identifier, а не diagnostic text.
- В `failure_kind` не допускаются hostname, IP, path, login или произвольные
  данные target.
- Marker parser принимает только точные известные значения.
- OR-2A не подключается к controller runtime или target VM.
- Эталонная VM не используется.

## 13. Error-handling invariants

1. Specific classification не влияет на решение success/failure.
2. Неизвестная ошибка не считается SSH-unreachable автоматически.
3. Classification failure не должна скрывать исходный `preflight_failed`.
4. Classifier не должен поднимать исключение на `None` или неожиданном text.
5. Timeout exception всегда имеет приоритет над текстовой классификацией.
6. Registration record не переходит в `awaiting_assignment` после ошибки.
7. Assignment и job не создаются ни в одном OR-2A failure scenario.
8. Повторный preflight после исправления причины разрешён.
9. Каждый `preflight_failed` из `run_preflight()` содержит allowlisted
   `failure_kind`.

## 14. Verification gate

Перед PR выполнить:

```bash
.venv/bin/python -m pytest -q \
  tests/alt_linux/test_or2a_preflight_failures.py \
  tests/alt_linux/test_operational_reliability_contract.py

.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q

ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

git diff --check origin/main...HEAD
```

Проверки должны выполняться в CI или в изолированном checkout. Нельзя заявлять
PASS без свежего фактического результата.

## 15. Acceptance criteria

OR-2A принят, когда:

- публичный `preflight_failed` сохранён;
- шесть `failure_kind` реализованы;
- classifier conservative и deterministic;
- sudo marker контролируемый и точный;
- outcome model содержит `failure_kind`;
- шесть outcomes добавлены в каталог;
- CLI и registration persistence проверены;
- missing/malformed result получают fallback;
- retryability доказана повторным успешным preflight;
- assignment и jobs отсутствуют после всех failures;
- strict SSH options не изменены;
- focused, ALT и full suites проходят;
- Ansible syntax-check проходит;
- final diff не содержит секретов или временного CI workflow.
