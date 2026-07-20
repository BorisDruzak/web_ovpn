# ALT Workstation Provisioning — handoff к этапу эксплуатационной надёжности

Дата фиксации контекста: 2026-07-20.

Этот документ является точкой входа для следующего рабочего чата по системе
автоматизированной подготовки рабочих станций ALT Linux. Он фиксирует уже
принятое состояние, границы следующего этапа, правила обращения с тестовыми
машинами и порядок разработки.

## 1. Цель проекта

Система должна безопасно и воспроизводимо готовить рабочую станцию ALT
Workstation K 11.2 после автоматической установки ОС:

1. зарегистрировать машину на контроллере;
2. проверить SSH, ОС и обязательные зависимости;
3. показать оператору точный preview предстоящих изменений;
4. назначить итоговый hostname и локальную учётную запись сотрудника;
5. настроить LightDM и AccountsService;
6. проверить результат на целевой машине;
7. сохранить структурированное задание и assignment;
8. исключить повторное provisioning уже назначенной машины.

Текущий этап не является системой общего управления конфигурациями и не должен
принимать произвольные playbook, inventory, shell-команды или Ansible extra
vars от оператора или будущего веб-интерфейса.

## 2. Состояние репозитория

Репозиторий:

```text
BorisDruzak/web_ovpn
```

Рабочая реализация объединена в `main` через PR #15.

Ключевые коммиты:

```text
98b7b3e5a96cf8f67d92af9c00494f3b96f7dd9b
    merge PR #15 в main

4cb8fe64941cc2406c9e00cc563fc5f3fbe82b30
    vpnctl корректно игнорирует недоступный необязательный vpnctl.env;
    добавлен регрессионный тест

a9300c3b43f9418574d2edbe15cf7ff06f7436a1
    merge актуального main в provisioning-ветку без переписывания истории

ac48838c064857b996b7dbb612433a57c4a443a5
    completed_at формируется непосредственно перед записью результата
```

Основные документы:

```text
deploy/alt-linux/README.md
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md
```

Если старые документы расходятся с кодом, источниками текущего поведения
являются `main`, `deploy/alt-linux/README.md`, этот handoff и автоматические
тесты.

## 3. Архитектура

### 3.1 Контроллер

Контроллер развёртывания:

```text
192.168.100.17
```

Сервисная учётная запись:

```text
altserver
```

Контроллер владеет:

- `workstationctl`;
- Ansible-проектом;
- SSH known-hosts и техническим SSH-доступом;
- Ansible Vault;
- provision jobs и их журналами;
- assignment records;
- job reconciliation и retention;
- transient systemd units для provisioning.

Будущий веб-интерфейс должен работать отдельно на `192.168.100.30` через
ограниченный API. Веб-сервер не должен получать SSH private keys, Vault,
произвольный Ansible или прямой доступ к рабочим станциям.

### 3.2 CLI

Основная команда:

```text
workstationctl
```

Реализованные операции:

```bash
sudo -u altserver workstationctl --json machines list
sudo -u altserver workstationctl --json machines show <uuid>

sudo -u altserver workstationctl --json preflight <uuid>

sudo -u altserver workstationctl --json provision preview <uuid> \
  --vars-file /path/to/request.json

sudo workstationctl --json provision start <uuid> \
  --vars-file /path/to/request.json

sudo -u altserver workstationctl --json jobs status <job_id>
sudo -u altserver workstationctl --json jobs log <job_id>
sudo -u altserver workstationctl --json jobs reconcile

sudo -u altserver workstationctl --json jobs cleanup
sudo workstationctl --json jobs cleanup --apply

sudo -u altserver workstationctl --json vault check
sudo -u altserver workstationctl --json controller permissions
sudo workstationctl --json controller permissions repair
```

`provision preview` не должен изменять целевую машину.

`provision start` требует root, потому что создаёт ограниченный transient
systemd unit. Повторный запуск для машины в состоянии `assigned` запрещён и
возвращает `machine_already_assigned`.

### 3.3 Provision request

Provision request не содержит пароль или password hash:

```json
{
  "machine_uuid": "<uuid>",
  "employee_login": "i-ivanov",
  "employee_full_name": "Иванов Иван Иванович",
  "final_hostname": "buh-023",
  "profile": "standard"
}
```

Текущий profile зафиксирован как `standard`. Несколько профилей и произвольный
список ролей пока не реализованы.

### 3.4 Структурированные стадии

Каноническая последовательность:

```text
created
launching
validating
connecting
identity
employee
login_screen
verifying
recording
complete
```

`state` и `stage` являются разными полями:

- `state`: `queued`, `running`, `successful`, `failed`;
- `stage`: последняя корректно достигнутая стадия;
- ошибка сохраняет последнюю стадию;
- успешное задание заканчивается `stage=complete`;
- неизвестные, обратные и пропущенные переходы запрещены;
- повтор текущего marker является byte-identical no-op.

## 4. Ansible-контур

Главный playbook первичного назначения:

```text
deploy/alt-linux/ansible/playbooks/02-provision-account.yml
```

Текущие роли:

```text
workstation_identity
local_employee
lightdm_accounts
provision_verify
```

Между ролями playbook вызывает внутренний helper контроллера:

```text
/usr/local/libexec/alt-job-stage
```

Helper не является публичной операторской командой. Marker выполняется через
`delegate_to: localhost`, `become: false`, `run_once: true` и
`changed_when: false`.

Новые роли добавляются отдельными каталогами под:

```text
deploy/alt-linux/ansible/roles/<role_name>/
```

Но на этапе эксплуатационной надёжности не следует добавлять браузер,
Nextcloud, принтеры и другие office-роли. Сначала необходимо доказать
надёжность текущего базового provisioning.

Не превращать `02-provision-account.yml` в монолитный office setup playbook.
Модель профилей и композиция дополнительных ролей являются отдельным будущим
этапом.

## 5. Принятая эталонная VM

Принятая тестовая машина:

```text
IP:               192.168.101.111
UUID:             cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7
исходный hostname: host-111
итоговый hostname: alt-phase23-test
employee login:   phase23-test
full name:        Phase 23 Test
profile:          standard
job:              job-20260720T085516Z-dc74bbc7
completed_at:     2026-07-20T10:14:19Z
state:            assigned
```

Принятые проверки:

- job successful, `stage=complete`;
- полный десятистадийный `stage_history`;
- server assignment совпадает с target assignment;
- после reboot LightDM активен;
- `ansible` скрыт в login screen и имеет passwordless sudo;
- `phase23-test` видим и не имеет sudo/wheel;
- `osn-admin` существует и видим;
- `test-autoinstal` оставлен как след ручной установки VM и считается
  допустимым для этого эталона;
- вход в KDE Plasma под `phase23-test` выполнен успешно;
- повторный provisioning заблокирован;
- дополнительное задание при проверках не создавалось.

## 6. Политика обращения с эталонной VM

Оригинальную VM не удалять. Она является принятой эталонной машиной.

На оригинальной VM разрешены только контролируемые read-only или
неразрушительные проверки:

- `machines show`;
- чтение job status и log;
- проверка assignment;
- reboot с последующей проверкой LightDM и login;
- проверка доступности SSH;
- проверка, что repeat provisioning по-прежнему запрещён, без обхода защиты.

На оригинальной VM запрещено:

- повторно запускать `provision start`;
- удалять assignment JSON вручную;
- изменять UUID;
- вручную удалять созданного сотрудника ради нового теста;
- выполнять destructive failure injection;
- использовать её для release/reassignment до проектирования соответствующего
  workflow.

Перед следующим этапом рекомендуется создать snapshot эталона, например:

```text
accepted-alt-provisioning-baseline-20260720
```

Разрушительные сценарии выполнять только на:

1. полном клоне эталонной VM; или
2. отдельной чистой VM ALT Workstation K 11.2; или
3. временном клоне, восстановленном из подтверждённого snapshot.

Каждый сценарий, меняющий систему, должен начинаться с нового клона или с
доказанного восстановления snapshot. Не накапливать несколько конфликтных
сценариев на одной машине без возврата к baseline.

## 7. Следующий этап: эксплуатационная надёжность

### 7.1 Цель

Доказать, что текущий CLI и provisioning-контур:

- предсказуемо отказывают при проблемах;
- сохраняют секреты;
- не создают ложный assignment;
- сохраняют последнюю корректную стадию;
- оставляют машину retryable, если assignment не завершён;
- корректно работают на совместимом частичном состоянии;
- не перезаписывают конфликтующие локальные данные;
- восстанавливаются после перезагрузок и потери worker.

### 7.2 Не входит в этап

Пока не реализовывать:

- release/reassignment;
- несколько profile;
- дополнительное ПО;
- browser policies;
- Nextcloud;
- принтеры;
- web API;
- web UI;
- произвольный запуск Ansible;
- массовый rollout.

### 7.3 Матрица failure injection

Проверить минимум следующие сценарии:

#### Подключение

- целевой SSH недоступен;
- timeout SSH;
- host-key mismatch;
- неправильная или отсутствующая known-host запись;
- direct-IP connection сохранил `ProxyCommand=none`;
- техническая учётная запись существует, но sudo недоступен.

#### Контроллер и секреты

- Vault отсутствует;
- Vault password file отсутствует;
- Vault не расшифровывается;
- обязательная переменная Vault отсутствует;
- hash не соответствует yescrypt;
- stage helper отсутствует;
- stage helper не executable;
- controller permission audit unhealthy.

#### Целевая система

- неподдерживаемая версия ALT;
- недостаточно свободного места;
- AccountsService inactive;
- LightDM inactive;
- случайно унаследован SSSD proxy;
- hostname не может быть применён;
- verification не может прочитать итоговое состояние.

#### Локальные учётные записи

- employee login уже занят совместимой учётной записью;
- employee login занят несовместимой учётной записью;
- существующий UID ниже 1000;
- home отличается от ожидаемого;
- primary group отсутствует;
- primary group существует совместимо;
- primary group конфликтует;
- login совпадает с защищённой технической учётной записью;
- employee неожиданно состоит в wheel или имеет sudo rule.

#### Job и recovery

- контроллер перезагружен на каждой значимой стадии;
- target перезагружен во время выполнения роли;
- transient worker исчез до `recording`;
- worker исчез на `recording` с валидным result;
- result malformed;
- result существует на недопустимой стадии;
- assignment write failure после успешной target verification;
- повторный stage marker;
- skipped/backward/unknown marker;
- malformed `stage_history` во всех readers.

Для каждого сценария зафиксировать:

- начальное состояние;
- ожидаемый error code;
- ожидаемые `state` и `stage`;
- создаётся ли assignment;
- retryable ли машина;
- остаётся ли worktree/runtime чистым;
- какие логи и evidence сохранены.

## 8. Идемпотентность

На отдельном клоне подготовить совместимые частичные состояния:

- hostname уже правильный;
- primary group уже создана;
- employee существует с ожидаемыми UID/GID/home/shell;
- AccountsService records уже правильные;
- LightDM drop-in уже правильный;
- target assignment отсутствует, но отдельные роли уже применены.

Ожидаемое поведение:

- provisioning не выполняет разрушительных изменений;
- совместимые задачи возвращают `ok`, а не обязательный `changed`;
- stage history остаётся монотонной;
- verification проходит;
- assignment создаётся только после полного подтверждения;
- повторная попытка после корректного assignment блокируется.

## 9. Conflict safety

Provisioning должен fail closed и не перезаписывать:

- системную учётную запись;
- пользователя с другим home;
- пользователя с конфликтующим UID/GID;
- защищённые технические аккаунты;
- группу с несовместимым GID;
- hostname, уже закреплённый за другой машиной;
- существующий assignment другой машине или другому сотруднику.

Нельзя считать удаление конфликтующих данных допустимым автоматическим
исправлением.

## 10. Second-machine acceptance

После автоматических и контролируемых failure tests провести второй полный
acceptance cycle на чистой VM, не используя UUID эталонной машины:

1. чистая установка ALT Workstation K 11.2;
2. автоматическая registration;
3. SSH readiness;
4. успешный preflight;
5. успешный provision preview;
6. root-only provision start;
7. полный stage history;
8. successful/complete;
9. reboot;
10. визуальная проверка LightDM;
11. графический вход сотрудника;
12. server/target assignment match;
13. repeat provisioning protection.

Только после этого обсуждать пилот на 3–5 реальных рабочих станциях.

## 11. Рекомендуемое разбиение работы

Не пытаться закрыть весь этап одним PR.

Рекомендуемая последовательность:

### OR-1 — test harness и спецификация failure outcomes

- каталог/модель тестовых сценариев;
- единый формат evidence;
- таблица ожидаемых error codes, state и stage;
- helper для создания isolated Settings и fake controller boundaries;
- без изменения production behavior, кроме обнаруженных тестами дефектов.

### OR-2 — SSH и controller/Vault failures

- недоступность SSH;
- timeout;
- host-key mismatch;
- Vault failures;
- missing helper;
- permission failures.

### OR-3 — account, group, LightDM и idempotency

- совместимые partial states;
- account/group conflicts;
- AccountsService и LightDM failures;
- conflict safety.

### OR-4 — job recovery и assignment boundary

- controller reboot;
- lost worker;
- malformed result;
- assignment write failure;
- target reboot;
- stage transition rejection.

### OR-5 — second-machine acceptance

- чистая VM;
- полный end-to-end цикл;
- reboot и visual acceptance;
- итоговый acceptance report.

Если конкретный тест обнаруживает дефект, исправлять его отдельным минимальным
коммитом с регрессионным тестом.

## 12. Порядок работы в каждом следующем чате

Работать контролируемыми шагами. Пользователь выполняет команды на контроллере
и присылает полный вывод. Не выдавать сразу длинную цепочку изменяющих команд,
если результат первого шага определяет следующий.

### 12.1 Начало сессии

1. Прочитать этот документ.
2. Проверить актуальный `origin/main`.
3. Создать isolated branch/worktree от текущего `main`.
4. Убедиться, что worktree чистый.
5. Зафиксировать текущие SHA и test baseline.
6. Выбрать один узкий сценарий из матрицы.

### 12.2 Для каждого дефекта

Использовать систематическую диагностику:

1. прочитать полную ошибку;
2. воспроизвести стабильно;
3. сравнить с рабочим примером;
4. проследить источник плохого состояния;
5. сформулировать одну проверяемую гипотезу;
6. не менять production-код до установления root cause.

Использовать TDD:

1. RED — минимальный регрессионный тест;
2. подтвердить, что он падает по ожидаемой причине;
3. GREEN — минимальное production-изменение;
4. focused tests;
5. ALT suite;
6. syntax/compile checks;
7. full integration gate перед PR.

### 12.3 Обязательные проверки

После Python/CLI изменения:

```bash
.venv/bin/python -m pytest -q tests/alt_linux
.venv/bin/python -m pytest -q

git diff --check
```

После Ansible изменения:

```bash
.venv/bin/python -m pytest -q tests/alt_linux

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/01-preflight.yml

ANSIBLE_CONFIG="$PWD/deploy/alt-linux/ansible/ansible.cfg" \
  ansible-playbook --syntax-check \
  deploy/alt-linux/ansible/playbooks/02-provision-account.yml

bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh

git diff --check
```

Перед заявлением о готовности обязательно привести фактический вывод тестов и
проверить clean worktree.

### 12.4 Git workflow

- не работать непосредственно в `main`;
- branch/worktree от актуального `origin/main`;
- один логический дефект или один узкий сценарий на коммит;
- перед push убедиться, что remote branch не сдвинулся;
- PR в `main`;
- merge commit предпочтителен для этапов с runtime evidence;
- не использовать force push и не переписывать уже принятую историю без
  отдельного обоснования.

## 13. Безопасность

Никогда не выводить и не коммитить:

- `/home/altserver/.ansible-vault-pass`;
- активный `group_vars/vault.yml`;
- расшифрованный Vault;
- employee password/hash;
- SSH private keys;
- содержимое файлов с секретами;
- runtime registration/job/assignment state целиком, если в нём могут быть
  приватные данные.

Разрешено фиксировать:

- SHA256 файлов;
- owner/group/mode;
- булевы результаты проверок;
- UUID тестовой машины;
- job ID;
- stage/state;
- обезличенные error codes;
- пути evidence без секретного содержимого.

Будущий API и CLI не должны принимать произвольный playbook path, inventory,
shell command или unrestricted extra vars.

## 14. Готовый промт для следующего чата

Скопировать следующий блок в новый чат:

```text
Работаем с репозиторием BorisDruzak/web_ovpn и системой ALT Workstation
Provisioning.

Сначала прочитай из актуальной ветки main файл:

docs/ALT_WORKSTATION_OPERATIONAL_RELIABILITY_HANDOFF.md

Также используй как источники текущего поведения:

- deploy/alt-linux/README.md
- docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
- docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
- deploy/alt-linux/control/alt_deploy/
- deploy/alt-linux/ansible/
- tests/alt_linux/

Текущее принятое состояние объединено в main через merge commit
98b7b3e5a96cf8f67d92af9c00494f3b96f7dd9b. Не полагайся только на этот SHA:
сначала проверь актуальный origin/main, потому что репозиторий мог измениться.

Следующий этап — эксплуатационная надёжность текущего CLI и базового
provisioning. Не добавляй пока browser, Nextcloud, принтеры, дополнительные
профили, API или веб-интерфейс.

Оригинальная VM 192.168.101.111 с UUID
cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7 является принятой эталонной машиной в
состоянии assigned. Не запускай на ней повторный provision start, не удаляй
assignment и не используй её для разрушительных тестов. Разрушительные
сценарии выполняются только на клонах/snapshot или новой чистой VM.

Начни с read-only аудита текущего main и предложи узкое разбиение первого PR
этапа operational reliability. Рекомендуемый первый блок — test harness и
контракт failure outcomes, после чего SSH/controller/Vault failure injection.

Работай по одному контролируемому шагу. Я выполняю команды на контроллере и
присылаю полный вывод. Не выдавай следующую изменяющую команду, пока не
проанализирован результат предыдущей.

Для каждого дефекта:

1. root-cause investigation;
2. стабильное воспроизведение;
3. RED regression test;
4. минимальный GREEN fix;
5. focused tests;
6. tests/alt_linux;
7. full pytest;
8. Ansible/Bash/compile checks по области изменения;
9. git diff --check;
10. commit, push, PR только после полного gate.

Не исправляй симптомы наугад. Не выводи Vault, password hashes, SSH private
keys или содержимое секретных файлов. Не принимай архитектурные решения,
нарушающие существующие CLI, job, assignment, Vault, structured-stage и
Ansible boundaries без конкретного failing requirement и регрессионного теста.

Первый ответ должен:

- кратко подтвердить прочитанный контекст;
- указать актуальный main SHA;
- перечислить, что уже готово и что является следующим этапом;
- предложить 2–3 варианта организации operational reliability с рекомендацией;
- задать только один уточняющий вопрос перед проектированием первого блока.
```

## 15. Критерий завершения handoff

Новый чат считается корректно начатым, если он:

- не предлагает удалить эталонную VM;
- не пытается повторно provision assigned UUID;
- не начинает с дополнительных Ansible office-ролей;
- проверяет актуальный `main`;
- выбирает один узкий failure scenario или test-harness блок;
- работает через isolated branch/worktree;
- соблюдает root-cause investigation и TDD;
- сохраняет evidence и не раскрывает секреты.
