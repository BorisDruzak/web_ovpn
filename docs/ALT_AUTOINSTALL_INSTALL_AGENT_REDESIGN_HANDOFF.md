# ALT Autoinstall + Install-Agent — handoff к переработке установки

Дата фиксации контекста: 2026-07-24.

Статус: документ фиксирует результаты текущего тестирования, выявленные ограничения
существующего `autoinstall.scm`, принятый целевой вариант `USB + install-agent`,
архитектурные решения и границы следующего этапа. Это контекст для нового чата и
будущей design/spec работы. Он не означает, что install-agent, динамический renderer,
веб-интерфейс установки или кастомный ISO уже реализованы.

Репозиторий:

```text
BorisDruzak/web_ovpn
```

Связанные документы, которые нужно читать вместе с этим handoff:

```text
docs/ALT_LINUX_AUTOINSTALL.md
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
deploy/alt-linux/README.md
```

Если старые документы расходятся с этим handoff по будущей архитектуре
автоустановки, этот документ фиксирует более поздние решения от 2026-07-24.
Фактическое production-поведение всегда определяется установленными файлами,
точным Git commit и проверками на контроллере.

---

## 1. Цель переработки

Нужно заменить текущий статический сценарий ALT autoinstall на управляемую систему:

```text
кастомный USB/ISO без ручного ввода параметров
    -> ранний install-agent
    -> автоматическое обнаружение оборудования
    -> создание install session на контроллере
    -> ожидание решения администратора
    -> выбор установки на сервере
    -> серверная генерация точного InstallPlan
    -> генерация autoinstall.scm и vm-profile.scm из шаблонов
    -> подтверждение уничтожения выбранного диска
    -> штатная установка ALT через Alterator
    -> локальное отображение текущего этапа и ошибок
    -> удалённые stages, heartbeat и технические логи
    -> reboot
    -> bootstrap и registration продолжают ту же install session
    -> SSH/Ansible verification
    -> complete
```

Главная операторская точка должна находиться на сервере. Локальный интерфейс
установщика остаётся минимальным: показать, что машина обнаружена, ожидает решения,
установка выполняется, какой этап активен и какая ошибка произошла.

---

## 2. Принятый способ загрузки

На первом этапе выбран вариант:

```text
USB + install-agent + кастомный ISO без ручного ввода команды
```

Пока не реализовывать PXE/iPXE и полную установку без USB. Архитектура agent/session
должна быть пригодна для будущего переноса на PXE, но сетевой boot не должен
расширять первый этап.

Текущий временный запуск со штатного ISO требует вручную добавить:

```text
ai curl=http://192.168.100.17:8087/metadata/
```

В новой сборке ручного ввода не должно быть. Кастомный ISO должен содержать готовый
пункт загрузки, например:

```text
Sosnadmin managed installation
Normal ALT installation
Diagnostics
```

Управляемый пункт не должен немедленно очищать диск. Он запускает install-agent,
который создаёт серверную сессию и ждёт утверждённого плана.

Нужно изменить загрузочные конфигурации как минимум для UEFI. Поддержка Legacy BIOS
остаётся отдельным решением; для первого production-capable этапа допустимо закрепить
UEFI-only и завершать Legacy-загрузку понятной ошибкой до изменения диска.

---

## 3. Текущая инфраструктура

Контроллер ALT deployment:

```text
IP:              192.168.100.17
service account: altserver
static HTTP:     http://192.168.100.17:8087/
registration:    http://192.168.100.17:8088/register
health:          http://192.168.100.17:8088/health
```

Текущие важные пути:

```text
/srv/alt-deploy/metadata/autoinstall.scm
/srv/alt-deploy/metadata/vm-profile.scm
/srv/alt-deploy/metadata/pkg-groups.tar
/srv/alt-deploy/metadata/install-scripts.tar
/srv/alt-deploy/bootstrap/bootstrap.sh
/srv/alt-deploy/bootstrap/ansible_authorized_keys
/srv/alt-deploy/registration/{pending,ready,failed}
/home/altserver/ansible
/home/altserver/.ssh/known_hosts_autoinstall
```

Текущий HTTP-сервис на `8087` является allowlisted static server и отдаёт только
разрешённые пространства `/metadata/*`, `/bootstrap/*` и `/health`. Он пока не умеет
создавать сессии, принимать inventory, формировать файлы для конкретной машины,
принимать stages или загружать логи.

Принятая общая граница доверия сохраняется:

```text
192.168.100.17
    authoritative install-session state
    renderer
    generated plans
    logs
    controller runtime
    Ansible/Vault/SSH identity

192.168.100.30
    будущий operator web UI в составе web_ovpn
    только constrained API к .17
    без Vault, private SSH key и прямого Ansible
```

Для первого прототипа backend и диагностическая операторская поверхность могут
появиться на `.17`, но конечная архитектура не должна переносить controller secrets
на `.30`.

---

## 4. Различие версий ALT, которое нельзя игнорировать

Существующая provisioning-документация и ранее принятый control plane ориентированы
на ALT Workstation K 11.2.

Текущий тест автоустановки выполнялся с ISO:

```text
alt-kworkstation-11.4-install-x86_64.iso
```

Это обязательный gate следующего этапа:

1. явно выбрать целевой релиз;
2. не считать 11.2 и 11.4 взаимозаменяемыми без acceptance;
3. привязывать `pkg-groups.tar`, metadata и ISO manifest к точному образу;
4. не копировать `pkg-groups.tar` из другой версии;
5. сохранять SHA-256 и идентификатор точного ISO в install session и InstallPlan;
6. повторно проверить bootstrap, registration, preflight и provisioning на выбранном
   релизе.

Рекомендуемое направление — принять текущий ISO 11.4 как кандидат нового этапа, но
не объявлять поддержку до полного end-to-end acceptance.

---

## 5. Текущий статический autoinstall

Активная production-конфигурация содержит следующие жёстко зафиксированные решения:

```text
language:             ru_RU
keyboard:             alt_sh_toggle
timezone:             Asia/Yekaterinburg
network interface:    enp3s0
network:              DHCP
temporary hostname:   alt-auto-test
disk mode:            clear first detected disk
profile name:         timeshiftstation
swap:                 4 GiB
Btrfs minimum:        40 GiB
Btrfs growth:         all remaining available space
subvolumes:           @ -> /, @home -> /home
bootloader:           UEFI, device "efi"
package set:          broad KWorkstation desktop/application groups
first boot:           bootstrap.sh from 192.168.100.17:8087
```

Санитизированная структура текущего дискового профиля:

```scheme
((timeshiftstation
  (title . "Sosnadmin ALT workstation")
  (action . trivial)
  (actiondata
    ("swap"
      (size 8388608 . 8388608)
      (fsim . "SWAPFS")
      (methods plain))
    (""
      (size 83886080 . #t)
      (fsim . "BtrFS")
      (methods plain)
      (subvols ("@" . "/") ("@home" . "/home"))))))
```

Размеры указаны в 512-байтовых блоках:

```text
8388608  -> 4 GiB
83886080 -> 40 GiB
```

Пара `(minimum . #t)` для Btrfs уже означает: создать раздел не меньше минимума и
дать ему доступный остаток. Следовательно, отдельные профили только ради дисков
32/50/100/200 GiB не нужны. Проблема текущего файла — слишком высокий фиксированный
минимум, а не отсутствие механизма роста.

Активный `autoinstall.scm` также содержит password hashes для root и `osn-admin`.
Их значения не должны попадать в Git, этот документ, логи или UI. Во время текущей
диагностики значения были показаны оператором; их нужно считать требующими ротации
до следующего реального rollout. Новый renderer не должен хранить постоянные hashes
в публично доступном static metadata.

---

## 6. Выявленные дефекты текущего сценария

### 6.1 Дисковый профиль привязан к большой тестовой машине

На VM с диском 32 GiB вызов:

```text
/evms/profiles/timeshiftstation action apply
```

вернул:

```text
answer: ((#f ""))
```

После этого установка завершалась `autoinstall FAILED` и не имела корректного
`/mnt/destination`.

После увеличения диска до 50 GiB тот же профиль вернул:

```text
answer: ((nextop /vm/table))
```

и установка прошла дальше к `pkg-install-init`, `pkg-install` и `preinstall`.

Вывод: первоначальный сбой был воспроизводимо связан с невозможностью вместить
`4 GiB swap + минимум 40 GiB Btrfs + служебные/EFI данные`.

### 6.2 Сеть привязана к `enp3s0`

Имя `enp3s0` было корректно только для прежней тестовой машины. Другой компьютер или
иная модель виртуального NIC может получить `enp6s18`, `ens18`, `enp1s0` и другое
имя. Новый agent должен обнаруживать интерфейсы и передавать их серверу. Renderer
не должен угадывать интерфейс по одному старому значению.

### 6.3 Hostname привязан к `alt-auto-test`

Во время установки допустимо временное уникальное имя. Окончательный hostname уже
назначается provisioning-контуром. Статическое имя создаёт конфликты при
параллельных установках и затрудняет наблюдение.

### 6.4 UEFI зафиксирован без проверки firmware

Текущий файл всегда выполняет:

```scheme
("/grub" action "write" device "efi" ...)
```

Первоначально тестовая VM загружалась через SeaBIOS и показывала:

```text
No EFI environment detected
```

Для продолжения теста VM была переведена на OVMF и получила EFI Disk.

### 6.5 Консоль не даёт нормального операторского состояния

Сейчас видны сырые Scheme-вызовы и ответы Alterator. Пользователь не получает
понятного текущего этапа, причины ошибки, session ID или указания, где смотреть
удалённый лог. При завершении с ошибкой консоль может закрываться слишком быстро.

### 6.6 Ранние логи не уходят на сервер

`install-scripts.tar` с `preinstall.d` и `postinstall.d` запускается слишком поздно
для ошибок disk profile/EVMS. Для наблюдаемости с самого начала агент должен быть
встроен в установочную среду или initrd и стартовать до запуска разрушительного
autoinstall.

---

## 7. Текущая тестовая VM

Последняя тестовая машина в Proxmox:

```text
VMID: 112
name: test-autoinstal
BIOS: ovmf
boot order: scsi0;ide2;net0
system disk: scsi0, 50G
ISO: alt-kworkstation-11.4-install-x86_64.iso
EFI disk: configured, 4M type, pre-enrolled keys disabled
```

До изменения VM использовала SeaBIOS и диск 32 GiB. После перехода на 50 GiB и OVMF
дисковый профиль начал применяться. Последний наблюдаемый запуск дошёл до
`pkg-install`/`preinstall`; полное завершение текущего запуска на момент фиксации
этого документа ещё не подтверждено.

Эта VM является расходной тестовой целью для автоустановки. Принятая эталонная
workstation остаётся вне этого этапа:

```text
IP:   192.168.101.111
UUID: cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7
```

Её нельзя переустанавливать, re-register, archive, release или reprovision ради
разработки install-agent.

---

## 8. Принятая модель профиля

Не создавать отдельные профили `disk-32`, `disk-50`, `disk-100` и `disk-200`, если
различается только размер диска.

Нужен один логический профиль-политика:

```text
standard-office
```

Он задаёт намерение, а не готовую Scheme-разметку:

```yaml
id: standard-office
version: 1
minimum_disk_policy: measured_and_validated
wipe_mode: whole_disk
filesystem: btrfs
swap_policy: template_variable
root_policy: all_remaining_space
subvolumes:
  - name: "@"
    mountpoint: "/"
  - name: "@home"
    mountpoint: "/home"
network: dhcp
interface_policy: selected_from_inventory
bootloader_policy: derived_from_firmware
package_set: standard-office
```

Размеры 32, 50, 100 и 200 GiB должны использовать тот же профиль, если выполняются
минимальные требования. Btrfs получает весь оставшийся диск.

Отдельный профиль нужен только для принципиально другой политики, например:

```text
шифрование
несколько дисков
отдельный фиксированный /home
серверная система
минимальный пакетный набор
```

На первом этапе реализуется только `standard-office`. Не строить общий конструктор
произвольных профилей и не давать оператору редактировать Scheme вручную.

---

## 9. Profile policy, InstallPlan и rendered files

Нужно разделить три уровня.

### 9.1 Profile policy

Версионируемая серверная политика с ограниченным набором типизированных полей.

### 9.2 Concrete InstallPlan

Неизменяемый план конкретной install session, сформированный из inventory и выбора
оператора.

Рекомендуемые поля:

```json
{
  "schema_version": 1,
  "session_id": "install-...",
  "profile_id": "standard-office",
  "profile_version": 1,
  "iso_id": "alt-kworkstation-11.4-install-x86_64",
  "iso_sha256": "<sha256>",
  "firmware": "uefi",
  "target_disk": {
    "path": "/dev/vda",
    "size_bytes": 53687091200,
    "model": "QEMU HARDDISK",
    "serial": "<optional>",
    "wwn": "<optional>"
  },
  "wipe_mode": "whole_disk",
  "swap_policy": {
    "mode": "fixed_or_ram_based",
    "size_mib": 2048
  },
  "filesystem": "btrfs",
  "root_grow": true,
  "subvolumes": {
    "@": "/",
    "@home": "/home"
  },
  "network_interface": "enp6s18",
  "network_mode": "dhcp",
  "temporary_hostname": "alt-install-...",
  "bootloader": "efi",
  "package_set": "standard-office",
  "approved_at": "<UTC>",
  "expires_at": "<UTC>",
  "plan_hash": "<sha256>"
}
```

Точные minimum disk и swap policy пока не зафиксированы. Их нужно получить из
измерений ALT 11.4 и acceptance на 32/50/100/200 GiB, а не выбрать произвольно.

### 9.3 Rendered files

Renderer на `.17` формирует для exact plan:

```text
plan.json
autoinstall.scm
vm-profile.scm
sha256sums
signature или signed-plan envelope
```

Нельзя позволять API-клиенту передавать произвольный Scheme, shell, package list,
disk command или Alterator method. UI меняет только allowlisted типизированные поля.

После утверждения plan immutable. Любое изменение диска, firmware, интерфейса,
профиля или package set создаёт новую revision и требует нового подтверждения.

---

## 10. Выбор диска и destructive approval

Agent передаёт полный bounded inventory дисков:

```text
path
size_bytes
model
serial
WWN, если доступен
removable
rotational
type
связь с boot media
существующие сигнатуры файловых систем
```

Путь `/dev/vda` или `/dev/sda` не является достаточной долговечной идентичностью.
InstallPlan должен связывать выбранный диск как минимум с path + size + model и,
когда доступны, serial/WWN.

До очистки диска локальный agent обязан повторно проверить, что:

1. выбранный диск всё ещё существует;
2. identity и размер совпадают с утверждённым plan;
3. диск не является установочным USB/ISO media;
4. minimum policy выполнена;
5. нет второго неразрешённого кандидата при неоднозначном inventory;
6. plan не истёк и не был отозван;
7. подпись/хеш plan корректны.

При любой неоднозначности установка fail closed до изменения диска.

Рекомендуемая safety policy: подтверждение exact target disk на сервере обязательно
для каждой новой установки, даже когда найден один системный диск. Автоматическое
предложение допускается, автоматическое разрушение без серверного approval — нет.

---

## 11. Install session без ручного токена

Пользователь не должен вводить токен на каждой машине.

Рекомендуемый поток:

```text
agent boot
    -> DHCP
    -> inventory
    -> POST create session на .17
    -> server возвращает session_id и ephemeral credential
    -> agent heartbeat/poll
    -> operator approves exact plan
    -> server publishes signed immutable plan
    -> agent verifies and executes
```

Не встраивать в ISO общий секрет, который даёт право очищать диски: ISO можно
скопировать. Допустимо встроить:

```text
controller URL
controller plan-signing public key
pinned CA/public trust material
release/agent version
```

Создание необязательной/неразрушительной сессии можно разрешить только из trusted
provisioning network. Сам факт создания сессии не даёт права начать установку.
Destructive authority появляется только в server-approved plan, привязанном к
конкретной машине и диску.

Для production transport предпочтителен HTTPS. Если технический прототип сначала
работает по HTTP в изолированной LAN, agent всё равно должен проверять
криптографически подписанный plan перед очисткой диска; HTTP не должен быть
единственной границей доверия.

---

## 12. Inventory

Минимальный inventory agent:

```json
{
  "agent_version": "...",
  "boot_id": "...",
  "dmi_uuid": "...",
  "manufacturer": "...",
  "product_name": "...",
  "serial_number": "...",
  "firmware": "uefi",
  "memory_bytes": 8589934592,
  "cpu_arch": "x86_64",
  "disks": [],
  "interfaces": [
    {
      "name": "enp6s18",
      "mac": "...",
      "carrier": true,
      "addresses": ["192.168.101.x/23"]
    }
  ],
  "source_ip": "derived by server",
  "iso_id": "...",
  "iso_sha256": "..."
}
```

Все поля валидируются и ограничиваются по длине/количеству. Не отправлять полный
`dmidecode`, неограниченный `udevadm`, секреты, содержимое дисков или произвольные
командные результаты.

---

## 13. Состояния install session

Рекомендуемая строгая state machine:

```text
discovered
inventory_ready
awaiting_approval
approved
plan_delivered
preflight
installing
reboot_pending
first_boot
verifying
complete
failed
cancelled
```

`state` и `stage` должны быть разными сущностями, как в текущем provisioning
control plane.

Рекомендуемые stages:

```text
agent_started
network_ready
session_created
inventory_uploaded
waiting_for_approval
plan_received
plan_verified
disk_preflight
disk_partitioning
base_install
package_install
preinstall
bootloader
accounts
postinstall
reboot_pending
first_boot
bootstrap
registration
ssh_verification
complete
```

Ошибка сохраняет последний достигнутый stage и содержит allowlisted `error_code`.
Не строить состояние путём ненадёжного парсинга последней строки лога.

Пример error codes:

```text
network_unavailable
controller_unavailable
inventory_invalid
awaiting_approval_timeout
plan_invalid
plan_expired
plan_signature_invalid
disk_missing
disk_identity_changed
disk_ambiguous
disk_too_small
disk_is_boot_media
disk_profile_failed
package_install_failed
bootloader_failed
postinstall_failed
reboot_not_observed
bootstrap_failed
registration_failed
verification_failed
```

---

## 14. Локальный интерфейс

Полноценный графический frontend не требуется.

Минимальный foreground/TUI экран:

```text
SOSNADMIN ALT INSTALLATION

Session: install-...
Server: 192.168.100.17
Machine: QEMU / 8 GiB / 50 GiB

Status: waiting for administrator approval
Last server contact: 2 seconds ago
```

После начала:

```text
Status: installation in progress
Stage: installing system packages
Detailed logs: deployment server
```

При ошибке:

```text
INSTALLATION FAILED

Stage: disk_partitioning
Error: disk_profile_failed
Session: install-...

Diagnostics were sent to 192.168.100.17.
The machine will not reboot automatically.
```

Требования:

1. экран ошибки остаётся открытым;
2. показывает session ID;
3. показывает last server contact;
4. не выводит secrets, hashes, auth tokens или полные технические логи;
5. не показывает фиктивный процент, если Alterator не предоставляет достоверный
   progress; stage-based progress предпочтительнее.

---

## 15. Серверные логи и удалённое наблюдение

Нужно разделить структурированные events и raw log chunks.

### 15.1 Structured events

Пример:

```json
{
  "session_id": "install-...",
  "sequence": 18,
  "stage": "package_install",
  "state": "running",
  "message_code": "installing_packages",
  "created_at": "<UTC>"
}
```

Сервер проверяет monotonic sequence. Повтор того же event должен быть idempotent.

### 15.2 Heartbeat

Heartbeat включает только bounded runtime status:

```text
session_id
agent boot_id
state
stage
last local sequence
agent version
UTC timestamp
```

Он не должен использоваться как единственный источник завершённости этапа.

### 15.3 Raw logs

Нужно собрать, насколько технически доступно:

```text
install-agent.log
/root/.install-log/wizard.log
Alterator/autoinstall stdout+stderr
EVMS/disk profile output
pkg-install output
GRUB/bootloader output
postinstall output
filtered dmesg/bootstrap diagnostics
/var/log/alt-bootstrap.log после first boot
```

Log chunks содержат:

```text
session_id
stream name
chunk sequence
offset
byte length
SHA-256
UTC timestamp
```

Повторная доставка byte-identical chunk — no-op. Должны быть лимиты на chunk,
общий объём и retention. До загрузки применить redaction для password/hash/token/key
patterns. Server хранит raw logs root/private; UI показывает ограниченный tail и
санитизированное скачивание.

### 15.4 Потеря связи

До destructive approval:

```text
нет сервера -> установка не начинается
agent продолжает retry и показывает ошибку связи
```

После начала очистки/установки:

```text
временная потеря сервера не должна произвольно остановить Alterator
stages/logs буферизуются локально
после восстановления выполняется ordered replay
```

Локальный буфер должен иметь лимит и безопасное поведение при заполнении.

---

## 16. Почему нужен ранний install-agent

Текущий параметр `ai curl=...` запускает autoinstall сразу. При этом сервер ещё не
получил inventory и оператор не успел выбрать/утвердить plan.

Нужен ранний handoff:

```text
custom ISO/initrd boot
    -> agent starts before destructive Alterator sequence
    -> inventory/session/approval
    -> generated metadata downloaded locally
    -> agent starts or hands off to stock autoinstall
    -> agent observes process and uploads status/logs
```

Критический технический spike следующего этапа — доказать на точном ALT 11.4 ISO:

1. где безопасно встроить agent;
2. как запустить его после network init, но до metadata autoinstall;
3. как передать локально сгенерированные `autoinstall.scm`, `vm-profile.scm`,
   `pkg-groups.tar` и `install-scripts.tar` штатному установщику;
4. как получить exit/result boundary Alterator;
5. как сохранить локальный UI активным после ошибки;
6. как перехватить/tee ранние журналы без изменения их семантики;
7. как продолжить session после reboot.

Не начинать большой API/UI implementation, пока этот handoff не доказан небольшим
prototype на disposable VM.

---

## 17. Кастомный ISO

Нужна воспроизводимая сборка, а не ручное редактирование одного USB.

В Git хранятся:

```text
build scripts
boot-menu templates
agent source
initrd overlay/patch manifest
exact upstream ISO identity and expected SHA-256
build manifest
verification tests
```

Не обязательно хранить большой ISO binary непосредственно в Git. Готовый образ
может публиковаться в контролируемом внутреннем хранилище вместе с manifest и SHA.

ISO должен:

1. запускать agent без ручного `ai curl=...`;
2. иметь fallback normal install;
3. иметь diagnostics entry;
4. фиксировать agent/build/ISO version;
5. не содержать production password hashes, Vault, SSH private keys или destructive
   shared secret;
6. поддерживать выбранный firmware mode;
7. проверяться в Proxmox и затем на disposable physical target.

---

## 18. Предлагаемые компоненты репозитория

Имена предварительные и должны быть утверждены в design spec.

```text
deploy/alt-linux/autoinstall/
    profiles/
        standard-office.yaml
    templates/
        autoinstall.scm.j2
        vm-profile.scm.j2
    renderer/
        policy.py
        plan.py
        render.py
        validate.py

deploy/alt-linux/install-session/
    api.py
    models.py
    repository.py
    state_machine.py
    approval.py
    signing.py
    events.py
    log_store.py

deploy/alt-linux/install-agent/
    agent.py
    inventory.py
    session_client.py
    plan_verify.py
    disk_preflight.py
    progress.py
    log_upload.py
    local_ui.py
    first_boot_resume.py

deploy/alt-linux/iso/
    build-managed-iso.sh
    boot-menu/
    initrd-overlay/
    manifests/

tests/alt_linux/
    test_install_policy.py
    test_install_plan.py
    test_autoinstall_renderer.py
    test_install_session_api.py
    test_install_session_state.py
    test_install_agent_inventory.py
    test_install_agent_plan_verify.py
    test_install_agent_disk_preflight.py
    test_install_agent_log_replay.py
    test_managed_iso_build.py
```

Будущая UI-интеграция в `web_ovpn` должна быть отдельным delivery и обращаться к
constrained install-session API на `.17`.

---

## 19. Предлагаемые API boundaries

Точные URI могут измениться, но операции должны оставаться узкими:

```text
POST /install-sessions
PUT  /install-sessions/{id}/inventory
POST /install-sessions/{id}/heartbeat
GET  /install-sessions/{id}/status
POST /install-sessions/{id}/events
POST /install-sessions/{id}/logs/chunks
GET  /install-sessions/{id}/plan
POST /operator/install-sessions/{id}/approve
POST /operator/install-sessions/{id}/cancel
GET  /operator/install-sessions
GET  /operator/install-sessions/{id}
GET  /operator/install-sessions/{id}/logs/tail
```

Agent API и operator API должны иметь разные authorization boundaries. Operator UI
не передаёт Scheme или команды. Agent не может сам approve plan.

---

## 20. Безопасность и fail-closed правила

Обязательные правила:

1. никакой disk mutation до server approval и локальной plan verification;
2. server approval привязан к exact session, machine identity и disk fingerprint;
3. plan имеет expiry, revision, hash и подпись;
4. agent проверяет controller identity/подпись;
5. UI не принимает arbitrary Scheme, shell, Ansible или package commands;
6. generated files являются производными от validated InstallPlan;
7. все state transitions монотонны и аудируются;
8. logs ограничены, redacted и не выполняются как код;
9. ISO не содержит универсального destructive secret;
10. reference workstation `192.168.101.111` исключена;
11. при multiple disks или changed identity — stop;
12. при несовместимом firmware — stop до разметки;
13. при неподдерживаемом ISO/agent/profile version — stop;
14. старые install sessions не переиспользуются как новая approval;
15. завершённый plan и его rendered files сохраняются для аудита по hash, но secret
    material не сохраняется в Git/UI.

---

## 21. Не входит в первый этап

Не реализовывать одновременно:

```text
PXE/iPXE
zero-touch boot для всего LAN
массовую очередь установок
несколько функциональных profile policies
произвольный конструктор разделов
шифрование дисков
multi-disk RAID/LVM design
полный графический установщик
произвольные Alterator/Scheme команды из UI
прямой Ansible из install UI
office/application roles сверх уже выбранного package set
release/reassignment существующих рабочих станций
```

Сначала доказать безопасную управляемую установку одной disposable VM.

---

## 22. Рекомендуемое разбиение реализации

Не закрывать весь этап одним PR.

### PR A — ALT 11.4 early-agent technical spike

Цель: без disk mutation доказать запуск agent до autoinstall, DHCP, inventory,
session creation, ожидание server approval и локальный экран.

Deliverables:

```text
точная точка интеграции initrd/installer
prototype custom ISO
agent_started/network_ready/inventory_uploaded
server session fixture
никакой разметки диска
```

### PR B — Profile policy, InstallPlan и renderer

Pure/TDD слой:

```text
standard-office policy
inventory validation
whole-disk plan generation
disk/firmware/NIC selection
sanitized autoinstall.scm renderer
vm-profile.scm renderer
plan hash/signature envelope
snapshot tests
```

### PR C — Install-session API и durable state

```text
session repository
state/stage transitions
operator approval
ephemeral agent credential
heartbeat
events
bounded audit
```

### PR D — Agent plan verification и disk preflight

```text
signed plan polling
expiry/revision checks
disk fingerprint revalidation
boot-media exclusion
fail-closed error screen
без реальной очистки в первых tests
```

### PR E — Stock Alterator handoff и real disposable install

```text
download rendered metadata
start/handoff to autoinstall
observe stage boundaries
first real disk wipe only after explicit approval
VM acceptance
```

### PR F — Logs and recovery visibility

```text
raw chunk uploader
ordered replay
wizard/EVMS/pkg/GRUB streams
server tail
local buffering
redaction/limits
```

### PR G — Reproducible managed ISO

```text
no manual kernel command
UEFI boot menu
normal-install fallback
diagnostics entry
build manifest and SHA verification
```

### PR H — web_ovpn operator UI on 192.168.100.30

```text
waiting sessions
inventory view
exact disk/profile preview
approve/cancel
timeline
heartbeat
logs tail/download
no controller secrets
```

### PR I — end-to-end acceptance and closure

```text
32/50/100/200 GiB VM matrix
UEFI
multiple-disk blocker
changed-disk blocker
server-loss scenarios
reboot/session continuation
registration
SSH/Ansible verification
sanitized acceptance report
```

---

## 23. Acceptance matrix

Минимум проверить:

### Boot and ISO

```text
managed USB boots without manual ai/curl input
normal installer fallback works
agent/build/ISO identity reported correctly
wrong/unsupported ISO fails before disk mutation
```

### Hardware

```text
32 GiB candidate
50 GiB candidate
100 GiB candidate
200 GiB candidate
one disk
multiple disks
different NIC names
UEFI
Legacy behavior: supported or explicit pre-mutation rejection
```

### Plan safety

```text
expired plan
bad signature
wrong session
changed disk size
changed serial/WWN
USB selected as target
ambiguous disk
unsupported profile version
operator changes selection -> new revision and approval
```

### Connectivity

```text
server unavailable before approval
server unavailable while waiting
connection lost after disk mutation
ordered event/log replay
heartbeat timeout
agent reboot or crash before approval
```

### Installation

```text
disk profile success
package install success
bootloader success
postinstall success
reboot
first boot resumes exact session
bootstrap
registration
SSH verification
complete
```

### UI and logs

```text
local stage visible
local error remains visible
server timeline monotonic
raw logs bounded
redaction works
duplicate log chunk is no-op
operator can inspect failure remotely
```

---

## 24. Открытые решения для следующего чата

Следующий design должен явно закрыть:

1. ALT 11.4 становится единственным target или нужна совместимость 11.2/11.4.
2. Точная точка запуска agent внутри ISO/initrd.
3. Точный handoff в штатный autoinstall после получения plan.
4. UEFI-only для первого этапа или сразу UEFI+Legacy.
5. Minimum disk policy после измерений.
6. Swap policy: fixed, RAM-based или без swap для отдельных размеров.
7. Как вычислять package-set requirements и свободное место.
8. Формат и алгоритм подписанного plan.
9. HTTPS/CA/mTLS boundary для agent API.
10. Порт и systemd unit нового install-session API.
11. Первичная operator surface до интеграции с `.30`.
12. Retention install sessions и raw logs.
13. Как корректно перехватывать ранний `wizard.log`/stdout Alterator.
14. Как session ID безопасно переносится в установленную систему через reboot.
15. Как rotation/замена root и local-admin credentials входит в новый renderer.

Не отвечать на эти вопросы случайными правками production `autoinstall.scm`; сначала
создать утверждённый design и технический spike.

---

## 25. Немедленные operational замечания

До начала новой реализации:

1. не считать текущий static config универсальным;
2. не расширять его серией профилей только по размеру диска;
3. не копировать показанные password hashes в Git;
4. запланировать ротацию root и `osn-admin` credentials;
5. сохранить точный текущий working/failing evidence;
6. дождаться результата текущей 50 GiB OVMF установки и записать, прошла ли она
   полностью;
7. не менять accepted workstation;
8. любые изменения installed metadata на `.17` выполнять только с backup/evidence
   и отдельным rollout approval;
9. future install-agent work вести локально через Git/PR/CI, а контроллер использовать
   для exact-commit verification и явно одобренных тестов.

---

## 26. Готовый prompt для нового чата

```text
Работаем с репозиторием BorisDruzak/web_ovpn и ALT Workstation autoinstall.

Сначала прочитай из актуальной main:

docs/ALT_AUTOINSTALL_INSTALL_AGENT_REDESIGN_HANDOFF.md
docs/ALT_LINUX_AUTOINSTALL.md
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
deploy/alt-linux/README.md

Цель нового этапа: спроектировать USB + install-agent + кастомный ISO без ручного
ввода `ai curl=...`. Agent должен стартовать до разрушительного autoinstall,
отправлять bounded hardware inventory на 192.168.100.17, создавать install session,
ждать выбора администратора, получать подписанный immutable InstallPlan и только
после локальной проверки exact disk запускать штатный Alterator.

Используем один логический профиль standard-office. Размер диска сам по себе не
создаёт отдельный профиль: renderer формирует vm-profile.scm так, чтобы Btrfs занял
весь оставшийся диск. UI не принимает произвольный Scheme или shell.

Локальный интерфейс минимальный: ожидание, текущий stage, связь с сервером и
неисчезающий экран ошибки. На сервер уходят structured stages, heartbeat и bounded
raw logs; до approval недоступность сервера блокирует установку, после начала
установки логи буферизуются и отправляются повторно.

Не трогай 192.168.101.111. Не изменяй production controller или metadata в начале.
Первым deliverable должен быть design/spec и небольшой технический spike на точном
ALT KWorkstation 11.4 ISO, доказывающий ранний запуск agent и безопасный handoff в
stock autoinstall без очистки диска.

Разработку вести TDD, небольшими PR. Не объединять API, agent, renderer, ISO build,
logs и web UI в один PR. Перед каждым controller/VM mutation показать точную команду,
эффект, rollback и дождаться явного подтверждения.
```
