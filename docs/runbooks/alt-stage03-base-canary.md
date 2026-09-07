# ALT Linux stage 03: проверка и canary базовой настройки

> **Статус и границы:** это локальная/static процедура и шаблон evidence. Этот
> документ не подтверждает выполненный canary на развёрнутом контроллере;
> runtime-приёмка выполняется в Task 6 только после отдельно разрешённого
> deployment и успешного controller readiness. Документ не разрешает выбор
> машины, вызов `netctl`, изменение bootstrap, DNS/network policy, firewall/VPN
> или Vault.

Этот runbook относится только к настройке уже установленной ALT Workstation K
11.x. Он не устанавливает ОС, не меняет сетевую топологию или DNS-политику,
не запускает `netctl` и не включает установку прикладного ПО или KRFB.

Проверки выполняются на контроллере, где уже развёрнута соответствующая версия
`alt_deploy`. Сам этот документ не является разрешением на развёртывание
контроллера или выбор рабочей станции: для canary назначается отдельная уже
установленная тестовая машина.

## Область canary

Используйте только базовый профиль:

- `software_profile`: `base`;
- `remote_access_profile`: `none`;
- `assigned_domain_user`: `null`.

Фактическая последовательность в `03-configure-domain-workstation.yml`:

1. preflight;
2. проверка или подтверждённое изменение hostname;
3. обновление ОС и базовый набор;
4. prerequisites Group Policy и DNS;
5. безопасное присоединение к AD;
6. клиент Group Policy;
7. baseline доменного входа (`pam_mkhomedir`);
8. проверка домена и запись структурированного результата.

Роли не перезагружают станцию и не перезапускают пользовательскую сессию.
Если результат содержит `reboot_required: true`, оператор решает о единичной
перезагрузке только после успешного завершения всей последовательности.

## 1. Предварительные условия

- У контроллера есть текущая копия Ansible-проекта; по умолчанию это
  `/home/altserver/ansible`.
- Рабочая станция уже установлена вручную, прошла bootstrap и зарегистрирована.
- Выбранный UUID и IP соответствуют назначенной тестовой машине.
- На контроллере доступны закрытый SSH-ключ, `known_hosts` и Ansible Vault.
- В request-файле нет пароля, ключа, Vault-значения или других секретов.

Не используйте `hostname_mode: change_confirmed`, если переименование не было
явно одобрено. Для обычного canary нужен `hostname_mode: verify`.

## 2. Проверка контроллера и синтаксиса

Все команды controller-side выполняйте от `altserver`, чтобы не создать файлы
состояния, недоступные сервисной учётной записи.

```bash
sudo -u altserver /usr/local/sbin/workstationctl --json controller readiness
```

Ожидаемый результат: `status` равен `ok`, `controller_readiness.ready` равен
`true`, а `controller_readiness.checks.ansible_manual_configure_syntax` равен
`true`. Эта проверка также убеждается в доступности Vault, runtime-файлов и
остальных базовых проверок контроллера.

Проверка синтаксиса stage 03 входит в readiness и выполняется контроллером.
Оператор не запускает `ansible-playbook` напрямую. Если у контроллера
переопределены `ALT_DEPLOY_ANSIBLE_PROJECT`, `ALT_DEPLOY_ANSIBLE_PLAYBOOK` или
иной путь runtime, проверяйте фактическое значение через разрешённый
controller readiness result, а не обходите fixed path.

При ошибке readiness или syntax check остановитесь: не запускайте canary,
не исправляйте проблему ручным запуском playbook на рабочей станции и не
изменяйте конфигурацию сети в рамках этого runbook.

## 3. Подготовка не секретного request-файла

Создайте защищённый файл, доступный `altserver`, с конкретным зарегистрированным
UUID и именем test-пользователя домена. Заполните только значения назначенной
машины:

```json
{
  "machine_uuid": "<registered-uuid>",
  "final_hostname": "alt-a1-pc3",
  "hostname_mode": "verify",
  "profile": "standard-domain",
  "domain": "sosnadmin.local",
  "realm": "SOSNADMIN.LOCAL",
  "workgroup": "SOSNADM",
  "computer_ou": "OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local",
  "domain_test_user": "<existing-domain-user>@sosnadmin.local",
  "software_profile": "base",
  "remote_access_profile": "none",
  "assigned_domain_user": null
}
```

`<registered-uuid>` в имени команды и поле `machine_uuid` должны совпадать.
Доменная учётная запись должна уже существовать; этот путь не создаёт AD-пользователей.

## 4. Preview без изменений

Сначала выполните только preview:

```bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure preview \
  <registered-uuid> --vars-file /path/to/request.json
```

До `start` сверяйте в ответе:

- `machine_uuid` и `target_ip` принадлежат назначенной canary-машине;
- `playbook` равен `03-configure-domain-workstation.yml`;
- `actions` описывает только базовую stage‑03 настройку;
- `deferred_actions` пуст;
- request соответствует base/none профилю выше.

Preview не проверяет DNS, время, hostname или AD-доступность станции и не
выполняет изменений.

## 5. Запуск и приёмка

Только после успешного review preview запустите фиксированный controller path:

```bash
sudo -u altserver /usr/local/sbin/workstationctl --json configure start \
  <registered-uuid> --vars-file /path/to/request.json
```

Контроллер использует строгую SSH-проверку ключа хоста и запускает только
`03-configure-domain-workstation.yml`; напрямую запускать playbook с рабочей
станции не нужно и нельзя.

Успешный ответ имеет структурированную схему `schema_version: 1`, содержит
`status: successful` или `status: degraded`, `error: null`, `components` и
`verification`. Зафиксируйте только run ID, статус, hostname, значения boolean
из `verification` и `reboot_required`; не переносите приватный Ansible-лог в
тикеты или общие хранилища.

Подтвердите на назначенной станции:

- DNS/KDC разрешаются с текущими настроенными серверами DNS;
- `net ads testjoin` успешен;
- SSSD отвечает на проверку доменного пользователя;
- Group Policy обновлён;
- если `reboot_required` равен `true`, после одного согласованного reboot
  выполняется доменный вход и создаётся домашний каталог пользователя.

Повторный base/none запуск после успешного canary должен подтвердить уже
существующее доверие Samba, не выполнять повторное присоединение и не изменять
существующий компьютерный объект AD.

## 5a. Профильные gates (без изменения base canary)

Этот runbook описывает базовый canary; остальные профили запускаются только
через тот же `configure preview` → review → `configure start` маршрут.

Для `software_profile: core-apps` start допустим только после успешного
preflight каждого выбранного approved artifact. При любом missing, checksum,
package-metadata или executable failure весь профиль останавливается до
установки компонентов. В публичный результат записываются только boolean
факты `software_browser`, `software_onlyoffice` и
`software_nextcloud_desktop`.

Для `remote_access_profile: krfb` до start отдельно подтверждаются:

- наличие обоих требуемых Vault-полей (проверка присутствия, без чтения или
  записи значения);
- один явно указанный уже существующий domain user;
- `ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED=true` на контроллере;
- отдельное evidence, что существующая VPN/firewall policy ограничивает TCP
  5900.

Этот gate не открывает порт и не изменяет firewall/VPN. KRFB не запускается
контроллером; после успешной настройки он может появиться только в обычном
графическом входе назначенного пользователя. При отсутствии любого evidence
остановитесь и не пытайтесь обойти gate.

## 6. Остановка и диагностика

При ненулевом завершении публичная ошибка controller path содержит безопасный
`run_id`. Частные артефакты запуска расположены по умолчанию в
`/var/lib/alt-deploy/configure-runs/<run_id>/`: `request.json`, `result.json`
и `ansible.log`; доступ к ним имеет только уполномоченный оператор.

Остановитесь при `hostname_mismatch`, `domain_computer_conflict`,
`domain_join_timeout`, ошибке readiness или любой нераспознанной ошибке. Не
удаляйте, не переносите, не сбрасывайте и не переиспользуйте объект компьютера
AD для «исправления» canary. Сначала сохраните run ID и локально разберите
приватный лог; повторный запуск допустим лишь после устранения подтверждённой
причины и нового preview.

Этот runbook не содержит операции rollback контроллера: откат его релиза и
любые изменения инфраструктуры выполняются только отдельной утверждённой
процедурой.
