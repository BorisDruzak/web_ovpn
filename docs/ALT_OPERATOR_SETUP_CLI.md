# ALT Workstation: операторский AD Setup CLI V1

CLI настраивает уже установленную ALT Workstation для существующего сотрудника AD. Оператор работает в терминале контроллера без Codex. ISO/PXE, сеть и веб-панель в этот workflow не входят.

## Допуск и подготовка

Администратор подтверждает конкретный зарегистрированный ПК, сотрудника, точную OU, профиль и действия. Для настроенного ПК сначала разрешается только чтение/планирование. План описывает намерения stage-03; он не является Ansible dry-run и не гарантирует `changed=0` всех baseline-ролей. Исправное trust исключает повторный join, однако apply может обновить baseline, программы и GPO.

Для первого join выделить разрешённый новый/disposable ПК. Проверка настроенного ПК не доказывает первый join. Перезагрузка и завершение сеанса требуют отдельного разрешения; CLI их не выполняет. Принятый эталонный ПК не использовать для destructive acceptance.

Exact проверенный SHA устанавливать штатным guarded deployment path, без обхода `alt-deploy-guard`. До deployment необходимы Controller Readiness, отсутствие несовместимых jobs, актуальные OR-3P3 backup/rehearsal evidence и независимый recovery access. Сохранять Vault, ключи, регистрации, jobs и оба вида assignments. Git, deployment и acceptance ПК — отдельные gates.

Действующий OR-3P3 component `controller_state` архивирует весь `/var/lib/alt-deploy` без исключений, включая `domain-assignments`, `setup-plans`, `setup-runs` и `setup-plan-runs`. Отдельный root-owned `/etc/alt-deploy/ad-directory.json` в этот component не входит: перед deployment сохранить его отдельно с ownership/mode и проверить восстановление утверждённых OU. Отсутствующая конфигурация оставляет OU allowlist пустым и блокирует новые планы.

Нужны существующие Python 3.12/Ansible/SSH prerequisites, OpenLDAP `ldapsearch`, Kerberos `kinit`/`kdestroy`. На ПК probe использует Python 3, passwordless sudo, `system-auth`, Samba `net`, SSSD и `getent`.

```sh
sudo -u altserver /usr/local/sbin/workstationctl --json controller readiness
sudo -u altserver /usr/local/sbin/workstationctl --json vault check
sudo -u altserver /usr/local/sbin/workstationctl --json jobs active
```

## Directory configuration и права

`/etc/alt-deploy/ad-directory.json`: root-owned, без group/other write, без секретов. Для чтения сервисной учёткой использовать mode `0644`; изменять файл может только root. Пример использует synthetic OU; реальная OU утверждается отдельно:

```json
{
  "uri": "ldap://sosnadmin.local",
  "auth": "gssapi",
  "credential_source": "join-vault",
  "approved_ous": ["OU=ApprovedComputers,DC=sosnadmin,DC=local"]
}
```

Без файла разрешены read-only queries через временный ticket из существующего join Vault, но approved_ous пуст и setup plan блокируется. Department-to-OU mapping в V1 отсутствует: OU выбирается явно, никогда из DN сотрудника.

GSSAPI требует confidentiality `minssf=56`. Источник `ticket` использует заранее выданный cache; `join-vault` получает временный ticket из существующих делегированных credentials; `readonly-vault` использует отдельные `vault_ad_readonly_user` и `vault_ad_readonly_password`. Adapter выполняет только LDAP search. Пароль поступает kinit через stdin; private cache удаляется.

Fallback `auth=starttls` требует `ldap://`; `auth=ldaps` требует `ldaps://`. Оба требуют отдельного `readonly-vault` и `ca_file`. Certificate/SAN verification обязательны; незашифрованного password bind нет. ldapsearch читает пароль из временного файла `0600`, argv содержит только путь.

Read identity нужны права чтения user/computer/OU и computed account-state attributes. UNKNOWN блокирует setup. Join identity нужны делегированные права штатного создания computer object только в утверждённой OU; Domain Admin не обязателен. Read-only lookup не доказывает это право: предупреждение сохраняется, недостаточные права требуют действия AD administrator.

## Сценарий оператора

Все команды AD/Setup выполнять от одной сервисной учётки `altserver`: protected plan/run/binding-файлы принадлежат ей и имеют mode `0600` в каталогах `0700`. Примеры ниже предполагают SSH-сеанс `altserver`; из другой административной учётки использовать `sudo -u altserver -H /usr/local/sbin/workstationctl ...`. Не смешивать root и altserver между plan/apply/status/verify. Root используется для deployment, directory configuration и штатного архивирования регистраций.

Поиск V1 точный по sAMAccountName/UPN. Частичного автоматического выбора нет:

```sh
workstationctl ad users search --login synthetic.user
workstationctl ad users show --login synthetic.user@sosnadmin.local
workstationctl ad ous list
workstationctl ad computers check --hostname alt-a1-pc3
workstationctl machines list
workstationctl setup plan --machine 11111111-2222-3333-4444-555555555555 \
  --user synthetic.user --computer-ou 'OU=ApprovedComputers,DC=sosnadmin,DC=local' \
  --software-profile core-apps
```

Добавлять `--json` перед командой для automation. AD display диагностирует disabled/locked/expired, а plan такие accounts отвергает. Machine selector — UUID либо уникальный зарегистрированный hostname; IP не идентификатор.

Проверить UUID/hostname/IP, сотрудника и GUID/SID, точную OU, computer object, domain/trust, profile, prerequisites, changes, warnings и deferred actions. Plan выполняет read-only AD/SSH и localhost component preflight; создаёт только защищённый план. Registry и assignments не переписываются.

core-apps использует действующий stage-03 catalog, включая CryptoPro, CAdES и ГосПлагин. License/Vault/artifacts проверяются до изменений ПК. base — минимальный профиль. Remote profile по умолчанию none. KRFB opt-in через `--remote-access-profile krfb`, дополнительно требуется существующее явное `ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED=true`. CLI его не выставляет.

Полный SHA связывает payload, source fingerprint и metadata/TTL 30 минут. content_sha256 детерминирован для одинакового семантического payload. При одинаковом времени/observations план одинаков; новый момент или состояние меняют полный SHA. Сохранённый JSON не редактировать.

```sh
workstationctl setup apply PLAN_ID --confirm-sha256 FULL_SHA256
workstationctl setup status RUN_ID
workstationctl setup verify --machine 11111111-2222-3333-4444-555555555555
```

Apply повторно проверяет AD/ПК/prerequisites под lifecycle lock. Drift требует нового плана. Только ConfigurePlanner и фиксированный stage-03 playbook; произвольные shell/playbook/Ansible vars отсутствуют. Test/assigned user — один выбранный UPN.

Domain assignment хранится отдельно: UUID, GUID/SID, login, OU, profiles, revision, run ID, дата/результат. Иная привязка блокируется; смена сотрудника вне V1. Один сотрудник допустим на нескольких ПК. Local provision assignment требует compatibility review; автоматической конверсии нет. Старые configure/provision сохранены для unbound ПК и блокируют обход managed domain assignment.

Status содержит configuration run ID, компоненты, GPO evidence, trust/SSSD/user verification, reboot requirement и deferred actions. Read-only verify показывает текущую identity/trust и group_policy_last_run из configure result; GPO update делает только pipeline. Home-dependent операции откладываются до первого domain login; затем пройти existing component acceptance checklist.

## Отказы и ручное продолжение

| Коды | Действие |
|---|---|
| ad_user_not_found / ad_user_ambiguous | Выбрать точную существующую запись; пользователей не создавать |
| ad_user_disabled / locked / expired / password_expired | Обратиться к AD administrator; CLI account не исправляет |
| ad_user_state_unknown / identity_invalid | Проверить атрибуты/read permissions; UNKNOWN не обходить |
| ad_dc_unavailable / timeout / tls_failed / kerberos_failed | Исправить connectivity/trust/time/credentials; verification не отключать |
| setup_ou_not_approved / not_found | Утвердить точную существующую OU |
| domain_computer_conflict / domain_conflict | Отдельный recovery review; account не удалять, не двигать и не сбрасывать |
| assignment_conflict / setup_assignment_managed | Корректный setup workflow; assignments не удалять для обхода |
| setup_plan_expired / mismatch / drift | Новый план и его полный SHA |
| setup_component_prerequisites_failed | Исправить catalog/artifacts/Vault до повторного plan |
| setup_execution_failed / previous_run_unresolved | RUN_ID из вывода → status → private result/log и фактическое состояние |

Failed/running/interrupted run автоматически не повторяется. V1 требует отдельного reviewed recovery workflow после ambiguous failure; удаление jobs/assignments не поддерживается. Exact завершённый plan возвращает сохранённый результат без execution. Новый безопасный повтор требует нового проверенного плана.

Для частичного первого join реализовано чтение и сохранение [отдельного recovery-плана](superpowers/plans/2026-10-11-alt-partial-join-recovery.md). После установки проверенной версии контроллера оператор может выполнить:

```sh
workstationctl setup recovery plan --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXISTING_COMPUTER_GUID
```

UUID/hostname, сотрудник, OU и профили берутся из защищённой истории исходной ошибки. GUID должен совпасть с единственным существующим компьютером; OU/user identities, время создания объекта, writable DC, регистрация, задания, текущее состояние авторизации, хеши фиксированных файлов/утилит, часы и prerequisites проверяются заново. Сохранённые исходные plan/run/index/binding/configuration result перечитываются и остаются побайтно неизменными. Несовпадение возвращает `recovery_current_state_invalid`; неполная история — `recovery_history_invalid`; неверный компьютер — `recovery_computer_identity_invalid`. Уже существующая попытка, включая прерванную или повреждённую, блокирует новый план с `recovery_attempt_reserved`.

Допускается также одна строго проверенная цепочка: закрытый первоначальный
таймаут обновления до join (binding revision 1), затем отдельный закрытый отказ
первого join (revision 2). Новый исходный план должен уже содержать хеши прежних
run/plan/request/log; оба index, идентичности и порядок времени проверяются
повторно. Отсутствие файлов, изменение хешей, следы join в прежнем журнале,
неизвестный результат или дополнительная revision блокируют чтение. Сохранённый
результат recovery проверяет ту же цепочку после продолжения Setup. Это только
проверка истории: она не разрешает сброс, replay или изменение assignment.

План имеет TTL 30 минут, SHA и отдельное пространство `recovery-`; normal `setup apply` его не принимает. Вывод содержит **Execution available: false** и оставшиеся gates. Исполнение доступно только через отдельный операторский execution-plan и его точный SHA, описанные ниже. Планирование не резервирует попытку, не сбрасывает пароль и не разрешает повторный join. Время создания — свидетельство для проверки, не доказательство принадлежности объекта оператору. Исполнение требует проверенного фиксированного GUID-only provider/local importer, сохранённого credential и backup, повторных проверок под lifecycle lock и отдельного разрешения на конкретный объект/план. Предварительная проверка GUID не делает повторный join по hostname безопасным.

Для подготовки review локальных эффектов служб доступен отдельный read-only сбор:

```sh
workstationctl setup recovery startup-inventory --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXACT_EXISTING_COMPUTER_GUID
```

Команда повторно проверяет тот же failed run, регистрацию, AD и текущие файлы ПК,
затем фиксированным SSH/bootstrap собирает консервативный граф systemd. Она
сохраняет собственное защищённое evidence и краткий план с TTL 30 минут,
SHA-256, числом units и возможных jobs. Большой граф хранится отдельными
неизменяемыми частями; команды и environment представлены только хешами.
Она не резервирует recovery attempt и не запускает службы. Возможные jobs не
являются прогнозом фактической транзакции, а digest графа не заменяет review
hooks, environment, manager actions и unresolved destinations. Этот план
также выводит **Execution available: false** и не принимается `setup apply`.

Внутренняя проверка выбранного пользователя через NSS подготовлена и описана
в [отчёте](verification/ALT_RECOVERY_USER_OBSERVATION_2026-10-12.md). Отдельной
The selected-user observation now belongs to the SHA-confirmed operator
execution envelope; older preparation plans do not grant execution authority.

Фиксированный stdin/bootstrap транспорта уже подготовлен и проверяет
источники до исполнения; [отчёт транспорта](verification/ALT_RECOVERY_USER_WIRE_2026-10-12.md)
отдельно описывает его ограничения. Сам builder не выполняет SSH и не
подтверждает полномочия оператора.
Отдельный [bundle-канал](verification/ALT_RECOVERY_BUNDLE_CHANNEL_2026-10-12.md)
теперь принимает фиксированные source envelopes до 1 МиБ с прежним лимитом
ответа 16 КиБ. Startup/native runtimes используют его по умолчанию; обычные
native-команды сохраняют предел stdin 128 КиБ. NSS controller runtime подключён к фиксированной операторской цепочке, описанной ниже.
Разрешение пользователя через NSS не подтверждает парольный или графический
вход. Возврат штатной политики и служб остаётся отдельной частью recovery.

Пароли/tickets/private keys/raw diagnostics в output не выводятся. State/logs доступны только сервисной учётке. Public reports обезличивают реальные identifiers.

## Live acceptance

L0: цель/действия. L1: real user GUID/SID/state, OU, computer. L2: plan/no mutations. L3: approved guarded deployment и confirmed apply. L4: trust/SSSD/getent/GPO/no local duplicate/identity continuity/repeated plan. L5: safe negatives без AD writes. Graphical login/home после reboot — только с отдельным разрешением. Code/CI/readiness эти gates не заменяют.

Контроллерная проверка связывает явное combined-подтверждение со свежим состоянием
сотрудника, исходными зависимостями и защищёнными startup/native receipts.
Фиксированный SSH transport сохраняет intent/result/failure и отказывает при
повторном запуске либо изменении данных. См. [отчёт](verification/ALT_RECOVERY_USER_CONTROLLER_2026-10-12.md).
Эти классы теперь используются фиксированным operator coordinator.
Coordinator uses genuine authority from the confirmed operator envelope,
including fixed terminal handoff. Live recovery acceptance requires separate
approval and execution.

Подготовлена отдельная внутренняя [проверка исходной конфигурации SSSD](verification/ALT_RECOVERY_ORIGINAL_POLICY_2026-10-12.md).
Она читает сохранённый main config в фиксированном sandbox без recovery-snippet
и сравнивает ту же конфигурацию после отсутствия snippet. Отсутствующие параметры
не подтверждают runtime defaults; службы, snippet и credentials эта проверка не
изменяет. Её source bundle и receipt ещё должны войти в отдельное подтверждение
terminal handoff; возврат политики теперь реализован отдельным фиксированным этапом.

Внутренний [baseline collector](verification/ALT_RECOVERY_POLICY_BASELINE_2026-10-12.md)
теперь читает исходную конфигурацию до reservation, без будущих import/startup
receipts. Стабильные поля сравниваются с поздним observer; runtime defaults и
работа служб этим не подтверждаются. Операторская команда описана ниже;
стабильная projection привязана к terminal approval в operator envelope.

Для подготовки read-only baseline после установки проверенного кода:

```text
workstationctl setup recovery policy-baseline --failed-run RUN_ID --computer-guid GUID
workstationctl --json setup recovery policy-baseline --failed-run RUN_ID --computer-guid GUID
```

Используйте исходный failed-run и точный GUID выбранного компьютера. Машина,
сотрудник и OU берутся из защищённой истории; произвольные root/vars/playbook
параметры не принимаются. Команда сохраняет собственный private план с TTL
30 минут и SHA-256, не резервирует recovery attempt и не меняет AD, службы,
credentials или конфигурацию ПК. Только private parser scratch создаётся и
удаляется. Вывод `Execution available: false` и `Defaults verified: false`
означает, что ещё нужны review runtime defaults/effects и отдельный terminal
handoff plan. Этот baseline не принимается `setup apply` и не подтверждает trust,
парольный или графический вход. Проверки и ограничения описаны в
[отчёте CLI](verification/ALT_RECOVERY_POLICY_BASELINE_CLI_2026-10-12.md).

Для отдельного сбора operative settings и runtime dependencies после установки
проверенного кода:

```text
workstationctl setup recovery policy-effects --failed-run RUN_ID --computer-guid GUID
workstationctl --json setup recovery policy-effects --failed-run RUN_ID --computer-guid GUID
```

Команда заново читает тот же зарегистрированный ПК и защищённую историю,
собирает baseline и расширенный inventory в одном фиксированном SSH/bootstrap.
Она сохраняет собственный план с TTL 30 минут и SHA-256. Доступны configured
presence/value для фиксированного набора identity/renewal/DNS options,
имена прочих параметров и метаданные зависимостей. Значения произвольных
параметров и private-key contents не выводятся; неизвестные имена остаются
непроверенными. Краткий вывод показывает их число.

`Execution available: false`, `Defaults reviewed: false` и
`Effects reviewed: false` означают, что этот inventory ещё не разрешает
возврат штатной политики или recovery apply. Он не резервирует attempt,
не открывает recovery credential и не запускает службы/AD/DNS операции.
Только private parser scratch создаётся и удаляется. Перед terminal handoff
нужен отдельный reviewed manifest, который описывает helper behavior,
conditional AD attribute/DNS RRset changes и оставшиеся ограничения.
Этот план не принимается `setup apply`. См.
[отчёт транспорта/CLI](verification/ALT_RECOVERY_POLICY_EFFECTS_CLI_2026-10-12.md).

Текущий фиксированный recovery apply, terminal handoff и новое Setup продолжение
описаны в [операторском recovery workflow](ALT_RECOVERY_OPERATOR.md). Старые
read-only plans не являются разрешением на эти операции.

### Обновление новой VM и отказ до join

Для штатных подписанных p11-источников bootstrap и `prejoin_upgrade` выбирают
`https://download.basealt.ru/pub/distributions/ALTLinux`. Ветка, архитектуры,
компоненты и параметры проверки подписей сохраняются. Другие репозитории и
закомментированные строки не заменяются; уже доменный ПК ролью не переключается.

План новой установки показывает смену источника, полный upgrade перед join и
бюджет выполнения 21600 секунд (6 часов). Это бюджет запуска, а не TTL плана:
подтвердить SHA и начать apply по-прежнему нужно в течение 30 минут. Для уже
настроенного ПК сохранён бюджет 5400 секунд. Таймаут обновления нового Setup
обозначается `setup_upgrade_timeout`, а поле `failure_phase` в status указывает
фактическую фазу; такой отказ сам по себе не означает ошибку Samba join.

После подтверждённого таймаута в `prejoin_upgrade` оператор может выполнить
обычные `setup plan` и `setup apply` заново с теми же UUID, сотрудником, OU и
профилями. CLI проверяет защищённую историю и исходный план, отсутствие
компьютерного объекта AD, доменного состояния, машинных credentials и активных
процессов предыдущего запуска. Новый план содержит ссылку на сохранённый
failed-run и hashes его evidence; apply заново проверяет условия под lock.
Закрытый run и старый plan не переисполняются; новая привязка получает новую
revision. Изменения пользователя, сброс компьютерного пароля и новые backups
в это продолжение не входят.

Если фазу, завершение процессов или отсутствие credentials невозможно
подтвердить, сохраняется `setup_previous_run_unresolved`. Отказы после join,
UNKNOWN, существующий AD-объект и конфликт привязки требуют отдельной процедуры.
Удалять state/assignments или редактировать внутренние JSON для продолжения
нельзя.

### Права первого join и необязательные сведения об ОС

Штатный ALT `system-auth` передаёт Samba `osName` и `osVer`. Это включает
отдельную запись `operatingSystem`, `operatingSystemVersion` и
`operatingSystemServicePack` до сохранения машинных credentials. Делегированные
права создания компьютера, смены его пароля и validated writes для DNS/SPN
не означают права записи этих трёх атрибутов.

Фиксированный адаптер первого join исключает оба необязательных OS-аргумента,
не расширяя ACL AD. Он проверяет форму native вызова и сохраняет выбранные OU,
DC, Kerberos, credential cache и `--no-dns-updates`. Неожиданная форма вызова
блокируется до запуска Samba. Этот фильтр действует и на более новых версиях
Samba; отдельная offline-генерация keytab остаётся только для затронутой 4.21.
Заполнение OS-атрибутов компьютера в AD не является частью Setup.
Существующие объекты по-прежнему не допускаются
к автоматическому сбросу или повторному join.

## First join without an AD computer

Use the operator-only [partial-local recovery runbook](runbooks/alt-partial-local-recovery.md). It preserves the old UNKNOWN and requires separate exact recovery and new Setup confirmations.
