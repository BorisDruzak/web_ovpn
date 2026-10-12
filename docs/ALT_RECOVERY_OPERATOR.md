# ALT: ограниченный операторский recovery и продолжение Setup

Только восстановление выбранного существующего computer account после первого
частичного join. Employee, UUID/hostname, GUID/SID, OU и profiles берутся из
защищённой истории исходного failed-run. Другой компьютер, пользователь, пароль,
playbook, command, root или vars-file через этот CLI выбрать нельзя.

Установите проверенный exact SHA штатным guarded deployment после Controller
Readiness и свежих OR-3P3 backup/verify/rehearsal. Code/CI/read-only план не
подтверждают выполненный recovery или acceptance реального рабочего места.

## Операторский план и единственное подтверждённое выполнение

```sh
workstationctl setup recovery execution-plan --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXISTING_COMPUTER_GUID
workstationctl --json setup recovery execution-plan --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXISTING_COMPUTER_GUID
```

Команда читает AD и ПК, проверяет исходную конфигурацию native SSSD parser,
stock systemd/Samba units, packaged helper bytes, environment и version-pinned
default/effect manifest. Она сохраняет отдельный immutable operator envelope
с SHA и TTL 30 минут. В него входят exact SHA recovery/startup/terminal subplans,
computer/user identities и reviewed source/target projection. Большой systemd
graph хранится отдельным diagnostic evidence; его транзитивные possibilities не
разрешают исполнять дополнительные jobs. Unknown hooks/options/environment,
неподдерживаемая версия, credential/TLS override и drift отклоняются.

Просмотрите все identities, side effects, SHA и expiry. Только после явного
разрешения на этот объект и план:

```sh
workstationctl setup recovery apply OPERATOR_PLAN_ID --confirm-sha256 OPERATOR_SHA
```

Один operator SHA подтверждает неизменный набор subplans. Перед reservation и
каждой фиксированной external operation проверяются operator intent/ready,
планы, источники и protected provenance. Stages владеют своими lifecycle locks;
внешнего повторного lock вокруг всей цепочки нет.

Фиксированный порядок: approval binding → retained credential/controller and
workstation backups/rehearsal → service preparation/quiescence → один GUID-only
machine-password Modify → local credential import → machine Kerberos proof →
temporary suppression install/verify → один SSSD start → native trust/NSS proof →
terminal handoff. Повторный join по hostname, второй ручной reset, password
rollback, автоматический restart/cleanup после ошибки и replay не поддерживаются.

## Штатная политика SSSD и границы доказательства

Terminal intent сохраняется до остановки. Проверяется текущая suppressed
invocation, SSSD останавливается один раз, отсутствие PID/jobs проверяется,
удаляется только exact owned snippet, original main config сохраняется и
повторно проверяется. Восстанавливаются только первоначально активные smb/nmb;
winbind и первоначально inactive units остаются inactive. Normal SSSD start
выполняется один раз с новой invocation/NRestarts=0. Fresh machine trust, current
service state, NSS и AD GUID/SID/OU/domain/KVNO проверяются заново.

Возврат обычной политики может включить native renewal, Samba credential/cache
effects, AD hostname/encryption/SPN reconciliation и DNS A/AAAA/PTR RRset updates
с partial success. Native discovery не считается GUID или peer pinning.
Поддерживаемый manifest фиксирует версии, package sources, helper bytes,
configured presence и source-supported defaults. SSSD может автоматически
добавить PAC responder. Service credential cache проверяется только по metadata;
его contents/principal не читаются, а создание tickets не доказывает authentication.

В этой версии любое изменение manually reset KVNO/credential или exact AD
continuity остаётся UNKNOWN: безопасная attribution обычной renewal не
утверждается. Entered attempts и intent остаются неизменными и исключают replay.
Ни NSS lookup, ни fresh machine trust не доказывают employee GUI/password login.

```sh
workstationctl setup recovery status --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXISTING_COMPUTER_GUID
```

Это чтение сохранённого результата, а не resume и не текущий live PASS.

## Новый Setup после recovery

```sh
workstationctl setup recovery continue-plan --failed-run ORIGINAL_FAILED_RUN \
  --computer-guid EXISTING_COMPUTER_GUID
```

Команда требует retained successful terminal plus fresh current verification,
создаёт additive resolution и новый обычный Setup plan/SHA/TTL. Старые failed
plan/run/index/configuration-result не меняются. Все пять исходных byte blobs,
включая failed binding, архивируются неизменно до обычной новой binding revision.
Recovery/reset/handoff оставляет все пять live paths прежними; отдельный normal
Setup apply законно продвигает latest binding. Это не переименование failed-run
в success и не повтор старого плана. Historical archive остаётся читаемым.

```sh
workstationctl setup apply NEW_SETUP_PLAN_ID --confirm-sha256 NEW_SETUP_SHA
```

Перед dispatch снова проверяются current terminal proof и исходные identities;
после dispatch existing normal Setup checks оценивают текущую конфигурацию.
Обычный stage03 restart не обязан сохранять retired recovery invocation.
Existing fixed stage03 используется без нового join только при fresh machine
trust/identity. GUI login/home, GPO и core-apps/signature suite проверяются
отдельно на выбранном ПК после разрешённого выполнения.

Старые `recovery plan`, `startup-inventory`, `policy-baseline`, `policy-effects`
остаются read-only/non-executable preparation commands. Их SHA не заменяют
operator envelope и не разрешают recovery apply.
