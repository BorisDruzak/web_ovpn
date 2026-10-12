# Проект: отдельный recovery после доказанного locale-отказа rehearsal

Статус: пользователь подтвердил проект и реализацию; код допуска ещё не написан.
Подтверждение проекта разрешает реализацию и проверки, но не новый machine reset.
Перед reset требуется отдельное подтверждение конкретного installed operator SHA.

## Цель и границы

Завершить recovery выбранного ранее тестового ПК и вернуть возможность штатного
Setup после единственного нового разрешённого сброса машинного пароля. Пользователь,
computer GUID/SID/OU и исходная failed Setup history остаются прежними.

Первая попытка A закрыта после backup preflight failure. Единственная разрешённая
для неё successor-попытка B закрыта после backup rehearsal failure. В обеих запись
в AD и изменения auth/service state на ПК не начинались. A и B не возобновляются;
claims, intents, receipts, protected envelopes и admission B не заменяются.

Добавляется один отдельный корректирующий контекст C только для указанного ниже
доказанного класса отказа B. Это явное расширение прежнего ограничения на lineage;
не общий retry/resume и не разрешение создавать неограниченную цепочку successors.
У C нет допустимого следующего successor в этом проекте.

## Допуск C: все условия обязательны

1. B выбирается по protected operator ID и exact SHA. Его исторические subplans
   проверяются на момент исходного подтверждения; их истёкшие TTL не становятся
   текущими полномочиями. B связан с той же failed-run/computer GUID парой.
2. Исходный immutable admission B и вся замороженная цепочка A остаются точными.
   Все записи B и четыре B envelopes читаются из его защищённого контекста;
   полный состав prefix artifacts фиксируется и сравнивается byte-for-byte.
3. B имеет завершённые operator/coordinator failure records, prepare/bind outcome,
   claim/sealed credential/preparation records и failed preparation receipt.
   Controller backup intent и failure сохранены, успешный preparation receipt
   отсутствует. Любой дополнительный поздний stage или неоднозначность — отказ.
4. Native audit B содержит ровно соответствующие create PASS, verify PASS и
   rehearse FAIL/backup_rehearsal_failed. Backup ID и защищённые manifest/verification
   hashes однозначно совпадают; rehearsal receipt отсутствует. Existing verify или
   rehearse не вызываются повторно и не заменяют историческое evidence.
5. Retained rehearsal tree проверяется фиксированным ограниченным read-only
   worker: metadata, source/shell/systemd/Ansible syntax, state и secret exclusion.
   Проверка fixed C environment воспроизводит только UTF-8 locale startup refusal;
   fixed C.UTF-8 проходит. Raw logs, Vault и секретные значения не экспортируются.
   Неизвестный/иной rehearsal failure не допускается этим проектом.
6. Требуется установленная и byte-verified исправленная версия native backup
   recovery caller с C.UTF-8. Фиксируются её source fingerprint, версия Ansible,
   доступность locale и hashes использованных проверяемых worker/tool sources.
7. Свежие AD/employee/OU/registration/workstation snapshots совпадают с B и A,
   кроме явно ожидаемого source fingerprint исправленного кода. Password metadata,
   GUID/SID/OU, auth files/tools и original history неизменны.
8. На ПК отсутствуют ВСЕ фиксированные recovery footprints для этой пары;
   controller/PC не имеют активного recovery. Native operation lock, guard,
   quiescence, readiness и disk capacity проходят. UNKNOWN/refusal не обходятся.
9. Есть место для нового guarded deployment backup, его rehearsal, runtime
   recovery backup и rehearsal. A/B evidence, failed backup/tree и свежие rollback
   copies сохраняются. При необходимости используются только ранее разрешённые
   штатные guarded удаления старых backup bundles, без ручной очистки evidence.

## Сохранение и композиция

Новый фиксированный тип защищённого admission/context различает C и исходный B.
Корни и пути определяются кодом и protected descriptor; произвольные root/path,
environment, shell/playbook overrides не принимаются. Один exclusive relation
для пары запрещает второй C. Частично записанная relation также блокирует новый C.

Descriptor C связывает hashes всех A/B envelopes, admissions и попыток, native
backup evidence и текущий immutable proof. Каждая store/credential/provider/worker
граница проверяет явный context и неизменность всей lineage. Plans сохраняются в
канонических защищённых plan stores; base/operator/startup/terminal hashes bind C.
Legacy status сохраняет A/B исходы; выбор C выполняется явно по protected plan.

Предлагаемая native команда планирования:

    workstationctl setup recovery rehearsal-failure-plan \
      --predecessor-operator CLOSED_B_OPERATOR_ID --predecessor-sha256 CLOSED_B_SHA

Команда создаёт собственный защищённый admission/plan; не сбрасывает пароль,
не готовит новые credentials и не изменяет AD/ПК. Повторное планирование возможно
только в том же C до его первого intent/claim, с новыми SHA/TTL и неизменным source.

## Исполнение и Setup

Исполнение — существующая фиксированная operator pipeline через ordinary apply
с новым C operator SHA после отдельного human confirmation. Каждый настоящий
component сохраняет собственную lock ownership и one-way execution exclusion.
Один GUID-only machine-password write; identity и OU сохраняются.
После него: fixed credentials import, Kerberos/trust, возврат штатной SSSD policy,
разрешённый startup, native trust/user и terminal verification.

Любой UNKNOWN, истёкший TTL, drift, observed renewal или failure останавливает C;
нет повторного reset, автоматического cleanup/rollback, ручного продолжения фаз
или следующего successor. Reboot/logout требуют отдельного разрешения.
Normal Setup continuation создаётся только после текущего terminal PASS и требует
свежего нормального Setup-плана. Успех CI/планирования не считается live recovery.

## Альтернативы и проверка

Удаление claim или replay B отвергнуты: теряются one-shot и historical authority.
Возврат рабочего backup/rehearsal outcome в B отвергнут: заменяет closed evidence.
Неограниченный retry registry отвергнут: scope шире доказанного locale-отказа.
Предлагается ограниченный additive C с запретом дальнейшего descendant.

TDD: exact failed B fixture, missing/extra records, wrong chain/backup/audit,
alternate failure, source/identity/auth drift, unsafe paths/process/locks,
capacity, admission race/partial persistence, mixed contexts, once-only apply,
TTL и explicit terminal/Setup continuation. Проверить весь relevant recovery
набор, root metadata/runtime cases, общую CI regression и independent review.
После publication/guarded install: actual selected-PC read-only admission,
A/B/history byte comparisons, exact installed-source checks, earliest child TTL.
Затем запросить конкретный reset SHA. Подтверждение проекта не разрешает reset.
