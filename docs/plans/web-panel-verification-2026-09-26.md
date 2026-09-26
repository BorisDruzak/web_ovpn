# Проверка SPEC T01–T13

T01–T13 реализованы и прошли соответствующие локальные acceptance gates.
Это проверка кода/синтетических данных, не production acceptance.
Исходный main: fab1cac1db0bc95e5536ff73c5d8fb103c90b358.
Итоговый implementation/test HEAD: c670db529d04c20be3e14bbd5ff42ec09941f820.
Этот отчёт и итоговая документация входят в следующий docs commit; полный
конечный SHA, рабочая копия и проверка origin/main приведены в финальном ответе
после Git-проверок. Deployment не выполнялся и запрещён SPEC.

Подробные команды, RED/GREEN, независимые проверки и промежуточные ограничения:
[журнал](web-panel-reliability-2026-09-26.md). Старые OPEN в журнале отражают
состояние на момент записи. Старое E3 v3 доказательство отозвано; принято v7.

| Требование | Проверенное поведение и основные файлы | Итог |
| --- | --- | --- |
| T01 | panel_operations.py/panel_operation_routes.py: bounded executor, owned Sessions, durable phases, deduplication, restart/unknown/partial effects; barrier/restart/secret regressions | PASS локально |
| T02 | permissions.py/auth.py: capabilities, CSRF, owner, secure cookie, create-only bootstrap/upgrade; XLSX rights/revocation; Context read-only403/no CLI; pinned trusted/untrusted proxy behavior | PASS локально |
| T03 | audit.py/inventory service/web/API: один commit, fresh-session rollback при позднем сбое, сохранение legacy audit default | PASS локально |
| T04 | network_hosts.html/host_snapshot.py: SQL count/page одного снимка, 230 уникальных строк, URL/Back/Forward/size/clamp/empty | PASS локально |
| T05 | inventory.js/asset form: IP/MAC map, insert/undo, zero, unsupported select, invalid numeric сохраняет прежнее, dirty lock; реальные клики | PASS локально |
| T06 | network_projection.py/endpoint cache: batch SSR/refresh projection, epoch, disabled/stale/ambiguity/deleted без SDK/live read;25/250 строк одинаковое число SELECT≤5 | PASS локально |
| T07 | form_drafts: UUID, owner,48h expiry, независимые вкладки, bounded cookie, conflict input; browser reload | PASS локально |
| T08 | network-hosts-refresh.js: serialized polling, generation/abort, hidden tab, timeout/auth recovery, unchanged snapshot+changed local epoch; controlled-timer Node suite | PASS локально |
| T09 | revisions/model/triggers: CAS HTML/API/children/bindings/deletion/discrepancy; manual facts отдельно от telemetry; migration twice | PASS локально |
| T10 | grouped navigation, saved views, operational/diagnostic/mobile; actual saved inventory_link select; E3 v7 | PASS локально |
| T11 | lifecycle/readers/workers/photos: soft-delete/history, retained peripherals/source, same-ID restore без автоматических связей, revision/race guards;2monitors+UPS и E3 v7 | PASS локально |
| T12 | XLSX source/writer/routes/private artifacts: coherent full selections, safe types, byte preflight, owner/read/export/deleted/TTL/quota;255cards/300interfaces/103bindings/parser/E3 v7 | PASS локально |
| T13 | stable identity/candidates/confirm/reject/history, оба направления, full SQL filter/epoch/export; saved source/presence/age/availability,4queries/1MiB guard; E3 v7 unavailable/recovery | PASS локально |

## Права и совместимость

| Граница | Browser | Service/MCP |
| --- | --- | --- |
| Inventory read/write | Active read; write требует inventory:write и CSRF | Явный scope; legacy read/write сохранён |
| Delete/restore/history | inventory:delete; revision/confirmation/reason | Не включены в legacy scope |
| Network read/diagnose/manage | network:read / diagnose / manage; CSRF на POST | Legacy diagnose сохранён; manage только явно |
| VPN read/manage/download | Раздельные capabilities; owner/atomic token consumption | Legacy базовые операции сохранены |
| POST /inventory/export | inventory:read+export; all/location/deleted; deleted также delete | Новый service endpoint не вводится |
| POST /network/export | network:read+export | Новый service endpoint не вводится |
| /operations/{id}: status/result/files | Owner+original/current capability; typed export scope/TTL | Owned ledger; нет blanket administration |
| User grants | admin:users + CSRF; atomic audit | Legacy не получает admin |

API обновления требуют expected_revision; Endpoint binding/discrepancy actions требуют заголовок X-Inventory-Revision (body alone не принимается). Отсутствие revision: 428, stale: 409; контракт описан в docs/runbooks/inventory-revisions.md. HTML
сохраняет конфликтный ввод. Netctl list по-прежнему ограничен250 строками;
readonly hosts export использует тот же фильтр/stdin projection и полный снимок.
Endpoint canonical SDK/OpenAPI граница не менялась. Отрицательный GitNexus путь
не использовался как доказательство отсутствия динамических зависимостей.
GitNexus indexed/remote baseline fab1cac; group indexStale/contractsStale=false,
commitsBehind0/missingRepos[]. Новые локальные commits учитывались отдельно.
Final InventoryAsset impactHIGH/direct21/total38depth2 — lower bound для dynamic
Base/interface relationships; source/tests проверяли реальные consumers.
Manual reindex/group_sync/generated manifest edits не выполнялись.

OPENVPN_WEB_API_PERMISSIONS задаёт explicit service scopes; пустое значение
запрещает protected routes. Legacy bearer не получает delete/export/network:manage.
Selected inventory_link требует обновлённого CLI/SQLite ≥3.35 с JSON1 и не может
молча игнорироваться старым CLI. HTTP nginx — bootstrap/development;
production требует TLS и private session key. Local unit pins forwarded trust127.0.0.1,
matching nginx upstream; forged untrusted headers игнорируются даже при env'*'.

## Данные и XLSX

Удаление сохраняет ID, характеристики и историю, завершает связи, оставляет
периферию и источник. Restore возвращает карточку с тем же ID; relink выполняется
явно с новой revision/confirmation. IP change не меняет stable MAC identity,
IP reuse не присваивает чужую карточку. Неоднозначность и повторный MAC не
создают двойное подтверждение. Worker observations не перезаписывают manual facts.

Inventory:8 листов, all/location/deleted scope; специализированные поля всех типов,
relations/identifier history, bindings/safe observations, checks/photo metadata,
UTC/source/epoch parameters. Network:3 листа, все совпавшие интерфейсы одного
снимка и локальные связи, отдельное время enrichment. Полный состав/лимиты:
[runbook](../runbooks/panel-xlsx-exports.md).

Файлы сохранены в ignored output этого checkout, доступны для ручного открытия:

| Файл | Размер/содержимое | SHA256 |
| --- | --- | --- |
| output/playwright/spec-final/inventory-synthetic.xlsx |15624bytes;4cards/2relations/3bindings;8sheets |c7ad42ef18f39a70c4d861a781fdcf52d6b7f581bdfb1e2b804f1575136b3e84 |
| output/playwright/spec-final/inventory-source-unavailable.xlsx |17282bytes;7cards/4relations/6bindings;8sheets |50bd857d4912bf632ddc4f0cf2bf158c251f4cbf6841f53cf44bd4d477794513 |
| output/playwright/spec-final/network-synthetic.xlsx |40765bytes;230snapshot+230relation rows;3sheets |7d4b9bf2f1d3a9d49e35588703265de1c4ae95ec1c921dcac70eb7a51c2041ba |

Parser проверил каждый cell: formulas/external links/macros отсутствуют.
13 relation/35 binding columns в Inventory. Состояние workplace relations явно
Действует/Завершена, в дополнение к endedUTC. Независимый verifier проверил
exact PC/peripheral IDs в DB и скачанных books. Большие255/300row selections
проверены unit/parser tests без реальной инвентаризации.

Actual E3 v7: найти источник→создать/выбрать PC→сравнить/подтвердить→открыть
из обоих разделов→MONITOR+UPS→исправить/сохранить→Excel→delete→проверить
retained exact peripheral IDs/source→restore same PC ID→explicit relink.
Повтор с Endpoint disabled/live Netctl unavailable: saved card/list/edit/export/
delete/restore работают; comparison HTTP200 показывает unavailable alert без
confirm action; recovery разрешает явную привязку. Все четыре control POST200,
pageErrors/serverFailures[], log без5xx/Traceback/IntegrityError. Independent и
root readonly verifier подтвердили latest attempt success, ровно один success
snapshot1 и сохранённую предыдущую failed attempt.
[Browser runbook](../runbooks/inventory-e3-browser.md). Старый E3 v3 отозван.

## Общая проверка и release

Pinned Windows Python3.12.14, SQLAlchemy2.0.36, SQLite3.53.1,
FastAPI0.115.6/Uvicorn0.34.0/openpyxl3.1.5. pip check clean; transitive freeze
вне repository. Pinned executable C:/Temp/web-ovpn-spec-pinned/Scripts/python.exe.

| Выполненная команда | Фактический результат |
| --- | --- |
| python -m pytest -q --disable-warnings --tb=short --junitxml=C:/Temp/web-ovpn-spec-pinned/final-suite.xml |2486PASS/14SKIP/0FAIL,664.44s; XMLerrors0/failures0/tests2500 |
| pytest tests/test_panel_schema_upgrade.py |1PASS; добавлен после full collection |
| pytest tests/test_panel_proxy_contract.py tests/test_panel_permissions.py tests/test_deploy_netopsctl.py tests/test_deploy_netopsctl_reconcile.py tests/test_deploy_network_paths.py |28PASS; proxy tests добавлены после full collection |
| pytest tests/test_inventory_xlsx.py tests/test_inventory_export_web.py tests/test_xlsx_export.py |18PASS после narrow explicit relation-state followup |
| node tests/network_hosts_refresh.test.js |PASS overlap/late/hidden/retry/timeout/session/malformed/freshness |
| Playwright MCP inventory_e3_journey.js, fresh loopback e3-v7 |Оба journeyPASS; controls200/no5xx; root/child relevant source diff пуст |
| python -m tests.browser.verify_inventory_e3 --fixture C:/Users/admin-2/Documents/ui_vpn/output/playwright/e3-v7 --artifacts C:/Users/admin-2/Documents/ui_vpn/output/playwright/e3-v7 |PASS root и independent review обоих journey+recovery |
| python -m compileall -q app netctl tests/browser; git diff --check |PASS после root integration |

Полный suite завершился до последнего narrow XLSX state-label followup; его
затронутые source/writer/routes проверены отдельным18PASS и final E3 v7.
Первый pinned run2463PASS/9FAIL/11SKIP не скрывается: obsolete date/capability/
migration fixtures исправлены с deny-before-CLI regression;3Linux-only tests
явно SKIP на Windows. В повторном full run baseline failures отсутствуют.
14SKIP — Linux/sysfs/FIFO/process/TLS/systemd/optional environment проверки,
не обозначены PASS. Detailed commands/results по каждому Txx в журнале.

Release: backup DB и protected config; install pinned requirements; обновить
Netctl CLI; выполнить non-destructive schema init проекта; SQLite >=3.35 с JSON1;
создать private exports directory/service permissions; HTTPS+production secret;
проверить health/rights/TTL. Новая export схема не добавляется. Ранее добавленные
revision/draft/lifecycle/operation migrations сохраняют IDs/history и проверены
повторно на synthetic old schema. Aggregate populated upgrade дважды сохранил
accountID/password hash/roles, PC/peripheralIDs/facts/canonical Endpoint binding,
восстановил additive tables/indexes/triggers; fresh Sessions после этого доказали
delete/restore/history retention. Rollback приложения сохраняет migrated DB;
без согласованного backup downgrade не объявляется безопасным.

PANEL_EXPORT_ROOT задаёт private storage; DOWNLOAD_TOKEN_TTL_MINUTES — TTL,
OPENVPN_WEB_API_PERMISSIONS — service scopes. Older API writers должны передавать
revision; old CLI не поддерживает selected projection/export. Budget errors
предлагают сузить охват, не усекают файл. SQLite — проверенная migration/card
consistency граница; PostgreSQL deployment не проверен. Production blockers:
HTTPS/private secret, complete migrations/new CLI, private directory permissions.

NOT RUN: production rollout/proxy acceptance, real data export/network writes,
Linux filesystem permissions и desktop Excel. Запущен только loopback synthetic
fixtures, которые остановлены. Windows owner+SYSTEM protected ACL/four-process
quota проверены; Linux0700/0600 подтверждены только кодом и условной веткой теста.
Настроенных самостоятельных lint/typecheck/build config при поиске не
найдено; pytest/browser/Node/compile/diff checks записываются как фактические.
