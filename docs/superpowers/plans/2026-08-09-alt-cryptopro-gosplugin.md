# CryptoPro CSP, ГосПлагин и корпоративный CA: план реализации

**Цель:** обязательный профиль ALT Workstation получает корпоративный CA, CryptoPro CSP 5.0.13600-7 и ГосПлагин 1.3.19.0-1. Расширения браузера остаются под AD GPO; IFCPlugin исключён.

**Архитектура:** роли organization_ca, software_cryptopro и software_gosuslugi_plugin запускаются после plasma_baseline и до standard_software. Controller artifacts проверяются фиксированными SHA-256 и metadata до передачи на рабочую станцию. Лицензия CryptoPro содержится только в Ansible Vault и применяется через no_log: true.

## Границы и артефакты

- Не менять managed ISO и ai curl, не устанавливать IFCPlugin, polisec, принтеры и прежний remote access.
- Не принимать путь к дистрибутиву из request JSON; не применять rpm -Uhv, glob-поиск RPM или обход зависимостей.
- Не записывать лицензию, Vault и opaque-пароли в Git, output, result JSON или журнал контроллера.
- CA в Git: files/organization_ca/sosnadmin-local-ca.crt, SHA-256 b9cef2205fe10e4a2a2b00852348f6cbbbcfa3b18db1588d093a407bee91029f.
- CSP archive на контроллере: /opt/alt-deploy-control/artifacts/cryptopro/linux-amd64.tgz, SHA-256 dcab1fb326397c1993bf52e55732096793037caeec9f374586fc4e6ff0d739d4.
- ГосПлагин на контроллере: /opt/alt-deploy-control/artifacts/gosuslugi/gosuslugi-plugin-1.3.19.0-1.x86_64.rpm, SHA-256 ca4ca31dfd5bbcb4f61a47d989a3087b5e2d1e80f72e73018976108488e96a98.
- Дистрибутивы должны принадлежать altserver:altserver, иметь режим 0600. RPM ГосПлагина не подписан, поэтому role дополнительно проверяет package name gosuslugi-plugin, version 1.3.19.0-1 и x86_64.

## Задача 1 — контракт, preflight и TDD

**Файлы:** group_vars/all.yml, control/alt_deploy/vault.py, control/alt_deploy/configure.py, tests/test_alt_domain_ansible_assets.py, tests/test_alt_manual_configure_request.py.

1. Добавить фиксированные пути, SHA-256, ожидаемые версии/архитектуру и утверждённый список RPM CSP в all.yml.
2. Добавить Vault-проверку vault_cryptopro_license. В result она раскрывает лишь boolean наличия. При отсутствии до запуска Ansible вернуть cryptopro_vault_incomplete.
3. Сначала добавить тесты на contracts, role order, CA anchor, запрет IFCPlugin, no_log лицензии и result keys. Они должны падать до реализации.
4. После задач 2–4 запустить pytest только этих test modules, затем полный ALT test suite.

## Задача 2 — роль organization_ca

**Создать:** ansible/files/organization_ca/sosnadmin-local-ca.crt; ansible/roles/organization_ca/defaults/main.yml; ansible/roles/organization_ca/tasks/main.yml; handlers/main.yml.

1. Проверить PEM локально через openssl и зафиксированный SHA-256.
2. Положить в /etc/pki/ca-trust/source/anchors/sosnadmin-local-ca.crt с root:root, 0644.
3. По изменению вызывать /bin/update-ca-trust; ошибку handler не скрывать.
4. Проверить существование anchor и присутствие CA в system trust с trust list или openssl verify.
5. Выдать в verification result только organization_ca_ok.
6. Включить после plasma_baseline.

## Задача 3 — роль software_cryptopro

**Создать:** ansible/roles/software_cryptopro/defaults/main.yml, tasks/main.yml, handlers/main.yml. **Изменить:** configure playbook и domain_verify.

1. Controller-side stat должен проверить archive, SHA-256 и read access до copy.
2. Распаковать archive во временный каталог цели; потребовать по одному RPM каждого утверждённого имени и проверить rpm -qp name/version/release/arch.
3. Установить cryptopro-preinstall с package module. Затем APT устанавливает exact CSP base, capilite, KC, reader core, GTK GUI/tools, PC/SC и JaCarta reader, PKCS#11, CAdES и browser native plugin.
4. Применить vault_cryptopro_license штатным средством CryptoPro с no_log: true; не строить changed condition на secret output.
5. Проверить RPM versions, /opt/cprocsp/bin/amd64/nmcades и /etc/opt/chrome/native-messaging-hosts/ru.cryptopro.nmcades.json.
6. Запустить pcscd только когда его требуют reader packages. Отсутствующий токен не является ошибкой provisioning.
7. Через always удалить временный каталог; в result дать cryptopro_ok, CSP version, cryptopro_native_host_ok без лицензии и output.
8. Включить после organization_ca.

## Задача 4 — роль software_gosuslugi_plugin

**Создать:** ansible/roles/software_gosuslugi_plugin/defaults/main.yml и tasks/main.yml. **Изменить:** configure playbook и domain_verify.

1. На контроллере проверить SHA-256 и rpm -qp (name gosuslugi-plugin; version 1.3.19.0-1; x86_64).
2. Скопировать проверенный RPM во временный каталог, установить через APT с обычной обработкой зависимостей, затем удалить каталог через always.
3. Проверить RPM query, /opt/iitrust/gosuslugi_plugin/bin/gosuslugi_plugin и /etc/opt/chrome/native-messaging-hosts/chrome.gosuslugi.plugin.json.
4. Manifest должен включать ID jabjbhgjaidecageckilhonbggakppme и путь к существующему host.
5. Не создавать browser policy и не устанавливать extension: GPO уже доставляет расширения. В result дать gosuslugi_plugin_ok, version и gosuslugi_plugin_native_host_ok.
6. Включить после software_cryptopro.

## Задача 5 — результат, документация и пилот

**Изменить:** domain_verify, configure.py, docs/ALT_MANUAL_ANSIBLE_MVP.md, docs/superpowers/plans/2026-08-06-alt-playbook-modernization.md.

1. Добавить result keys: organization_ca_ok, cryptopro_ok, cryptopro_native_host_ok, gosuslugi_plugin_ok, gosuslugi_plugin_native_host_ok.
2. Зафиксировать order: plasma_baseline -> organization_ca -> software_cryptopro -> software_gosuslugi_plugin -> standard_software -> remote_access_krfb -> domain_verify.
3. Документировать: подготовку Vault/artifacts, исключение IFCPlugin, GPO ownership расширений и идемпотентный повторный запуск.
4. Перед deployment сделать точечный backup изменяемых путей на controller; не запускать общий installer по dirty source tree.
5. На controller выполнить Ansible syntax-check и configure preview. После отдельного подтверждения оператора выполнить configure на одном пилоте.
6. Проверить result keys, rpm -q, CA trust, оба native host, pcscd, net ads testjoin, SSSD и machine gpupdate; затем в GUI проверить, что GPO доставило заданные extensions.
7. Повторить configure без изменений: ожидается changed=0 либо только явно предусмотренное обновление политик. Не выполнять реальную подпись без тестового сертификата/токена и отдельного согласования.

## Проверка реализации

В worktree запустить:

- pytest -q tests/test_alt_domain_ansible_assets.py tests/test_alt_manual_configure_request.py
- python -m compileall deploy/alt-linux/control/alt_deploy

На controller выполнить syntax-check и configure preview. В отчёт включать версии, SHA-256 controller artifacts и только безопасные boolean result-поля.

## Самопроверка плана

- CA устанавливается до зависящих от trust компонентов.
- Два программных продукта имеют независимые hash, metadata и runtime проверки.
- Расширения управляются AD GPO, IFCPlugin отсутствует.
- Повторное выполнение и пилотная проверка входят в acceptance criteria.
