# ALT: CryptoPro, ГосПлагин и корпоративный CA

## Цель

Добавить в фиксированный контроллерный Ansible-процесс три обязательных
системных компонента для доменной ALT Workstation K 11.x:

1. корпоративный корневой сертификат `Sosnadmin Local CA`;
2. CryptoPro CSP 5.0.13600-7 и его нативный CAdES Browser Plug-in;
3. ГосПлагин 1.3.19.0-1.

Расширения браузера не устанавливаются Ansible. Их принудительная установка и
обновление выполняются уже настроенной AD GPO через `gpupdate`.

## Границы

- Единственная точка запуска остаётся
  `03-configure-domain-workstation.yml` через `workstationctl configure`.
- `IFCPlugin 3.1.1` исключён: он устарел, требует недоступный `ccid` и не
  является частью целевого профиля.
- Никакая роль не принимает URL, произвольный пакет, путь к файлу или лицензию
  из request JSON.
- Лицензия CryptoPro хранится только в Ansible Vault. Она не попадает в Git,
  JSON-запросы, результаты или логи.
- Локальные политики Яндекс Браузера, `polisec` и прямое управление
  расширениями Ansible не используются.

## Утверждённые артефакты

| Компонент | Контроллерный артефакт | Проверка |
| --- | --- | --- |
| Корпоративный CA | `sosnadmin-local-ca.crt` | SHA-256 `b9cef2205fe10e4a2a2b00852348f6cbbbcfa3b18db1588d093a407bee91029f` |
| CryptoPro CSP | `linux-amd64.tgz` | SHA-256 `dcab1fb326397c1993bf52e55732096793037caeec9f374586fc4e6ff0d739d4`; manifest 5.0.13600-7 |
| ГосПлагин | `gosuslugi-plugin-1.3.19.0-1.x86_64.rpm` | SHA-256 `ca4ca31dfd5bbcb4f61a47d989a3087b5e2d1e80f72e73018976108488e96a98` |

У этих RPM отсутствует криптографическая RPM-подпись. Поэтому установка
разрешена только после проверки утверждённого controller-side SHA-256 и
ожидаемых package EVR/architecture.

## Роли и порядок

После domain join, GPO-клиента и базового Plasma-профиля playbook вызывает:

1. `organization_ca` — кладёт сертификат в
   `/etc/pki/ca-trust/source/anchors/`, запускает `update-ca-trust` и
   подтверждает отпечаток через `trust`/файл хранилища.
2. `software_cryptopro` — проверяет архив, извлекает его только во временный
   каталог, ставит фиксированный минимальный список CSP/CAdES RPM через
   `apt-get`, применяет лицензию из Vault с `no_log: true`, проверяет версии и
   наличие `nmcades`.
3. `software_gosuslugi_plugin` — проверяет RPM, ставит его через `apt-get`,
   проверяет package EVR, native-messaging manifest и бинарный файл.

Временные файлы удаляются в `always`; повторный запуск не переустанавливает
уже подтверждённые версии. `domain_verify` публикует только boolean-статусы
`organization_ca`, `cryptopro` и `gosuslugi_plugin`.

## Зависимости и расширения

На ALT 11 уже имеются `ca-trust`, `pcsc-lite`, `pcsc-lite-ccid` и `opensc`.
CryptoPro-роль управляет только утверждёнными CSP reader-модулями, включая
PC/SC и JaCarta, не перебирает весь архив. ГосПлагин предоставляет native host
`chrome.gosuslugi.plugin`; его расширение имеет ID
`jabjbhgjaidecageckilhonbggakppme` и уже назначается AD GPO.

CryptoPro CAdES native host разрешает несколько extension ID. Его единственный
целевой ID и источник обновления фиксируются в уже созданной AD GPO до
пилотного запуска; Ansible это не изменяет.

## Проверка

Пилот выполняется на зарегистрированном физическом ПК после controller preview.
Проверяются:

- SHA-256 artefacts до копирования на ПК;
- CA в системном trust store;
- package EVR и бинарные native hosts;
- отсутствие лицензии в логе и result JSON;
- machine GPO и отображение двух расширений в `browser://policy`;
- один операторский сценарий подписи с подключённым токеном.

Не проверяются и не развёртываются персональные сертификаты пользователя,
закрытые ключи и токены.
