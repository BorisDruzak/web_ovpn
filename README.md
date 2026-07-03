# OpenVPN Web Manager

Документация по публикации, установке, деплою и эксплуатационным проверкам: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Минимальный FastAPI/Jinja2 web-интерфейс для управления OpenVPN-профилями через `vpnctl`.

## Модель безопасности

- Web-приложение не читает и не редактирует PKI, CCD, CRL, `.ovpn`, iptables или systemd напрямую.
- Все системные действия выполняются только через `vpnctl --json ...`.
- `app/vpnctl_client.py` вызывает CLI через `subprocess.run([...], shell=False, timeout=...)`.
- API использует Bearer token. В `/etc/openvpn-web/openvpn-web.env` хранится только `OPENVPN_WEB_API_TOKEN_HASH`.
- Download tokens одноразовые, живут 15 минут по умолчанию и хранятся только как HMAC-SHA256 hash.
- Web-БД хранит пользователей, audit, download-токены и настройки. Содержимое `.ovpn`, приватные ключи и сертификаты в web-БД не сохраняются.
- Опасные действия выполняются только POST-запросами, защищены CSRF и требуют ручного ввода имени клиента.
- Client delete намеренно не опубликован в API/MCP. Для агентского управления доступно только отключение клиента через disable с `confirm_client` и `reason`.

## Установка на Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y python3-venv
sudo useradd --system --home /opt/openvpn-web --shell /usr/sbin/nologin openvpn-web
sudo mkdir -p /opt/openvpn-web /etc/openvpn-web /var/lib/openvpn-web
sudo chown -R openvpn-web:openvpn-web /opt/openvpn-web /var/lib/openvpn-web
```

Скопировать проект в `/opt/openvpn-web`, затем:

```bash
cd /opt/openvpn-web
sudo -u openvpn-web python3 -m venv .venv
sudo -u openvpn-web .venv/bin/pip install -r requirements.txt
```

Создать `/etc/openvpn-web/openvpn-web.env`:

```bash
DATABASE_URL=sqlite:////var/lib/openvpn-web/openvpn-web.sqlite
VPNCTL_PATH=/usr/local/sbin/vpnctl
VPNCTL_USE_SUDO=1
APP_SECRET_KEY=<long-random-secret>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<initial-admin-password>
OUT_DIR=/etc/openvpn/client-generator/output
SHARE_OUT_DIR=/mnt/antares_soft/vpn_config
ARCHIVE_DIR=/etc/openvpn/client-generator/archive
DOWNLOAD_TOKEN_TTL_MINUTES=15
```

Для API дополнительно:

```bash
OPENVPN_WEB_API_TOKEN_HASH=<sha256-hex-of-token>
OPENVPN_WEB_API_ACTOR=api:codex-local
```

Установить sudoers:

```bash
sudo install -m 0440 deploy/sudoers-openvpn-web /etc/sudoers.d/openvpn-web
sudo visudo -cf /etc/sudoers.d/openvpn-web
```

Установить systemd unit:

```bash
sudo install -m 0644 deploy/openvpn-web.service /etc/systemd/system/openvpn-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-web.service
```

По умолчанию unit слушает `0.0.0.0:8088`. Если нужен nginx reverse proxy, установите nginx и используйте `deploy/nginx-openvpn-web.conf`.

## OpenVPN Management Interface

Web UI управляет текущими подключениями через `vpnctl`, а `vpnctl` подключается к OpenVPN Management Interface только через Unix socket. TCP management interface намеренно не используется.

Рекомендуемая настройка через UI:

1. Откройте `Настройки -> OpenVPN`.
2. Нажмите `Включить Management Interface`.
3. Нажмите `Проверить соединение`.
4. При необходимости измените `Период обновления клиентов`; по умолчанию используется `10` секунд.

Ручная настройка:

```bash
sudo groupadd --system openvpn-web || true
sudo usermod -aG openvpn-web openvpn-web

sudo vpnctl --json server-config apply \
  --status-interval 10 \
  --status-version 2 \
  --enable-management \
  --management-socket /run/openvpn/server.sock \
  --management-client-group openvpn-web \
  --management-log-cache 300 \
  --restart

sudo vpnctl --json management test
```

После применения в `/etc/openvpn/server/server.conf` должны быть директивы:

```conf
status /var/log/openvpn/status.log 10
status-version 2
management /run/openvpn/server.sock unix
management-client-group openvpn-web
management-log-cache 300
```

`status.log` остается fallback-источником для списка подключений. По умолчанию:

```bash
sudo vpnctl --json connected --source auto
```

сначала пробует management socket, а если он недоступен, читает `/var/log/openvpn/status.log`. Для принудительной проверки:

```bash
sudo vpnctl --json connected --source management
sudo vpnctl --json connected --source status-log
```

Отключение активной сессии без revoke:

```bash
sudo vpnctl --json management kill CLIENT
sudo vpnctl --json reconnect CLIENT
```

`disable` в web UI и API вызывает `vpnctl --json disable CLIENT --reason REASON --kill-active`: профиль отключается и активная сессия сразу выбивается, если management socket доступен. Client delete по-прежнему не опубликован в API/MCP.

Site-to-site режим пока подготовлен как модель/preview на уровне профилей и CCD-шаблонов. Серверные `route` для удаленных LAN нужно включать только контролируемым managed block и после проверки конфликтов CIDR.

## Локальный запуск

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./openvpn-web.sqlite
export VPNCTL_PATH=/path/to/vpnctl
export VPNCTL_USE_SUDO=0
export APP_SECRET_KEY=dev-secret
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin-pass
uvicorn app.main:app --reload
```

## Тесты

```bash
pytest
```

## API и MCP

Основной API префикс: `/api/v1`.

Примеры:

```bash
curl -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" \
  http://192.168.100.30:8088/api/v1/status

curl -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" \
  http://192.168.100.30:8088/api/v1/clients
```

Локальный Codex plugin `openvpn-control` использует MCP server через stdio. MCP server читает:

```bash
OPENVPN_WEB_BASE_URL=http://192.168.100.30:8088
OPENVPN_WEB_API_TOKEN_FILE=C:\Users\admin-2\.codex\openvpn-control-api-token.txt
```

MCP tools не содержат client delete. Для отключения клиента используется `openvpn_disable_client` с точным `confirm_client` и обязательным `reason`.

## Backup notes

Перед обновлением сохраняйте:

```bash
sudo cp /var/lib/openvpn-web/openvpn-web.sqlite /var/lib/openvpn-web/openvpn-web.sqlite.backup.$(date +%F_%H-%M-%S)
sudo cp /etc/openvpn-web/openvpn-web.env /etc/openvpn-web/openvpn-web.env.backup.$(date +%F_%H-%M-%S)
```

Реестр OpenVPN-клиентов находится отдельно: `/var/lib/openvpn-client-manager/openvpn-manager.sqlite`. Web-приложение не мутирует эту базу напрямую.
