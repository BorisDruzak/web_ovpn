# PLANS.md — план прокачки OpenVPN Web Manager

## Контекст текущей сетевой схемы

Текущая рабочая схема уже переведена с NAT на маршрутизацию без NAT:

```text
OpenVPN client VPN IP: 192.168.50.X
OpenVPN server Ubuntu: 192.168.100.30
MikroTik: 192.168.100.250 / маршрутизация к ViPNet Coordinator
ViPNet Coordinator: туннелирует 192.168.50.0/24, 192.168.51.0/24, 192.168.52.0/24
```

На Ubuntu OpenVPN server pool уже должен быть:

```conf
server 192.168.50.0 255.255.255.0
```

Старый пул `10.8.0.0/24` считается legacy и не должен использоваться для новых профилей, новых NAT-правил, новых шаблонов, подсказок UI или документации.

Новая логика адресации:

```text
192.168.50.0/24 — OpenVPN tunnel pool для обычных клиентов и VPN-адресов роутеров.
192.168.50.1    — OpenVPN server tunnel IP.
192.168.50.2-199 — динамические/обычные пользователи.
192.168.50.200-249 — фиксированные VPN-IP для роутеров.
192.168.51.0/24 — remote LAN за site-to-site роутером №1.
192.168.52.0/24 — remote LAN за site-to-site роутером №2.
```

Цель обновления: убрать из приложения и `vpnctl` старые предположения про `10.8.0.0/24`, добавить полноценную поддержку роутеров и site-to-site, усилить проверки, документацию, UI и тесты.

---

## 1. Главные архитектурные правила

1. Web UI не должен напрямую редактировать OpenVPN, CCD, PKI, CRL, iptables, systemd и файлы `.ovpn`.
2. Все системные операции выполнять только через `vpnctl --json ...`.
3. Web вызывает `vpnctl` через `subprocess.run([...], shell=False)`. `shell=True` запрещён.
4. Web-БД не является источником истины для OpenVPN-клиентов. Источник истины — `vpnctl list`, `vpnctl inspect`, `vpnctl connected`, `vpnctl server-config inspect`.
5. В web-БД можно хранить только web users, audit, settings, download tokens, UI metadata/cache.
6. Не хранить содержимое `.ovpn`, приватные ключи, сертификаты, download tokens и secrets в SQL.
7. Все dangerous actions — только POST, CSRF, подтверждение именем клиента.
8. Для отключения текущих активных сессий использовать OpenVPN Management Interface через Unix socket.

---

## 2. Что уже есть в текущей реализации

Текущий проект уже содержит:

- FastAPI/Jinja2 web-интерфейс.
- Вызов `vpnctl` через `app/vpnctl_client.py`.
- Авторизацию, CSRF, audit, download logic.
- Страницы клиентов, создания профиля, подключений, настроек OpenVPN, сетей.
- Management Interface UI и команды `server-config`, `management test`, `management kill`, `connected --source auto`.
- API `/api/v1` с Bearer token.
- Автосинхронизацию клиентов после generate/disable.
- Редактирование сетей/шаблонов и применение маршрутов к клиенту.

Нужно не переписать всё заново, а довести до нового сетевого стандарта и закрыть пробелы.

---

## 3. Обязательный переход с `10.8.0.0/24` на `192.168.50.0/24`

### 3.1. Найти все legacy references

Выполнить по проекту:

```bash
grep -R "10\.8\." -n .
grep -R "10.8.0.0" -n .
grep -R "VPN_NET" -n .
grep -R "vipnet-openvpn-nat" -n .
grep -R "VIPNET_OPENVPN_SNAT" -n .
```

Задача: удалить или пометить как legacy все упоминания старого пула.

### 3.2. Добавить централизованные настройки сетей

Добавить в config/settings и `vpnctl` единый источник настроек:

```text
OPENVPN_TUNNEL_CIDR=192.168.50.0/24
OPENVPN_SERVER_TUNNEL_IP=192.168.50.1
OPENVPN_USER_POOL_START=192.168.50.2
OPENVPN_USER_POOL_END=192.168.50.199
OPENVPN_ROUTER_POOL_START=192.168.50.200
OPENVPN_ROUTER_POOL_END=192.168.50.249
OPENVPN_LEGACY_CIDRS=10.8.0.0/24
REMOTE_SITE_CIDRS=192.168.51.0/24,192.168.52.0/24
CENTRAL_LAN_CIDRS=192.168.100.0/23,10.10.10.0/23,10.83.1.0/24
VIPNET_TARGET_CIDRS=172.153.153.0/24,172.153.155.0/24,172.153.159.0/24,172.20.59.0/24,192.168.241.0/24
```

Лучше хранить это не только в env, но и в `vpnctl` config file, например:

```text
/etc/openvpn-client-manager/vpnctl.env
```

Web UI должен показывать эти значения в `Настройки -> OpenVPN -> Адресация`.

### 3.3. Server config checks

`vpnctl server-config inspect` должен возвращать:

```json
{
  "settings": {
    "server_network": "192.168.50.0/24",
    "server_tunnel_ip": "192.168.50.1",
    "status_interval": 10,
    "status_version": 2,
    "management_enabled": true
  },
  "warnings": []
}
```

Добавить warning, если в `server.conf` найдено:

```conf
server 10.8.0.0 255.255.255.0
```

Добавить command:

```bash
vpnctl --json server-config migrate-pool \
  --from 10.8.0.0/24 \
  --to 192.168.50.0/24 \
  --backup \
  --restart
```

Но в текущей эксплуатации миграция уже сделана. Поэтому command нужна скорее для проверки и восстановления, а не для обязательного запуска.

---

## 4. Удалить зависимость от старого NAT

Ранее существовала схема:

```text
10.8.0.0/24 -> ViPNet networks -> SNAT 192.168.100.30
```

Теперь она не нужна. Новая схема — без NAT:

```text
192.168.50.X -> ViPNet targets
```

### 4.1. `vpnctl nat-status`

Обновить `nat-status`, чтобы он явно показывал:

```json
{
  "status": "ok",
  "mode": "disabled_expected",
  "legacy_nat_service": {
    "name": "vipnet-openvpn-nat.service",
    "active": false,
    "enabled": false
  },
  "legacy_chain": {
    "name": "VIPNET_OPENVPN_SNAT",
    "exists": false
  },
  "warnings": []
}
```

Если `VIPNET_OPENVPN_SNAT` существует или `vipnet-openvpn-nat.service` активен — показать warning:

```text
Legacy SNAT is active. Current routing design expects no NAT for 192.168.50.0/24.
```

### 4.2. UI

На странице `Сети` / `OpenVPN settings` добавить блок:

```text
Legacy NAT: inactive / active
Ожидаемый режим: no NAT
```

Если NAT активен — красный alert и кнопка:

```text
Отключить legacy NAT
```

Команда через vpnctl:

```bash
vpnctl --json nat disable-legacy
```

Команда должна:

- `systemctl disable --now vipnet-openvpn-nat.service`, если есть;
- удалить jump `POSTROUTING -> VIPNET_OPENVPN_SNAT`, если есть;
- очистить и удалить chain, если есть;
- не трогать другие NAT-правила, например `wg0 MASQUERADE`.

---

## 5. Профили клиентов

### 5.1. Разделить client_type и access_profile

Сейчас форма создания профиля имеет только:

```text
client
profile
vpn_ip
comment
```

Нужно добавить:

```text
client_type:
  user
  router_nat
  router_site_to_site

access_profile:
  directum_dns
  directum_hosts
  directum17_dns
  directum17_hosts
  vipnet
  router_vipnet
  lan_full
  custom
```

`profile` сохранить для обратной совместимости, но в новой логике отображать как `access_profile`.

### 5.2. Обычный пользователь

Для `client_type=user`:

- VPN-IP optional.
- Если VPN-IP не указан — динамический из `192.168.50.2-199`.
- Если фиксированный — он должен попадать в `192.168.50.2-199`, если не выбран advanced mode.
- `router_*` профили скрывать или показывать с предупреждением.

### 5.3. Роутер с NAT

Для `client_type=router_nat`:

- fixed VPN-IP обязателен.
- IP должен попадать в `192.168.50.200-249`.
- `remote_lan_cidr` optional, справочно.
- `iroute` не создаётся.
- OpenVPN видит подключение только роутера.
- MikroTik/Coordinator видит source как VPN-IP роутера, например `192.168.50.200`.
- Пользователи за роутером не видны по отдельным IP, если на роутере NAT.

CCD пример:

```conf
ifconfig-push 192.168.50.200 255.255.255.0
push "route 192.168.100.10 255.255.255.255"
push "route 192.168.100.1 255.255.255.255"
push "dhcp-option DNS 192.168.100.1"
push "dhcp-option DOMAIN sosnadmin.local"
push "route 172.153.159.0 255.255.255.0"
```

### 5.4. Роутер site-to-site без NAT

Для `client_type=router_site_to_site`:

- fixed VPN-IP обязателен.
- IP должен попадать в `192.168.50.200-249`.
- `remote_lan_cidr` обязателен.
- `remote_lan_cidr` не должен пересекаться с:
  - `192.168.50.0/24`;
  - `192.168.100.0/23`;
  - `10.10.10.0/23`;
  - `10.83.1.0/24`;
  - ViPNet target networks;
  - другими remote LAN, уже зарегистрированными в vpnctl registry;
  - legacy networks `10.8.0.0/24`.
- CCD должен содержать `iroute`.

CCD пример:

```conf
ifconfig-push 192.168.50.200 255.255.255.0
iroute 192.168.51.0 255.255.255.0
push "route 192.168.100.10 255.255.255.255"
push "route 192.168.100.1 255.255.255.255"
push "dhcp-option DNS 192.168.100.1"
push "dhcp-option DOMAIN sosnadmin.local"
push "route 172.153.159.0 255.255.255.0"
```

OpenVPN server route должен быть добавлен в managed block:

```conf
# BEGIN VPNCTL SITE ROUTES
route 192.168.51.0 255.255.255.0
# END VPNCTL SITE ROUTES
```

Нельзя просто хаотично дописывать `route` в конец `server.conf`. Нужен idempotent managed block.

---

## 6. `vpnctl` commands для site-to-site

Добавить/обновить команды:

### 6.1. Generate router NAT

```bash
vpnctl --json generate router_001 router_vipnet 192.168.50.200 \
  --client-type router_nat \
  --comment "Site A router with NAT"
```

### 6.2. Generate router site-to-site

```bash
vpnctl --json generate router_site_001 router_vipnet 192.168.50.201 \
  --client-type router_site_to_site \
  --remote-lan 192.168.51.0/24 \
  --create-server-route \
  --comment "Site A router without NAT"
```

### 6.3. Preview router site-to-site

```bash
vpnctl --json preview router_site_001 router_vipnet 192.168.50.201 \
  --client-type router_site_to_site \
  --remote-lan 192.168.51.0/24 \
  --create-server-route
```

Preview должен показывать:

- planned CCD lines;
- planned server route lines;
- conflicts;
- router instructions;
- MikroTik requirements;
- Coordinator requirements.

### 6.4. Site route management

```bash
vpnctl --json site-routes list
vpnctl --json site-routes add 192.168.51.0/24 --client router_site_001 --restart
vpnctl --json site-routes remove 192.168.51.0/24 --restart
```

Managed block must be idempotent.

### 6.5. Validation commands

```bash
vpnctl --json validate-network-plan
vpnctl --json validate-client router_site_001
vpnctl --json validate-routes
```

Checks:

- `server.conf` uses `192.168.50.0/24`.
- `status /var/log/openvpn/status.log 10` exists.
- `status-version 2` exists.
- management Unix socket enabled.
- no active legacy NAT.
- CCD fixed IPs are inside configured tunnel CIDR.
- no duplicate fixed VPN-IP.
- no duplicate remote LAN.
- no overlapping CIDR.
- `ipp.txt` does not contain stale `10.8.*` leases.
- profiles with `router_site_to_site` have `remote_lan_cidr` and `iroute`.

---

## 7. Web UI changes

### 7.1. Client creation form

Update `/clients/new`:

Fields:

```text
Client name
Client type:
  - Обычный пользователь
  - Роутер с NAT
  - Роутер site-to-site без NAT
Access profile
VPN IP:
  - auto for user
  - required for router
Remote LAN CIDR:
  - hidden for user
  - optional for router_nat
  - required for router_site_to_site
Create server route:
  - only for router_site_to_site
Comment
```

Dynamic UI behaviour:

- If `client_type=user`, show `VPN IP` as optional and placeholder `192.168.50.X или пусто`.
- If `client_type=router_nat`, require `VPN IP`, suggest next free `192.168.50.200+`.
- If `client_type=router_site_to_site`, require `VPN IP` and `remote_lan_cidr`, suggest `192.168.51.0/24` / next free.
- Show warnings if selected profile is inconsistent with client type.

### 7.2. Client detail page

Add fields:

```text
Client type
Access profile
VPN IP
Remote LAN CIDR
Has iroute
Has server route
Connected yes/no
Current real address
Current virtual address
```

Actions:

- Download OVPN.
- Reconnect client.
- Kill active session.
- Disable with kill-active.
- Apply network template.
- For site-to-site: show router setup instruction.

### 7.3. Router instructions page/block

For every router client, show generated instruction:

#### Router NAT mode instruction

```text
1. Import OVPN profile into router.
2. Ensure router uses NAT/MASQUERADE from LAN to OpenVPN tunnel.
3. Add routes on router to required central/ViPNet networks via OpenVPN:
   - 192.168.100.10/32
   - 192.168.100.1/32
   - ViPNet target networks from profile
4. OpenVPN server will see only router VPN IP.
5. Coordinator/MikroTik will not see individual LAN users behind the router.
```

#### Router site-to-site mode instruction

```text
1. Import OVPN profile into router.
2. Disable NAT/MASQUERADE from remote LAN to OpenVPN tunnel.
3. Ensure router routes central/ViPNet networks through OpenVPN.
4. Ensure remote LAN is exactly: <remote_lan_cidr>.
5. OpenVPN CCD contains iroute for <remote_lan_cidr>.
6. OpenVPN server.conf contains route for <remote_lan_cidr>.
7. MikroTik must have route: <remote_lan_cidr> -> 192.168.100.30.
8. MikroTik address-list vipnet2corp must include <remote_lan_cidr>.
9. ViPNet Coordinator tunnel IP ranges must include <remote_lan_cidr>.
10. Users behind router will be visible by their real IP addresses in MikroTik/Coordinator logs.
```

### 7.4. Settings -> OpenVPN -> Addressing

Add read-only/validated block:

```text
OpenVPN tunnel CIDR: 192.168.50.0/24
Server tunnel IP: 192.168.50.1
User dynamic range: 192.168.50.2-199
Router fixed range: 192.168.50.200-249
Remote LAN pools: 192.168.51.0/24, 192.168.52.0/24
Legacy CIDRs: 10.8.0.0/24
Legacy NAT: inactive expected
```

Add action:

```text
Run network validation
```

Calling:

```bash
vpnctl --json validate-network-plan
```

### 7.5. Networks page

Update terminology:

- `ViPNet target networks` — where users go.
- `OpenVPN tunnel network` — `192.168.50.0/24`.
- `Remote site LANs` — `192.168.51.0/24`, `192.168.52.0/24`.
- `Legacy NAT` — should be disabled.

Avoid UI implying that new ViPNet networks require NAT restart. Current expected mode is no NAT.

---

## 8. API changes

Extend API models:

```python
class ClientProfileRequest(BaseModel):
    profile: str
    vpn_ip: str = ""
    comment: str = ""
    client_type: Literal["user", "router_nat", "router_site_to_site"] = "user"
    remote_lan_cidr: str = ""
    create_server_route: bool = False
```

Update `/api/v1/clients/{client}/preview` and `/generate` to pass these fields to `vpnctl`.

Add endpoints:

```text
GET  /api/v1/openvpn/addressing
POST /api/v1/openvpn/validate-network-plan
GET  /api/v1/site-routes
POST /api/v1/site-routes
DELETE /api/v1/site-routes/{cidr}
GET  /api/v1/clients/{client}/router-instructions
```

Delete endpoint can remain intentionally not public, as current README says delete is not exposed for API/MCP.

---

## 9. Bug fixes to check

### 9.1. Download link behavior

Current `download-link` POST returns `FileResponse` immediately. The project also has `/download/{token}`, but `download-link` does not appear to create a one-time token in the shown code path.

Required:

- `POST /clients/{client}/download-link` should create one-time token and show/copy URL, or rename action to direct download.
- If requirement is one-time links, implement token creation and redirect/show link.
- Keep direct download only if explicitly intended.

### 9.2. `download/{token}` uses `consume_download_token(token)` without passing DB session in shown code

Check implementation of `download_tokens.py`. If it uses global session incorrectly, fix it.

### 9.3. `client_new_action` passes `args = [action, client, profile]`

This works only if CLI has commands `preview` and `generate` as top-level. Ensure new flags are appended in correct order:

```bash
vpnctl --json preview CLIENT PROFILE [VPN_IP] --client-type ... --remote-lan ...
vpnctl --json generate CLIENT PROFILE [VPN_IP] --client-type ... --remote-lan ...
```

### 9.4. Empty string filtering in `run_vpnctl`

`clean_args = [str(arg) for arg in args if str(arg) != ""]` can accidentally remove intentional empty arguments. Fine for now, but be careful with flags that accept empty values. Prefer not passing optional args when empty.

### 9.5. Status key mismatch

Some pages use `list_from(data, "connected")`, others may expect `clients`. Standardize:

```json
connected returns {"connected": [...], "source": "management"}
management status returns {"connected": [...], "source": "management"}
```

or update adapter to accept both `clients` and `connected`.

### 9.6. Management function names

Current code uses both:

```text
reconnect-client
management kill
```

Earlier plan used `reconnect`. Standardize on one public command:

```text
vpnctl reconnect-client CLIENT --reason REASON
```

Keep alias `reconnect` only if needed.

### 9.7. `config-view`, `client-template-apply`, `client-networks-apply`, `ovpn-update`, `repair-artifacts`

These commands are already called by web UI. Ensure `vpnctl` actually implements them and returns stable JSON. Add tests for every CLI command that web calls.

### 9.8. OpenVPN status service command line mismatch

Systemd status may show OpenVPN writes status to `/run/openvpn-server/status-server.log` via unit args, while `server.conf` contains `/var/log/openvpn/status.log 10`. Check actual active status source. Ensure `vpnctl connected` source auto works with management first and status-log fallback second.

### 9.9. Existing fixed CCD IPs

Old CCDs have been migrated from `10.8.*` to `192.168.50.*`. Add validation to catch any remaining `10.8.*`:

```bash
vpnctl --json validate-network-plan
```

should warn with exact CCD path.

---

## 10. Tests to add

### 10.1. Unit tests: network validation

- `192.168.50.10` valid for user fixed IP.
- `192.168.50.200` valid for router fixed IP.
- `10.8.0.10` rejected for new fixed IP.
- `192.168.51.0/24` valid remote LAN.
- `192.168.50.0/24` rejected as remote LAN.
- `192.168.100.0/24` rejected as remote LAN due overlap with central LAN.
- duplicate remote LAN rejected.
- duplicate fixed VPN-IP rejected.

### 10.2. Unit tests: CCD rendering

- user profile has no `iroute`.
- router_nat has fixed `ifconfig-push`, no `iroute`.
- router_site_to_site has fixed `ifconfig-push` and `iroute`.
- profile `vipnet` pushes ViPNet networks and DNS.
- generated CCD contains no `10.8.`.

### 10.3. Unit tests: server route managed block

- adding first site route creates block.
- adding second site route preserves first.
- repeated add is idempotent.
- remove deletes only selected route.
- block update makes backup.

### 10.4. Unit tests: NAT disabled expected

- `nat-status` returns warning if `VIPNET_OPENVPN_SNAT` exists.
- `nat disable-legacy` does not touch unrelated NAT rules.

### 10.5. Web tests

- `/clients/new` shows client type field.
- `router_site_to_site` requires `vpn_ip` and `remote_lan_cidr`.
- preview displays `iroute` and server route plan.
- client detail shows router instructions.
- settings page shows addressing block.
- networks page no longer suggests NAT restart as default for ViPNet target networks.

### 10.6. API tests

- `/api/v1/clients/{client}/preview` accepts client_type and remote_lan_cidr.
- `/api/v1/openvpn/validate-network-plan` returns warnings/errors.
- `/api/v1/clients/{client}/router-instructions` returns mode-specific instruction.

---

## 11. Deployment and migration steps

### 11.1. Before deploying

Backup:

```bash
sudo cp /etc/openvpn/server/server.conf /etc/openvpn/server/server.conf.backup.$(date +%F_%H-%M-%S)
sudo tar -czf /etc/openvpn/server/ccd.backup.$(date +%F_%H-%M-%S).tar.gz -C /etc/openvpn/server/ccd .
sudo cp /var/lib/openvpn-client-manager/openvpn-manager.sqlite /var/lib/openvpn-client-manager/openvpn-manager.sqlite.backup.$(date +%F_%H-%M-%S) || true
sudo cp /var/lib/openvpn-web/openvpn-web.sqlite /var/lib/openvpn-web/openvpn-web.sqlite.backup.$(date +%F_%H-%M-%S) || true
```

### 11.2. Required live network state

OpenVPN:

```conf
server 192.168.50.0 255.255.255.0
status /var/log/openvpn/status.log 10
status-version 2
management /run/openvpn/server.sock unix
management-client-group openvpn-web
management-log-cache 300
```

MikroTik:

```mikrotik
/ip route add dst-address=192.168.50.0/24 gateway=192.168.100.30 comment="OpenVPN new pool via Ubuntu"
/ip firewall address-list add list=vipnet2corp address=192.168.50.0/24 comment="OpenVPN new pool to ViPNet without NAT"
```

For site-to-site:

```mikrotik
/ip route add dst-address=192.168.51.0/24 gateway=192.168.100.30 comment="Remote site 1 via OpenVPN"
/ip firewall address-list add list=vipnet2corp address=192.168.51.0/24 comment="Remote site 1 to ViPNet"
```

Coordinator tunnel ranges already configured:

```text
192.168.50.1-192.168.50.254
192.168.51.1-192.168.51.254
192.168.52.1-192.168.52.254
```

### 11.3. Post-deploy validation

```bash
sudo vpnctl --json server-config inspect
sudo vpnctl --json validate-network-plan
sudo vpnctl --json connected --source auto
sudo vpnctl --json nat-status
```

Create test preview:

```bash
sudo vpnctl --json preview test_user_vipnet vipnet
sudo vpnctl --json preview test_router_nat router_vipnet 192.168.50.200 --client-type router_nat
sudo vpnctl --json preview test_router_s2s router_vipnet 192.168.50.201 --client-type router_site_to_site --remote-lan 192.168.51.0/24 --create-server-route
```

No output should contain `10.8.` except in legacy warnings.

---

## 12. Codex implementation prompt

Use this section as the direct implementation prompt for Codex.

```text
You are working in repository BorisDruzak/web_ovpn.

Implement a network model upgrade for OpenVPN Web Manager.

Current production network has migrated from legacy OpenVPN pool 10.8.0.0/24 to new pool 192.168.50.0/24. The app and vpnctl must stop creating new rules, profiles, CCDs, NAT rules, templates, documentation, or UI hints for 10.8.0.0/24. 10.8.0.0/24 may appear only as legacy detection/warning.

Target addressing:
- 192.168.50.0/24: OpenVPN tunnel pool.
- 192.168.50.1: OpenVPN server tunnel IP.
- 192.168.50.2-199: normal users.
- 192.168.50.200-249: routers.
- 192.168.51.0/24 and 192.168.52.0/24: remote LANs behind site-to-site routers.

Current expected design has no SNAT from OpenVPN to ViPNet. Legacy `vipnet-openvpn-nat.service` and `VIPNET_OPENVPN_SNAT` should be inactive. Add checks and UI warnings if they are active.

Implement:

1. Centralized addressing settings in vpnctl and web config.
2. vpnctl `validate-network-plan` command.
3. vpnctl `nat-status` update for no-NAT expected mode.
4. vpnctl `nat disable-legacy` safe command.
5. Extend generate/preview to support:
   - `--client-type user|router_nat|router_site_to_site`
   - `--remote-lan CIDR`
   - `--create-server-route`
6. For router_site_to_site, render CCD with `iroute` and manage server route in idempotent managed block:
   `# BEGIN VPNCTL SITE ROUTES` / `# END VPNCTL SITE ROUTES`.
7. Add `site-routes list/add/remove` commands.
8. Add router instructions generation command or include instructions in inspect/preview.
9. Update web UI `/clients/new` with client type, remote LAN CIDR, route options and dynamic validation.
10. Update client detail page to display client_type, remote_lan_cidr, iroute, server route and router instructions.
11. Update settings OpenVPN page with Addressing block and validation action.
12. Update networks page terminology: ViPNet targets vs OpenVPN tunnel network vs Remote site LANs. Do not suggest NAT restart by default.
13. Update API models/endpoints for client_type and remote_lan_cidr.
14. Add tests for validation, CCD rendering, site route managed block, no-NAT checks, web forms and API.
15. Fix existing bugs listed in PLANS.md, especially download-link vs one-time token behavior, command consistency, status key consistency, and any missing vpnctl commands called by web UI.
16. Update README and deployment docs.

Acceptance criteria:
- `grep -R "10\.8\." .` returns only legacy warning/testing references.
- `vpnctl --json preview test_user vipnet` generates no 10.8 addresses.
- `vpnctl --json preview test_router_s2s router_vipnet 192.168.50.201 --client-type router_site_to_site --remote-lan 192.168.51.0/24 --create-server-route` shows CCD with `ifconfig-push 192.168.50.201 ...` and `iroute 192.168.51.0 ...`.
- `vpnctl --json validate-network-plan` detects old CCDs with 10.8, active legacy NAT, duplicate VPN IPs, overlapping remote LANs and missing server routes.
- Web UI can create/preview normal user, router NAT and router site-to-site profiles.
- Site-to-site router instructions are visible in UI.
- All tests pass.
```

---

## 13. Definition of Done

The upgrade is complete when:

1. New user profiles use `192.168.50.0/24` only.
2. New router profiles use fixed `192.168.50.200-249` IPs.
3. Site-to-site profiles can define remote LANs and `iroute`.
4. Server routes for remote LANs are managed idempotently.
5. Legacy NAT is disabled and monitored.
6. UI shows addressing state and warns about legacy config.
7. UI provides router setup instructions.
8. API supports client_type and remote_lan_cidr.
9. `validate-network-plan` is available and useful before/after changes.
10. README contains exact deployment and MikroTik/Coordinator prerequisites.
11. Tests cover the new behavior.
