# Remote hEX site `192.168.99.0/24`

Дата фиксации: 2026-07-06.

## Что видно из `hex_config.rsc`

- Router: MikroTik hEX / RB750Gr3.
- RouterOS: `6.49.7`.
- Identity: `m-arhiv`.
- LAN: `192.168.99.1/24` на `bridge1-lan`.
- DHCP pool: `192.168.99.20-192.168.99.200`.
- WAN: PPPoE на `ether1-wan`.
- В конфиге есть IPsec policy:
  - `src-address=192.168.99.0/24`;
  - `dst-address=192.168.100.0/23`;
  - peer `ics-asmr-tunnel`.
- В конфиге нет OpenVPN client.
- RouterOS services:
  - WinBox включен;
  - SSH/API/API-SSL отключены.

Секреты из экспорта намеренно не фиксируются в документации.

## Совместимость с текущим Ubuntu OpenVPN

Текущий OpenVPN на Ubuntu:

- `proto udp`;
- `tls-crypt-v2`;
- `cipher AES-128-GCM`;
- `client-config-dir ccd`;
- site-route `192.168.99.0/24` уже добавлен в `server.conf`.

Этот профиль не является MikroTik RouterOS 6.49.7 compatible. Нельзя просто импортировать обычный `.ovpn` из нашего OpenVPN Web в этот hEX и ожидать, что site-to-site заработает.

Причины:

- на hEX стоит RouterOS 6.49.7;
- `tls-crypt/tls-crypt-v2` для RouterOS OpenVPN появился в ветке RouterOS 7.17;
- текущий сервер настроен как UDP/tls-crypt-v2, а для старого RouterOS 6 нужен отдельный совместимый дизайн.

## Рабочие варианты

### Вариант A: оставить IPsec для hEX

Это наиболее реалистично для RouterOS 6.49.7.

Нужно:

1. На центральной стороне поднять встречный IPsec peer/policy к удаленному hEX.
2. Добавить политики не только для `192.168.100.0/23`, но и для телефонии:
   - remote `192.168.99.0/24` -> central phone `192.168.0.0/24`;
   - central phone `192.168.0.0/24` -> remote `192.168.99.0/24`.
3. На hEX добавить NAT bypass выше masquerade для трафика в центральные сети.
4. На UCM добавить:
   - SIP NAT local network `192.168.99.0/24`;
   - static route `192.168.99.0/24 -> 192.168.0.250`.

### Вариант B: отдельный MikroTik-compatible OpenVPN server на Ubuntu

Это возможно, но это отдельный OpenVPN listener, не текущий основной OpenVPN.

Нужно:

1. Создать отдельный TCP OpenVPN server на другом порту.
2. Не использовать текущий `tls-crypt-v2` профиль для RouterOS 6.
3. Подобрать совместимые TLS/cipher/auth параметры для MikroTik.
4. Создать сертификаты/пользователя для hEX.
5. Настроить `iroute 192.168.99.0 255.255.255.0` для клиента `m-arhiv`.
6. Добавить route на сервере и firewall/route на центральном MikroTik.

Это потребует отдельного тестового окна, потому что меняет VPN-архитектуру.

### Вариант C: обновить hEX до RouterOS 7.17+ и делать OpenVPN через него

Теоретически совместимость OpenVPN лучше в RouterOS 7.17+, но это обновление роутера. Перед этим нужен backup/export и окно работ.

## Что уже сделано на Ubuntu/OpenVPN

- `192.168.99.0/24` добавлена в каталог сетей как `remote-site`, NAT выключен.
- В `server.conf` добавлен site-route:
  - `route 192.168.99.0 255.255.255.0`.
- OpenVPN не перезапускался, чтобы не ронять активных клиентов.

Этого недостаточно для работы site-to-site без конкретного клиента с `iroute`.

## Что нужно решить

Нужно выбрать транспорт для hEX:

- IPsec на RouterOS 6.49.7;
- отдельный совместимый OpenVPN TCP server;
- обновление RouterOS и последующая OpenVPN-настройка.

До выбора транспорта не нужно применять `lan_full_telephony` к обычному клиенту: это не создаст `iroute` для `192.168.99.0/24`.
