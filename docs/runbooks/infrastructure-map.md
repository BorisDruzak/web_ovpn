# Карта инфраструктуры

Раздел «Сеть и диагностика → Инфраструктура» читает готовый снимок. Веб, API `GET /api/v1/network/infrastructure` и инструмент MCP `openvpn_network_infrastructure` используют один формат. Для браузера действуют обычные права просмотра сети. Для API и MCP нужен токен с `network:read`.

## Сбор снимка

Запускайте сборщик из корня установленного UI_VPN от учётной записи, которой доступны команды чтения netctl и файл Server Observer. Подготовьте каталог снимка с флагом setgid и группой, доступной сервису панели. Сборщик заменяет файл атомарно. При ошибке сборщика доступен предыдущий снимок, а наблюдения старше 25 минут отмечаются как устаревшие.

В файле привязок задаются устойчивые идентификаторы объектов из `network-context.yaml` и соответствие источникам. Значения ниже условные.

```json
{
  "roles": {
    "document_service": {"label": "Документооборот", "asset": "document-server"}
  },
  "guests": {
    "103": {"asset": "document-server", "mac": "02:00:00:00:00:03"}
  }
}
```

Перед добавлением привязки сопоставьте адрес цели проверки с гостевой ОС и запишите MAC её интерфейса из конфигурации Proxmox. При несовпадении MAC новая ВМ с таким же VMID отображается отдельным узлом. Коммутаторы читаются из netctl и сетевого контекста. Уверенность в соединениях определяется сведениями GitHub, netctl и LLDP.

Для автоматического чтения Proxmox используйте HTTPS-имя, соответствующее сертификату, и токен с разделением привилегий. Файл токена содержит значение заголовка `PVEAPIToken=USER@REALM!TOKENID=SECRET`. Сборщику нужны права чтения узлов, списка ВМ и конфигураций ВМ с привязками. Укажите файл доверенного CA, если его нет в системном хранилище.

```bash
python -m app.infrastructure_collect \
  --context /srv/network_configuration/config/network-context.yaml \
  --schema /srv/network_configuration/schemas/network-context.schema.json \
  --git-revision "$(git -C /srv/network_configuration rev-parse HEAD)" \
  --server-health /var/lib/openvpn-web/server-observer/latest.json \
  --bindings /etc/openvpn-web/infrastructure/bindings.json \
  --proxmox-url https://proxmox.example.invalid:8006 \
  --proxmox-token-file /etc/openvpn-web/infrastructure/pve-token \
  --proxmox-ca /etc/openvpn-web/infrastructure/pve-ca.pem \
  --output /var/lib/openvpn-web/infrastructure/latest.json
```

Сборщик можно вызывать из системного таймера каждые пять минут. По умолчанию панель читает файл из примера. Другой путь задаётся через `INFRASTRUCTURE_MAP_SNAPSHOT_PATH`. Для разового импорта используется `--proxmox-export` с полями `at`, `cluster`, `nodes`, `guests` и `configs`, где последнее поле содержит конфигурации привязанных ВМ по VMID. При запуске от учётной записи с прямым доступом к netctl задайте `NETCTL_USE_SUDO=0`.

## Просмотр в VR

Откройте карту через HTTPS в браузере гарнитуры. Кнопка «Открыть в VR» появляется, когда браузер подтверждает поддержку `immersive-vr`. Открывается текущая вкладка карты. Выбор узла контроллером показывает его имя и статус. Выйти можно штатным действием гарнитуры. [Спецификация WebXR](https://www.w3.org/TR/webxr/)
