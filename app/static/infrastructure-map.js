import { setupInfrastructureVr } from './infrastructure-xr.js';

(() => {
  let data = JSON.parse(document.getElementById("infrastructure-data").textContent);
  const root = document.getElementById('infra-map-review');
  const groups = root.querySelector('#map-groups');
  const details = root.querySelector('#map-details');
  const related = root.querySelector('#map-related');
  const search = root.querySelector('#map-query');
  const feedback = root.querySelector('#map-search-result');
  const pathKinds = new Set(['Путь по MAC-таблице', 'Путь через общий порт']);
  const reciprocalMacSource = 'SNMP · взаимные MAC';
  const arpDiagnosticLabels = {no_reply: 'Нет ответа ARP', matched: 'MAC совпал с инвентарём',
    different_mac: 'ARP показывает другой MAC', unconfirmed: 'Ответ ARP не подтверждён'};
  const availabilityStates = {
    ok: 'Доступен',
    warn: 'Доступен, есть сбои проверок',
    critical: 'Недоступен',
    unknown: 'Доступность не подтверждена',
  };
  const observerStates = {ok: 'В норме', warn: 'Отклонение', critical: 'Ошибка', unknown: 'Нет подтверждения'};
  const observerNumber = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 2});
  const measurement = (unit, value) => {
    if (!Number.isFinite(value)) return '';
    if (unit === 'percent') return observerNumber.format(value) + '%';
    if (unit === 'bytes') return observerNumber.format(value / 2**30) + ' ГиБ';
    if (unit === 'hours') return observerNumber.format(value) + ' ч';
    if (unit === 'count') return observerNumber.format(value);
    return '';
  };
  const availabilityOf = node => {
    const color = node.mapStatus ?? 'unknown';
    let label = availabilityStates[color];
    if (node.reachability?.state === 'stopped') {
      label = node.kind === 'Сервис'
        ? (node.reachability.source === 'Redfish' ? 'Недоступен, сервер выключен' : 'Недоступен, ВМ выключена')
        : 'Выключен';
    }
    if (color === 'unknown' && node.reachability?.state === 'reachable') {
      label = 'Доступен, есть проверки без подтверждения';
    }
    if (color === 'warn' && node.serviceAvailability?.unavailable?.length) label = 'Доступен, есть недоступные сервисы';
    if (node.id === data.clusterId && color === 'warn') label = 'Кластер доступен, есть сбои';
    return {label, color};
  };
  let byId, incident, connected, networkKinds, primary, anchors, networkDistance;
  const buttons = new Map();
  const graphs = [];
  const resize = new ResizeObserver(draw);
  const viewButtons = Array.from(root.querySelectorAll('[data-view]'));
  let view = 'overview';
  let selected = null;
  let selectedPort = null;
  let focusedRanks = null;
  const make = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const formatTime = value => new Intl.DateTimeFormat('ru-RU', { timeZone:'Asia/Yekaterinburg', dateStyle:'short', timeStyle:'short' }).format(new Date(value));
  const portObservationTime = new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Asia/Yekaterinburg', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  const formatWindowsPortEvidence = ({ifIndex, checkedAt, switchCheckedAt}) =>
    `Windows (ifIndex ${ifIndex}) · ${portObservationTime.format(new Date(checkedAt))} · SNMP · ${portObservationTime.format(new Date(switchCheckedAt))} ЕКБ`;
  const formatPortSpeed = bps => bps ? (bps / 1e6).toLocaleString('ru-RU') + ' Мбит/с' : '';
  const portLabels = {up: 'линк поднят', down: 'линк опущен', disabled: 'порт отключён'};
  const formatUptime = seconds => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor(seconds / 3600) % 24;
    const minutes = Math.floor(seconds / 60) % 60;
    return [days && `${days} д.`, hours && `${hours} ч.`, `${minutes} мин.`].filter(Boolean).join(' ');
  };
  const formatEndpointMac = ({deviceId, mac, checkedAt}) =>
    [byId.get(deviceId)?.name, mac, 'MAC-таблица SNMP', formatTime(checkedAt)].filter(Boolean).join(' · ');
  const formatStpPort = ({state, enabled, checkedAt}) => {
    const states = {disabled: 'отключено', blocking: 'блокировка', listening: 'прослушивание',
      learning: 'обучение', forwarding: 'пересылка', broken: 'ошибка'};
    const settings = {true: 'параметр STP включён', false: 'параметр STP выключен'};
    return ['Состояние STP ' + states[state], settings[enabled], 'SNMP', formatTime(checkedAt)].filter(Boolean).join(' · ');
  };
  const source = root.querySelector('#map-sources');
  const availability = root.querySelector('#map-availability');
  const availabilityLabels = {
    missing: 'Снимок инфраструктуры ещё не опубликован.',
    invalid: 'Снимок инфраструктуры недоступен.',
    stale: 'Снимок устарел. Связи показаны по последним доступным данным.',
  };
  const proxmoxUnavailable = () => data.collectionIssues?.includes('proxmox');
  const collectionMessages = {
    proxmox: 'Опрос Proxmox завершился ошибкой. Текущее состояние и размещение ВМ не подтверждены.',
    network_observer: 'Опрос Network Observer завершился ошибкой. Свежие данные SNMP, LLDP и MAC-таблиц недоступны.',
    server_observer_unavailable: 'Отчёт Server Observer недоступен. Внутренние проверки серверов не подтверждены.',
    server_observer_stale: 'Отчёт Server Observer устарел. Внутренние проверки серверов не подтверждены.',
  };
  function showAvailability(message = [availabilityLabels[data.availability],
    ...(data.collectionIssues ?? []).map(issue => collectionMessages[issue])].filter(Boolean).join(' ')) {
    availability.textContent = message;
    availability.hidden = !message;
  }
  function formatLldpPortId(portId, subtype) {
    if (!portId) return '';
    const labels = {interface_alias:'псевдоним интерфейса', port_component:'компонент порта',
      mac_address:'MAC-адрес', network_address:'сетевой адрес', interface_name:'имя интерфейса',
      agent_circuit_id:'идентификатор цепи', local:'локальный идентификатор'};
    const type = Object.hasOwn(labels, subtype) ? labels[subtype] : '';
    return `ID порта ${portId}${type ? ' (' + type + ')' : ''}`;
  }
  function appendRxErrorCounters(parent, counters, portName = '') {
    const labels = {ifInErrors:'Всего RX', fcsErrors:'FCS', alignmentErrors:'Выравнивание',
      frameTooLongs:'Длинные кадры', internalMacRxErrors:'Внутренние ошибки MAC', symbolErrors:'Ошибки символов',
      rxPauseFrames:'Кадры PAUSE RX', txPauseFrames:'Кадры PAUSE TX'};
    const counts = Object.entries(labels).filter(([key]) => key in counters)
      .map(([key, label]) => `${label} ${counters[key].toLocaleString('ru-RU')}`);
    const pauseModes = {disabled:'выключен', tx_only:'передача', rx_only:'приём', tx_rx:'приём и передача'};
    if (Object.hasOwn(pauseModes, counters.pauseOperMode)) counts.push(`Режим PAUSE: ${pauseModes[counters.pauseOperMode]}`);
    const title = [portName, 'Накопленные счётчики SNMP', formatTime(counters.checkedAt)].filter(Boolean).join(' · ');
    parent.append(make('small', title), make('small', counts.join(' · ')));
  }
  function formatRxSilence({startedAt, checkedAt, intervalCount, txBytes}) {
    const duration = (Date.parse(checkedAt) - Date.parse(startedAt)) / 1000;
    return `RX 0 байт за ${formatUptime(duration)} · TX ${txBytes.toLocaleString('ru-RU')} байт · ${intervalCount} интервалов SNMP · ${formatTime(checkedAt)}`;
  }
  function appendPortLinkDetails(row, port, label) {
    if (port.linkMode) {
      const {duplex, autoNegotiation, checkedAt} = port.linkMode;
      const configured = {true: 'Автосогласование включено', false: 'Автосогласование выключено'};
      const mode = {full: 'Полный дуплекс', half: 'Полудуплекс'};
      row.append(make('small', [label, mode[duplex], configured[autoNegotiation], 'SNMP · ' + formatTime(checkedAt)]
        .filter(Boolean).join(' · ')));
    }
    if (port.transceiver) {
      const {formFactor, vendor, media, nominalBps, checkedAt, opticalPower} = port.transceiver;
      const rate = nominalBps && 'номинал ' + (nominalBps / 1e9).toLocaleString('ru-RU') + ' Гбит/с';
      row.append(make('small', [label, 'Модуль ' + formFactor, vendor, media, rate, 'SNMP · ' + formatTime(checkedAt)]
        .filter(Boolean).join(' · ')));
      if (opticalPower?.state === 'unavailable') {
        row.append(make('small', [label, 'DDM · нет достоверных показаний мощности'].filter(Boolean).join(' · ')));
      } else if (opticalPower?.state === 'available') {
        const power = [['RX', opticalPower.rxDbm], ['TX', opticalPower.txDbm]]
          .filter(([, value]) => value !== undefined)
          .map(([direction, value]) => direction + ' ' + value.toLocaleString('ru-RU') + ' дБм');
        row.append(make('small', [label, 'DDM', ...power].filter(Boolean).join(' · ')));
      }
    }
  }
  function formatPortCounterChanges(telemetry) {
    const counters = {rxErrors:'Ошибки RX', txErrors:'Ошибки TX', rxDiscards:'Отбросы RX', txDiscards:'Отбросы TX'};
    const counts = Object.entries(counters).filter(([key]) => telemetry[key] > 0)
      .map(([key, label]) => `${label} ${telemetry[key].toLocaleString('ru-RU')}`);
    return counts.length ? [...counts, `${telemetry.intervalSeconds} с`, formatTime(telemetry.checkedAt)].join(' · ') : '';
  }
  function renderPortCounterSummary() {
    const panel = root.querySelector('#map-port-counters');
    const summary = panel.querySelector('summary');
    const list = panel.querySelector('ul');
    const activeLink = list.contains(document.activeElement) ? document.activeElement.href : '';
    const {affectedPorts = 0, ports = []} = data.portCounterAudit ?? {};
    panel.hidden = !affectedPorts;
    summary.textContent = 'Ошибки и отбросы на портах · ' + affectedPorts;
    list.replaceChildren(...ports.map(({deviceId, deviceName, port, configuredLabel, telemetry}) => {
      const item = make('li');
      const link = make('a', `${deviceName} · ${port}` + (configuredLabel ? ` · ${configuredLabel.text}` : ''));
      link.href = '?' + new URLSearchParams({node: deviceId, port});
      item.append(link, make('small', formatPortCounterChanges(telemetry)));
      return item;
    }));
    if (activeLink && !panel.hidden) {
      ([...list.querySelectorAll('a')].find(link => link.href === activeLink) ?? summary).focus({preventScroll: true});
    }
  }
  function renderPortRxSilenceSummary() {
    const panel = root.querySelector('#map-port-rx-silence');
    const summary = panel.querySelector('summary');
    const list = panel.querySelector('ul');
    const more = panel.querySelector('small');
    const activeLink = list.contains(document.activeElement) ? document.activeElement.href : '';
    const {total = 0, ports = []} = data.portRxSilenceAudit ?? {};
    panel.hidden = !total;
    summary.textContent = `Порты с передачей и без приёма · ${total}`;
    list.replaceChildren(...ports.map(({deviceId, deviceName, port, configuredLabel, rxSilence}) => {
      const row = make('li');
      const link = make('a', [deviceName, port, configuredLabel?.text].filter(Boolean).join(' · '));
      link.href = '?' + new URLSearchParams({node: deviceId, port});
      row.append(link, make('small', formatRxSilence(rxSilence)));
      return row;
    }));
    more.hidden = ports.length >= total;
    more.textContent = `Показано ${ports.length} из ${total}`;
    if (activeLink && !panel.hidden) {
      ([...list.querySelectorAll('a')].find(link => link.href === activeLink) ?? summary).focus({preventScroll: true});
    }
  }
  function portPairEndpoint(id, name, port) {
    if (port && byId.get(id)?.ports?.some(item => portKeys(item).includes(portKey(port)))) {
      return switchPortButton(id, name, port);
    }
    const label = name + ' · ' + (port || 'порт неизвестен');
    if (!byId.has(id)) return make('span', label);
    const link = make('a', label);
    link.href = '?' + new URLSearchParams({node: id});
    return link;
  }
  function confirmedPortPairRow({a, b, nameA, nameB, portA, portB, evidence}) {
    const row = make('li');
    row.append(portPairEndpoint(a, nameA, portA), ' ↔ ', portPairEndpoint(b, nameB, portB));
    for (const {source, checkedAt, windowsAdapter} of evidence) {
      row.append(make('small', source + ' · ' + formatTime(checkedAt)));
      if (windowsAdapter) row.append(make('small', formatWindowsPortEvidence(windowsAdapter)));
    }
    return row;
  }
  function formatLinkCheck(check) {
    const states = {reachable: 'Отвечает', unreachable: 'Недоступен', unknown: 'Нет подтверждения'};
    return [check.method, states[check.state], check.source, formatTime(check.checkedAt)].filter(Boolean).join(' · ');
  }
  function renderConfirmedPortPairs() {
    const panel = root.querySelector('#map-confirmed-port-pairs');
    const {currentPortPairTotal = 0, currentPortPairs = []} = data;
    panel.hidden = view !== 'switches' || !currentPortPairTotal;
    if (panel.hidden) return;
    const summary = panel.querySelector('summary');
    const list = panel.querySelector('ul');
    const more = panel.querySelector('small');
    summary.textContent = 'Подтверждённые пары портов · ' + currentPortPairTotal;
    list.replaceChildren(...currentPortPairs.map(confirmedPortPairRow));
    more.hidden = currentPortPairs.length >= currentPortPairTotal;
    more.textContent = `Показано ${currentPortPairs.length} из ${currentPortPairTotal}`;
  }
  function renderPortPairSummary() {
    renderConfirmedPortPairs();
    const panel = root.querySelector('#map-port-pairs');
    const summary = panel.querySelector('summary');
    const list = panel.querySelector('ul');
    const more = panel.querySelector('small');
    const {pendingPortPairTotal = 0, pendingPortPairs = [],
      lacpPartnerInterfaceGapTotal = 0, lacpPartnerInterfaceGaps = []} = data;
    const total = pendingPortPairTotal + lacpPartnerInterfaceGapTotal;
    panel.hidden = view !== 'switches' || !total;
    if (panel.hidden) return;
    summary.textContent = 'Пары портов без подтверждения · ' + pendingPortPairTotal;
    if (lacpPartnerInterfaceGapTotal) summary.append(' · Интерфейсы LACP · ' + lacpPartnerInterfaceGapTotal);
    const pending = pendingPortPairs.map(pendingPortPairRow);
    const lacp = lacpPartnerInterfaceGaps.map(({name, switchId, aggregate, switchPort, partnerPort}) => {
      const item = make('li');
      item.append(portPairEndpoint(switchId, byId.get(switchId)?.name || switchId, switchPort),
        ` ↔ ${name} · LACP ${aggregate} · порт партнёра ${partnerPort}`,
        make('small', 'Имя интерфейса на стороне партнёра неизвестно'));
      return item;
    });
    list.replaceChildren(...pending, ...lacp);
    const shown = pending.length + lacp.length;
    more.hidden = shown >= total;
    more.textContent = `Показано ${shown} из ${total}`;
  }
  function appendInventorySources(container, sources) {
    if (!sources?.length) return;
    const referenceList = make('details');
    referenceList.append(make('summary', `Источники инвентаря (${sources.length})`));
    for (const {path, observedOn} of sources) {
      const line = make('small', `${observedOn} · `);
      if (/^[0-9a-f]{40}$/.test(data.git)) {
        const link = make('a', path.split('/').pop());
        link.href = `https://github.com/BorisDruzak/network_configuration/blob/${data.git}/${path}`;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        line.append(link);
      } else {
        line.append(path);
      }
      referenceList.append(line);
    }
    container.append(referenceList);
  }
  function pendingPortPairRow({a, b, nameA, nameB, portA, portB, observedSources = [], lldpPortIds = [],
      observedSourceTimes = {}, identifiedPeerSides = [], archivedPortSides = [], inventoryPortSides = [],
      portObservations = {}, stpPaths = [], stpBridgeConnections = [], stpBridgeMacObservations = [], lldpPeers = {},
      archivedPortAt = {}, inventorySources = [], inventoryPeerPorts = [], arpDiagnostics = {}, observedPaths = [],
      multiMacPortSides = [], unconfirmedLldpCandidates = []}) {
    const item = make('li');
    const provenance = key => archivedPortSides.includes(key) ? ' (по архиву)' :
      inventoryPortSides.includes(key) ? ' (по инвентарю)' : '';
    item.append(portPairEndpoint(a, nameA, portA), provenance('a'), ' ↔ ',
      portPairEndpoint(b, nameB, portB), provenance('b'));
    for (const [side, checkedAt] of Object.entries(archivedPortAt)) {
      if (checkedAt) item.append(make('small', `Архив · ${side === 'a' ? nameA : nameB} · ${formatTime(checkedAt)}`));
    }
    appendInventorySources(item, inventorySources);
    for (const source of observedSources) {
      const label = source === 'netctl FDB' ? 'MAC на порту' : source;
      const checkedAt = observedSourceTimes[source];
      item.append(make('small', checkedAt ? `${label} · ${formatTime(checkedAt)}` : label));
    }
    for (const path of observedPaths) {
      if (!path.portA || !path.portB) continue;
      const row = make('small', `Наблюдаемый путь · ${path.source} · `);
      row.append(portPairEndpoint(a, nameA, path.portA), ' ↔ ', portPairEndpoint(b, nameB, path.portB));
      if (path.checkedAt) row.append(` · ${formatTime(path.checkedAt)}`);
      item.append(row);
    }
    for (const [side, peers] of Object.entries(lldpPeers)) {
      const [observer, neighbor] = side === 'a' ? [nameA, nameB] : [nameB, nameA];
      for (const {localPort, portId, portIdSubtype, chassisId, checkedAt} of peers) {
        const identity = portId ? formatLldpPortId(portId, portIdSubtype) : chassisId;
        item.append(make('small', `LLDP · ${observer} ${localPort} → ${neighbor} · ${identity} · ${formatTime(checkedAt)}`));
      }
    }
    if (!Object.keys(lldpPeers).length && lldpPortIds.length) {
      item.append(make('small', 'LLDP Port ID ' + lldpPortIds.join(', ')));
    }
    for (const {systemName, portId, portIdSubtype, chassisId, checkedAt} of unconfirmedLldpCandidates) {
      const evidence = [systemName, portId && formatLldpPortId(portId, portIdSubtype), chassisId, formatTime(checkedAt)];
      item.append(make('small', ['Возможный сосед LLDP', ...evidence.filter(Boolean)].join(' · ')));
    }
    for (const {port, inventorySources} of inventoryPeerPorts) {
      item.append(make('small', `По инвентарю · ${nameB} · ${port}`));
      appendInventorySources(item, inventorySources);
    }
    if (identifiedPeerSides.length) {
      const observers = identifiedPeerSides.map(side => side === 'a' ? nameA : nameB);
      item.append(make('small', 'Сосед опознан со стороны ' + observers.join(', ')));
    }
    for (const path of stpPaths) appendStpPath(item, path);
    if (stpBridgeConnections.length) {
      const list = make('ul', null, 'map-detail-list');
      list.append(...stpBridgeConnections.map(confirmedPortPairRow));
      item.append(make('small', 'Подтверждённые пары на порту моста STP'), list);
    }
    for (const {bridgeDeviceId, switchId, port, checkedAt} of stpBridgeMacObservations) {
      const bridge = byId.get(bridgeDeviceId)?.name ?? bridgeDeviceId;
      const row = make('small', `MAC моста STP ${bridge} виден на `);
      row.append(portPairEndpoint(switchId, byId.get(switchId)?.name ?? switchId, port), ` · ${formatTime(checkedAt)}`);
      item.append(row);
    }
    for (const [side, readings] of Object.entries(arpDiagnostics)) {
      const name = side === 'a' ? nameA : nameB;
      for (const {address, state, interface: sourcePort, checkedAt} of readings) {
        item.append(make('small', `${name} · ARP к ${address} · ${arpDiagnosticLabels[state]} · UI_VPN ${sourcePort} · ${formatTime(checkedAt)}`));
      }
    }
    for (const [side, port] of Object.entries(portObservations)) {
      const label = `${side === 'a' ? nameA : nameB} ${port.name}`;
      const reading = [label, portLabels[port.state], formatPortSpeed(port.speedBps), formatTime(port.checkedAt)];
      if (port.rxSilence) reading.push(formatRxSilence(port.rxSilence));
      item.append(make('small', reading.filter(Boolean).join(' · ')));
      const counterChanges = port.telemetry && formatPortCounterChanges(port.telemetry);
      if (counterChanges) item.append(make('small', `${label} · ${counterChanges}`));
      if (port.rxErrorCounters) appendRxErrorCounters(item, port.rxErrorCounters, label);
      appendPortLinkDetails(item, port, label);
      if (port.fdbLearned) {
        const {learnedMacCount, partial, checkedAt} = port.fdbLearned;
        item.append(make('small', [label, `Изучено MAC ${learnedMacCount}`, partial ? 'неполный опрос' : '',
          formatTime(checkedAt)].filter(Boolean).join(' · ')));
        if (multiMacPortSides.includes(side)) {
          item.append(make('small', `${label} · несколько MAC на порту. Дальний разъём требует сверки.`));
        }
      }
      if (port.lldpPort?.delta) {
        item.append(make('small', `${label} · ${formatLldpDelta(port.lldpPort.delta)} · ${formatTime(port.lldpPort.checkedAt)}`));
      }
    }
    return item;
  }
  function formatLldpDelta({intervalSeconds, rxFrames, txFrames}) {
    return [`LLDP за ${Math.round(intervalSeconds)} с`, `получено кадров ${rxFrames.toLocaleString('ru-RU')}`,
      `отправлено кадров ${txFrames.toLocaleString('ru-RU')}`].join(' · ');
  }
  function appendStpPath(parent, {deviceId, localPort, bridgeDeviceId, designatedBridgeMac, designatedPortId,
    designatedPortName, checkedAt}) {
    const bridge = byId.get(bridgeDeviceId)?.name ?? designatedBridgeMac;
    const remote = designatedPortName ? `${bridge} ${designatedPortName}` : bridge;
    const row = make('small', `STP · ${byId.get(deviceId)?.name ?? deviceId} ${localPort} → `);
    if (designatedPortName && byId.get(bridgeDeviceId)?.ports?.some(port => portKeys(port).includes(portKey(designatedPortName)))) {
      const link = make('a', remote);
      link.href = '?' + new URLSearchParams({node: bridgeDeviceId, port: designatedPortName});
      row.append(link);
    } else {
      row.append(remote);
    }
    row.append(` · ${designatedPortId} · ${formatTime(checkedAt)}`);
    parent.append(row);
  }
  function renderSnapshotHeader() {
    source.replaceChildren();
    if (data.snapshotAt) source.append('Снимок · ' + formatTime(data.snapshotAt) + ' (ЕКБ)');
    if (data.git) {
      const canonical = make('a', 'GitHub ' + data.git.slice(0, 7));
      canonical.href = 'https://github.com/BorisDruzak/network_configuration/blob/' + data.git + '/config/network-context.yaml';
      canonical.target = '_blank';
      canonical.rel = 'noopener noreferrer';
      source.append(' · ', canonical);
    }
    showAvailability();
    renderPortCounterSummary();
    renderPortRxSilenceSummary();
    root.querySelector('#map-port-alert-legend').hidden = !data.links.some(edge => edge.portAlerts?.length);
    for (const section of ['.map-views', '.map-legend', '#map-search']) {
      root.querySelector(section).hidden = !data.nodes.length;
    }
  }
  function group(title) {
    const section = make('section', null, 'map-group');
    section.append(make('h2', title));
    groups.append(section);
    return section;
  }
  function nodeButton(id) {
    const node = byId.get(id);
    const button = make('button', null, 'map-node');
    button.type = 'button';
    const availability = availabilityOf(node);
    button.dataset.state = availability.color;
    button.setAttribute('aria-label', node.name + ', ' + availability.label);
    button.setAttribute('aria-pressed', 'false');
    const label = node.guest && focusedRanks ? 'ВМ ' + node.vmid : node.name;
    button.append(make('i'), make('span', label));
    button.firstChild.dataset.state = availability.color;
    button.addEventListener('click', () => select(id));
    buttons.set(id, button);
    return button;
  }
  function traversal(seed, seen, visible) {
    const distance = new Map([[seed, 0]]);
    const queue = [seed];
    for (const id of queue) {
      seen.add(id);
      for (const peer of connected.get(id)) {
        if (distance.has(peer) || !visible.has(peer)) continue;
        distance.set(peer, distance.get(id) + 1);
        queue.push(peer);
      }
    }
    return distance;
  }
  const nameOrder = (a, b) => byId.get(a).name.localeCompare(byId.get(b).name, 'ru');
  const onBackbone = node => node.id !== data.clusterId && (!node.guest || data.overviewGuests.includes(node.id));
  function indexSnapshot() {
    byId = new Map(data.nodes.map(node => [node.id, node]));
    incident = new Map(data.nodes.map(node => [node.id, []]));
    connected = new Map(data.nodes.map(node => [node.id, []]));
    for (const edge of data.links) {
      incident.get(edge.a).push(edge);
      incident.get(edge.b).push(edge);
      if (edge.confirmed) {
        connected.get(edge.a).push(edge.b);
        connected.get(edge.b).push(edge.a);
      }
    }
    networkKinds = new Set(data.switchKinds);
    const roots = data.nodes.filter(node => networkKinds.has(node.kind)).map(node => node.id);
    primary = roots.sort((a, b) => connected.get(b).length - connected.get(a).length || nameOrder(a, b))[0];
    anchors = [primary, ...data.overviewGuests].filter(Boolean);
    const backboneIds = new Set(data.nodes.filter(onBackbone).map(node => node.id));
    networkDistance = primary ? traversal(primary, new Set(), backboneIds) : new Map();
  }

  function focusedTopology(id) {
    const path = [id];
    let current = id;
    const host = byId.get(id).pveHost;
    if (!networkDistance.has(id) && connected.get(id).includes(host)) {
      path.unshift(host);
      current = host;
    }
    while (networkDistance.get(current) > 0) {
      const parent = connected.get(current).find(peer => networkDistance.get(peer) === networkDistance.get(current) - 1);
      if (!parent) break;
      path.unshift(parent);
      current = parent;
    }
    if (path.length === 1) {
      const incoming = incident.get(id).find(edge => edge.confirmed && edge.b === id &&
        ['Размещение', 'Размещение ВМ', 'Цель проверки'].includes(edge.kind));
      if (incoming) path.unshift(incoming.a);
    }
    const ranks = new Map(path.map((nodeId, rank) => [nodeId, rank]));
    for (const peer of connected.get(id)) {
      if (!ranks.has(peer)) ranks.set(peer, path.length);
    }
    return ranks;
  }
  function addGraph(title, components) {
    const section = group(title);
    const graph = make('div', null, 'map-graph');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('map-wires');
    svg.setAttribute('aria-hidden','true');
    graph.append(svg);
    const ranks = [];
    for (const component of components) {
      for (const [id, rank] of component) {
        (ranks[rank] ??= []).push(id);
      }
    }
    graph.style.setProperty('--ranks', ranks.length);
    let previous = new Map();
    for (const row of ranks) {
      const parentIndex = id => Math.min(...connected.get(id).filter(peer => previous.has(peer)).map(peer => previous.get(peer)), Infinity);
      row.sort((a,b) => parentIndex(a) - parentIndex(b) || nameOrder(a,b));
      const lane = make('div', null, 'map-rank');
      lane.append(...row.map(nodeButton));
      graph.append(lane);
      previous = new Map(row.map((id,index) => [id,index]));
    }
    section.append(graph);
    const members = new Set(components.flatMap(component => [...component.keys()]));
    graphs.push({
      graph, svg, components,
      edges: data.links.filter(edge => edge.confirmed && members.has(edge.a) && members.has(edge.b)),
    });
  }
  function addGrid(title, ids) {
    const section = group(title);
    const grid = make('div', null, 'map-isolated');
    grid.append(...ids.map(nodeButton));
    section.append(grid);
  }
  function addGuestGroups(guests) {
    const hosts = new Map();
    for (const guest of guests) {
      if (!hosts.has(guest.pveHost)) hosts.set(guest.pveHost, []);
      hosts.get(guest.pveHost).push(guest);
    }
    for (const [host, entries] of hosts) {
      addGrid((host || 'Размещение не подтверждено') + ' · ВМ и контейнеры (' + entries.length + ')',
              entries.sort((a,b) => a.vmid - b.vmid).map(node => node.id));
    }
  }
  function renderView(mode, focus=null) {
    if (selected) clearSelection();
    resize.disconnect();
    graphs.length = 0;
    groups.replaceChildren();
    buttons.clear();
    view = mode;
    renderPortPairSummary();
    focusedRanks = focus ? focusedTopology(focus) : null;
    viewButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.view === mode)));
    if (!data.nodes.length) return;
    if (focusedRanks) {
      addGraph('Схема связей', [focusedRanks]);
      const graph = graphs.at(-1).graph;
      graph.classList.add('map-focused-graph');
      if (focusedRanks.get(focus) === Math.max(...focusedRanks.values())) graph.classList.add('map-focus-leaf');
    } else if (mode === 'cluster') {
      if (byId.has(data.clusterId) && data.nodeOrder.length) {
        addGraph('Кластер и узлы', [new Map([[data.clusterId, 0], ...data.nodeOrder.map(id => [id, 1])])]);
      } else {
        group('Нет данных о кластере');
      }
      for (const id of data.nodeOrder) {
        const guests = data.nodes.filter(node => node.pveHost === id).sort((a,b) => a.vmid - b.vmid);
        if (guests.length) addGrid(id + ' · ВМ (' + guests.length + ')', guests.map(node => node.id));
        else if (!proxmoxUnavailable()) group(id + ' · ВМ отсутствуют');
      }
      if (proxmoxUnavailable()) addGuestGroups(data.nodes.filter(node => node.guest && !node.pveHost));
    } else {
      const isOverview = mode === 'overview';
      const visible = new Set(data.nodes.filter(node => isOverview
        ? onBackbone(node)
        : networkKinds.has(node.kind)).map(node => node.id));
      const order = [...new Set([...anchors.filter(id => visible.has(id)), ...visible])];
      const components = new Map();
      const seen = new Set();
      const isolated = [];
      for (const seed of order) {
        if (seen.has(seed)) continue;
        const component = traversal(seed, seen, visible);
        if (component.size === 1) isolated.push(seed);
        else components.set(seed, component);
      }
      const main = components.get(primary);
      if (main) addGraph(isOverview ? 'Сеть и виртуализация' : 'Схема соединений', [main]);
      const other = [...components].filter(([seed]) => seed !== primary).map(([,component]) => component);
      if (other.length) addGraph(isOverview ? 'Серверы и сервисы' : 'Другие подтверждённые соединения', other);
      if (isolated.length) addGrid('Узлы без подтверждённых связей в этом разделе', isolated.sort(nameOrder));
      if (isOverview) {
        if (byId.has(data.clusterId)) addGrid('Кластер Proxmox', [data.clusterId]);
        addGuestGroups(data.nodes.filter(node => node.guest && !visible.has(node.id)));
      }
    }
    for (const {graph} of graphs) resize.observe(graph);
    requestAnimationFrame(draw);
  }
  function draw() {
    for (const {graph, svg, edges, components} of graphs) {
      const affectedPairs = new Set(edges.filter(edge => edge.portAlerts?.length).map(edge => edgeKey(edge.a, edge.b)));
      const ranks = Number(graph.style.getPropertyValue('--ranks'));
      graph.classList.toggle('vertical', graph.clientWidth / ranks < 113);
      const vertical = graph.classList.contains('vertical');
      const bounds = graph.getBoundingClientRect();
      const point = (id, end) => {
        const box = buttons.get(id).getBoundingClientRect();
        return vertical
          ? {x: box.left + box.width / 2 - bounds.left, y:(end ? box.top : box.bottom) - bounds.top}
          : {x:(end ? box.left : box.right) - bounds.left, y:box.top + box.height / 2 - bounds.top};
      };
      const drawn = new Set();
      const active = new Set();
      const ranksByNode = components.find(component => component.has(selected));
      if (ranksByNode) {
        for (const peer of connected.get(selected)) active.add(edgeKey(selected, peer));
        let child = selected;
        while (ranksByNode.get(child) > 0) {
          const parent = connected.get(child).find(peer => ranksByNode.get(peer) === ranksByNode.get(child) - 1);
          if (!parent) break;
          active.add(edgeKey(child, parent));
          child = parent;
        }
      }
      svg.replaceChildren();
      for (const edge of edges) {
        const pair = edgeKey(edge.a, edge.b);
        if (drawn.has(pair)) continue;
        drawn.add(pair);
        const aBox = buttons.get(edge.a).getBoundingClientRect();
        const bBox = buttons.get(edge.b).getBoundingClientRect();
        const flip = vertical ? aBox.top > bBox.top : aBox.left > bBox.left;
        const start = point(flip ? edge.b : edge.a, false);
        const end = point(flip ? edge.a : edge.b, true);
        const sameRank = vertical ? Math.abs(aBox.top - bBox.top) < 5 : Math.abs(aBox.left - bBox.left) < 5;
        let d;
        if (sameRank) {
          const first = buttons.get(edge.a).getBoundingClientRect();
          const second = buttons.get(edge.b).getBoundingClientRect();
          if (vertical) {
            const y = first.top - bounds.top - 5;
            d = 'M '+(first.left+first.width/2-bounds.left)+' '+(first.top-bounds.top)+' V '+y+' H '+(second.left+second.width/2-bounds.left)+' V '+(second.top-bounds.top);
          } else {
            const x = first.left - bounds.left - 6;
            d = 'M '+(first.left-bounds.left)+' '+start.y+' H '+x+' V '+end.y+' H '+(second.left-bounds.left);
          }
        } else if (vertical) {
          const mid = (start.y + end.y) / 2;
          d = 'M '+start.x+' '+start.y+' C '+start.x+' '+mid+', '+end.x+' '+mid+', '+end.x+' '+end.y;
        } else {
          const mid = (start.x + end.x) / 2;
          d = 'M '+start.x+' '+start.y+' C '+mid+' '+start.y+', '+mid+' '+end.y+', '+end.x+' '+end.y;
        }
        const path = document.createElementNS('http://www.w3.org/2000/svg','path');
        path.setAttribute('d',d);
        if (affectedPairs.has(pair)) path.classList.add('port-alert');
        else if (edge.kind === 'Транзитный сегмент') path.setAttribute('stroke-dasharray', '2 3');
        else if (pathKinds.has(edge.kind)) path.setAttribute('stroke-dasharray', '5 4');
        if (active.has(pair)) path.classList.add('active');
        svg.append(path);
      }
    }
  }
  const edgeKey = (a, b) => JSON.stringify([a, b].sort());

  const portKey = name => name.trim().toLowerCase().replace(/^(?:gi|gigabitethernet)\s*(\d+\/\d+\/\d+)$/, 'gi$1');
  const portKeys = port => [port.name, ...(port.aliases ?? [])].map(portKey);
  const lldpCounts = port => [
    port.lldpChassisCount && 'Шасси LLDP · ' + port.lldpChassisCount,
    port.lldpNeighborCount && port.lldpNeighborCount !== port.lldpChassisCount &&
      'Порты соседей LLDP · ' + port.lldpNeighborCount,
  ].filter(Boolean);
  const proxmoxPortStatus = port => port.proxmoxActive === undefined ? 'Нет подтверждения' :
    port.proxmoxActive ? 'Интерфейс активен в ОС' : 'Интерфейс не отмечен активным';

  function bridgePathLabel(uplink) {
    const label = uplink.viaMacTable ? 'Путь аплинка по MAC-таблице' : 'Аплинк моста';
    return uplink.configuredOnly ? label + ' · гостевой линк неактивен' : label;
  }

  function linksForPort(id, port) {
    const keys = portKeys(port);
    return incident.get(id).flatMap(edge => {
      const side = edge.a === id ? 'a' : 'b';
      const evidence = (edge.portEvidence ?? []).filter(report => {
        const label = report[side];
        return [label, ...label.split(' / ')].some(name => keys.includes(portKey(name)));
      });
      if (!evidence.length) return [];
      const confirmedReports = evidence.filter(report => report.confirmed);
      const confirmed = edge.confirmed && confirmedReports.length > 0;
      const sources = (confirmed ? confirmedReports : evidence).map(report => report.source).filter(Boolean);
      const scopedEdge = {...edge, portEvidence: evidence, confirmed};
      if (sources.length && !sources.includes(edge.source)) {
        scopedEdge.source = sources[0];
        scopedEdge.details = '';
      }
      return [scopedEdge];
    });
  }

  function guestsForPort(id, port) {
    const keys = portKeys(port);
    const guests = new Map();
    for (const edge of data.links) {
      if (!edge.confirmed) continue;
      for (const report of edge.portEvidence ?? []) {
        if (!report.confirmed || !report.virtual) continue;
        const {switchPorts, switchUplink, uplinks, bridgeActive, linkDisabled} = report.virtual;
        const guest = byId.get(edge.b);
        const macLabel = guest.kind === 'Контейнер' ? 'MAC контейнера замечен' : 'MAC ВМ замечен';
        const observations = (switchPorts ?? []).map(match => ({match, label: macLabel + ' · netctl FDB'}));
        if (switchUplink) {
          observations.push({match: switchUplink, label: bridgePathLabel(switchUplink)});
        }
        if (port.source === 'Proxmox' && !port.stale && edge.a === id && report.at &&
            (uplinks ?? []).some(name => keys.includes(portKey(name)))) {
          const labels = ['Интерфейс в конфигурации моста'];
          if (bridgeActive === false) labels.push('мост неактивен');
          if (linkDisabled) labels.push('адаптер гостя отключён');
          observations.push({match: {id, port: port.name, at: report.at}, label: labels.join(' · ')});
        }
        for (const {match, label} of observations) {
          if (match.id !== id || !keys.includes(portKey(match.port))) continue;
          if (!guests.has(guest.id)) guests.set(guest.id, new Set());
          const host = byId.get(edge.a).name;
          const vlan = match.vlan ? 'VLAN ' + match.vlan : '';
          guests.get(guest.id).add([label, host, report.a, report.b, vlan, formatTime(match.at)].filter(Boolean).join(' · '));
        }
      }
    }
    for (const row of data.guestSwitchAttachments?.[id] ?? []) {
      if (!keys.includes(portKey(row.switchPort))) continue;
      if (!guests.has(row.guest.id)) guests.set(row.guest.id, new Set());
      const {hostPort, switchPort, source, checkedAt} = row.physicalPair;
      guests.get(row.guest.id).add(
        `${row.guestPort} · ${row.bridge} · ${row.hypervisor.name} ${hostPort} ↔ ${row.switch.name} ${switchPort} · ${source} · ${formatTime(checkedAt)}`);
    }
    return guests;
  }

  function updateNodeUrl(id, port=null) {
    const url = new URL(window.location.href);
    if (id) url.searchParams.set('node', id);
    else url.searchParams.delete('node');
    if (port) url.searchParams.set('port', port);
    else url.searchParams.delete('port');
    window.history.replaceState(null, '', url);
  }

  function clearSelection() {
    buttons.get(selected)?.setAttribute('aria-pressed','false');
    selected = null;
    selectedPort = null;
    updateNodeUrl(null);
    for (const panel of [related, details]) {
      panel.replaceChildren();
      panel.hidden = true;
    }
  }

  function closeSelection() {
    const previous = selected;
    if (focusedRanks) renderView(view);
    else clearSelection();
    buttons.get(previous)?.focus({preventScroll: true});
    requestAnimationFrame(draw);
  }

  function renderRelated(id) {
    const ids = new Set([id]);
    if (focusedRanks) for (const peer of focusedRanks.keys()) ids.add(peer);
    for (const peer of connected.get(id)) ids.add(peer);
    const list = make('ul', null, 'map-related-list');
    for (const peerId of ids) {
      const peer = byId.get(peerId);
      const availability = availabilityOf(peer);
      const entry = make('li');
      const open = make('button', null, 'map-related-node');
      open.type = 'button';
      open.setAttribute('aria-pressed', String(peerId === id));
      const dot = make('i');
      dot.dataset.state = availability.color;
      const title = make('span', peer.guest ? 'ВМ ' + peer.vmid : peer.name);
      title.append(make('small', peer.guest ? peer.name : peer.kind));
      const state = make('span', availability.label, 'map-related-state');
      state.dataset.state = availability.color;
      open.append(dot, title, state);
      open.addEventListener('click', () => select(peerId));
      entry.append(open);
      list.append(entry);
    }
    related.replaceChildren(make('h2', 'Связанные объекты'), list);
    related.hidden = false;
  }

  function select(id, reveal=true) {
    const target = byId.get(id);
    if (!target) return;
    if (view === 'overview') {
      renderView('overview', id);
    } else if (!buttons.has(id)) {
      const clusterItem = target.guest || data.nodeOrder.includes(id) || id === data.clusterId;
      renderView(clusterItem ? 'cluster' : 'overview', clusterItem ? null : id);
    }
    if (!buttons.has(id)) return;
    renderSelection(id, reveal);
  }

  function selectPort(id, port) {
    const previous = selectedPort;
    renderSelection(id, false, port);
    const panel = details.querySelector('details[data-section="ports"]');
    panel.open = true;
    const control = [...panel.querySelectorAll('button[data-port]')]
      .find(button => button.dataset.port === (port ? '' : previous));
    control?.focus();
  }

  const agentAudits = new Map();

  async function refreshAgentStatus(label) {
    if (!label || !root.dataset.agentsUrl) return;
    const nodeId = label.dataset.agentStatus;
    let cached = agentAudits.get(nodeId);
    if (!cached || Date.now() >= cached.expires) {
      const url = new URL(root.dataset.agentsUrl, window.location.origin);
      url.searchParams.set('node_id', nodeId);
      cached = {expires: Infinity};
      cached.promise = (async () => {
        try {
          const response = await fetch(url, {
            cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8_000),
          });
          if (!response.ok) throw new Error('Agent audit request failed');
          return (await response.json()).infrastructure?.agentAudit;
        } catch {
          return null;
        } finally {
          cached.expires = Date.now() + 30_000;
        }
      })();
      agentAudits.set(nodeId, cached);
    }
    const agentAudit = await cached.promise;
    if (!label.isConnected) return;
    if (agentAudit?.sourceState !== 'ready') {
      label.textContent = 'Источник недоступен';
      return;
    }
    const entry = agentAudit.guests?.find(item => item.id === nodeId)
      ?? agentAudit.hypervisors?.find(item => item.id === nodeId);
    const reasons = {
      duplicate_guest_mac: 'Повторяющийся MAC в Proxmox',
      multiple_registrations: 'Несколько регистраций Endpoint',
      registration_matches_multiple_guests: 'Регистрация совпадает с несколькими узлами Proxmox',
      enrollment_registration_conflict: 'Регистрация расходится с данными MAC',
      enrollment_presence_unconfirmed: 'Состояние проверенной регистрации не подтверждено',
      no_matching_registration: 'Совпадений в Endpoint нет',
      guest_stopped: 'Гость выключен',
      guest_paused: 'Гость приостановлен',
      guest_not_started: 'Гостевая ОС ещё не запущена',
      guest_template: 'Шаблон Proxmox',
      proxmox_stale: 'Данные Proxmox устарели',
      proxmox_unconfirmed: 'Состояние гостя не подтверждено',
      network_config_unconfirmed: 'Настройки сети гостя не подтверждены',
      no_enabled_network_adapter: 'Нет включённого сетевого адаптера',
      no_unique_network_identity: 'Нет однозначного MAC для сопоставления',
      management_mac_unconfirmed: 'MAC адреса управления Proxmox не подтверждён',
    };
    label.textContent = entry?.presence === 'online'
      ? 'На связи · ' + formatTime(entry.lastSeenAt)
      : reasons[entry?.reason] ?? (entry?.state === 'matched' ? 'Связь не подтверждена' : 'Привязка не подтверждена');
    const identitySourceLabels = {
      verified_enrollment: 'Регистрация сверена на ВМ',
      active_mac_registration: 'Одна активная регистрация с этим MAC',
      proxmox_management_mac: 'MAC управления сверён по Proxmox и ARP',
    };
    if (Object.hasOwn(identitySourceLabels, entry?.identitySource)) {
      const proof = make('div');
      proof.append(make('small', [identitySourceLabels[entry.identitySource],
        entry.identityCheckedAt && formatTime(entry.identityCheckedAt)].filter(Boolean).join(' · ')));
      label.append(proof);
    }
    const system = entry?.operatingSystem;
    if (system) {
      const name = system.name || (system.platform === 'windows' ? 'Windows' : 'Linux');
      const build = system.build && !system.version?.split('.').includes(system.build) && `сборка ${system.build}`;
      const row = make('div');
      row.append(make('small', [
        ['ОС', name, system.version].filter(Boolean).join(' '), build,
        system.architecture, 'Инвентарь ' + formatTime(system.collectedAt),
      ].filter(Boolean).join(' · ')));
      label.append(row);
    }
    const health = entry?.health;
    if (health) {
      const row = make('div');
      const metrics = [];
      if (health.memoryAvailableBytes !== undefined) {
        const memory = (health.memoryAvailableBytes / 2**30).toLocaleString('ru-RU', {maximumFractionDigits: 2});
        metrics.push(`Доступно в ОС ${memory} ГиБ`);
      }
      if (health.loadAverage1m !== undefined) {
        const load = health.loadAverage1m.toLocaleString('ru-RU', {maximumFractionDigits: 2});
        metrics.push(`Нагрузка за 1 мин ${load}`);
      }
      if (health.uptimeSeconds !== undefined) metrics.push('Время работы ОС ' + formatUptime(health.uptimeSeconds));
      row.append(make('small', [...metrics, formatTime(health.checkedAt)].join(' · ')));
      label.append(row);
      if (health.services?.length) {
        const states = {active: 'активна', inactive: 'неактивна', failed: 'сбой', unknown: 'нет подтверждения'};
        const services = health.services.map(({name, status}) => name + ' — ' + states[status]);
        const units = make('div');
        units.append(make('small', 'Службы ОС · ' + services.join(' · ')));
        const outcomes = {reachable: 'отвечает', unreachable: 'недоступен', unknown: 'нет подтверждения'};
        for (const check of entry.networkServiceChecks ?? []) {
          const reading = make('small', `Сетевая проверка · ${check.method} ${check.target}:${check.port} · ${outcomes[check.state]} · ${formatTime(check.checkedAt)} · `);
          const service = make('a', byId.get(check.serviceId)?.name ?? check.serviceId);
          service.href = '?' + new URLSearchParams({node: check.serviceId});
          reading.append(service);
          units.append(reading);
        }
        label.append(units);
      }
    }
    const network = entry?.network;
    if (network) {
      const row = make('div');
      row.append(make('small', 'IPv4 по Endpoint · ' + formatTime(network.checkedAt) + (network.stale ? ' · устарело' : '')));
      if (network.snapshotAt) row.append(make('small', 'Снимок Endpoint · ' + formatTime(network.snapshotAt)));
      if (network.reason === 'no_reported_ipv4') row.append(make('small', 'Endpoint не сообщил IPv4'));
      for (const {name, ipv4} of network.interfaces) {
        row.append(make('small', name + ' · ' + ipv4.join(', ')));
      }
      const comparison = entry.ipv4Comparison;
      if (comparison) {
        for (const [key, title] of [['matched', 'Совпали с наблюдением сети'], ['endpointOnly', 'Видны только в Endpoint'],
                                    ['observedOnly', 'Видны только в наблюдении сети']]) {
          if (comparison[key].length) row.append(make('small', title + ' · ' + comparison[key].join(', ')));
        }
        for (const {address, guestPort, bridge, hypervisorId, switchId, physicalPair} of comparison.matchedPaths ?? []) {
          const host = byId.get(hypervisorId)?.name ?? hypervisorId;
          const path = make('small', `${address} · ${guestPort} → ${bridge} → ${host} ${physicalPair.hostPort} → `);
          path.append(portPairEndpoint(switchId, byId.get(switchId)?.name ?? switchId, physicalPair.switchPort));
          row.append(path);
        }
      }
      label.append(row);
    }
    const profileLabels = {health_v1: 'Состояние', network_v1: 'Сеть', inventory_v1: 'Инвентарь'};
    const displayedProfiles = {inventory_v1: system?.collectedAt, network_v1: network?.snapshotAt ?? network?.checkedAt};
    for (const {profile, collectedAt} of entry?.contextProfiles ?? []) {
      if (Object.hasOwn(profileLabels, profile) && displayedProfiles[profile] !== collectedAt) {
        const row = make('div');
        row.append(make('small', `${profileLabels[profile]} · ${formatTime(collectedAt)}`));
        label.append(row);
      }
    }
  }

  function switchPortButton(id, name, targetPort) {
    const open = make('button', name + ' ' + targetPort);
    open.type = 'button';
    open.addEventListener('click', () => {
      const port = byId.get(id)?.ports?.find(item => portKeys(item).includes(portKey(targetPort)));
      select(id);
      if (port && selected === id) selectPort(id, port.name);
    });
    return open;
  }

  function renderLacpHealth(node, placementHost, chosenPort) {
    const selectedKeys = chosenPort ? portKeys(chosenPort) : [];
    const reports = chosenPort ? data.nodes.flatMap(host => (host.lacpHealth ?? [])
      .filter(({switchId, aggregate, members}) => switchId === node.id &&
        [aggregate, ...members.map(member => member.name)].some(port => selectedKeys.includes(portKey(port))))
      .map(report => ({host, report}))) : (placementHost.lacpHealth ?? []).map(report => ({host: placementHost, report}));
    if (!reports.length) return null;

    const panel = make('section');
    panel.dataset.section = 'lacp-health';
    const list = make('ul', null, 'map-detail-list');
    const labels = {forwarding: 'Готов к передаче', down: 'Линк опущен', disabled: 'Порт отключён', unknown: 'Нет подтверждения'};
    for (const {host, report: {switchId, aggregate, members}} of reports) {
      const row = make('li');
      const sw = byId.get(switchId);
      const confirmed = members.filter(member => member.status === 'forwarding').length;
      if (chosenPort) {
        const open = make('button', host.name);
        open.type = 'button';
        open.addEventListener('click', () => select(host.id));
        row.append(open);
      }
      row.append(make('strong', `${sw.name} ${aggregate} · ${confirmed} из ${members.length} портов готовы к передаче`));
      const appendPort = port => {
        const target = sw.ports?.find(item => portKeys(item).includes(portKey(port)));
        if (target && !selectedKeys.includes(portKey(port))) row.append(switchPortButton(switchId, sw.name, target.name));
      };
      appendPort(aggregate);
      for (const {name: port, status, checkedAt, partnerPort, partnerInterfaceState} of members) {
        appendPort(port);
        const fields = [port, labels[status], partnerPort && `порт партнёра LACP №${partnerPort}`,
          partnerInterfaceState === 'unconfirmed' && 'Имя интерфейса не сверено',
          checkedAt && `SNMP · ${formatTime(checkedAt)}`];
        row.append(make('small', fields.filter(Boolean).join(' · ')));
      }
      list.append(row);
    }
    const title = chosenPort || placementHost === node ? 'Резервирование LACP' : `Подключение ${placementHost.name} по LACP`;
    panel.append(make('h3', title), list);
    return panel;
  }

  function ntpLabel(ntp) {
    return ntp ? [`NTPv${ntp.version}`, `stratum ${ntp.stratum}`, `LI ${ntp.leapIndicator}`, ntp.kissCode]
      .filter(Boolean).join(' · ') : '';
  }

  function certificateLabel(expiresAt, version) {
    return [version, `Срок действия до ${formatTime(expiresAt)}`].filter(Boolean).join(' · ');
  }

  function smbNegotiationLabel(dialect, signingRequired) {
    return `SMB ${dialect} · ${signingRequired ? 'сервер требует подпись' : 'сервер не требует подпись'}`;
  }

  function postgresqlTlsLabel(state, version) {
    if (state === 'negotiated') return `Согласован ${version ?? 'TLS'}`;
    if (state === 'declined') return 'Сервер отклонил TLS';
    if (state === 'failed') return 'Сбой согласования TLS';
    return '';
  }

  const serviceCheckReasons = {
    connection_refused: 'Отказ на UDP-запрос, источник не определён', timeout: 'Ответ не получен вовремя',
    icmp_port_unreachable: 'ICMP: UDP-порт недоступен', icmp_rejected: 'Получен отказ ICMP',
    icmp_no_echo_reply: 'Нет ответа ICMP Echo Reply', icmp_unreachable: 'Получено сообщение о недостижимости',
    icmp_reply_unconfirmed: 'Ответ ICMP не подтверждён',
    icmp_source_ssh_unavailable: 'Проверка с маршрутизатора пропущена из-за ошибки SSH',
    icmp_probe_error: 'Не удалось выполнить ICMP-проверку',
    ipsec_observation_unavailable: 'Нет свежих данных опроса',
    ipsec_ssh_unavailable: 'Опрос политик по SSH не выполнен',
    ipsec_policy_missing: 'Ожидаемая политика не найдена',
    ipsec_phase2_not_established: 'Политика найдена, фаза 2 не установлена',
    icmp_route_unconfirmed: 'Маршрут UI_VPN не подтверждён, ICMP не отправлен',
    icmp_route_mismatch: 'Выбран другой маршрут UI_VPN, ICMP не отправлен',
    transport_error: 'Ошибка сетевого запроса', unexpected_response: 'Ответ не соответствует запросу',
    sip_route_unconfirmed: 'Маршрут UI_VPN не подтверждён, SIP-запрос не отправлен',
    sip_route_mismatch: 'Выбран другой маршрут UI_VPN, SIP-запрос не отправлен',
    snmp_fdb_unavailable: 'Не получена актуальная таблица MAC',
    snmp_collection_failed: 'Последний сбор завершился ошибкой',
    snmp_collection_partial: 'Последний сбор завершился частично',
    snmp_collection_unconfirmed: 'Нет завершённого опроса',
    dns_no_answer: 'Нет записи запрошенного типа', dns_address_mismatch: 'Адреса не совпадают с ожидаемыми',
    dns_srv_mismatch: 'Имена или порты SRV не совпадают с ожидаемыми',
    dns_unexpected_source: 'DNS-ответ пришёл с другого адреса или порта',
    dns_truncated: 'UDP-ответ DNS усечён',
    dns_route_unconfirmed: 'Маршрут UI_VPN не подтверждён, DNS-запрос не отправлен',
    dns_route_mismatch: 'Выбран другой маршрут UI_VPN, DNS-запрос не отправлен',
    http_content_type: 'Неожиданный тип ответа', http_body_limit: 'Ответ превышает лимит проверки',
    http_content_encoding: 'Неподдерживаемое или повреждённое сжатие ответа',
    http_invalid_json: 'Ответ не содержит ожидаемый объект JSON',
    http_reported_unavailable: 'Приложение сообщило о сбое',
    http_payload_mismatch: 'Содержимое ответа не совпало с ожидаемым',
    oidc_rs256_key_missing: 'В JWKS нет пригодного публичного ключа подписи RS256',
    http_certificate_pin: 'Не совпал отпечаток сертификата',
    http_tls_certificate: 'Сертификат TLS не прошёл проверку', http_tls_error: 'Ошибка TLS',
    http_bad_response: 'Ответ HTTP неполный или некорректный',
    winrm_auth_required: 'WinRM запросил аутентификацию',
    http_connection_refused: 'Отклонено TCP-соединение', http_connection_reset: 'Сброшено TCP-соединение',
    tcp_connection_refused: 'Отклонено TCP-соединение',
    rdp_negotiation_rejected: 'Сервер отклонил согласование RDP',
    ntp_unsynchronized: 'Сервер NTP не предоставил синхронизированное время',
    ntp_rate_limited: 'Сервер NTP ограничил частоту запросов',
    ntp_access_denied: 'Сервер NTP отклонил запрос по правилам доступа',
    ntp_route_mismatch: 'Выбран другой маршрут UI_VPN, NTP-запрос не отправлен',
    ntp_route_unconfirmed: 'Маршрут UI_VPN не подтверждён, NTP-запрос не отправлен',
    rtsp_connection_refused: 'Отклонено TCP-соединение', rtsp_auth_required: 'Требуется авторизация',
    http_configuration: 'Ошибка настройки проверки',
    probe_configuration: 'Некорректный список проверок',
    probe_target_unconfirmed: 'Адрес цели не подтверждён',
    probe_target_mismatch: 'Адрес в настройках проверок не совпал с подтверждённым',
    probe_host_stopped: 'ВМ сервиса выключена',
    openvpn_tunnel_probe: 'Не удалось прочитать параметры туннеля',
    openvpn_management_unavailable: 'Не удалось прочитать сокет OpenVPN Management',
    openvpn_management_incomplete: 'OpenVPN Management вернул неполный ответ',
    openvpn_daemon_unconfirmed: 'OpenVPN Management не подтвердил состояние CONNECTED',
    openvpn_no_active_sessions: 'Нет активной сессии для подтверждения клиентской связности',
    openvpn_tunnel_missing: 'Туннельный интерфейс отсутствует',
    openvpn_tunnel_kind: 'Интерфейс другого типа',
    openvpn_tunnel_down: 'Туннельный интерфейс не поднят',
    openvpn_tunnel_address: 'На интерфейсе нет ожидаемого адреса',
    smb_mount_probe: 'Не удалось проверить подключение',
    smb_mount_idle: 'Автоподключение ещё не выполнено',
    smb_mount_missing: 'Подключение отсутствует',
    smb_mount_source: 'Подключён другой ресурс',
    smb_mount_read: 'Чтение метаданных каталога завершилось ошибкой',
    smb_mount_changed: 'Подключение сменилось во время проверки',
    postgresql_tls_handshake: 'Не удалось согласовать TLS',
    ssh_connection_refused: 'SSH-порт отклонил подключение',
    ssh_identification_invalid: 'Нет корректного ответа SSH',
    ssh_closed_before_identification: 'TCP принят, соединение закрыто без ответа SSH',
    ftp_connection_refused: 'Порт FTP отклонил подключение',
    ftp_unexpected_reply: 'Неожиданный код ответа FTP',
    ftp_invalid_reply: 'Неполный или некорректный ответ FTP',
    tls_certificate_pin: 'Отпечаток сертификата изменился',
    tls_certificate_expired: 'Срок действия сертификата истёк',
    tls_certificate_not_yet_valid: 'Сертификат ещё не вступил в силу',
    tls_certificate_unconfirmed: 'Сертификат TLS не подтверждён',
    tls_certificate_verification_failed: 'Сертификат TLS не прошёл проверку имени или цепочки доверия',
    ldaps_response_unconfirmed: 'Полный ответ RootDSE не подтверждён',
    ldaps_naming_context_mismatch: 'RootDSE вернул другой контекст каталога',
    ldaps_tls_certificate: 'Сертификат LDAPS не прошёл проверку',
    ldaps_connection_refused: 'Порт LDAPS отклонил подключение',
    ldaps_transport_unconfirmed: 'Соединение LDAPS не подтверждено',
    tls_connection_refused: 'Порт TLS отклонил подключение',
    icmp_identity_unconfirmed: 'Принадлежность адреса этому узлу не подтверждена',
    route_other_gateway: 'Активен другой шлюз', route_inactive: 'Маршрут через ожидаемый шлюз неактивен',
    route_rejecting: 'Активный маршрут отбрасывает трафик',
    route_multiple_gateways: 'Обнаружено несколько активных шлюзов',
    backup_no_result: 'Нет подтверждённого результата задания',
    backup_task_failed: 'Последнее копирование завершилось ошибкой',
    backup_overdue: 'Копия старше порога',
    backup_schedule_missing: 'ВМ отсутствует в активном расписании',
    backup_untracked_schedule: 'Есть активное задание без настроенного порога',
    vlan_probe_error: 'Не удалось проверить транзит',
    vlan_interface_missing: 'Интерфейс VLAN отсутствует',
    vlan_id_mismatch: 'Тип или номер VLAN не совпал',
    vlan_link_down: 'Интерфейс VLAN не поднят',
    vlan_address_mismatch: 'Локальный адрес не совпал',
    vlan_route_mismatch: 'Маршрут к соседу проходит вне ожидаемого VLAN',
    vlan_peer_identity_mismatch: 'MAC соседа отличается от MAC адаптера Proxmox',
    vlan_peer_identity_unconfirmed: 'MAC соседа по VLAN не подтверждён',
    wireguard_route_unconfirmed: 'Маршрут ядра не подтверждён',
    wireguard_route_mismatch: 'Ядро выбрало другой маршрут',
    wireguard_evidence_unavailable: 'Нет свежего отчёта о маркировке и WireGuard',
    wireguard_mark_unconfirmed: 'Входная маркировка не подтверждена',
    wireguard_mark_mismatch: 'Фактическая метка отличается',
    wireguard_handshake_unconfirmed: 'Нет свежего handshake с однозначно определённым пиром',
  };

  function renderServicePaths(paths) {
    if (!paths?.length) return null;
    const panel = make('section');
    panel.dataset.section = 'service-path';
    const list = make('ul', null, 'map-detail-list');
    const groups = new Map();
    for (const path of paths) {
      const attachment = path.routerAttachment ?? path.switchAttachment;
      const key = JSON.stringify([path.method, path.target, path.port, path.gateway, path.guestId, path.guestPort,
        path.hypervisorId, path.physicalPair?.hostPort, path.switchId, path.physicalPair?.switchPort,
        attachment?.routerId, attachment?.switchId, attachment?.port,
        path.lacpAttachment?.switchId, path.lacpAttachment?.aggregate]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(path);
    }
    for (const probes of groups.values()) {
      const [path] = probes;
      const endpoint = path.target + (path.port ? ':' + path.port : '');
      const label = [path.method, endpoint].join(' · ');
      const row = make('li');
      row.append(make('strong', label));
      const result = {reachable: 'Отвечает', unreachable: 'Недоступен', unknown: 'Нет подтверждения'};
      const readings = new Set();
      for (const probe of probes) {
        const rtt = probe.roundTripMs === undefined ? '' :
          `RTT ${probe.roundTripMs.toLocaleString('ru-RU', {maximumFractionDigits: 3})} мс`;
        const outcome = probe.localListener ? 'Открыт локально' :
          (probe.state !== 'reachable' && serviceCheckReasons[probe.reason]) || result[probe.state];
        const dns = probe.dns;
        const question = dns && [dns.transport, dns.record, dns.name].filter(Boolean).join(' ');
        const responder = dns?.unexpectedResponder;
        const responseFrom = probe.errorSource ? `Отказ от ${probe.errorSource}` :
          responder && `Ответ от ${responder.address}:${responder.port}`;
        const code = probe.httpStatus ? `HTTP ${probe.httpStatus}` : probe.responseCode ? `SIP ${probe.responseCode}` :
          probe.rtspStatus ? `RTSP ${probe.rtspStatus}` : probe.ftpReply ? `FTP ${probe.ftpReply}` : '';
        const rdp = probe.rdpSecurity ?? (probe.rdpFailureCode && `Код отказа RDP ${probe.rdpFailureCode}`);
        const tls = probe.tlsExpiresAt && certificateLabel(probe.tlsExpiresAt, probe.tlsVersion);
        const zabbix = probe.zabbixVersion && `Zabbix ${probe.zabbixVersion}`;
        const smb = probe.smbDialect && smbNegotiationLabel(probe.smbDialect, probe.smbSigningRequired);
        const postgres = postgresqlTlsLabel(probe.postgresqlTls, probe.tlsVersion);
        const redfish = probe.redfishVersion && `Redfish ${probe.redfishVersion}`;
        readings.add([probe.path, question, outcome, code, rdp, tls, zabbix, redfish, smb, postgres, ntpLabel(probe.ntp), responseFrom, rtt,
          probe.state && formatTime(probe.checkedAt)].filter(Boolean).join(' · '));
      }
      for (const reading of readings) {
        if (reading) row.append(make('small', reading));
      }
      if (path.lacpAttachment) {
        const {switchId, aggregate, checkedAt, members, aggregateState} = path.lacpAttachment;
        const device = byId.get(switchId)?.name ?? switchId;
        row.append(make('small', `LACP + ARP · ${formatTime(checkedAt)}`), switchPortButton(switchId, device, aggregate));
        if (aggregateState && !aggregateState.stale) {
          const {state, speedBps, checkedAt: observedAt} = aggregateState;
          const details = [portLabels[state], formatPortSpeed(speedBps), 'SNMP', formatTime(observedAt)];
          row.append(make('small', `Агрегат ${aggregate}: ${details.filter(Boolean).join(' · ')}`));
        }
        for (const {name, partnerPort, partnerInterfaceState} of members) {
          const gap = partnerInterfaceState === 'unconfirmed' ? ' · Имя интерфейса не подтверждено' : '';
          row.append(switchPortButton(switchId, device, name), make('small', `Порт партнёра LACP ${partnerPort}${gap}`));
        }
        list.append(row);
        continue;
      }
      const attachment = path.routerAttachment ?? path.switchAttachment;
      if (attachment) {
        const {routerId, switchId, port, source, checkedAt, physicalPair, archivedPeer, lldpPeers = []} = attachment;
        const deviceId = routerId ?? switchId;
        const device = byId.get(deviceId)?.name ?? deviceId;
        const evidence = switchId ? 'ARP + FDB коммутатора' : source;
        row.append(make('small', [evidence, formatTime(checkedAt)].join(' · ')),
          switchPortButton(deviceId, device, port));
        for (const peer of lldpPeers) {
          const label = formatLldpPortId(peer.portId, peer.portIdSubtype);
          row.append(make('small', `Объявление LLDP · ${label} · ${formatTime(peer.checkedAt)}`));
        }
        if (archivedPeer) {
          const {nodeId, port: peerPort, checkedAt: peerAt, inventorySources} = archivedPeer;
          const peer = byId.get(nodeId)?.name ?? nodeId;
          const reading = make('small');
          reading.append(portPairEndpoint(nodeId, peer, peerPort), ' · по архиву',
            peerAt ? ` · ${formatTime(peerAt)}` : '');
          row.append(reading);
          appendInventorySources(row, inventorySources);
        }
        if (physicalPair) {
          const {hostId, hostPort, source: pairSource, checkedAt: pairAt} = physicalPair;
          const host = byId.get(hostId);
          const name = host?.name ?? hostId;
          const hasPort = host?.ports?.some(item => portKeys(item).includes(portKey(hostPort)));
          row.append(hasPort ? switchPortButton(hostId, name, hostPort) : make('small', `${name} ${hostPort}`),
            make('small', ['Физическая пара подтверждена', pairSource, formatTime(pairAt)].join(' · ')));
        }
        list.append(row);
        continue;
      }
      const {hostPort, switchPort} = path.physicalPair;
      const guest = byId.get(path.guestId)?.name ?? path.guestId;
      const host = byId.get(path.hypervisorId)?.name ?? path.hypervisorId;
      const target = byId.get(path.switchId)?.name ?? path.switchId;
      const connection = path.management ? `${host} ${hostPort} · интерфейс управления`
        : [`${guest} ${path.guestPort}`, path.bridge, `${host} ${hostPort}`].join(' → ');
      row.append(make('small', connection),
        switchPortButton(path.switchId, target, switchPort));
      if (path.gateway) {
        row.append(make('small', 'Вход через шлюз ' + path.gateway));
      }
      if (path.localNeighbor) {
        row.append(make('small', `VLAN ${path.localNeighbor.vlan} · соседство на ${path.localNeighbor.interface} · физическая пара аплинка`));
      }
      list.append(row);
    }
    panel.append(make('h3', paths.every(path => path.routerAttachment) ? 'Порт маршрутизатора' : 'Путь до коммутатора'), list);
    return panel;
  }

  function renderHostPortPairs(host, pending = false, port = null) {
    const records = pending ? data.pendingPortPairs : data.currentPortPairs;
    const keys = port ? portKeys(port) : null;
    const pairs = (records ?? []).filter(pair =>
      (pair.a === host.id && (!keys || keys.includes(portKey(pair.portA)))) ||
      (pair.b === host.id && (!keys || keys.includes(portKey(pair.portB)))));
    if (!pairs.length) return null;
    const panel = make('details', null, 'map-port-panel');
    panel.dataset.section = pending ? 'service-host-pending-port-pairs' : 'service-host-port-pairs';
    const list = make('ul', null, 'map-detail-list');
    for (const pair of pairs) {
      const row = pending ? pendingPortPairRow(pair) : confirmedPortPairRow(pair);
      if (!pending && host.kind === 'Точка доступа') {
        const [switchId, switchPort] = pair.a === host.id ? [pair.b, pair.portB] : [pair.a, pair.portA];
        const port = data.servicePorts?.[switchId]?.find(item => portKey(item.port) === portKey(switchPort));
        const neighbor = port?.services.find(item => item.id === host.id && item.basis.includes('lldp_peer'));
        for (const check of neighbor?.linkChecks ?? []) row.append(make('small', formatLinkCheck(check)));
      }
      list.append(row);
    }
    panel.append(make('summary', pending ? 'Пары портов устройства без подтверждения' : 'Подтверждённые порты устройства'), list);
    return panel;
  }

  function renderInventoryPortPairs(host, port) {
    const keys = port ? portKeys(port) : null;
    const pairs = (data.inventoryPairs ?? []).filter(pair =>
      (pair.a === host.id && (!keys || keys.includes(portKey(pair.portA)))) ||
      (pair.b === host.id && (!keys || keys.includes(portKey(pair.portB)))));
    if (!pairs.length) return null;
    const panel = make('details', null, 'map-port-panel');
    panel.dataset.section = 'inventory-port-pairs';
    const list = make('ul', null, 'map-detail-list');
    for (const {a, b, portA, portB, inventorySources, endpointMacObservations = {}} of pairs) {
      const row = make('li');
      row.append(portPairEndpoint(a, byId.get(a)?.name ?? a, portA), ' ↔ ',
        portPairEndpoint(b, byId.get(b)?.name ?? b, portB));
      for (const [side, endpoint] of Object.entries(endpointMacObservations)) {
        const [device, port] = side === 'a' ? [a, portA] : [b, portB];
        row.append(make('small', `${byId.get(device)?.name ?? device} ${port} · ${formatEndpointMac(endpoint)}`));
      }
      appendInventorySources(row, inventorySources);
      list.append(row);
    }
    panel.append(make('summary', `Пары из обследований (${pairs.length})`), list);
    return panel;
  }

  function renderObservedHostPorts(host, paths) {
    const list = make('ul', null, 'map-detail-list');
    const rendered = new Set();
    for (const edge of incident.get(host.id) ?? []) {
      if (!edge.confirmed) continue;
      const switchSide = edge.a === host.id ? 'b' : 'a';
      const target = byId.get(edge[switchSide]);
      for (const reading of edge.portEvidence ?? []) {
        const endpoint = reading.learnedEndpoint;
        const port = reading[switchSide];
        if (!reading.confirmed || endpoint?.deviceId !== host.id || endpoint.switchId !== target.id || !port) continue;
        if (paths.some(path => path.switchAttachment?.switchId === target.id
            && portKey(path.switchAttachment.port) === portKey(port))) continue;
        const key = [target.id, portKey(port), endpoint.mac].join('/');
        if (rendered.has(key)) continue;
        rendered.add(key);
        const row = make('li');
        row.append(switchPortButton(target.id, target.name, port),
          make('small', [endpoint.mac, reading.source, formatTime(reading.at)].join(' · ')));
        list.append(row);
      }
    }
    if (!rendered.size) return null;
    const panel = make('section');
    panel.dataset.section = 'observed-host-ports';
    panel.append(make('h3', 'MAC на порту коммутатора'), list);
    return panel;
  }

  function renderGuestAttachment(attachment) {
    if (!attachment?.interfaces.length) return null;
    const panel = make('details', null, 'map-port-panel');
    panel.dataset.section = 'guest-attachment';
    panel.open = attachment.interfaces.some(iface => iface.switchObservations.some(item => item.physicalPair));
    const list = make('ul', null, 'map-detail-list');
    const labels = {
      guest_mac: 'MAC гостя замечен',
      bridge_uplink: 'Аплинк моста наблюдался',
      configured_bridge: 'Привязка по конфигурации',
    };
    const bridgeModes = {
      enabled: 'VLAN-aware включён в конфигурации моста',
      disabled: 'VLAN-aware выключен в конфигурации моста',
      not_reported: 'VLAN-aware в конфигурации моста не указан',
    };
    for (const iface of attachment.interfaces) {
      const row = make('li');
      row.append(make('strong', [iface.guestPort, iface.bridge, attachment.hypervisor.name].filter(Boolean).join(' → ')));
      const state = iface.linkDisabled ? 'Адаптер отключён' : iface.bridgeActive === false ? 'Мост неактивен' : '';
      if (state) row.append(make('small', state));
      if (iface.bridgeVlanConfig) {
        const {mode, source, checkedAt} = iface.bridgeVlanConfig;
        if (Object.hasOwn(bridgeModes, mode)) {
          row.append(make('small', [bridgeModes[mode], source, formatTime(checkedAt)].join(' · ')));
        }
      }
      for (const {address, source, method, checkedAt} of iface.ipv4Observations ?? []) {
        row.append(make('small', [address, source, method, formatTime(checkedAt)].join(' · ')));
      }
      if (iface.arpDiagnostic) {
        const {address, interface: sourcePort, sourceIP, state, checkedAt, identityCheckedAt} = iface.arpDiagnostic;
        const result = {no_reply: 'нет ответа', matched: 'MAC совпал', different_mac: 'ответил другой MAC',
          unconfirmed: 'ответ не подтверждён'}[state];
        row.append(make('small', [
          `ARP к ${address}: ${result}`, `UI_VPN ${sourcePort} (${sourceIP})`, formatTime(checkedAt),
          'IP из таблицы маршрутизатора · ' + formatTime(identityCheckedAt),
        ].join(' · ')));
      }
      if (iface.localNeighbor) {
        const {vlan, interface: localInterface, peerAddress, checkedAt} = iface.localNeighbor;
        row.append(make('small', ['Соседство VLAN ' + vlan + ' подтверждено', localInterface + ' → ' + peerAddress,
          formatTime(checkedAt)].join(' · ')));
      }
      if (!iface.switchObservations.length) row.append(make('small', 'Порт коммутатора не подтверждён'));
      if (iface.ambiguousSwitchPorts?.length) {
        row.append(make('small', 'MAC гостя виден на нескольких портах. Порт адаптера не определён однозначно.'));
      }
      for (const observation of iface.switchObservations) {
        const {basis, physicalPair, switch: target, switchPort, checkedAt, vlanMemberships} = observation;
        const targetPort = physicalPair?.switchPort ?? switchPort;
        if (physicalPair) row.append(make('small', 'Интерфейс хоста ' + physicalPair.hostPort + ' ↔'));
        row.append(switchPortButton(target.id, target.name, targetPort));
        const vlan = observation.vlan ?? iface.vlan;
        row.append(make('small', [labels[basis], vlan && 'VLAN ' + vlan, formatTime(checkedAt)].filter(Boolean).join(' · ')));
        if (basis === 'bridge_uplink') row.append(make('small', 'MAC гостя на коммутаторе не подтверждён'));
        if (physicalPair) row.append(make('small',
          ['Физическая пара подтверждена', physicalPair.source, formatTime(physicalPair.checkedAt)].join(' · ')));
        if (vlanMemberships) {
          const modes = {tagged: 'с тегом', untagged: 'без тега'};
          for (const [side, reading] of Object.entries(vlanMemberships.ports)) {
            const port = side === 'host' ? physicalPair.hostPort : targetPort;
            row.append(make('small', [
              `VLAN ${vlanMemberships.id} на ${port}`, modes[reading.egress], reading.pvid && 'PVID',
              reading.source, formatTime(reading.checkedAt),
            ].filter(Boolean).join(' · ')));
          }
        }
        if (physicalPair && iface.localNeighbor && vlanMemberships?.id !== iface.localNeighbor.vlan) {
          row.append(make('small', `VLAN ${iface.localNeighbor.vlan} на этой физической паре пока без наблюдений`));
        }
      }
      list.append(row);
    }
    panel.append(make('summary', 'Сетевой путь'), list);
    return panel;
  }

  function renderSelection(id, reveal, port=null) {
    buttons.get(selected)?.setAttribute('aria-pressed','false');
    selected = id;
    const node = byId.get(id);
    const chosenPort = port ? node.ports?.find(item => portKeys(item).includes(portKey(port))) : null;
    selectedPort = chosenPort?.name ?? null;
    updateNodeUrl(id, selectedPort);
    details.replaceChildren();
    const button = buttons.get(id);
    button.setAttribute('aria-pressed','true');
    details.hidden = false;
    const heading = make('div', null, 'map-detail-heading');
    const close = make('button','Закрыть','map-close');
    close.type = 'button';
    close.addEventListener('click', closeSelection);
    const availability = availabilityOf(node);
    const state = make('p', availability.label, 'map-state');
    state.dataset.state = availability.color;
    const identity = make('div', null, 'map-detail-identity');
    identity.append(make('h2', node.name), state);
    heading.append(identity, close);
    const properties = make('dl');
    const observation = node.reachability ?? {};
    const checked = observation.checkedAt ? formatTime(observation.checkedAt) + (observation.stale ? ' · устарело' : '') : '';
    const items = {
      'Тип': node.kind, 'VMID': node.guest ? String(node.vmid) : '', 'Узел Proxmox': node.pveHost,
      'Доступность узла': {reachable:'Доступен', unreachable:'Недоступен', stopped:'Выключен'}[observation.state] ?? 'Нет подтверждения',
      'Источник': observation.source, 'Способ проверки': observation.method, 'Проверено': checked,
    };
    for (const [name,value] of Object.entries(items)) {
      if (value) properties.append(make('dt',name), make('dd',value));
    }
    if ((node.guest || node.kind === 'Гипервизор') && observation.state !== 'stopped') {
      const agent = make('dd', 'Проверяется…');
      agent.dataset.agentStatus = node.id;
      agent.setAttribute('aria-live', 'polite');
      properties.append(make('dt', 'Агент Endpoint'), agent);
      void refreshAgentStatus(agent);
    }
    const columns = make('div', null, 'map-detail-columns');
    const propertiesSection = make('section');
    propertiesSection.append(make('h3', 'Доступность'), properties);
    if (node.checks?.length) {
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'checks';
      panel.open = node.checks.some(check => (check.required && check.status !== 'ok')
        || (check.unit && ['warn', 'critical'].includes(check.status)));
      const list = make('ul', null, 'map-detail-list');
      const errors = {
        timeout: 'Нет ответа от проверки', transport: 'Ошибка соединения сборщика',
        parse: 'Сборщик не смог прочитать ответ', unexpected_response: 'Неожиданный ответ',
      };
      const priority = check => check.required && check.status !== 'ok' ? 0 : 1;
      const ordered = [...node.checks].sort((a, b) => priority(a) - priority(b));
      const backupStates = {succeeded: 'Выполнено', failed: 'Сбой запуска',
        running: 'Выполняется', unconfirmed: 'Результат не подтверждён'};
      for (const check of ordered) {
        const row = make('li');
        const value = measurement(check.unit, check.observed);
        const disk = check.diskCapacity;
        const capacity = disk && `${measurement('bytes', disk.freeBytes)} из ${measurement('bytes', disk.totalBytes)}`;
        const threshold = measurement(check.unit, check.warningThreshold);
        const limit = check.unit === 'hours' ? 'предел ' : 'порог предупреждения ';
        const memoryMeasurement = /^(windows|linux)_memory_available_/.test(check.name);
        const status = check.status === 'ok' && memoryMeasurement ? 'Измерено' : observerStates[check.status];
        const job = check.backupJob;
        const jobDetails = job ? [backupStates[job.state],
          job.exitCode !== null && `код ${job.exitCode}`,
          job.completedAt && `завершено ${formatTime(job.completedAt)}`,
          job.timerActive === false && 'таймер неактивен',
          job.timerActive === null && 'состояние таймера не подтверждено'] : [status];
        const notes = [...jobDetails, errors[check.error], value, capacity, threshold && limit + threshold,
          check.required && 'обязательная проверка', check.checkedAt && formatTime(check.checkedAt),
          check.stale && 'устарело'];
        row.append(make('strong', check.label || check.name), make('small', notes.filter(Boolean).join(' · ')));
        if (check.backupRepository) {
          const {usedBytes, maximumBytes, freeGiB, minimumFreeGiB, checkedAt} = check.backupRepository;
          row.append(make('small', [
            `Репозиторий ${measurement('bytes', usedBytes)} из ${measurement('bytes', maximumBytes)}`,
            `Свободно ${observerNumber.format(freeGiB)} ГиБ при минимуме ${observerNumber.format(minimumFreeGiB)} ГиБ`,
            'Watchdog · ' + formatTime(checkedAt),
          ].join(' · ')));
        }
        if (check.sourceNodeId && byId.has(check.sourceNodeId)) {
          const link = make('a', 'Источник · ' + byId.get(check.sourceNodeId).name);
          link.href = '?' + new URLSearchParams({node: check.sourceNodeId});
          row.append(link);
        }
        list.append(row);
      }
      panel.append(make('summary', 'Проверки Server Observer'), list);
      propertiesSection.append(panel);
    }
    if (node.hardwarePower) {
      const {state, checkedAt, restorePolicy, lastResetAt} = node.hardwarePower;
      const labels = {On: 'Включён', Off: 'Выключен', PoweringOn: 'Включается', PoweringOff: 'Выключается'};
      propertiesSection.append(make('h3', 'Питание сервера'),
        make('p', labels[state] + ' · Redfish · ' + formatTime(checkedAt)));
      const restoreLabels = {AlwaysOff: 'Остаться выключенным', AlwaysOn: 'Включиться', LastState: 'Вернуть прежнее состояние'};
      if (restorePolicy) propertiesSection.append(make('p', 'После восстановления электропитания · ' + restoreLabels[restorePolicy]));
      if (lastResetAt) propertiesSection.append(make('p', 'Последний сброс по Redfish · ' + formatTime(lastResetAt)));
    }
    const measurements = Object.entries(node.properties ?? {})
      .filter(([name, value]) => value && !items[name]
        && !(node.resources?.cpuRatio !== undefined && name === 'CPU по Proxmox')
        && !(node.resources?.memoryTotalBytes !== undefined && ['Память по Proxmox', 'Память (выделено)'].includes(name)));
    if (node.probeTransition) {
      const {to, previousCheckedAt, checkedAt} = node.probeTransition;
      const state = to === 'reachable' ? 'Снова отвечает' : 'Перестал отвечать';
      measurements.unshift(['Последнее изменение', `${state} · между ${formatTime(previousCheckedAt)} и ${formatTime(checkedAt)}`]);
    }
    if (node.firmware) {
      const {product, version, build, source, checkedAt, observerId, observerPort} = node.firmware;
      const observer = byId.get(observerId)?.name;
      measurements.push(['Версия ПО', [
        product + ' ' + version, build && 'сборка ' + build, source,
        observer && observer + ' · ' + observerPort, formatTime(checkedAt),
      ].filter(Boolean).join(' · ')]);
    }
    if (node.guestNetwork) {
      const {configured, enabled, disabled} = node.guestNetwork;
      const unresolved = configured - enabled - disabled;
      const network = configured ? [
        'настроено ' + configured, 'включено ' + enabled,
        disabled && 'отключено ' + disabled, unresolved && 'без сведений о мосте ' + unresolved,
      ].filter(Boolean).join(' · ') : 'Не заданы';
      measurements.push(['Адаптеры Proxmox', network]);
    }
    if (measurements.length) {
      const list = make('dl');
      for (const [name, value] of measurements) {
        list.append(make('dt', name), make('dd', value));
      }
      propertiesSection.append(make('h3', 'Параметры узла'), list);
    }
    let placementHost = node;
    if (node.kind === 'Сервис') {
      const hosts = new Set((incident.get(id) ?? [])
        .filter(edge => edge.b === id && edge.confirmed && ['Размещение', 'Цель проверки'].includes(edge.kind))
        .map(edge => edge.a));
      if (hosts.size === 1) {
        const [hostId] = hosts;
        const host = byId.get(hostId);
        if (host) placementHost = host;
      }
    }
    const resourceHost = placementHost.guest ? placementHost : node;
    const paths = data.servicePaths?.[id] ?? [];
    const servicePaths = renderServicePaths(paths);
    if (servicePaths) propertiesSection.append(servicePaths);
    for (const edge of incident.get(placementHost.id) ?? []) {
      if (edge.b !== placementHost.id || edge.kind !== 'Управление оборудованием') continue;
      const controller = byId.get(edge.a);
      if (controller?.kind !== 'Контроллер управления') continue;
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'hardware-management';
      const open = make('a', controller.name);
      open.href = '?' + new URLSearchParams({node: controller.id});
      panel.append(make('summary', 'Управление оборудованием'), open);
      if (!edge.confirmed) panel.append(make('small', 'Принадлежность контроллера серверу не подтверждена'));
      const controllerPaths = renderServicePaths(data.servicePaths?.[controller.id]);
      if (controllerPaths) panel.append(controllerPaths);
      for (const pairs of [renderHostPortPairs(controller), renderInventoryPortPairs(controller),
        renderHostPortPairs(controller, true)]) {
        if (pairs) panel.append(pairs);
      }
      propertiesSection.append(panel);
    }
    if (node.kind === 'Сервис' && placementHost !== node && !placementHost.guest) {
      if (!servicePaths) {
        const portPairs = renderHostPortPairs(placementHost);
        if (portPairs) propertiesSection.append(portPairs);
      }
      const pendingPairs = renderHostPortPairs(placementHost, true);
      if (pendingPairs) propertiesSection.append(pendingPairs);
      const inventoryPairs = renderInventoryPortPairs(placementHost);
      if (inventoryPairs) propertiesSection.append(inventoryPairs);
      const observedPorts = renderObservedHostPorts(placementHost, paths);
      if (observedPorts) propertiesSection.append(observedPorts);
    }
    if (node.kind !== 'Сервис' && !node.guest) {
      for (const pending of [false, true]) {
        const pairs = renderHostPortPairs(node, pending, chosenPort);
        if (pairs) propertiesSection.append(pairs);
      }
      const inventoryPairs = renderInventoryPortPairs(node, chosenPort);
      if (inventoryPairs) propertiesSection.append(inventoryPairs);
    }
    const guestAttachment = renderGuestAttachment(data.guestAttachments?.[resourceHost.id]);
    if (guestAttachment) {
      if (servicePaths) guestAttachment.open = false;
      propertiesSection.append(guestAttachment);
    }
    if (resourceHost.resources) {
      const {cpuRatio, logicalCpus, memoryUsedBytes, memoryTotalBytes, rootUsedBytes, rootTotalBytes,
        uptimeSeconds, checkedAt} = resourceHost.resources;
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const percent = ratio => number.format(ratio * 100) + '%';
      const usage = (used, total) => `${number.format(used / 2**30)} из ${number.format(total / 2**30)} ГиБ (${percent(used / total)})`;
      const list = make('dl');
      if (cpuRatio !== undefined) list.append(make('dt', 'CPU'), make('dd', percent(cpuRatio)));
      if (logicalCpus !== undefined) {
        list.append(make('dt', resourceHost.guest ? 'vCPU' : 'Логические CPU'), make('dd', number.format(logicalCpus)));
      }
      if (memoryTotalBytes !== undefined) list.append(make('dt', 'Память'), make('dd', usage(memoryUsedBytes, memoryTotalBytes)));
      if (rootTotalBytes !== undefined) list.append(make('dt', 'Корневой раздел /'), make('dd', usage(rootUsedBytes, rootTotalBytes)));
      if (uptimeSeconds !== undefined) {
        list.append(make('dt', 'Время работы'), make('dd', formatUptime(uptimeSeconds)));
      }
      if (resourceHost.guestIo) {
        const {networkInBytesPerSecond, networkOutBytesPerSecond, diskReadBytesPerSecond,
          diskWriteBytesPerSecond, intervalSeconds} = resourceHost.guestIo;
        const rate = bytes => {
          if (bytes >= 2**20) return number.format(bytes / 2**20) + ' МиБ/с';
          if (bytes >= 2**10) return number.format(bytes / 2**10) + ' КиБ/с';
          return number.format(bytes) + ' Б/с';
        };
        if (networkInBytesPerSecond !== undefined) {
          list.append(make('dt', 'Сеть, приём / передача'),
            make('dd', rate(networkInBytesPerSecond) + ' / ' + rate(networkOutBytesPerSecond)));
        }
        if (diskReadBytesPerSecond !== undefined) {
          list.append(make('dt', 'Диск, чтение / запись'),
            make('dd', rate(diskReadBytesPerSecond) + ' / ' + rate(diskWriteBytesPerSecond)));
        }
        list.append(make('dt', 'Интервал измерения'), make('dd', number.format(intervalSeconds) + ' с'));
      }
      list.append(make('dt', 'Опрос ресурсов'), make('dd', formatTime(checkedAt)));
      const section = make('section');
      section.dataset.section = 'proxmox-resources';
      section.append(make('h3', resourceHost.guest ? 'Ресурсы ВМ' : 'Ресурсы Proxmox'));
      if (resourceHost !== node) {
        const button = make('button', resourceHost.name);
        button.type = 'button';
        button.addEventListener('click', () => select(resourceHost.id));
        section.append(button);
      }
      section.append(list);
      propertiesSection.append(section);
    }
    if (node.resourceCapacity) {
      const {root, swap, memory, thresholds, checkedAt, stale} = node.resourceCapacity;
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const measure = (bytes, total) => `${number.format(bytes / 2**30)} ГиБ (${number.format(100 * bytes / total)}%)`;
      const list = make('dl');
      const rootText = root.status === 'unknown' ? 'Нет подтверждения' : measure(root.availableBytes, root.totalBytes);
      const swapText = swap.status === 'unknown' ? 'Нет подтверждения' : swap.status === 'not_configured'
        ? 'Не настроен' : measure(swap.usedBytes, swap.totalBytes);
      list.append(make('dt', 'Доступно на разделе /'), make('dd', rootText + (root.status === 'warn'
        ? ` · порог ${thresholds.rootFreePercent}%` : '')),
        make('dt', 'Занято в swap'), make('dd', swapText + (swap.status === 'warn'
          ? ` · порог ${thresholds.swapUsedPercent}%` : '')));
      if (memory) {
        const available = memory.availableBytes !== undefined;
        list.append(make('dt', available ? 'Доступная память' : 'Свободная память по Proxmox'),
          make('dd', measure(available ? memory.availableBytes : memory.freeBytes, memory.totalBytes)));
      }
      if (checkedAt) list.append(make('dt', 'Опрос ёмкости'), make('dd', formatTime(checkedAt) + (stale ? ' · устарел' : '')));
      propertiesSection.append(make('h3', 'Ёмкость узла'), list);
    }
    if (node.hardwareDisks) {
      const {checkedAt, disks} = node.hardwareDisks;
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'hardware-disks';
      panel.open = disks.some(disk => disk.smartState === 'critical');
      const status = {ok: 'SMART в норме', critical: 'Ошибка SMART', unknown: 'Нет данных SMART'};
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const list = make('ul', null, 'map-detail-list');
      for (const disk of disks) {
        const row = make('li');
        const size = disk.sizeBytes ? number.format(disk.sizeBytes / 2**30) + ' ГиБ' : '';
        const endurance = disk.endurancePercent !== undefined ? 'Ресурс по Proxmox ' + number.format(disk.endurancePercent) + '%' : '';
        row.append(make('strong', disk.device), make('small', [disk.kind.toUpperCase(), status[disk.smartState], size, endurance].filter(Boolean).join(' · ')));
        list.append(row);
      }
      panel.append(make('summary', `Физические диски (${disks.length})`), make('small', 'Proxmox · ' + formatTime(checkedAt)), list);
      propertiesSection.append(panel);
    }
    if (node.zfsPools) {
      const {checkedAt, pools} = node.zfsPools;
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'zfs-pools';
      panel.open = pools.some(pool => !['ONLINE', 'UNKNOWN'].includes(pool.health));
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const list = make('ul', null, 'map-detail-list');
      for (const pool of pools) {
        const row = make('li');
        const health = pool.health === 'UNKNOWN' ? 'Нет данных о состоянии' : pool.health;
        const capacity = pool.sizeBytes ? number.format(pool.sizeBytes / 2**30) + ' ГиБ всего' : '';
        const free = pool.freeBytes !== undefined ? number.format(pool.freeBytes / 2**30) + ' ГиБ свободно' : '';
        row.append(make('strong', pool.name), make('small', [health, free, capacity].filter(Boolean).join(' · ')));
        list.append(row);
      }
      panel.append(make('summary', `Пулы ZFS (${pools.length})`), make('small', 'Proxmox · ' + formatTime(checkedAt)), list);
      propertiesSection.append(panel);
    }
    if (node.lvmThinPools) {
      const {checkedAt, warningThresholdPercent, pools} = node.lvmThinPools;
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'lvm-thin-pools';
      panel.open = pools.some(pool => pool.capacityStatus === 'warn');
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const usage = (used, size) => size === undefined ? 'нет данных'
        : `${number.format(used / 2**30)} из ${number.format(size / 2**30)} ГиБ (${number.format(100 * used / size)}%)`;
      const list = make('ul', null, 'map-detail-list');
      for (const pool of pools) {
        const row = make('li');
        row.append(make('strong', pool.volumeGroup + '/' + pool.name),
          make('small', 'Данные · ' + usage(pool.usedBytes, pool.sizeBytes)),
          make('small', 'Метаданные · ' + usage(pool.metadataUsedBytes, pool.metadataSizeBytes)));
        if (pool.capacityStatus === 'warn') row.append(make('small', 'Порог заполнения достигнут'));
        list.append(row);
      }
      panel.append(make('summary', `Пулы LVM-thin (${pools.length})`),
        make('small', 'Порог ' + warningThresholdPercent + '% · Proxmox · ' + formatTime(checkedAt)), list);
      propertiesSection.append(panel);
    }
    if (node.storageAssignments) {
      const {checkedAt, hosts} = node.storageAssignments;
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'storage-assignments';
      const list = make('ul', null, 'map-detail-list');
      for (const host of hosts) {
        const row = make('li');
        const open = make('button', byId.get(host.id).name);
        open.type = 'button';
        open.addEventListener('click', () => select(host.id));
        row.append(open);
        for (const storage of host.storages) {
          row.append(make('small', `${storage.id} · ВМ и контейнеров: ${storage.guestCount} · дисков: ${storage.diskCount}`));
        }
        list.append(row);
      }
      panel.append(make('summary', 'Хранилища из конфигураций ВМ'),
        make('small', 'Proxmox · ' + formatTime(checkedAt)), list);
      propertiesSection.append(panel);
    }
    if (node.backupScope) {
      const {storage, total, scheduled, notScheduled, unknown, running, runningGaps = []} = node.backupScope;
      const list = make('dl');
      list.append(make('dt', 'Хранилище'), make('dd', storage),
        make('dt', 'В расписании'), make('dd', `${scheduled} из ${total}`),
        make('dt', 'Вне расписания'), make('dd', String(notScheduled)),
        make('dt', 'Без подтверждения'), make('dd', String(unknown)));
      const panel = make('section');
      panel.dataset.section = 'backup-scope';
      panel.append(make('h3', 'Расписание копирования ВМ и контейнеров'), list);
      if (running && runningGaps.length) {
        const review = make('details');
        const count = running.notScheduled + running.unknown;
        const guests = make('ul', null, 'map-detail-list');
        for (const {id, name, vmid, state} of runningGaps) {
          const row = make('li');
          const open = make('button', `ВМ/КТ ${vmid} · ${name}`);
          open.type = 'button';
          open.addEventListener('click', () => select(id));
          row.append(open, make('small', state === 'not_scheduled' ? 'Вне расписания' : 'Расписание не подтверждено'));
          guests.append(row);
        }
        review.append(make('summary', `Проверить расписание запущенных ВМ и контейнеров · ${count}`), guests);
        if (count > runningGaps.length) {
          review.append(make('small', `Показано ${runningGaps.length} из ${count}`));
        }
        panel.append(review);
      }
      propertiesSection.append(panel);
    }
    if (node.backupCoverage) {
      const {storage, serviceId, state, checkedAt, stale} = node.backupCoverage;
      const labels = {
        scheduled: 'В активном расписании',
        not_scheduled: 'Отсутствует в активном расписании',
        unknown: 'Расписание не подтверждено',
      };
      const list = make('ul', null, 'map-detail-list');
      const row = make('li');
      const label = labels[state] + ' · ' + storage;
      if (byId.has(serviceId)) {
        const open = make('button', label);
        open.type = 'button';
        open.addEventListener('click', () => select(serviceId));
        row.append(open);
      } else {
        row.append(make('strong', label));
      }
      if (state === 'scheduled' && !node.serviceChecks?.some(check => check.backupVmid === node.vmid)) {
        row.append(make('small', 'Порог свежести не настроен'));
      }
      row.append(make('small', 'Proxmox · ' + formatTime(checkedAt) + (stale ? ' · устарело' : '')));
      list.append(row);
      propertiesSection.append(make('h3', 'Резервное копирование'), list);
    }
    if (node.guestStorage) {
      const list = make('dl');
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 2});
      for (const {device, storage, sizeBytes} of node.guestStorage.disks) {
        const size = sizeBytes >= 2**30 ? `${number.format(sizeBytes / 2**30)} ГиБ`
          : sizeBytes >= 2**20 ? `${number.format(sizeBytes / 2**20)} МиБ`
          : sizeBytes ? `${number.format(sizeBytes)} Б` : '';
        list.append(make('dt', device), make('dd', [storage, size].filter(Boolean).join(' · ')));
      }
      list.append(make('dt', 'Конфигурация прочитана'), make('dd', formatTime(node.guestStorage.checkedAt)));
      propertiesSection.append(make('h3', 'Диски по конфигурации Proxmox'), list);
    }
    const lacpHealth = renderLacpHealth(node, placementHost, chosenPort);
    if (lacpHealth) propertiesSection.append(lacpHealth);
    if (node.downstream) {
      const {upstreamId, port, basis, checkedAt, stpCheckedAt, deviceCount, devices} = node.downstream;
      const panel = make('details', null, 'map-port-panel');
      const list = make('ul', null, 'map-detail-list');
      const labels = {reachable: 'Доступен', unreachable: 'Недоступен', unknown: 'Нет подтверждения'};
      for (const {mac, ip, reachability, switchPort} of devices) {
        const row = make('li');
        row.append(make('strong', ip ?? mac), make('small', [ip && mac, labels[reachability.state],
          reachability.method, reachability.checkedAt && formatTime(reachability.checkedAt)].filter(Boolean).join(' · ')));
        if (switchPort) {
          const portButton = make('button', switchPort.name);
          portButton.type = 'button';
          portButton.addEventListener('click', () => selectPort(id, switchPort.name));
          row.append(portButton, make('small', 'MAC виден на порту · SNMP · ' + formatTime(switchPort.checkedAt)));
        }
        list.append(row);
      }
      const method = {
        lldp: 'Аплинк по LLDP',
        reciprocal_mac: 'Путь по взаимным MAC',
        inventory_stp: 'Порты по инвентарю · STP',
      }[basis ?? 'lldp'];
      const source = [`${byId.get(upstreamId).name} ${port}`, method,
        formatTime(stpCheckedAt ?? checkedAt)].join(' · ');
      const count = devices.length === deviceCount ? deviceCount : `${devices.length} из ${deviceCount}`;
      panel.append(make('summary', `Устройства за коммутатором (${count})`), make('small', source), list);
      propertiesSection.append(panel);
    }
    if (node.stpRoot) {
      const {localPort, rootBridgeMac, rootDeviceId, checkedAt} = node.stpRoot;
      const list = make('ul', null, 'map-detail-list');
      const row = make('li');
      const port = make('button', localPort);
      port.type = 'button';
      port.addEventListener('click', () => selectPort(id, localPort));
      const bridge = [byId.get(rootDeviceId)?.name, rootBridgeMac].filter(Boolean).join(' · ');
      row.append(port, make('small', bridge), make('small', 'SNMP · ' + formatTime(checkedAt)));
      list.append(row);
      propertiesSection.append(make('h3', 'Корневой мост STP'), list);
    }
    if (node.stpRootPath) {
      const {localPort, designatedBridgeMac, designatedPortId, checkedAt, bridgeDeviceId,
        designatedPortName, designatedPortCheckedAt} = node.stpRootPath;
      const list = make('ul', null, 'map-detail-list');
      const row = make('li');
      const port = make('button', localPort);
      port.type = 'button';
      port.addEventListener('click', () => selectPort(id, localPort));
      const bridge = [byId.get(bridgeDeviceId)?.name, designatedBridgeMac].filter(Boolean).join(' · ');
      row.append(port, make('small', 'Назначенный мост · ' + bridge),
        make('small', 'Идентификатор порта STP · ' + designatedPortId),
        make('small', 'SNMP · ' + formatTime(checkedAt)));
      if (designatedPortName) {
        const remote = make('button', `Порт назначенного моста ${designatedPortName}`);
        remote.type = 'button';
        remote.addEventListener('click', () => selectPort(bridgeDeviceId, designatedPortName));
        row.append(remote, make('small', 'SNMP · ' + formatTime(designatedPortCheckedAt)));
      }
      list.append(row);
      propertiesSection.append(make('h3', 'Корневой порт STP'), list);
    }
    if (node.ports?.length) {
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'ports';
      panel.open = selectedPort !== null;
      const list = make('ul', null, 'map-detail-list');
      const states = {up: 'Линк поднят', down: 'Линк опущен', disabled: 'Отключён', unknown: 'Нет подтверждения'};
      const proxmox = node.ports.every(port => port.source === 'Proxmox');
      const sorted = [...node.ports].sort((a,b) => a.name.localeCompare(b.name, 'ru', {numeric: true}));
      for (const port of sorted) {
        if (selectedPort && portKey(port.name) !== portKey(selectedPort)) continue;
        const row = make('li');
        const time = port.checkedAt ? formatTime(port.checkedAt) : '';
        const speed = formatPortSpeed(port.speedBps);
        const state = port.source === 'Proxmox' ? proxmoxPortStatus(port) : states[port.state];
        const status = [state, speed, port.source, time, port.stale && time ? 'устарело' : ''].filter(Boolean).join(' · ');
        const name = make(selectedPort ? 'strong' : 'button', port.name);
        if (!selectedPort) {
          name.type = 'button';
          name.dataset.port = port.name;
          name.addEventListener('click', () => selectPort(id, port.name));
        }
        row.append(name, make('small', status));
        if (selectedPort && port.configuredLabel) {
          const {text, checkedAt} = port.configuredLabel;
          row.append(make('small', `Подпись на коммутаторе · ${text} · ${formatTime(checkedAt)}`));
        }
        if (selectedPort) for (const count of lldpCounts(port)) row.append(make('small', count));
        if (selectedPort && port.lldpPort) {
          const {admin, rxFrames, txFrames, checkedAt, delta} = port.lldpPort;
          const modes = {tx_rx: 'приём и передача', rx_only: 'только приём', tx_only: 'только передача', disabled: 'отключён'};
          const counters = [['получено', rxFrames], ['отправлено', txFrames]]
            .filter(([, value]) => value !== undefined)
            .map(([direction, value]) => direction + ' кадров ' + value.toLocaleString('ru-RU'));
          row.append(make('small', ['LLDP', modes[admin], ...counters, formatTime(checkedAt)].join(' · ')));
          if (delta) row.append(make('small', formatLldpDelta(delta)));
        }
        if (selectedPort && port.lldpNeighbors?.length) {
          const observed = make('details');
          const count = port.lldpNeighbors.length;
          observed.append(make('summary', `Объявления LLDP (${count} из ${port.lldpNeighborCount})`),
            make('small', formatTime(port.lldpCheckedAt)));
          const neighbors = make('ul', null, 'map-detail-list');
          for (const {systemName, chassisId, portId, portIdSubtype, hostName, inventoryDeviceId} of port.lldpNeighbors) {
            const peer = [systemName, chassisId && 'шасси ' + chassisId, formatLldpPortId(portId, portIdSubtype),
              hostName && hostName !== systemName && 'имя по MAC ' + hostName];
            const entry = make('li', peer.filter(Boolean).join(' · '));
            const device = byId.get(inventoryDeviceId);
            if (device) {
              const open = make('button', device.name);
              open.type = 'button';
              open.addEventListener('click', () => select(device.id));
              entry.append(' · ', open);
            }
            neighbors.append(entry);
          }
          observed.append(neighbors);
          row.append(observed);
        }
        if (selectedPort && port.routerNeighbors) {
          const {checkedAt, total, devices} = port.routerNeighbors;
          const observed = make('details');
          const count = devices.length === total ? total : `${devices.length} из ${total}`;
          observed.append(make('summary', `Соседи RouterOS (${count})`), make('small', formatTime(checkedAt)));
          const neighbors = make('ul', null, 'map-detail-list');
          for (const {name, platform, mac, address} of devices) {
            neighbors.append(make('li', [name, platform, mac, address].filter(Boolean).join(' · ')));
          }
          observed.append(neighbors);
          row.append(observed);
        }
        if (selectedPort && port.vlanMemberships) {
          const vlans = port.vlanMemberships.vlans;
          for (const [label, selected] of [
            ['PVID', vlans.filter(vlan => vlan.pvid)],
            ['VLAN без тега', vlans.filter(vlan => vlan.egress === 'untagged')],
            ['VLAN с тегом', vlans.filter(vlan => vlan.egress === 'tagged')],
          ]) {
            if (selected.length) row.append(make('small', label + ' · ' + selected.map(vlan => vlan.id).join(', ')));
          }
        }
        if (selectedPort && port.fdbVlans) {
          const vlans = port.fdbVlans.vlans.map(vlan => `${vlan.id} (${vlan.learnedMacCount} MAC)`);
          row.append(make('small', 'VLAN по MAC-таблице · ' + vlans.join(', ')));
        }
        if (selectedPort) appendPortLinkDetails(row, port);
        if (selectedPort && port.stpPort) row.append(make('small', formatStpPort(port.stpPort)));
        if (selectedPort && port.endpointMac) row.append(make('small', formatEndpointMac(port.endpointMac)));
        if (selectedPort && node.kind === 'Коммутатор' && port.state === 'up') {
          const learned = port.fdbLearned;
          const summary = learned
            ? 'Изученных MAC · ' + learned.learnedMacCount + (learned.partial ? ' · часть строк опроса пропущена' : '')
            : 'Нет свежего результата MAC-таблицы';
          row.append(make('small', summary));
        }
        if (selectedPort && port.telemetry) {
          const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 2});
          const rate = (label, value) => value === undefined ? '' : label + ' ' + number.format(value / 1e6) + ' Мбит/с';
          const counter = (label, value) => value === undefined ? '' : label + ' ' + number.format(value);
          const metrics = port.telemetry;
          row.append(make('small', 'Интервал измерения · ' + number.format(metrics.intervalSeconds) + ' с'));
          for (const readings of [
            [rate('Приём', metrics.rxBps), rate('передача', metrics.txBps)],
            [counter('Ошибок RX', metrics.rxErrors), counter('ошибок TX', metrics.txErrors)],
            [counter('Отброшено RX', metrics.rxDiscards), counter('отброшено TX', metrics.txDiscards)],
          ]) {
            const text = readings.filter(Boolean).join(' · ');
            if (text) row.append(make('small', text));
          }
        }
        if (selectedPort && port.rxErrorCounters) {
          appendRxErrorCounters(row, port.rxErrorCounters);
        }
        if (selectedPort && port.rxSilence) row.append(make('small', formatRxSilence(port.rxSilence)));
        list.append(row);
      }
      const up = node.ports.filter(port => proxmox ? port.proxmoxActive : port.state === 'up').length;
      const active = proxmox ? 'активны в ОС' : 'линк поднят на';
      const summary = selectedPort ? 'Порт ' + selectedPort : 'Интерфейсы (' + node.ports.length + ', ' + active + ' ' + up + ')';
      panel.append(make('summary', summary), make('small', proxmox ? 'Proxmox API' : 'Network Observer'), list);
      if (selectedPort) {
        const reset = make('button', 'Все порты', 'map-close');
        reset.type = 'button';
        reset.dataset.port = '';
        reset.addEventListener('click', () => selectPort(id, null));
        panel.append(reset);
      }
      propertiesSection.append(panel);
    }
    if (node.serviceChecks?.length) {
      const list = make('ul', null, 'map-detail-list');
      const listenerPorts = new Set(node.serviceChecks.filter(check => check.method === 'OpenVPN UDP-сокет')
        .map(check => check.configuredPort));
      for (const check of node.serviceChecks) {
        const row = make('li');
        const backup = [check.backupCompletedAt && 'Завершено ' + formatTime(check.backupCompletedAt),
          check.backupMaxAgeHours && 'Порог ' + check.backupMaxAgeHours + ' ч'].filter(Boolean).map(text => ' · ' + text).join('');
        const vlan = check.vlanTransit;
        const wireguard = check.wireguardPolicy;
        const pppoe = check.pppoe;
        const policy = wireguard ? [wireguard.ingress && 'Вход ' + wireguard.ingress,
          wireguard.mark !== undefined && 'метка 0x' + wireguard.mark.toString(16),
          wireguard.table && 'таблица ' + wireguard.table,
          wireguard.latestHandshake && 'handshake ' + formatTime(wireguard.latestHandshake)]
          .filter(Boolean).map(text => ' · ' + text).join('') : '';
        const endpoint = [check.method, wireguard?.interface, vlan?.id, check.backupVmid && 'ВМ ' + check.backupVmid,
          check.target, check.ipsecPolicy && '↔ ' + check.ipsecPolicy.remoteNetwork, check.httpHost, check.port, check.path, check.dns?.name,
          check.dns?.record, check.tunnelInterface, check.tunnelAddress, check.smbShare].filter(Boolean).join(' ');
        const confirmed = ['Маршрут', 'Маршрут · WireGuard', 'OpenVPN TUN', 'OpenVPN UDP-сокет', 'SMB Mount',
          'Копия Proxmox', 'IPsec фаза 2', 'Сбор данных SNMP']
          .includes(check.method) ? 'Подтверждён' :
          node.id === data.clusterId ? 'В норме' : 'Отвечает';
        const sessionState = pppoe && {
          connected: 'Сессия поднята', disconnected: 'Сессия разорвана', disabled: 'Сессия отключена',
        }[pppoe.state];
        const result = sessionState ?? (check.skipped ? 'Не запущена' :
          ({reachable:confirmed, unreachable:'Сбой проверки'}[check.state] ?? 'Нет подтверждения'));
        const reason = check.responseCode ? 'SIP ' + check.responseCode : serviceCheckReasons[check.reason];
        const errorSource = check.errorSource ? ' от ' + check.errorSource : '';
        const gatewayLabel = check.method === 'Маршрут' && check.state !== 'reachable' ? 'ожидаемый шлюз' : 'через';
        let gateway = check.via ? ' · ' + gatewayLabel + ' ' + check.via : '';
        if (check.observedVia) gateway = ' ' + check.observedVia + gateway;
        if (pppoe?.parent) gateway += ' · Интерфейс ' + pppoe.parent;
        const management = [
          check.method === 'OpenVPN Management' && check.configuredPort && 'настроен UDP/' + check.configuredPort,
          check.daemonReady === true && 'демон CONNECTED',
          check.sessionCount !== undefined && 'клиентских сессий: ' + check.sessionCount,
        ].filter(Boolean).map(value => ' · ' + value).join('');
        const udp = check.method === 'OpenVPN Management' && listenerPorts.has(check.configuredPort)
          ? null : check.localUdpSocket;
        const source = check.source ? ' · ' + check.source : '';
        const time = check.checkedAt ? ' · ' + formatTime(check.checkedAt) : '';
        const identity = check.identityCheckedAt ? ' · Адрес сверён ' + formatTime(check.identityCheckedAt) : '';
        const attempts = check.attempts ? ' · попыток: ' + check.attempts : '';
        const responder = check.dns?.unexpectedResponder;
        const srvRecords = check.dns?.srvRecords?.map(record => `${record.target}:${record.port}`).join(', ');
        const dns = [check.dns?.rcode, check.dns?.transport, check.dns?.addresses?.join(', '), srvRecords,
          responder && `Ответ от ${responder.address} · порт ${responder.port}`,
          responder?.rcode, responder?.addresses?.join(', '),
          responder?.matchesExpectedAddresses === true && 'записи совпали с ожидаемыми']
          .filter(Boolean).map(value => ' · ' + value).join('');
        const http = (check.httpStatus ? ' · HTTP ' + check.httpStatus : '')
          + (check.redfishVersion ? ' · Redfish ' + check.redfishVersion : '')
          + (check.zabbixVersion ? ' · Zabbix ' + check.zabbixVersion : '');
        const rtsp = check.rtspStatus ? ' · RTSP ' + check.rtspStatus : '';
        const ftp = check.ftpReply ? ' · FTP ' + check.ftpReply : '';
        const certificate = check.tlsExpiresAt ? ' · ' + [check.tlsVersion,
          'Действует до ' + formatTime(check.tlsExpiresAt)].filter(Boolean).join(' · ') : '';
        const localRoute = check.localRoute;
        const arp = check.arpDiagnostic;
        const arpResult = arp && arpDiagnosticLabels[arp.state];
        const vlanPeer = vlan?.peer;
        const peer = vlanPeer && ({matched: ' · Сосед ' + vlanPeer.guestPort + ' подтверждён',
          unconfirmed: ' · Сосед не подтверждён'}[vlanPeer.state] ?? '');
        const egress = vlan ? ' · ' + vlan.interface + ' · ' + vlan.localAddress + (peer || '') : localRoute?.interface
          ? ' · Выход UI_VPN: ' + [localRoute.sourceIP, localRoute.interface,
            localRoute.gateway && 'через ' + localRoute.gateway,
            localRoute.state === 'unreachable' && 'ожидался ' + localRoute.expectedGateway].filter(Boolean).join(' · ')
          : '';
        const rtt = check.roundTripMs === undefined ? '' : ' · RTT ' +
          check.roundTripMs.toLocaleString('ru-RU', {maximumFractionDigits: 3}) + ' мс';
        const postgres = postgresqlTlsLabel(check.postgresqlTls, check.tlsVersion);
        const postgresql = postgres ? ' · ' + postgres : '';
        const smb = check.smbDialect ? ' · ' + smbNegotiationLabel(check.smbDialect, check.smbSigningRequired) : '';
        const scope = check.supplemental ? ' · дополнительная проверка' :
          check.component ? ' · компонент сервиса' : check.required ? ' · проверка доступности' : '';
        const guests = node.guest || !check.backupVmid ? [] :
          data.nodes.filter(item => item.guest && item.vmid === check.backupVmid);
        const title = make(guests.length === 1 ? 'button' : 'strong', endpoint || 'Проверка');
        if (guests.length === 1) {
          title.type = 'button';
          title.addEventListener('click', () => select(guests[0].id));
        }
        const ntp = check.ntp ? ' · ' + ntpLabel(check.ntp) : '';
        row.append(title, make('small', result + http + rtsp + ftp + certificate + postgresql + smb + (reason ? ' · ' + reason + errorSource : '') + backup + policy + dns + ntp + rtt + attempts + gateway + egress + management + scope + source + time + identity + (check.stale ? ' · устарело' : '')));
        if (udp) {
          const addresses = udp.addresses?.map(address => address.includes(':') ? `[${address}]` : address).join(', ');
          const label = {bound: 'Открыт локальный UDP-сокет', unbound: 'Локальный UDP-сокет отсутствует',
            unknown: 'Локальный UDP-сокет не проверен'}[udp.state];
          row.append(make('small', [label, `UDP/${check.configuredPort}`, addresses].filter(Boolean).join(' · ')));
        }
        for (const direction of check.ipsecPolicy?.directions ?? []) {
          const status = direction.state === 'reachable' ? 'Фаза 2 установлена' : serviceCheckReasons[direction.reason];
          row.append(make('small', [direction.source, status, direction.checkedAt && formatTime(direction.checkedAt)]
            .filter(Boolean).join(' · ')));
        }
        if (arpResult) {
          row.append(make('small', arpResult + ' · ' + arp.address + ' · из ' + arp.sourceIP + ' · ' + arp.interface));
        }
        if (pppoe?.parentLink) {
          const {state, source, checkedAt} = pppoe.parentLink;
          const link = {up: 'Линк поднят', down: 'Линк опущен', disabled: 'Порт отключён'}[state];
          row.append(make('small', [pppoe.parent, link, source, formatTime(checkedAt)].join(' · ')));
        }
        list.append(row);
      }
      propertiesSection.append(make('h3', 'Проверки'), list);
    }
    for (const [key, title] of [['unavailable', 'Недоступные сервисы'], ['degraded', 'Сервисы со сбоями проверок'],
                                ['unknown', 'Сервисы без подтверждения']]) {
      const ids = node.serviceAvailability?.[key] ?? [];
      if (!ids.length) continue;
      const list = make('ul', null, 'map-detail-list');
      for (const service of ids) {
        const row = make('li');
        const open = make('button', byId.get(service).name);
        open.type = 'button';
        open.addEventListener('click', () => select(service));
        row.append(open);
        list.append(row);
      }
      propertiesSection.append(make('h3', title), list);
    }
    columns.append(propertiesSection);
    details.append(heading, columns);
    const links = chosenPort ? linksForPort(id, chosenPort) : incident.get(id);
    if (links.length || selectedPort) {
      const list = make('ul',null,'map-detail-list');
      const observations = make('ul',null,'map-detail-list');
      const comparisonLabels = {
        both_up: 'Оба линка подняты', one_down: 'Один линк опущен или отключён',
        both_down: 'Оба линка опущены или отключены', speed_mismatch: 'Скорости линков различаются',
      };
      const pairOf = edge => edgeKey(edge.a, edge.b);
      const reciprocalPaths = new Set(links
        .filter(edge => edge.confirmed && edge.source === reciprocalMacSource)
        .map(pairOf));
      const inventory = new Map(links
        .filter(edge => !edge.confirmed && edge.kind === 'Сетевое соединение' &&
          edge.source === 'GitHub' && reciprocalPaths.has(pairOf(edge)))
        .map(edge => [pairOf(edge), edge]));
      const portName = name => name && name.toLowerCase() !== 'unknown' ? name : 'порт неизвестен';
      for (const edge of links.slice().sort((a,b) => Number(b.confirmed)-Number(a.confirmed))) {
        const declared = inventory.get(pairOf(edge));
        if (edge === declared) continue;
        const unconfirmedPath = !selectedPort && !edge.confirmed && pathKinds.has(edge.kind);
        const peer = byId.get(edge.a === id ? edge.b : edge.a);
        const li = make('li');
        const go = make('button',peer.name);
        go.type = 'button';
        go.addEventListener('click',() => select(peer.id));
        const reciprocal = edge.confirmed && edge.source === reciprocalMacSource;
        const pending = edge.kind === 'Сетевое соединение' ? 'Пара портов не подтверждена' : 'Связь не подтверждена';
        const status = edge.confirmed || unconfirmedPath ? edge.source : pending + ' · ' + edge.source;
        li.append(go,make('small',edge.kind+' · '+status+(edge.details ? ' · '+edge.details : '')));
        if (edge.confirmed && pathKinds.has(edge.kind)) li.append(make('small', 'Прямое соединение не подтверждено'));
        const renderedPorts = new Set();
        const aggregates = new Set((edge.portEvidence ?? []).flatMap(({lacp}) =>
          lacp?.aggregateState ? [lacp.side + ':' + lacp.aggregateState.name] : []));
        const comparedPorts = new Set();
        for (const evidence of edge.portEvidence ?? []) {
          const [local, remote] = edge.a === id ? [evidence.a, evidence.b] : [evidence.b, evidence.a];
          const ports = portName(local) + ' ↔ ' + portName(remote);
          const source = evidence.source === 'GitHub' ? 'GitHub (конфигурация)' : evidence.source;
          const vlan = evidence.vlan ? ' · VLAN ' + evidence.vlan : '';
          const time = evidence.at ? ' · ' + formatTime(evidence.at) : '';
          const proof = {current: ' · пара по свежему наблюдению',
                         verified_inventory: ' · пара по подтверждённой записи инвентаря'}[evidence.pairEvidence] ?? '';
          const unverified = evidence.confirmed ? '' : ' · ' + pending.toLocaleLowerCase('ru-RU');
          li.append(make('small', ports + vlan + ' · ' + source + time + proof + unverified));
          if (evidence.windowsAdapter) li.append(make('small', formatWindowsPortEvidence(evidence.windowsAdapter)));
          if (evidence.learnedEndpoint) {
            const {switchId, mac} = evidence.learnedEndpoint;
            const switchPort = edge.a === switchId ? evidence.a : evidence.b;
            li.append(make('small', 'MAC ' + mac + ' изучен на ' + byId.get(switchId).name + ' ' + switchPort));
          }
          appendInventorySources(li, evidence.inventorySources);
          for (const path of evidence.stpPaths ?? []) appendStpPath(li, path);
          for (const side of ['a', 'b']) {
            const port = evidence.portStates?.[side];
            const key = side + ':' + port?.name;
            if (!port || renderedPorts.has(key) || aggregates.has(key)) continue;
            renderedPorts.add(key);
            const device = byId.get(edge[side]).name;
            const label = port.source === 'Proxmox' ? proxmoxPortStatus(port) : portLabels[port.state];
            const state = [label, formatPortSpeed(port.speedBps), port.source ?? 'SNMP', formatTime(port.checkedAt)];
            state.push(...lldpCounts(port));
            li.append(make('small', `${device} ${port.name}: ${state.filter(Boolean).join(' · ')}`));
            for (const {localPort, chassisId, portId, portIdSubtype, checkedAt} of evidence.lldpPeers?.[side] ?? []) {
              const peer = byId.get(edge[side === 'a' ? 'b' : 'a']).name;
              const fields = [localPort, 'LLDP', peer, formatLldpPortId(portId, portIdSubtype),
                'шасси ' + chassisId, formatTime(checkedAt)];
              li.append(make('small', fields.filter(Boolean).join(' · ')));
            }
            if (port.configuredLabel) {
              const {text, checkedAt} = port.configuredLabel;
              li.append(make('small', `${port.name} · Подпись на коммутаторе · ${text} · ${formatTime(checkedAt)}`));
            }
            if (port.stpPort) li.append(make('small', `${port.name} · ${formatStpPort(port.stpPort)}`));
            if (port.endpointMac) li.append(make('small', `${port.name} · ${formatEndpointMac(port.endpointMac)}`));
            if (port.telemetry) {
              const {rxBps, txBps, rxErrors, txErrors, rxDiscards, txDiscards, intervalSeconds, checkedAt} = port.telemetry;
              const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 2});
              const rate = (value, label) => value === undefined ? '' : `${label} ${number.format(value / 1e6)} Мбит/с`;
              const counters = [[rxErrors, 'ошибок RX'], [txErrors, 'ошибок TX'],
                [rxDiscards, 'отброшено RX'], [txDiscards, 'отброшено TX']]
                .filter(([value]) => value !== undefined).map(([value, label]) => `${label} ${number.format(value)}`);
              const metrics = [rate(rxBps, 'RX'), rate(txBps, 'TX'), ...counters,
                `${number.format(intervalSeconds)} с`, formatTime(checkedAt)];
              li.append(make('small', `${port.name} · ${metrics.filter(Boolean).join(' · ')}`));
            }
            if (port.rxErrorCounters) appendRxErrorCounters(li, port.rxErrorCounters, port.name);
            if (port.rxSilence) li.append(make('small', `${port.name} · ${formatRxSilence(port.rxSilence)}`));
          }
          if (evidence.lacp?.aggregateState) {
            const {side, aggregateState} = evidence.lacp;
            const key = side + ':' + aggregateState.name;
            if (!renderedPorts.has(key)) {
              renderedPorts.add(key);
              const {name, state, speedBps, checkedAt} = aggregateState;
              const details = [portLabels[state], formatPortSpeed(speedBps), 'SNMP', formatTime(checkedAt)];
              li.append(make('small', `Агрегат ${name}: ${details.filter(Boolean).join(' · ')}`));
            }
          }
          if (evidence.portComparison) {
            const pair = JSON.stringify(['a', 'b'].map(side => evidence.portStates[side].name));
            if (!comparedPorts.has(pair)) {
              comparedPorts.add(pair);
              const {state, checkedAt} = evidence.portComparison;
              const sources = [...new Set(['a', 'b'].map(side => evidence.portStates[side].source ?? 'SNMP'))];
              li.append(make('small', comparisonLabels[state] + ' · ' + sources.join(' + ') + ' · ' + formatTime(checkedAt)));
            }
          }
          if (evidence.vlanAudit?.length) {
            const audit = make('details');
            const vlans = make('ul', null, 'map-detail-list');
            const modes = {tagged: 'с тегом', untagged: 'без тега'};
            const states = {confirmed: 'Режим подтверждён', mismatch: 'Режим расходится', unconfirmed: 'Режим подтверждён частично или неизвестен'};
            for (const vlan of evidence.vlanAudit) {
              const row = make('li');
              row.append(make('strong', `VLAN ${vlan.id} · ожидается ${modes[vlan.expected]}`), make('small', states[vlan.state]));
              for (const side of ['a', 'b']) {
                const port = vlan.ports[side] ?? {};
                const membership = port.egress ? `${modes[port.egress]} · ${formatTime(port.membershipCheckedAt)}`
                  : port.vlanCollection?.state === 'empty' ? `SNMP не вернул данные VLAN · ${formatTime(port.vlanCollection.checkedAt)}`
                  : 'режим неизвестен';
                const learned = port.learnedMacCount ? ` · изучено MAC ${port.learnedMacCount} · ${formatTime(port.fdbCheckedAt)}` : '';
                row.append(make('small', `${byId.get(edge[side]).name} ${evidence[side]} · ${membership}${learned}`));
              }
              if (vlan.managementObservation) {
                const {address, switchSide, checkedAt} = vlan.managementObservation;
                const name = byId.get(edge[switchSide]).name;
                row.append(make('small', `MAC адреса управления ${address} виден на ${name} ${evidence[switchSide]} · ${formatTime(checkedAt)}`));
              }
              vlans.append(row);
            }
            audit.append(make('summary', 'Сверка VLAN'), vlans);
            li.append(audit);
          }
          if (evidence.confirmed && evidence.virtual) {
            const network = evidence.virtual;
            const notes = [];
            if (network.linkDisabled) notes.push('Интерфейс отключён в настройках ВМ');
            if (network.bridgeActive === true) notes.push('Мост активен');
            if (network.bridgeActive === false) notes.push('Мост неактивен');
            if (network.uplinks.length) notes.push('Интерфейсы моста: ' + network.uplinks.join(', '));
            if (notes.length) li.append(make('small', notes.join(' · ')));
            if (network.switchUplink) {
              const {id, port, at} = network.switchUplink;
              const label = bridgePathLabel(network.switchUplink);
              li.append(make('small', label + ': ' + byId.get(id).name + ' ' + port + ' · ' + formatTime(at)));
            }
            for (const observed of network.switchPorts ?? []) {
              const name = byId.get(observed.id).name;
              const vlan = observed.vlan ? ' · VLAN ' + observed.vlan : '';
              li.append(make('small', 'MAC ВМ замечен на ' + name + ' ' + observed.port + vlan + ' · netctl FDB · ' + formatTime(observed.at)));
            }
          }
        }
        if (reciprocal && declared) {
          for (const evidence of declared.portEvidence ?? []) {
            if (evidence.source !== 'GitHub') continue;
            const [local, remote] = declared.a === id ? [evidence.a, evidence.b] : [evidence.b, evidence.a];
            li.append(make('small', portName(local) + ' ↔ ' + portName(remote) + ' · GitHub (конфигурация)'));
            appendInventorySources(li, evidence.inventorySources);
          }
        }
        (unconfirmedPath ? observations : list).append(li);
      }
      const relationships = make('section');
      relationships.append(make('h3', selectedPort ? 'Наблюдения по порту ' + selectedPort : 'Наблюдения о связях'));
      const guests = chosenPort ? guestsForPort(id, chosenPort) : null;
      const serviceGroup = chosenPort && data.servicePorts?.[id]?.find(item => portKeys(chosenPort).includes(portKey(item.port)));
      if (!links.length && !guests?.size && !serviceGroup) relationships.append(make('p', 'Для этого порта нет наблюдений о связях'));
      if (list.children.length) relationships.append(list);
      if (serviceGroup) {
        const panel = make('details', null, 'map-port-panel');
        panel.dataset.section = 'services-on-port';
        const services = make('ul', null, 'map-detail-list');
        const bases = {host_mac: 'MAC устройства', host_lacp: 'LACP хоста', host_management: 'Интерфейс управления',
          guest_gateway: 'Вход через шлюз', guest_local_udp: 'Привязка к интерфейсу ВМ',
          router_arp: 'Подключённый маршрут и ARP', router_mac: 'ARP и FDB маршрутизатора',
          switch_mac: 'Адрес проверен по ARP и FDB', lldp_peer: 'Сосед по LLDP',
          endpoint_mac: 'MAC станции подтверждён на порту'};
        for (const service of serviceGroup.services) {
          const row = make('li');
          const open = make('button', service.name);
          open.type = 'button';
          open.addEventListener('click', () => select(service.id));
          row.append(open);
          const observed = (service.basis ?? []).map(basis => bases[basis]).filter(Boolean);
          if (observed.length) row.append(make('small', observed.join(' · ')));
          for (const check of service.observerIssues ?? []) {
            const threshold = measurement(check.unit, check.warningThreshold);
            row.append(make('small', ['Server Observer', check.label || check.name, observerStates[check.status],
              !check.stale && measurement(check.unit, check.observed), threshold && `порог ${threshold}`,
              check.checkedAt && formatTime(check.checkedAt)].filter(Boolean).join(' · ')));
          }
          const dependencyLabels = {unavailable: 'Недоступны', degraded: 'Есть сбои', unknown: 'Без подтверждения'};
          for (const [state, label] of Object.entries(dependencyLabels)) {
            const ids = service.dependencies?.[state];
            if (!ids?.length) continue;
            const dependency = make('small', `${label} · `);
            ids.forEach((id, index) => {
              if (index) dependency.append(', ');
              const node = byId.get(id);
              const target = make(node ? 'a' : 'span', node?.name ?? id);
              if (node) target.href = '?' + new URLSearchParams({node: id});
              dependency.append(target);
            });
            row.append(dependency);
          }
          if (service.backupScope) {
            const {storage, total, scheduled, notScheduled, unknown} = service.backupScope;
            row.append(make('small', `Расписание ${storage} · включено: ${scheduled} из ${total} · вне расписания: ${notScheduled} · без подтверждения: ${unknown}`));
          }
          if (service.backupChecks) {
            const {passed, failed, unconfirmed} = service.backupChecks;
            row.append(make('small', `Копии ВМ · прошли: ${passed} · сбои: ${failed} · без подтверждения: ${unconfirmed}`));
          }
          for (const check of service.linkChecks ?? []) {
            row.append(make('small', formatLinkCheck(check)));
          }
          for (const probe of service.probeEndpoints ?? []) {
            const address = probe.target.includes(':') ? `[${probe.target}]` : probe.target;
            const count = probe.passed + probe.failed + probe.unconfirmed;
            const latest = probe.lastCheckedByOutcome ?? {};
            const withTime = (label, outcome) => latest[outcome] ? `${label} · ${formatTime(latest[outcome])}` : label;
            const states = probe.localListener ? ['Открыт локально'] : count === 1
              ? [probe.passed ? withTime('Отвечает', 'passed') : probe.failed ? withTime('Сбой', 'failed')
                : withTime('Нет подтверждения', 'unconfirmed')]
              : [probe.passed && withTime(`прошли: ${probe.passed}`, 'passed'),
                probe.failed && withTime(`сбои: ${probe.failed}`, 'failed'),
                probe.unconfirmed && withTime(`без подтверждения: ${probe.unconfirmed}`, 'unconfirmed')];
            row.append(make('small', [
              [probe.method, probe.localListener ? '' : probe.transport].filter(Boolean).join(' '),
              `${address}${probe.port ? ':' + probe.port : ''}${probe.path ?? ''}`, ...states,
              probe.roundTripSamplesMs?.length && `RTT ${probe.roundTripSamplesMs.map(value =>
                value.toLocaleString('ru-RU', {maximumFractionDigits: 3})).join(', ')} мс`,
              ...(probe.issues ?? []).map(({reason, errorSource}) => [serviceCheckReasons[reason],
                errorSource && `Отказ от ${errorSource}`].filter(Boolean).join(' · ')),
              probe.responseCodes?.length && `Ответ ${probe.responseCodes.join(', ')}`,
              probe.rdpSecurityModes?.join(', '),
              ...(probe.zabbixVersions ?? []).map(version => `Zabbix ${version}`),
              ...(probe.redfishVersions ?? []).map(version => `Redfish ${version}`),
              ...(probe.smbNegotiations ?? []).map(item => smbNegotiationLabel(item.dialect, item.signingRequired)),
              ...(probe.postgresqlTlsResults ?? []).map(item => postgresqlTlsLabel(item.state, item.version)),
              ...(probe.tlsCertificates ?? []).map(cert => certificateLabel(cert.expiresAt, cert.version)),
              probe.dns && `${probe.dns.record} ${probe.dns.name}`,
            ].filter(Boolean).join(' · ')));
          }
          services.append(row);
        }
        const title = serviceGroup.services.some(service => service.kind !== 'Сервис') ? 'Узлы и сервисы на порту' : 'Сервисы на порту';
        panel.append(make('summary', `${title} (${serviceGroup.total})`), services);
        if (serviceGroup.services.length < serviceGroup.total) {
          panel.append(make('small', `Показано ${serviceGroup.services.length} из ${serviceGroup.total}`));
        }
        relationships.append(panel);
      }
      if (observations.children.length) {
        const panel = make('details', null, 'map-port-panel');
        panel.dataset.section = 'mac-paths';
        panel.append(make('summary', `Неподтверждённые пути (${observations.children.length})`), observations);
        relationships.append(panel);
      }
      if (guests?.size) {
        const guestList = make('ul', null, 'map-detail-list');
        guestList.dataset.section = 'guest-observations';
        for (const [guestId, readings] of guests) {
          const guest = byId.get(guestId);
          const kind = guest.kind === 'Контейнер' ? 'LXC' : 'ВМ';
          const label = guest.vmid ? `${kind} ${guest.vmid} · ${guest.name}` : guest.name;
          const item = make('li');
          const open = make('button', label);
          open.type = 'button';
          open.addEventListener('click', () => select(guestId));
          item.append(open, ...Array.from(readings, reading => make('small', reading)));
          guestList.append(item);
        }
        relationships.append(make('h3', 'Наблюдения о ВМ и контейнерах'), guestList);
      }
      columns.append(relationships);
    }
    renderRelated(id);
    requestAnimationFrame(() => {
      draw();
      if (reveal) button.focus();
    });
  }
  function findNode() {
    const term = search.value.trim().toLocaleLowerCase('ru-RU');
    if (!term) {
      feedback.textContent = '';
      return;
    }
    const terms = node => [node.name, node.id, ...(node.aliases ?? []), String(node.vmid ?? '')].map(value => value.toLocaleLowerCase('ru-RU'));
    const matches = data.nodes.filter(node => terms(node).some(value => value.includes(term)));
    const exact = matches.filter(value => terms(value).includes(term));
    const node = exact.find(value => value.name.toLocaleLowerCase('ru-RU') === term) ?? exact[0] ?? matches[0];
    feedback.textContent = node ? (matches.length > 1 ? 'Совпадений '+matches.length+'. Открыт '+node.name+'.' : '') : 'Узел не найден';
    if (node) select(node.id);
  }
  root.querySelector('#map-search button').addEventListener('click', findNode);
  search.addEventListener('keydown', event => {
    if (event.key === 'Enter') findNode();
  });
  root.addEventListener('keydown', event => {
    if (event.key === 'Escape' && selected) closeSelection();
  });
  viewButtons.forEach(button => button.addEventListener('click', () => {
    if (button.dataset.view !== view || focusedRanks) renderView(button.dataset.view);
  }));
  function displaySnapshot(graph) {
    const params = new URLSearchParams(window.location.search);
    const wanted = selected ?? params.get('node');
    const wantedPort = selected ? selectedPort : params.get('port');
    const panelStates = new Map(Array.from(details.querySelectorAll('details'),
      panel => [panel.dataset.section, panel.open]));
    const active = document.activeElement;
    const activeNode = [...buttons].find(([, button]) => button === active)?.[0];
    const activePanel = active?.closest('summary')?.parentElement.dataset.section;
    const activePort = active?.dataset.port;
    const inCard = details.contains(active) || related.contains(active);
    data = graph;
    indexSnapshot();
    renderSnapshotHeader();
    const focus = view === 'overview' && byId.has(wanted) ? wanted : null;
    renderView(view, focus);
    if (buttons.has(wanted)) {
      renderSelection(wanted, false, wantedPort);
      for (const panel of details.querySelectorAll('details')) {
        if (panelStates.has(panel.dataset.section)) panel.open = panelStates.get(panel.dataset.section);
      }
    }
    const summary = activePanel && details.querySelector(`[data-section="${activePanel}"] summary`);
    const portControl = activePort === undefined ? null : [...details.querySelectorAll('button[data-port]')]
      .find(button => button.dataset.port === activePort);
    const replacement = summary || portControl || buttons.get(activeNode ?? (inCard ? wanted : null));
    replacement?.focus({preventScroll: true});
  }

  displaySnapshot(data);
  let lastSnapshot = JSON.stringify(data);
  let refreshing = false;
  async function refreshSnapshot() {
    if (document.hidden || refreshing) return;
    refreshing = true;
    try {
      const response = await fetch(root.dataset.snapshotUrl, {
        cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error('Snapshot request failed');
      const {infrastructure: graph} = await response.json();
      if (!Array.isArray(graph?.nodes) || !Array.isArray(graph.links)) throw new Error('Invalid snapshot');
      const serialized = JSON.stringify(graph);
      if (serialized !== lastSnapshot) {
        displaySnapshot(graph);
        lastSnapshot = serialized;
      } else {
        showAvailability();
      }
      void refreshAgentStatus(details.querySelector('[data-agent-status]'));
    } catch {
      showAvailability(data.snapshotAt ? 'Обновление карты недоступно. Показан последний полученный снимок.' : 'Не удалось загрузить снимок карты.');
    } finally {
      refreshing = false;
    }
  }
  if (root.dataset.snapshotUrl) {
    window.setInterval(refreshSnapshot, 30_000);
    document.addEventListener('visibilitychange', refreshSnapshot);
  }

  setupInfrastructureVr(root.querySelector('#map-vr'), root.querySelector('#map-vr-status'), () => {
    draw();
    const bounds = groups.getBoundingClientRect();
    const box = element => {
      const rect = element.getBoundingClientRect();
      return {x: rect.left - bounds.left, y: rect.top - bounds.top, width: rect.width, height: rect.height};
    };
    return {
      width: bounds.width, height: bounds.height,
      headings: Array.from(groups.querySelectorAll('h2'), element => ({...box(element), text: element.textContent})),
      nodes: Array.from(buttons, ([id, element]) => {
        const node = byId.get(id);
        const availability = availabilityOf(node);
        return {...box(element), id, text: element.textContent, status: availability.color,
                name: node.name, state: availability.label};
      }),
      lines: graphs.flatMap(({svg}) => Array.from(svg.querySelectorAll('path'), element => ({
        ...box(svg), path: element.getAttribute('d'), active: element.classList.contains('active'),
      }))),
      selected,
    };
  });
})();
