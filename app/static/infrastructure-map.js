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
  const availabilityStates = {
    ok: 'Доступен',
    warn: 'Доступен, есть сбои проверок',
    critical: 'Недоступен',
    unknown: 'Доступность не подтверждена',
  };
  const availabilityOf = node => {
    const color = node.mapStatus ?? 'unknown';
    let label = availabilityStates[color];
    if (node.reachability?.state === 'stopped') label = 'Выключен';
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
  const formatPortSpeed = bps => bps ? (bps / 1e6).toLocaleString('ru-RU') + ' Мбит/с' : '';
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
        if (pathKinds.has(edge.kind)) path.setAttribute('stroke-dasharray', '5 4');
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
      return [{...edge, portEvidence: evidence, confirmed: edge.confirmed && evidence.some(report => report.confirmed)}];
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
      const state = make('span', availability.color === 'unknown' ? 'Нет подтверждения' : availability.label, 'map-related-state');
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
    const columns = make('div', null, 'map-detail-columns');
    const propertiesSection = make('section');
    propertiesSection.append(make('h3', 'Доступность'), properties);
    const measurements = Object.entries(node.properties ?? {})
      .filter(([name, value]) => value && !items[name]);
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
    if (node.resources) {
      const {cpuRatio, logicalCpus, memoryUsedBytes, memoryTotalBytes, rootUsedBytes, rootTotalBytes,
        uptimeSeconds, checkedAt} = node.resources;
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
      const percent = ratio => number.format(ratio * 100) + '%';
      const usage = (used, total) => `${number.format(used / 2**30)} из ${number.format(total / 2**30)} ГиБ (${percent(used / total)})`;
      const list = make('dl');
      if (cpuRatio !== undefined) list.append(make('dt', 'CPU'), make('dd', percent(cpuRatio)));
      if (logicalCpus !== undefined) list.append(make('dt', 'Логические CPU'), make('dd', number.format(logicalCpus)));
      if (memoryTotalBytes !== undefined) list.append(make('dt', 'Память'), make('dd', usage(memoryUsedBytes, memoryTotalBytes)));
      if (rootTotalBytes !== undefined) list.append(make('dt', 'Корневой раздел /'), make('dd', usage(rootUsedBytes, rootTotalBytes)));
      if (uptimeSeconds !== undefined) {
        const days = Math.floor(uptimeSeconds / 86400);
        const hours = Math.floor(uptimeSeconds / 3600) % 24;
        const minutes = Math.floor(uptimeSeconds / 60) % 60;
        const uptime = [days ? `${days} д.` : '', hours ? `${hours} ч.` : '', `${minutes} мин.`].filter(Boolean).join(' ');
        list.append(make('dt', 'Время работы'), make('dd', uptime));
      }
      list.append(make('dt', 'Опрос ресурсов'), make('dd', formatTime(checkedAt)));
      propertiesSection.append(make('h3', 'Ресурсы Proxmox'), list);
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
    if (node.ports?.length) {
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'ports';
      panel.open = selectedPort !== null;
      const list = make('ul', null, 'map-detail-list');
      const states = {up: 'Линк поднят', down: 'Линк опущен', disabled: 'Отключён', unknown: 'Нет подтверждения'};
      const proxmox = node.ports.some(port => port.source === 'Proxmox');
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
        if (selectedPort) for (const count of lldpCounts(port)) row.append(make('small', count));
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
      const reasons = {
        connection_refused: 'Отказ на UDP-запрос, источник не определён', timeout: 'Ответ не получен вовремя',
        icmp_port_unreachable: 'ICMP: UDP-порт недоступен', icmp_rejected: 'Получен отказ ICMP',
        icmp_no_echo_reply: 'Нет ответа ICMP Echo Reply', icmp_unreachable: 'Получено сообщение о недостижимости',
        icmp_probe_error: 'Не удалось выполнить ICMP-проверку',
        transport_error: 'Ошибка сетевого запроса', unexpected_response: 'Ответ не соответствует запросу',
        dns_no_answer: 'Нет записи запрошенного типа', dns_address_mismatch: 'Адреса не совпадают с ожидаемыми',
        http_content_type: 'Неожиданный тип ответа', http_body_limit: 'Ответ превышает лимит проверки',
        http_invalid_json: 'Ответ не содержит ожидаемый объект JSON',
        http_reported_unavailable: 'Приложение сообщило о сбое',
        http_payload_mismatch: 'Содержимое ответа не совпало с ожидаемым',
        http_certificate_pin: 'Не совпал отпечаток сертификата',
        http_tls_certificate: 'Сертификат TLS не прошёл проверку', http_tls_error: 'Ошибка TLS',
        http_bad_response: 'Ответ HTTP неполный или некорректный',
        http_connection_refused: 'Отклонено TCP-соединение', http_connection_reset: 'Сброшено TCP-соединение',
        http_configuration: 'Ошибка настройки проверки',
        probe_target_unconfirmed: 'Адрес цели не подтверждён',
        probe_target_mismatch: 'Адрес в настройках проверок не совпал с подтверждённым',
        openvpn_tunnel_probe: 'Не удалось прочитать параметры туннеля',
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
        icmp_identity_unconfirmed: 'Принадлежность адреса этому узлу не подтверждена',
        route_other_gateway: 'Активен другой шлюз', route_inactive: 'Маршрут через ожидаемый шлюз неактивен',
        route_rejecting: 'Активный маршрут отбрасывает трафик',
        route_multiple_gateways: 'Обнаружено несколько активных шлюзов',
      };
      for (const check of node.serviceChecks) {
        const row = make('li');
        const endpoint = [check.method, check.target, check.httpHost, check.port, check.path, check.dns?.name,
          check.dns?.record, check.tunnelInterface, check.tunnelAddress, check.smbShare].filter(Boolean).join(' ');
        const confirmed = ['Маршрут', 'OpenVPN TUN', 'SMB Mount'].includes(check.method) ? 'Подтверждён' :
          node.id === data.clusterId ? 'В норме' : 'Отвечает';
        const result = check.skipped ? 'Не запущена' :
          ({reachable:confirmed, unreachable:'Сбой проверки'}[check.state] ?? 'Нет подтверждения');
        const reason = check.responseCode ? 'SIP ' + check.responseCode : reasons[check.reason];
        const errorSource = check.errorSource ? ' от ' + check.errorSource : '';
        const gatewayLabel = check.method === 'Маршрут' && check.state !== 'reachable' ? 'ожидаемый шлюз' : 'через';
        let gateway = check.via ? ' · ' + gatewayLabel + ' ' + check.via : '';
        if (check.observedVia) gateway = ' ' + check.observedVia + gateway;
        const management = [
          check.configuredPort && 'настроен UDP/' + check.configuredPort,
          check.daemonReady === true && 'демон CONNECTED',
          check.sessionCount !== undefined && 'клиентских сессий: ' + check.sessionCount,
        ].filter(Boolean).map(value => ' · ' + value).join('');
        const source = check.source ? ' · ' + check.source : '';
        const time = check.checkedAt ? ' · ' + formatTime(check.checkedAt) : '';
        const attempts = check.attempts ? ' · попыток: ' + check.attempts : '';
        const dns = [check.dns?.rcode, check.dns?.transport, check.dns?.addresses?.join(', ')]
          .filter(Boolean).map(value => ' · ' + value).join('');
        const http = check.httpStatus ? ' · HTTP ' + check.httpStatus : '';
        const rtt = check.roundTripMs === undefined ? '' : ' · RTT ' +
          check.roundTripMs.toLocaleString('ru-RU', {maximumFractionDigits: 3}) + ' мс';
        const postgresql = check.postgresqlTls === 'negotiated' ? ' · Согласован ' + (check.tlsVersion ?? 'TLS') :
          check.postgresqlTls === 'declined' ? ' · Сервер отклонил TLS' : '';
        const smb = check.smbDialect ? ' · SMB ' + check.smbDialect +
          (check.smbSigningRequired ? ' · сервер требует подпись' : ' · сервер не требует подпись') : '';
        const scope = check.supplemental ? ' · дополнительная проверка' :
          check.component ? ' · компонент сервиса' : check.required ? ' · проверка доступности' : '';
        row.append(make('strong', endpoint || 'Проверка'), make('small', result + http + postgresql + smb + (reason ? ' · ' + reason + errorSource : '') + dns + rtt + attempts + gateway + management + scope + source + time + (check.stale ? ' · устарело' : '')));
        list.append(row);
      }
      propertiesSection.append(make('h3', 'Проверки'), list);
    }
    if (node.checks?.length) {
      const panel = make('details', null, 'map-port-panel');
      panel.dataset.section = 'checks';
      panel.open = node.checks.some(check => (check.required && check.status !== 'ok')
        || (check.unit && ['warn', 'critical'].includes(check.status)));
      const list = make('ul', null, 'map-detail-list');
      const states = {ok: 'В норме', warn: 'Отклонение', critical: 'Ошибка', unknown: 'Нет подтверждения'};
      const number = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 2});
      const measurement = (unit, value) => {
        if (!Number.isFinite(value)) return '';
        if (unit === 'percent') return number.format(value) + '%';
        if (unit === 'bytes') return number.format(value / 2**30) + ' ГиБ';
        if (unit === 'hours') return number.format(value) + ' ч';
        if (unit === 'count') return number.format(value);
        return '';
      };
      for (const check of node.checks) {
        const row = make('li');
        const value = measurement(check.unit, check.observed);
        const threshold = measurement(check.unit, check.warningThreshold);
        const limit = check.unit === 'hours' ? 'предел ' : 'порог предупреждения ';
        const notes = [states[check.status], value, threshold && limit + threshold,
          check.required && 'обязательная проверка', check.checkedAt && formatTime(check.checkedAt),
          check.stale && 'устарело'];
        row.append(make('strong', check.label || check.name), make('small', notes.filter(Boolean).join(' · ')));
        list.append(row);
      }
      panel.append(make('summary', 'Проверки Server Observer'), list);
      propertiesSection.append(panel);
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
      const portLabels = {up: 'линк поднят', down: 'линк опущен', disabled: 'порт отключён'};
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
        const status = edge.confirmed || unconfirmedPath ? edge.source : 'Связь не подтверждена · ' + edge.source;
        li.append(go,make('small',edge.kind+' · '+status+(edge.details ? ' · '+edge.details : '')));
        if (reciprocal) li.append(make('small', 'Прямое соединение не подтверждено'));
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
          li.append(make('small', ports + vlan + ' · ' + source + time + proof + (evidence.confirmed ? '' : ' · без подтверждения')));
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
          }
        }
        (unconfirmedPath ? observations : list).append(li);
      }
      const relationships = make('section');
      relationships.append(make('h3', selectedPort ? 'Наблюдения по порту ' + selectedPort : 'Наблюдения о связях'));
      const guests = chosenPort ? guestsForPort(id, chosenPort) : null;
      if (!links.length && !guests?.size) relationships.append(make('p', 'Для этого порта нет наблюдений о связях'));
      if (list.children.length) relationships.append(list);
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
