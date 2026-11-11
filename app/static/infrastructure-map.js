import { setupInfrastructureVr } from './infrastructure-xr.js';

(() => {
  const data = JSON.parse(document.getElementById("infrastructure-data").textContent);
  const root = document.getElementById('infra-map-review');
  const groups = root.querySelector('#map-groups');
  const details = root.querySelector('#map-details');
  const related = root.querySelector('#map-related');
  const search = root.querySelector('#map-query');
  const feedback = root.querySelector('#map-search-result');
  const availabilityStates = {
    reachable: {label:'Доступен', color:'ok'},
    unreachable: {label:'Не отвечает', color:'critical'},
    stopped: {label:'Выключен', color:'warn'},
    unknown: {label:'Доступность не подтверждена', color:'unknown'},
  };
  const availabilityOf = node => availabilityStates[node.reachability?.state] ?? availabilityStates.unknown;
  const byId = new Map(data.nodes.map(node => [node.id, node]));
  const incident = new Map(data.nodes.map(node => [node.id, []]));
  const connected = new Map(data.nodes.map(node => [node.id, []]));
  for (const edge of data.links) {
    incident.get(edge.a).push(edge);
    incident.get(edge.b).push(edge);
    if (edge.confirmed) {
      connected.get(edge.a).push(edge.b);
      connected.get(edge.b).push(edge.a);
    }
  }
  const buttons = new Map();
  const graphs = [];
  const resize = new ResizeObserver(draw);
  const viewButtons = Array.from(root.querySelectorAll('[data-view]'));
  const networkKinds = new Set(data.switchKinds);
  let view = 'overview';
  let selected = null;
  let focusedRanks = null;
  const make = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const formatTime = value => new Intl.DateTimeFormat('ru-RU', { timeZone:'Asia/Yekaterinburg', dateStyle:'short', timeStyle:'short' }).format(new Date(value));
  const source = root.querySelector('#map-sources');
  const canonical = make('a','GitHub ' + data.git.slice(0,7));
  canonical.href = 'https://github.com/BorisDruzak/network_configuration/blob/' + data.git + '/config/network-context.yaml';
  canonical.target = '_blank';
  canonical.rel = 'noopener noreferrer';
  if (data.snapshotAt) source.append('Снимок · ' + formatTime(data.snapshotAt) + ' (ЕКБ)');
  if (data.git) source.append(' · ', canonical);
  const availability = root.querySelector('#map-availability');
  const availabilityLabels = {
    missing: 'Снимок инфраструктуры ещё не опубликован.',
    invalid: 'Снимок инфраструктуры недоступен.',
    stale: 'Снимок устарел. Связи показаны по последним доступным данным.',
  };
  if (availabilityLabels[data.availability]) {
    availability.textContent = availabilityLabels[data.availability];
    availability.hidden = false;
  }
  if (!data.nodes.length) {
    root.querySelector('.map-views').hidden = true;
    root.querySelector('.map-legend').hidden = true;
    root.querySelector('#map-search').hidden = true;
    return;
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
  const networkRoots = data.nodes.filter(node => networkKinds.has(node.kind)).map(node => node.id);
  const primary = networkRoots.sort((a, b) => connected.get(b).length - connected.get(a).length || nameOrder(a, b))[0];
  const anchors = [primary, ...data.overviewGuests].filter(Boolean);
  const onBackbone = node => node.id !== data.clusterId && (!node.guest || data.overviewGuests.includes(node.id));
  const backboneIds = new Set(data.nodes.filter(onBackbone).map(node => node.id));
  const networkDistance = primary ? traversal(primary, new Set(), backboneIds) : new Map();

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
      addGrid((host || 'Без размещения') + ' · ВМ и контейнеры (' + entries.length + ')',
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
        else group(id + ' · ВМ отсутствуют');
      }
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
        if (active.has(pair)) path.classList.add('active');
        svg.append(path);
      }
    }
  }
  const edgeKey = (a, b) => JSON.stringify([a, b].sort());

  function updateNodeUrl(id) {
    const url = new URL(window.location.href);
    if (id) url.searchParams.set('node', id);
    else url.searchParams.delete('node');
    window.history.replaceState(null, '', url);
  }

  function clearSelection() {
    buttons.get(selected)?.setAttribute('aria-pressed','false');
    selected = null;
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
    buttons.get(selected)?.setAttribute('aria-pressed','false');
    selected = id;
    updateNodeUrl(id);
    details.replaceChildren();
    const node = byId.get(id);
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
      'Источник': observation.source, 'Способ проверки': observation.method, 'Проверено': checked,
    };
    for (const [name,value] of Object.entries(items)) {
      if (value) properties.append(make('dt',name), make('dd',value));
    }
    const columns = make('div', null, 'map-detail-columns');
    const propertiesSection = make('section');
    propertiesSection.append(make('h3', 'Доступность'), properties);
    columns.append(propertiesSection);
    details.append(heading, columns);
    const links = incident.get(id);
    if (links.length) {
      const list = make('ul',null,'map-detail-list');
      for (const edge of links.slice().sort((a,b) => Number(b.confirmed)-Number(a.confirmed))) {
        const peer = byId.get(edge.a === id ? edge.b : edge.a);
        const li = make('li');
        const go = make('button',peer.name);
        go.type = 'button';
        go.addEventListener('click',() => select(peer.id));
        const status = edge.confirmed ? edge.source : 'Связь не подтверждена · ' + edge.source;
        li.append(go,make('small',edge.kind+' · '+status+(edge.details ? ' · '+edge.details : '')));
        list.append(li);
      }
      const relationships = make('section');
      relationships.append(make('h3','Наблюдения о связях'), list);
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
  renderView('overview');
  const linkedNode = new URLSearchParams(window.location.search).get('node');
  if (byId.has(linkedNode)) select(linkedNode, false);

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
