(() => {
  const root = document.querySelector("[data-network-hosts]");
  if (!root) return;

  const rows = root.querySelector("[data-hosts-rows]");
  const snapshotState = root.querySelector("[data-host-snapshot-state]");
  const pagination = root.querySelector("[data-host-pagination]");
  const warning = root.querySelector("[data-host-refresh-warning]");
  const sourceLabels = {
    openvpn: "VPN", mikrotik_arp: "MikroTik ARP", mikrotik_dhcp: "DHCP",
    mikrotik_neighbor: "Neighbor", mikrotik_identity: "Identity",
  };
  const categoryLabels = {
    local_device: "Обычная сеть", vpn_client: "VPN", router: "Роутер",
    site_device: "Site-to-site", network_infra: "Сетевая инфраструктура",
    telephony: "Телефония", mgmt: "Управление", wan: "WAN/провайдер",
    vipnet_transit: "ViPNet transit", noise: "Шум", unknown: "Неизвестно",
  };
  const deviceTypeLabels = {
    pc: "ПК", phone: "Телефон", server: "Сервер", network: "Сеть",
    camera: "Камера", printer: "Принтер", noise: "Шум", unknown: "Неизвестно",
  };
  let currentSnapshotId = Number(root.dataset.snapshotId || 0);
  let controller;
  let requestSequence = 0;
  let metaSequence = 0;

  const text = (value, fallback = "-") => String(value || fallback);
  const statusClass = (value) => {
    const state = String(value || "").toLowerCase();
    if (["active", "connected", "valid", "ok", "true"].includes(state)) return "ok";
    if (["disabled", "warning", "warn", "stale"].includes(state)) return "warn";
    if (["deleted", "revoked", "error", "failed", "inactive", "critical"].includes(state)) return "bad";
    return "muted";
  };
  const addText = (parent, value, className = "") => {
    const node = document.createElement("span");
    if (className) node.className = className;
    node.textContent = text(value);
    parent.append(node);
    return node;
  };
  const addBadge = (parent, value, className = "muted") => addText(parent, value, `badge ${className}`);
  const availabilityMethod = (value) => {
    const method = String(value || "").toLowerCase();
    if (method === "icmp") return "ICMP";
    if (method === "tcp") return "TCP";
    if (method.startsWith("tcp:")) return /^tcp:\d+$/.test(method) ? method.toUpperCase() : "TCP";
    return method.toUpperCase();
  };
  const evidence = (values, separator = ", ") => {
    const labels = { mikrotik_arp: "ARP", mikrotik_dhcp: "DHCP", mikrotik_bridge: "bridge", snmp_fdb: "FDB" };
    return Array.isArray(values) ? values.map((value) => labels[String(value).toLowerCase()]).filter(Boolean).join(separator) : "";
  };
  const availabilityStatus = (host) => {
    const availability = host.availability;
    if (!availability || typeof availability !== "object") return "не мониторится";
    const state = String(availability.state || "").toLowerCase();
    if (state === "online") return availabilityMethod(availability.active_method) ? `online · ${availabilityMethod(availability.active_method)}` : "не мониторится";
    if (state === "seen") return evidence(availability.passive_evidence, "/") ? `seen · ${evidence(availability.passive_evidence, "/")}` : "seen";
    if (state === "offline") return "offline";
    if (state === "stale") return "данные устарели";
    if (state === "connected" || host.status === "connected") return "VPN подключён";
    return "не мониторится";
  };
  const availabilityReason = (value) => ({
    active_probe: "активная проверка (active probe)", passive_evidence: "пассивные наблюдения",
    active_negative_no_passive_evidence: "нет ответа и свежих наблюдений", missing_run: "нет запуска",
    run_failed: "ошибка запуска / run failed (run_failed)", run_stale: "устаревший запуск",
    missing_result: "нет результата", openvpn_management: "сессия OpenVPN", not_monitored: "не мониторится",
  })[String(value || "").split(" ", 1)[0]] || "";
  const cell = (row, value, className = "") => {
    const node = document.createElement("td");
    if (className) node.className = className;
    if (value !== undefined) node.textContent = text(value);
    row.append(node);
    return node;
  };
  const addHostRow = (host) => {
    const row = document.createElement("tr");
    cell(row, host.ip, "mono");
    cell(row, host.mac, "mono");
    cell(row, host.manual_name || host.display_name || host.hostname);
    const typeCell = cell(row);
    addBadge(typeCell, deviceTypeLabels[host.device_type] || host.device_type || "-");
    if (host.device_confidence) addText(typeCell, ` ${host.device_confidence}%`, "muted");
    const categoryCell = cell(row);
    addBadge(categoryCell, categoryLabels[host.category] || host.category, statusClass(host.category));
    const statusCell = cell(row);
    const statusLink = document.createElement("a");
    statusLink.href = `/network/hosts/${encodeURIComponent(host.ip || "")}`;
    statusLink.title = "Открыть доступность устройства";
    addBadge(statusLink, availabilityStatus(host), statusClass(host.status));
    statusCell.append(statusLink);
    cell(row, "—").classList.add("muted");
    const availability = host.availability;
    if (availability && typeof availability === "object") {
      cell(row, `${availabilityMethod(availability.active_method) || "-"}${availability.checked_at ? ` · ${availability.checked_at}` : ""}`);
      cell(row, evidence(availability.passive_evidence) || availabilityReason(availability.reason) || "-");
    } else {
      cell(row, "не мониторится");
      cell(row, "не мониторится");
    }
    const sourcesCell = cell(row);
    (Array.isArray(host.sources) ? host.sources : []).forEach((source) => addBadge(sourcesCell, sourceLabels[source] || source));
    const tagsCell = cell(row);
    (Array.isArray(host.manual_tags) ? host.manual_tags : []).forEach((tag) => addBadge(tagsCell, tag, "ok"));
    cell(row, host.site);
    cell(row, host.last_seen_at);
    const actionsCell = cell(row, undefined, "actions");
    const action = document.createElement("a");
    action.className = "button small secondary";
    const key = String(host.device_key || "");
    action.href = (key.startsWith("mac:") || key.startsWith("legacy-host:"))
      ? `/network/assets/${encodeURIComponent(key)}`
      : `/network/hosts/${encodeURIComponent(host.ip || "")}`;
    action.textContent = "Открыть";
    actionsCell.append(action);
    rows.append(row);
  };
  const replaceRows = (data) => {
    const hosts = Array.isArray(data.hosts) ? data.hosts : [];
    rows.replaceChildren();
    if (!hosts.length) {
      const row = document.createElement("tr");
      const empty = cell(row, "Нет данных. Запустите сбор.", "empty");
      empty.colSpan = 14;
      rows.append(row);
    } else hosts.forEach(addHostRow);
    const snapshot = data.snapshot || {};
    currentSnapshotId = Number(snapshot.snapshot_id || 0);
    root.dataset.snapshotId = String(currentSnapshotId);
    renderSnapshot(snapshot);
    renderPagination(data.pagination || {});
  };
  const renderSnapshot = (snapshot) => {
    const snapshotId = Number(snapshot.snapshot_id || 0);
    const stale = Boolean(snapshot.stale);
    const state = !snapshotId ? "pending" : stale ? "stale" : "ready";
    snapshotState.dataset.state = state;
    if (!snapshotId) snapshotState.textContent = "Снимок ещё не опубликован. Ожидание данных.";
    else snapshotState.textContent = `Снимок №${snapshotId} от ${text(snapshot.generated_at)}${stale ? " устарел" : ""} · ${Number(snapshot.total_hosts || 0)} устройств.`;
  };
  const renderPagination = (page) => {
    pagination.textContent = `Страница ${Number(page.page || 1)} из ${Number(page.pages || 0)} · ${Number(page.total || 0)} устройств по текущему фильтру.`;
  };
  const showWarning = (message) => {
    warning.textContent = message;
    warning.hidden = false;
  };
  const clearWarning = () => { warning.hidden = true; warning.textContent = ""; };
  const currentListUrl = () => `/api/v1/network/hosts${window.location.search}`;
  const poll = async () => {
    const metaRequest = ++metaSequence;
    try {
      const metaResponse = await fetch("/api/v1/network/hosts/meta", { credentials: "same-origin" });
      if (!metaResponse.ok) throw new Error("metadata request failed");
      const nextMeta = (await metaResponse.json()).data?.snapshot;
      if (!nextMeta || metaRequest !== metaSequence) throw new Error("invalid metadata response");
      clearWarning();
      if (Number(nextMeta.snapshot_id || 0) === currentSnapshotId) return;
      controller?.abort();
      controller = new AbortController();
      const sequence = ++requestSequence;
      const response = await fetch(currentListUrl(), { signal: controller.signal, credentials: "same-origin" });
      if (!response.ok) throw new Error("snapshot page request failed");
      const payload = await response.json();
      if (requestSequence === sequence) replaceRows(payload.data || {});
    } catch (error) {
      if (error.name !== "AbortError") showWarning("Не удалось обновить снимок. Показаны ранее загруженные данные.");
    }
  };
  poll();
  window.setInterval(poll, 15000);
})();
