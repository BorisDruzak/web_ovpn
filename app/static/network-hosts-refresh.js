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
  const createHostRow = (host) => {
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
    return row;
  };
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const isString = (value) => typeof value === "string";
  const isNullableString = (value) => value === null || isString(value);
  const isStringArray = (value) => Array.isArray(value) && value.every(isString);
  const isNonNegativeInteger = (value) => Number.isInteger(value) && value >= 0;
  const isSnapshot = (value) => isObject(value)
    && isNonNegativeInteger(value.snapshot_id)
    && isNullableString(value.generated_at)
    && isNonNegativeInteger(value.total_hosts)
    && isNonNegativeInteger(value.duration_ms)
    && (value.stale === undefined || typeof value.stale === "boolean");
  const isPagination = (value) => isObject(value)
    && Number.isInteger(value.page) && value.page >= 1
    && Number.isInteger(value.limit) && value.limit >= 1
    && isNonNegativeInteger(value.total)
    && isNonNegativeInteger(value.pages);
  const isAvailability = (value) => value === null || (
    isObject(value)
    && ["state", "active_method", "checked_at", "run_status", "cidr", "check_origin", "reason"]
      .every((key) => value[key] === undefined || isString(value[key]))
    && (value.passive_evidence === undefined || isStringArray(value.passive_evidence))
  );
  const isHost = (value) => isObject(value)
    && isString(value.ip) && value.ip.length > 0
    && ["mac", "hostname", "manual_name"].every((key) => isNullableString(value[key]))
    && ["display_name", "category", "device_key", "device_type", "status", "site", "last_seen_at", "last_source"]
      .every((key) => isString(value[key]))
    && typeof value.device_confidence === "number" && Number.isFinite(value.device_confidence)
    && ["device_evidence", "tags", "manual_tags", "sources"].every((key) => isStringArray(value[key]))
    && isAvailability(value.availability)
    && value.vpn_client === null;
  const replacementFor = (payload) => {
    if (!isObject(payload) || payload.status !== "ok" || !isObject(payload.data)) {
      throw new Error("invalid snapshot page envelope");
    }
    const { hosts, pagination: nextPagination, snapshot } = payload.data;
    if (!Array.isArray(hosts) || !hosts.every(isHost) || !isPagination(nextPagination) || !isSnapshot(snapshot)) {
      throw new Error("invalid snapshot page data");
    }
    const fragment = document.createDocumentFragment();
    if (!hosts.length) {
      const row = document.createElement("tr");
      const empty = cell(row, "Нет данных. Запустите сбор.", "empty");
      empty.colSpan = 14;
      fragment.append(row);
    } else hosts.forEach((host) => fragment.append(createHostRow(host)));
    return {
      fragment,
      paginationText: `Страница ${nextPagination.page} из ${nextPagination.pages} · ${nextPagination.total} устройств по текущему фильтру.`,
      snapshot,
      snapshotText: snapshotTextFor(snapshot),
    };
  };
  const snapshotTextFor = (snapshot) => {
    const snapshotId = snapshot.snapshot_id;
    const stale = snapshot.stale === true;
    const state = !snapshotId ? "pending" : stale ? "stale" : "ready";
    return {
      state,
      text: !snapshotId
        ? "Снимок ещё не опубликован. Ожидание данных."
        : `Снимок №${snapshotId} от ${text(snapshot.generated_at)}${stale ? " устарел" : ""} · ${snapshot.total_hosts} устройств.`,
    };
  };
  const replaceRows = (payload) => {
    const replacement = replacementFor(payload);
    rows.replaceChildren(replacement.fragment);
    root.dataset.snapshotId = String(replacement.snapshot.snapshot_id);
    currentSnapshotId = replacement.snapshot.snapshot_id;
    snapshotState.dataset.state = replacement.snapshotText.state;
    snapshotState.textContent = replacement.snapshotText.text;
    pagination.textContent = replacement.paginationText;
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
      if (metaRequest !== metaSequence) return;
      if (!metaResponse.ok) throw new Error("metadata request failed");
      const metaPayload = await metaResponse.json();
      if (metaRequest !== metaSequence) return;
      const nextMeta = metaPayload.data?.snapshot;
      if (!isSnapshot(nextMeta)) throw new Error("invalid metadata response");
      if (nextMeta.snapshot_id === currentSnapshotId) {
        const freshness = snapshotTextFor(nextMeta);
        snapshotState.dataset.state = freshness.state;
        snapshotState.textContent = freshness.text;
        clearWarning();
        return;
      }
      controller?.abort();
      controller = new AbortController();
      const sequence = ++requestSequence;
      const response = await fetch(currentListUrl(), { signal: controller.signal, credentials: "same-origin" });
      if (!response.ok) throw new Error("snapshot page request failed");
      const payload = await response.json();
      if (metaRequest !== metaSequence || requestSequence !== sequence) return;
      replaceRows(payload);
      clearWarning();
    } catch (error) {
      if (metaRequest !== metaSequence || error.name === "AbortError") return;
      showWarning("Не удалось обновить снимок. Показаны ранее загруженные данные.");
    }
  };
  poll();
  window.setInterval(poll, 15000);
})();
