document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  const dangerButton = form.querySelector("button.danger");
  const confirmInput = form.querySelector('input[name="confirm_name"]');
  if (!dangerButton || !confirmInput) return;
  if (!confirmInput.value.trim()) {
    event.preventDefault();
    confirmInput.focus();
  }
});

function runtimeHealthValue(value) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "Unknown";
}

function dashboardStatusClass(value) {
  const normalized = String(value || "unknown").toLowerCase();
  if (["active", "connected", "valid", "ok", "true"].includes(normalized)) return "ok";
  if (["disabled", "warning", "warn", "stale"].includes(normalized)) return "warn";
  if (["deleted", "revoked", "error", "failed", "inactive", "critical"].includes(normalized)) return "bad";
  return "muted";
}

const DASHBOARD_REFRESH_DELAY_MS = 5000;
let dashboardInFlight = false;
let dashboardTimer = null;

function dashboardFreshnessLabel(generatedAt, stale) {
  const generatedAtMs = Date.parse(generatedAt || "");
  if (!Number.isFinite(generatedAtMs)) return stale ? "Данные устарели" : "Время обновления неизвестно";
  const ageSeconds = Math.max(0, Math.floor((Date.now() - generatedAtMs) / 1000));
  const age = ageSeconds < 2 ? "только что" : `${ageSeconds} с назад`;
  return stale ? `Данные устарели — обновлены ${age}` : `Обновлено ${age}`;
}

function setDashboardFreshness(card, message, stale = false) {
  const element = card.querySelector("[data-dashboard-freshness]");
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("stale", stale);
}

async function loadDashboardData() {
  const card = document.querySelector("[data-dashboard-url]");
  if (!card || dashboardInFlight) return;
  dashboardInFlight = true;
  const setValue = (selector, value, badge = false) => {
    const element = card.querySelector(selector);
    if (!element) return;
    element.textContent = String(value);
    if (badge) element.className = `badge ${dashboardStatusClass(value)}`;
  };
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(card.dataset.dashboardUrl, {credentials: "same-origin", signal: controller.signal});
    if (!response.ok) throw new Error("dashboard unavailable");
    const payload = await response.json();
    const data = payload.data || {};
    setValue("[data-dashboard-openvpn]", data.openvpn || "unknown", true);
    setValue("[data-dashboard-nat]", data.nat || "unknown", true);
    setValue("[data-dashboard-clients]", Number.isFinite(data.clients_count) ? data.clients_count : "-");
    setValue("[data-dashboard-connected]", Number.isFinite(data.connected_count) ? data.connected_count : "-");
    setDashboardFreshness(card, dashboardFreshnessLabel(payload.generated_at, payload.stale), Boolean(payload.stale));
  } catch (_) {
    setValue("[data-dashboard-openvpn]", "unavailable", true);
    setValue("[data-dashboard-nat]", "unavailable", true);
    setDashboardFreshness(card, "Данные недоступны", true);
  } finally {
    window.clearTimeout(timeout);
    dashboardInFlight = false;
  }
}

function scheduleDashboardData() {
  if (!document.querySelector("[data-dashboard-url]") || document.hidden) return;
  void loadDashboardData().finally(() => {
    if (!document.hidden) {
      dashboardTimer = window.setTimeout(scheduleDashboardData, DASHBOARD_REFRESH_DELAY_MS);
    }
  });
}

function runtimeHealthRows(sections) {
  const openvpn = sections.openvpn || {};
  const wireguard = sections.wireguard || {};
  const policyRouting = sections.policy_routing || {};
  const fields = [
    ["OpenVPN service", openvpn.service_active],
    ["OpenVPN management", openvpn.management_available],
    ["WireGuard service", wireguard.service_active],
    ["WireGuard link", wireguard.link_present],
    ["WireGuard handshake age (s)", wireguard.handshake_age_seconds],
    ["WireGuard MTU", wireguard.mtu],
    ["Policy rule", policyRouting.rule_present],
    ["Policy table 123 default", policyRouting.table_123_default],
    ["Policy mangle chain", policyRouting.mangle_chain_present],
    ["Policy NAT chain", policyRouting.nat_chain_present],
    ["Legacy UDP 51820 rule", policyRouting.legacy_51820_rule_present],
  ];

  return fields.flatMap(([label, value]) => {
    const term = document.createElement("dt");
    const definition = document.createElement("dd");
    term.textContent = label;
    definition.textContent = runtimeHealthValue(value);
    return [term, definition];
  });
}

function runtimeHealthMessage(message) {
  return String(message)
    .replace(/(^|[^A-Za-z0-9+/])(?:[A-Za-z0-9+/]{43}=)(?=$|[^A-Za-z0-9+/=])/g, "$1[redacted key]")
    .replace(/\[(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*\](?::\d{1,5})?(?:\/\d{1,3})?/gi, "[redacted address]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?::\d{1,5})?\b/g, "[redacted address]")
    .replace(/(^|[^0-9a-f:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]+(?=$|[^0-9a-f:])/gi, "$1[redacted address]")
    .replace(/(\b(?:endpoint|peer(?:[ _-]?(?:host|hostname))?|hostname|host|remote(?:[ _-]?host)?|address)\s*(?:=|:)\s*)[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?/gi, "$1[redacted address]")
    .replace(/(^|[^A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}:\d{1,5}(?=$|[^0-9])/g, "$1[redacted address]")
    .replace(/(^|[^A-Za-z0-9-])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?::\d{1,5})(?=$|[^0-9])/g, "$1[redacted address]")
    .replace(/(^|[^A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?=$|[^A-Za-z0-9.-])/g, "$1[redacted address]");
}

function runtimeHealthMessages(messages) {
  if (!Array.isArray(messages)) return [];
  return messages.filter((message) => typeof message === "string").map((message) => {
    const item = document.createElement("li");
    item.textContent = runtimeHealthMessage(message);
    return item;
  });
}

let runtimeHealthInFlight = false;
let runtimeHealthTimer = null;

async function loadVpnRuntimeHealth() {
  const card = document.querySelector("#vpn-runtime-card");
  if (!card) return;
  if (runtimeHealthInFlight) return;
  runtimeHealthInFlight = true;

  const state = card.querySelector("[data-runtime-health-state]");
  const details = card.querySelector("[data-runtime-health-details]");
  const warnings = card.querySelector("[data-runtime-health-warnings]");
  const errors = card.querySelector("[data-runtime-health-errors]");

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch("/network/runtime-health", {credentials: "same-origin", signal: controller.signal});
    if (!response.ok) throw new Error("runtime status unavailable");

    const health = await response.json();
    state.textContent = health.overall === "ok" ? "OK" : "Error";
    details.replaceChildren(...runtimeHealthRows(health.sections || {}));

    const warningItems = runtimeHealthMessages(health.warnings);
    warnings.replaceChildren(...warningItems);
    warnings.hidden = warningItems.length === 0;

    const errorItems = runtimeHealthMessages(health.errors);
    errors.replaceChildren(...errorItems);
    errors.hidden = errorItems.length === 0;
  } catch (_) {
    state.textContent = "Status unavailable";
    details.replaceChildren();
    warnings.replaceChildren();
    warnings.hidden = true;
    errors.replaceChildren();
    errors.hidden = true;
  } finally {
    window.clearTimeout(timeout);
    runtimeHealthInFlight = false;
  }
}

function scheduleVpnRuntimeHealth() {
  if (!document.querySelector("#vpn-runtime-card") || document.hidden) return;
  void loadVpnRuntimeHealth().finally(() => {
    if (!document.hidden) {
      runtimeHealthTimer = window.setTimeout(scheduleVpnRuntimeHealth, 30000);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const hasDashboard = Boolean(document.querySelector("[data-dashboard-url]"));
  if (hasDashboard) scheduleDashboardData();
  const copyButton = document.querySelector("[data-copy-observer-key]");
  const publicKey = document.querySelector("[data-observer-public-key]");
  const copyStatus = document.querySelector("[data-observer-key-status]");

  if (copyButton && publicKey && copyStatus) {
    void fetch("/network/server-drafts/public-key", {credentials: "same-origin"})
      .then((response) => {
        if (!response.ok) throw new Error("public key unavailable");
        return response.text();
      })
      .then((key) => {
        publicKey.value = key;
        copyButton.disabled = false;
        copyStatus.textContent = "";
      })
      .catch(() => {
        copyStatus.textContent = "Public key unavailable.";
      });

    copyButton.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(publicKey.value);
        copyStatus.textContent = "Public key copied.";
      } catch (_) {
        copyStatus.textContent = "Unable to copy public key.";
      }
    });
  }

  const hasRuntimeHealth = Boolean(document.querySelector("#vpn-runtime-card"));
  if (hasRuntimeHealth) scheduleVpnRuntimeHealth();
  if (!hasDashboard && !hasRuntimeHealth) return;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      if (dashboardTimer) window.clearTimeout(dashboardTimer);
      dashboardTimer = null;
      if (runtimeHealthTimer) window.clearTimeout(runtimeHealthTimer);
      runtimeHealthTimer = null;
    } else {
      if (hasDashboard && !dashboardTimer && !dashboardInFlight) {
        scheduleDashboardData();
      }
      if (hasRuntimeHealth && !runtimeHealthTimer && !runtimeHealthInFlight) {
        scheduleVpnRuntimeHealth();
      }
    }
  });
});
