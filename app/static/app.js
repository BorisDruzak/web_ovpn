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
    .replace(/(\b(?:endpoint|peer(?:[ _-]?(?:host|hostname))?|hostname|host|remote(?:[ _-]?host)?|address)\s*(?:=|:)\s*)[A-Za-z0-9][A-Za-z0-9.-]*/gi, "$1[redacted address]")
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

async function loadVpnRuntimeHealth() {
  const card = document.querySelector("#vpn-runtime-card");
  if (!card) return;

  const state = card.querySelector("[data-runtime-health-state]");
  const details = card.querySelector("[data-runtime-health-details]");
  const warnings = card.querySelector("[data-runtime-health-warnings]");
  const errors = card.querySelector("[data-runtime-health-errors]");

  try {
    const response = await fetch("/network/runtime-health", {credentials: "same-origin"});
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
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (!document.querySelector("#vpn-runtime-card")) return;
  void loadVpnRuntimeHealth();
  window.setInterval(loadVpnRuntimeHealth, 30000);
});
