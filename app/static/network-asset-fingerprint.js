(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.NetworkAssetFingerprint = api;
    const start = () => api.initFingerprintPanel(root.document, root);
    if (root.document.readyState === "loading") {
      root.document.addEventListener("DOMContentLoaded", start, {once: true});
    } else {
      start();
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const POLL_DELAY_MS = 2000;
  const POLL_DEADLINE_MS = 30000;

  function createFingerprintPoller(options) {
    const fetchImpl = options.fetchImpl;
    const now = options.now;
    const isVisible = options.isVisible;
    const setTimer = options.setTimer;
    const clearTimer = options.clearTimer;
    const render = options.render;
    let started = false;
    let stopped = false;
    let inFlight = false;
    let timer = null;
    let startedAt = 0;

    function beforeDeadline() {
      return now() - startedAt < POLL_DEADLINE_MS;
    }

    function cancelPendingTimer() {
      if (timer !== null) {
        clearTimer(timer);
        timer = null;
      }
    }

    function scheduleNext() {
      if (stopped || timer !== null || !isVisible() || !beforeDeadline()) return;
      timer = setTimer(() => {
        timer = null;
        void poll();
      }, POLL_DELAY_MS);
    }

    async function poll() {
      if (stopped || inFlight || !isVisible() || !beforeDeadline()) return;
      inFlight = true;
      let keepPolling = true;
      try {
        const response = await fetchImpl(options.statusUrl, {
          method: "GET",
          credentials: "same-origin",
        });
        if (response.ok) {
          const payload = await response.json();
          render(payload);
          if (payload.status === "failed" || (payload.status === "success" && payload.fresh === true)) {
            stopped = true;
            keepPolling = false;
          }
        }
      } catch (_error) {
        keepPolling = true;
      } finally {
        inFlight = false;
        if (keepPolling) scheduleNext();
      }
    }

    async function start() {
      if (started) return;
      started = true;
      startedAt = now();
      try {
        await fetchImpl(options.ensureUrl, {
          method: "POST",
          credentials: "same-origin",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: new URLSearchParams({csrf_token: options.csrfToken}).toString(),
        });
      } catch (_error) {}
      await poll();
    }

    function stop() {
      stopped = true;
      cancelPendingTimer();
    }

    function visibilityChanged() {
      if (!isVisible()) {
        cancelPendingTimer();
        return Promise.resolve();
      }
      if (!started || stopped || !beforeDeadline()) return Promise.resolve();
      return poll();
    }

    return {start, stop, visibilityChanged};
  }

  function setText(documentRef, selector, value, fallback = "-") {
    const node = documentRef.querySelector(selector);
    if (node) node.textContent = value === "" || value === null || value === undefined ? fallback : String(value);
  }

  function renderFingerprintPanel(documentRef, payload) {
    const stateLabels = {
      not_run: "Нет данных",
      running: "Обновление...",
      success: payload.fresh ? "Актуально" : "Нет данных",
      failed: "Ошибка fingerprint",
      unavailable: "Нет данных",
    };
    setText(documentRef, "[data-fingerprint-state]", stateLabels[payload.status] || "Нет данных");
    setText(documentRef, "[data-fingerprint-type]", payload.device_type || "unknown");
    setText(documentRef, "[data-fingerprint-confidence]", Number.isInteger(payload.confidence) ? `${payload.confidence}%` : "0%");
    setText(documentRef, "[data-fingerprint-vendor]", payload.vendor || "-");
    setText(documentRef, "[data-fingerprint-os]", payload.os || "-");
    setText(documentRef, "[data-fingerprint-accuracy]", Number.isInteger(payload.nmap_accuracy) ? `${payload.nmap_accuracy}%` : "-");
    setText(documentRef, "[data-fingerprint-time]", payload.last_fingerprint_at || "-");

    const servicesNode = documentRef.querySelector("[data-fingerprint-services]");
    if (servicesNode) {
      const rows = [];
      for (const service of Array.isArray(payload.services) ? payload.services.slice(0, 64) : []) {
        const row = documentRef.createElement("tr");
        for (const value of [service.port, service.protocol, service.service, service.product, service.version]) {
          const cell = documentRef.createElement("td");
          cell.textContent = value === "" || value === null || value === undefined ? "-" : String(value);
          row.appendChild(cell);
        }
        rows.push(row);
      }
      if (rows.length === 0) {
        const row = documentRef.createElement("tr");
        const cell = documentRef.createElement("td");
        cell.colSpan = 5;
        cell.textContent = "Нет данных";
        row.appendChild(cell);
        rows.push(row);
      }
      servicesNode.replaceChildren(...rows);
    }

    const evidenceNode = documentRef.querySelector("[data-fingerprint-evidence]");
    if (evidenceNode) {
      const items = [];
      for (const item of Array.isArray(payload.evidence) ? payload.evidence.slice(0, 16) : []) {
        const row = documentRef.createElement("li");
        row.textContent = `${item.source || "Evidence"}: ${item.summary || "-"}`;
        items.push(row);
      }
      if (items.length === 0) {
        const row = documentRef.createElement("li");
        row.textContent = "Нет данных";
        items.push(row);
      }
      evidenceNode.replaceChildren(...items);
    }
  }

  function initFingerprintPanel(documentRef, windowRef) {
    const panel = documentRef.querySelector("[data-fingerprint-panel]");
    if (!panel) return null;
    const controller = createFingerprintPoller({
      ensureUrl: panel.dataset.ensureUrl,
      statusUrl: panel.dataset.statusUrl,
      csrfToken: panel.dataset.csrfToken,
      fetchImpl: windowRef.fetch.bind(windowRef),
      now: () => windowRef.Date.now(),
      isVisible: () => !documentRef.hidden,
      setTimer: windowRef.setTimeout.bind(windowRef),
      clearTimer: windowRef.clearTimeout.bind(windowRef),
      render: (payload) => renderFingerprintPanel(documentRef, payload),
    });
    documentRef.addEventListener("visibilitychange", () => {
      void controller.visibilityChanged();
    });
    controller.ready = controller.start();
    return controller;
  }

  return {createFingerprintPoller, initFingerprintPanel, renderFingerprintPanel};
});
