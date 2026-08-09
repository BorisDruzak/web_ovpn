import shutil
import subprocess
from pathlib import Path

import pytest


NODE = shutil.which("node")
SCRIPT = Path(__file__).parents[1] / "app" / "static" / "network-asset-fingerprint.js"


def run_node(source: str) -> None:
    completed = subprocess.run(
        [NODE, "-e", source, str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


@pytest.mark.skipif(NODE is None, reason="node is required for browser lifecycle tests")
def test_fingerprint_poller_posts_once_and_never_overlaps_status_requests():
    run_node(
        r"""
const assert = require("node:assert/strict");
const { createFingerprintPoller } = require(process.argv[1]);

(async () => {
  const requests = [];
  const scheduled = [];
  let statusCalls = 0;
  let resolveSecondStatus;
  const fetchImpl = async (url, options) => {
    requests.push({url, method: options.method || "GET", body: options.body || ""});
    if ((options.method || "GET") === "POST") {
      return {ok: true, status: 202, json: async () => ({status: "scheduled"})};
    }
    statusCalls += 1;
    if (statusCalls === 1) {
      return {ok: true, status: 200, json: async () => ({status: "running"})};
    }
    if (statusCalls === 2) {
      return await new Promise((resolve) => { resolveSecondStatus = resolve; });
    }
    return {ok: true, status: 200, json: async () => ({status: "success"})};
  };
  const poller = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf-value",
    fetchImpl,
    now: () => 0,
    isVisible: () => true,
    setTimer: (fn, delay) => {
      const timer = {fn, delay, cancelled: false};
      scheduled.push(timer);
      return timer;
    },
    clearTimer: (timer) => { timer.cancelled = true; },
    render: () => {},
  });

  await poller.start();
  await poller.start();
  assert.equal(requests.filter((item) => item.method === "POST").length, 1);
  assert.equal(requests[0].body, "csrf_token=csrf-value");
  assert.equal(statusCalls, 1);
  assert.equal(scheduled.length, 1);
  assert.equal(scheduled[0].delay, 2000);

  scheduled[0].fn();
  await Promise.resolve();
  assert.equal(statusCalls, 2);
  scheduled[0].fn();
  await Promise.resolve();
  assert.equal(statusCalls, 2, "a pending status request must suppress overlap");

  resolveSecondStatus({
    ok: true,
    status: 200,
    json: async () => ({status: "running"}),
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(scheduled.length, 2);
  assert.equal(scheduled[1].delay, 2000);
})();
"""
    )


@pytest.mark.skipif(NODE is None, reason="node is required for browser lifecycle tests")
def test_fingerprint_poller_pauses_hidden_stops_terminal_and_honors_deadline():
    run_node(
        r"""
const assert = require("node:assert/strict");
const { createFingerprintPoller } = require(process.argv[1]);

(async () => {
  let clock = 0;
  let visible = true;
  let statusCalls = 0;
  const timers = [];
  const statuses = [
    {status: "running", fresh: false},
    {status: "success", fresh: true},
  ];
  const poller = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf",
    fetchImpl: async (_url, options) => {
      if (options.method === "POST") return {ok: true, status: 202};
      const status = statuses[statusCalls++] || {status: "success", fresh: true};
      return {ok: true, status: 200, json: async () => status};
    },
    now: () => clock,
    isVisible: () => visible,
    setTimer: (fn, delay) => {
      const timer = {fn, delay, cancelled: false};
      timers.push(timer);
      return timer;
    },
    clearTimer: (timer) => { timer.cancelled = true; },
    render: () => {},
  });

  await poller.start();
  assert.equal(statusCalls, 1);
  assert.equal(timers.length, 1);

  visible = false;
  await poller.visibilityChanged();
  assert.equal(timers[0].cancelled, true);
  timers[0].fn();
  await Promise.resolve();
  assert.equal(statusCalls, 1, "hidden pages must not poll");

  visible = true;
  clock = 1000;
  await poller.visibilityChanged();
  assert.equal(statusCalls, 2);
  assert.equal(timers.length, 1, "success must stop polling");

  let deadlineClock = 0;
  let deadlineStatusCalls = 0;
  const deadlineTimers = [];
  const deadlinePoller = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf",
    fetchImpl: async (_url, options) => {
      if (options.method === "POST") return {ok: true, status: 202};
      deadlineStatusCalls += 1;
      return {ok: true, status: 200, json: async () => ({status: "running"})};
    },
    now: () => deadlineClock,
    isVisible: () => true,
    setTimer: (fn, delay) => {
      const timer = {fn, delay, cancelled: false};
      deadlineTimers.push(timer);
      return timer;
    },
    clearTimer: (timer) => { timer.cancelled = true; },
    render: () => {},
  });

  await deadlinePoller.start();
  assert.equal(deadlineStatusCalls, 1);
  deadlineClock = 30000;
  deadlineTimers[0].fn();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(deadlineStatusCalls, 1);
  assert.equal(deadlineTimers.length, 1, "deadline must prevent rescheduling");
})();
"""
    )


@pytest.mark.skipif(NODE is None, reason="node is required for browser lifecycle tests")
def test_browser_adapter_starts_and_renders_normalized_terminal_payload_safely():
    run_node(
        r"""
const assert = require("node:assert/strict");
const { initFingerprintPanel } = require(process.argv[1]);

(async () => {
  function element(tag = "div") {
    return {
      tag,
      textContent: "",
      children: [],
      appendChild(child) { this.children.push(child); },
      replaceChildren(...children) { this.children = children; },
      set innerHTML(_value) { throw new Error("unsafe innerHTML render"); },
    };
  }
  const panel = element("section");
  panel.dataset = {
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf-token",
  };
  const nodes = {
    "[data-fingerprint-state]": element(),
    "[data-fingerprint-type]": element(),
    "[data-fingerprint-confidence]": element(),
    "[data-fingerprint-vendor]": element(),
    "[data-fingerprint-os]": element(),
    "[data-fingerprint-accuracy]": element(),
    "[data-fingerprint-time]": element(),
    "[data-fingerprint-services]": element("tbody"),
    "[data-fingerprint-evidence]": element("ul"),
  };
  const listeners = {};
  const documentRef = {
    hidden: false,
    querySelector(selector) {
      if (selector === "[data-fingerprint-panel]") return panel;
      return nodes[selector] || null;
    },
    createElement: element,
    addEventListener(name, callback) { listeners[name] = callback; },
  };
  const requests = [];
  const payload = {
    status: "success",
    fresh: true,
    device_type: "network",
    confidence: 96,
    vendor: "MikroTik",
    os: "RouterOS 7.15",
    nmap_accuracy: 98,
    last_fingerprint_at: "2026-08-09T10:00:01Z",
    services: [{port: 22, protocol: "tcp", service: "ssh", product: "RouterOS sshd", version: "7.15"}],
    evidence: [{source: "LLDP", summary: "bridge"}],
  };
  const windowRef = {
    fetch: async (url, options) => {
      requests.push({url, method: options.method});
      if (options.method === "POST") return {ok: true, status: 202};
      return {ok: true, status: 200, json: async () => payload};
    },
    setTimeout,
    clearTimeout,
    Date,
  };

  const controller = initFingerprintPanel(documentRef, windowRef);
  await controller.ready;

  assert.deepEqual(requests, [
    {url: "/ensure", method: "POST"},
    {url: "/status", method: "GET"},
  ]);
  assert.equal(nodes["[data-fingerprint-state]"].textContent, "Актуально");
  assert.equal(nodes["[data-fingerprint-type]"].textContent, "network");
  assert.equal(nodes["[data-fingerprint-confidence]"].textContent, "96%");
  assert.equal(nodes["[data-fingerprint-vendor]"].textContent, "MikroTik");
  assert.equal(nodes["[data-fingerprint-os]"].textContent, "RouterOS 7.15");
  assert.equal(nodes["[data-fingerprint-accuracy]"].textContent, "98%");
  assert.equal(nodes["[data-fingerprint-time]"].textContent, "2026-08-09T10:00:01Z");
  const serviceCells = nodes["[data-fingerprint-services]"].children[0].children;
  assert.deepEqual(serviceCells.map((cell) => cell.textContent), ["22", "tcp", "ssh", "RouterOS sshd", "7.15"]);
  assert.equal(nodes["[data-fingerprint-evidence]"].children[0].textContent, "LLDP: bridge");
  assert.equal(typeof listeners.visibilitychange, "function");
})();
"""
    )


@pytest.mark.skipif(NODE is None, reason="node is required for browser lifecycle tests")
def test_fingerprint_poller_contains_transport_failures_without_failing_card():
    run_node(
        r"""
const assert = require("node:assert/strict");
const { createFingerprintPoller } = require(process.argv[1]);

(async () => {
  const rendered = [];
  let calls = 0;
  const ensureFailure = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf",
    fetchImpl: async (_url, options) => {
      calls += 1;
      if (options.method === "POST") throw new Error("ensure unavailable");
      return {ok: true, status: 200, json: async () => ({status: "failed"})};
    },
    now: () => 0,
    isVisible: () => true,
    setTimer: () => { throw new Error("failed is terminal"); },
    clearTimer: () => {},
    render: (payload) => rendered.push(payload.status),
  });
  await ensureFailure.start();
  assert.equal(calls, 2);
  assert.deepEqual(rendered, ["failed"]);

  const retryTimers = [];
  const statusFailure = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf",
    fetchImpl: async (_url, options) => {
      if (options.method === "POST") return {ok: true, status: 202};
      throw new Error("status unavailable");
    },
    now: () => 0,
    isVisible: () => true,
    setTimer: (fn, delay) => {
      retryTimers.push({fn, delay});
      return retryTimers.at(-1);
    },
    clearTimer: () => {},
    render: () => { throw new Error("transport errors have no payload"); },
  });
  await statusFailure.start();
  assert.equal(retryTimers.length, 1);
  assert.equal(retryTimers[0].delay, 2000);
})();
"""
    )


@pytest.mark.skipif(NODE is None, reason="node is required for browser lifecycle tests")
def test_fingerprint_poller_does_not_stop_on_stale_success_before_background_claim():
    run_node(
        r"""
const assert = require("node:assert/strict");
const { createFingerprintPoller } = require(process.argv[1]);

(async () => {
  const statuses = [
    {status: "success", fresh: false},
    {status: "running", fresh: false},
    {status: "success", fresh: true},
  ];
  const timers = [];
  let statusCalls = 0;
  const poller = createFingerprintPoller({
    ensureUrl: "/ensure",
    statusUrl: "/status",
    csrfToken: "csrf",
    fetchImpl: async (_url, options) => {
      if (options.method === "POST") return {ok: true, status: 202};
      const payload = statuses[statusCalls++];
      return {ok: true, status: 200, json: async () => payload};
    },
    now: () => 0,
    isVisible: () => true,
    setTimer: (fn, delay) => {
      const timer = {fn, delay};
      timers.push(timer);
      return timer;
    },
    clearTimer: () => {},
    render: () => {},
  });

  await poller.start();
  assert.equal(timers.length, 1, "stale success must wait for the new background claim");
  timers.shift().fn();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(timers.length, 1);
  timers.shift().fn();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(statusCalls, 3);
  assert.equal(timers.length, 0, "fresh success is terminal");
})();
"""
    )
