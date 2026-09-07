const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "..", "app", "static", "network-hosts-refresh.js"), "utf8");

class Element {
  constructor() {
    this.children = [];
    this.dataset = {};
    this.textContent = "";
    this.hidden = false;
    this.className = "";
    this.classList = { add: (name) => { this.className = `${this.className} ${name}`.trim(); } };
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes) {
    this.children = nodes;
  }
}

const response = (data) => ({ ok: true, json: async () => data });
const snapshot = (snapshot_id) => ({ snapshot_id, generated_at: "2026-09-07T10:00:00Z", total_hosts: 1, duration_ms: 1 });
const settle = async () => {
  for (let turn = 0; turn < 12; turn += 1) await Promise.resolve();
};

async function start(fetch) {
  const root = new Element();
  root.dataset.snapshotId = "1";
  const rows = new Element();
  const oldRow = new Element();
  rows.append(oldRow);
  const snapshotState = new Element();
  snapshotState.textContent = "snapshot before refresh";
  const pagination = new Element();
  pagination.textContent = "pagination before refresh";
  const warning = new Element();
  warning.hidden = true;
  const elements = {
    "[data-hosts-rows]": rows,
    "[data-host-snapshot-state]": snapshotState,
    "[data-host-pagination]": pagination,
    "[data-host-refresh-warning]": warning,
  };
  root.querySelector = (selector) => elements[selector] || null;
  let interval;
  vm.runInNewContext(script, {
    AbortController,
    document: { querySelector: (selector) => selector === "[data-network-hosts]" ? root : null, createElement: () => new Element() },
    fetch,
    window: { location: { search: "?q=printer&page=2" }, setInterval: (callback) => { interval = callback; } },
  });
  await settle();
  return { interval, oldRow, pagination, root, rows, snapshotState, warning };
}

async function malformedRowsPreserveCurrentDom() {
  const env = await start((url) => url.endsWith("/meta")
    ? Promise.resolve(response({ status: "ok", data: { snapshot: snapshot(2) } }))
    : Promise.resolve(response({ status: "ok", data: { hosts: [null], pagination: { page: 2, limit: 100, total: 1, pages: 1 }, snapshot: snapshot(2) } })));

  assert.deepEqual(env.rows.children, [env.oldRow]);
  assert.equal(env.snapshotState.textContent, "snapshot before refresh");
  assert.equal(env.pagination.textContent, "pagination before refresh");
  assert.equal(env.warning.hidden, false);
}

async function obsoleteMetadataDoesNotWarnAfterNewerSuccess() {
  const requests = [];
  const env = await start(() => new Promise((resolve) => requests.push(resolve)));
  env.interval();
  await settle();
  assert.equal(requests.length, 2);

  requests[1](response({ status: "ok", data: { snapshot: snapshot(1) } }));
  await settle();
  requests[0](response({ status: "ok", data: { snapshot: snapshot(2) } }));
  await settle();

  assert.equal(env.warning.hidden, true);
  assert.equal(env.snapshotState.textContent, "snapshot before refresh");
}

(async () => {
  await malformedRowsPreserveCurrentDom();
  await obsoleteMetadataDoesNotWarnAfterNewerSuccess();
})();
