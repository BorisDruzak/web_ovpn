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
  let timerId = 0;
  const timers = new Map();
  const events = {};
  const document = { hidden: false,
    querySelector: (selector) => selector === "[data-network-hosts]" ? root : null,
    createElement: () => new Element(), createDocumentFragment: () => new Element(),
    addEventListener: (name, callback) => { events[name] = callback; },
  };
  const window = { location: { search: "?q=printer&page=2" },
    setTimeout: (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; },
    clearTimeout: (id) => timers.delete(id),
    addEventListener: (name, callback) => { events[name] = callback; },
  };
  const tick = async (delay) => {
    for (const [id, timer] of [...timers]) {
      if (timer.delay === delay) { timers.delete(id); timer.callback(); }
    }
    await settle();
  };
  vm.runInNewContext(script, {
    AbortController,
    document,
    fetch,
    window,
  });
  await settle();
  return { interval: () => tick(15000), tick, timers, events, document, window,
    oldRow, pagination, root, rows, snapshotState, warning };
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

async function pendingMetadataDoesNotOverlap() {
  const requests = [];
  const env = await start(() => new Promise((resolve) => requests.push(resolve)));
  env.interval();
  await settle();
  assert.equal(requests.length, 1, "a pending metadata request must not overlap another poll");

  requests[0](response({ status: "ok", data: { snapshot: snapshot(1) } }));
  await settle();

  assert.equal(env.warning.hidden, true);
  assert.equal(env.snapshotState.dataset.state, "ready");
}

const emptyPage = (id) => response({status:"ok", data:{hosts:[],
  snapshot:snapshot(id), pagination:{page:1,limit:100,total:0,pages:0}}});

async function hiddenNavigationDiscardsLateResponse() {
  const requests = [];
  const env = await start((url, options) => new Promise((resolve) => requests.push({url, options, resolve})));
  env.document.hidden = true;
  env.events.visibilitychange();
  assert.equal(requests[0].options.signal.aborted, true);
  await env.tick(15000);
  assert.equal(requests.length, 1);
  env.document.hidden = false;
  env.window.location.search = "?q=new&page=1";
  env.events.visibilitychange();
  requests[1].resolve(response({status:"ok",data:{snapshot:snapshot(3)}}));
  await settle();
  assert.equal(requests[2].url, "/api/v1/network/hosts?q=new&page=1");
  requests[2].resolve(emptyPage(3));
  await settle();
  requests[0].resolve(response({status:"ok",data:{snapshot:snapshot(2)}}));
  await settle();
  assert.equal(env.root.dataset.snapshotId, "3");
  assert.equal(env.warning.hidden, true);
}

async function failedRowsRetryEvenWhenMetadataReturnsCurrentSnapshot() {
  let step = 0;
  const env = await start(() => {
    step++;
    if (step === 1) return Promise.resolve(response({status:"ok",data:{snapshot:snapshot(2)}}));
    if (step === 2) return Promise.reject(new Error("rows failed"));
    if (step === 3) return Promise.resolve(response({status:"ok",data:{snapshot:snapshot(1)}}));
    return Promise.resolve(emptyPage(1));
  });
  assert.equal(env.warning.hidden, false);
  await env.tick(30000);
  assert.equal(step, 4, "metadata-only success must retry the failed rows");
  assert.equal(env.warning.hidden, true);
  assert.match(env.pagination.textContent, /^0 устройств/);
}

async function timeoutAndSessionExpiryKeepLastRows() {
  const requests = [];
  const env = await start((url, options) => new Promise((resolve) => requests.push({resolve, options})));
  await env.tick(20000);
  assert.equal(requests[0].options.signal.aborted, true);
  assert.equal(env.warning.hidden, false);
  assert.deepEqual(env.rows.children, [env.oldRow]);
  await env.tick(30000);
  requests[1].resolve({ok:false,status:401});
  await settle();
  assert.match(env.warning.textContent, /Войдите снова/);
  await env.tick(60000);
  requests[2].resolve(response({status:"ok",data:{snapshot:snapshot(1)}}));
  await settle();
  assert.equal(env.warning.hidden, true);
  requests[0].resolve(response({status:"ok",data:{snapshot:snapshot(9)}}));
  await settle();
  assert.equal(env.root.dataset.snapshotId, "1");
}

async function bfcacheRestorationResumesPolling() {
  const requests = [];
  const env = await start(() => new Promise((resolve) => requests.push(resolve)));
  env.events.pagehide();
  assert.equal(typeof env.events.pageshow, "function", "Back/Forward cache must resume polling");
  env.events.pageshow({persisted:true});
  assert.equal(requests.length, 2);
  requests[1](response({status:"ok",data:{snapshot:snapshot(1)}}));
  await settle();
}

async function unchangedSnapshotShowsFreshnessTransitionsWithoutFetchingRows() {
  let stale = false;
  const env = await start((url) => {
    assert.ok(url.endsWith("/meta"), "unchanged snapshot must only fetch metadata");
    return Promise.resolve(response({ status: "ok", data: { snapshot: { ...snapshot(1), stale } } }));
  });
  assert.equal(env.snapshotState.dataset.state, "ready");
  stale = true;
  env.interval();
  await settle();
  assert.equal(env.snapshotState.dataset.state, "stale");
  assert.match(env.snapshotState.textContent, /устарел/);
  stale = false;
  env.interval();
  await settle();
  assert.equal(env.snapshotState.dataset.state, "ready");
  assert.deepEqual(env.rows.children, [env.oldRow]);
}

async function projectionChangesRefreshRowsWithoutNewSnapshot() {
  let projection = "first";
  const host = {ip: "192.0.2.11", mac: null, hostname: null, manual_name: null,
    display_name: "Synthetic", category: "unknown", device_key: "ip:192.0.2.11", device_type: "pc",
    status: "online", site: "", last_seen_at: "", last_source: "", device_confidence: 0,
    device_evidence: [], tags: [], manual_tags: [], sources: [], availability: null, vpn_client: null,
    endpoint_agent: {state: "confirmed", freshness: "stale"},
    inventory: {state: "linked", asset: {id: "11111111-1111-1111-1111-111111111111", name: "Synthetic physical card",
      inventory_number: null, location: null, assigned_person_name: null}}};
  let rowsRequests = 0;
  const env = await start((url) => Promise.resolve(response({status: "ok", data: url.endsWith('/meta')
    ? {snapshot: snapshot(1), projection_version: projection}
    : (rowsRequests++, {snapshot: snapshot(1), projection_version: projection, hosts: [host],
      pagination: {page: 1, limit: 100, total: 1, pages: 1}})})));
  assert.equal(rowsRequests, 1);
  const flatten = (node) => node.textContent + node.children.map(flatten).join('');
  assert.match(flatten(env.rows), /Подтверждённая связь/);
  assert.match(flatten(env.rows), /Данные устарели/);
  assert.match(flatten(env.rows), /Synthetic physical card/);
  assert.equal(env.rows.children[0].children[0].children.length, 15);
  projection = "second";
  host.endpoint_agent = {state: "disabled", freshness: "unknown"};
  await env.interval();
  assert.equal(rowsRequests, 2);
  assert.match(flatten(env.rows), /Интеграция отключена/);
  assert.equal(env.root.dataset.snapshotId, "1");
}

(async () => {
  await malformedRowsPreserveCurrentDom();
  await pendingMetadataDoesNotOverlap();
  await unchangedSnapshotShowsFreshnessTransitionsWithoutFetchingRows();
  await hiddenNavigationDiscardsLateResponse();
  await failedRowsRetryEvenWhenMetadataReturnsCurrentSnapshot();
  await timeoutAndSessionExpiryKeepLastRows();
  await bfcacheRestorationResumesPolling();
  await projectionChangesRefreshRowsWithoutNewSnapshot();
  console.log("PASS: no overlap, late response, hidden/navigation, row retry, timeout, session recovery, malformed rows, freshness");
})();
