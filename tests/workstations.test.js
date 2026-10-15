'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {EventCursor, Poller, jobMessage, verificationLabel, canApply, findingDetails} = require('../app/static/workstations.js');

test('malformed DNS evidence names the source zone without claiming device identity', () => {
  const text=findingDetails({code:'dns_record_malformed',evidence:{name:'foreign.other.invalid.',zone:'example.invalid'}});
  assert.match(text,/foreign\.other\.invalid\./);assert.match(text,/example\.invalid/);assert.match(text,/исключена/);
  assert.equal(findingDetails({code:'network_only',evidence:{name:'unrelated'}}),'');
});

test('cursor drains pages, deduplicates reconnect and reports gaps without inventing evidence', () => {
  const cursor = new EventCursor();
  assert.equal(cursor.consume({events: [{sequence: 1}, {sequence: 2}], next_sequence: 2, total: 3}).events.length, 2);
  assert.equal(cursor.consume({events: [{sequence: 2}, {sequence: 3}], next_sequence: 3, total: 3}).events.length, 1);
  assert.equal(cursor.after, 3);
  assert.equal(cursor.consume({events: [{sequence: 5}], next_sequence: 5, total: 5}).gap, true);
  assert.equal(cursor.after, 3);
  assert.equal(new EventCursor({after: 3}).consume({events: [], next_sequence: 3, total: 3}).events.length, 0);
  assert.equal(new EventCursor().consume({events: [], next_sequence: 0, total: 3}).gap, true);
});

test('visible polling uses two seconds, hidden tabs do no reads and failures back off', async () => {
  let visible = true, calls = 0, fail = false;
  const queue = [];
  const poller = new Poller(async () => {calls++; if(fail) throw Error('synthetic');}, {
    visible: () => visible, schedule: (fn, delay) => {queue.push({fn, delay}); return queue.length;}, cancel: () => {}
  });
  await poller.start();
  assert.equal(calls, 1); assert.equal(queue[0].delay, 2000);
  visible = false; await queue.shift().fn(); assert.equal(calls, 1);
  visible = true; fail = true; await queue.shift().fn(); assert.equal(calls, 2); assert.equal(queue[0].delay, 4000);
  fail = false; await queue.shift().fn(); assert.equal(queue[0].delay, 2000);
  poller.stop();
});

test('waking a tab cannot overlap an in-flight poll', async () => {
  let calls=0,release;
  const gate=new Promise(resolve=>{release=resolve;});
  const poller=new Poller(async()=>{calls++;await gate;},{visible:()=>true,schedule:()=>0,cancel:()=>{}});
  const pending=poller.start();
  await poller.wake();await poller.wake();assert.equal(calls,1);
  release();await pending;poller.stop();
});

test('waiting reboot, first login, failed and unknown states show a concrete human action', () => {
  assert.match(jobMessage({state: 'waiting_reboot'}), /перезагруз/i);
  assert.match(jobMessage({state: 'waiting_first_login'}), /вход/i);
  assert.match(jobMessage({state: 'unknown_requires_review'}), /UNKNOWN/);
  assert.match(jobMessage({state: 'failed'}), /ошиб/i);
  assert.match(jobMessage({state: 'queued'}), /очеред/i);
});

test('technical verification remains distinct from functional acceptance', () => {
  assert.notEqual(verificationLabel('technical_verified'), verificationLabel('functional_verification_required'));
  assert.match(verificationLabel('functional_verification_required'), /пользовател/i);
  assert.match(verificationLabel(null), /нет|не провер/i);
  assert.match(verificationLabel('compliant'), /Технически проверено/);
});

test('only a current exact plan with explicit checkbox can be applied once', () => {
  const plan = {plan_id: 'setup-' + 'a'.repeat(64), sha256: 'a'.repeat(64), expires_at: '2099-01-01T00:00:00Z'};
  assert.equal(canApply(plan, {confirmed: true, allowed: true, submitted: false}), true);
  assert.equal(canApply(plan, {confirmed: false, allowed: true}), false);
  assert.equal(canApply({...plan, expires_at: '2000-01-01T00:00:00Z'}, {confirmed: true, allowed: true}), false);
  assert.equal(canApply({...plan, sha256: 'b'.repeat(64)}, {confirmed: true, allowed: true}), false);
  assert.equal(canApply(plan, {confirmed: true, allowed: true, submitted: true}), false);
});

test('component blockers and incomplete action evidence disable submission', () => {
  const plan={plan_id:'setup-component-'+'a'.repeat(64),sha256:'a'.repeat(64),expires_at:'2099-01-01T00:00:00Z'};
  const consent={confirmed:true,allowed:true};
  for(const action of ['blocked','unknown',undefined]) assert.equal(canApply({...plan,action},consent),false);
  assert.equal(canApply({...plan,action:'install',preflight:{ready:false}},consent),false);
  for(const action of ['noop','install','repair']) assert.equal(canApply({...plan,action,preflight:{ready:true}},consent),true);
});
