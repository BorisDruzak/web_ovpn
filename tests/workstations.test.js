'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {EventCursor, Poller, jobMessage, verificationLabel, canApply, findingDetails, readReadyMachines} = require('../app/static/workstations.js');

test('ready machine selection reads beyond unrelated device pages', async () => {
  const rows=Array.from({length:200},(_,i)=>({device_key:'network:'+i}));
  rows.push({machine_uuid:'ready-machine',registration_state:'ready',hostname:'Ready PC'},
    {machine_uuid:'pending-machine',registration_state:'pending'});
  const offsets=[];
  const found=await readReadyMachines(async offset=>{
    offsets.push(offset);return {devices:rows.slice(offset,offset+100),total:rows.length,
      next_offset:Math.min(offset+100,rows.length),source_revision:'stable'};
  });
  assert.deepEqual(offsets,[0,100,200]);assert.deepEqual(found,[rows[200]]);
});

test('ready machine selection supports the complete registry-only fallback', async () => {
  const row={machine_uuid:'registered',registration_state:'ready'};
  assert.deepEqual(await readReadyMachines(async()=>({devices:[row],total:1,next_offset:1,generation:'registry'})),[row]);
});

for(const change of ['generation','total','offset','empty','limit','duplicate']){
  test('ready machine selection rejects incomplete or changed pages: '+change, async () => {
    await assert.rejects(readReadyMachines(async offset=>{
      const devices=Array.from({length:100},(_,i)=>({device_key:'network:'+(offset+i)}));
      if(change==='duplicate')devices[0]={machine_uuid:'repeated',registration_state:'ready'};
      return {devices:offset&&change==='empty'?[]:devices,total:change==='limit'?10001:offset&&change==='total'?201:200,
        next_offset:offset&&change==='offset'?offset:offset+100,source_revision:offset&&change==='generation'?'changed':'stable'};
    }),/список|источник/i);
  });
}

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

test('an unclaimed admission blocker explains why the queued PC has not started', () => {
  const message=jobMessage({state:'queued',queue_position:1,error_code:'setup_queue_admission_unverified'});
  assert.match(message,/допуск/i);
  assert.match(message,/не начат/i);
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
