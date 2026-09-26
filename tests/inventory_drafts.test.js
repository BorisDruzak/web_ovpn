const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const script = fs.readFileSync('app/static/inventory-drafts.js', 'utf8');
const settle = async () => { for (let i=0; i<12; i++) await Promise.resolve(); };

function start() {
  let now = 10000, next = 0;
  const timers = new Map(), events = {}, calls = [];
  const feedback = {textContent:''};
  const values = {draft_id:'synthetic-id', csrf_token:'synthetic-csrf', custom_name:'Original', description:'', expected_revision:'2'};
  const form = {dataset:{draftRevision:'1',restoredDraft:'false'},
    elements:{namedItem:name => ({value:values[name]})},
    querySelector:()=>feedback,
    addEventListener:(name, callback)=>{events['form:'+name]=callback;}};
  const document = {hidden:false, querySelector:selector=>selector === '[data-inventory-asset-form]' ? form : null,
    addEventListener:(name,callback)=>{events[name]=callback;}};
  const window = {addEventListener:(name,callback)=>{events[name]=callback;},confirm:()=>true};
  class FormData { constructor() {this.entries=Object.entries(values);} [Symbol.iterator]() {return this.entries[Symbol.iterator]();} }
  const fetch = (url, options) => new Promise((resolve,reject)=>{
    calls.push({url, options, resolve, reject, at:now});
    options.signal.addEventListener('abort',()=>reject(new Error('aborted')));
  });
  const clock = {now:()=>now};
  vm.runInNewContext(script, {document,window,FormData,Date:clock,fetch,AbortController,encodeURIComponent,
    setTimeout:(callback,delay)=>{timers.set(++next,{callback,at:now+delay});return next;},
    clearTimeout:id=>timers.delete(id)});
  const tick = async amount => {
    now += amount;
    for (const [id,timer] of [...timers]) if(timer.at<=now) {timers.delete(id);timer.callback();}
    await settle();
  };
  const change = value => {values.description=value;events['form:input']();};
  const reply = (index,status,revision) => calls[index].resolve({ok:status===200,status,json:async()=>({draft_revision:revision})});
  return {values,events,calls,feedback,tick,change,reply};
}

(async()=>{
  const state = start();
  state.change('One');
  await state.tick(1500);
  assert.equal(state.calls.length,1);
  state.change('Two');
  await state.tick(6000);
  assert.equal(state.calls.length,1,'pending autosave must not overlap');
  state.reply(0,200,2);
  await settle();
  await state.tick(1500);
  assert.equal(state.calls.length,2);
  const second = JSON.parse(state.calls[1].options.body);
  assert.equal(second.fields.description,'Two');
  assert.equal(second.draft_revision,2);
  assert.ok(state.calls[1].at-state.calls[0].at>=5000);
  assert.equal(second.fields.csrf_token,undefined);
  assert.equal(second.fields.draft_id,undefined);
  state.reply(1,409);
  await settle();
  state.change('Kept after conflict');
  await state.tick(15000);
  assert.equal(state.calls.length,2,'conflict must not blind-retry an obsolete draft');
  assert.equal(state.values.description,'Kept after conflict');
  assert.match(state.feedback.textContent,/приостановлено/);
  const timeout = start();
  timeout.change('Preserved timeout input');
  await timeout.tick(1500);
  await timeout.tick(10000);
  assert.equal(timeout.calls[0].options.signal.aborted,true);
  await timeout.tick(15000);
  assert.equal(timeout.calls.length,1,'unknown save outcome must not be retried blindly');
  let warned = false;
  timeout.events.beforeunload({preventDefault:()=>{warned=true;}});
  assert.equal(warned,true);
  timeout.events['form:submit']({defaultPrevented:false});
  warned = false;
  timeout.events.beforeunload({preventDefault:()=>{warned=true;}});
  assert.equal(warned,false,'successful form submission should not trigger leave warning');
  process.stdout.write('Inventory draft debounce, serialization, CAS, timeout and leave warning: PASS\n');
})().catch(error=>{console.error(error);process.exitCode=1;});
