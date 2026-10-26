// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import assert from 'node:assert/strict';
import test from 'node:test';
import {createDVBStreamsController} from '../../web/dvb-streams.js';

// Only DOM, clock and HTTP ports are doubles; all controller logic runs unchanged.
class Element {
  [Symbol.for('nodejs.util.inspect.custom')]() {return `<${this.tagName} ${this.id || this.dataset.streamId || ''}>`;}
  constructor(tag, doc) {
    this.tagName = tag; this.doc = doc; this.children = []; this.dataset = {};
    this.attributes = new Map(); this.handlers = new Map(); this.value = ''; this._text = '';
    this.className = ''; this.hidden = false; this.disabled = false; this.checked = false;
    this.classList = {toggle:() => {}};
  }
  get textContent() {return this._text + this.children.map(child => child.textContent).join('');}
  set textContent(value) {this._text = String(value); this.replaceChildren();}
  get firstChild() {return this.children[0];}
  get lastChild() {return this.children.at(-1);}
  get options() {return this.children;}
  get selectedOptions() {return this.children.filter(child => child.value === this.value);}
  get isConnected() {return this.parentNode ? this.parentNode.isConnected : this === this.doc;}
  append(...items) {for (const item of items) this.insertBefore(item,null);}
  insertBefore(item, reference) {
    item.remove(); const index = reference ? this.children.indexOf(reference) : this.children.length;
    this.children.splice(index,0,item); item.parentNode = this; return item;
  }
  replaceChildren(...items) {for (const child of [...this.children]) child.remove(); this.append(...items);}
  remove() {
    if (this.parentNode) this.parentNode.children.splice(this.parentNode.children.indexOf(this),1);
    this.parentNode = null;
  }
  after(item) {this.parentNode.insertBefore(item,this.parentNode.children[this.parentNode.children.indexOf(this)+1] || null);}
  contains(item) {return this === item || this.children.some(child => child.contains(item));}
  querySelector(selector) {
    const match = el => selector.startsWith('.') ? el.className.split(' ').includes(selector.slice(1)) : el.tagName === selector;
    for (const child of this.children) {if (match(child)) return child; const found = child.querySelector(selector); if (found) return found;}
    return null;
  }
  closest(selector) {
    for (let el = this; el; el = el.parentNode) {
      if (selector.startsWith('.') ? el.className.split(' ').includes(selector.slice(1)) : el.tagName === selector) return el;
    }
    return null;
  }
  setAttribute(key,value) {this.attributes.set(key,String(value));}
  removeAttribute(key) {this.attributes.delete(key);}
  getAttribute(key) {return this.attributes.get(key) ?? null;}
  addEventListener(key,handler) {if (!this.handlers.has(key)) this.handlers.set(key,[]); this.handlers.get(key).push(handler);}
  emit(key) {for (const fn of this.handlers.get(key) || []) fn({preventDefault() {}});}
  focus() {this.doc.activeElement = this;}
  setCustomValidity() {}
  reset() {}
  showModal() {this.open = true;}
  close() {this.open = false;}
}
const settle = async () => {for (let i = 0; i < 20; i++) await Promise.resolve();};
const runtime = (state = 'waiting_keys', reason = state) => ({state:'locked',signal:{signal_percent:77,snr_percent:66},placement:{actual_card_id:'card-a',actual_address:'0.0'},bitrate_kbps:100,descrambling:{state,reason,metrics:{sample_stale:false,sample_age_ms:0}}});
const stream = (id = 's0', rt = runtime()) => ({id,name:`Stream ${id}`,group_id:'g',protocol:'udp',output_url:'udp://239.1.1.1:1234',dvb:{delivery_system:'dvbs2',service_id:1,frequency_khz:11000000,adapter:{mode:'auto'}},runtime:rt});
const event = (revision, rt, id = 's0') => ({kind:'dvb.stream.changed',resource_id:id,revision,payload:{mode:'runtime',runtime:rt}});

async function fixture(t, {hash = '#dvb-streams', items = [stream(),stream('s1')], count = items.length, groups = [{id:'g',name:'News'}], canManage, canControl, openEditor, openScan, confirmAction = () => true} = {}) {
  t.mock.timers.enable({apis:['setTimeout','Date'],now:10000});
  const doc = new Element('document'); doc.doc = doc; doc.createElement = tag => new Element(tag,doc);
  const ids = new Map();
  const id = key => {
    if (!ids.has(key)) {
      const el = new Element('div',doc); el.id = key;
      const label = new Element('label',doc); doc.append(label); label.append(el); ids.set(key,el);
    }
    return ids.get(key);
  };
  doc.querySelector = selector => id(selector.slice(1));
  id('dvbGroupNav').append(Object.assign(doc.createElement('div'),{className:'dvb-group-entries'}));
  id('dvbBulkResults').append(doc.createElement('ul'));
  for (const [value, label] of [['start','Start'],['stop','Stop'],['restart','Restart'],['move_group','Move group'],['assign_adapter','Assign adapter'],['delete','Delete']]) {
    id('dvbBulkAction').append(Object.assign(doc.createElement('option'),{value,textContent:label}));
  }
  for (const [className, keys] of [['dvb-group-actions',['addDVBGroupBtn','renameDVBGroupBtn','deleteDVBGroupBtn','moveDVBGroupUpBtn','moveDVBGroupDownBtn']],['dvb-primary-actions',['addDVBStreamBtn','openDVBScanBtn','dvbSelectPage']]]) {
    const container = Object.assign(doc.createElement('div'),{className}); doc.append(container);
    for (const key of keys) container.append(id(key).parentNode);
  }
  id('dvbBulkAction').value = 'start'; id('dvbBulkAdapterMode').value = 'auto';
  const storage = new Map(), win = {location:{hash},sessionStorage:{getItem:key => storage.get(key),setItem:(key,value) => storage.set(key,value)}};
  win.history = {replaceState:(_state,_title,hash) => {win.location.hash = hash;}};
  const calls = [], f = {items,groups,hold:null};
  const requestJSON = async (path, options = {}) => {
    calls.push({path,options});
    if (options.method && options.method !== 'GET') {
      assert.ok(f.write,`unexpected write: ${options.method} ${path}`);
      return f.write(path,options);
    }
    if (path === '/api/v1/dvb-groups') return {groups:f.groups,counts:{g:count,'':0}};
    const url = new URL(path,'https://fixture.test');
    assert.equal(url.pathname,'/api/v1/dvb-streams','no individual status GETs');
    const p = url.searchParams, view = f.items.filter(item => (!p.get('descrambling_state') || item.runtime?.descrambling?.state === p.get('descrambling_state'))
      && (!p.get('descrambling_reason') || item.runtime?.descrambling?.reason === p.get('descrambling_reason')));
    const result = structuredClone({items:view,total:count,page:Number(p.get('page')),limit:Number(p.get('limit')),facets:{}});
    if (f.hold) await f.hold.promise;
    return result;
  };
  let loads = 0;
  const controller = createDVBStreamsController({requestJSON,root:doc,window:win,confirmAction,canManage,canControl,openEditor,openScan,onPageLoad:() => loads++});
  t.after(() => controller.deactivate());
  assert.equal(await controller.activate(),true);
  const body = id('dvbStreamTableBody');
  const row = (key = 's0') => body.children.find(child => child.dataset.streamId === key);
  return Object.assign(f,{controller,id,doc,win,storage,calls,row,body,loads:() => loads,
    async tick(ms) {t.mock.timers.tick(ms);await settle();},
    async change(key,value) {id(key).value = value;id(key).emit('change');await settle();},
  });
}

test('StageC controller restores canonical filters and persists changes with page reset', async t => {
  const f = await fixture(t,{hash:'#dvb-streams?page=2&descrambling_state=waiting_keys&descrambling_reason=waiting_keys&group=g',count:1000});
  assert.equal(f.id('dvbStreamsDescramblingState').value,'waiting_keys');
  assert.equal(f.id('dvbStreamsDescramblingReason').value,'waiting_keys');
  await f.change('dvbStreamsDescramblingReason','key_expired');
  const p = new URL(f.calls.at(-1).path,'https://fixture.test').searchParams;
  assert.equal(p.get('descrambling_reason'),'key_expired'); assert.equal(p.get('descrambling_state'),'waiting_keys');
  assert.equal(p.get('page'),'1');assert.equal(p.get('group'),'g');
  assert.match(f.win.location.hash,/descrambling_reason=key_expired/);
  assert.match([...f.storage.values()][0],/"descrambling_reason":"key_expired"/);
});

test('StageC compact cached states remain independent of RF and never claim decoded success', async t => {
  const states = ['waiting_psi','waiting_route','waiting_keys','key_expired','partial_clear','payload_processed','unsupported','capacity','stopped'];
  const items = states.map((state,i) => stream(`s${i}`,runtime(state,state === 'unsupported' ? 'backend_unavailable' : state)));
  items.push(stream('missing',{state:'locked',signal:null,placement:null}));
  items[0].runtime.descrambling.metrics = {sample_stale:true,sample_age_ms:42};
  const f = await fixture(t,{items});
  for (const [i,state] of states.entries()) {
    const row = f.row(`s${i}`), compact = row.querySelector('.dvb-stream-descrambling');
    assert.ok(compact,'independent compact status node');
    assert.match(compact.textContent,new RegExp(state));
    assert.match(row.textContent,/udp \/ locked/);
    assert.doesNotMatch(compact.textContent,/decoded success|media succeeded|success/i);
  }
  assert.match(f.row('s0').querySelector('.dvb-stream-descrambling').textContent,/stale/i);
  assert.match(f.row('s5').querySelector('.dvb-stream-descrambling').textContent,/not.*decoded/i);
  assert.match(f.row('s6').querySelector('.dvb-stream-descrambling').textContent,/backend_unavailable/);
  assert.match(f.row('missing').querySelector('.dvb-stream-descrambling').textContent,/unavailable/i);
  assert.equal(f.calls.length,2);
});

test('StageC runtime bursts use one shared 1Hz timer, keep latest model, keyed focus selection and disclosures', async t => {
  const f = await fixture(t,{hash:'#dvb-streams?limit=200',items:Array.from({length:200},(_,i) => stream(`s${i}`)),count:1000});
  const row = f.row(), other = f.row('s199'), checkbox = row.querySelector('input');
  checkbox.checked = true; checkbox.emit('change'); checkbox.focus();
  const output = row.querySelector('details'); output.open = true;
  const before = row.textContent, otherBefore = other.textContent;
  const timers = t.mock.method(globalThis,'setTimeout');
  for (let i = 1; i <= 80; i++) {
    const rt = runtime('partial_clear');rt.bitrate_kbps = i;
    f.controller.applyEvent(event(i,rt,i % 2 ? 's0' : 's1'));
  }
  assert.equal(row.textContent,before,'runtime DOM must wait for shared cadence');
  assert.equal(timers.mock.callCount(),1,'not one timer per row/event');
  row.querySelector('button').emit('click');
  const raw = f.body.querySelector('pre');
  assert.equal(JSON.parse(raw.textContent).runtime.bitrate_kbps,79,'model is current before paint');
  await f.tick(999); assert.equal(row.textContent,before);
  await f.tick(1); assert.match(row.textContent,/79 kbps/);
  assert.equal(f.row(),row); assert.equal(f.row('s199'),other); assert.equal(other.textContent,otherBefore);
  assert.equal(checkbox.checked,true);assert.equal(f.doc.activeElement,checkbox);assert.equal(output.open,true);
  f.controller.applyEvent(event(79,runtime('capacity')));
  await f.tick(1000);assert.match(row.textContent,/partial_clear/,'older revision rejected');
  assert.equal(f.loads(),1);assert.equal(f.calls.length,2);
});

for (const filter of ['descrambling_state','descrambling_reason']) test(`StageC ${filter} invalidates on visible and off-page transitions, not metric-only changes`, async t => {
  const f = await fixture(t,{hash:`#dvb-streams?${filter}=waiting_keys`});
  f.controller.applyEvent(event(1,{...runtime(),bitrate_kbps:999}));
  await f.tick(1100);assert.equal(f.loads(),1);
  f.items[0].runtime = runtime('key_expired');
  f.controller.applyEvent(event(2,runtime('key_expired')));
  await f.tick(1100);assert.equal(f.loads(),2);assert.equal(!!f.row(),false);
  f.controller.applyEvent(event(3,runtime('waiting_keys'),'off-page'));
  await f.tick(1100);assert.equal(f.loads(),3);
});

test('StageC buffered runtime filters obsolete HTTP rows and cancellation fences late reads and paints', async t => {
  const f = await fixture(t,{hash:'#dvb-streams?descrambling_state=waiting_keys'});
  f.hold = Promise.withResolvers();const hold = f.hold;
  const read = f.controller.resync();await settle();
  f.controller.applyEvent(event(10,runtime('key_expired')));
  hold.resolve();
  assert.equal(await read,true);assert.equal(!!f.row(),false,'late snapshot cannot restore nonmatching row');
  f.hold = null; await f.controller.resync();
  const row = f.row(), before = row.textContent;
  f.controller.applyEvent(event(11,runtime('capacity')));
  f.hold = Promise.withResolvers();const late = f.hold;
  const staleRead = f.controller.resync();await settle();
  f.controller.deactivate();const calls = f.calls.length;
  late.resolve();assert.equal(await staleRead,false);
  await f.tick(2000);assert.equal(row.textContent,before);assert.equal(f.calls.length,calls);
});

test('StageC saved policy notice is visible on list after modal closes and confirms configuration only', async t => {
  const f = await fixture(t);
  const saved = {...stream(),dvb_descrambling:{enabled:true,algorithm:'dvb-csa'}};
  assert.equal(await f.controller.saved(saved),true);
  const notice = f.id('dvbGroupNotice');
  assert.equal(notice.hidden,false);
  assert.match(notice.textContent,/configuration saved/i);
  assert.match(notice.textContent,/not.*runtime.*decoded/i);
  assert.doesNotMatch(notice.textContent,/descrambling succeeded|media success/i);
});

test('StageC replacement runtime and group/readback snapshots cannot bypass the shared cadence', async t => {
  const f = await fixture(t,{hash:'#dvb-streams?descrambling_state=waiting_keys'});
  const row = f.row(), original = row.textContent;
  f.items[0].runtime.bitrate_kbps = 201;
  f.controller.applyEvent({kind:'dvb.stream.changed',resource_id:'s0',revision:1,payload:{mode:'replace',resource:structuredClone(f.items[0])}});
  assert.equal(row.textContent,original,'replacement runtime must not paint immediately');
  await f.tick(100);
  assert.equal(row.textContent,original,'group snapshot must not paint pending runtime');
  assert.equal(f.loads(),1,'metric-only replacement must not invalidate descrambling filter');
  await f.tick(900); assert.match(row.textContent,/201 kbps/);
  f.items[0].runtime.bitrate_kbps = 202;
  assert.equal(await f.controller.resync(),true);
  assert.match(row.textContent,/201 kbps/,'HTTP readback is also coalesced for retained rows');
  await f.tick(999);assert.match(row.textContent,/201 kbps/);
  await f.tick(1);assert.match(row.textContent,/202 kbps/);
  f.controller.applyEvent(event(2,{...runtime('partial_clear'),bitrate_kbps:203}));
  f.items[0].runtime = {...runtime('partial_clear'),bitrate_kbps:203};
  await f.tick(1000);assert.equal(!!f.row(),false,'replacement/runtime still invalidate membership');
});

for (const filter of ['descrambling_state','descrambling_reason']) test(`StageC ${filter} ignores changes in the other dimension`, async t => {
  const f = await fixture(t,{hash:`#dvb-streams?${filter}=waiting_keys`});
  const rt = filter === 'descrambling_state' ? runtime('waiting_keys','profile_unavailable') : runtime('partial_clear','waiting_keys');
  f.controller.applyEvent(event(1,rt));await f.tick(1000);
  assert.equal(f.loads(),1);assert.equal(f.calls.length,2);
});

test('StageC accepted event survives late HTTP and epoch reset rejects pending old paints', async t => {
  const f = await fixture(t);
  f.hold = Promise.withResolvers();const held = f.hold;
  const read = f.controller.resync();await settle();
  const rt = {...runtime('key_expired'),signal:null,placement:null,bitrate_kbps:0};
  f.controller.applyEvent(event(90,rt));
  held.resolve();assert.equal(await read,true);f.hold = null;
  await f.tick(1000);assert.match(f.row().textContent,/key_expired/);assert.doesNotMatch(f.row().textContent,/77%|card-a/);
  f.controller.applyEvent(event(91,runtime('capacity')));
  assert.equal(await f.controller.synchronize({revision:0}),true);
  f.controller.applyEvent(event(1,{...runtime('partial_clear'),bitrate_kbps:7}));
  await f.tick(1000);
  assert.match(f.row().textContent,/partial_clear/);assert.match(f.row().textContent,/7 kbps/);assert.doesNotMatch(f.row().textContent,/capacity/);
});

const writes = f => f.calls.filter(call => call.options.method && call.options.method !== 'GET');
const selectFirst = f => {const input = f.row().querySelector('input');input.checked = true;input.emit('change');};
const success = options => {
  const {ids} = JSON.parse(options.body);
  return {results:ids.map(id => ({id,ok:true})),succeeded:ids.length,failed:0};
};

for (const [role, manage, control, actions] of [
  ['Administrator',true,false,['start','stop','restart','move_group','assign_adapter','delete']],
  ['Operator',false,true,['start','stop','restart']],
  ['Viewer',false,false,[]],
]) test(`${role}: available stream controls and whole field wrappers match role`, async t => {
  const f = await fixture(t,{canManage:() => manage,canControl:() => control,openEditor:() => {},openScan:() => {}});
  for (const key of ['addDVBStreamBtn','openDVBScanBtn','addDVBGroupBtn','renameDVBGroupBtn','deleteDVBGroupBtn','moveDVBGroupUpBtn','moveDVBGroupDownBtn']) {
    assert.equal(f.id(key).hidden,!manage,key);
    if (!manage) assert.equal(f.id(key).disabled,true,key);
  }
  assert.equal(f.id('addDVBGroupBtn').closest('.dvb-group-actions').hidden,!manage);
  assert.deepEqual(f.id('dvbBulkAction').options.map(option => option.value),actions);
  assert.equal(f.id('dvbBulkBar').hidden,!manage && !control);
  assert.equal(f.id('dvbSelectPage').closest('label').hidden,!manage && !control);
  assert.equal(f.row().querySelector('input').closest('label').hidden,!manage && !control);
  if (!manage) {
    assert.equal(f.row().children[0].children.find(el => el.textContent === 'Edit')?.hidden,true);
    for (const key of ['dvbBulkGroup','dvbBulkAdapterMode','dvbBulkCard']) assert.equal(f.id(key).closest('label').hidden,true,key);
  }
});

for (const role of ['Operator','Viewer']) for (const key of ['addDVBStreamBtn','openDVBScanBtn','addDVBGroupBtn','renameDVBGroupBtn','deleteDVBGroupBtn','moveDVBGroupUpBtn','moveDVBGroupDownBtn']) {
  test(`${role}: forced ${key} handler cannot open or mutate management`, async t => {
    let editors = 0, scans = 0;
    const f = await fixture(t,{hash:'#dvb-streams?group=g',groups:[{id:'a',name:'A'},{id:'g',name:'News'},{id:'z',name:'Z'}],canManage:() => false,canControl:() => role === 'Operator',openEditor:() => editors++,openScan:() => scans++});
    f.write = () => ({});
    f.id(key).disabled = false; f.id(key).emit('click'); await settle();
    assert.equal(editors,0);assert.equal(scans,0);assert.notEqual(f.id('dvbGroupDialog').open,true);
    assert.deepEqual(writes(f),[]);
  });
}

for (const action of ['start','stop','restart']) test(`Operator: bulk ${action} targets only selected existing streams`, async t => {
  const f = await fixture(t,{canManage:() => false,canControl:() => true});
  f.write = (_path, options) => success(options);
  selectFirst(f); await f.change('dvbBulkAction',action);
  assert.equal(f.id('dvbBulkApply').disabled,false);
  f.id('dvbBulkApply').emit('click');await settle();
  assert.equal(writes(f).length,1);
  assert.equal(writes(f)[0].path,'/api/v1/dvb-streams/bulk');
  assert.equal(writes(f)[0].options.method,'POST');
  assert.deepEqual(JSON.parse(writes(f)[0].options.body),{action,ids:['s0']});
  assert.equal(f.id('dvbSelectedCount').textContent,'0');
  assert.equal(f.row().querySelector('input').checked,false);
});

for (const action of ['move_group','assign_adapter','delete']) test(`Operator: injected bulk ${action} is rejected by handler`, async t => {
  let confirmations = 0;
  const f = await fixture(t,{canManage:() => false,canControl:() => true,confirmAction:() => {confirmations++;return true;}});
  f.write = (_path, options) => success(options);
  selectFirst(f);
  f.id('dvbBulkAction').append(Object.assign(f.doc.createElement('option'),{value:action}));
  await f.change('dvbBulkAction',action);
  f.id('dvbBulkApply').disabled = false;f.id('dvbBulkApply').emit('click');await settle();
  assert.deepEqual(writes(f),[]);assert.equal(confirmations,0);
  assert.equal(f.calls.some(call => call.path.startsWith('/api/v1/dvb-cards')),false);
});

test('Viewer: forced row/page selection and submit cannot create a bulk write', async t => {
  const f = await fixture(t,{canManage:() => false,canControl:() => false});
  f.write = (_path, options) => success(options);
  selectFirst(f);
  f.id('dvbSelectPage').disabled = false;f.id('dvbSelectPage').checked = true;f.id('dvbSelectPage').emit('change');
  assert.equal(f.id('dvbSelectedCount').textContent,'0');
  assert.equal(f.row().querySelector('input').checked,false);
  f.id('dvbBulkAction').value = 'start';f.id('dvbBulkApply').disabled = false;
  f.id('dvbBulkApply').emit('click');await settle();assert.deepEqual(writes(f),[]);
});

test('role reactivation rebuilds options and late events never re-enable management or Viewer checks', async t => {
  let manage = true, control = true;
  const f = await fixture(t,{canManage:() => manage,canControl:() => control,openEditor:() => {},openScan:() => {}});
  selectFirst(f);await f.change('dvbBulkAction','delete');
  f.controller.deactivate();manage = false;
  assert.equal(await f.controller.activate(),true);
  assert.deepEqual(f.id('dvbBulkAction').options.map(option => option.value),['start','stop','restart']);
  assert.equal(f.id('dvbBulkAction').value,'start');
  assert.equal(f.id('addDVBStreamBtn').disabled,true);
  f.controller.deactivate();control = false;
  assert.equal(await f.controller.activate(),true);
  f.controller.applyEvent({kind:'dvb.group.changed',resource_id:'g',revision:1,payload:{mode:'invalidate'}});
  await f.tick(1100); f.id('dvbStreamDialog').emit('close'); f.id('dvb-scan-dialog').emit('dvb-scan-statechange');
  assert.equal(f.id('dvbSelectedCount').textContent,'0');
  assert.equal(f.id('dvbSelectPage').disabled,true);assert.equal(f.row().querySelector('input').disabled,true);
  assert.equal(f.id('dvbBulkApply').disabled,true);assert.equal(f.id('addDVBGroupBtn').disabled,true);
  assert.equal(f.id('addDVBStreamBtn').hidden,true);assert.equal(f.id('dvbBulkBar').hidden,true);
  f.controller.deactivate();manage = true;
  assert.equal(await f.controller.activate(),true);
  assert.deepEqual(f.id('dvbBulkAction').options.map(option => option.value),['start','stop','restart','move_group','assign_adapter','delete']);
  assert.equal(f.id('addDVBStreamBtn').hidden,false);assert.equal(f.id('dvbBulkBar').hidden,false);
});

for (const role of ['Operator','Viewer']) test(`${role}: withheld URLs preserve monitor, Details, group filter and search`, async t => {
  const item = stream();delete item.output_url;delete item.input_url;
  const f = await fixture(t,{items:[item],canManage:() => false,canControl:() => role === 'Operator'});
  assert.equal(f.id('dvbStreamsError').hidden,true);assert.match(f.row().textContent,/Stream s0/);
  assert.equal(f.row().querySelector('.dvb-stream-output').hidden,true);
  f.row().querySelector('button').emit('click');
  assert.equal(JSON.parse(f.body.querySelector('pre').textContent).id,'s0');
  f.controller.applyEvent(event(1,{...runtime('partial_clear'),bitrate_kbps:42}));await f.tick(1000);
  assert.match(f.row().textContent,/42 kbps/);
  await f.change('dvbGroupSelect','id:g');
  assert.match(f.win.location.hash,/group=g/);
  f.id('dvbStreamsSearch').value = 'Stream';f.id('dvbStreamsSearch').emit('input');await f.tick(250);
  assert.match(f.win.location.hash,/q=Stream/);assert.deepEqual(writes(f),[]);
});

test('Operator: pending and unknown bulk outcomes retain the existing durable write fence', async t => {
  let control = true;const f = await fixture(t,{canManage:() => false,canControl:() => control});
  const held = Promise.withResolvers();f.write = () => held.promise;
  selectFirst(f);f.id('dvbBulkApply').emit('click');await settle();
  assert.equal(f.id('dvbBulkApply').disabled,true);
  f.id('dvbBulkApply').disabled = false;f.id('dvbBulkApply').emit('click');await settle();
  assert.equal(writes(f).length,1);
  held.reject(new Error('transport outcome unknown'));await settle();
  assert.match(f.id('dvbBulkNotice').textContent,/unknown/i);
  f.controller.deactivate();control = false;assert.equal(await f.controller.activate(),true);
  f.controller.deactivate();control = true;assert.equal(await f.controller.activate(),true);
  f.id('dvbBulkApply').disabled = false;f.id('dvbBulkApply').emit('click');await settle();
  assert.equal(writes(f).length,1);
});

test('Administrator: losing management during bulk confirmation prevents dispatch', async t => {
  let manage = true;
  const held = Promise.withResolvers();
  const f = await fixture(t,{canManage:() => manage,canControl:() => true,confirmAction:() => held.promise});
  f.write = (_path, options) => success(options);selectFirst(f);await f.change('dvbBulkAction','delete');
  f.id('dvbBulkApply').emit('click');await settle();manage = false;held.resolve(true);await settle();
  assert.deepEqual(writes(f),[]);
});

test('Administrator: create, existing Edit and Scan callbacks remain reachable', async t => {
  const edited = [];let scans = 0;
  const f = await fixture(t,{canManage:() => true,canControl:() => false,openEditor:id => edited.push(id),openScan:() => scans++});
  f.id('addDVBStreamBtn').emit('click');await settle();
  f.row().children[0].children.find(el => el.textContent === 'Edit').emit('click');await settle();
  f.id('openDVBScanBtn').emit('click');await settle();
  assert.deepEqual(edited,[null,'s0']);assert.equal(scans,1);
});

for (const [action, extra] of [['move_group',{group_id:'g'}],['assign_adapter',{adapter:{mode:'auto'}}],['delete',{}]]) {
  test(`Administrator: bulk ${action} remains available without canControl`, async t => {
    const f = await fixture(t,{canManage:() => true,canControl:() => false});f.write = (_path, options) => success(options);
    selectFirst(f);await f.change('dvbBulkAction',action);
    if (action === 'move_group') await f.change('dvbBulkGroup','g');
    f.id('dvbBulkApply').emit('click');await settle();
    assert.equal(writes(f).length,1);assert.equal(writes(f)[0].path,'/api/v1/dvb-streams/bulk');
    assert.deepEqual(JSON.parse(writes(f)[0].options.body),{action,ids:['s0'],...extra});
  });
}

for (const [key, path, method, payload] of [
  ['addDVBGroupBtn','/api/v1/dvb-groups','POST',{name:'Fresh'}],
  ['renameDVBGroupBtn','/api/v1/dvb-groups/g','PUT',{name:'Fresh'}],
  ['deleteDVBGroupBtn','/api/v1/dvb-groups/g','DELETE',null],
  ['moveDVBGroupUpBtn','/api/v1/dvb-groups/reorder','POST',{ids:['g','a','z']}],
  ['moveDVBGroupDownBtn','/api/v1/dvb-groups/reorder','POST',{ids:['a','z','g']}],
]) test(`Administrator: ${key} retains the existing group mutation contract`, async t => {
  const f = await fixture(t,{hash:'#dvb-streams?group=g',groups:[{id:'a',name:'A'},{id:'g',name:'News'},{id:'z',name:'Z'}],canManage:() => true,canControl:() => false});
  f.write = () => ({moved_streams:2});f.id(key).emit('click');await settle();
  if (['addDVBGroupBtn','renameDVBGroupBtn'].includes(key)) {
    assert.equal(f.id('dvbGroupDialog').open,true);f.id('dvbGroupName').value = 'Fresh';f.id('dvbGroupForm').emit('submit');await settle();
  }
  assert.equal(writes(f).length,1);assert.equal(writes(f)[0].path,path);assert.equal(writes(f)[0].options.method,method);
  assert.deepEqual(writes(f)[0].options.body ? JSON.parse(writes(f)[0].options.body) : null,payload);
});

test('late group confirmation and already-open group form recheck management', async t => {
  let manage = true;const held = Promise.withResolvers();
  const f = await fixture(t,{hash:'#dvb-streams?group=g',canManage:() => manage,confirmAction:() => held.promise});
  f.write = () => ({});f.id('deleteDVBGroupBtn').emit('click');await settle();
  manage = false;held.resolve(true);await settle();assert.deepEqual(writes(f),[]);
  manage = true;f.id('renameDVBGroupBtn').emit('click');await settle();assert.equal(f.id('dvbGroupDialog').open,true);
  manage = false;f.id('dvbGroupName').value = 'Forbidden';f.id('dvbGroupForm').emit('submit');await settle();
  assert.deepEqual(writes(f),[]);
});

test('late editor completion never re-enables management after a role change', async t => {
  let manage = true;const held = Promise.withResolvers();
  const f = await fixture(t,{canManage:() => manage,canControl:() => false,openEditor:() => held.promise});
  f.id('addDVBStreamBtn').emit('click');await settle();manage = false;held.resolve();await settle();
  assert.equal(f.id('addDVBStreamBtn').disabled,true);assert.equal(f.id('addDVBStreamBtn').hidden,true);
  assert.equal(f.id('addDVBGroupBtn').disabled,true);assert.equal(f.id('dvbSelectPage').disabled,true);
  assert.equal(f.row().querySelector('input').disabled,true);
});

test('late Administrator snapshot cannot overwrite redacted Viewer rows or permissions', async t => {
  let manage = true;const f = await fixture(t,{canManage:() => manage,canControl:() => false});
  const held = Promise.withResolvers();f.hold = held;const stale = f.controller.resync();await settle();
  const oldRequest = f.calls.at(-1);f.controller.deactivate();assert.equal(oldRequest.options.signal.aborted,true);
  manage = false;f.hold = null;f.items = [stream()];delete f.items[0].output_url;
  assert.equal(await f.controller.activate(),true);held.resolve();assert.equal(await stale,false);
  assert.equal(f.row().querySelector('.dvb-stream-output').hidden,true);
  assert.equal(f.id('dvbBulkBar').hidden,true);assert.equal(f.row().querySelector('input').disabled,true);
});
