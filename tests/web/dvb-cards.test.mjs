// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import assert from 'node:assert/strict';
import test from 'node:test';
import {createDVBCardsController} from '../../web/dvb-cards.js';

class Element {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase();this.doc = doc;this.children = [];this.dataset = {};this.handlers = new Map();
    this.attributes = new Map();this.value = '';this._text = '';this.hidden = false;this.disabled = false;this.checked = false;this.className = '';this.open = false;
  }
  get textContent() {return this._text + this.children.map(el => el.textContent).join('');}
  set textContent(value) {this._text = String(value);this.replaceChildren();}
  get valueAsNumber() {return Number(this.value);}
  get firstChild() {return this.children[0] || null;}
  get nextSibling() {return this.parentNode?.children[this.parentNode.children.indexOf(this)+1] || null;}
  get options() {return this.children;}
  get isConnected() {return this.parentNode ? this.parentNode.isConnected : this === this.doc;}
  append(...items) {for (let item of items) {if (typeof item === 'string') item = Object.assign(new Element('text',this.doc),{textContent:item});this.insertBefore(item,null);}}
  insertBefore(item, before) {item.remove();const index = before ? this.children.indexOf(before) : this.children.length;this.children.splice(index,0,item);item.parentNode = this;return item;}
  replaceChildren(...items) {for (const child of [...this.children]) child.remove();this.append(...items);}
  remove() {if (this.parentNode) this.parentNode.children.splice(this.parentNode.children.indexOf(this),1);this.parentNode = null;}
  contains(item) {return this === item || this.children.some(child => child.contains(item));}
  matches(selector) {
    if (selector.startsWith('.')) return this.className.split(' ').includes(selector.slice(1));
    const match = selector.match(/^([a-z]+)?\[data-([a-z-]+)(?:="([^"]+)")?\]$/);
    if (match) {const key = match[2].replace(/-([a-z])/g,(_,ch) => ch.toUpperCase());return (!match[1] || this.tagName === match[1].toUpperCase()) && Object.hasOwn(this.dataset,key) && (!match[3] || this.dataset[key] === match[3]);}
    return this.tagName === selector.toUpperCase();
  }
  querySelectorAll(selector) {return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []),...child.querySelectorAll(selector)]);}
  querySelector(selector) {return this.querySelectorAll(selector)[0] || null;}
  closest(selector) {for (let el = this; el; el = el.parentNode) if (el.matches(selector)) return el;return null;}
  setAttribute(key,value) {this.attributes.set(key,String(value));}
  removeAttribute(key) {this.attributes.delete(key);}
  getAttribute(key) {return this.attributes.get(key) ?? null;}
  addEventListener(key,fn) {if (!this.handlers.has(key)) this.handlers.set(key,[]);this.handlers.get(key).push(fn);}
  removeEventListener(key,fn) {this.handlers.set(key,(this.handlers.get(key) || []).filter(handler => handler !== fn));}
  emit(key) {const event = {target:this,preventDefault() {}};for (let el = this; el; el = el.parentNode) for (const fn of el.handlers.get(key) || []) fn(event);}
  focus() {this.doc.activeElement = this;}
  reset() {}
  showModal() {this.open = true;}
  close() {this.open = false;}
}
const settle = async () => {for (let i = 0; i < 30; i++) await Promise.resolve();};
const card = () => ({id:'card-a',address:'0.0',device_key:'fixture-a',model:'Fixture tuner',present:true,status:'active',active_streams:1,active_sessions:1,
  delivery_systems:['dvbs2'],application:{state:'applied'},config:{alias:'News card',enabled:true,
    rf_defaults:{lof1:9750,lof2:10600,slof:11700,force_tone:false,mode:'universal',unicable_slot:1,slot_position:'A',slot_frequency:1210},
    advanced:{enable_monitoring:true,modulation:'auto',fec:'auto',rolloff:'auto',stream_id:0,timeout_sec:10,dvb_api:'v5',dvb_api_v3:false}},
  signal:{locked:true,signal_percent:80,snr_percent:70},last_error:''});

async function fixture(t, {canManage,canControl,confirmAction = () => true} = {}) {
  t.mock.timers.enable({apis:['setTimeout','Date'],now:10000});
  const doc = new Element('document');doc.doc = doc;doc.createElement = tag => new Element(tag,doc);
  const ids = new Map(), id = key => {if (!ids.has(key)) {const el = doc.createElement('div');el.id = key;doc.append(el);ids.set(key,el);}return ids.get(key);};
  doc.querySelector = selector => id(selector.slice(1));
  const summary = Array.from({length:7},() => doc.createElement('p'));
  doc.querySelectorAll = selector => selector === '#dvbCardsSummary p' ? summary : [];
  for (const key of ['cardSettingsDialog','cardRestartDialog']) id(key).append(Object.assign(doc.createElement('div'),{className:'dvb-dialog-body'}));
  const fields = new Map(), form = id('cardSettingsForm');
  const field = name => {if (!fields.has(name)) {const el = doc.createElement(['rf_mode','unicable_slot','slot_position','dvb_api'].includes(name) ? 'select' : 'input');el.name = name;fields.set(name,el);form.append(el);}return fields.get(name);};
  form.elements = {namedItem:field};form.append(doc.createElement('fieldset'));
  for (const section of ['lnb','unicable']) form.append(Object.assign(doc.createElement('section'),{dataset:{rfSection:section}}));
  const win = {location:{hash:'#dvb-cards',origin:'https://fixture.test'},history:{replaceState(_state,_title,hash) {win.location.hash = hash;}}};
  const calls = [], f = {card:card()};
  const requestJSON = async (path,options = {}) => {
    calls.push({path,options});
    if (f.respond) {const response = await f.respond(path,options);if (response !== undefined) return response;}
    if (path.startsWith('/api/v1/dvb-cards?')) return structuredClone({items:[f.card],total:1,facets:{},refreshed_at:'2026-10-24T00:00:00Z'});
    if (path === '/api/v1/dvb-cards/card-a') return structuredClone(f.card);
    if (path === '/api/v1/dvb-cards/refresh') return {};
    if (path === '/api/v1/dvb-cards/card-a/restart') return {id:'op-a',kind:'dvb.card.restart',resource_id:'card-a',status:'succeeded',operation_url:'/api/v1/dvb-cards/card-a/operations/op-a'};
    throw new Error(`Unexpected request ${path}`);
  };
  const controller = createDVBCardsController({requestJSON,root:doc,window:win,canManage,canControl,confirmAction});
  t.after(() => controller.deactivate());
  assert.ok(await controller.activate());
  const body = id('dvbCardsTableBody');
  const action = key => body.querySelectorAll('button[data-card-action]').find(el => el.dataset.cardAction === key);
  return Object.assign(f,{controller,id,field,doc,win,calls,body,action,
    async click(key) {action(key).emit('click');await settle();},
    async tick(ms) {t.mock.timers.tick(ms);await settle();},
  });
}
const writes = f => f.calls.filter(call => call.options.method && call.options.method !== 'GET');

for (const role of ['Operator','Viewer']) test(`${role}: cards hide management but retain Details and cached GET refresh`, async t => {
  const f = await fixture(t,{canManage:() => false,canControl:() => role === 'Operator'});
  for (const key of ['settings','restart']) {assert.equal(f.action(key).hidden,true);assert.equal(f.action(key).disabled,true);}
  assert.equal(f.action('restart').closest('section').hidden,true);
  assert.match(f.id('refreshDVBCardsBtn').textContent,/refresh view/i);
  const details = f.body.querySelector('button[data-card-details]');details.emit('click');
  assert.equal(details.getAttribute('aria-expanded'),'true');assert.match(f.body.textContent,/Fixture tuner/);
  f.id('refreshDVBCardsBtn').emit('click');await settle();
  assert.deepEqual(writes(f),[]);assert.equal(f.calls.length,2);
  assert.ok(f.calls.every(call => call.path.startsWith('/api/v1/dvb-cards?')));
});

for (const role of ['Operator','Viewer']) test(`${role}: forced card settings/restart and form handlers cannot mutate`, async t => {
  let confirmations = 0;
  const f = await fixture(t,{canManage:() => false,canControl:() => role === 'Operator',confirmAction:() => {confirmations++;return true;}});
  for (const key of ['settings','restart']) {f.action(key).disabled = false;await f.click(key);}
  f.id('cardSettingsForm').emit('submit');await settle();
  assert.equal(f.id('cardSettingsDialog').open,false);assert.equal(f.id('cardRestartDialog').open,false);
  assert.equal(confirmations,0);assert.deepEqual(writes(f),[]);assert.equal(f.calls.length,1);
});

test('default Administrator: settings save, card restart and privileged refresh remain functional', async t => {
  const f = await fixture(t);
  assert.equal(f.action('settings').hidden,false);assert.equal(f.action('restart').disabled,false);
  await f.click('settings');assert.equal(f.id('cardSettingsSave').disabled,false);
  f.id('cardSettingsForm').emit('submit');await settle();
  assert.equal(writes(f)[0].options.method,'PUT');
  assert.equal(writes(f)[0].path,'/api/v1/dvb-cards/card-a');
  assert.equal(JSON.parse(writes(f)[0].options.body).alias,'News card');
  f.id('cardSettingsClose').emit('click');await f.click('restart');
  assert.equal(writes(f)[1].path,'/api/v1/dvb-cards/card-a/restart');
  f.id('refreshDVBCardsBtn').emit('click');await settle();
  assert.equal(writes(f)[2].path,'/api/v1/dvb-cards/refresh');assert.equal(writes(f)[2].options.method,'POST');
});

test('card reactivation and late inventory events cannot re-enable a downgraded role', async t => {
  let manage = true;
  const f = await fixture(t,{canManage:() => manage});
  f.controller.deactivate();manage = false;await f.controller.activate();
  f.controller.applyEvent({kind:'dvb.card.changed',resource_id:'card-a',revision:1,payload:{mode:'replace',resource:card()}});
  await f.tick(1100);
  for (const key of ['settings','restart']) {assert.equal(f.action(key).hidden,true);assert.equal(f.action(key).disabled,true);}
  assert.match(f.id('refreshDVBCardsBtn').textContent,/refresh view/i);
  f.controller.deactivate();manage = true;await f.controller.activate();
  assert.equal(f.action('settings').hidden,false);assert.equal(f.action('settings').disabled,false);
  assert.equal(f.action('restart').closest('section').hidden,false);
});

test('card settings late load cannot enable saving after management is revoked', async t => {
  let manage = true;const held = Promise.withResolvers();
  const f = await fixture(t,{canManage:() => manage});
  f.respond = path => path === '/api/v1/dvb-cards/card-a' ? held.promise : undefined;
  f.action('settings').emit('click');await settle();manage = false;held.resolve(card());await settle();
  assert.equal(f.id('cardSettingsSave').disabled,true);
  f.id('cardSettingsSave').disabled = false;f.id('cardSettingsForm').emit('submit');await settle();
  assert.deepEqual(writes(f),[]);
});

for (const stage of ['confirmation','preflight']) test(`card restart rechecks management after ${stage}`, async t => {
  let manage = true;const held = Promise.withResolvers();
  const f = await fixture(t,{canManage:() => manage,confirmAction:() => stage === 'confirmation' ? held.promise : true});
  if (stage === 'preflight') f.respond = path => path === '/api/v1/dvb-cards/card-a' ? held.promise : undefined;
  f.action('restart').emit('click');await settle();manage = false;
  held.resolve(stage === 'confirmation' ? true : card());await settle();
  assert.deepEqual(writes(f),[]);
});

test('card pending/unknown saves keep their fence across role reactivation', async t => {
  let manage = true;const held = Promise.withResolvers();
  const f = await fixture(t,{canManage:() => manage});await f.click('settings');
  f.respond = (_path,options) => options.method === 'PUT' ? held.promise : undefined;
  f.id('cardSettingsForm').emit('submit');f.id('cardSettingsForm').emit('submit');await settle();
  assert.equal(writes(f).length,1);
  f.controller.deactivate();manage = false;await f.controller.activate();
  held.reject(new Error('unknown save'));await settle();
  f.controller.deactivate();manage = true;await f.controller.activate();await f.click('settings');
  assert.equal(f.id('cardSettingsSave').disabled,true);
  f.id('cardSettingsSave').disabled = false;f.id('cardSettingsForm').emit('submit');await settle();assert.equal(writes(f).length,1);
});

test('card deactivation aborts cached inventory and fences its late response', async t => {
  const f = await fixture(t,{canManage:() => false});const held = Promise.withResolvers();
  f.respond = path => path.startsWith('/api/v1/dvb-cards?') ? held.promise : undefined;
  const read = f.controller.resync();await settle();const last = f.calls.at(-1);
  f.controller.deactivate();assert.equal(last.options.signal.aborted,true);
  held.resolve({items:[],total:0});await read;
  assert.match(f.body.textContent,/Fixture tuner/);assert.equal(f.action('settings').disabled,true);
});

test('card activation reapplies permissions even when the panel is already active', async t => {
  let manage = true;const f = await fixture(t,{canManage:() => manage});
  manage = false;await f.controller.activate();
  assert.equal(f.action('settings').hidden,true);assert.equal(f.action('restart').disabled,true);
  assert.match(f.id('refreshDVBCardsBtn').textContent,/refresh view/i);
});

test('card ownership monitoring accepts withheld diagnostics without repeated inventory reads', async t => {
  const f = await fixture(t,{canManage:() => false});
  f.controller.applyEvent({kind:'dvb.card.changed',resource_id:'card-a',revision:1,payload:{mode:'ownership',ownership:{
    application:null,current_transport:null,active_sessions:1,active_streams:1,signal:{locked:true,signal_percent:33,snr_percent:22},
  }}});
  await f.tick(1000);
  assert.equal(f.calls.length,1);assert.match(f.body.textContent,/Signal 33%/);
  assert.equal(f.action('restart').disabled,true);
});

test('already loaded card settings cannot save after management is revoked', async t => {
  let manage = true;const f = await fixture(t,{canManage:() => manage});await f.click('settings');
  assert.equal(f.id('cardSettingsSave').disabled,false);manage = false;
  f.id('cardSettingsForm').emit('submit');await settle();assert.deepEqual(writes(f),[]);
});
