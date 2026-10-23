// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('../../web/app.js',import.meta.url),'utf8');
function el(value='') {
 const listeners={},attrs={};return {value,disabled:false,hidden:true,textContent:'',open:false,
 addEventListener(n,fn){(listeners[n] ||= []).push(fn);},
 async emit(n){let prevented=false;for(const fn of listeners[n]||[]) await fn({preventDefault(){prevented=true;}});if(n==='cancel'&&!prevented)this.close();return prevented;},
 setAttribute(n,v){attrs[n]=String(v);},removeAttribute(n){delete attrs[n];},getAttribute(n){return attrs[n]??null;},close(){this.open=false;},
 };
}
function harness(){
 const calls=[],els={},controls={};let responder=async()=>{},refresh=async()=>{},owner=0;
 for(const kind of ['Generate','Upload']){
  const form=el(),dialog=el(),notice=el(),cancel=el();
  Object.assign(form,kind==='Generate'?{hosts:el('localhost, 127.0.0.1'),duration_days:el('1'),common_name:el('Fixture')}:{cert:el('SYNTHETIC CERT'),key:el('SYNTHETIC KEY')});
  const submit=el();controls[kind]=[...Object.values(form).filter(x=>x&&typeof x==='object'&&'value'in x),cancel,submit];
  form.querySelectorAll=()=>controls[kind];form.reset=()=>{};
  Object.assign(els,{[`cert${kind}Form`]:form,[`cert${kind}Dialog`]:dialog,[`cert${kind}Notice`]:notice,[`cancelCert${kind}Btn`]:cancel});
 }
 Object.assign(els,{generateCertBtn:el(),uploadCertBtn:el(),deleteCertBtn:el(),settingsNotice:el()});
 const sessions=new WeakMap();const context=vm.createContext({els,editorSessions:sessions,
  openEditor(d){sessions.set(d,{});d.open=true;},beginNoticeAction(){return ++owner;},isCurrentAction(a){return a===owner;},
  showPersistentNotice(n,kind,msg){n.hidden=false;n.textContent=msg;n.setAttribute('role',kind==='err'?'alert':'status');},
  showSettingsNotice(kind,msg){els.settingsNotice.textContent=msg;},confirm(){return true;},
  loadCertStatus:()=>refresh(),api:async(p,o)=>{calls.push({path:p,body:o.body&&JSON.parse(o.body)});return responder();},
 });
 const b=source.indexOf('function beginEditorSubmission('),e=source.indexOf('function softcamFormPayload(',b);vm.runInContext(source.slice(b,e),context);
 const start=source.includes('let certificateWritePending')?source.indexOf('let certificateWritePending'):source.indexOf('els.generateCertBtn?.addEventListener');
 vm.runInContext(source.slice(start,source.indexOf('function setMenuOpen(',start)),context);
 return {els,calls,controls,respond(fn){responder=fn;},refresh(fn){refresh=fn;},open:k=>els[k==='Generate'?'generateCertBtn':'uploadCertBtn'].emit('click'),submit:k=>els[`cert${k}Form`].emit('submit')};
}
for(const kind of ['Generate','Upload']){
 test(`${kind}: success explains the HTTPS bind prerequisite before restart`,async()=>{
  const h=harness();await h.open(kind);await h.submit(kind);
  assert.match(h.els.settingsNotice.textContent,/control_listen_https/);
  assert.match(h.els.settingsNotice.textContent,/concrete IP/);
  assert.match(h.els.settingsNotice.textContent,/certificate/);
 });
 test(`${kind}: one pending write, disabled controls, rejection restores original states and allows retry`,async()=>{
  const h=harness(),held=Promise.withResolvers();h.controls[kind][0].disabled=true;h.respond(()=>held.promise);await h.open(kind);
  const first=h.submit(kind),again=h.submit(kind);const pending={count:h.calls.length,disabled:h.controls[kind].every(x=>x.disabled),busy:h.els[`cert${kind}Form`].getAttribute('aria-busy'),text:h.els[`cert${kind}Notice`].textContent};
  held.reject(new Error('Rejected <b>literal</b>'));await Promise.all([first,again]);
  assert.equal(pending.count,1);assert.equal(pending.disabled,true);assert.equal(pending.busy,'true');assert.match(pending.text,/Wait/);
  assert.equal(h.controls[kind][0].disabled,true);assert.equal(h.controls[kind].at(-1).disabled,false);assert.equal(h.els[`cert${kind}Form`].getAttribute('aria-busy'),null);assert.equal(h.els[`cert${kind}Dialog`].open,true);assert.match(h.els[`cert${kind}Notice`].textContent,/Rejected <b>literal<\/b>/);
  h.respond(async()=>{});await h.submit(kind);assert.equal(h.calls.length,2);assert.equal(h.els[`cert${kind}Dialog`].open,false);
 });
 test(`${kind}: Cancel and Escape stay pending; conflicting opens/submits/delete are blocked`,async()=>{
  const h=harness(),held=Promise.withResolvers();h.respond(()=>held.promise);await h.open(kind);const first=h.submit(kind);
  await h.els[`cancelCert${kind}Btn`].emit('click');const openAfterCancel=h.els[`cert${kind}Dialog`].open;await h.els[`cert${kind}Dialog`].emit('cancel');const openAfterEscape=h.els[`cert${kind}Dialog`].open;
  const other=kind==='Generate'?'Upload':'Generate';await h.open(other);const conflicting=h.submit(other),deletion=h.els.deleteCertBtn.emit('click');const count=h.calls.length,otherOpen=h.els[`cert${other}Dialog`].open;
  held.reject(new Error('Delayed rejection'));await Promise.all([first,conflicting,deletion]);
  assert.equal(openAfterCancel,true);assert.equal(openAfterEscape,true);assert.equal(otherOpen,false);assert.equal(count,1);assert.match(h.els[`cert${kind}Notice`].textContent,/Delayed rejection/);
  await h.els[`cancelCert${kind}Btn`].emit('click');assert.equal(h.els[`cert${kind}Dialog`].open,false);assert.equal(h.els.generateCertBtn.disabled,false);
 });
 test(`${kind}: acknowledged write retains success and releases controls after status refresh`,async()=>{
  const h=harness(),held=Promise.withResolvers();h.refresh(()=>held.promise);await h.open(kind);const saving=h.submit(kind);await Promise.resolve();held.resolve();await saving;
  assert.equal(h.calls.length,1);assert.match(h.els.settingsNotice.textContent,/Restart/);assert.equal(h.els[`cert${kind}Dialog`].open,false);assert.equal(h.els.uploadCertBtn.disabled,false);
 });
}

test('pending deletion blocks duplicate delete and generation/upload until result, then restores actions', async()=>{
 const h=harness(),held=Promise.withResolvers();h.respond(()=>held.promise);
 const first=h.els.deleteCertBtn.emit('click'),again=h.els.deleteCertBtn.emit('click');
 await h.open('Generate');await h.open('Upload');const pending={count:h.calls.length,generate:h.els.certGenerateDialog.open,upload:h.els.certUploadDialog.open,disabled:h.els.generateCertBtn.disabled};
 held.reject(new Error('Deletion rejected'));await Promise.all([first,again]);
 assert.equal(pending.count,1);assert.equal(pending.generate,false);assert.equal(pending.upload,false);assert.equal(pending.disabled,true);assert.equal(h.els.generateCertBtn.disabled,false);assert.match(h.els.settingsNotice.textContent,/Deletion rejected/);
});
for(const kind of ['Generate','Upload','Delete']) test(`${kind}: held readback never holds the acknowledged mutation fence`, async()=>{
 const h=harness(),held=Promise.withResolvers(),reading=Promise.withResolvers();h.refresh(()=>{reading.resolve();return held.promise;});
 if(kind!=='Delete')await h.open(kind);
 const first=kind==='Delete'?h.els.deleteCertBtn.emit('click'):h.submit(kind);await reading.promise;
 const disabled=h.els.generateCertBtn.disabled;const acknowledged=h.els.settingsNotice.textContent;
 held.resolve();await first;
 assert.equal(disabled,false);assert.match(acknowledged,/Restart/);
});
for(const failed of [false,true]) test(`stale certificate status ${failed?'failure':'success'} cannot overwrite newer state`,async()=>{
 const held=Promise.withResolvers(),state={certExists:true};let renders=0,owned=true;
 const context=vm.createContext({state,api:()=>held.promise,updateCertUI(){renders++;}});
 const a=source.indexOf('async function loadCertStatus('),b=source.indexOf('function updateCertUI(',a);vm.runInContext(source.slice(a,b),context);
 const reading=context.loadCertStatus(()=>owned);owned=false;
 if(failed)held.reject(new Error('stale'));else held.resolve({exists:false});await reading;
 assert.equal(state.certExists,true);assert.equal(renders,0);
});
