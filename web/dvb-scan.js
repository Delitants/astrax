// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import {hydrateDVBStream, loadEditorCards} from './dvb-editor.js?v=3';
import {availableScanCards, buildScanRequest, scanResultURL, validateScanResult, buildImportPreview, analyzeScanImport} from './dvb-scan-model.js?v=2';

const terminal = status => ['succeeded','partial','failed','cancelled'].includes(status);
const importable = status => ['succeeded','partial'].includes(status);
const rejected = reason => !Object.hasOwn(reason?.body || {},'results') && [400,401,403,405,413,415,422].includes(reason?.status);
function scanStartRejected(reason) {
  if (rejected(reason)) return true;
  const body = reason?.body, error = body?.error;
  // StartDVBScan returns these conflicts before creating/spawning a scan.
  // This exception does not apply to import or ambiguous operation envelopes.
  return reason?.status === 409 && body && Object.keys(body).length === 1
    && error && typeof error === 'object' && !Array.isArray(error)
    && Object.keys(error).every(key => ['code','message','field'].includes(key))
    && ['card_busy_external','card_unavailable','resource_busy'].includes(error.code)
    && typeof error.message === 'string' && !!error.message.trim()
    && (error.field === undefined || typeof error.field === 'string');
}
const metric = (value, unit = '') => Number.isFinite(value) ? `${value}${unit}` : 'unavailable';

export function createDVBScan({requestJSON, onImported, root = document, window = globalThis.window}) {
  const doc = root.ownerDocument || root, find = id => root.querySelector(`#dvb-scan-${id}`);
  const dialog = find('dialog'), form = find('form');
  if (!dialog || !form) throw Error('Scan markup is missing.');
  const field = name => form.elements.namedItem(name);
  let generation = 0, contextRead, pollRead, resumeRead = false, eventRead = false, timer, invoker;
  let ready = false, loading = false, contextError = '', readError = false, settings = {}, cards = [];
  let job, snapshot, write = '', batch, syncing = false, servicePage = 0;
  const selected = new Set();
  const state = () => write || (batch?.readback ? 'readback-pending' : job && !terminal(job.status) ? 'scan-running' : '');
  const values = prefix => Object.fromEntries([...form.elements].filter(el => el.name?.startsWith(prefix)).map(el => [el.name.slice(prefix.length),el.type === 'checkbox' ? el.checked : el.value]));
  function node(tag, text) {const el = doc.createElement(tag);if (text !== undefined) el.textContent = text;return el;}
  function message(text, error = false) {
    const el = find('status');el.textContent = text;el.classList.toggle('err',error);el.setAttribute('role',error ? 'alert' : 'status');
  }
  function changed() {dialog.dispatchEvent(new window.Event('dvb-scan-statechange'));}
  function stopReads() {
    ++generation;window.clearTimeout(timer);timer = undefined;contextRead?.abort();contextRead = undefined;
    pollRead?.abort.abort();resumeRead = false;eventRead = false;loading = false;
  }
  function close() {
    stopReads();if (dialog.open) dialog.close();invoker?.focus();changed();return true;
  }
  function choices(control, items, empty) {
    const prior = control.value;control.replaceChildren(Object.assign(node('option',empty),{value:''}));
    for (const item of items) control.append(Object.assign(node('option',item.name || item.id),{value:item.id}));
    if (items.some(item => item.id === prior)) control.value = prior;
  }
  function cardChoices() {
    const delivery = snapshot?.request.dvb.delivery_system || field('scan_delivery_system').value;
    const available = new Set(availableScanCards(cards,delivery).map(card => card.device_key));
    for (const prefix of ['scan','import']) {
      const select = field(`${prefix}_device_key`), prior = select.value;
      select.replaceChildren(Object.assign(node('option','Select a card'),{value:''}));
      for (const card of cards) select.append(Object.assign(node('option',`${card.model || 'Unknown model'} / ${card.address || 'address unavailable'} / ${card.frontend_type || 'type unavailable'} / ${(card.delivery_systems || []).join(', ')} / ${card.status || 'status unavailable'}`),{value:card.device_key,disabled:!available.has(card.device_key)}));
      select.value = prior;
    }
  }
  function filtered() {
    const search = find('search').value.trim().toLowerCase();
    return (snapshot?.services || []).filter(service => !search || [service.sid,service.name,service.provider,service.type,service.video_pid,service.audio_pid,service.pcr_pid,...(service.audio_languages || []),...(service.caids || []),service.scrambled ? 'scrambled' : 'fta',service.has_epg ? 'epg' : ''].join(' ').toLowerCase().includes(search));
  }
  function renderServices() {
    const items = filtered();servicePage = Math.min(servicePage,Math.max(0,Math.ceil(items.length / 200)-1));
    find('services').replaceChildren(...items.slice(servicePage*200,(servicePage+1)*200).map(service => {
      const li = node('li'), label = node('label'), checkbox = node('input');checkbox.type = 'checkbox';checkbox.dataset.sid = service.sid;
      checkbox.setAttribute('aria-label',`Select ${service.name || 'Service'} (SID ${service.sid})`);
      label.append(checkbox,node('span',`${service.name || 'Unnamed service'} / SID ${service.sid}`));
      li.append(label,node('p',`Provider: ${service.provider || 'unavailable'} / Type: ${service.type || 'unavailable'} / ${service.scrambled ? 'Scrambled' : 'FTA'}`),
        node('p',`Video PID: ${service.video_pid} / Audio PID: ${service.audio_pid} / PCR PID: ${service.pcr_pid} / Languages: ${(service.audio_languages || []).join(', ') || 'unavailable'}`),
        node('p',`CAIDs: ${(service.caids || []).map(value => `0x${value.toString(16).toUpperCase()} (${value})`).join(', ') || 'none reported'} / EPG: ${service.has_epg ? 'present' : 'not reported'}`));
      return li;
    }));
    find('page').textContent = `${items.length} matching / Page ${servicePage+1} of ${Math.max(1,Math.ceil(items.length/200))}`;
    find('prev').disabled = servicePage === 0;find('next').disabled = (servicePage+1)*200 >= items.length;
    sync();
  }
  function preview() {
    const v = values('import_'), delivery = snapshot?.request.dvb.delivery_system;
    if (!ready) throw Error(contextError || 'Cached import context is unavailable. Retry read.');
    if (v.adapter_mode === 'fixed' && !availableScanCards(cards,delivery).some(card => card.device_key === v.device_key)) throw Error('Select a compatible available physical card.');
    const ids = (snapshot?.services || []).filter(service => selected.has(service.sid)).map(service => service.sid);
    return buildImportPreview(snapshot?.services || [],ids,v,settings,window.location.hostname);
  }
  function renderPreview() {
    let result, error = '';
    try {result = batch || preview();} catch (reason) {error = reason.message;}
    find('preview-error').textContent = error;find('preview-error').hidden = !error || !selected.size;
    find('preview').replaceChildren(...(result?.rows || []).map(row => {const li = node('li',`${row.name} / SID ${row.sid}`);li.append(node('output',row.output));if (row.xmltv) li.append(node('span',`XMLTV: ${row.xmltv}`));return li;}));
    return !!result && !batch;
  }
  function sync() {
    const busy = !!state(), selectionLocked = !!batch || !!write;
    let tuningError = '';
    if (!ready) tuningError = contextError || 'Loading cached context...';
    else try {buildScanRequest(values('scan_'),cards,settings,window.location.hostname);} catch (error) {tuningError = error.message;}
    find('tuning-error').textContent = tuningError;
    find('tuning').disabled = loading || !!job || !!write || !!batch;
    find('defaults').disabled = loading || !ready || selectionLocked;
    form.querySelector('[data-scan-fixed]').hidden = field('scan_adapter_mode').value !== 'fixed';
    form.querySelector('[data-import-fixed]').hidden = field('import_adapter_mode').value !== 'fixed';
    form.querySelector('[data-scan-rf]').hidden = !field('scan_rf_override').checked;
    form.querySelector('[data-scan-unicable]').hidden = !['unicable1','unicable2'].includes(field('scan_rf_mode').value);
    for (const opt of field('scan_modulation').options) opt.disabled = field('scan_delivery_system').value === 'dvbs' && ['8psk','16apsk','32apsk'].includes(opt.value);
    for (const opt of field('scan_slot_position').options) opt.disabled = field('scan_rf_mode').value === 'unicable1' && ['C','D'].includes(opt.value);
    find('start').disabled = !dialog.open || !!job || !!batch || busy || loading || !!tuningError;
    find('start').hidden = !!job || !!batch;
    find('new').hidden = !job || !terminal(job.status) || busy;
    find('new').disabled = loading || !!pollRead;
    find('retry').hidden = !(readError || contextError || batch?.readback);
    find('retry').disabled = loading || !!pollRead || syncing || !!write;
    find('select-all').disabled = selectionLocked || !snapshot?.services.length;
    find('select-none').disabled = selectionLocked || !selected.size;
    for (const el of find('services').querySelectorAll('input[data-sid]')) {el.checked = selected.has(Number(el.dataset.sid));el.disabled = selectionLocked;}
    find('selection-count').textContent = `${selected.size} selected across all filters. All/none affects matching services only; maximum 1000 selected. 200 results per page.`;
    const valid = renderPreview();
    find('import').disabled = !dialog.open || loading || busy || !importable(snapshot?.status) || !valid;
    form.setAttribute('aria-busy',String(loading || !!write && write.endsWith('-pending') || syncing));
    changed();
  }
  function renderSnapshot() {
    const signal = snapshot?.signal;
    find('signal').textContent = `Signal: ${metric(signal?.signal_percent,'%')} / SNR: ${metric(signal?.snr_percent,'%')} / BER: ${metric(signal?.ber)} / UNC: ${metric(signal?.uncorrected_blocks)} / Lock: ${typeof signal?.locked === 'boolean' ? signal.locked ? 'locked' : 'not locked' : 'unavailable'}`;
    find('progress').textContent = snapshot ? `${snapshot.status} / ${snapshot.services.length} discovered services. ${snapshot.status === 'partial' ? 'Partial scan: discovered services can be imported.' : ''}` : 'No scan started.';
    cardChoices();renderServices();
  }
  async function loadContext() {
    const token = generation, abort = new AbortController();contextRead?.abort();contextRead = abort;
    loading = true;ready = false;contextError = '';sync();
    try {
      const options = {signal:abort.signal};
      const [groups,cams,config,inventory] = await Promise.all([requestJSON('/api/v1/dvb-groups',options),requestJSON('/api/v1/softcams',options),requestJSON('/api/v1/settings',options),loadEditorCards(requestJSON,options)]);
      if (generation !== token || !dialog.open) return false;
      const validateChoices = (value,key) => {
        const list = value?.[key] === null ? [] : value?.[key], seen = new Set();
        if (!Array.isArray(list) || list.length > 5000 || list.some(item => !item || typeof item.id !== 'string' || !item.id || seen.has(item.id) || (seen.add(item.id), typeof item.name !== 'string'))) throw Error(`Malformed ${key} snapshot.`);
        return list;
      };
      const groupItems = validateChoices(groups,'groups'), camItems = validateChoices(cams,'softcams');
      if (!Number.isInteger(config?.http_play_port) || config.http_play_port < 1 || config.http_play_port > 65535
        || inventory.some(card => !Array.isArray(card.delivery_systems) || card.delivery_systems.some(d => typeof d !== 'string'))) throw Error('Malformed playback settings or card capabilities.');
      settings = config;cards = inventory;choices(field('import_group_id'),groupItems,'Ungrouped');choices(field('import_softcam_id'),camItems,'None');
      ready = true;cardChoices();return true;
    } catch (reason) {
      if (generation === token) {contextError = `Could not load cached context: ${reason.message}. Retry read; no device refresh is performed.`;message(contextError,true);}
      return false;
    } finally {if (generation === token) {loading = false;contextRead = undefined;sync();}}
  }
  async function poll() {
    if (!dialog.open || !job || terminal(job.status) || write) return false;
    if (pollRead) {resumeRead = true;return false;}
    window.clearTimeout(timer);timer = undefined;
    const read = {abort:new AbortController(),token:generation,job};pollRead = read;readError = false;resumeRead = false;eventRead = false;
    const current = () => dialog.open && generation === read.token && job === read.job;
    try {
      const result = validateScanResult(await requestJSON(read.job.path,{signal:read.abort.signal}),read.job.id);
      if (!current()) return false;
      snapshot = result;job.status = result.status;
      const liveIDs = new Set(result.services.map(service => service.sid));for (const sid of selected) if (!liveIDs.has(sid)) selected.delete(sid);
      message(`Scan ${result.status}. ${result.status === 'partial' ? 'Partial results are available for import. ' : ''}${typeof result.error === 'string' ? result.error : ''}`.trim(),['failed','cancelled'].includes(result.status));
      renderSnapshot();return true;
    } catch (reason) {
      if (current()) {readError = true;message(`Scan read failed: ${reason.message}. Use Retry read; do not start another scan.`,true);}
      return false;
    } finally {
      if (pollRead === read) pollRead = undefined;
      if (current()) {sync();if (!readError && !terminal(job.status)) timer = window.setTimeout(()=>{void poll();},eventRead ? 100 : 1000);}
      else if (resumeRead && dialog.open) {resumeRead = false;void poll();}
    }
  }
  async function start() {
    if (!dialog.open || !ready || loading || job || batch || state()) return;
    let dto;try {dto = buildScanRequest(values('scan_'),cards,settings,window.location.hostname);} catch (reason) {message(reason.message,true);sync();return;}
    write = 'scan-pending';message('Starting scan. Do not repeat this request. Closing stops polling, not the server operation.');sync();
    try {
      // Mutation lifetime is independent of navigation; never attach a read AbortSignal.
      const operation = await requestJSON('/api/v1/dvb-scans',{method:'POST',body:JSON.stringify(dto)});
      const path = scanResultURL(operation);
      job = {id:operation.id,path,status:'queued'};write = '';message('Scan accepted. Reading the known job.');
      if (dialog.open) void poll();
    } catch (reason) {
      write = scanStartRejected(reason) ? '' : 'scan-unknown';
      message(write ? 'Scan outcome unknown. Do not retry or submit other writes; inspect server state independently.' : `Scan rejected; no scan started: ${reason.message}. Correct the request before Start.`,true);
    } finally {sync();}
  }
  function renderResults(result) {
    find('results').hidden = false;
    find('results').querySelector('ul').replaceChildren(...batch.rows.map(row => {
      const item = result.results.find(item => item.sid === row.sid);
      return node('li',`${row.name} (SID ${row.sid}): ${item ? item.ok ? `Created stream ${item.id}` : `Failed: ${item.error}` : 'Outcome unknown; inspect server state'}`);
    }));
  }
  async function readback() {
    if (!batch?.readback || syncing || !dialog.open) return false;
    const currentBatch = batch, token = generation;syncing = true;sync();
    let ok = false;
    try {ok = typeof onImported === 'function' && await onImported() === true;} catch { /* A readback error is never a failed import or permission to re-POST. */ }
    if (batch === currentBatch) {
      if (ok && dialog.open && token === generation) batch.readback = false;
      message(`${batch.summary} ${batch.readback ? 'Import outcomes are known; snapshot readback pending. Retry read only, never re-import.' : 'Snapshot verified. This batch is locked against repeat import.'}`,batch.readback || batch.failed > 0);
    }
    syncing = false;sync();return !batch?.readback;
  }
  async function importSelected() {
    if (!dialog.open || loading || !ready || state() || batch || !importable(snapshot?.status)) return;
    let frozen;try {frozen = preview();} catch (reason) {message(reason.message,true);sync();return;}
    batch = structuredClone(frozen);write = 'import-pending';message(`Importing ${batch.rows.length} services. Do not repeat this request.`);sync();
    let response, failure;
    try {response = await requestJSON(`${job.path}/import`,{method:'POST',body:JSON.stringify(batch.dto)});} catch (reason) {failure = reason;response = reason?.body;}
    if (failure && rejected(failure)) {batch = undefined;write = '';message(`Import rejected before admission: ${failure.message}. Correct the request before retrying.`,true);sync();return;}
    const result = analyzeScanImport(response,batch.dto.service_ids);renderResults(result);
    if (!result.complete) {write = 'import-unknown';message('Import outcome unknown or inconsistent. Batch locked; inspect server state independently before further writes.',true);sync();return;}
    write = '';batch.summary = `${result.succeeded} succeeded, ${result.failed} failed.`;batch.failed = result.failed;batch.readback = true;
    message(`${batch.summary} Known outcomes; snapshot readback pending.`,result.failed > 0);sync();
    if (dialog.open) await readback();
  }
  async function open() {
    if (dialog.open) return true;
    ++generation;invoker = doc.activeElement;dialog.showModal();sync();
    const token = generation;await loadContext();
    if (token !== generation || !dialog.open) return false;
    if (job && !terminal(job.status) && !write) void poll();
    return true;
  }
  form.addEventListener('submit',event => {event.preventDefault();void start();});
  form.addEventListener('input',event => {if (event.target.name) sync();});
  form.addEventListener('change',event => {if (event.target.name === 'scan_delivery_system') cardChoices();if (event.target.name) sync();});
  find('close').addEventListener('click',close);
  dialog.addEventListener('cancel',event => {event.preventDefault();close();});
  dialog.addEventListener('close',()=>{if (dialog.open) return;stopReads();changed();});
  find('search').addEventListener('input',()=>{servicePage = 0;renderServices();});
  find('prev').addEventListener('click',()=>{servicePage = Math.max(0,servicePage-1);renderServices();});
  find('next').addEventListener('click',()=>{++servicePage;renderServices();});
  find('services').addEventListener('change',event => {
    const el = event.target, sid = Number(el.dataset.sid);if (!sid || batch || write) {sync();return;}
    if (el.checked) {if (selected.size < 1000) selected.add(sid);else message('Select at most 1000 services.',true);} else selected.delete(sid);sync();
  });
  find('select-all').addEventListener('click',()=>{
    if (batch || write) return;
    const union = new Set([...selected,...filtered().map(service => service.sid)]);
    if (union.size > 1000) {message('All matching would exceed 1000 selected services. Narrow the search first.',true);return;}
    for (const sid of union) selected.add(sid);sync();
  });
  find('select-none').addEventListener('click',()=>{if (batch || write) return;for (const service of filtered()) selected.delete(service.sid);sync();});
  find('import').addEventListener('click',()=>{void importSelected();});
  find('retry').addEventListener('click',async()=>{
    if (loading || syncing || pollRead || write) return;
    if (batch?.readback) {await readback();return;}
    if (contextError) await loadContext();
    if (dialog.open && job && !terminal(job.status)) await poll();
  });
  find('new').addEventListener('click',()=>{
    if (!job || !terminal(job.status) || state() || loading || pollRead) return;
    ++generation;job = undefined;snapshot = undefined;batch = undefined;readError = false;selected.clear();servicePage = 0;
    find('results').hidden = true;find('results').querySelector('ul').replaceChildren();message('New scan prepared; Start explicitly tunes a card.');renderSnapshot();
    void loadContext();
  });
  const defaults = hydrateDVBStream();
  for (const [key,value] of Object.entries(defaults)) {
    const el = field(`scan_${key}`);if (!el) continue;if (el.type === 'checkbox') el.checked = value;else el.value = value;
  }
  function applyEvent(event) {
    if (!dialog.open || !job || terminal(job.status) || write || readError ||
        event?.kind !== 'dvb.scan.operation.changed' || event.resource_id !== job.id ||
        event.payload?.mode !== 'replace' || event.payload.resource?.id !== job.id) return;
    try {if (scanResultURL(event.payload.resource) !== job.path) return;} catch {return;}
    // Operations are read hints, not service results. Keep the canonical result
    // read and its mutation fence; bursts queue at most one follow-up GET.
    if (eventRead) return;
    eventRead = true;
    if (!pollRead) {
      window.clearTimeout(timer);
      timer = window.setTimeout(()=>{void poll();},100);
    }
  }
  return {open,close,deactivate:close,writeState:state,applyEvent};
}
