// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import {enums, storageKey, readView, validateView, nondefaults, viewHash, requestPath, groupOption, optionGroup, groupCounts, countValue, validPage, searchWithinLimit} from './dvb-stream-query.js?v=2';
import {analyzeBulkResult, bulkRejected, bulkErrorText, loadBulkCards} from './dvb-bulk.js?v=1';

const shown = value => value === null || value === undefined || value === '' ? 'unavailable' : String(value);
const metric = (value, unit) => Number.isFinite(value) ? `${value}${unit}` : 'unavailable';
const definiteRejection = reason => reason?.status >= 400 && reason.status < 500 && ![408, 499].includes(reason.status);
const groupPath = id => `/api/v1/dvb-groups/${encodeURIComponent(id)}`;
const labels = ['Name / group', 'Service / transponder', 'Requested card', 'Actual card', 'Output / state'];
const bulkActions = [['start','Start'],['stop','Stop'],['restart','Restart'],['move_group','Move group'],['assign_adapter','Assign adapter'],['delete','Delete']];
const controlActions = ['start','stop','restart'];
const descramblingText = value => {
  const state = enums.descrambling_state.includes(value?.state) ? value.state : 'unavailable';
  const reason = enums.descrambling_reason.includes(value?.reason) && value.reason !== state ? ` / ${value.reason}` : '';
  const processed = state === 'payload_processed' ? ' (not proof of decoded media)' : '';
  return `Descrambling ${state}${reason}${processed}${value?.metrics?.sample_stale === true ? ' / stale cache' : ''}`;
};

// Scan imports have their own result identity contract and durable write fence.
export function createDVBStreamsController({requestJSON, confirmAction = message => window.confirm(message), canManage = () => true, canControl = () => true, openEditor, editorWriteState = () => '', openScan, scanWriteState = () => '', onPageLoad = () => {}, root = document, window = globalThis.window}) {
  const doc = root.ownerDocument || root, find = id => root.querySelector(`#${id}`);
  const body = find('dvbStreamTableBody'), groupSelect = find('dvbGroupSelect'), rail = find('dvbGroupNav').querySelector('.dvb-group-entries');
  const form = find('dvbGroupForm'), dialog = find('dvbGroupDialog'), name = find('dvbGroupName');
  const prev = find('dvbStreamsPrev'), next = find('dvbStreamsNext'), refresh = find('refreshDVBStreamsBtn');
  const controls = Object.fromEntries(Object.entries({q:'Search', status:'Status', delivery_system:'Delivery', requested_adapter:'RequestedAdapter', actual_adapter:'ActualAdapter', protocol:'Protocol', descrambling_state:'DescramblingState', descrambling_reason:'DescramblingReason', sort:'Sort', order:'Order', limit:'Limit'}).map(([key, suffix]) => [key, find(`dvbStreams${suffix}`)]));
  const groupActions = ['add', 'rename', 'delete', 'moveUp', 'moveDown'];
  const buttons = Object.fromEntries(groupActions.map((key, i) => [key, find(['addDVBGroupBtn','renameDVBGroupBtn','deleteDVBGroupBtn','moveDVBGroupUpBtn','moveDVBGroupDownBtn'][i])]));
  const rows = new Map(), groupButtons = new Map();
  const selected = new Set(), selectedItems = new Map();
  const bulk = Object.fromEntries(['Action','Group','AdapterMode','Card','Apply','Clear','Results'].map(key => [key,find(`dvbBulk${key}`)]));
  const selectPage = find('dvbSelectPage'), editorDialog = find('dvbStreamDialog'), scanDialog = find('dvb-scan-dialog');
  let active = false, life = 0, pageGeneration = 0, groupGeneration = 0, query = readView(), total = null;
  let pageRead, groupRead, groups = [], counts = {}, groupsReady = false, searchTimer, eventTimer, sequence = 0, pageFacets = {};
  let mutation, groupView, actionText = '', actionFailed = false, searchInvalid = false;
  let bulkLock, bulkOutcome, bulkText = '', bulkFailed = false, editorOpening = false, scanOpening = false, viewChange;
  let cards = [], cardsReady = false, cardsError = '', cardRead;
  const revisions = new Map(), runtimeSamples = new Map(), cardOwnership = new Map();
  const pendingRuntime = new Set();
  let runtimeTimer, nextRuntimeAt = 0;
  let nextPageReadAt = 0;
  let epoch = 0, facetRead, facetTimer, nextFacetAt = 0, liveState = 'stopped', liveReason = '', snapshotTime = '';
  let dirty = {page:false, groups:false, facets:false,cards:false};
  controls.q.setAttribute('aria-describedby','dvbStreamsError');

  function node(tag, text, className) {
    const el = doc.createElement(tag); if (text !== undefined) el.textContent = text;
    if (className) el.className = className; return el;
  }
  function text(el, value) { if (el.textContent !== value) el.textContent = value; }
  function message(id, value, failure = false) {
    if (id === 'dvbBulkNotice' || id === 'dvbGroupNotice') {
      const state = editorWriteState();
      if (state === 'saving') {value = 'Editor write is pending. Wait for its outcome before further writes.';failure = false;}
      else if (state === 'unknown') {value = 'Editor write outcome is unknown. Inspect server state independently; do not retry or submit other writes.';failure = true;}
      else if (scanWriteState()) {value = `Scan/import ${scanWriteState()}. Reopen Scan and Import to inspect or resume its read; other writes are blocked. Never repeat an unknown write.`;failure = scanWriteState().includes('unknown');}
    }
    const el = find(id); text(el, value); el.hidden = !value; el.setAttribute('role', failure ? 'alert' : 'status');
    el.classList.toggle('err', failure);
  }
  function action(value, failure = false) {
    actionText = value; actionFailed = failure;
    if (active) message('dvbGroupNotice', value, failure);
  }
  const editorBusy = () => editorOpening || !!editorDialog?.open || !!editorWriteState();
  const scanBusy = () => scanOpening || !!scanDialog?.open || !!scanWriteState();
  const otherWriteBusy = () => !!mutation || !!bulkLock || !!viewChange || editorBusy();
  const writeBusy = () => otherWriteBusy() || scanBusy();
  const controlsAllowed = () => canManage() || canControl();
  const bulkAllowed = action => canManage() ? bulkActions.some(([value]) => value === action) : canControl() && controlActions.includes(action);
  function syncBulkActions(reset = false) {
    const actions = bulkActions.filter(([value]) => bulkAllowed(value)), previous = bulk.Action.value;
    if (JSON.stringify([...bulk.Action.options].map(option => option.value)) !== JSON.stringify(actions.map(([value]) => value))) {
      bulk.Action.replaceChildren(...actions.map(([value,label]) => Object.assign(node('option',label),{value})));
    }
    bulk.Action.value = actions.some(([value]) => value === previous) ? previous : reset ? actions[0]?.[0] || '' : '';
  }
  function bulkMessage(value, failure = false) {
    bulkText = value; bulkFailed = failure;
    if (active) message('dvbBulkNotice',value,failure);
  }
  function setSelected(id, checked) {
    if (checked) {selected.add(id);if (rows.has(id)) selectedItems.set(id,rows.get(id).item);}
    else {selected.delete(id);selectedItems.delete(id);}
  }
  function clearSelection() {selected.clear();selectedItems.clear();}
  const canonicalDelivery = value => String(value || '').toLowerCase().replace(/[^a-z0-9]/g,'');
  const compatible = card => [...selected].every(id => {
    const delivery = canonicalDelivery(selectedItems.get(id)?.dvb?.delivery_system);
    return !!delivery && (card.delivery_systems || []).map(canonicalDelivery).includes(delivery);
  });
  const retainedCard = key => selected.size > 0 && [...selected].every(id => {
    const adapter = selectedItems.get(id)?.dvb?.adapter;
    return adapter?.mode === 'fixed' && adapter.device_key === key;
  });
  const available = card => card.present === true && card.config?.enabled !== false && ['available','active'].includes(card.status);
  function cardChoices() {
    const previous = bulk.Card.value;
    const entries = [Object.assign(node('option','Select a card'),{value:''})];
    for (const card of cards) {
      if (!compatible(card) && !retainedCard(card.device_key)) continue;
      const unavailable = !available(card);
      entries.push(Object.assign(node('option',`${shown(card.address)} / ${shown(card.model)} / ${shown(card.frontend_type)} / ${(card.delivery_systems || []).join(', ') || 'delivery unknown'} / ${shown(card.status)}${unavailable && retainedCard(card.device_key) ? ' (configured preference retained)' : ''}`),{
        value:card.device_key, disabled:!compatible(card) || unavailable && !retainedCard(card.device_key),
      }));
    }
    const missing = new Map();
    for (const id of selected) {
      const adapter = selectedItems.get(id)?.dvb?.adapter;
      if (adapter?.mode === 'fixed' && adapter.device_key && !entries.some(o => o.value === adapter.device_key)) missing.set(adapter.device_key,adapter.last_address);
    }
    for (const [key,address] of missing) entries.push(Object.assign(node('option',`Configured ${key} / ${shown(address)} / offline or unavailable; compatibility unverified`),{value:key,disabled:true}));
    if (previous && !entries.some(o => o.value === previous)) entries.push(Object.assign(node('option',`${previous} / no longer compatible or available`),{value:previous,disabled:true}));
    bulk.Card.replaceChildren(...entries);bulk.Card.value = previous;
  }
  function fixedCard() {
    const card = cards.find(card => card.device_key === bulk.Card.value);
    return cardsReady && card && compatible(card) && (available(card) || retainedCard(card.device_key)) ? card : null;
  }
  function loadCards() {
    if (!active || !canManage() || cardRead) return cardRead?.promise || Promise.resolve(false);
    const read = {abort:new AbortController(),life};cardRead = read;cardsReady = false;cardsError = '';bulkEnabled();
    read.promise = (async () => {
      try {
        const result = await loadBulkCards(requestJSON,{signal:read.abort.signal});
        if (cardRead !== read || !active || life !== read.life || read.stale) return false;
        cards = result;cardOwnership.clear();cardsReady = true;return true;
      } catch (reason) {
        if (cardRead === read) cardsError = `Card inventory unavailable or stale: ${reason?.message || reason}`;
        return false;
      } finally {if (cardRead === read) {cardRead = undefined;if (active) {bulkEnabled();scheduleRefresh();}}}
    })();
    return read.promise;
  }
  function renderBulkResults() {
    if (!active || !bulkOutcome) return;
    bulk.Results.hidden = false;
    const list = bulk.Results.querySelector('ul');
    list.replaceChildren(...bulkOutcome.ids.map(id => {
      const item = bulkOutcome.results.find(item => item.id === id), label = bulkOutcome.names.get(id) || id;
      return node('li',`${label} (${id})${rows.has(id) ? '' : ' - not on current page'}: ${item ? item.ok ? 'Succeeded' : `Failed - ${item.error}` : 'Outcome unknown - inspect server state'}`);
    }));
  }
  function bulkEnabled() {
    const manage = canManage(), control = controlsAllowed();
    if (!control) clearSelection();
    syncBulkActions();
    const locked = !active || !control || writeBusy() || !!groupView;
    const present = [...rows.keys()].filter(id => selected.has(id)).length;
    text(find('dvbSelectedCount'),String(selected.size));
    find('dvbBulkBar').hidden = !control;
    selectPage.closest('label').hidden = !control;
    selectPage.disabled = locked || total === null || !rows.size;
    selectPage.checked = rows.size > 0 && present === rows.size;
    selectPage.indeterminate = present > 0 && present < rows.size;
    for (const [id,row] of rows) {
      row.select.closest('label').hidden = !control;
      row.select.checked = selected.has(id);row.select.disabled = locked || total === null;
    }
    cardChoices();
    bulk.Action.disabled = locked;
    for (const key of ['Group','AdapterMode','Card']) bulk[key].disabled = locked || !manage;
    bulk.Group.closest('label').hidden = !manage || bulk.Action.value !== 'move_group';
    bulk.AdapterMode.closest('label').hidden = !manage || bulk.Action.value !== 'assign_adapter';
    bulk.Card.closest('label').hidden = !manage || bulk.Action.value !== 'assign_adapter' || bulk.AdapterMode.value !== 'fixed';
    bulk.Apply.disabled = locked || !bulkAllowed(bulk.Action.value) || !selected.size || bulk.Action.value === 'move_group' && (!groupsReady || !!bulk.Group.selectedOptions[0]?.disabled)
      || bulk.Action.value === 'assign_adapter' && bulk.AdapterMode.value === 'fixed' && !fixedCard();
    bulk.Clear.disabled = locked || !selected.size;
    find('dvbBulkBar').setAttribute('aria-busy',String(!!bulkLock && ['confirming','writing','readback'].includes(bulkLock.phase)));
    const fixed = cards.find(card => card.device_key === bulk.Card.value);
    const warning = bulk.AdapterMode.value !== 'fixed' ? '' : cardRead ? ' Loading bounded card inventory.' : !cardsReady ? ` ${cardsError || 'Card inventory unavailable; reload before fixed assignment.'}`
      : !fixedCard() ? ' Select a compatible, available card; offline or busy configured preferences remain visible.'
      : !available(fixed) ? ` Configured fixed preference retained: ${fixed.status}. This card is offline, busy or unavailable; successful tuning is not guaranteed.` : '';
    message('dvbBulkTargetNotice',bulk.Action.value === 'move_group' ? 'Group membership is organizational only; it does not change runtime.'
      : bulk.Action.value === 'assign_adapter' ? `Requested preference, not actual placement. Availability and tuning are not guaranteed.${warning}` : '');
    message('dvbBulkNotice',bulkText || 'Select streams on this page to apply an action.',bulkFailed);
  }
  async function edit(id) {
    if (!active || !canManage() || writeBusy() || groupView || typeof openEditor !== 'function') return;
    editorOpening = true; groupEnabled();
    try {await openEditor(id);} finally {editorOpening = false;groupEnabled();}
  }
  async function scan() {
    // Its own known/unknown job may be reopened, but not over another writer.
    if (!active || !canManage() || otherWriteBusy() || groupView || scanOpening || scanDialog?.open || typeof openScan !== 'function') return;
    scanOpening = true;groupEnabled();
    try {await openScan();} finally {scanOpening = false;groupEnabled();}
  }
  async function applyBulk() {
    if (!active || !bulkAllowed(bulk.Action.value) || writeBusy() || groupView || !selected.size || bulk.Apply.disabled) return;
    const ids = [...selected], action = bulk.Action.value;
    const payload = {action,ids}, names = new Map(ids.map(id => [id,selectedItems.get(id)?.name || id]));
    let target = '';
    if (action === 'move_group') {payload.group_id = bulk.Group.value;target = groupName(payload.group_id);}
    if (action === 'assign_adapter') {
      if (bulk.AdapterMode.value === 'fixed') {
        const card = fixedCard();if (!card) return;
        payload.adapter = {mode:'fixed',device_key:card.device_key,...(typeof card.address === 'string' && card.address ? {last_address:card.address} : {})};
        target = bulk.Card.selectedOptions[0].textContent;
      } else {payload.adapter = {mode:'auto'};target = 'Auto';}
    }
    const lock = {phase:'confirming',life}; bulkLock = lock; groupEnabled();
    try {
      if (['assign_adapter','delete'].includes(action)) {
        const prompt = action === 'delete' ? `Delete ${ids.length} selected streams permanently? This interrupts their outputs and cannot be undone.`
          : `Assign adapter for ${ids.length} selected streams to ${target}? This may interrupt outputs. Requested preference is not actual placement or a guarantee of tuning.`;
        if (!await confirmAction(prompt) || !active || lock.life !== life) return;
      }
      if (!active || lock.life !== life || !bulkAllowed(action)) return;
      lock.phase = 'writing';cancelDebounce();invalidatePage();invalidateGroups();groupEnabled();
      bulkMessage(`Applying ${action} to ${ids.length} streams. Do not repeat this request.`);
      let response, failure;
      try {response = await requestJSON('/api/v1/dvb-streams/bulk',{method:'POST',body:JSON.stringify(payload)});}
      catch (reason) {failure = reason;response = reason?.body;}
      if (failure && bulkRejected(failure)) {
        bulkMessage(`Bulk request rejected before admission: ${bulkErrorText(response) || failure.message}. Correct the request before retrying.`,true);
        return;
      }
      const result = analyzeBulkResult(response,ids);
      bulkOutcome = {...result,ids,names};
      for (const item of result.results) if (item.ok) setSelected(item.id,false);
      renderBulkResults();
      const summary = `${result.succeeded} succeeded, ${result.failed} failed`;
      const aggregate = bulkErrorText(response);
      if (!result.complete) {
        lock.phase = 'unknown';
        bulkMessage(`${summary}${result.unknown ? `, ${result.unknown} unknown` : ''}. Bulk outcome unknown or inconsistent. Do not retry; inspect server state independently before further writes.`,true);
        return;
      }
      lock.phase = 'readback';
      const notice = `${summary}.${aggregate ? ` Server error: ${aggregate}.` : ''}`;
      bulkOutcome.notice = notice;
      bulkMessage(notice,result.failed > 0 || !!aggregate);
      if (!active) {lock.phase = 'readback-failed';bulkMessage(`${notice} Snapshot readback pending; Refresh before further writes.`,true);return;}
      invalidatePage();invalidateGroups();
      const readback = await Promise.all([loadGroups(),loadPage()]);
      if (!active || !readback.every(Boolean)) {
        lock.phase = 'readback-failed';
        bulkMessage(`${notice} Write results are known, but snapshot readback failed. Refresh to verify; do not resend completed IDs.`,true);
      }
    } catch (reason) {
      if (lock.phase !== 'confirming') lock.phase = 'unknown';
      bulkMessage(lock.phase === 'unknown' ? 'Bulk outcome unknown. Do not retry; inspect server state independently.' : `Confirmation failed: ${reason?.message || reason}`,true);
    } finally {
      if (bulkLock === lock && !['unknown','readback-failed'].includes(lock.phase)) bulkLock = undefined;
      if (active) groupEnabled();
    }
  }
  function freshness() {
    text(find('dvbStreamsFreshness'), `${liveState === 'live' ? dirty.page || pageRead ? 'Syncing current view; latest completed snapshot shown.' : 'Live updates connected.' : `${liveState}; snapshot is not live.`}${snapshotTime ? ` Snapshot read ${snapshotTime}.` : ''}${liveReason ? ` ${liveReason}` : ''}`);
  }
  function setLiveState({state, reason = ''} = {}) {
    liveState = ['connecting','syncing','live','reconnecting','stopped'].includes(state) ? state : 'stopped';
    liveReason = String(reason || ''); freshness();
  }
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const nullableObject = value => value === null || object(value);
  const validRuntime = value => object(value) && typeof value.state === 'string'
    && nullableObject(value.signal) && nullableObject(value.placement)
    && (value.bitrate_kbps === undefined || Number.isFinite(value.bitrate_kbps));
  const mergeEvent = (item, event) => event.payload.mode === 'replace' ? event.payload.resource : {...item,runtime:event.payload.runtime};
  function remember(event) {
    const key = `${event.kind.split('.')[1]}:${event.resource_id || ''}`;
    if (!Number.isSafeInteger(event.revision) || event.revision < 1) return false;
    if (event.revision <= (revisions.get(key) || 0)) return null;
    revisions.delete(key); revisions.set(key,event.revision);
    // The outer feed checks all resource revisions. Retain only a bounded local guard.
    if (revisions.size > 1024) revisions.delete(revisions.keys().next().value);
    return true;
  }
  function queueRefresh(flags) {
    for (const key of Object.keys(dirty)) if (flags[key]) dirty[key] = true;
    if (flags.page) freshness();
    if (flags.groups && groupRead) groupRead.discard = true;
    scheduleRefresh();
  }
  function scheduleRefresh() {
    if (!active || searchTimer) return;
    if (dirty.facets && !dirty.page && !facetRead && !pageRead && !facetTimer) {
      facetTimer = setTimeout(() => {
        facetTimer = undefined;
        if (active && dirty.facets && !dirty.page && !pageRead) {dirty.facets = false;void loadFacets();}
      },Math.max(0,nextFacetAt - Date.now()));
    }
    if (eventTimer || !(dirty.page && !pageRead || dirty.groups && !groupRead || dirty.cards && !cardRead)) return;
    eventTimer = setTimeout(() => {
      eventTimer = undefined;
      if (!active) return;
      if (dirty.cards && !cardRead) {dirty.cards = false;void loadCards();}
      if (dirty.groups && !groupRead) {dirty.groups = false;void loadGroups();}
      if (dirty.page && !pageRead && Date.now() >= nextPageReadAt) {dirty.page = false;dirty.facets = false;nextPageReadAt = Date.now() + 1000;void loadPage();}
      scheduleRefresh();
    },dirty.groups || dirty.cards ? 100 : Math.max(100,nextPageReadAt - Date.now()));
  }
  async function loadFacets() {
    const view = {...query,page:1,limit:50}, owner = life, token = pageGeneration;
    const read = {abort:new AbortController()}; facetRead = read;nextFacetAt = Date.now() + 1000;
    try {
      // API minimum is 50. These records are discarded; this is not a page load.
      const result = await requestJSON(requestPath(view),{signal:read.abort.signal});
      if (!active || owner !== life || token !== pageGeneration || facetRead !== read || read.abort.signal.aborted) return;
      if (!validPage(result,view)) throw new Error('Invalid bounded facet response');
      syncControls(result.facets);
    } catch (reason) {
      if (facetRead === read && !read.abort.signal.aborted) message('dvbStreamsError',`Facets stale: ${reason?.message || reason}`,true);
    } finally {if (facetRead === read) {facetRead = undefined;scheduleRefresh();}}
  }
  const runtimeFacets = value => ({state:String(value?.state || '').trim().toLowerCase(),actual:String(value?.placement?.actual_card_id || '').trim() || 'unassigned',descrambling_state:value?.descrambling?.state || '',descrambling_reason:value?.descrambling?.reason || ''});
  function runtimeChanges(before, after) {
    const old = before, next = runtimeFacets(after);
    return Object.fromEntries(Object.keys(next).map(key => [key,!old || old[key] !== next[key]]));
  }
  function runtimeAffectsQuery(changes) {
    return changes.state && (!!query.status || ['status','state'].includes(query.sort))
      || changes.actual && (!!query.actual_adapter || !!query.q || query.sort === 'actual_adapter')
      || changes.descrambling_state && !!query.descrambling_state || changes.descrambling_reason && !!query.descrambling_reason;
  }
  function replacementAffectsQuery(before, after) {
    const fields = new Set(['group_id','protocol']);
    if (query.q) for (const key of ['name','input_url','output_url','dvb','runtime']) fields.add(key);
    if (query.status) fields.add('runtime');
    const changes = runtimeChanges(runtimeFacets(before.runtime),after.runtime);
    if (query.descrambling_state && changes.descrambling_state || query.descrambling_reason && changes.descrambling_reason) return true;
    if (query.actual_adapter) fields.add('runtime');
    if (query.requested_adapter || query.delivery_system) fields.add('dvb');
    const sortFields = {name:['name'],id:[],group:['group_id'],group_id:['group_id'],status:['runtime'],state:['runtime'],actual_adapter:['runtime'],requested_adapter:['dvb'],service:['dvb'],service_id:['dvb'],transponder:['dvb'],frequency:['dvb'],frequency_khz:['dvb'],output:['output_url'],output_url:['output_url'],protocol:['protocol'],updated:['updated_at'],updated_at:['updated_at'],updated_time:['updated_at']};
    for (const key of sortFields[query.sort] || []) fields.add(key);
    return [...fields].some(key => JSON.stringify(before[key]) !== JSON.stringify(after[key]));
  }
  function rememberRuntime(id, runtime) {
    runtimeSamples.delete(id);runtimeSamples.set(id,runtimeFacets(runtime));
    if (runtimeSamples.size > 1024) runtimeSamples.delete(runtimeSamples.keys().next().value);
  }
  function bufferEvent(event) {
    if (!pageRead) return;
    const id = event.resource_id, previous = pageRead.events.get(id);
    pageRead.events.delete(id);
    pageRead.events.set(id,event.payload.mode === 'runtime' && previous?.payload.mode === 'replace'
      ? {...event,payload:{mode:'replace',resource:mergeEvent(previous.payload.resource,event)}} : event);
    if (pageRead.events.size > 256) {
      // Never evict a rendered row's newer fields. Unknown off-page overflow
      // requests another snapshot, but cannot veto every completed snapshot.
      const evict = [...pageRead.events.keys()].find(key => !rows.has(key));
      pageRead.events.delete(evict);queueRefresh({page:true});
    }
  }
  function matchesView(item, view) {
    const dvb = item.dvb || {}, rt = runtimeFacets(item.runtime), adapter = dvb.adapter || {};
    const requested = !adapter.mode || adapter.mode === 'auto' ? 'auto' : adapter.device_key || (adapter.last_address ? `address:${adapter.last_address}` : '');
    if (view.status && rt.state !== view.status || view.actual_adapter && rt.actual !== view.actual_adapter
      || view.descrambling_state && rt.descrambling_state !== view.descrambling_state || view.descrambling_reason && rt.descrambling_reason !== view.descrambling_reason
      || view.requested_adapter && requested !== view.requested_adapter || view.group !== null && (item.group_id || '') !== view.group
      || view.protocol && item.protocol !== view.protocol || view.delivery_system && canonicalDelivery(dvb.delivery_system) !== view.delivery_system) return false;
    const haystack = [item.id,item.name,item.input_url,item.output_url,item.group_id,item.protocol,dvb.delivery_system,dvb.polarization,dvb.frequency_khz,dvb.service_id,requested,rt.actual].join(' ').toLowerCase();
    return !view.q || haystack.includes(view.q.trim().toLowerCase());
  }
  // HTTP retains diagnostics; SSE projects nonempty errors to "card unavailable".
  const ownershipKey = value => JSON.stringify([value?.active_sessions > 0,value?.active_streams > 0,!!value?.current_transport,!!value?.last_error]);
  function cardEventAffectsAvailability(event) {
    if (event.kind === 'dvb.card.removed' || event.payload?.mode !== 'ownership') {cardOwnership.delete(event.resource_id);return true;}
    const value = event.payload.ownership;
    if (!object(value) || !Number.isSafeInteger(value.active_sessions) || !Number.isSafeInteger(value.active_streams) || value.active_sessions < 0 || value.active_streams < 0
      || !['application','current_transport','signal'].every(key => nullableObject(value[key])) || typeof value.last_error !== 'string') return true;
    const id = event.resource_id, cached = cards.find(card => card.id === id);
    const previous = cardOwnership.get(id) ?? (cached ? ownershipKey(cached) : undefined), next = ownershipKey(value);
    cardOwnership.delete(id);cardOwnership.set(id,next);
    if (cardOwnership.size > 1024) cardOwnership.delete(cardOwnership.keys().next().value);
    return previous !== next;
  }
  function applyEvent(event) {
    if (active && canManage() && (['dvb.card.changed','dvb.card.removed'].includes(event?.kind) && cardEventAffectsAvailability(event) || event?.kind === 'dvb.collection.changed' && event.payload?.cards === true)) {
      const needed = cardsReady || !!cardRead || bulk.Action.value === 'assign_adapter';
      cardsReady = false;
      if (cardRead) cardRead.stale = true;
      if (needed) queueRefresh({cards:true});
    }
    if (!active || !['dvb.stream.changed','dvb.stream.removed','dvb.group.changed','dvb.group.removed','dvb.collection.changed'].includes(event?.kind)) return;
    const accepted = remember(event); if (accepted === null) return;
    if (!accepted || !object(event.payload)) {queueRefresh({page:true,groups:true});return;}
    const payload = event.payload;
    if (event.kind === 'dvb.collection.changed') {
      if (payload.mode !== 'invalidate') {queueRefresh({page:true,groups:true});return;}
      queueRefresh({page:payload.streams === true,groups:payload.groups === true});return;
    }
    if (event.kind.startsWith('dvb.group.')) {
      queueRefresh({groups:true,page:event.kind.endsWith('.removed') || payload.mode === 'remove' || ['group','group_id'].includes(query.sort)});return;
    }
    const id = event.resource_id, row = rows.get(id);
    const runtime = payload.mode === 'runtime' && validRuntime(payload.runtime);
    const replacement = payload.mode === 'replace' && object(payload.resource) && payload.resource.id === id
      && typeof payload.resource.name === 'string' && object(payload.resource.dvb) && validRuntime(payload.resource.runtime);
    if (id && (event.kind.endsWith('.removed') || payload.mode === 'remove')) {
      runtimeSamples.delete(id);bufferEvent({...event,payload:{mode:'remove'}});queueRefresh({page:true,groups:true});return;
    }
    if (!id || !runtime && !replacement) {queueRefresh({page:true,groups:true});return;}
    bufferEvent(event);
    const item = row ? mergeEvent(row.item,event) : null;
    const changes = runtime ? runtimeChanges(row ? runtimeFacets(row.item.runtime) : runtimeSamples.get(id),payload.runtime) : null;
    const affects = runtime ? runtimeAffectsQuery(changes) : !row || replacementAffectsQuery(row.item,item);
    const facetsChanged = !runtime || changes.state || changes.actual;
    rememberRuntime(id,runtime ? payload.runtime : payload.resource.runtime);
    if (row) {
      if (replacement) patchRow(row,item);
      else {setRowItem(row,item);queueRuntimePaint(row);}
    }
    // Unknown previous off-page values cannot safely be subtracted from facets.
    queueRefresh({page:affects,facets:!affects && facetsChanged,groups:replacement});
  }
  async function synchronize({signal, revision} = {}) {
    if (!active || signal?.aborted) throw new Error('Stream synchronization inactive or aborted');
    const owner = life, token = ++epoch;
    const refreshCards = cardsReady || !!cardRead || bulk.Action.value === 'assign_adapter';
    cardRead?.abort.abort();cardRead = undefined;cardsReady = false;
    revisions.clear();runtimeSamples.clear();cardOwnership.clear();nextPageReadAt = 0; dirty = {page:false,groups:false,facets:false,cards:refreshCards};
    cancelRuntimePaint();
    clearTimeout(eventTimer);eventTimer = undefined;clearTimeout(facetTimer);facetTimer = undefined;
    invalidatePage();invalidateGroups();facetRead?.abort.abort();facetRead = undefined;
    setLiveState({state:'syncing'});scheduleRefresh();
    let rejectAbort;
    const cancelled = new Promise((_,reject) => {rejectAbort = reject;});
    const abort = () => {
      if (token === epoch) {invalidatePage();invalidateGroups();}
      rejectAbort(new Error('Stream synchronization aborted'));
    };
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const results = await Promise.race([Promise.all([loadGroups(),loadPage()]),cancelled]);
      if (!active || owner !== life || token !== epoch || signal?.aborted || !results.every(Boolean)) throw new Error('Stream synchronization failed or superseded');
      return true;
    } finally {signal?.removeEventListener('abort',abort);}
  }
  function cancelDebounce() { clearTimeout(facetTimer);facetTimer = undefined; clearTimeout(searchTimer); searchTimer = undefined; clearTimeout(eventTimer); eventTimer = undefined; }
  function invalidatePage() { ++pageGeneration; pageRead?.abort.abort(); pageRead = undefined; }
  function invalidateGroups() { ++groupGeneration; groupRead?.abort.abort(); groupRead = undefined; }
  function persist() {
    window.history.replaceState(null, '', viewHash(query));
    try { window.sessionStorage.setItem(storageKey, JSON.stringify(nondefaults(query))); } catch { /* Storage can be disabled; URL still preserves the view. */ }
  }
  function validateSearchInput() {
    const wasInvalid = searchInvalid;
    searchInvalid = !searchWithinLimit(controls.q.value);
    const feedback = searchInvalid ? 'Search must be at most 256 UTF-8 bytes. Shorten the text to apply it; the previous snapshot is retained.' : '';
    controls.q.setAttribute('aria-invalid',String(searchInvalid)); controls.q.setCustomValidity(feedback);
    if (searchInvalid) {message('dvbStreamsError',feedback,true);message('dvbStreamsLoading','');}
    else if (wasInvalid) message('dvbStreamsError','');
    return !searchInvalid;
  }
  function options(control, values, current, first) {
    const entries = [...new Set([...values, ...(current ? [current] : [])])];
    const items = first ? [Object.assign(node('option', first), {value:''})] : [];
    items.push(...entries.filter(v => v !== '').map(value => Object.assign(node('option', value), {value})));
    control.replaceChildren(...items); control.value = current;
  }
  function syncControls(facets = pageFacets) {
    pageFacets = facets;
    const maps = {status:'statuses', delivery_system:'delivery_systems', protocol:'protocols', requested_adapter:'requested_adapters', actual_adapter:'actual_adapters', descrambling_state:'descrambling_states', descrambling_reason:'descrambling_reasons'};
    for (const [key, field] of Object.entries(maps)) {
      const values = [...(enums[key] || []), ...Object.keys(facets[field] || {})].filter(v => !enums[key] || enums[key].includes(v));
      options(controls[key], values, query[key], key.includes('adapter') ? 'All adapters' : key.startsWith('descrambling_') ? `All descrambling ${key.endsWith('state') ? 'states' : 'reasons'}` : `All ${key === 'status' ? 'statuses' : key === 'protocol' ? 'protocols' : 'systems'}`);
    }
    options(controls.sort, enums.sort, query.sort);
    for (const key of ['q','limit','order']) if (key !== 'q' || !searchTimer && !searchInvalid) controls[key].value = query[key];
    groupSelect.value = groupOption(query.group);
  }
  function pager() {
    const manage = canManage();
    find('addDVBStreamBtn').hidden = !manage;
    find('openDVBScanBtn').hidden = !manage;
    const primary = find('addDVBStreamBtn').closest('.dvb-primary-actions');
    if (primary) primary.hidden = !controlsAllowed();
    find('addDVBStreamBtn').disabled = !active || !manage || typeof openEditor !== 'function' || writeBusy() || !!groupView;
    find('openDVBScanBtn').disabled = !active || !manage || typeof openScan !== 'function' || otherWriteBusy() || !!groupView || scanOpening || !!scanDialog?.open;
    for (const row of rows.values()) if (row.edit) {row.edit.hidden = !manage;row.edit.disabled = !active || !manage || writeBusy() || !!groupView;}
    text(find('dvbStreamsPageInfo'), total === null ? 'Page - of -' : `Page ${query.page} of ${Math.max(1, Math.ceil(total / query.limit))} / ${total} matching streams`);
    prev.disabled = !active || searchInvalid || !!pageRead || total === null || query.page <= 1;
    next.disabled = !active || searchInvalid || !!pageRead || total === null || query.page * query.limit >= total;
    refresh.disabled = !active || !!pageRead || !!groupRead || !!mutation && mutation.phase !== 'unknown' || !!bulkLock && !['unknown','readback-failed'].includes(bulkLock.phase);
    bulkEnabled();
  }
  function groupEnabled() {
    const index = groups.findIndex(g => g.id === query.group), editable = groupsReady && index >= 0;
    const manage = canManage(), actions = buttons.add.closest('.dvb-group-actions');
    if (actions) actions.hidden = !manage;
    for (const button of Object.values(buttons)) button.hidden = !manage;
    buttons.add.disabled = !active || !manage || !groupsReady || writeBusy();
    for (const key of ['rename','delete']) buttons[key].disabled = !active || !manage || !editable || writeBusy();
    buttons.moveUp.disabled = !active || !manage || !editable || index <= 0 || writeBusy();
    buttons.moveDown.disabled = !active || !manage || !editable || index >= groups.length - 1 || writeBusy();
    const busy = !!mutation && mutation.phase !== 'unknown';
    find('dvbGroupSave').hidden = !manage;
    find('dvbGroupSave').disabled = !active || !manage || writeBusy() || !!groupView?.saved || !groupsReady;
    find('dvbGroupCancel').disabled = busy; name.disabled = !manage || busy || !!groupView?.saved || mutation?.phase === 'unknown';
    form.setAttribute('aria-busy', String(busy));
    if (active) message('dvbGroupNotice',actionText,actionFailed);
    pager();
  }
  function renderGroups() {
    const summary = groupCounts(groups, counts), displayCount = value => value === null ? 'unknown' : String(value);
    const entries = [{id:null,name:'All Streams',count:summary.all}, {id:'',name:'Ungrouped',count:summary.ungrouped}, ...groups.map(g => ({...g,count:countValue(Object.hasOwn(counts,g.id) ? counts[g.id] : null)}))];
    if (query.group && !groups.some(g => g.id === query.group)) entries.push({id:query.group,name:`Unavailable group: ${query.group}`,count:null});
    const keep = new Set(), ordered = [];
    for (const entry of entries) {
      const key = groupOption(entry.id), caption = `${entry.name} (${displayCount(entry.count)})`; keep.add(key);
      let button = groupButtons.get(key);
      if (!button) {
        button = node('button'); button.type = 'button'; button.dataset.group = key;
        button.append(node('span', '', 'dvb-group-entry-name'), node('span', '', 'dvb-group-entry-count'));
        button.addEventListener('click', () => change({group:entry.id})); groupButtons.set(key,button);
      }
      text(button.firstChild,entry.name); text(button.lastChild,` (${displayCount(entry.count)})`);
      button.title = caption; button.setAttribute('aria-pressed',String(query.group === entry.id));
      button.disabled = !active; ordered.push(button);
    }
    for (const [key, button] of groupButtons) if (!keep.has(key)) {button.remove(); groupButtons.delete(key);}
    ordered.forEach((el,index) => {if (rail.children[index] !== el) rail.insertBefore(el,rail.children[index] || null);});
    groupSelect.replaceChildren(...entries.map(g => Object.assign(node('option',`${g.name} (${displayCount(g.count)})`),{value:groupOption(g.id)})));
    groupSelect.value = groupOption(query.group); groupEnabled();
    const target = bulk.Group.value;
    bulk.Group.replaceChildren(...[{id:'',name:'Ungrouped'},...groups].map(g => Object.assign(node('option',g.name),{value:g.id})));
    if (target && ![...bulk.Group.options].some(o => o.value === target)) bulk.Group.append(Object.assign(node('option',`Unavailable group: ${target}`),{value:target,disabled:true}));
    bulk.Group.value = target;bulkEnabled();
  }
  const groupName = id => id === '' || id === undefined ? 'Ungrouped' : groups.find(g => g.id === id)?.name || id;
  function setRowItem(row, item) {
    row.item = item;
    if (selected.has(item.id)) selectedItems.set(item.id,item);
  }
  function cancelRuntimePaint() {
    clearTimeout(runtimeTimer);runtimeTimer = undefined;pendingRuntime.clear();
  }
  function patchRuntime(row) {
    const item = row.item, runtime = item.runtime || {}, actual = runtime.placement;
    text(row.actual, actual?.actual_card_id ? `${actual.actual_card_id}\n${shown(actual.actual_address)}` : 'Unassigned / actual card unavailable');
    text(row.status, `${shown(item.protocol)} / ${shown(runtime.state)}`);
    text(row.descrambling, descramblingText(runtime.descrambling));
    text(row.metrics, `${Number.isFinite(runtime.bitrate_kbps) ? runtime.bitrate_kbps + ' kbps' : 'Bitrate unavailable'}\nSignal ${metric(runtime.signal?.signal_percent,'%')} / SNR ${metric(runtime.signal?.snr_percent,'%')}`);
    if (row.detail) text(row.raw, JSON.stringify(item, null, 2));
    row.renderedRuntime = JSON.stringify([item.protocol,runtime]);
  }
  function queueRuntimePaint(row) {
    if (row.renderedRuntime === JSON.stringify([row.item.protocol,row.item.runtime || {}])
      && (!row.detail || row.raw.textContent === JSON.stringify(row.item,null,2))) return;
    pendingRuntime.add(row.item.id);
    if (runtimeTimer !== undefined || !active) return;
    const owner = life, boundary = epoch;
    // One visible-page cadence, not one timeout per stream. Read the latest model at paint time.
    runtimeTimer = setTimeout(() => {
      runtimeTimer = undefined;
      if (!active || owner !== life || boundary !== epoch) {pendingRuntime.clear();return;}
      nextRuntimeAt = Date.now() + 1000;
      for (const id of pendingRuntime) {const current = rows.get(id);if (current) patchRuntime(current);}
      pendingRuntime.clear();
    },Math.max(0,nextRuntimeAt - Date.now()));
  }
  function patchRow(row, item) {
    setRowItem(row,item);
    row.select.setAttribute('aria-label',`Select ${item.name || item.id} (${item.id})`);
    const dvb = item.dvb || {}, adapter = dvb.adapter || {};
    text(row.name, shown(item.name)); text(row.group, groupName(item.group_id));
    text(row.transport, `Service ${shown(dvb.service_id)}${dvb.service?.name ? ` / ${dvb.service.name}` : ''}\n${shown(dvb.delivery_system)} / ${Number.isFinite(dvb.frequency_khz) ? dvb.frequency_khz / 1000 + ' MHz' : 'frequency unavailable'}\n${metric(dvb.symbol_rate / 1000, ' kSym/s')} / Pol ${shown(dvb.polarization)}`);
    text(row.requested, adapter.mode === 'auto' ? 'Auto' : adapter.mode === 'fixed' ? `Fixed\n${shown(adapter.device_key || adapter.last_address)}` : 'Requested card unavailable');
    text(row.output, shown(item.output_url));
    row.outputDetails.hidden = typeof item.output_url !== 'string' || !item.output_url;
    if (row.renderedRuntime === undefined) {patchRuntime(row);nextRuntimeAt = Date.now() + 1000;}
    else queueRuntimePaint(row);
  }
  function createRow(item) {
    const tr = node('tr'); tr.dataset.streamId = item.id;
    const cells = labels.map(label => {const td = node('td'); td.dataset.label = label; tr.append(td); return td;});
    const row = {tr, name:node('strong'),group:node('span',undefined,'dvb-stream-group'),transport:node('div'),requested:node('div'),actual:node('div'),output:node('code',undefined,'url-value'),status:node('div'),descrambling:node('div',undefined,'hint dvb-stream-descrambling'),metrics:node('div',undefined,'hint')};
    row.select = node('input');row.select.type = 'checkbox';
    row.select.addEventListener('change',() => {
      if (!active || !controlsAllowed() || writeBusy() || groupView || total === null) {bulkEnabled();return;}
      setSelected(item.id,row.select.checked);bulkEnabled();
    });
    const selection = node('label',undefined,'dvb-stream-select');selection.append(row.select,node('span','Select'));
    const detailID = `dvb-stream-detail-${++sequence}`, toggle = node('button','Details');
    toggle.type = 'button'; toggle.setAttribute('aria-expanded','false');
    toggle.addEventListener('click', () => {
      if (row.detail) {
        row.detail.remove(); row.detail = null; row.raw = null;
        toggle.removeAttribute('aria-controls'); toggle.setAttribute('aria-expanded','false');
      } else {
        const detail = node('tr',undefined,'dvb-stream-details'), cell = node('td');
        cell.colSpan = labels.length; detail.id = detailID;
        row.raw = node('pre',JSON.stringify(row.item,null,2)); row.detail = detail;
        cell.append(row.raw); detail.append(cell); tr.after(detail);
        toggle.setAttribute('aria-controls',detailID); toggle.setAttribute('aria-expanded','true');
      }
    });
    const output = node('details',undefined,'dvb-stream-output'); output.append(node('summary','Output URL'),row.output);
    row.outputDetails = output;
    cells[0].append(selection,row.name,row.group,toggle);cells[1].append(row.transport);cells[2].append(row.requested);cells[3].append(row.actual);cells[4].append(row.status,row.descrambling,output,row.metrics);
    if (typeof openEditor === 'function') {
      row.edit = node('button','Edit'); row.edit.type = 'button';
      row.edit.addEventListener('click', () => {void edit(row.item.id);});
      cells[0].append(row.edit);
    }
    return row;
  }
  function renderRows(items) {
    const focus = doc.activeElement, keep = new Set(), ordered = [];
    for (const item of items) {
      let row = rows.get(item.id); if (!row) {row = createRow(item); rows.set(item.id,row);}
      patchRow(row,item); keep.add(item.id); ordered.push(row.tr); if (row.detail) ordered.push(row.detail);
    }
    for (const [id,row] of rows) if (!keep.has(id)) {row.tr.remove();row.detail?.remove();rows.delete(id);pendingRuntime.delete(id);}
    if (!pendingRuntime.size) cancelRuntimePaint();
    // Do not detach unchanged keyed nodes: their disclosures and focus are native state.
    ordered.forEach((el,index) => {if (body.children[index] !== el) body.insertBefore(el,body.children[index] || null);});
    if (focus !== doc.activeElement && focus?.isConnected && body.contains(focus)) focus.focus({preventScroll:true});
    bulkEnabled();renderBulkResults();
  }
  function loadPage() {
    if (!active) return Promise.resolve(false);
    if (pageRead) return pageRead.promise;
    const view = {...query}, token = ++pageGeneration, owner = life, abort = new AbortController();
    const current = () => active && owner === life && token === pageGeneration && !abort.signal.aborted;
    clearTimeout(facetTimer);facetTimer = undefined;nextFacetAt = Date.now() + 1000;
    const read = {abort,events:new Map()}; pageRead = read; dirty.page = false; dirty.facets = false; pager(); message('dvbStreamsLoading','Loading bounded stream snapshot...');
    read.promise = (async () => {
      try {
        onPageLoad();
        let result = await requestJSON(requestPath(view),{signal:abort.signal});
        if (!current()) return false;
        if (!validPage(result,view)) throw new Error('Invalid bounded stream page response');
        const last = Math.max(1,Math.ceil(result.total / view.limit));
        if (view.page > last) {
          view.page = last; query.page = last; persist();
          onPageLoad();
          result = await requestJSON(requestPath(view),{signal:abort.signal});
          if (!current()) return false;
          if (!validPage(result,view) || view.page > Math.max(1,Math.ceil(result.total / view.limit))) throw new Error('Stream total changed again; Refresh to retry the bounded page');
        }
        // Commit useful snapshot progress even when a follow-up is pending.
        result.items = result.items.flatMap(item => {
          const event = read.events.get(item.id);
          if (event?.payload.mode === 'remove') return [];
          const value = event ? mergeEvent(item,event) : item;
          return event && !matchesView(value,view) ? [] : [value];
        });
        total = result.total; renderRows(result.items); syncControls(result.facets); renderGroups();
        message('dvbStreamsError',''); message('dvbStreamsEmpty',total === 0 ? 'No streams match these filters.' : '');
        snapshotTime = new Date().toLocaleTimeString();freshness();
        return true;
      } catch (reason) {
        if (current()) {message('dvbStreamsError',`${rows.size ? 'Snapshot stale; previous rows retained' : 'Snapshot unavailable'}: ${reason?.message || reason}`,true); message('dvbStreamsEmpty','');}
        return false;
      } finally {if (current()) {pageRead = undefined;message('dvbStreamsLoading','');pager();freshness();scheduleRefresh();}}
    })();
    return read.promise;
  }
  function loadGroups() {
    if (!active) return Promise.resolve(false);
    if (groupRead) return groupRead.promise;
    const token = ++groupGeneration, owner = life, abort = new AbortController();
    const current = () => active && owner === life && token === groupGeneration && !abort.signal.aborted;
    const read = {abort}; groupRead = read; dirty.groups = false; pager();
    read.promise = (async () => {
      try {
        const result = await requestJSON('/api/v1/dvb-groups',{signal:abort.signal});
        if (!current()) return false;
        const collection = result?.groups === null ? [] : result?.groups;
        if (!Array.isArray(collection) || collection.some(g => !g || typeof g.id !== 'string' || !g.id || g.id.toLowerCase() === 'ungrouped' || typeof g.name !== 'string') || new Set(collection.map(g => g.id)).size !== collection.length) throw new Error('Ambiguous or invalid group response');
        if (read.discard) return false;
        groups = collection; counts = result.counts && typeof result.counts === 'object' ? result.counts : {}; groupsReady = true;
        renderGroups(); for (const row of rows.values()) text(row.group,groupName(row.item.group_id));
        message('dvbGroupsError',''); if (!actionText) action('Global group counts. Select one group per stream.');
        return true;
      } catch (reason) {if (current()) {groupsReady = false;groupEnabled();message('dvbGroupsError',`Group snapshot unavailable or stale: ${reason?.message || reason}`,true);} return false;}
      finally {if (current()) {groupRead = undefined;pager();scheduleRefresh();}}
    })();
    return read.promise;
  }
  function resync() {
    if (!active) return Promise.resolve(false);
    if (viewChange || bulkLock && ['confirming','writing','readback'].includes(bulkLock.phase)) return Promise.resolve(false);
    cancelDebounce();
    if (!validateSearchInput()) {pager();return loadGroups().then(() => false);}
    if (controls.q.value !== query.q) {
      return change({q:controls.q.value},true);
    }
    return Promise.all([loadGroups(),loadPage()]).then(results => {
      const success = results.every(Boolean);
      if (success && bulkLock?.phase === 'readback-failed') {
        bulkLock = undefined;bulkMessage(`${bulkOutcome.notice} Snapshot verified; completed IDs remain deselected.`,bulkOutcome.failed > 0);groupEnabled();
      }
      return success;
    });
  }
  async function adoptView(nextView) {
    if (JSON.stringify(nextView) === JSON.stringify(query)) {syncControls();persist();return true;}
    if (viewChange || bulkLock) {syncControls();persist();return false;}
    if (selected.size) {
      const lock = {life};viewChange = lock;groupEnabled();
      let accepted = false;
      try {accepted = await confirmAction(`Change this stream view and clear ${selected.size} selected IDs? Selection applies to the current page, not all matching streams.`);}
      finally {if (viewChange === lock) viewChange = undefined;}
      if (!accepted || !active || life !== lock.life) {if (active) {syncControls();persist();groupEnabled();}return false;}
      clearSelection();
    }
    cancelRuntimePaint();invalidatePage();query = nextView;total = null;syncControls();persist();renderGroups();return true;
  }
  async function change(values, refreshGroups = false) {
    if (!active) return false;
    cancelDebounce();
    if (!validateSearchInput()) {
      for (const key of Object.keys(values)) if (controls[key] && key !== 'q') controls[key].value = query[key];
      groupSelect.value = groupOption(query.group); pager(); return false;
    }
    const nextView = validateView({...query,q:controls.q.value,...values,page:values.page || 1});
    if (!await adoptView(nextView)) return false;
    return refreshGroups ? resync() : loadPage();
  }
  function closeDialog(force = false) {
    if (!groupView || !force && mutation && mutation.phase !== 'unknown') return;
    const opener = groupView.opener; groupView = undefined; dialog.close();
    groupEnabled();
    if (active && opener?.isConnected) opener.focus({preventScroll:true});
  }
  function openGroup(id, opener) {
    if (!active || !canManage() || writeBusy() || !groupsReady) return;
    const group = groups.find(g => g.id === id); if (id !== null && !group) return;
    groupView = {id,opener,life,saved:false}; form.reset(); name.value = group?.name || '';
    text(find('dvbGroupDialogTitle'),group ? `Rename group: ${group.name}` : 'Create group'); message('dvbGroupError',''); groupEnabled();
    dialog.showModal(); find('dvbGroupDialogTitle').focus();
  }
  async function mutate(kind, id, payload, view = null) {
    if (!active || !canManage() || writeBusy() || !groupsReady || view && (view !== groupView || view.saved)) return;
    const lock = {phase:'confirming',life}; mutation = lock; groupEnabled();
    const current = () => active && lock.life === life;
    try {
      if (kind === 'delete') {
        const selected = groups.find(g => g.id === id);
        const accepted = await confirmAction(`Delete group "${selected?.name || id}"? Its streams move to Ungrouped; this does not delete streams.`);
        if (!accepted || !current()) return;
      }
      if (!current() || !canManage()) return;
      lock.phase = 'writing'; cancelDebounce(); invalidatePage(); invalidateGroups(); groupEnabled();
      action('Saving group change... Do not repeat this request.');
      if (view) message('dvbGroupError','Saving... Wait for the response.');
      const path = kind === 'create' ? '/api/v1/dvb-groups' : kind === 'reorder' ? '/api/v1/dvb-groups/reorder' : groupPath(id);
      let result;
      try {
        result = await requestJSON(path,{method:kind === 'delete' ? 'DELETE' : kind === 'rename' ? 'PUT' : 'POST',...(payload ? {body:JSON.stringify(payload)} : {})});
      } catch (reason) {
        const known = definiteRejection(reason);
        if (!known) lock.phase = 'unknown';
        const value = known ? `Group change not saved: ${reason?.message || reason}` : `Group save outcome unknown: ${reason?.message || reason}. Do not retry; verify server state independently before further writes.`;
        action(value,true);
        if (current() && view === groupView) message('dvbGroupError',value,true);
        if (known && current()) await resync();
        return;
      }
      if (!current()) {action('Group change saved outside this view. Refresh to verify its snapshot; do not repeat the mutation.'); return;}
      lock.phase = 'readback'; if (view === groupView && view) view.saved = true;
      invalidatePage(); invalidateGroups();
      if (kind === 'delete' && query.group === id) {query.group = '';query.page = 1;persist();}
      groupEnabled();
      const success = await resync();
      if (!current()) return;
      const label = kind === 'create' ? 'Group created' : kind === 'rename' ? 'Group renamed' : kind === 'reorder' ? 'Group order saved' : `Group deleted; ${shown(result?.moved_streams)} streams moved to Ungrouped`;
      const value = success ? `${label}.` : `${label}; saved, but snapshot readback failed. Refresh to verify; do not repeat the mutation.`;
      action(value,!success);
      if (view === groupView && view) {
        if (success) {
          mutation = undefined; groupEnabled(); closeDialog(true);
        } else message('dvbGroupError',value,true);
      }
    } catch (reason) {
      if (current()) action(`Group action could not finish: ${reason?.message || reason}`,true);
    } finally {
      if (mutation === lock && lock.phase !== 'unknown') mutation = undefined;
      if (active) groupEnabled();
    }
  }
  function reorder(delta) {
    if (!active || !canManage()) return;
    const index = groups.findIndex(g => g.id === query.group), target = index + delta;
    if (index < 0 || target < 0 || target >= groups.length) return;
    const ids = groups.map(g => g.id); [ids[index],ids[target]] = [ids[target],ids[index]];
    void mutate('reorder',query.group,{ids});
  }

  for (const [key, control] of Object.entries(controls)) control.addEventListener(key === 'q' ? 'input' : 'change', () => {
    if (!active) return;
    if (bulkLock || viewChange) {syncControls();persist();return;}
    if (key !== 'q') return change({[key]:control.value});
    cancelDebounce(); invalidatePage();
    if (!validateSearchInput()) {pager();return;}
    pager();
    searchTimer = setTimeout(() => {searchTimer = undefined; if (active) change({q:control.value});},250);
  });
  groupSelect.addEventListener('change', () => change({group:optionGroup(groupSelect.value)}));
  prev.addEventListener('click', () => {if (!prev.disabled) change({page:query.page - 1});});
  next.addEventListener('click', () => {if (!next.disabled) change({page:query.page + 1});});
  refresh.addEventListener('click', () => {void resync();});
  find('addDVBStreamBtn').addEventListener('click', () => {void edit(null);});
  find('openDVBScanBtn').addEventListener('click', () => {void scan();});
  bulk.Apply.addEventListener('click',() => {void applyBulk();});
  bulk.Clear.addEventListener('click',() => {if (active && controlsAllowed() && !writeBusy() && !groupView) {clearSelection();bulkEnabled();}});
  for (const key of ['Action','Group','AdapterMode','Card']) bulk[key].addEventListener('change',() => {
    bulkEnabled();
    if (active && canManage() && !writeBusy() && bulk.Action.value === 'assign_adapter' && (key === 'Action' || key === 'AdapterMode' && !cardsReady)) void loadCards();
  });
  selectPage.addEventListener('change',() => {
    if (active && controlsAllowed() && !writeBusy() && !groupView && total !== null) for (const id of rows.keys()) setSelected(id,selectPage.checked);
    bulkEnabled();
  });
  editorDialog?.addEventListener('close',groupEnabled);
  scanDialog?.addEventListener('close',groupEnabled);
  scanDialog?.addEventListener('dvb-scan-statechange',groupEnabled);
  buttons.add.addEventListener('click', () => openGroup(null,buttons.add));
  buttons.rename.addEventListener('click', () => openGroup(query.group,buttons.rename));
  buttons.delete.addEventListener('click', () => {void mutate('delete',query.group);});
  buttons.moveUp.addEventListener('click', () => reorder(-1)); buttons.moveDown.addEventListener('click', () => reorder(1));
  form.addEventListener('submit', event => {
    event.preventDefault(); if (!canManage() || !groupView || groupView.life !== life || !dialog.open || writeBusy() || groupView.saved) return;
    if (!name.value.trim()) {message('dvbGroupError','Group name is required.',true);name.focus();return;}
    void mutate(groupView.id === null ? 'create' : 'rename',groupView.id,{name:name.value},groupView);
  });
  find('dvbGroupCancel').addEventListener('click', () => closeDialog());
  dialog.addEventListener('cancel', event => {event.preventDefault();closeDialog();});

  return {
    async activate() {
      if (!active) {active = true;++life;}
      syncBulkActions(true);groupEnabled();
      const owner = life, boundary = epoch;
      let stored; try {stored = window.sessionStorage.getItem(storageKey);} catch { /* Optional storage. */ }
      const accepted = await adoptView(readView(window.location.hash,stored));
      if (!active || owner !== life || boundary !== epoch) return false;
      persist();syncControls();renderGroups();
      if (actionText) message('dvbGroupNotice',actionText,actionFailed);
      if (bulkText) message('dvbBulkNotice',bulkText,bulkFailed);
      renderBulkResults();
      return accepted ? resync() : false;
    },
    deactivate() {
      cancelRuntimePaint();nextRuntimeAt = 0;
      active = false; ++life; ++epoch;runtimeSamples.clear();cardOwnership.clear();nextPageReadAt = 0; dirty = {page:false,groups:false,facets:false,cards:false};facetRead?.abort.abort();facetRead = undefined;setLiveState({state:'stopped'}); cancelDebounce();invalidatePage();invalidateGroups();closeDialog(true);
      cardRead?.abort.abort();cardRead = undefined;cardsReady = false;groupEnabled();
    },
    resync,
    imported() {
      // A pre-import snapshot must never certify a completed import's readback.
      invalidatePage(); invalidateGroups();
      return resync();
    },
    async saved(stream) {
      action(`DVB stream configuration saved: ${stream.name || stream.id}.${stream.dvb_descrambling ? ' Saved configuration is not proof of runtime readiness or decoded media.' : ''}`);
      // Refresh only this bounded view and its global group counts, never External streams.
      invalidatePage(); invalidateGroups();
      return resync();
    },
    applyEvent, synchronize, setLiveState,
  };
}
