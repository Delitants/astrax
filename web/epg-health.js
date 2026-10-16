// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import {requestJSON, formatDuration} from './ui-common.js?v=18';

const sourceStates = {healthy:'Healthy',retained:'Retained data',stale:'Refresh in progress - cached data',expired:'Expired',never_fetched:'Never fetched',error:'No usable cache',disabled:'Disabled'};
const errorLabels = {fetch_failed:'Source fetch failed',parse_failed:'Invalid XMLTV response',write_failed:'Local output write failed',source_too_large:'Source size limit exceeded',programme_limit:'Programme limit exceeded',xml_depth_limit:'XML nesting limit exceeded',fetch_timeout:'Source timeout exceeded'};
const outputStates = {pending:'Not written yet',current:'Current',stale:'Not confirmed current',error:'Last write failed',disabled:'Disabled',unconfigured:'Not configured'};
const known = (labels,key,fallback) => Object.hasOwn(labels,key) ? labels[key] : fallback;
const count = value => Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : '-';
const timestamp = value => {
  if (!value || typeof value !== 'string' || value.startsWith('0001-')) return 'Never';
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString().replace('T',' ').replace('.000Z',' UTC') : 'Unknown';
};

export function createEPGHealthController({els,document = globalThis.document,request = requestJSON}) {
  let active = false, generation = 0, pending = null;
  function unavailable(message = 'EPG health unavailable. Retry the read-only check.') {
    els.feed.textContent = 'Unknown';
    for (const key of ['channels','programmes','merge','snapshot']) els[key].textContent = '-';
    els.sources.replaceChildren();
    els.output.textContent = 'Local output status unknown.';
    els.notice.textContent = message;
    els.notice.hidden = false;
    els.notice.className = 'notice err';
    els.notice.setAttribute('role','alert');
  }
  function render(value) {
    if (!value || typeof value.enabled !== 'boolean' || typeof value.available !== 'boolean'
      || !Array.isArray(value.sources) || !value.output || typeof value.output !== 'object'
      || !Number.isSafeInteger(value.channel_count) || value.channel_count < 0
      || !Number.isSafeInteger(value.programme_count) || value.programme_count < 0
      || !value.snapshot_at || !Number.isFinite(Date.parse(value.snapshot_at))) throw new Error('Invalid health snapshot');
    els.feed.textContent = !value.enabled ? 'Disabled' : value.available ? 'Available' : 'Unavailable';
    els.channels.textContent = count(value.channel_count);
    els.programmes.textContent = count(value.programme_count);
    els.merge.textContent = timestamp(value.last_merge);
    els.snapshot.textContent = `Snapshot: ${timestamp(value.snapshot_at)}. Read-only; no source fetch was requested.`;
    const rows = value.sources.map((source,index) => {
      const row = document.createElement('tr');
      const label = known(sourceStates,source?.status,'Unknown');
      const safeError = known(errorLabels,source?.error_code,'');
      const age = Number.isFinite(source?.cache_age_seconds) && source.cache_age_seconds >= 0
        ? formatDuration(source.cache_age_seconds) : '-';
      const fields = [`Source ${index+1}`,safeError ? `${label} - ${safeError}` : label,
        timestamp(source?.last_attempt),timestamp(source?.last_success),age,
        `${count(source?.channel_count)} channels / ${count(source?.programme_count)} programmes`];
      for (const field of fields) {
        const cell = document.createElement('td'); cell.textContent = field; row.append(cell);
      }
      return row;
    });
    els.sources.replaceChildren(...rows);
    if (!rows.length) {
      const row = document.createElement('tr'), cell = document.createElement('td');
      cell.colSpan = 6; cell.textContent = 'No external XMLTV sources configured.'; row.append(cell); els.sources.append(row);
    }
    const output = value.output;
    const label = output.configured ? known(outputStates,output.status,'Unknown') : 'Not configured';
    const memory = value.enabled && value.available ? 'Memory feed remains available.' : 'Memory feed is not available.';
    els.output.textContent = `Local XMLTV output: ${label}. ${memory} Last attempt: ${timestamp(output.last_attempt)}. Last successful write: ${timestamp(output.last_success)}.`;
    els.notice.hidden = true;
    els.notice.textContent = '';
    if (value.runtime_available === false) {
      els.feed.textContent = value.enabled ? 'Unavailable' : 'Disabled';
      els.notice.textContent = 'EPG runtime is unavailable. Configuration alone does not indicate feed health.';
      els.notice.className = 'notice err'; els.notice.setAttribute('role','alert'); els.notice.hidden = false;
    }
  }
  function refresh() {
    if (!active) return Promise.resolve();
    if (pending) return pending.promise;
    const token = ++generation, abort = new AbortController();
    els.refresh.disabled = true;
    els.refresh.setAttribute('aria-busy','true');
    const operation = {abort};
    pending = operation;
    operation.promise = (async () => {
      try {
        const value = await request('/api/v1/epg/status',{method:'GET',cache:'no-store',signal:abort.signal});
        if (active && generation === token) render(value);
      } catch {
        if (active && generation === token) unavailable();
      } finally {
        if (pending === operation) {
          pending = null; els.refresh.disabled = false; els.refresh.removeAttribute('aria-busy');
        }
      }
    })();
    return operation.promise;
  }
  els.refresh.addEventListener('click',refresh);
  return {
    activate() {active = true; return refresh();},
    deactivate() {
      active = false; generation++; pending?.abort.abort(); pending = null;
      els.refresh.disabled = false; els.refresh.removeAttribute('aria-busy');
    },
    settingsSaved() {
      generation++; pending?.abort.abort(); pending = null;
      els.refresh.disabled = false; els.refresh.removeAttribute('aria-busy');
      unavailable('EPG settings saved. Checking current health...');
      return refresh();
    },
    refresh,
  };
}
