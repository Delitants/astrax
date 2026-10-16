// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import {hydrateDVBStream, serializeDVBStream, resolveDVBTuning} from './dvb-editor.js?v=3';
import {buildOutputURL, sanitizeMPEGTSPath} from './output-builder.js?v=1';

const statuses = ['queued','running','succeeded','partial','failed','cancelled'];
const boundedText = (value, max = 4096) => typeof value === 'string' && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const identity = value => boundedText(value, 512) && !!value.trim() && !['.','..'].includes(value);
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const fail = message => {throw Error(message);};
const canonical = value => String(value || '').toLowerCase().replace(/^dvb-/, 'dvb');
// Match strings.TrimSpace in the store, including NEL but not the BOM.
const trimStore = value => value.replace(/^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g,'');

export function availableScanCards(cards, delivery) {
  return cards.filter(card => card && identity(card.device_key) && card.present === true && card.config?.enabled !== false
    && ['available','active'].includes(card.status) && !card.application?.admission_blocked
    && Array.isArray(card.delivery_systems) && card.delivery_systems.map(canonical).includes(delivery));
}

export function buildScanRequest(values, cards, settings, hostname) {
  if (!['dvbs','dvbs2'].includes(values.delivery_system)) fail('Scanning supports DVB-S/S2 only.');
  const candidates = availableScanCards(cards,values.delivery_system).filter(card => values.adapter_mode !== 'fixed' || card.device_key === values.device_key);
  if (!candidates.length) fail('No compatible available card in the cached inventory. Reload the snapshot before Start.');
  let problem;
  for (const card of candidates) {
    try {
      const draft = {...hydrateDVBStream(null,settings),...values,name:'Scan transport',enabled:true,service_id:'1',protocol:'mpegts',mpegts_path:'/scan-validation'};
      const {dvb} = serializeDVBStream(draft,null,settings,hostname,card.config || {});
      resolveDVBTuning(dvb,card.config || {});
      dvb.service_id = 0;
      return {dvb};
    } catch (error) {problem ??= error;}
  }
  throw problem;
}

export function scanResultURL(operation) {
  if (!operation || !identity(operation.id) || operation.kind !== 'dvb.scan' || !statuses.includes(operation.status)) fail('Malformed scan operation; outcome unknown.');
  // Derive the only permitted read route locally; result_url is never followed.
  const path = `/api/v1/dvb-scans/${encodeURIComponent(operation.id)}`;
  if (operation.result_url !== undefined) {
    // Go PathEscape and encodeURIComponent differ for +, !, :, @ and friends.
    // Verify a single local path segment by identity, then use our own URL only.
    const suffix = typeof operation.result_url === 'string' && operation.result_url.startsWith('/api/v1/dvb-scans/') ? operation.result_url.slice('/api/v1/dvb-scans/'.length) : '';
    let matches = false;
    try {matches = !!suffix && !/[/?#\\\s]/.test(suffix) && decodeURIComponent(suffix) === operation.id;} catch { /* Invalid escapes never become a navigation target. */ }
    if (!matches) fail('Scan result URL is not the canonical local route; outcome unknown.');
  }
  return path;
}

export function validateScanResult(result, id) {
  const d = result?.request?.dvb;
  if (!result || result.id !== id || result.operation_id !== undefined && result.operation_id !== id || !statuses.includes(result.status)
      || !d || !['dvbs','dvbs2'].includes(d.delivery_system) || !integer(d.frequency_khz,1,4294967295)
      || !integer(d.symbol_rate,1,4294967295) || !['H','V'].includes(d.polarization)
      || !['auto','fixed'].includes(d.adapter?.mode) || d.adapter.mode === 'fixed' && !identity(d.adapter.device_key)) fail('Scan status identity or request is malformed; retry the read.');
  const services = result.services ?? [], seen = new Set();
  if (!Array.isArray(services) || services.length > 65535) fail('Scan service list is malformed or too large.');
  for (const s of services) {
    if (!s || !integer(s.sid,1,65535) || seen.has(s.sid) || !boundedText(s.name) || !boundedText(s.type)
        || s.provider !== undefined && !boundedText(s.provider)
        || ['video_pid','audio_pid','pcr_pid'].some(key => !integer(s[key],0,8191))
        || ['scrambled','has_epg'].some(key => s[key] !== undefined && typeof s[key] !== 'boolean')
        || s.audio_languages != null && (!Array.isArray(s.audio_languages) || s.audio_languages.length > 256 || s.audio_languages.some(v => !boundedText(v,64)))
        || s.caids != null && (!Array.isArray(s.caids) || s.caids.length > 256 || s.caids.some(v => !integer(v,0,65535)))) fail('Scan service metadata is malformed or has duplicate SIDs.');
    seen.add(s.sid);
  }
  return {...result,services};
}

function template(value, fallback = '') {
  const text = value === '' || value == null ? fallback : value;
  if (!boundedText(text) || /[{}]/.test(text.replace(/\{(?:name|sid|index)\}/g,''))) fail('Template tokens are exactly {name}, {sid}, and {index}.');
  return text;
}
const expand = (text, service, index) => text.replace(/\{(name|sid|index)\}/g, (_, key) => key === 'name' ? service.name : String(key === 'sid' ? service.sid : index));
function safePath(path) {
  if (!/^\/[A-Za-z0-9_./~-]+$/.test(path) || path.includes('//') || path.split('/').some(part => part === '.' || part === '..') || path.endsWith('/')) fail('Use a literal safe play path: letters, digits, -, _, ~, dots and path separators; name substitutions cannot contain separators, spaces or URL escapes.');
  const suffix = path.match(/\.(ts|m3u8)$/i)?.[0];
  if (suffix && suffix !== suffix.toLowerCase()) fail('Output suffix must be lowercase .ts or .m3u8 to match the published route.');
  const normalized = path.replace(/\.(ts|m3u8)$/i,'');
  if (normalized.split('/').some(part => part === '.' || part === '..')) fail('Output normalizes to an unsafe dot route.');
  if (!normalized || normalized === '/' || /^\/(stream|hls)(\/|$)/.test(normalized)) fail('Output overlaps the built-in HTTP namespace.');
  return normalized;
}

function numericSegmentBase(alias) {
  const match = alias.match(/^(.*)_(0|[1-9][0-9]*)\.ts$/);
  // Match routing.go's canonical decimal index and 64-bit strconv.Atoi bound.
  return match && match[1] && BigInt(match[2]) <= 9223372036854775807n ? match[1] : null;
}

function batchRoutes() {
  const bases = new Set(), aliases = new Set(), segmentParents = new Set();
  return base => {
    const claims = [base,`${base}.ts`,`${base}.m3u8`];
    // A bare path also owns both exact suffix aliases and its numeric segments.
    // Reverse claims detect a parent added after a child, without pairwise scans.
    if (segmentParents.has(base) || claims.some(alias => aliases.has(alias) || bases.has(numericSegmentBase(alias)))) {
      fail('Duplicate or conflicting HTTP output routes, aliases or numeric segments.');
    }
    bases.add(base);
    for (const alias of claims) {aliases.add(alias);const parent = numericSegmentBase(alias);if (parent) segmentParents.add(parent);}
  };
}

export function buildImportPreview(services, ids, values, settings, hostname) {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > 1000 || new Set(ids).size !== ids.length) fail('Select between 1 and 1000 unique services.');
  if (!['mpegts','hls'].includes(values.protocol)) fail('Scan import supports MPEGTS and HLS HTTP play paths only.');
  if (!integer(settings?.http_play_port,1,65535)) fail('Configured HTTP play port is unavailable.');
  if (!['auto','fixed'].includes(values.adapter_mode) || values.adapter_mode === 'fixed' && !identity(values.device_key)) fail('Choose Auto or a fixed physical card.');
  for (const key of ['group_id','softcam_id']) if (values[key] && !identity(values[key])) fail(`Invalid ${key}.`);
  const name = template(values.name_template,'{name}'), xmltv = template(values.xmltv_template);
  const path = sanitizeMPEGTSPath(template(values.path_template));
  if (!String(values.path_template || '').trim()) fail('Output path template is required.');
  const output = buildOutputURL(values.protocol,{mpegts_path:path},settings,hostname);
  const byID = new Map(services.map(service => [service.sid,service])), claimRoute = batchRoutes();
  const rows = ids.map((sid,i) => {
    const service = byID.get(sid);
    if (!integer(sid,1,65535) || !service) fail('Selected service is not in this scan.');
    if (path.includes('{name}') && !/^[A-Za-z0-9_.~-]+$/.test(service.name)) fail('Service name is unsafe for literal URL substitution; use {sid} or {index}.');
    const renderedPath = expand(path,service,i+1);
    const finalPath = values.protocol === 'hls' && !path.endsWith('.m3u8') ? `${renderedPath}.m3u8` : renderedPath;
    const normalized = safePath(finalPath);
    claimRoute(normalized);
    const generated = expand(output,service,i+1);
    const parsed = new URL(generated);
    if (parsed.protocol !== 'http:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== finalPath) fail('Output cannot be previewed without changing literal backend substitution.');
    return {sid,name:trimStore(expand(name,service,i+1)) || `Service ${sid}`,output:trimStore(generated),xmltv:trimStore(expand(xmltv,service,i+1))};
  });
  return {rows,dto:{service_ids:[...ids],group_id:values.group_id || '',adapter:values.adapter_mode === 'fixed' ? {mode:'fixed',device_key:values.device_key} : {mode:'auto'},
    name_template:name,output_template:output,protocol:values.protocol,softcam_id:values.softcam_id || '',xmltv_channel_id_template:xmltv,enabled:!!values.enabled}};
}

export function analyzeScanImport(body, ids) {
  const items = Array.isArray(body?.results) ? body.results : [], created = new Set(), results = [];
  let valid = Array.isArray(ids) && ids.length > 0 && ids.length <= 1000 && new Set(ids).size === ids.length && items.length === ids.length;
  for (let i = 0; i < ids.length; i++) {
    const item = items[i];
    if (!item || typeof item.ok !== 'boolean' || !identity(item.id) || (item.ok
      ? created.has(item.id) || item.error !== undefined && item.error !== ''
      : item.id !== String(ids[i]) || !boundedText(item.error) || !item.error.trim())) {valid = false;continue;}
    if (item.ok) created.add(item.id);
    results.push({...item,sid:ids[i]});
  }
  const succeeded = results.filter(item => item.ok).length, failed = results.length - succeeded;
  return {complete:valid && body?.succeeded === succeeded && body?.failed === failed,succeeded,failed,results};
}
