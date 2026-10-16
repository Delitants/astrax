// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

// Canonical query values from httpapi/dvb_contract.go; identities stay opaque.
export const enums = {
  status: 'starting tuning on-demand stopped error running locked'.split(' '),
  protocol: 'mpegts mpegts-secure udp srt hls hls-secure http rtsp rtsp-secure dvb'.split(' '),
  sort: 'id status state group group_id service service_id transponder frequency frequency_khz requested_adapter actual_adapter output output_url protocol updated updated_at updated_time name'.split(' '),
  order: ['asc', 'desc'], delivery_system: ['dvbs', 'dvbs2', 'dvbc', 'dvbt', 'dvbt2'],
  descrambling_state: 'waiting_psi waiting_route waiting_keys key_expired partial_clear payload_processed unsupported capacity stopped'.split(' '),
  descrambling_reason: 'stream_stopped policy_disabled catalog_missing catalog_stale input_closed catalog_unavailable no_ca_descriptors unsupported_ca_layout backend_unavailable pipeline_unavailable sink_unavailable unsupported_descrambling_output waiting_keys key_expired partial_clear payload_processed capacity stale_attachment policy_invalid profile_unavailable cipher_failed'.split(' '),
};
export const storageKey = 'astrax.dvb-streams.view.v1';
export const defaults = Object.freeze({page: 1, limit: 100, group: null, status: '', requested_adapter: '', actual_adapter: '', delivery_system: '', protocol: '', descrambling_state: '', descrambling_reason: '', q: '', sort: 'name', order: 'asc'});
const safeText = (value, max = 1024) => typeof value === 'string' && new TextEncoder().encode(value).length <= max;
export const searchWithinLimit = value => safeText(value, 256);
const positive = value => (typeof value === 'number' || typeof value === 'string' && /^\d+$/.test(value)) && Number.isSafeInteger(Number(value)) && Number(value) > 0;

export function validateView(input) {
  const value = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const result = {...defaults};
  for (const [key, allowed] of Object.entries(enums)) if (allowed.includes(value[key])) result[key] = value[key];
  for (const key of ['group', 'requested_adapter', 'actual_adapter', 'q']) if (key === 'q' ? searchWithinLimit(value[key]) : safeText(value[key])) result[key] = value[key];
  if (result.group?.toLowerCase() === 'ungrouped') result.group = '';
  if (positive(value.limit) && [50, 100, 200].includes(Number(value.limit))) result.limit = Number(value.limit);
  if (positive(value.page) && Number.isSafeInteger((Number(value.page) - 1) * result.limit)) result.page = Number(value.page);
  return result;
}

export function readView(hash = '', stored = null) {
  if (hash.startsWith('#dvb-streams?')) {
    const params = new URLSearchParams(hash.slice(13));
    return validateView(Object.fromEntries([...params].filter(([key]) => params.getAll(key).length === 1)));
  }
  try { return validateView(JSON.parse(stored)); } catch { return {...defaults}; }
}
export const nondefaults = view => Object.fromEntries(Object.entries(validateView(view)).filter(([key, value]) => value !== defaults[key]));
export function viewHash(view) {
  const values = nondefaults(view);
  if (values.group === '') values.group = 'ungrouped';
  const query = new URLSearchParams(values).toString();
  return '#dvb-streams' + (query ? `?${query}` : '');
}
export function requestPath(view) {
  return '/api/v1/dvb-streams?' + new URLSearchParams({page: view.page, limit: view.limit, ...nondefaults(view)});
}
export const groupOption = id => id === null ? '@all' : id === '' ? '@ungrouped' : `id:${id}`;
export const optionGroup = option => option === '@ungrouped' ? '' : option.startsWith('id:') ? option.slice(3) : null;
export const countValue = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
export function groupCounts(groups, counts) {
  const values = counts && typeof counts === 'object' ? counts : {};
  const complete = ['', ...groups.map(g => g.id)].every(id => Object.hasOwn(values, id) && countValue(values[id]) !== null);
  const all = Object.values(values).every(v => countValue(v) !== null) ? Object.values(values).reduce((a, b) => a + b, 0) : null;
  return {all: complete ? countValue(all) : null, ungrouped: Object.hasOwn(values, '') ? countValue(values['']) : null};
}
export function validPage(page, view) {
  return !!page && Array.isArray(page.items) && page.items.length <= view.limit && page.items.length <= page.total
    && page.items.every(item => item && typeof item.id === 'string' && item.id !== '')
    && new Set(page.items.map(item => item.id)).size === page.items.length
    && countValue(page.total) !== null && page.page === view.page && page.limit === view.limit;
}
