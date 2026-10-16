// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import {buildOutputURL, parseOutputURL} from './output-builder.js?v=1';
import {hydrateDescrambling, serializeDescrambling, createDescramblingPanel} from './dvb-descrambling.js?v=1';

const deliveries = ['dvbs', 'dvbs2', 'dvbc', 'dvbt', 'dvbt2'];
const satelliteModulations = {dvbs: ['auto', 'qpsk'], dvbs2: ['auto', 'qpsk', '8psk', '16apsk', '32apsk']};
const fecValues = ['auto', '1/2', '2/3', '3/4', '3/5', '4/5', '5/6', '6/7', '7/8', '8/9', '9/10'];
const rolloffValues = ['auto', '35', '25', '20'];
const tuningDefaults = {modulation: 'auto', fec: 'auto', rolloff: '35', stream_id: ''};
const httpProtocols = ['mpegts', 'mpegts-secure', 'hls', 'hls-secure'];
const advancedKeys = ['enable_monitoring', 'timeout_sec', 'dvb_api', 'dvb_api_v3'];
const tuningKeys = ['modulation', 'fec', 'rolloff', 'stream_id'];
const serviceKeys = ['sid', 'name', 'video_pid', 'audio_pid', 'pcr_pid', 'type', 'provider', 'scrambled', 'has_epg', 'audio_languages', 'selected', 'caids'];
const string = value => value == null ? '' : String(value);
const canonical = value => string(value).trim().toLowerCase().replace(/^dvb-/, 'dvb');
const satellite = delivery => ['dvbs', 'dvbs2'].includes(delivery);
const pick = (object, keys) => Object.fromEntries(keys.filter(k => Object.hasOwn(object || {}, k)).map(k => [k, object[k]]));
const invalid = (field, message) => { throw Object.assign(new Error(message), {field}); };

function supportedModulation(value, delivery) {
  if (!satellite(delivery) || !string(value).trim()) return true;
  const token = string(value).toLowerCase().replace(/[\s_-]/g, '');
  const alias = {psk: 'qpsk', psk8: '8psk', apsk16: '16apsk', apsk32: '32apsk'};
  return satelliteModulations[delivery].includes(alias[token] || token);
}

function normalizedTuning(key, value, delivery) {
  const raw = string(value), compact = raw.toLowerCase().replace(/\s/g, '');
  if (key === 'modulation') {
    const token = compact.replace(/[_-]/g, '');
    const alias = {psk: 'qpsk', psk8: '8psk', apsk16: '16apsk', apsk32: '32apsk'};
    const result = alias[token] || token;
    return satelliteModulations[delivery]?.includes(result) ? result : null;
  }
  if (key === 'fec') return fecValues.find(v => v === compact || v.replace('/', '') === compact) ?? null;
  if (key === 'rolloff') return rolloffValues.find(v => v === compact || v !== 'auto' && `0.${v}` === compact) ?? null;
  const isi = raw.trim();
  if (!isi) return '';
  return delivery === 'dvbs2' && /^\d+$/.test(isi) && Number(isi) <= 255 ? String(Number(isi)) : null;
}

export function resolveDVBTuning(dvb, card = {}) {
  const delivery = canonical(dvb.delivery_system), result = {};
  for (const key of tuningKeys) {
    let value = card.advanced?.[key] ?? '', field = 'card.' + key, source = 'card defaults';
    if (string(dvb.advanced?.[key]) !== '') {value = dvb.advanced[key]; field = 'advanced_' + key; source = 'advanced fallback';}
    if (string(dvb[key]) !== '') {value = dvb[key]; field = key; source = 'primary tuning';}
    if (key !== 'stream_id' && !string(value).trim()) value = tuningDefaults[key];
    result[key] = normalizedTuning(key, value, delivery);
    if (result[key] === null) {
      const label = {modulation: 'Modulation', fec: 'FEC', rolloff: 'Roll-off', stream_id: 'Input stream ID'}[key];
      const rule = key === 'stream_id' ? 'Use decimal ISI 0-255 for DVB-S2; DVB-S requires no effective stream ID.' : 'Choose a supported value or correct the inherited card setting.';
      invalid(field, `${label} from ${source} is not supported for ${delivery.toUpperCase()}. ${rule}`);
    }
  }
  return result;
}

function rfMode(value) {
  const raw = string(value).trim().toLowerCase(), token = raw.replace(/[\s_-]/g, '');
  if (!token || token === 'universal') return 'universal';
  if (raw.split(/[-_\s]+/).includes('custom')) return 'custom';
  if (['unicable', 'unicable1', 'unicablei', 'en50494'].includes(token)) return 'unicable1';
  if (['unicable2', 'unicableii', 'jess', 'en50607'].includes(token)) return 'unicable2';
  return null;
}

function rfConfig(values) {
  const mode = rfMode(values.rf_mode);
  if (!mode) invalid('rf_mode', 'Choose a supported LNB mode; the configured RF mode is unknown.');
  const rf = {mode: values.rf_mode, force_tone: !!values.force_tone, slot_position: values.slot_position};
  for (const key of ['lof1', 'lof2', 'slof']) rf[key] = integer(values, key, 1, 2147483647, 'LNB oscillator / band switch');
  for (const key of ['unicable_slot', 'slot_frequency']) rf[key] = integer(values, key, 0, 2147483647, key === 'slot_frequency' ? 'User-band frequency' : 'Unicable slot');
  const positions = mode === 'unicable1' ? ['A', 'B'] : ['A', 'B', 'C', 'D'];
  if (!positions.includes(string(rf.slot_position).trim().toUpperCase() || 'A')) invalid('slot_position', `Satellite position must be ${positions.join(', ')} for this mode.`);
  if (['unicable1', 'unicable2'].includes(mode)) {
    rf.unicable_slot = integer(values, 'unicable_slot', 1, mode === 'unicable1' ? 8 : 32, 'Unicable slot');
    rf.slot_frequency = integer(values, 'slot_frequency', 1, 2147483647, 'User-band frequency');
  }
  return rf;
}

function draftTuning(values) {
  return {delivery_system: values.delivery_system, ...pick(values, tuningKeys), advanced: Object.fromEntries(tuningKeys.map(key => [key, values[`advanced_${key}`]]))};
}

export function hydrateDVBStream(stream = null, settings = {}) {
  const d = stream?.dvb || {}, rf = d.rf_override || {}, advanced = d.advanced || {};
  const values = {
    name: stream?.name || '', enabled: stream?.enabled ?? true, group_id: stream?.group_id || '', softcam_id: stream?.softcam_id || '',
    protocol: stream?.protocol || 'mpegts', xmltv_channel_id: stream?.xmltv_channel_id || '',
    on_demand: stream?.on_demand ?? false, on_demand_timeout_sec: string(stream?.on_demand_timeout_sec ?? 30),
    delivery_system: canonical(d.delivery_system || 'dvbs2'), frequency_mhz: d.frequency_khz == null ? '' : string(d.frequency_khz / 1000),
    symbol_rate_ksps: d.symbol_rate == null ? '' : string(d.symbol_rate / 1000), polarization: d.polarization || 'H',
    service_id: string(d.service_id), video_pid: string(d.video_pid), audio_pids: (d.audio_pids || []).join(', '), pcr_pid: string(d.pcr_pid),
    adapter_mode: d.adapter?.mode || 'auto', device_key: d.adapter?.device_key || '',
    rf_override: !!d.rf_override, rf_mode: rf.mode ?? 'universal',
    lof1: string(rf.lof1 ?? 9750), lof2: string(rf.lof2 ?? 10600), slof: string(rf.slof ?? 11700), force_tone: rf.force_tone ?? false,
    unicable_slot: string(rf.unicable_slot ?? 1), slot_frequency: string(rf.slot_frequency ?? 1210), slot_position: rf.slot_position || 'A',
    enable_monitoring: advanced.enable_monitoring ?? false, timeout_sec: string(advanced.timeout_sec ?? 120),
    dvb_api: advanced.dvb_api ?? 'v5', dvb_api_v3: advanced.dvb_api_v3 ?? false,
    ...parseOutputURL(stream?.output_url || '', stream?.protocol || 'mpegts', settings),
    ...hydrateDescrambling(stream),
  };
  for (const key of tuningKeys) {
    values[key] = d[key] ?? (!stream && key !== 'stream_id' ? 'auto' : '');
    values[`advanced_${key}`] = advanced[key] ?? '';
  }
  return values;
}

function integer(values, key, min, max, label, optional = false) {
  const raw = string(values[key]).trim();
  if (optional && raw === '') return undefined;
  const n = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(n) || n < min || n > max) invalid(key, `${label} must be an integer from ${min} to ${max}.`);
  return n;
}

function scaled(values, key, required, label) {
  const raw = string(values[key]).trim();
  if (!raw && !required) return undefined;
  // Decimal string arithmetic prevents floating-point rounding or a second unit conversion.
  if (!/^\d+(?:\.\d{1,3})?$/.test(raw)) invalid(key, `${label} requires at most three decimal places.`);
  const [whole, fraction = ''] = raw.split('.');
  const n = Number(whole + fraction.padEnd(3, '0'));
  if (!Number.isSafeInteger(n) || n < (required ? 1 : 0) || n > 4294967295) invalid(key, `${label} is outside the supported range.`);
  return n;
}

function outputKeys(protocol) {
  if (httpProtocols.includes(protocol)) return ['mpegts_path'];
  if (protocol === 'srt') return ['srt_mode', 'srt_host', 'srt_port_override', 'srt_streamid', 'srt_latency', 'srt_passphrase', 'srt_pbkeylen', 'srt_fec_enabled', 'srt_fec_cols', 'srt_fec_rows'];
  if (protocol === 'udp') return ['udp_host', 'udp_port'];
  return ['output_url'];
}

function unchangedOutput(values, original, settings) {
  if (!original || values.protocol !== original.protocol) return false;
  const initial = parseOutputURL(original.output_url, original.protocol, settings);
  return outputKeys(values.protocol).every(key => values[key] === initial[key]);
}

function host(values, key) {
  const value = string(values[key]).trim();
  if (!value || /[\s/@?#\\]/.test(value)) invalid(key, 'Output host must be a hostname or IP address, without a port or path.');
  try {
    const url = new URL(`http://${value}`);
    if (!url.hostname || url.port || url.username || url.password || url.pathname !== '/') throw Error();
  } catch { invalid(key, 'Output host must be a hostname or bracketed IPv6 address, without a port or path.'); }
}

function outputURL(values, original, settings, hostname) {
  const p = values.protocol;
  if (httpProtocols.includes(p)) {
    integer({port: settings.http_play_port}, 'port', 1, 65535, 'Configured HTTP play port');
    if (!string(values.mpegts_path).trim()) invalid('mpegts_path', 'HTTP play path is required.');
  } else if (p === 'srt') {
    host(values, 'srt_host');
    if (!['listener', 'caller'].includes(values.srt_mode)) invalid('srt_mode', 'Choose Listener or Caller.');
    integer({srt_port_override: values.srt_port_override || settings.srt_play_port}, 'srt_port_override', 1, 65535, 'SRT port');
    integer(values, 'srt_latency', 20, 8000, 'SRT latency');
    if (!['16', '24', '32'].includes(string(values.srt_pbkeylen))) invalid('srt_pbkeylen', 'SRT key length must be 16, 24 or 32 bytes.');
    const pass = string(values.srt_passphrase).trim();
    if (pass && (pass.length < 10 || pass.length > 79)) invalid('srt_passphrase', 'SRT passphrase must contain 10-79 characters.');
    if (values.srt_fec_enabled) {
      integer(values, 'srt_fec_cols', 1, 64, 'SRT FEC columns'); integer(values, 'srt_fec_rows', 1, 64, 'SRT FEC rows');
    }
  } else if (p === 'udp') {
    host(values, 'udp_host'); integer(values, 'udp_port', 1, 65535, 'UDP port');
  } else if (!string(values.output_url).trim()) invalid('output_url', 'Output URL is required.');
  return unchangedOutput(values, original, settings) ? original.output_url : buildOutputURL(p, values, settings, hostname);
}

export function serializeDVBStream(values, original = null, settings = {}, hostname = '127.0.0.1', card = {}) {
  if (!string(values.name).trim()) invalid('name', 'Name is required.');
  const delivery = canonical(values.delivery_system), isSatellite = satellite(delivery);
  if (!deliveries.includes(delivery)) invalid('delivery_system', 'Unsupported delivery system is read-only; this backend cannot save it, even disabled.');
  if (!isSatellite && values.enabled) invalid('enabled', 'Current runtime tunes DVB-S/S2 only. Explicitly disable Enabled to save this delivery as a disabled configuration.');
  const dvb = {
    delivery_system: delivery, frequency_khz: scaled(values, 'frequency_mhz', true, 'Frequency (MHz)'),
    service_id: integer(values, 'service_id', 1, 65535, 'Service ID'),
    advanced: {}, adapter: {mode: values.adapter_mode},
  };
  if (!['auto', 'fixed'].includes(values.adapter_mode)) invalid('adapter_mode', 'Choose Auto or Fixed card.');
  if (values.adapter_mode === 'fixed') {
    const current = original?.dvb?.adapter;
    if (!values.device_key && !(current?.mode === 'fixed' && !current.device_key && current.last_address)) invalid('device_key', 'Select a fixed card with a stable device key.');
    if (values.device_key) dvb.adapter.device_key = values.device_key;
    if (current?.mode === 'fixed' && (current.device_key || '') === values.device_key && current.last_address) dvb.adapter.last_address = current.last_address;
  }
  if (isSatellite || delivery === 'dvbc') {
    const rate = scaled(values, 'symbol_rate_ksps', isSatellite, 'Symbol rate (kS/s)');
    if (rate !== undefined) dvb.symbol_rate = rate;
  }
  if (isSatellite) {
    if (!['H', 'V'].includes(values.polarization)) invalid('polarization', 'Polarization must be H or V.');
    dvb.polarization = values.polarization;
  }
  for (const key of tuningKeys) {
    if (!isSatellite && ['rolloff', 'stream_id'].includes(key)) continue;
    const primary = string(values[key]), advanced = string(values[`advanced_${key}`]);
    if (primary !== '' || Object.hasOwn(original?.dvb || {}, key)) dvb[key] = primary;
    if (advanced !== '' || Object.hasOwn(original?.dvb?.advanced || {}, key)) dvb.advanced[key] = advanced;
  }
  for (const key of ['video_pid', 'pcr_pid']) {
    const pid = integer(values, key, 0, 8191, key === 'video_pid' ? 'Video PID' : 'PCR PID', true);
    if (pid !== undefined) dvb[key] = pid;
  }
  const audio = string(values.audio_pids).trim();
  dvb.audio_pids = audio ? audio.split(',').map(value => integer({audio_pids: value.trim()}, 'audio_pids', 0, 8191, 'Audio PID')) : [];
  if (original?.dvb?.service) dvb.service = structuredClone(pick(original.dvb.service, serviceKeys));
  dvb.advanced = {...dvb.advanced, ...pick(values, advancedKeys), timeout_sec: integer(values, 'timeout_sec', 0, 2147483647, 'Tuning timeout')};
  if (isSatellite && values.enabled) resolveDVBTuning(dvb, card);
  if (isSatellite && values.rf_override) dvb.rf_override = rfConfig(values);
  const policy = serializeDescrambling(values, original);
  return {
    name: string(values.name).trim(), output_url: outputURL(values, original, settings, hostname), protocol: values.protocol,
    ...(policy === undefined ? {} : {dvb_descrambling:policy}),
    enabled: !!values.enabled, group_id: values.group_id || '', softcam_id: values.softcam_id || '', dvb,
    scrambled: original?.scrambled ?? false, caids: [...(original?.caids || [])], on_demand: !!values.on_demand,
    on_demand_timeout_sec: integer(values, 'on_demand_timeout_sec', values.on_demand ? 5 : 0, 3600, 'On-demand timeout'),
    xmltv_channel_id: string(values.xmltv_channel_id),
  };
}

export async function loadEditorCards(requestJSON, options = {}) {
  const items = [], seen = new Set(); let total;
  for (let page = 1; page <= 25; page++) {
    options.signal?.throwIfAborted();
    const result = await requestJSON(`/api/v1/dvb-cards?page=${page}&limit=200`, options);
    if (!result || !Array.isArray(result.items) || result.stale || result.refresh_error || !Number.isSafeInteger(result.total)
        || result.total < 0 || result.total > 5000 || result.page !== page || result.limit !== 200
        || (total !== undefined && result.total !== total)) throw Error('Card inventory is incomplete, stale, changed, or exceeds the 5000-card editor limit. Refresh inventory before saving.');
    total = result.total;
    if (result.items.length !== Math.min(200, total - items.length)) throw Error('Card inventory page is incomplete. Refresh inventory before saving.');
    for (const card of result.items) {
      if (typeof card.device_key !== 'string' || !card.device_key || seen.has(card.device_key)) throw Error('Card inventory contains missing or duplicate stable keys. Refresh inventory before saving.');
      seen.add(card.device_key); items.push(card);
    }
    if (items.length === total) return items;
  }
  throw Error('Card inventory is incomplete; saving is disabled.');
}

function safePreview(raw) {
  try {
    const url = new URL(raw);
    if (url.username) url.username = 'hidden'; if (url.password) url.password = 'hidden';
    for (const key of [...url.searchParams.keys()]) {
      // Only non-secret transport controls are displayed; opaque custom parameters may be credentials.
      if (!['mode', 'latency', 'pbkeylen', 'packetfilter'].includes(key.toLowerCase())) url.searchParams.set(key, '[hidden]');
    }
    return url.toString();
  } catch { return 'Output preview unavailable.'; }
}

export function createDVBEditor({requestJSON, onSaved, root = document, window = globalThis.window}) {
  const find = id => root.querySelector(`#${id}`), dialog = find('dvbStreamDialog'), form = find('dvbStreamForm');
  if (!dialog || !form) throw Error('DVB editor markup is missing');
  const field = name => form.elements.namedItem(name), title = find('dvbStreamDialogTitle'), notice = find('dvbStreamNotice');
  const save = find('dvbStreamSave'), closeButton = find('dvbStreamClose');
  let generation = 0, reads, streamID = null, original = null, settings = {}, cards = [], phase = 'closed';
  let invoker;
  let statusRevision = -1;
  let statusTimer, pendingStatus;
  function clearStatus() {
    clearTimeout(statusTimer); statusTimer = undefined; pendingStatus = undefined;
  }
  function applyStatus(snapshot) {
    if (snapshot?.id !== streamID || phase !== 'ready') return;
    const s = snapshot.runtime?.descrambling;
    if (s?.state === 'waiting_psi' || ['catalog_stale','catalog_missing','input_closed','stale_attachment','catalog_unavailable','no_ca_descriptors','unsupported_ca_layout'].includes(s?.reason)) descrambling.invalidateMetadata();
    pendingStatus = snapshot;
    if (statusTimer !== undefined) return;
    statusTimer = setTimeout(() => {
      statusTimer = undefined;
      const next = pendingStatus; pendingStatus = undefined;
      if (phase === 'ready' && next?.id === streamID) descrambling.applyStatus(next);
    }, 1000);
  }
  const descrambling = createDescramblingPanel({requestJSON, root, onPolicyChange:() => {if (phase === 'ready') lock();}});
  const readValues = () => Object.fromEntries([...form.elements].filter(el => el.name).map(el => [el.name, el.type === 'checkbox' ? el.checked : el.value]));
  function message(text, error = false) {
    notice.textContent = text; notice.className = `notice${error ? ' err' : ''}`; notice.setAttribute('role', error ? 'alert' : 'status');
  }
  function lock() {
    for (const section of form.querySelectorAll('fieldset')) section.disabled = phase !== 'ready';
    const delivery = field('delivery_system').value;
    save.disabled = phase !== 'ready' || !satellite(delivery) && field('enabled').checked
      || !!runtimeValidation(readValues()).problem
      || field('descrambling_enabled').checked && descrambling.backendAvailable() === false;
    closeButton.disabled = phase === 'saving';
    if (['loading', 'saving'].includes(phase)) form.setAttribute('aria-busy', 'true'); else form.removeAttribute('aria-busy');
  }
  function option(select, value, label, disabled = false) {
    const opt = form.ownerDocument.createElement('option'); opt.value = value; opt.textContent = label; opt.disabled = disabled; select.append(opt);
  }
  function retain(select, value, label = 'Configured value (unavailable)') {
    if (![...select.options].some(o => o.value === value)) option(select, value, `${label}: ${value}`);
    select.value = value;
  }
  function choices(name, items, empty) {
    const select = field(name); select.replaceChildren(); option(select, '', empty);
    for (const item of items) option(select, item.id, item.name || item.id);
  }
  function compatible(card) { return (card.delivery_systems || []).map(canonical).includes(field('delivery_system').value); }
  function tuningCards(values) {
    const candidates = values.adapter_mode === 'fixed'
      ? cards.filter(card => card.device_key === values.device_key)
      : cards.filter(card => compatible(card) && card.present && card.config?.enabled !== false && ['available', 'active'].includes(card.status));
    return candidates.length ? candidates.map(card => card.config || {}) : [{}];
  }
  function runtimeValidation(values) {
    const result = {card: {}, problem: null, warning: ''};
    if (!satellite(values.delivery_system)) return result;
    try {
      if (values.enabled) {
        let validCard, firstProblem;
        const tuning = draftTuning(values);
        for (const card of tuningCards(values)) {
          try {resolveDVBTuning(tuning, card); validCard ??= card;}
          catch (error) {firstProblem ??= error;}
        }
        if (!validCard) throw firstProblem;
        // A usable snapshot candidate validates Auto; it does not change desired placement.
        result.card = validCard;
        if (values.adapter_mode === 'auto' && firstProblem) result.warning = 'Some Auto candidates have unsupported inherited tuning; a valid alternative exists in this snapshot. Placement and tuning are not guaranteed.';
      }
      if (values.rf_override) rfConfig(values);
    } catch (error) {result.problem = error;}
    return result;
  }
  function modulationChoices() {
    const delivery = field('delivery_system').value, allowed = satelliteModulations[delivery] || ['auto'];
    const warnings = [];
    for (const name of ['modulation', 'advanced_modulation']) {
      const select = field(name), current = select.value, supported = supportedModulation(current, delivery);
      select.replaceChildren(); option(select, '', 'Inherit fallback / card setting');
      for (const value of allowed) option(select, value, value === 'auto' ? 'Auto' : value.toUpperCase());
      if (current && !allowed.includes(current)) option(select, current, `${supported ? 'Configured value' : 'Unsupported configured value'}: ${current}`, !supported);
      select.value = current;
      if (!supported) warnings.push(`${name === 'modulation' ? 'Main' : 'Advanced'} modulation ${current} is unsupported for ${delivery.toUpperCase()}. Choose a supported value.`);
    }
    const warning = find('dvbStreamModulationWarning'); warning.textContent = warnings.join(' '); warning.hidden = !warnings.length;
  }
  function tuningChoices() {
    const delivery = field('delivery_system').value;
    for (const key of ['fec', 'rolloff']) for (const name of [key, `advanced_${key}`]) {
      const select = field(name), current = select.value, allowed = key === 'fec' ? fecValues : rolloffValues;
      select.replaceChildren(); option(select, '', 'Inherit fallback / card setting');
      for (const value of allowed) option(select, value, value === 'auto' ? 'Auto (overrides fallback)' : key === 'rolloff' ? `0.${value}` : value);
      if (current && !allowed.includes(current)) {
        const supported = !satellite(delivery) || normalizedTuning(key, current, delivery) !== null;
        option(select, current, `${supported ? 'Configured value' : 'Unsupported configured value'}: ${current}`, !supported);
      }
      select.value = current;
    }
  }
  function cardChoices() {
    const select = field('device_key'), previous = select.value, current = original?.dvb?.adapter;
    select.replaceChildren(); option(select, '', current?.mode === 'fixed' && !current.device_key && current.last_address ? `Configured address ${current.last_address} (legacy)` : 'Select a card');
    for (const card of cards) {
      const retained = current?.mode === 'fixed' && card.device_key === current.device_key;
      if (!compatible(card) && !retained) continue;
      const unavailable = !card.present || ['busy_external', 'offline', 'disabled', 'error', 'restarting'].includes(card.status) || card.config?.enabled === false;
      option(select, card.device_key, `${card.config?.alias || 'Unnamed'} / ${card.address} / ${card.model || 'Unknown model'} / ${(card.delivery_systems || []).join(', ')} / ${card.status}`, (!compatible(card) || unavailable) && !retained);
    }
    if (current?.mode === 'fixed' && current.device_key && ![...select.options].some(o => o.value === current.device_key)) option(select, current.device_key, `Configured card ${current.device_key} / ${current.last_address || 'unknown address'} / offline (not in inventory)`);
    select.value = [...select.options].some(o => o.value === previous) ? previous : '';
  }
  function sync() {
    modulationChoices(); tuningChoices();
    const v = readValues(), isSatellite = satellite(v.delivery_system), fixed = v.adapter_mode === 'fixed';
    descrambling.updateProfile(v.softcam_id);
    const runtimeWarning = find('dvbStreamRuntimeWarning');
    runtimeWarning.hidden = isSatellite || !deliveries.includes(v.delivery_system);
    runtimeWarning.textContent = 'Current runtime tunes DVB-S/S2 only. For DVB-C/T/T2, explicitly disable Enabled before saving. Disabled configuration can be edited, but cannot be started by this runtime.';
    for (const el of form.querySelectorAll('[data-dvb-satellite]')) el.hidden = !isSatellite;
    form.querySelector('[data-dvb-symbol]').hidden = !isSatellite && v.delivery_system !== 'dvbc';
    form.querySelector('[data-dvb-fixed]').hidden = !fixed;
    form.querySelector('[data-dvb-rf]').hidden = !v.rf_override;
    const mode = rfMode(v.rf_mode), unicable = ['unicable1', 'unicable2'].includes(mode);
    form.querySelector('[data-dvb-lnb]').hidden = unicable;
    form.querySelector('[data-dvb-unicable]').hidden = !unicable;
    field('unicable_slot').max = mode === 'unicable1' ? '8' : '32';
    for (const opt of field('slot_position').options) opt.disabled = mode === 'unicable1' && !['A', 'B'].includes(opt.value);
    for (const el of form.querySelectorAll('[data-dvb-output]')) el.hidden = el.dataset.dvbOutput !== (httpProtocols.includes(v.protocol) ? 'http' : ['srt', 'udp'].includes(v.protocol) ? v.protocol : 'other');
    for (const el of form.querySelectorAll('[data-dvb-fec]')) el.hidden = !v.srt_fec_enabled;
    const card = cards.find(c => c.device_key === v.device_key), warnings = [];
    if (fixed) {
      if (!card) warnings.push('Configured card is offline or unavailable in inventory; assignment is retained, not inferred from runtime.');
      else {
        if (!compatible(card)) warnings.push('Configured card is incompatible with this delivery system. Select Auto or another compatible card.');
        if (!card.present || !['available', 'active'].includes(card.status) || card.config?.enabled === false) warnings.push(`Card state: ${card.status}. Fixed assignment is retained; successful tuning is not guaranteed.`);
      }
    }
    const validation = runtimeValidation(v), problem = validation.problem, tuningWarning = find('dvbStreamTuningWarning');
    if (validation.warning) warnings.push(validation.warning);
    find('dvbStreamAdapterWarning').textContent = warnings.join(' ');
    tuningWarning.hidden = !problem; tuningWarning.textContent = problem?.message || '';
    const target = problem && field(visibleErrorField(problem.field));
    if (target) revealTarget(target);
    try { find('dvbStreamOutputPreview').textContent = safePreview(outputURL(v, original, settings, window?.location?.hostname)); }
    catch { find('dvbStreamOutputPreview').textContent = 'Complete valid output settings to preview the URL.'; }
    lock();
    for (const el of form.querySelectorAll('[aria-invalid="true"]')) revealTarget(el);
  }
  function clearErrors() {
    for (const el of form.querySelectorAll('[aria-invalid]')) {
      el.removeAttribute('aria-invalid');
      const description = string(el.getAttribute('aria-describedby')).split(' ').filter(id => id && id !== 'dvbStreamNotice').join(' ');
      if (description) el.setAttribute('aria-describedby', description); else el.removeAttribute('aria-describedby');
    }
  }
  function revealTarget(el) {
    for (let parent = el; parent && parent !== form; parent = parent.parentElement) {
      if (parent.tagName === 'DETAILS') parent.open = true;
      if (parent.hidden) parent.hidden = false;
    }
  }
  function visibleErrorField(raw) {
    if (raw === 'dvb_descrambling') return 'descrambling_enabled';
    if (raw.startsWith('dvb_descrambling.')) return raw.replace('dvb_descrambling.', 'descrambling_');
    const names = {'dvb.frequency_khz': 'frequency_mhz', 'dvb.symbol_rate': 'symbol_rate_ksps', 'dvb.adapter.device_key': 'device_key', 'dvb.adapter': 'adapter_mode'};
    if (raw === 'output_url') {
      const protocol = field('protocol').value;
      return httpProtocols.includes(protocol) ? 'mpegts_path' : protocol === 'srt' ? 'srt_port_override' : protocol === 'udp' ? 'udp_port' : 'output_url';
    }
    if (raw.startsWith('card.')) return field('adapter_mode').value === 'fixed' ? 'device_key' : 'adapter_mode';
    if (raw.startsWith('dvb.advanced.')) {
      const key = raw.slice('dvb.advanced.'.length);
      return tuningKeys.includes(key) ? `advanced_${key}` : key;
    }
    const name = names[raw] || raw.replace(/^dvb\.rf_override\./, '').replace(/^dvb\./, '');
    if (name === 'mode') return 'rf_mode';
    if (!satellite(field('delivery_system').value) && ['polarization', 'rolloff', 'stream_id', 'rf_override'].includes(name)) return 'delivery_system';
    return name;
  }
  function rejectionText(error) {
    let text = string(error.message) || 'The request was rejected.';
    const secrets = [field('srt_passphrase').value];
    try {
      const url = new URL(field('output_url').value);
      secrets.push(url.password, decodeURIComponent(url.password), url.searchParams.get('passphrase'));
    } catch { /* A malformed draft URL has no parseable credentials. */ }
    for (const secret of secrets.filter(Boolean)) {
      text = text.split(secret).join('[hidden]').split(encodeURIComponent(secret)).join('[hidden]');
    }
    const code = /^[a-z0-9_]+$/.test(error.code || '') ? ` (${error.code})` : '';
    return `Save rejected${code}: ${text}`;
  }
  function showError(error, remote = false) {
    const el = field(visibleErrorField(string(error.field)));
    message(remote ? rejectionText(error) : error.message, true);
    if (el) {
      el.setAttribute('aria-invalid', 'true');
      el.setAttribute('aria-describedby', [...new Set([...string(el.getAttribute('aria-describedby')).split(' ').filter(Boolean), 'dvbStreamNotice'])].join(' '));
      revealTarget(el); el.focus(); el.scrollIntoView({block: 'nearest'});
    }
  }
  function reveal() {
    if (!dialog.open) dialog.showModal();
    title.focus();
  }
  async function open(id = null) {
    if (phase === 'saving') return false;
    if (phase === 'unknown') {reveal(); return false;}
    descrambling.deactivate();
    clearStatus();
    reads?.abort(); reads = new AbortController(); const token = ++generation, options = {signal: reads.signal};
    streamID = id; statusRevision = -1; original = null; cards = []; settings = {}; phase = 'loading'; invoker = form.ownerDocument.activeElement;
    form.reset(); clearErrors(); title.textContent = id === null ? 'Add DVB stream' : 'Edit DVB stream';
    message('Loading stream, groups, card inventory, Softcams and settings...'); lock(); reveal();
    form.querySelector('.dvb-dialog-body').scrollTop = 0;
    try {
      const [stream, groups, inventory, cams, config] = await Promise.all([
        id === null ? null : requestJSON(`/api/v1/dvb-streams/${encodeURIComponent(id)}`, options),
        requestJSON('/api/v1/dvb-groups', options), loadEditorCards(requestJSON, options),
        requestJSON('/api/v1/softcams', options), requestJSON('/api/v1/settings', options),
      ]);
      if (token !== generation) return false;
      const groupItems = groups?.groups === null ? [] : groups?.groups;
      const softcamItems = cams?.softcams === null ? [] : cams?.softcams;
      if ((id !== null && (stream?.id !== id || !stream?.dvb || typeof stream.name !== 'string' || typeof stream.output_url !== 'string'
          || typeof stream.enabled !== 'boolean' || typeof stream.protocol !== 'string'
          || !Number.isInteger(stream.dvb.frequency_khz) || !Number.isInteger(stream.dvb.service_id)
          || !stream.dvb.adapter || !stream.dvb.advanced || typeof stream.dvb.delivery_system !== 'string'))
          || !Array.isArray(groupItems) || !Array.isArray(softcamItems) || !config) throw Error('Incomplete editor load; saving is disabled.');
      for (const key of ['http_play_port', 'srt_play_port']) integer({[key]:config[key]}, key, 1, 65535, 'Configured play port');
      original = stream; settings = config; cards = inventory;
      choices('group_id', groupItems, 'Ungrouped'); choices('softcam_id', softcamItems, 'None');
      const values = hydrateDVBStream(stream, settings);
      for (const [name, value] of Object.entries(values)) {
        const el = field(name); if (!el || name === 'device_key') continue;
        if (el.type === 'checkbox') el.checked = value; else if (el.tagName === 'SELECT') retain(el, string(value)); else el.value = string(value);
      }
      cardChoices(); retain(field('device_key'), values.device_key); sync();
      find('dvbStreamMetadata').textContent = stream?.dvb?.service ? `Service metadata retained: ${stream.dvb.service.name || ''} / ${stream.dvb.service.provider || ''}. Scrambled and CAID metadata are preserved.` : 'Existing service, scrambled and CAID metadata are preserved on edit.';
      phase = deliveries.includes(values.delivery_system) ? 'ready' : 'unsupported';
      descrambling.activate(id, stream, softcamItems);
      message(phase === 'ready' ? 'Ready. Review desired configuration before saving.' : 'Unsupported delivery system: read-only. This backend cannot save it, even disabled.', phase !== 'ready'); lock();
      return phase === 'ready';
    } catch (error) {
      if (token !== generation) return false;
      reads.abort(); phase = 'load-error'; lock();
      message(error.message?.includes('inventory') ? error.message : 'Unable to load complete editor data. Saving is disabled. Close and reopen to retry the read.', true);
      return false;
    }
  }
  function close() {
    clearStatus();
    if (phase === 'saving') {descrambling.clearCredentials(); return false;}
    descrambling.deactivate();
    reads?.abort(); ++generation;
    if (phase !== 'unknown') phase = 'closed';
    lock(); if (dialog.open) dialog.close(); invoker?.focus?.(); return true;
  }
  async function submit(event) {
    event.preventDefault(); if (phase !== 'ready') return;
    clearErrors(); let payload;
    try {
      const values = readValues(), card = cards.find(c => c.device_key === values.device_key);
      if (values.descrambling_enabled && descrambling.backendAvailable() === false) invalid('descrambling_enabled', 'Backend unavailable: disable the policy or use a CSA-enabled build.');
      if (values.adapter_mode === 'fixed' && card && !compatible(card)) invalid('device_key', 'Select a card compatible with this delivery system or choose Auto.');
      const validation = runtimeValidation(values); if (validation.problem) throw validation.problem;
      payload = serializeDVBStream(values, original, settings, window?.location?.hostname, validation.card);
    } catch (error) {showError(error); return;}
    phase = 'saving'; lock(); message('Saving desired stream configuration. Do not close or retry while the outcome is pending.');
    let result;
    try {
      result = await requestJSON(streamID === null ? '/api/v1/dvb-streams' : `/api/v1/dvb-streams/${encodeURIComponent(streamID)}`, {
        method: streamID === null ? 'POST' : 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
      });
    } catch (error) {
      const definiteRejection = [400, 401, 403, 405, 413, 415, 422].includes(error.status)
        || error.status === 404 && ['group_not_found', 'softcam_not_found'].includes(error.code)
        || error.status === 409 && error.code === 'output_conflict';
      if (definiteRejection) {
        phase = 'ready'; lock(); showError(error, true);
      } else {
        phase = 'unknown'; lock(); message('Save outcome is unknown. Draft retained. Refresh and inspect streams before any further mutation; do not blindly retry.', true);
      }
      return;
    }
    phase = 'ready'; close(); message('Stream saved. Configuration saved, not proof of runtime descrambling or decoded media.');
    // A list refresh is separate from the completed mutation and must never unlock a retry.
    try { await onSaved?.(result); } catch { /* The integrating controller owns refresh failure feedback. */ }
  }
  form.addEventListener('submit', submit);
  form.addEventListener('input', () => {if (phase === 'ready') sync();});
  form.addEventListener('change', event => {
    if (phase !== 'ready') return;
    if (['delivery_system', 'adapter_mode', 'rf_override', 'rf_mode', 'protocol', 'srt_fec_enabled'].includes(event.target.name)) clearErrors();
    if (event.target === field('delivery_system')) cardChoices();
    sync();
  });
  dialog.addEventListener('wheel', () => {
    const active = form.ownerDocument.activeElement;
    // Blur before the native number-input wheel step; do not cancel or consume scrolling.
    if (form.contains(active) && active.matches('input[type="number"]')) active.blur();
  }, {capture: true, passive: true});
  closeButton.addEventListener('click', close);
  dialog.addEventListener('cancel', event => {event.preventDefault(); close();});
  dialog.addEventListener('close', () => {
    // A previous close event may be queued after a new editor has already opened.
    if (dialog.open) return;
    clearStatus();
    if (phase === 'saving') {descrambling.clearCredentials(); return;}
    reads?.abort(); ++generation;
    if (phase !== 'unknown') phase = 'closed';
    descrambling.deactivate(); lock();
  });
  window?.addEventListener?.('pagehide', close);
  function applyEvent(event) {
    if (phase !== 'ready' || event?.resource_id !== streamID || !Number.isSafeInteger(event.revision) || event.revision <= statusRevision) return;
    statusRevision = event.revision;
    if (event.kind === 'dvb.stream.removed') {clearStatus(); descrambling.deactivate(); return;}
    if (event.kind !== 'dvb.stream.changed') return;
    const p = event.payload;
    if (p?.mode === 'runtime') applyStatus({id:streamID, runtime:p.runtime});
    if (p?.mode === 'replace' && p.resource?.id === streamID) applyStatus(p.resource);
  }
  function synchronize() {
    statusRevision = -1; clearStatus(); descrambling.resetEpoch();
  }
  return {open, close, deactivate: close, applyEvent, applyStatus, synchronize, writeState: () => ['saving','unknown'].includes(phase) ? phase : ''};
}
