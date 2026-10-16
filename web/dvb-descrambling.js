// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const text = value => value == null ? '' : String(value);
const fields = ['enabled', 'algorithm', 'caid', 'provider', 'ecm_pid'];
const ownedPolicy = policy => policy ? structuredClone(Object.fromEntries(fields.filter(k => Object.hasOwn(policy, k)).map(k => [k, policy[k]]))) : undefined;
const invalid = (field, message) => {throw Object.assign(new Error(message), {field});};

export function hydrateDescrambling(stream) {
  const p = stream?.dvb_descrambling;
  return {
    descrambling_enabled: p?.enabled ?? false,
    descrambling_algorithm: p?.algorithm ?? 'dvb-csa',
    descrambling_caid: text(p?.caid), descrambling_provider: text(p?.provider),
    descrambling_ecm_pid: text(p?.ecm_pid),
  };
}

export function serializeDescrambling(values, original) {
  if (values.descrambling_remove) return undefined;
  const before = hydrateDescrambling(original);
  if (!Object.hasOwn(values, 'descrambling_enabled') || Object.keys(before).every(k => values[k] === before[k])) {
    return ownedPolicy(original?.dvb_descrambling);
  }
  const p = {enabled:!!values.descrambling_enabled, algorithm:text(values.descrambling_algorithm).trim(),
    caid:text(values.descrambling_caid).trim().toUpperCase(), provider:text(values.descrambling_provider).trim().toUpperCase()};
  for (const [key, width] of [['caid',4],['provider',6]]) {
    if ((p.enabled || p[key]) && !new RegExp(`^[0-9A-F]{${width}}$`).test(p[key])) invalid(`descrambling_${key}`, `${key === 'caid' ? 'CAID' : 'Provider'} requires exactly ${width} hexadecimal digits; enter an explicit value.`);
  }
  const pid = text(values.descrambling_ecm_pid).trim();
  if (pid) {
    if (!/^\d+$/.test(pid) || Number(pid) < 1 || Number(pid) > 8190) invalid('descrambling_ecm_pid', 'ECM PID must be an integer from 1 to 8190, or empty for an unambiguous route.');
    p.ecm_pid = Number(pid);
  }
  if (p.enabled) {
    if (p.algorithm !== 'dvb-csa') invalid('descrambling_algorithm', 'Only DVB-CSA is supported.');
    if (!values.softcam_id) invalid('softcam_id', 'Select an explicit Softcam profile before enabling descrambling.');
  }
  if (!original?.dvb_descrambling && !p.enabled && !p.caid && !p.provider && !pid) return undefined;
  return p;
}

const label = value => text(value).replaceAll('_', ' ') || 'Not checked';
const count = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : 'Not measured';

// This panel reads cached diagnostics only. Saving and the single event feed remain editor-owned.
export function createDescramblingPanel({requestJSON, root = document, onPolicyChange = () => {}}) {
  const find = id => root.querySelector(`#${id}`);
  const tokenField = find('dvbDescramblingToken'), load = find('dvbDescramblingLoad');
  let generation = 0, statusVersion = 0, read, streamID, backend, profiles = [], active = false;
  const put = (id, value) => {find(id).textContent = value;};
  function clearDiagnostics(resetBackend = false) {
    tokenField.value = '';
    find('dvbDescramblingCandidates').replaceChildren();
    if (resetBackend) {backend = undefined; put('dvbDescramblingBackend', 'Not checked');}
    put('dvbDescramblingIdentity', 'Cached service identity not checked');
  }
  function clearCredentials() {
    ++generation; ++statusVersion; read?.abort(); read = undefined;
    tokenField.value = ''; load.disabled = !active || !streamID;
  }
  function invalidateMetadata() {
    clearCredentials(); clearDiagnostics();
    put('dvbDescramblingDiagnosticNotice', 'Cached CA metadata invalidated. Load candidates again after fresh PSI is available.');
  }
  function resetEpoch() {
    clearCredentials(); clearDiagnostics(true);
    put('dvbDescramblingDiagnosticNotice', 'Runtime resynchronizing. Cached diagnostics must be checked again.');
  }
  function applyStatus(snapshot) {
    if (!active || !snapshot) return;
    ++statusVersion;
    const s = snapshot.runtime?.descrambling || snapshot;
    if (snapshot.runtime) {
      put('dvbDescramblingRF', label(snapshot.runtime.state));
    }
    put('dvbDescramblingState', label(s.state));
    put('dvbDescramblingReason', label(s.reason));
    put('dvbDescramblingMetrics', `Queued ${count(s.metrics?.queued)} / Output queued ${count(s.metrics?.output_queued)} / Processed ${count(s.metrics?.processed)} / Dropped ${count(s.metrics?.dropped)}`);
    put('dvbDescramblingSample', typeof s.metrics?.sample_stale === 'boolean'
      ? `${s.metrics.sample_stale ? 'Stale cached sample' : 'Cached sample'}; age ${count(s.metrics.sample_age_ms)} ms` : 'Sample freshness not checked');
    if (typeof snapshot.backend?.available === 'boolean') {
      backend = snapshot.backend.available;
      put('dvbDescramblingBackend', backend ? 'Available (cached check)' : `Backend unavailable (${label(snapshot.backend.reason)}): enabled policy cannot be saved.`);
      const id = snapshot.identity;
      put('dvbDescramblingIdentity', id ? `Cached input ${text(id.input_id)} / generation ${text(id.input_generation)} / ONID ${text(id.onid)} / TSID ${text(id.tsid)} / service ${text(id.service_id)}` : 'No cached service identity; PSI may be missing or stale.');
    }
    if (Array.isArray(snapshot.candidates)) {
      const host = find('dvbDescramblingCandidates'); host.replaceChildren();
      for (const candidate of snapshot.candidates.slice(0,16)) {
        if (!/^[0-9a-f]{4}$/i.test(candidate.caid) || !Number.isInteger(candidate.ecm_pid) || candidate.ecm_pid < 1 || candidate.ecm_pid > 8190) continue;
        const row = host.ownerDocument.createElement('li'), button = host.ownerDocument.createElement('button');
        const scope = candidate.program_level ? 'Program' : 'ES PIDs ' + (candidate.es_pids || []).filter(Number.isInteger).slice(0,64).join(', ');
        const description = host.ownerDocument.createElement('span');
        description.textContent = `CAID ${candidate.caid.toUpperCase()} / ECM PID ${candidate.ecm_pid} / ${scope}`;
        button.type = 'button'; button.textContent = 'Use PID'; button.setAttribute('aria-label', `Use CAID ${candidate.caid} ECM PID ${candidate.ecm_pid}`);
        button.addEventListener('click', () => {
          root.querySelector('[name="descrambling_caid"]').value = candidate.caid.toUpperCase();
          root.querySelector('[name="descrambling_ecm_pid"]').value = String(candidate.ecm_pid);
          onPolicyChange();
        });
        row.append(description,button); host.append(row);
      }
      if (!host.children.length) put('dvbDescramblingDiagnosticNotice', 'No cached CA candidates. Missing or stale PSI is not evidence of a clear service.');
    }
    onPolicyChange();
  }
  function updateProfile(id) {
    const profile = profiles.find(p => p.id === id);
    put('dvbDescramblingAuth', !id ? 'No profile selected' : !profile ? 'Profile unavailable' : profile.enabled === false ? 'Profile disabled' : profile.runtime?.authenticated === true ? 'Authenticated (not media success)' : profile.runtime?.authenticated === false ? 'Not authenticated' : 'Authentication not checked');
  }
  function deactivate() {
    active = false; ++generation; read?.abort(); read = undefined; streamID = null; profiles = [];
    clearDiagnostics(true); load.disabled = true;
    find('dvbDescramblingAccess').open = false;
  }
  function activate(id, current = null, cams = []) {
    deactivate(); active = true; streamID = id; profiles = cams;
    load.disabled = !id;
    put('dvbDescramblingDiagnosticNotice', id ? 'Optional: load cached candidates with an existing read-scoped token. No tuning or scanning.' : 'Save the stream before reading cached candidates.');
    put('dvbDescramblingRF', label(current?.runtime?.state));
    put('dvbDescramblingState', 'Not checked'); put('dvbDescramblingReason', 'Not checked');
    put('dvbDescramblingMetrics', 'Counters not measured'); put('dvbDescramblingSample', 'Sample freshness not checked');
    updateProfile(current?.softcam_id || '');
    if (current?.runtime?.descrambling) applyStatus(current);
  }
  async function readStatus() {
    if (!active || !streamID || load.disabled) return;
    const credential = tokenField.value.trim();
    if (!credential || /\s/.test(credential)) {put('dvbDescramblingDiagnosticNotice','Enter an existing read-scoped token.'); return;}
    read?.abort(); read = new AbortController(); const fence = ++generation, statusFence = statusVersion;
    load.disabled = true; put('dvbDescramblingDiagnosticNotice','Reading cached diagnostics...');
    try {
      const snapshot = await requestJSON(`/api/v1/dvb-streams/${encodeURIComponent(streamID)}/descrambling`, {signal:read.signal, headers:{Authorization:`Bearer ${credential}`}});
      if (!active || fence !== generation) return;
      if (statusFence !== statusVersion) {put('dvbDescramblingDiagnosticNotice','Stream status changed during this read. Load cached candidates again for a current sample.'); return;}
      if (typeof snapshot?.backend?.available !== 'boolean' || !Array.isArray(snapshot.candidates) || !snapshot.metrics) throw Error('Invalid diagnostics');
      put('dvbDescramblingDiagnosticNotice','Cached diagnostics loaded. Provider must still be entered explicitly.'); applyStatus(snapshot);
    } catch (error) {
      if (!active || fence !== generation) return;
      clearDiagnostics();
      // Never render server exception text: it may echo the supplied token.
      put('dvbDescramblingDiagnosticNotice',[401,403].includes(error.status) ? 'Read token rejected or revoked. Diagnostics cleared; ordinary editing remains available.' : 'Cached diagnostics unavailable. Ordinary editing remains available.');
      onPolicyChange();
    } finally {if (active && fence === generation) load.disabled = false;}
  }
  load.addEventListener('click', readStatus);
  tokenField.addEventListener('keydown', event => {
    if (event.key === 'Enter') {event.preventDefault(); void readStatus();}
  });
  return {activate, deactivate, applyStatus, updateProfile, clearCredentials, invalidateMetadata, resetEpoch, backendAvailable:() => backend};
}
