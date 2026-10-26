// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const statuses = ["available", "active", "busy_external", "error", "offline", "disabled"];
const systems = ["dvbs", "dvbs2", "dvbc", "dvbt", "dvbt2", "atsc", "isdbt"];
const systemAliases = {"dvb-s": "dvbs", "dvb-s2": "dvbs2", "dvb-c": "dvbc", "dvb-t": "dvbt", "dvb-t2": "dvbt2", "isdb-t": "isdbt"};
const sharedRFWarning = "Shared RF or Unicable equipment may briefly disrupt other adapters.";
const statusLabels = { available: "Available", active: "Active", busy_external: "Externally busy", error: "Error", offline: "Offline", disabled: "Disabled" };
const snapshotLabel = "Inventory snapshot; automatic updates are not yet connected.";
const shown = value => value === null || value === undefined || value === "" ? "unavailable" : String(value);
const structured = value => value == null ? "unavailable" : JSON.stringify(value, null, 2);
const numberUnit = (value, divisor, unit) => Number.isFinite(value) ? `${value / divisor} ${unit}` : "unavailable";
const percent = value => Number.isFinite(value) ? `${value}%` : "unavailable";
const rfFields = ["lof1", "lof2", "slof", "force_tone", "mode", "unicable_slot", "slot_position", "slot_frequency"];
const advancedFields = ["enable_monitoring", "modulation", "fec", "rolloff", "stream_id", "timeout_sec", "dvb_api", "dvb_api_v3"];
const operationStates = ["queued", "running", "succeeded", "partial", "failed", "cancelled"];
const pendingOperation = op => op && ["queued", "running"].includes(op.status);
const restartPending = record => record && record.phase !== "rejected" && (!record.op || pendingOperation(record.op));
const definiteRejection = reason => reason?.status >= 400 && reason.status < 500 && ![408, 499].includes(reason.status);
const cardPath = id => `/api/v1/dvb-cards/${encodeURIComponent(id)}`;
const cardLabel = card => [card.address, card.config?.alias].filter(Boolean).join(" / ") || card.id;

function restartBlock(card) {
  if (card?.status === "busy_external") return "Owned by another process";
  if (!card?.present || card.config?.enabled !== true || !["active", "available"].includes(card.status)
    || card.application?.state === "runtime_disabled") return "Restart unavailable for this card state";
  if (!Number.isSafeInteger(card.active_streams) || card.active_streams < 0) return "Attached stream count unavailable";
  return "";
}

function readQuery(hash) {
  const params = new URLSearchParams(hash.startsWith("#dvb-cards?") ? hash.slice(11) : "");
  const page = Number(params.get("page"));
  const limit = Number(params.get("limit"));
  const rawSystem = (params.get("delivery_system") || "").trim().toLowerCase();
  const system = Object.hasOwn(systemAliases, rawSystem) ? systemAliases[rawSystem] : rawSystem;
  return {
    q: params.get("q") || "", status: statuses.includes(params.get("status")) ? params.get("status") : "",
    delivery_system: systems.includes(system) ? system : "",
    model: params.get("model") || "", sort: ["address", "type"].includes(params.get("sort")) ? params.get("sort") : "address",
    page: Number.isSafeInteger(page) && page > 0 ? page : 1, limit: [50, 100, 200].includes(limit) ? limit : 100,
  };
}

function transportText(value) {
  if (!value) return "Transport unavailable";
  return [shown(value.delivery_system), numberUnit(value.frequency_khz, 1000, "MHz"),
    numberUnit(value.symbol_rate, 1000, "kSym/s"), `Pol ${shown(value.polarization)}`].join("\n");
}

function signalText(signal) {
  if (!signal) return "Signal/SNR/BER/UNC unavailable";
  return [signal.locked === true ? "Locked" : signal.locked === false ? "Unlocked" : "Lock unavailable",
    `Signal ${percent(signal.signal_percent)}`, `SNR ${percent(signal.snr_percent)}`,
    `BER ${shown(signal.ber)}`, `UNC ${shown(signal.uncorrected_blocks)}`].join("\n");
}

export function createDVBCardsController({ requestJSON, root = document, window = globalThis.window, confirmAction = message => window.confirm(message), canManage = () => true }) {
  const doc = root.ownerDocument || root;
  const find = id => root.querySelector(`#${id}`);
  const body = find("dvbCardsTableBody");
  const notice = find("dvbCardsNotice");
  const error = find("dvbCardsError");
  const loading = find("dvbCardsLoading");
  const empty = find("dvbCardsEmpty");
  const refreshButton = find("refreshDVBCardsBtn");
  const prev = find("dvbCardsPrev"), next = find("dvbCardsNext");
  const pageInfo = find("dvbCardsPageInfo");
  const unknownPageInfo = pageInfo?.textContent || "Page - of -";
  const controls = { q: find("dvbCardsSearch"), delivery_system: find("dvbCardsDelivery"), model: find("dvbCardsModel"),
    status: find("dvbCardsStatus"), sort: find("dvbCardsSort"), limit: find("dvbCardsLimit") };
  const rows = new Map(), revisions = new Map(), ownershipSamples = new Map();
  let nextEventReadAt = 0;
  const settingsDialog = find("cardSettingsDialog"), settingsForm = find("cardSettingsForm");
  const settingsNotice = find("cardSettingsNotice"), settingsSave = find("cardSettingsSave"), settingsClose = find("cardSettingsClose");
  const operationDialog = find("cardRestartDialog"), operationStatus = find("cardOperationStatus"), operationError = find("cardOperationError");
  const operationRetry = find("cardOperationRetry"), operationStreams = find("cardOperationStreams");
  const saveLocks = new Map(), operations = new Map();
  let settingsView, operationView;
  let active = false, query, generation = 0, life = 0, request, pendingLoad;
  let searchTimer, eventTimer, refreshRequest, refreshToken = 0, refreshPending = false;
  let total = null, lastPage, localFailure = "", loadFailure = "", refreshSuccess = false, rowSequence = 0;
  const handlers = [];
  let epoch = 0, dirty = false, liveState = 'stopped', liveReason = '';
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const ownershipFields = ['application','current_transport','active_sessions','active_streams','signal','last_error'];
  const nullableObject = value => value === null || object(value);
  const validOwnership = value => object(value) && ['application','current_transport','signal'].every(key => nullableObject(value[key]))
    && ['active_sessions','active_streams'].every(key => Number.isSafeInteger(value[key]) && value[key] >= 0)
    && (value.last_error === undefined || typeof value.last_error === 'string');
  // HTTP retains diagnostics; SSE projects nonempty errors to "card unavailable".
  const ownershipKey = value => JSON.stringify([value?.active_sessions > 0,value?.active_streams > 0,!!value?.current_transport,!!value?.last_error]);
  const mergeEvent = (card,event) => event.payload.mode === 'replace' ? event.payload.resource
    : {...card,...Object.fromEntries(ownershipFields.map(key => [key,event.payload.ownership[key]]))};
  function setLiveState({state,reason = ''} = {}) {
    liveState = ['connecting','syncing','live','reconnecting','stopped'].includes(state) ? state : 'stopped';
    liveReason = String(reason || '');feedback();
  }

  function node(tag, text, className) {
    const element = doc.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }

  function setText(element, text) {
    if (element && element.textContent !== text) element.textContent = text;
  }

  function message(element, text, failure = false) {
    setText(element, text); element.hidden = !text;
    element.className = `notice${failure ? " err" : ""}`;
    element.setAttribute("role", failure ? "alert" : "status");
  }

  function pageMessage(text, failure = false) {
    message(find("dvbCardsActionNotice"), text, failure);
  }

  function field(name) {
    return settingsForm.elements.namedItem(name);
  }

  function settingsCurrent(view) {
    return active && settingsView === view && settingsDialog.open && view.life === life;
  }

  function settingsEnabled() {
    const view = settingsView;
    const locked = view && saveLocks.get(view.id);
    const enabled = active && canManage() && view?.loaded && !view.saved && !locked;
    settingsForm.querySelectorAll("fieldset").forEach(el => {el.disabled = !enabled;});
    settingsSave.disabled = !enabled;
    settingsSave.hidden = !canManage();
    settingsClose.disabled = !!view?.saving;
  }

  function lockMessage(lock) {
    return lock.state === "pending" ? "A save is still pending. Do not retry; closing does not cancel the server request."
      : "Save outcome is unknown. Verify desired settings before any further mutation; this view will not retry the save.";
  }

  function syncRF() {
    const mode = field("rf_mode").value, unicable = mode === "unicable1" || mode === "unicable2";
    settingsForm.querySelector('[data-rf-section="lnb"]').hidden = unicable;
    settingsForm.querySelector('[data-rf-section="unicable"]').hidden = !unicable;
    setText(find("cardRFHint"), unicable
      ? `Unicable ${mode === "unicable1" ? "I: slots 1-8" : "II: slots 1-32"}. Choose the installed user band. Oscillator and tone values are retained while hidden; all RF frequencies are MHz.`
      : "Universal / custom oscillator and tone settings. Unicable values are retained while hidden. All RF frequencies are MHz; zero uses the server default.");
    const select = field("unicable_slot"), current = select.value;
    const max = mode === "unicable1" ? 8 : 32;
    const values = Array.from({length: max}, (_, i) => String(i + 1));
    const opts = values.map(value => {const option = node("option", value); option.value = value; return option;});
    if (!values.includes(current)) {
      const invalid = node("option", `${current || "Unset"} - select a valid slot`);
      invalid.value = current; invalid.disabled = true; opts.unshift(invalid);
    }
    select.replaceChildren(...opts); select.value = current;
  }

  function hydrate(card) {
    const config = card.config;
    if (!config || typeof config.enabled !== "boolean" || !config.rf_defaults || !config.advanced
      || !rfFields.every(key => Object.hasOwn(config.rf_defaults, key))
      || !advancedFields.every(key => Object.hasOwn(config.advanced, key))) throw new Error("Incomplete card settings response; saving is disabled");
    field("alias").value = config.alias || ""; field("enabled").checked = config.enabled;
    for (const [keys, values] of [[rfFields, config.rf_defaults], [advancedFields, config.advanced]]) for (const key of keys) {
      const control = field(key === "mode" ? "rf_mode" : key);
      if (!control) continue;
      if (control.type === "checkbox") control.checked = values[key];
      else {
        if (control.tagName === "SELECT" && ![...control.options].some(opt => opt.value === String(values[key]))) {
          const option = node("option", String(values[key])); option.value = String(values[key]); control.append(option);
        }
        control.value = String(values[key]);
      }
    }
    const retained = find("cardAdvancedRetained"); retained.replaceChildren();
    for (const key of ["modulation", "fec", "rolloff", "stream_id", "dvb_api_v3"]) retained.append(node("dt", key), node("dd", shown(config.advanced[key])));
    syncRF();
  }

  function closeSettings(force = false) {
    const view = settingsView;
    if (!view || view.saving && !force) return;
    clearTimeout(view.closeTimer); view.abort?.abort(); settingsView = undefined;
    settingsDialog.close();
    if (active && view.opener?.isConnected) view.opener.focus({preventScroll: true});
  }

  async function openSettings(id, opener) {
    if (!active || !canManage() || settingsView?.saving) return;
    closeSettings();
    const view = {id, life, opener, abort: new AbortController(), loaded: false}; settingsView = view;
    settingsForm.reset(); settingsEnabled();
    settingsForm.setAttribute("aria-busy", "true");
    setText(find("cardSettingsDialogTitle"), `Card settings - ${cardLabel(rows.get(id).card)}`);
    message(settingsNotice, "Loading cached desired settings (no hardware refresh)..."); settingsDialog.showModal();
    settingsDialog.querySelector(".dvb-dialog-body").scrollTop = 0;
    try {
      const card = await requestJSON(cardPath(id), {signal: view.abort.signal});
      if (!settingsCurrent(view)) return;
      if (!canManage()) return;
      if (card?.id !== id) throw new Error("Card settings identity mismatch");
      hydrate(card); view.config = card.config; view.loaded = true;
      setText(find("cardSettingsDialogTitle"), `Card settings - ${cardLabel(card)}`);
      const lock = saveLocks.get(id);
      message(settingsNotice, lock ? lockMessage(lock) : "Editing cached desired settings. Save does not confirm successful tuning.", !!lock);
    } catch (reason) {
      if (settingsCurrent(view)) message(settingsNotice, `Settings could not be loaded: ${reason?.message || reason}`, true);
    } finally {
      if (settingsCurrent(view)) {settingsForm.removeAttribute("aria-busy"); settingsEnabled();}
    }
  }

  function focusSetting(name) {
    const key = String(name || "").replace(/^(config\.)?(rf_defaults|advanced)\./, "");
    const control = field(key === "mode" ? "rf_mode" : key);
    if (!control) return;
    const section = control.closest("[data-rf-section]"); if (section) section.hidden = false;
    control.focus();
  }

  function settingsPayload(config) {
    const pick = (value, keys) => Object.fromEntries(keys.map(key => [key, value[key]]));
    const rf = pick(config.rf_defaults, rfFields), advanced = pick(config.advanced, advancedFields);
    const numeric = name => {
      const input = field(name), value = input.valueAsNumber;
      if (!Number.isSafeInteger(value) || value < 0) throw Object.assign(new Error("Enter a non-negative whole number"), {field: name});
      return value;
    };
    for (const key of ["lof1", "lof2", "slof", "slot_frequency"]) rf[key] = numeric(key);
    rf.mode = field("rf_mode").value; rf.force_tone = field("force_tone").checked;
    rf.slot_position = field("slot_position").value; rf.unicable_slot = Number(field("unicable_slot").value);
    if (["unicable1", "unicable2"].includes(rf.mode)) {
      const max = rf.mode === "unicable1" ? 8 : 32;
      if (!Number.isSafeInteger(rf.unicable_slot) || rf.unicable_slot < 1 || rf.unicable_slot > max) throw Object.assign(new Error(`Choose a Unicable slot between 1 and ${max}; the previous slot has not been changed automatically.`), {field: "unicable_slot"});
      if (rf.slot_frequency <= 0) throw Object.assign(new Error("User-band frequency must be positive (MHz)"), {field: "slot_frequency"});
    }
    advanced.timeout_sec = numeric("timeout_sec"); advanced.enable_monitoring = field("enable_monitoring").checked;
    advanced.dvb_api = field("dvb_api").value;
    if (advanced.dvb_api !== config.advanced.dvb_api) advanced.dvb_api_v3 = advanced.dvb_api === "v3";
    return {alias: field("alias").value, enabled: field("enabled").checked, rf_defaults: rf, advanced};
  }

  function applicationMessage(card) {
    const application = card.application;
    return `Saved desired settings for ${cardLabel(card)}. This is not confirmation of hardware application or tuning. Application: ${application?.state || "unavailable"}. ${[application?.reason, application?.error].filter(Boolean).join(" / ")}`.trim();
  }

  async function saveSettings(event) {
    event.preventDefault();
    const view = settingsView;
    if (!canManage() || !view || !settingsCurrent(view) || !view.loaded || view.saved || saveLocks.has(view.id)) return;
    let payload;
    try {payload = settingsPayload(view.config);} catch (reason) {message(settingsNotice, reason.message, true); focusSetting(reason.field); return;}
    const lock = {state: "pending", abort: new AbortController()}; saveLocks.set(view.id, lock);
    view.saving = true; settingsEnabled(); settingsForm.setAttribute("aria-busy", "true");
    message(settingsNotice, "Saving desired settings... Wait for the response; this request must not be repeated.");
    try {
      const card = await requestJSON(cardPath(view.id), {method: "PUT", body: JSON.stringify(payload), signal: lock.abort.signal});
      if (card?.id !== view.id || !card.config) throw new Error("Invalid saved card response");
      saveLocks.delete(view.id);
      if (!settingsCurrent(view)) return;
      view.saved = true;
      // Fence older inventory snapshots before patching the affected keyed row.
      invalidateLoad();
      const row = rows.get(view.id); if (row) patchRow(row, card);
      const text = applicationMessage(card);
      message(settingsNotice, text); pageMessage(text, !!card.application?.error);
      view.closeTimer = setTimeout(() => {if (settingsCurrent(view)) closeSettings();}, 600);
    } catch (reason) {
      // A rejected validation/conflict is definite; transport/server failures may have committed.
      if (definiteRejection(reason)) saveLocks.delete(view.id);
      else lock.state = "unknown";
      if (settingsCurrent(view)) {
        message(settingsNotice, saveLocks.has(view.id) ? `${lockMessage(lock)} ${reason?.message || reason}` : `Save failed: ${reason?.message || reason}`, true);
        view.saving = false; settingsEnabled(); focusSetting(reason.field);
      }
    } finally {
      view.saving = false;
      if (settingsCurrent(view)) {settingsForm.removeAttribute("aria-busy"); settingsEnabled();}
    }
  }

  function validOperation(op, cardID, opID) {
    return op && typeof op.id === "string" && op.id.length > 0 && (!opID || op.id === opID)
      && op.kind === "dvb.card.restart" && op.resource_id === cardID && operationStates.includes(op.status)
      && (op.stream_results === undefined || Array.isArray(op.stream_results) && op.stream_results.every(item => item && typeof item.id === "string" && typeof item.ok === "boolean"));
  }

  function scopedOperationPath(op, value) {
    if (typeof value !== "string") throw new Error("Missing operation status path");
    const url = new URL(value, window.location.origin);
    const parts = url.pathname.match(/^\/api\/v1\/dvb-cards\/([^/]+)\/operations\/([^/]+)$/);
    if (url.origin !== window.location.origin || url.username || url.password || url.search || url.hash || !parts
      || decodeURIComponent(parts[1]) !== op.resource_id || decodeURIComponent(parts[2]) !== op.id) throw new Error("Invalid card-scoped operation path");
    return url.pathname;
  }

  function interested(record) {
    return active && operationView?.record === record && operationDialog.open;
  }

  function syncActions(row) {
    const record = operations.get(row.card?.id);
    const blocked = restartBlock(row.card);
    const manage = canManage();
    row.settings.hidden = !manage;
    row.settings.disabled = !active || !manage;
    row.restart.hidden = !manage;
    row.restart.disabled = !active || !manage || !!blocked || !!restartPending(record);
    row.restartSection.hidden = !manage && !record;
    row.restart.title = blocked || (restartPending(record) ? "A restart is pending or its outcome is unknown; use Restart progress" : `Restart this card. ${sharedRFWarning}`);
    row.progress.hidden = !record || ["confirming", "checking"].includes(record.phase);
    row.progress.disabled = !active;
    setText(row.hint, !manage ? record ? "Use Restart progress for the latest known outcome." : ""
      : blocked || (record ? "Use Restart progress for the latest known outcome." : `Restart interrupts this card's streams. ${sharedRFWarning}`));
  }

  function stopPoll(record) {
    clearTimeout(record.timer); record.timer = undefined; record.version++;
    record.readAbort?.abort();
  }

  function showOperation(record) {
    if (!interested(record)) return;
    const op = record.op;
    const labels = {queued: "Queued", running: "Running", succeeded: "Succeeded", partial: "Partial - some streams did not resume", failed: "Failed", cancelled: "Cancelled"};
    const text = op ? [labels[op.status], Number.isFinite(op.progress) ? `${op.progress}%` : "", op.message, op.error].filter(Boolean).join(". ")
      : record.phase === "posting" ? "Submitting restart... Closing does not cancel the server operation."
        : record.phase === "rejected" ? "Restart rejected. No new operation was accepted."
        : "Restart outcome is unknown. Do not repeat the restart; verify server state before another mutation.";
    message(operationStatus, text, record.phase === "rejected" || op && ["partial", "failed", "cancelled"].includes(op.status));
    message(operationError, record.error || "", true);
    operationRetry.hidden = !record.error || !record.op;
    operationRetry.disabled = !!record.reading;
    operationStreams.replaceChildren(...(op?.stream_results || []).map(item => node("li", `${item.id}: ${item.ok ? "completed" : `failed - ${item.error || "No error detail"}`}`)));
  }

  function schedulePoll(record) {
    if (!interested(record) || !pendingOperation(record.op) || record.reading || record.timer || record.error) return;
    record.timer = setTimeout(() => {record.timer = undefined; void pollOperation(record);}, Math.max(1000, (record.lastRead || 0) + 1000 - Date.now()));
  }

  async function pollOperation(record) {
    if (!interested(record) || !record.op || record.reading) return;
    const delay = (record.lastRead || 0) + 1000 - Date.now();
    if (delay > 0) {if (!record.timer) record.timer = setTimeout(() => {record.timer = undefined; void pollOperation(record);}, delay); return;}
    clearTimeout(record.timer); record.timer = undefined;
    record.reading = true; record.lastRead = Date.now(); record.error = "";
    const version = record.version, lifecycle = life;
    const abort = new AbortController(); record.readAbort = abort; showOperation(record);
    try {
      const op = await requestJSON(record.path, {signal: abort.signal});
      if (!interested(record) || lifecycle !== life || version !== record.version) return;
      if (!validOperation(op, record.cardID, record.op.id)) throw new Error("Invalid operation identity or status");
      record.op = op;
    } catch (reason) {
      if (interested(record) && lifecycle === life && version === record.version) record.error = `Status read failed (operation outcome unchanged): ${reason?.message || reason}`;
    } finally {
      record.reading = false; record.readAbort = undefined;
      if (interested(record)) {
        showOperation(record); const row = rows.get(record.cardID); if (row) syncActions(row);
        schedulePoll(record);
      }
    }
  }

  function closeOperation() {
    if (!operationView) return;
    const view = operationView; operationView = undefined; stopPoll(view.record); operationDialog.close();
    if (active && view.opener?.isConnected) view.opener.focus({preventScroll: true});
  }

  function openOperation(record, opener) {
    if (!active) return;
    closeOperation(); operationView = {record, opener};
    if (pendingOperation(record.op)) record.error = "";
    setText(find("cardOperationTitle"), `Card restart - ${record.label}`); operationDialog.showModal(); showOperation(record);
    operationDialog.querySelector(".dvb-dialog-body").scrollTop = 0;
    schedulePoll(record);
  }

  async function restartCard(id, opener) {
    const row = rows.get(id), existing = operations.get(id);
    if (!active || !canManage() || !row || restartBlock(row.card) || restartPending(existing)) return;
    const card = row.card, lifecycle = life;
    const record = {cardID: id, label: cardLabel(card), phase: "confirming", version: 0, revision: 0, error: ""};
    operations.set(id, record); syncActions(row);
    const current = () => active && lifecycle === life && operations.get(id) === record;
    try {
      const confirmed = await confirmAction(`Restart ${record.label}? This interrupts ${card.active_streams} attached streams on this card. Other cards are not restarted by AstraX. ${sharedRFWarning}`);
      if (!current()) return;
      if (!confirmed || !canManage()) {operations.delete(id); return;}
      record.phase = "checking"; record.actionAbort = new AbortController();
      const latest = await requestJSON(cardPath(id), {signal: record.actionAbort.signal});
      if (!current()) return;
      if (!canManage()) {operations.delete(id); return;}
      const blocked = rows.get(id) !== row || latest?.id !== id ? "Card identity changed"
        : restartBlock(row.card) || restartBlock(latest);
      if (blocked || latest.active_streams !== card.active_streams || row.card.active_streams !== card.active_streams) throw new Error(blocked || "Attached stream count changed. Review the card and confirm again.");
      // No await between the final safety check and action dispatch.
      patchRow(row, latest); record.phase = "posting"; openOperation(record, opener);
      const result = await requestJSON(`${cardPath(id)}/restart`, {method: "POST", signal: record.actionAbort.signal});
      if (!validOperation(result, id)) throw new Error("Invalid accepted operation identity or status");
      const path = scopedOperationPath(result, result.operation_url);
      record.op = result; record.path = path; record.phase = "known";
      if (current()) {showOperation(record); schedulePoll(record);}
    } catch (reason) {
      if (record.phase === "posting") {
        record.phase = definiteRejection(reason) ? "rejected" : "unknown";
        record.error = `${record.phase === "rejected" ? "Restart rejected" : "Restart outcome is unknown"}: ${reason?.message || reason}. No restart will be retried automatically.`;
        if (current()) showOperation(record);
      } else if (current()) {operations.delete(id); pageMessage(`Restart not submitted: ${reason?.message || reason}`, true);}
    } finally {
      if (active && lifecycle === life) {
        // Preflight may outlive its row; reconcile using the current row and operation record.
        const currentRow = rows.get(id);
        if (currentRow) syncActions(currentRow);
      }
    }
  }

  function writeQuery() {
    const suffix = new URLSearchParams(Object.entries(query).filter(([, value]) => value !== "")).toString();
    // replaceState preserves tab navigation without a reentrant hashchange.
    if (window.location.hash.split("?")[0] === "#dvb-cards") window.history.replaceState(window.history.state, "", `#dvb-cards?${suffix}`);
    return suffix;
  }

  function options(select, values, selected, allLabel) {
    if (!select) return;
    const entries = [...new Set([...values, ...(selected ? [selected] : [])])];
    const pairs = allLabel ? [["", allLabel], ...entries.map(value => [value, statusLabels[value] || value])] : entries.map(value => [String(value), String(value)]);
    const signature = JSON.stringify(pairs);
    if (select.dataset.options !== signature) {
      select.replaceChildren(...pairs.map(([value, label]) => {
        const option = node("option", label); option.value = value; return option;
      }));
      select.dataset.options = signature;
    }
    select.value = String(selected);
  }

  function syncControls(facets = lastPage?.facets) {
    options(controls.status, statuses, query.status, "All statuses");
    options(controls.delivery_system, facets?.delivery_systems || systems, query.delivery_system, "All systems");
    options(controls.model, facets?.models || [], query.model, "All models");
    options(controls.limit, [50, 100, 200], query.limit);
    controls.q.value = query.q;
    controls.sort.value = query.sort;
    Object.values(controls).forEach(control => { if (control) control.disabled = !active; });
    setText(refreshButton, canManage() ? "Refresh" : "Refresh view");
    refreshButton.disabled = !active || refreshPending;
    const pages = total === null ? null : Math.max(1, Math.ceil(total / query.limit));
    if (prev) prev.disabled = !active || pages === null || query.page <= 1;
    if (next) next.disabled = !active || pages === null || query.page >= pages;
    setText(pageInfo, pages === null ? unknownPageInfo : `Page ${query.page} of ${pages} (${total} cards)`);
  }

  function feedback(page = lastPage) {
    const failure = [...new Set([loadFailure, localFailure, page?.refresh_error].filter(Boolean))].join("\n");
    const stale = !!failure || !!page?.stale;
    const timestamp = page?.refreshed_at;
    const validTime = typeof timestamp === "string" && !timestamp.startsWith("0001-") && Number.isFinite(Date.parse(timestamp));
    const timing = validTime ? `Last refreshed: ${timestamp}.` : "Inventory never read (no refresh time).";
    const result = refreshPending ? canManage() ? "Refreshing hardware inventory..." : "Refreshing cached inventory view..."
      : stale ? "Stale inventory." : refreshSuccess ? "Refresh successful." : "";
    setText(notice, `${result} ${timing} ${liveState === 'live' ? dirty || request ? 'Syncing card status; latest completed inventory snapshot shown.' : 'Live updates connected.' : `${liveState}; snapshot is not live. ${snapshotLabel}`} ${liveReason}`.trim());
    notice.hidden = false;
    notice.className = `notice ${stale ? "err" : ""}`.trim();
    error.hidden = !failure;
    setText(error, failure);
  }

  function makeRow(card) {
    const main = node("tr"); main.dataset.cardId = card.id;
    const cells = ["Card", "Hardware", "Status/owner", "Transport/usage", "Signal", "Actions"].map(label => {
      const cell = node("td"); cell.dataset.label = label; return cell;
    });
    const parts = [2, 3, 2, 2, 3].map((count, i) => Array.from({length: count}, (_, j) => {
      const part = node("span", "", j ? "dvb-card-secondary" : "dvb-card-primary");
      if (j) cells[i].append("\n");
      cells[i].append(part); return part;
    }));
    main.append(...cells);
    const detail = node("tr"); detail.className = "dvb-card-details";
    detail.id = `dvb-card-detail-${++rowSequence}`; detail.hidden = true;
    const detailCell = node("td"); detailCell.colSpan = 6;
    const explanation = node("p", `Application state is scheduler acceptance, not successful tuning. Settings save desired configuration; Restart targets this card. ${sharedRFWarning}`, "hint");
    const raw = node("details", undefined, "dvb-card-raw");
    const list = node("dl"); raw.append(node("summary", "All technical details and configuration"), list);
    const restartSection = node("section", undefined, "dvb-card-restart");
    const restartTitle = node("h4"); restartSection.append(restartTitle);
    detailCell.append(explanation, raw, restartSection); detail.append(detailCell);
    const button = node("button", "Details"); button.type = "button";
    button.dataset.cardDetails = card.id;
    button.setAttribute("aria-expanded", "false"); button.setAttribute("aria-controls", detail.id);
    cells[5].className = "dvb-card-actions";
    const actions = {};
    for (const [key, name] of [["settings", "Settings"], ["restart", "Restart"], ["progress", "Restart progress"]]) {
      const action = node("button", name); action.type = "button"; action.disabled = true;
      action.dataset.cardAction = key; action.dataset.cardId = card.id; actions[key] = action;
      if (key === "settings") cells[5].append(action, button);
      else {action.setAttribute("aria-describedby", `${detail.id}-actions`); restartSection.append(action);}
    }
    const hint = node("small", "", "hint"); hint.id = `${detail.id}-actions`;
    restartSection.insertBefore(hint, actions.restart);
    return {main, detail, cells, parts, list, restartTitle, restartSection, fields: new Map(), card: null, hint, ...actions};
  }

  function patchRow(row, card) {
    const owner = [card.owner_command, card.owner_pid ? `PID ${card.owner_pid}` : ""].filter(Boolean).join(" / ");
    const signal = signalText(card.signal).split("\n");
    const values = [
      [shown(card.address), card.config?.alias || ""],
      [shown(card.model), `${shown(card.manufacturer)} / ${shown(card.frontend_type)}`, (card.delivery_systems || []).join(" / ")],
      [statusLabels[card.status] || shown(card.status), owner || (card.status === "busy_external" ? "Owner unidentified" : "")],
      [transportText(card.current_transport).replaceAll("\n", " / "), `${shown(card.active_sessions)} sessions / ${shown(card.active_streams)} streams`],
      [signal[0], signal.slice(1, 3).join(" / "), signal.slice(3).join(" / ")],
    ];
    values.forEach((value, i) => value.forEach((text, j) => setText(row.parts[i][j], text)));
    if (row.cells[2].dataset.status !== card.status) row.cells[2].dataset.status = card.status;
    setText(row.restartTitle, `Restart ${cardLabel(card)}`);
    const fields = {
      device_key: shown(card.device_key), device_path: shown(card.device_path), sysfs_path: shown(card.sysfs_path),
      capabilities: structured({frontend_type: card.frontend_type, delivery_systems: card.delivery_systems}),
      rf_defaults: structured(card.config?.rf_defaults), advanced: structured(card.config?.advanced),
      "Desired configuration": structured(card.config), "Application (desired / applied)": structured(card.application),
      "Current transport": card.current_transport ? `${transportText(card.current_transport)}\n${structured(card.current_transport)}` : "unavailable",
      "Signal snapshot": card.signal ? `${signalText(card.signal)}\nStatus bits ${shown(card.signal.status_bits)}` : "unavailable",
      Warning: shown(card.warning), "Recent error": shown(card.last_error), "Updated at": shown(card.updated_at),
    };
    for (const [label, value] of Object.entries(fields)) {
      let field = row.fields.get(label);
      if (!field) { field = node("dd"); row.fields.set(label, field); row.list.append(node("dt", label), field); }
      setText(field, value);
    }
    row.card = card;
    syncActions(row);
  }

  function render(page) {
    const focused = body.contains(doc.activeElement) ? doc.activeElement : null;
    const ids = new Set(page.items.map(card => card.id));
    for (const [id, row] of rows) {
      if (!ids.has(id)) { row.main.remove(); row.detail.remove(); rows.delete(id); }
    }
    // Insert only out-of-place pairs: unchanged controls and focus remain intact.
    let cursor = body.firstChild;
    for (const card of page.items) {
      let row = rows.get(card.id);
      if (!row) { row = makeRow(card); rows.set(card.id, row); }
      patchRow(row, card);
      for (const element of [row.main, row.detail]) {
        if (element !== cursor) body.insertBefore(element, cursor);
        cursor = element.nextSibling;
      }
    }
    if (focused?.isConnected && doc.activeElement !== focused) focused.focus({preventScroll: true});
    total = page.total;
    const summary = page.summary;
    const counts = summary ? [summary.total, summary.available, summary.active, summary.busy_external, summary.error + summary.offline] : [];
    root.querySelectorAll("#dvbCardsSummary p").forEach((p, i) => setText(p, Number.isFinite(counts[i]) ? String(counts[i]) : "-"));
    empty.hidden = page.items.length !== 0;
    setText(empty, page.total === 0 ? "No cards match the current filters." : "No cards on this page. Inventory changed; refresh the view.");
    lastPage = page;
    syncControls(page.facets); feedback(page);
  }

  function invalidateLoad() {
    generation++;
    request?.abort(); request = undefined; pendingLoad = undefined;
    loading.hidden = true;
  }

  async function load(clamp = true) {
    if (!active) return;
    clearTimeout(eventTimer); eventTimer = undefined;
    invalidateLoad();
    const token = generation;
    const abort = new AbortController(); abort.events = new Map(); request = abort; dirty = false;
    loading.hidden = false;
    const path = `/api/v1/dvb-cards?${writeQuery()}`;
    try {
      const page = await requestJSON(path, {signal: abort.signal});
      if (!active || token !== generation || abort.signal.aborted) return;
      if (!page || !Array.isArray(page.items) || page.items.length > query.limit || !page.items.every(card => object(card) && typeof card.id === "string" && card.id) || new Set(page.items.map(card => card.id)).size !== page.items.length || !Number.isSafeInteger(page.total) || page.total < page.items.length) throw new Error("Invalid card inventory response");
      const maxPage = Math.max(1, Math.ceil(page.total / query.limit));
      if (clamp && page.items.length === 0 && query.page > maxPage) {
        query.page = maxPage; syncControls(); return await load(false);
      }
      if (abort.discard) return;
      page.items = page.items.map(card => abort.events.has(card.id) ? mergeEvent(card,abort.events.get(card.id)) : card);
      loadFailure = "";
      render(page);
      return page;
    } catch (reason) {
      if (!active || token !== generation || abort.signal.aborted) return;
      loadFailure = `Card inventory could not be loaded: ${reason?.message || reason}`;
      empty.hidden = true; feedback();
    } finally {
      if (token === generation) { request = undefined; pendingLoad = undefined; loading.hidden = true; feedback();scheduleEventRead(); }
    }
  }

  function resync() {
    if (!active) return Promise.resolve();
    pendingLoad = load();
    return pendingLoad;
  }

  function cancelSearch() {
    clearTimeout(searchTimer); searchTimer = undefined;
  }

  function changed(key, value, delay = 0) {
    if (!active) return;
    cancelSearch(); clearTimeout(eventTimer); eventTimer = undefined;
    invalidateLoad();
    query[key] = key === "limit" ? Number(value) : value;
    query.page = 1; writeQuery(); syncControls();
    if (delay) searchTimer = setTimeout(() => { searchTimer = undefined; void resync(); }, delay);
    else void resync();
  }

  async function refresh() {
    if (!active || refreshPending) return;
    refreshPending = true; refreshSuccess = false;
    const token = ++refreshToken, lifecycle = life;
    const abort = new AbortController(); refreshRequest = abort;
    syncControls(); feedback();
    try {
      if (canManage()) await requestJSON("/api/v1/dvb-cards/refresh", {method: "POST", signal: abort.signal});
      if (!active || token !== refreshToken || life !== lifecycle) return;
      localFailure = "";
      const page = await resync();
      if (!active || token !== refreshToken || life !== lifecycle) return;
      refreshSuccess = !!page && !page.stale && !page.refresh_error;
    } catch (reason) {
      if (!active || token !== refreshToken || life !== lifecycle) return;
      // A newer filter read is independent of this failed hardware refresh.
      localFailure = `Refresh failed: ${reason?.message || reason}`;
    } finally {
      if (token === refreshToken && life === lifecycle) {
        refreshPending = false; refreshRequest = undefined;
        syncControls(); feedback();
      }
    }
  }

  function listen(element, type, handler) {
    if (!element) return;
    element.addEventListener(type, handler); handlers.push(() => element.removeEventListener(type, handler));
  }

  function activate() {
    const wasActive = active;
    if (!active) {active = true; life++; query = readQuery(window.location.hash);}
    syncControls(); feedback(); settingsEnabled();
    for (const row of rows.values()) syncActions(row);
    if (wasActive) return pendingLoad || Promise.resolve();
    listen(controls.q, "input", () => changed("q", controls.q.value, 250));
    for (const key of ["delivery_system", "model", "status", "sort", "limit"]) listen(controls[key], "change", () => changed(key, controls[key].value));
    listen(refreshButton, "click", () => { void refresh(); });
    for (const [button, offset] of [[prev, -1], [next, 1]]) listen(button, "click", () => {
      cancelSearch(); query.page = Math.max(1, query.page + offset); syncControls(); void resync();
    });
    listen(body, "click", event => {
      const action = event.target.closest("button[data-card-action]");
      if (action && body.contains(action)) {
        if (action.disabled || !active) return;
        const id = action.dataset.cardId;
        if (action.dataset.cardAction === "settings") void openSettings(id, action);
        else if (action.dataset.cardAction === "restart") void restartCard(id, action);
        else {const record = operations.get(id); if (record) openOperation(record, action);}
        return;
      }
      const button = event.target.closest("button[data-card-details]");
      if (!button || !body.contains(button)) return;
      const row = rows.get(button.dataset.cardDetails);
      row.detail.hidden = !row.detail.hidden;
      button.setAttribute("aria-expanded", String(!row.detail.hidden));
    });
    listen(settingsForm, "submit", saveSettings);
    listen(field("rf_mode"), "change", syncRF);
    listen(settingsClose, "click", () => closeSettings());
    listen(settingsDialog, "cancel", event => {event.preventDefault(); closeSettings();});
    listen(settingsDialog, "close", () => {if (!settingsDialog.open) closeSettings(true);});
    listen(find("cardOperationClose"), "click", closeOperation);
    listen(operationDialog, "cancel", event => {event.preventDefault(); closeOperation();});
    listen(operationDialog, "close", () => {if (!operationDialog.open) closeOperation();});
    listen(operationRetry, "click", () => {if (operationView) void pollOperation(operationView.record);});
    return resync();
  }

  function deactivate() {
    if (!active) return;
    active = false; life++; refreshToken++; epoch++;ownershipSamples.clear();nextEventReadAt = 0; dirty = false;setLiveState({state:'stopped'});
    closeSettings(true); closeOperation();
    for (const lock of saveLocks.values()) lock.abort?.abort();
    for (const [id, record] of operations) {
      stopPoll(record); record.actionAbort?.abort();
      if (["confirming", "checking"].includes(record.phase)) operations.delete(id);
    }
    cancelSearch(); clearTimeout(eventTimer); eventTimer = undefined;
    invalidateLoad(); refreshRequest?.abort(); refreshRequest = undefined; refreshPending = false;
    handlers.splice(0).forEach(remove => remove()); syncControls();
    for (const row of rows.values()) syncActions(row);
  }

  function scheduleEventRead() {
    if (!active || !dirty || request || eventTimer || searchTimer) return;
    eventTimer = setTimeout(() => {eventTimer = undefined;if (active && dirty) {nextEventReadAt = Date.now() + 1000;void resync();}},Math.max(0,nextEventReadAt - Date.now()));
  }

  function scheduleResync(discard = true) {
    dirty = true;
    if (request && discard) request.discard = true;
    feedback();scheduleEventRead();
  }

  async function synchronize({signal,revision} = {}) {
    if (!active || signal?.aborted) throw new Error('Card synchronization inactive or aborted');
    const owner = life, token = ++epoch;
    revisions.clear();ownershipSamples.clear();nextEventReadAt = 0;dirty = false;clearTimeout(eventTimer);eventTimer = undefined;
    invalidateLoad();
    for (const record of operations.values()) {record.revision = 0;stopPoll(record);}
    setLiveState({state:'syncing'});
    let rejectAbort;
    const cancelled = new Promise((_,reject) => {rejectAbort = reject;});
    const abort = () => {if (token === epoch) invalidateLoad();rejectAbort(new Error('Card synchronization aborted'));};
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const result = await Promise.race([resync(),cancelled]);
      if (!result || !active || owner !== life || token !== epoch || signal?.aborted) throw new Error('Card synchronization failed or superseded');
      for (const record of operations.values()) schedulePoll(record);
      return result;
    } finally {signal?.removeEventListener('abort',abort);}
  }

  function applyEvent(event) {
    if (!active) return;
    if (event?.kind === "dvb.card.operation.changed") {
      const op = event.payload?.resource;
      const record = operations.get(op?.resource_id);
      if (!record?.op || event.payload?.mode !== "replace" || event.resource_id !== record.op.id
        || !validOperation(op, record.cardID, record.op.id) || !Number.isSafeInteger(event.revision)
        || event.revision <= record.revision || !pendingOperation(record.op)) return;
      record.revision = event.revision; record.version++; record.op = op; record.error = "";
      if (!pendingOperation(op)) stopPoll(record);
      showOperation(record); schedulePoll(record);
      const row = rows.get(record.cardID); if (row) syncActions(row);
      return;
    }
    const collection = event?.kind === "dvb.collection.changed";
    if (collection ? event.payload?.cards !== true : !["dvb.card.changed", "dvb.card.removed"].includes(event?.kind)) return;
    const id = event.resource_id || "";
    const revisionKey = collection ? "collection" : `card:${id}`;
    if (!Number.isSafeInteger(event.revision) || event.revision < 1) {scheduleResync();return;}
    if (event.revision <= (revisions.get(revisionKey) || 0)) return;
    revisions.delete(revisionKey);revisions.set(revisionKey, event.revision);
    if (revisions.size > 1024) revisions.delete(revisions.keys().next().value);
    const payload = event.payload, resource = payload?.resource, row = rows.get(id);
    const ownership = payload?.mode === 'ownership' && validOwnership(payload.ownership);
    const replacement = payload?.mode === 'replace' && object(resource) && resource.id === id
      && typeof resource.address === 'string' && Array.isArray(resource.delivery_systems) && object(resource.config);
    if (collection || !id || !ownership && !replacement || event.kind.endsWith('.removed')) {scheduleResync();return;}
    if (request && !request.discard) {
      const previous = request.events.get(id);
      request.events.delete(id);
      request.events.set(id,ownership && previous?.payload.mode === 'replace'
        ? {...event,payload:{mode:'replace',resource:mergeEvent(previous.payload.resource,event)}} : event);
      if (request.events.size > 256) {
        const evict = [...request.events.keys()].find(key => !rows.has(key));
        request.events.delete(evict);scheduleResync(!ownership);
      }
    }
    if (ownership) {
      const previous = row ? ownershipKey(row.card) : ownershipSamples.get(id), next = ownershipKey(payload.ownership);
      ownershipSamples.delete(id);ownershipSamples.set(id,next);
      if (ownershipSamples.size > 1024) ownershipSamples.delete(ownershipSamples.keys().next().value);
      // Ownership omits authoritative status and detector/summary context. Read
      // those on transitions, not on every signal sample; never veto that read.
      if (previous !== next) scheduleResync(false);
    } else ownershipSamples.delete(id);
    if (!row) {if (replacement) scheduleResync();return;}
    const card = mergeEvent(row.card,event);
    const metadata = value => Object.fromEntries(Object.entries(value).filter(([key]) => ![...ownershipFields,'updated_at'].includes(key)));
    const changesQuery = replacement && JSON.stringify(metadata(row.card)) !== JSON.stringify(metadata(card));
    patchRow(row,card);
    if (changesQuery) scheduleResync();
  }

  return {activate, deactivate, resync, applyEvent, synchronize, setLiveState};
}
