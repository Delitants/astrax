// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import { buildOutputURL, parseOutputURL, sanitizeMPEGTSPath, parsePositiveInt } from "./output-builder.js?v=1";
import { requestJSON as api, formatDuration, confirmAction } from "./ui-common.js?v=18";
import { createPageNavigation } from "./page-navigation.js?v=21";
import { createDVBEditor } from "./dvb-editor.js?v=3";
import { createDVBScan } from "./dvb-scan.js?v=3";
import { createDVBStreamsController } from "./dvb-streams.js?v=7";
import { createDVBCardsController } from "./dvb-cards.js?v=24";
import { createPageEventFeed } from "./events.js?v=2";
import { createAPIManagementController } from "./api-management.js?v=1";
import { createEPGHealthController } from "./epg-health.js?v=2";
import {bootstrapAuth, fetchProtected, verifyEventSession, authGeneration, authenticatedUser, onUnauthorized} from './auth.js';
import {permissionsFor, canAccessPage} from './permissions.js';
import {createUsersController} from './users.js';

const DEFAULT_DES_KEY = "0102030405060708091011121314";
const canManage = () => permissionsFor(authenticatedUser()).manage;
const canControl = () => permissionsFor(authenticatedUser()).control;

const state = {
  streams: [],
  adapters: [],
  softcams: [],
  logs: [],
  settings: null,
  lastStatus: null,
  liveConnected: false,
  eventState: "connecting",
  eventPage: "overview",
  certExists: null,
};

const els = {
  statusPill: document.getElementById("statusPill"),
  globalActionNotice: document.getElementById("globalActionNotice"),
  menuToggle: document.getElementById("menuToggle"),
  currentPageLabel: document.getElementById("currentPageLabel"),
  navTabs: document.getElementById("navTabs"),
  panels: document.querySelectorAll(".panel"),
  versionVal: document.getElementById("versionVal"),
  uptimeVal: document.getElementById("uptimeVal"),
  streamCountVal: document.getElementById("streamCountVal"),
  endpointVal: document.getElementById("endpointVal"),

  streamsBody: document.getElementById("streamsBody"),
  overviewAdaptersBody: document.getElementById("overviewAdaptersBody"),
  softcamsBody: document.getElementById("softcamsBody"),

  settingsForm: document.getElementById("settingsForm"),
  settingsNotice: document.getElementById("settingsNotice"),
  epgForm: document.getElementById("epgForm"),
  epgNotice: document.getElementById("epgNotice"),
  epgFeedNotice: document.getElementById("epgFeedNotice"),
  epgStatus: document.getElementById("epgStatus"),
  refreshEpgBtn: document.getElementById("refreshEpgBtn"),
  certStatus: document.getElementById("certStatus"),
  generateCertBtn: document.getElementById("generateCertBtn"),
  uploadCertBtn: document.getElementById("uploadCertBtn"),
  deleteCertBtn: document.getElementById("deleteCertBtn"),
  certGenerateDialog: document.getElementById("certGenerateDialog"),
  certGenerateForm: document.getElementById("certGenerateForm"),
  certGenerateNotice: document.getElementById("certGenerateNotice"),
  cancelCertGenerateBtn: document.getElementById("cancelCertGenerateBtn"),
  certUploadDialog: document.getElementById("certUploadDialog"),
  certUploadForm: document.getElementById("certUploadForm"),
  certUploadNotice: document.getElementById("certUploadNotice"),
  cancelCertUploadBtn: document.getElementById("cancelCertUploadBtn"),
  logSettingsForm: document.getElementById("logSettingsForm"),
  logSettingsNotice: document.getElementById("logSettingsNotice"),
  logViewLevel: document.getElementById("logViewLevel"),
  logViewSearch: document.getElementById("logViewSearch"),
  logsBox: document.getElementById("logsBox"),
  refreshLogsBtn: document.getElementById("refreshLogsBtn"),

  addStreamBtn: document.getElementById("addStreamBtn"),
  streamDialog: document.getElementById("streamDialog"),
  streamDialogTitle: document.getElementById("streamDialogTitle"),
  streamForm: document.getElementById("streamForm"),
  streamMpegtsPanel: document.getElementById("streamMpegtsPanel"),
  streamSrtPanel: document.getElementById("streamSrtPanel"),
  streamUdpPanel: document.getElementById("streamUdpPanel"),
  streamOutputHint: document.getElementById("streamOutputHint"),
  cancelStreamBtn: document.getElementById("cancelStreamBtn"),
  copyOutputUrlBtn: document.getElementById("copyOutputUrlBtn"),
  streamRowTemplate: document.getElementById("streamRowTemplate"),

  addSoftcamBtn: document.getElementById("addSoftcamBtn"),
  softcamDialog: document.getElementById("softcamDialog"),
  softcamDialogTitle: document.getElementById("softcamDialogTitle"),
  softcamForm: document.getElementById("softcamForm"),
  softcamDESKeyRow: document.getElementById("softcamDESKeyRow"),
  softcamPasswordHint: document.getElementById("softcamPasswordHint"),
  softcamProtocolHint: document.getElementById("softcamProtocolHint"),
  softcamNotice: document.getElementById("softcamNotice"),
  cancelSoftcamBtn: document.getElementById("cancelSoftcamBtn"),
  softcamRowTemplate: document.getElementById("softcamRowTemplate"),
  softcamTestDialog: document.getElementById("softcamTestDialog"),
  softcamTestTitle: document.getElementById("softcamTestTitle"),
  softcamTestResult: document.getElementById("softcamTestResult"),
  closeSoftcamTestBtn: document.getElementById("closeSoftcamTestBtn"),
};

let globalActionOwner = null;
let actionGeneration = 0;
let settingsRevision = 0;
let settingsReplacementRevision = 0;
const settingsSectionRevisions = {general: 0, logging: 0, epg: 0};
let settingsSavePending = false;
let settingsDraftRevision = 0;
let logSettingsDraftRevision = 0;
let epgDraftRevision = 0;
const settingsHydratedDrafts = {general: 0, logging: 0, epg: 0};
const pendingSettingsSections = new WeakSet();
let softcamSavePending = false;
const noticeActions = new WeakMap();
const editorSessions = new WeakMap();

function beginNoticeAction(target, writesSettings = false, settingsSection = null) {
  const action = { target, generation: ++actionGeneration, authEpoch: authGeneration(), previousError: globalActionOwner };
  if (writesSettings) {
    action.settingsRevision = ++settingsRevision;
    if (settingsSection) {
      action.settingsSection = settingsSection;
      action.sectionRevision = ++settingsSectionRevisions[settingsSection];
      action.replacementRevision = settingsReplacementRevision;
    } else {
      settingsReplacementRevision++;
    }
  }
  noticeActions.set(target, action);
  return action;
}

function isCurrentSettingsWrite(action) {
  if (action.settingsSection) {
    return action.sectionRevision === settingsSectionRevisions[action.settingsSection]
      && action.replacementRevision === settingsReplacementRevision;
  }
  return action.settingsRevision === undefined || action.settingsRevision === settingsRevision;
}

function isCurrentAction(action) {
  return action.authEpoch === authGeneration() && noticeActions.get(action.target) === action && isCurrentSettingsWrite(action);
}

function showError(error, action = null) {
  if (error?.status === 401) return;
  if (action && (!isCurrentAction(action) || globalActionOwner?.generation > action.generation)) return;
  const owner = { target: action?.target, generation: action?.generation ?? ++actionGeneration };
  globalActionOwner = owner;
  const prefix = action ? "Action failed" : "Previously reported action failure (may already be resolved)";
  showPersistentNotice(els.globalActionNotice, "err", `${prefix}: ${error.message}`);
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "secondary";
  dismiss.textContent = "Dismiss action notice";
  dismiss.addEventListener("click", () => {
    if (globalActionOwner === owner) clearActionError();
  });
  els.globalActionNotice.append(" ", dismiss);
}

function resolveActionError(action) {
  if (!isCurrentAction(action) || globalActionOwner !== action.previousError
    || globalActionOwner?.target !== action.target) return;
  clearActionError();
}

function clearActionError() {
  globalActionOwner = null;
  els.globalActionNotice.hidden = true;
  els.globalActionNotice.textContent = "";
  els.globalActionNotice.setAttribute("role", "status");
  els.globalActionNotice.setAttribute("aria-live", "polite");
}

function showSettingsNotice(kind, message) {
  showPersistentNotice(els.settingsNotice, kind, message);
}

function showPersistentNotice(target, kind, message) {
  target.classList.toggle("err", kind === "err");
  target.classList.toggle("ok", kind !== "err");
  target.setAttribute("role", kind === "err" ? "alert" : "status");
  target.setAttribute("aria-live", kind === "err" ? "assertive" : "polite");
  target.hidden = false;
  target.textContent = message;
}

function settingsDrafts() {
  return {general: settingsDraftRevision, logging: logSettingsDraftRevision, epg: epgDraftRevision};
}

function shouldHydrateSettingsSection(section, acceptedDrafts) {
  const revision = settingsDrafts()[section];
  if (revision !== (acceptedDrafts[section] ?? settingsHydratedDrafts[section])) return false;
  settingsHydratedDrafts[section] = revision;
  return true;
}

function metric(value, unit = "") {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? `${value}${unit}` : "Unavailable";
}

function streamCounts(status) {
  return `${metric(status.running_streams)} running, ${metric(status.enabled_streams)} enabled, ${metric(status.total_streams)} total`;
}

function refreshStatusPill() {
  if (state.eventPage.startsWith("dvb-")) {
    els.statusPill.textContent = `DVB updates: ${state.eventState}`;
    els.statusPill.style.borderColor = state.liveConnected ? "#d5d9d0" : "#ca6702";
    return;
  }
  if (!state.lastStatus) {
    els.statusPill.textContent = "Loading...";
    return;
  }

  const liveTag = state.liveConnected ? "live" : "reconnecting";
  const running = streamCounts(state.lastStatus);
  const softcams = `${metric(state.lastStatus.online_softcams)} online, ${metric(state.lastStatus.enabled_softcams)} enabled`;
  els.statusPill.textContent = `${liveTag} - streams ${running} - softcam ${softcams}`;
  els.statusPill.style.borderColor = state.liveConnected ? "#d5d9d0" : "#ca6702";
}

function updateOverview(status) {
  state.lastStatus = status;
  els.versionVal.textContent = status.version ?? "Unavailable";
  els.uptimeVal.textContent = metric(status.uptime_seconds) === "Unavailable" ? "Unavailable" : formatDuration(status.uptime_seconds);
  els.streamCountVal.textContent = streamCounts(status);
  els.endpointVal.textContent = status.control_endpoint ?? "Unavailable";
  document.getElementById('managementAddress').textContent = `${location.origin} · Configured HTTP: ${status.control_endpoint ?? 'Unavailable'}`;
  refreshStatusPill();
}

function runtimeLabel(runtime) {
  if (!runtime || !runtime.state) {
    return "Unavailable";
  }
  if (runtime.state === "running") {
    return metric(runtime.uptime_seconds) === "Unavailable" ? "running (uptime unavailable)" : `running (${formatDuration(runtime.uptime_seconds)})`;
  }
  return runtime.state;
}

function softcamRuntimeLabel(runtime) {
  if (runtime?.authenticated === true && runtime.descrambling_supported === false &&
      runtime.connected === true && ["connected", "running"].includes(runtime.state)) {
    return "authenticated (no descrambling)";
  }
  return runtimeLabel(runtime);
}

function softcamNameByID(id) {
  if (!id) return "-";
  const profile = state.softcams.find((item) => item.id === id);
  return profile ? profile.name : id;
}

function renderURL(cell, value, open = false) {
  const text = String(value ?? "");
  if (!text) {
    cell.textContent = "Unavailable";
    return;
  }
  const details = document.createElement("details");
  details.open = open;
  const summary = document.createElement("summary");
  summary.textContent = text.length > 42 ? `${text.slice(0, 42)}...` : text;
  summary.setAttribute("aria-label", `Show full ${cell.className} URL`);
  const full = document.createElement("p");
  full.className = "url-value";
  full.textContent = text;
  details.append(summary, full);
  cell.replaceChildren(details);
}

function renderStreams() {
  // Legacy snapshots replace rows; retain the new URL disclosures and their focus.
  const previousURLs = new Map(Array.from(els.streamsBody.querySelectorAll("tr[data-stream-id]"), row => [row.dataset.streamId, {
    input: row.querySelector(".input details")?.open,
    output: row.querySelector(".output details")?.open,
    focus: ["input", "output"].find(column => row.querySelector(`.${column} summary`) === document.activeElement),
  }]));
  els.streamsBody.innerHTML = "";
  const externalStreams = state.streams.filter((s) => !s.dvb && !s.adapter_profile_id);
  if (!externalStreams.length) {
    const row = document.createElement("tr");
    row.innerHTML = canManage() ? '<td colspan="10">No external streams yet. Add your first external stream.</td>' : '<td colspan="10">No external streams.</td>';
    els.streamsBody.append(row);
    return;
  }

  for (const stream of externalStreams) {
    const fragment = els.streamRowTemplate.content.cloneNode(true);
    const row = fragment.querySelector("tr");
    row.dataset.streamId = stream.id;
    const previousURL = previousURLs.get(row.dataset.streamId);

    row.querySelector(".name").textContent = stream.name;
    renderURL(row.querySelector(".input"), stream.input_url, previousURL?.input);
    renderURL(row.querySelector(".output"), stream.output_url, previousURL?.output);
    row.querySelector(".protocol").textContent = stream.protocol;
    row.querySelector(".softcam").textContent = softcamNameByID(stream.softcam_id);
    row.querySelector(".enabled").textContent = stream.enabled ? "yes" : "no";
    row.querySelector(".runtime").textContent = runtimeLabel(stream.runtime);
    row.querySelector(".bitrate").textContent = metric(stream.runtime?.bitrate_kbps, " kbps");
    row.querySelector(".packets").textContent = metric(stream.runtime?.packets);

    const startBtn = row.querySelector('[data-action="start"]');
    const stopBtn = row.querySelector('[data-action="stop"]');
    const restartBtn = row.querySelector('[data-action="restart"]');
    const editBtn = row.querySelector('[data-action="edit"]');
    const deleteBtn = row.querySelector('[data-action="delete"]');

    startBtn.disabled = !canControl() || stream.enabled && stream.runtime?.state !== "error";
    stopBtn.disabled = !canControl() || !stream.enabled;
    restartBtn.disabled = !canControl() || !stream.enabled;
    for (const button of [startBtn,stopBtn,restartBtn]) button.hidden = !canControl();
    for (const button of [editBtn,deleteBtn]) button.hidden = !canManage();

    startBtn.addEventListener("click", () => void controlStream(stream.id, "start"));
    stopBtn.addEventListener("click", () => void controlStream(stream.id, "stop"));
    restartBtn.addEventListener("click", () => void controlStream(stream.id, "restart"));
    editBtn.addEventListener("click", () => {if (canManage()) openStreamDialog(stream);});
    deleteBtn.addEventListener("click", () => {if (canManage()) void deleteStream(stream.id);});

    els.streamsBody.append(fragment);
    if (previousURL?.focus) row.querySelector(`.${previousURL.focus} summary`)?.focus({ preventScroll: true });
  }
}

function renderAdapters() {
  const runtimeAdapters = state.adapters.filter((item) => item.type !== "dvb");

  els.overviewAdaptersBody.innerHTML = "";
  if (!runtimeAdapters.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="4">No runtime adapters detected.</td>';
    els.overviewAdaptersBody.append(row);
  } else {
    for (const adapter of runtimeAdapters) {
      const row = document.createElement("tr");
      for (const value of [adapter.id, adapter.type, adapter.description, adapter.status]) {
        const cell = document.createElement("td");
        cell.textContent = value ?? "-";
        row.append(cell);
      }
      els.overviewAdaptersBody.append(row);
    }
  }
}

function renderSoftcams() {
  els.softcamsBody.innerHTML = "";
  if (!state.softcams.length) {
    const row = document.createElement("tr");
    row.innerHTML = '<td colspan="8">No softcam profiles yet.</td>';
    els.softcamsBody.append(row);
    return;
  }

  for (const profile of state.softcams) {
    const fragment = els.softcamRowTemplate.content.cloneNode(true);
    const row = fragment.querySelector("tr");

    row.querySelector(".name").textContent = profile.name;
    row.querySelector(".type").textContent = profile.type;
    row.querySelector(".endpoint").textContent = `${profile.host}:${profile.port}`;
    row.querySelector(".user").textContent = profile.username;
    row.querySelector(".enabled").textContent = profile.enabled ? "yes" : "no";
    row.querySelector(".runtime").textContent = softcamRuntimeLabel(profile.runtime);
    row.querySelector(".latency").textContent = metric(profile.runtime?.latency_ms, " ms");

    const testBtn = row.querySelector('[data-action="test"]');
    const startBtn = row.querySelector('[data-action="start"]');
    const stopBtn = row.querySelector('[data-action="stop"]');
    const restartBtn = row.querySelector('[data-action="restart"]');
    const editBtn = row.querySelector('[data-action="edit"]');
    const deleteBtn = row.querySelector('[data-action="delete"]');

    startBtn.disabled = profile.enabled && profile.runtime?.state !== "error";
    stopBtn.disabled = !profile.enabled;
    restartBtn.disabled = !profile.enabled;

    testBtn.addEventListener("click", () => void testSoftcam(profile.id));
    startBtn.addEventListener("click", () => void controlSoftcam(profile.id, "start"));
    stopBtn.addEventListener("click", () => void controlSoftcam(profile.id, "stop"));
    restartBtn.addEventListener("click", () => void controlSoftcam(profile.id, "restart"));
    editBtn.addEventListener("click", () => openSoftcamDialog(profile));
    deleteBtn.addEventListener("click", () => void deleteSoftcam(profile.id));

    els.softcamsBody.append(fragment);
  }
}

function renderSettings(settings, acceptedDrafts = {}) {
  const form = els.settingsForm;
  if (shouldHydrateSettingsSection("general", acceptedDrafts)) {
    form.http_play_port.value = settings.http_play_port;
    form.srt_play_port.value = settings.srt_play_port || 9000;
    form.playlist_name.value = settings.playlist_name;
    form.control_listen.value = settings.control_listen;
    form.control_listen_https.value = settings.control_listen_https || "127.0.0.1:8443";
    form.redirect_https.checked = settings.redirect_https || false;
    form.tls_min_version.value = settings.tls_min_version || "1.2";
  }
  if (els.logSettingsForm && shouldHydrateSettingsSection("logging", acceptedDrafts)) {
    els.logSettingsForm.log_level.value = settings.log_level;
  }
  if (els.epgForm && shouldHydrateSettingsSection("epg", acceptedDrafts)) {
    els.epgForm.epg_enabled.checked = settings.epg_enabled || false;
    els.epgForm.epg_source_urls.value = (settings.epg_source_urls || []).join("\n");
    els.epgForm.epg_from_dvb.checked = settings.epg_from_dvb || false;
    els.epgForm.epg_dvb_interval_sec.value = settings.epg_dvb_interval_sec || 900;
    els.epgForm.epg_dvb_depth.value = settings.epg_dvb_depth || "present_following";
    els.epgForm.epg_dvb_priority.checked = settings.epg_dvb_priority || false;
    els.epgForm.epg_local_path.value = settings.epg_local_path || "";
    els.epgForm.epg_source_retention_hours.value = settings.epg_source_retention_hours || 24;
    els.epgForm.epg_max_source_mib.value = settings.epg_max_source_mib || 64;
    els.epgForm.epg_source_timeout_sec.value = settings.epg_source_timeout_sec || 30;
    els.epgForm.epg_max_programmes.value = settings.epg_max_programmes || 500000;
  }
  if (els.epgStatus) {
    const enabled = settings.epg_enabled || false;
    const sources = settings.epg_source_urls || [];
    const dvbEpg = settings.epg_from_dvb || false;
    if (!enabled) {
      els.epgStatus.textContent = "EPG aggregator is disabled.";
    } else if (sources.length === 0 && !dvbEpg) {
      els.epgStatus.textContent = "No EPG sources configured. Add XMLTV URLs above or enable DVB EPG.";
    } else {
      let parts = [];
      if (dvbEpg) parts.push("DVB EIT extraction");
      if (sources.length > 0) parts.push(`${sources.length} XMLTV source(s)`);
      els.epgStatus.textContent = `EPG enabled with ${parts.join(" and ")}. Check Cached Feed checks the current response without refreshing sources; View XMLTV Feed opens the output.`;
    }
  }
  if (els.streamDialog.open) {
    syncStreamOutputURL();
  }
}

function renderLogs(logs) {
  if (Array.isArray(logs)) state.logs = logs;
  const level = els.logViewLevel.value;
  const query = els.logViewSearch.value.trim().toLowerCase();
  const displayed = state.logs.filter(entry => (!level || entry.level === level)
    && `${entry.timestamp} ${entry.level} ${entry.message}`.toLowerCase().includes(query));
  if (!displayed.length) {
    els.logsBox.textContent = state.logs.length ? "No displayed log entries match these filters." : "No log entries yet.";
    return;
  }

  const lines = displayed.map((entry) => {
    const ts = new Date(entry.timestamp).toISOString();
    return `[${ts}] ${entry.level.toUpperCase()} ${entry.message}`;
  });
  els.logsBox.textContent = lines.join("\n");
}

function currentHTTPPlayPort() {
  const port = Number(state.settings?.http_play_port || 8000);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    return 8000;
  }
  return port;
}

let streamOriginalOutput = null;
let streamOutputDirty = false;
let streamSavePending = false;

function currentSRTPlayPort() {
  const port = Number(state.settings?.srt_play_port || 9000);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    return 9000;
  }
  return port;
}

function outputFormValues() {
  const values = {};
  for (const key of Object.keys(parseOutputURL('', 'mpegts'))) {
    const field = els.streamForm.elements.namedItem(key);
    if (field) values[key] = field.type === 'checkbox' ? field.checked : field.value;
  }
  return values;
}

function buildExternalOutputURL(protocol) {
  const values = outputFormValues();
  // Preserve the existing form normalization while construction stays pure.
  if (['mpegts', 'mpegts-secure', 'hls', 'hls-secure'].includes(protocol)) {
    els.streamForm.mpegts_path.value = sanitizeMPEGTSPath(values.mpegts_path);
  } else if (protocol === 'srt') {
    els.streamForm.srt_host.value = values.srt_host.trim() || (values.srt_mode === 'caller' ? '127.0.0.1' : '0.0.0.0');
    els.streamForm.srt_latency.value = String(parsePositiveInt(values.srt_latency, 120));
    if (values.srt_fec_enabled) {
      els.streamForm.srt_fec_cols.value = String(parsePositiveInt(values.srt_fec_cols, 10));
      els.streamForm.srt_fec_rows.value = String(parsePositiveInt(values.srt_fec_rows, 8));
    }
  } else if (protocol === 'udp') {
    els.streamForm.udp_host.value = values.udp_host.trim() || '127.0.0.1';
    els.streamForm.udp_port.value = String(parsePositiveInt(values.udp_port, 1234));
  }
  return buildOutputURL(protocol, values, state.settings || {}, window.location.hostname);
}

function buildMPEGTSOutputURL() { return buildExternalOutputURL(els.streamForm.protocol.value); }
function buildHLSOutputURL() { return buildExternalOutputURL(els.streamForm.protocol.value); }
function buildSRTOutputURL() { return buildExternalOutputURL('srt'); }
function buildUDPOutputURL() { return buildExternalOutputURL('udp'); }

function syncStreamOutputURL() {
  if (streamOriginalOutput !== null && !streamOutputDirty) {
    els.streamForm.output_url.value = streamOriginalOutput;
    return;
  }
  const protocol = els.streamForm.protocol.value;
  if (protocol === "mpegts" || protocol === "mpegts-secure") {
    els.streamForm.output_url.value = buildMPEGTSOutputURL();
    return;
  }
  if (protocol === "hls" || protocol === "hls-secure") {
    els.streamForm.output_url.value = buildHLSOutputURL();
    return;
  }
  if (protocol === "srt") {
    els.streamForm.output_url.value = buildSRTOutputURL();
    return;
  }
  if (protocol === "udp") {
    els.streamForm.output_url.value = buildUDPOutputURL();
  }
}

function protocolOutputHint(protocol) {
  switch (protocol) {
    case "mpegts":
    case "mpegts-secure":
      return "Auto-built from HTTP Play Path and global HTTP Play Port.";
    case "hls":
    case "hls-secure":
      return "Auto-built from HTTP Play Path with .m3u8 suffix.";
    case "srt":
      return "Auto-built from SRT mode, host, port, stream ID, encryption, latency and FEC.";
    case "udp":
      return "Auto-built from UDP host and port.";
    default:
      return "Enter the exact target URL for this protocol.";
  }
}

function updateSoftcamTypeUI() {
  const isNewcamd = els.softcamForm.type.value === "newcamd";
  els.softcamDESKeyRow.hidden = !isNewcamd;
  els.softcamForm.des_key.required = isNewcamd;
  els.softcamProtocolHint.hidden = isNewcamd;
}

function updateStreamProtocolUI() {
  const protocol = els.streamForm.protocol.value;
  const isMPEGTS = ["mpegts", "mpegts-secure", "hls", "hls-secure"].includes(protocol);
  const isSRT = protocol === "srt";
  const isUDP = protocol === "udp";

  els.streamMpegtsPanel.classList.toggle("active", isMPEGTS);
  els.streamSrtPanel.classList.toggle("active", isSRT);
  els.streamUdpPanel.classList.toggle("active", isUDP);
  els.streamForm.output_url.readOnly = isMPEGTS || isSRT || isUDP;
  els.streamOutputHint.textContent = `${protocolOutputHint(protocol)} An untouched output keeps its exact original URL. Changing output fields rebuilds it and replaces unrepresented URL parameters.`;

  syncStreamOutputURL();
}

function hydrateOutputBuilderFromStream(stream) {
  const values = parseOutputURL(stream?.output_url, stream?.protocol || 'mpegts', state.settings || {});
  for (const [key, value] of Object.entries(values)) {
    if (key === 'output_url') continue;
    const field = els.streamForm.elements.namedItem(key);
    if (field.type === 'checkbox') field.checked = value;
    else field.value = value;
  }
}

function populateStreamSoftcamOptions(selectedID = "") {
  const select = els.streamForm.softcam_id;
  if (!select) return;

  const current = selectedID || select.value || "";
  select.innerHTML = '<option value="">None</option>';
  for (const profile of state.softcams) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = `${profile.name} (${profile.host}:${profile.port})`;
    select.append(option);
  }
  select.value = current;
}

function openStreamDialog(stream) {
  if (streamSavePending) return;
  streamOriginalOutput = stream ? stream.output_url : null;
  streamOutputDirty = false;
  populateStreamSoftcamOptions(stream?.softcam_id || "");

  const isService = !!stream?.adapter_profile_id;
  const inputUrlLabel = els.streamForm.input_url.closest("label");
  const protocolLabel = els.streamForm.protocol.closest("label");

  if (stream) {
    els.streamDialogTitle.textContent = `${isService ? "Edit Service" : "Edit External Stream"} - ${stream.name}`;
    els.streamForm.id.value = stream.id;
    els.streamForm.adapter_profile_id.value = stream.adapter_profile_id || "";
    els.streamForm.name.value = stream.name;
    els.streamForm.input_url.value = stream.input_url;
    els.streamForm.protocol.value = stream.protocol || "mpegts";
    els.streamForm.softcam_id.value = stream.softcam_id || "";
    els.streamForm.enabled.checked = stream.enabled;
    els.streamForm.on_demand.checked = stream.on_demand || false;
    els.streamForm.on_demand_timeout_sec.value = String(stream.on_demand_timeout_sec || 30);
    els.streamForm.xmltv_channel_id.value = stream.xmltv_channel_id || "";
    els.streamForm.dataset.scrambled = stream.scrambled ? "1" : "";
    els.streamForm.dataset.caids = JSON.stringify(stream.caids || []);
    hydrateOutputBuilderFromStream(stream);
    const autoProtocols = ["mpegts", "mpegts-secure", "hls", "hls-secure", "srt", "udp"];
    if (!autoProtocols.includes(stream.protocol)) {
      els.streamForm.output_url.value = stream.output_url;
    }
  } else {
    els.streamDialogTitle.textContent = "Add External Stream";
    els.streamForm.reset();
    els.streamForm.id.value = "";
    els.streamForm.protocol.value = "mpegts";
    els.streamForm.softcam_id.value = "";
    els.streamForm.enabled.checked = true;
    els.streamForm.on_demand.checked = false;
    els.streamForm.on_demand_timeout_sec.value = "30";
    els.streamForm.xmltv_channel_id.value = "";
    els.streamForm.dataset.scrambled = "";
    els.streamForm.dataset.caids = "[]";
    els.streamForm.output_url.value = "";
    hydrateOutputBuilderFromStream(null);
  }

  // Hide input_url and protocol for adapter services
  if (inputUrlLabel) inputUrlLabel.hidden = isService;
  if (protocolLabel) protocolLabel.hidden = isService;

  updateStreamProtocolUI();
  openEditor(els.streamDialog);
}

function streamFormPayload() {
  syncStreamOutputURL();
  return {
    name: els.streamForm.name.value.trim(),
    input_url: els.streamForm.input_url.value.trim(),
    output_url: streamOriginalOutput !== null && !streamOutputDirty
      ? streamOriginalOutput : els.streamForm.output_url.value.trim(),
    protocol: els.streamForm.protocol.value,
    softcam_id: els.streamForm.softcam_id.value || "",
    enabled: els.streamForm.enabled.checked,
    on_demand: els.streamForm.on_demand.checked,
    on_demand_timeout_sec: parsePositiveInt(els.streamForm.on_demand_timeout_sec.value, 30),
    xmltv_channel_id: els.streamForm.xmltv_channel_id.value.trim(),
    adapter_profile_id: els.streamForm.adapter_profile_id.value || "",
    scrambled: els.streamForm.dataset.scrambled === "1",
    caids: JSON.parse(els.streamForm.dataset.caids || "[]"),
  };
}

function openSoftcamDialog(profile) {
  if (softcamSavePending) return;
  if (profile) {
    els.softcamDialogTitle.textContent = `Edit Softcam - ${profile.name}`;
    els.softcamForm.id.value = profile.id;
    els.softcamForm.name.value = profile.name;
    els.softcamForm.type.value = profile.type === "cccam" ? "cccam" : "newcamd";
    els.softcamForm.host.value = profile.host;
    els.softcamForm.port.value = profile.port;
    els.softcamForm.username.value = profile.username;
    els.softcamForm.password.value = "";
    els.softcamForm.des_key.value = profile.des_key || DEFAULT_DES_KEY;
    els.softcamForm.connect_timeout_sec.value = profile.connect_timeout_sec || 6;
    els.softcamForm.enabled.checked = profile.enabled;
  } else {
    els.softcamDialogTitle.textContent = "Add Softcam";
    els.softcamForm.reset();
    els.softcamForm.id.value = "";
    els.softcamForm.name.value = "";
    els.softcamForm.host.value = "";
    els.softcamForm.port.value = "10000";
    els.softcamForm.username.value = "";
    els.softcamForm.password.value = "";
    els.softcamForm.des_key.value = DEFAULT_DES_KEY;
    els.softcamForm.connect_timeout_sec.value = "6";
    els.softcamForm.enabled.checked = true;
    updateSoftcamTypeUI();
  }
  updateSoftcamTypeUI();
  els.softcamForm.password.required = !profile;
  els.softcamPasswordHint.textContent = profile
    ? "Leave blank to keep the saved password."
    : "Password is required for a new profile.";
  openEditor(els.softcamDialog);
}

function openEditor(dialog) {
  editorSessions.set(dialog, {});
  const notice = dialog.querySelector("[data-editor-notice]");
  if (notice) notice.hidden = true;
  dialog.showModal();
  const body = dialog.querySelector(".editor-body");
  if (body) body.scrollTop = 0;
  dialog.querySelector("[autofocus]")?.focus({ preventScroll: true });
}

function beginEditorSubmission(dialog) {
  const submission = {};
  editorSessions.set(dialog, submission);
  return (allowClosed = false) => (allowClosed || dialog.open) && editorSessions.get(dialog) === submission;
}

function softcamFormPayload() {
  const payload = {
    name: els.softcamForm.name.value.trim(),
    type: els.softcamForm.type.value,
    host: els.softcamForm.host.value.trim(),
    port: Number(els.softcamForm.port.value),
    username: els.softcamForm.username.value.trim(),
    password: els.softcamForm.password.value,
    des_key: els.softcamForm.des_key.value.trim() || DEFAULT_DES_KEY,
    connect_timeout_sec: Number(els.softcamForm.connect_timeout_sec.value) || 6,
    enabled: els.softcamForm.enabled.checked,
  };

  if (!payload.password) {
    delete payload.password;
  }
  if (payload.type !== "newcamd") {
    delete payload.des_key;
  }

  return payload;
}

function applySnapshot(snapshot) {
  if (!snapshot) {
    return;
  }

  state.streams = snapshot.streams || [];
  for (const stream of state.streams) dvbEditor.applyStatus(stream);
  if (canManage() && Array.isArray(snapshot.softcams)) {
    state.softcams = snapshot.softcams;
  }

  renderStreams();
  renderSoftcams();
  populateStreamSoftcamOptions();

  if (snapshot.status) {
    updateOverview(snapshot.status);
  }

  if (canManage() && snapshot.logs && snapshot.logs.length) {
    renderLogs(snapshot.logs);
  }
}

async function controlStream(id, action) {
  if (!canControl()) return;
  try {
    await api(`/api/v1/streams/${id}/${action}`, { method: "POST" });
    await Promise.all([refreshStreamsAndStatus(), loadLogs()]);
  } catch (error) {
    showError(error);
  }
}

async function deleteStream(id) {
  const proceed = await confirmAction("Delete this stream?");
  if (!proceed) {
    return;
  }

  try {
    await api(`/api/v1/streams/${id}`, { method: "DELETE" });
    await Promise.all([refreshStreamsAndStatus(), loadLogs()]);
  } catch (error) {
    showError(error);
  }
}

async function controlSoftcam(id, action) {
  try {
    await api(`/api/v1/softcams/${id}/${action}`, { method: "POST" });
    await Promise.all([loadSoftcams(), loadLogs()]);
  } catch (error) {
    showError(error);
  }
}

async function testSoftcam(id) {
  const name = softcamNameByID(id);
  const line = (text, className) => {
    const node = document.createElement("div");
    node.className = className;
    node.textContent = text;
    els.softcamTestResult.append(node);
  };
  let isCurrent = () => false;
  try {
    els.softcamTestTitle.textContent = `Testing Softcam Connection - ${name}`;
    els.softcamTestResult.replaceChildren();
    line("Connecting...", "status-line");
    openEditor(els.softcamTestDialog);
    isCurrent = beginEditorSubmission(els.softcamTestDialog);

    const data = await api(`/api/v1/softcams/${id}/test`, { method: "POST" });
    if (!isCurrent()) return;

    els.softcamTestResult.replaceChildren();
    const isCCcam = data.protocol === "cccam";
    if (data.success && data.connected && (!isCCcam || data.authenticated === true)) {
      els.softcamTestTitle.textContent = `Connection Successful - ${name}`;
      line(isCCcam ? "Authenticated control connection" : "Connected successfully", "status-line ok");
      if (isCCcam) line("Stream descrambling: not implemented", "detail-row");
      line(`CAIDs: ${data.caids?.length ? data.caids.join(", ") : "None reported"}`, "detail-row");
      line(`Latency: ${metric(data.latency_ms, " ms")}`, "detail-row");
      if (data.protocol) {
        line(`Protocol: ${String(data.protocol).toUpperCase()}`, "detail-row");
      }
    } else {
      els.softcamTestTitle.textContent = `Connection Failed - ${name}`;
      line(data.error || (isCCcam ? "CCcam authentication not confirmed" : "Failed to connect"), "status-line err");
    }
  } catch (error) {
    if (!isCurrent()) return;
    els.softcamTestTitle.textContent = `Test Error - ${name}`;
    els.softcamTestResult.replaceChildren();
    line(error.message, "status-line err");
  }
}

async function deleteSoftcam(id) {
  const proceed = await confirmAction("Delete this softcam profile?");
  if (!proceed) {
    return;
  }

  try {
    await api(`/api/v1/softcams/${id}`, { method: "DELETE" });
    await Promise.all([loadSoftcams(), refreshStreamsAndStatus(), loadLogs()]);
  } catch (error) {
    showError(error);
  }
}

async function refreshStreamsAndStatus() {
  const [statusData, streamsData] = await Promise.all([
    api("/api/v1/status"),
    api("/api/v1/streams?scope=external"),
  ]);

  state.streams = streamsData.streams || [];
  updateOverview(statusData);
  renderStreams();
}

async function loadAdapters() {
  const data = await api("/api/v1/adapters");
  state.adapters = data.adapters || [];
  renderAdapters();
}

async function loadSoftcams() {
  if (!canManage()) return;
  const data = await api("/api/v1/softcams");
  state.softcams = data.softcams || [];
  renderSoftcams();
  populateStreamSoftcamOptions();
}

async function loadSettings(canRender = () => true, acceptedDrafts = {}) {
  if (!canManage()) return;
  const revision = settingsRevision;
  const settings = await api("/api/v1/settings");
  // Only a newer settings write invalidates data; notice ownership gates form hydration.
  if (revision !== settingsRevision) return;
  state.settings = settings;
  if (canRender()) renderSettings(settings, acceptedDrafts);
}

async function loadLogs() {
  if (!canManage()) return;
  const data = await api("/api/v1/logs?limit=200");
  renderLogs(data.logs || []);
}

async function bootstrap() {
  try {
    await Promise.all([
      refreshStreamsAndStatus(),
      loadAdapters(),
      loadSoftcams(),
      loadSettings(),
      loadLogs(),
      ...(canManage() ? [loadCertStatus()] : []),
    ]);
  } catch (error) {
    showError(error);
  }
}

els.addStreamBtn.addEventListener("click", () => openStreamDialog(null));
els.cancelStreamBtn.addEventListener("click", () => { if (!streamSavePending) els.streamDialog.close(); });
els.streamDialog.addEventListener("cancel", event => { if (streamSavePending) event.preventDefault(); });
els.streamForm.protocol.addEventListener("change", () => {
  streamOutputDirty = true;
  updateStreamProtocolUI();
});
for (const fieldName of [
  "mpegts_path",
  "srt_mode",
  "srt_host",
  "srt_port_override",
  "srt_streamid",
  "srt_passphrase",
  "srt_pbkeylen",
  "srt_latency",
  "srt_fec_enabled",
  "srt_fec_cols",
  "srt_fec_rows",
  "udp_host",
  "udp_port",
  "output_url",
]) {
  const field = els.streamForm[fieldName];
  if (!field) continue;
  const changed = () => { streamOutputDirty = true; syncStreamOutputURL(); };
  field.addEventListener("input", changed);
  field.addEventListener("change", changed);
}

els.copyOutputUrlBtn?.addEventListener("click", () => {
  const url = els.streamForm.output_url.value;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(url).catch(() => {});
  } else {
    const ta = document.createElement("textarea");
    ta.value = url;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
  const orig = els.copyOutputUrlBtn.textContent;
  els.copyOutputUrlBtn.textContent = "Copied!";
  setTimeout(() => (els.copyOutputUrlBtn.textContent = orig), 1200);
});

els.streamForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (streamSavePending) return;
  const id = els.streamForm.id.value;
  const payload = streamFormPayload();
  const isCurrent = beginEditorSubmission(els.streamDialog);
  streamSavePending = true;
  const controls = [...els.streamForm.querySelectorAll("input, select, textarea, button")];
  const disabled = controls.map(control => control.disabled);
  controls.forEach(control => { control.disabled = true; });
  els.streamForm.setAttribute("aria-busy", "true");
  showPersistentNotice(els.streamDialog.querySelector("[data-editor-notice]"), "", "Saving... Wait for the result; do not repeat this request.");

  try {
    if (id) {
      await api(`/api/v1/streams/${id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
    } else {
      await api("/api/v1/streams", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    }

  } catch (error) {
    if (isCurrent()) {
      showError(error);
      showPersistentNotice(els.streamDialog.querySelector("[data-editor-notice]"), "err", `Save failed: ${error.message}`);
    }
    return;
  } finally {
    streamSavePending = false;
    controls.forEach((control, index) => { control.disabled = disabled[index]; });
    els.streamForm.removeAttribute("aria-busy");
  }
  if (isCurrent()) els.streamDialog.close();
  try {
    await Promise.all([refreshStreamsAndStatus(), loadLogs()]);
  } catch (error) {
    showError(new Error(`"${payload.name}" saved; refresh failed: ${error.message}`));
  }
});

els.addSoftcamBtn.addEventListener("click", () => openSoftcamDialog(null));
els.cancelSoftcamBtn.addEventListener("click", () => { if (!softcamSavePending) els.softcamDialog.close(); });
els.softcamDialog.addEventListener("cancel", event => { if (softcamSavePending) event.preventDefault(); });
els.closeSoftcamTestBtn.addEventListener("click", () => els.softcamTestDialog.close());
els.softcamForm.type.addEventListener("change", updateSoftcamTypeUI);

els.softcamForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (softcamSavePending) return;
  const id = els.softcamForm.id.value;
  const payload = softcamFormPayload();
  const isCurrent = beginEditorSubmission(els.softcamDialog);
  softcamSavePending = true;
  const controls = [...els.softcamForm.querySelectorAll("input, select, textarea, button")];
  const disabled = controls.map(control => control.disabled);
  controls.forEach(control => { control.disabled = true; });
  els.softcamForm.setAttribute("aria-busy", "true");
  showPersistentNotice(els.softcamDialog.querySelector("[data-editor-notice]"), "", "Saving... Wait for the result; do not repeat this request.");

  let runtimeApplicationFailed = false;
  try {
    if (id) {
      await api(`/api/v1/softcams/${id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
    } else {
      await api("/api/v1/softcams", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    }

  } catch (error) {
    if (error.body?.persisted === true && error.body.error_code === "runtime_application_failed") {
      runtimeApplicationFailed = true;
    } else {
      if (isCurrent()) {
        showError(error);
        showPersistentNotice(els.softcamDialog.querySelector("[data-editor-notice]"), "err", `Save failed: ${error.message}`);
      }
      return;
    }
  } finally {
    softcamSavePending = false;
    controls.forEach((control, index) => { control.disabled = disabled[index]; });
    els.softcamForm.removeAttribute("aria-busy");
  }
  showPersistentNotice(els.softcamNotice, runtimeApplicationFailed ? "err" : "ok", runtimeApplicationFailed
    ? `"${payload.name}" saved; runtime application failed; prior worker may remain active.`
    : `"${payload.name}" saved. Runtime connection status is reported separately.`);
  if (isCurrent()) els.softcamDialog.close();
  try {
    await Promise.all([loadSoftcams(), refreshStreamsAndStatus(), loadLogs()]);
  } catch (error) {
    showError(new Error(`"${payload.name}" saved; refresh failed: ${error.message}`));
  }
});

els.settingsForm.addEventListener("input", () => { settingsDraftRevision++; });
els.settingsForm.addEventListener("change", () => { settingsDraftRevision++; });
els.settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (settingsSavePending) return;
  const action = beginNoticeAction(els.settingsNotice, true, "general");
  const draftRevision = settingsDraftRevision;
  const saveButton = els.settingsForm.querySelector('[type="submit"]');
  const saveLabel = saveButton.textContent;

  const payload = {
    http_play_port: Number(els.settingsForm.http_play_port.value),
    srt_play_port: Number(els.settingsForm.srt_play_port.value),
    playlist_name: els.settingsForm.playlist_name.value.trim(),
    control_listen: els.settingsForm.control_listen.value.trim(),
    control_listen_https: els.settingsForm.control_listen_https.value.trim(),
    redirect_https: els.settingsForm.redirect_https.checked,
    tls_min_version: els.settingsForm.tls_min_version.value,
  };

  settingsSavePending = true;
  saveButton.disabled = true;
  saveButton.textContent = "Saving...";
  els.settingsForm.setAttribute("aria-busy", "true");
  showSettingsNotice("ok", "Saving...");
  try {
    await api("/api/v1/settings", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  } catch (error) {
    if (isCurrentAction(action)) {
      showSettingsNotice("err", `Save failed: ${error.message}`);
      showError(error, action);
    }
    return;
  } finally {
    // Only the write is single-flight; a slow readback must not block a new save.
    settingsSavePending = false;
    saveButton.disabled = false;
    saveButton.textContent = saveLabel;
    els.settingsForm.removeAttribute("aria-busy");
  }
  if (!isCurrentSettingsWrite(action)) return;
  if (isCurrentAction(action)) showSettingsNotice("ok", "Settings saved. Refreshing...");
  try {
    await Promise.all([
      loadSettings(() => isCurrentAction(action), {general: draftRevision}),
      loadLogs(), refreshStreamsAndStatus(),
    ]);
    if (!isCurrentAction(action)) return;
    showSettingsNotice("ok", "Settings saved.");
    resolveActionError(action);
  } catch (error) {
    if (!isCurrentAction(action)) return;
    const refreshError = new Error(`Settings saved; refresh failed: ${error.message}`);
    showSettingsNotice("err", refreshError.message);
    showError(refreshError, action);
  }
});

els.refreshLogsBtn.addEventListener("click", () => void loadLogs().catch(showError));
els.logViewLevel.addEventListener("change", () => renderLogs());
els.logViewSearch.addEventListener("input", () => renderLogs());

async function saveSettingsSection(form, notice, label, section, payload) {
  if (pendingSettingsSections.has(form)) return;
  const action = beginNoticeAction(notice, true, section);
  const draftRevision = settingsDrafts()[section];
  const saveButton = form.querySelector('[type="submit"]');
  const saveLabel = saveButton.textContent;
  pendingSettingsSections.add(form);
  saveButton.disabled = true;
  saveButton.textContent = "Saving...";
  form.setAttribute("aria-busy", "true");
  showPersistentNotice(notice, "ok", "Saving...");
  try {
    await api("/api/v1/settings", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  } catch (error) {
    if (isCurrentAction(action)) {
      showPersistentNotice(notice, "err", `Save failed: ${error.message}`);
      showError(error, action);
    }
    return;
  } finally {
    pendingSettingsSections.delete(form);
    saveButton.disabled = false;
    saveButton.textContent = saveLabel;
    form.removeAttribute("aria-busy");
  }
  if (!isCurrentSettingsWrite(action)) return;
  if (section === "epg") void epgHealthController.settingsSaved();
  if (isCurrentAction(action)) showPersistentNotice(notice, "ok", `${label} saved. Refreshing...`);
  try {
    await Promise.all([
      loadSettings(() => isCurrentAction(action), {[section]: draftRevision}),
      loadLogs(), refreshStreamsAndStatus(),
    ]);
    if (!isCurrentAction(action)) return;
    const draftHint = draftRevision === settingsDrafts()[section] ? "" : " Newer edits remain unsaved.";
    showPersistentNotice(notice, "ok", `${label} saved.${draftHint}`);
    resolveActionError(action);
  } catch (error) {
    if (!isCurrentAction(action)) return;
    const refreshError = new Error(`${label} saved; refresh failed: ${error.message}`);
    showPersistentNotice(notice, "err", refreshError.message);
    showError(refreshError, action);
  }
}

for (const event of ["input", "change"]) {
  els.logSettingsForm?.addEventListener(event, () => { logSettingsDraftRevision++; });
  els.epgForm?.addEventListener(event, () => { epgDraftRevision++; });
}

els.logSettingsForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  await saveSettingsSection(els.logSettingsForm, els.logSettingsNotice, "Recording settings", "logging", {
    log_level: els.logSettingsForm.log_level.value,
  });
});

els.epgForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const urls = els.epgForm.epg_source_urls.value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const payload = {
    epg_enabled: els.epgForm.epg_enabled.checked,
    epg_source_urls: urls,
    epg_from_dvb: els.epgForm.epg_from_dvb.checked,
    epg_dvb_interval_sec: Number(els.epgForm.epg_dvb_interval_sec.value) || 900,
    epg_dvb_depth: els.epgForm.epg_dvb_depth.value,
    epg_dvb_priority: els.epgForm.epg_dvb_priority.checked,
    epg_local_path: els.epgForm.epg_local_path.value.trim(),
    epg_source_retention_hours: Number(els.epgForm.epg_source_retention_hours.value),
    epg_max_source_mib: Number(els.epgForm.epg_max_source_mib.value),
    epg_source_timeout_sec: Number(els.epgForm.epg_source_timeout_sec.value),
    epg_max_programmes: Number(els.epgForm.epg_max_programmes.value),
  };
  await saveSettingsSection(els.epgForm, els.epgNotice, "EPG settings", "epg", payload);
});

els.refreshEpgBtn?.addEventListener("click", async () => {
  const action = beginNoticeAction(els.epgFeedNotice);
  const started = authGeneration();
  try {
    const resp = await fetchProtected("/api/v1/epg");
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: "epg unavailable" }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    const blob = await resp.blob();
    if (started !== authGeneration()) return;
    if (isCurrentAction(action)) showEPGFeedNotice("ok", `Cached EPG feed checked. ${blob.size} bytes. No source refresh was requested.`);
  } catch (error) {
    if (error.status === 401) return;
    if (isCurrentAction(action)) showEPGFeedNotice("err", error.message);
  }
});

function showEPGFeedNotice(kind, message) {
  showPersistentNotice(els.epgFeedNotice, kind, message);
}

async function loadCertStatus(shouldApply = () => true) {
  try {
    const data = await api("/api/v1/certificates/status");
    if (!shouldApply()) return;
    state.certExists = typeof data?.exists === "boolean" ? data.exists : null;
    updateCertUI();
  } catch {
    if (!shouldApply()) return;
    state.certExists = null;
    updateCertUI();
  }
}

function updateCertUI() {
  if (els.certStatus) {
    els.certStatus.textContent = state.certExists === null ? "Certificate status unavailable. Verify the active listener separately."
      : state.certExists ? "Certificates configured. Verify the active HTTPS listener separately."
        : "No certificates configured.";
    els.certStatus.className = `notice ${state.certExists ? "ok" : ""}`;
  }
  // Disable/enable secure protocol options
  const secureOptions = els.streamForm?.protocol?.querySelectorAll('option[value$="-secure"]');
  secureOptions?.forEach((opt) => {
    opt.disabled = !state.certExists;
  });
}

let certificateWritePending = false;

async function certificateWrite(form, dialog, notice, path, payload, message) {
  if (certificateWritePending) return;
  certificateWritePending = true;
  const action = beginNoticeAction(els.settingsNotice);
  const isCurrent = beginEditorSubmission(dialog);
  const controls = [...form.querySelectorAll("input, select, textarea, button"), els.generateCertBtn, els.uploadCertBtn, els.deleteCertBtn].filter(Boolean);
  const disabled = controls.map(control => control.disabled);
  controls.forEach(control => { control.disabled = true; });
  form.setAttribute("aria-busy", "true");
  showPersistentNotice(notice, "", "Saving certificate... Wait for the result; do not repeat this request.");
  try {
    await api(path, {method: "POST", body: JSON.stringify(payload)});

  } catch (error) {
    if (isCurrent()) showPersistentNotice(notice, "err", error.message);
    return;
  } finally {
    certificateWritePending = false;
    controls.forEach((control, index) => { control.disabled = disabled[index]; });
    form.removeAttribute("aria-busy");
  }
  if (isCurrent()) dialog.close();
  const shouldApply = () => isCurrentAction(action) && isCurrent(true);
  if (shouldApply()) showSettingsNotice("ok", message);
  await loadCertStatus(shouldApply);
}

for (const dialog of [els.certGenerateDialog, els.certUploadDialog]) {
  dialog?.addEventListener("cancel", event => { if (certificateWritePending) event.preventDefault(); });
}

els.generateCertBtn?.addEventListener("click", () => {
  if (certificateWritePending) return;
  els.certGenerateForm.reset();
  if (els.certGenerateNotice) els.certGenerateNotice.hidden = true;
  openEditor(els.certGenerateDialog);
});

els.cancelCertGenerateBtn?.addEventListener("click", () => {
  if (!certificateWritePending) els.certGenerateDialog.close();
});

els.certGenerateForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (certificateWritePending) return;
  const hosts = els.certGenerateForm.hosts.value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const payload = {
    hosts,
    duration_days: Number(els.certGenerateForm.duration_days.value),
    common_name: els.certGenerateForm.common_name.value.trim(),
  };
  await certificateWrite(els.certGenerateForm, els.certGenerateDialog, els.certGenerateNotice,
    "/api/v1/certificates/generate", payload, "Self-signed certificate generated. Set control_listen_https to a concrete IP and ensure the certificate covers the browser address. Save Settings first. Restart the application to enable HTTPS.");
});

els.uploadCertBtn?.addEventListener("click", () => {
  if (certificateWritePending) return;
  els.certUploadForm.reset();
  if (els.certUploadNotice) els.certUploadNotice.hidden = true;
  openEditor(els.certUploadDialog);
});

els.cancelCertUploadBtn?.addEventListener("click", () => {
  if (!certificateWritePending) els.certUploadDialog.close();
});

els.certUploadForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (certificateWritePending) return;
  const payload = {
    cert: els.certUploadForm.cert.value.trim(),
    key: els.certUploadForm.key.value.trim(),
  };
  await certificateWrite(els.certUploadForm, els.certUploadDialog, els.certUploadNotice,
    "/api/v1/certificates/upload", payload, "Certificate uploaded. Set control_listen_https to a concrete IP and ensure the certificate covers the browser address. Save Settings first. Restart the application to enable HTTPS.");
});

els.deleteCertBtn?.addEventListener("click", async () => {
  if (certificateWritePending) return;
  if (!confirm("Delete certificates? HTTPS will be disabled after restart.")) return;
  certificateWritePending = true;
  const controls = [els.generateCertBtn, els.uploadCertBtn, els.deleteCertBtn].filter(Boolean);
  const disabled = controls.map(control => control.disabled);
  controls.forEach(control => { control.disabled = true; });
  const action = beginNoticeAction(els.settingsNotice);
  showSettingsNotice("", "Deleting certificates... Wait for the result.");
  try {
    await api("/api/v1/certificates/delete", { method: "POST" });

  } catch (error) {
    if (isCurrentAction(action)) showSettingsNotice("err", error.message);
    return;
  } finally {
    certificateWritePending = false;
    controls.forEach((control, index) => { control.disabled = disabled[index]; });
  }
  if (isCurrentAction(action)) showSettingsNotice("ok", "Certificates deleted. Restart the application to disable HTTPS.");
  await loadCertStatus(() => isCurrentAction(action));
});

function setMenuOpen(open) {
  const wasOpen = els.menuToggle.getAttribute("aria-expanded") === "true";
  els.menuToggle.setAttribute("aria-expanded", String(open));
  els.navTabs.classList.toggle("menu-open", open);
  if (!open && wasOpen && els.menuToggle.getClientRects().length) els.menuToggle.focus();
}

els.menuToggle.addEventListener("click", () => setMenuOpen(els.menuToggle.getAttribute("aria-expanded") !== "true"));
els.navTabs.addEventListener("click", (event) => {
  if (event.target.closest("button[data-tab]")) setMenuOpen(false);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !document.querySelector("dialog[open]") && els.menuToggle.getAttribute("aria-expanded") === "true") {
    setMenuOpen(false);
    event.preventDefault();
  }
});

let fullDVBReloads = 0;
Object.defineProperty(window, '__astraxDiagnostics', {value:Object.freeze({
  get dvbRowsRendered() {return document.querySelectorAll('#dvbStreamTableBody tr[data-stream-id]').length;},
  get cardRowsRendered() {return document.querySelectorAll('#dvbCardsTableBody tr[data-card-id]').length;},
  get fullDVBReloads() {return fullDVBReloads;},
})});

const dvbEditor = createDVBEditor({requestJSON: api, onSaved: stream => dvbStreamsController.saved(stream)});
const dvbScan = createDVBScan({requestJSON: api, onImported: () => dvbStreamsController.imported()});
const dvbStreamsController = createDVBStreamsController({
  canManage, canControl,
  requestJSON: api, confirmAction, openEditor: id => dvbEditor.open(id),
  editorWriteState: () => dvbEditor.writeState(), openScan: () => dvbScan.open(),
  scanWriteState: () => dvbScan.writeState(),
  onPageLoad: () => {fullDVBReloads++;},
});
const dvbCardsController = createDVBCardsController({requestJSON: api, confirmAction, canManage});
const apiManagementController = createAPIManagementController({requestJSON: api, confirmAction});
const usersController = createUsersController({root:document.querySelector('[data-panel="users"]'), request:api,
  confirmAction, currentUser:authenticatedUser, onSessionRevoked:onUnauthorized});
const eventFeed = createPageEventFeed({
  checkAuth: verifyEventSession,
  controllers: {
    'dvb-cards': dvbCardsController,
    'dvb-streams': {...dvbStreamsController, synchronize(options) {
      dvbEditor.synchronize();
      return dvbStreamsController.synchronize(options);
    }, applyEvent(event) {
      dvbStreamsController.applyEvent(event);
      dvbEditor.applyEvent(event);
      dvbScan.applyEvent?.(event);
    }},
  },
  onSnapshot: applySnapshot,
  onError: showError,
  onState(info) {
    state.eventState = info.state;
    state.liveConnected = info.state === 'live';
    refreshStatusPill();
  },
});
const epgHealthController = createEPGHealthController({els: {
  notice: document.getElementById("epgHealthNotice"), refresh: document.getElementById("epgHealthRefresh"),
  feed: document.getElementById("epgHealthFeed"), channels: document.getElementById("epgHealthChannels"),
  programmes: document.getElementById("epgHealthProgrammes"), merge: document.getElementById("epgHealthMerge"),
  sources: document.getElementById("epgHealthSources"), output: document.getElementById("epgHealthOutput"),
  snapshot: document.getElementById("epgHealthSnapshot"),
}});
const pageNavigation = createPageNavigation({
  nav: els.navTabs,
  panels: els.panels,
  canAccess: name => canAccessPage(authenticatedUser(),name),
  controllers: {
    "dvb-cards": dvbCardsController,
    api: apiManagementController,
    users: usersController,
    "dvb-streams": {...dvbStreamsController, deactivate() { dvbEditor.deactivate(); dvbScan.deactivate(); dvbStreamsController.deactivate(); }},
    logs: {activate: loadLogs},
    softcams: {activate: loadSoftcams},
    epg: epgHealthController,
  },
  onError: showError,
  onChange(name) {
    state.eventPage = name;
    eventFeed.select(name);
    refreshStatusPill();
    els.currentPageLabel.textContent = els.navTabs.querySelector(`[data-tab="${name}"]`).textContent;
    setMenuOpen(false);
    for (const [page, ids] of Object.entries({
      "dvb-cards": ["cardSettingsDialog", "cardRestartDialog"],
    })) {
      if (page === name) continue;
      for (const id of ids) {
        const dialog = document.getElementById(id);
        if (dialog?.open) dialog.close();
      }
    }
  },
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-close-dialog]");
  const dialog = button?.closest("dialog");
  // DVB controllers own pending-mutation and operation cleanup on close.
  if (dialog && ["cardSettingsDialog", "cardRestartDialog", "dvbStreamDialog", "dvb-scan-dialog"].includes(dialog.id)) return;
  if (dialog && dialog.id === button.dataset.closeDialog) dialog.close();
});

window.addEventListener("beforeunload", () => {
  pageNavigation.stop();
  eventFeed.stop();
});

function clearManagementView() {
  pageNavigation.stop();
  eventFeed.stop();
  usersController.clear();
  state.streams = [];
  state.adapters = [];
  state.softcams = [];
  state.logs = [];
  state.settings = null;
  state.lastStatus = null;
  state.liveConnected = false;
  for (const id of ['streamsBody','overviewAdaptersBody','softcamsBody','logsBox',
    'dvbStreamTableBody','dvbCardsTableBody','apiTokensBody','epgHealthOutput']) {
    const target = document.getElementById(id);
    if (target) target.textContent = '';
  }
  for (const id of ['versionVal','uptimeVal','streamCountVal','endpointVal']) {
    const target = document.getElementById(id);
    if (target) target.textContent = '-';
  }
  document.querySelectorAll('#dashboard input[type="password"], #apiTokenSecret, #apiTryToken, #certUploadForm [name="key"]').forEach(field => {field.value = '';});
  document.querySelectorAll('#dashboard .notice').forEach(notice => {notice.hidden = true; notice.textContent = '';});
  els.statusPill.textContent = 'Loading...';
  clearActionError();
  const account = document.getElementById('currentUserLabel');
  if (account) account.textContent = '';
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
}

void bootstrapAuth({
  onAuthenticated(user) {
    for (const button of els.navTabs.querySelectorAll('button[data-tab]')) {
      button.hidden = !canAccessPage(user,button.dataset.tab);
      button.disabled = button.hidden;
    }
    els.addStreamBtn.hidden = !canManage();
    document.getElementById('currentUserLabel').textContent = `${user.username} / ${user.role[0].toUpperCase()}${user.role.slice(1)}`;
    document.getElementById('accountUsername').textContent = user.username;
    document.getElementById('accountRole').textContent = user.role[0].toUpperCase() + user.role.slice(1);
    pageNavigation.start();
    void bootstrap();
  },
  onExpired: clearManagementView,
});
