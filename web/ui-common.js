// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

export async function requestJSON(path, options = {}) {
  const {includeResponseText = false, ...fetchOptions} = options;
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {...fetchOptions, headers});
  if (response.status === 204) return null;
  let body, text;
  try {
    if (includeResponseText) {
      text = await response.text();
      body = JSON.parse(text);
    } else {
      body = await response.json();
    }
  } catch (error) {
    if (response.ok || !(error instanceof SyntaxError)) throw error;
    body = null;
  }
  if (!response.ok) {
    const detail = body?.error;
    const message = typeof detail === "string" ? detail : detail?.message;
    throw Object.assign(new Error(typeof message === "string" && message ? message : `Request failed (${response.status})`), {
      status: response.status,
      body,
      code: typeof detail?.code === "string" ? detail.code : undefined,
      field: typeof detail?.field === "string" ? detail.field : undefined,
    });
  }
  return includeResponseText ? {body, text} : body;
}

const noticeTimers = new WeakMap();

export function showNotice(target, kind, message) {
  if (!target) return;
  clearTimeout(noticeTimers.get(target));
  target.className = `notice ${kind === "err" ? "err" : "ok"}`;
  target.textContent = message;
  target.setAttribute("role", kind === "err" ? "alert" : "status");
  target.hidden = false;
  noticeTimers.set(target, setTimeout(() => {
    target.hidden = true;
    noticeTimers.delete(target);
  }, 3500));
}

export function formatDuration(totalSeconds) {
  const value = Number(totalSeconds || 0);
  const sec = Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h || d) parts.push(`${h}h`);
  if (m || h || d) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(" ");
}

export function formatSignal(value, unit = "%") {
  if (!Number.isFinite(value)) return "-";
  if (unit === "%") return `${Math.round(Math.max(0, Math.min(100, value)))}%`;
  return `${Number(value.toFixed(1))} ${unit}`;
}

export function debounce(fn, delay = 250) {
  let timer;
  function debounced(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = undefined;
      fn.apply(this, args);
    }, delay);
  }
  debounced.cancel = () => {
    clearTimeout(timer);
    timer = undefined;
  };
  return debounced;
}

export async function confirmAction(message) {
  return globalThis.confirm(message);
}
