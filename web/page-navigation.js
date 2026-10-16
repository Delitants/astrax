// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

export function createPageNavigation({nav, panels, controllers = {}, onError, onChange, window: win = globalThis.window}) {
  const pages = new Map(Array.from(panels, (panel) => [panel.dataset.panel, panel]));
  const remembered = new Map();
  let running = false;
  let generation = 0;
  let active = null;

  function remember(fragment) {
    const value = String(fragment || "").replace(/^#/, "");
    if (active && value.split("?", 1)[0] === active.name) {
      remembered.set(active.name, value);
      active.fragment = value;
    }
  }

  function report(error, token) {
    if (!running || generation !== token) return;
    try { Promise.resolve(onError?.(error)).catch(() => {}); } catch { /* An error observer must not trap navigation. */ }
  }

  function invoke(fn, owner, token, ...args) {
    try { Promise.resolve(fn?.call(owner, ...args)).catch((error) => report(error, token)); }
    catch (error) { report(error, token); }
  }

  function select(fragment, restore = false, outgoing = win.location.hash) {
    if (!running) return;
    // Controllers update filters with replaceState, which emits no hashchange.
    remember(outgoing);
    const raw = String(fragment || "").replace(/^#/, "");
    const split = raw.indexOf("?");
    const requested = split < 0 ? raw : raw.slice(0, split);
    const aliased = requested === "adapters" ? "dvb-cards" : requested;
    const name = pages.has(aliased) ? aliased : "overview";
    let canonical = name + (pages.has(aliased) && split >= 0 ? raw.slice(split) : "");
    if (restore && split < 0 && pages.has(aliased)) canonical = remembered.get(name) || name;
    if (win.location.hash !== `#${canonical}`) win.history.replaceState(null, "", `#${canonical}`);
    if (active?.fragment === canonical) return;

    const token = ++generation;
    const previous = active?.name;
    // Clear before teardown: abort/cleanup handlers may navigate again.
    active = null;
    invoke(controllers[previous]?.deactivate, controllers[previous], token);
    if (!running || generation !== token) return;

    active = {name, fragment: canonical};
    remembered.set(name, canonical);
    for (const [pageName, panel] of pages) {
      panel.id ||= `panel-${pageName}`;
      panel.hidden = pageName !== name;
      panel.classList.toggle("active", pageName === name);
    }
    for (const button of nav.querySelectorAll("button[data-tab]")) {
      const selected = button.dataset.tab === name;
      button.classList.toggle("active", selected);
      if (selected) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
      const panel = pages.get(button.dataset.tab);
      if (panel) button.setAttribute("aria-controls", panel.id);
    }
    invoke(onChange, null, token, name, previous);
    if (running && generation === token) invoke(controllers[name]?.activate, controllers[name], token);
  }

  const hashChanged = (event) => {
    // The current hash is already incoming; only oldURL describes the view left.
    select(win.location.hash, false, event?.oldURL ? new URL(event.oldURL).hash : null);
  };
  function clicked(event) {
    const button = event.target.closest?.("button[data-tab]");
    if (button && nav.contains(button) && !button.disabled && pages.has(button.dataset.tab)) select(button.dataset.tab, true);
  }

  return {
    start() {
      if (running) return;
      running = true;
      nav.addEventListener("click", clicked);
      win.addEventListener("hashchange", hashChanged);
      hashChanged();
    },
    activate(fragment) { select(fragment, true); },
    stop() {
      if (!running) return;
      running = false;
      const token = ++generation;
      nav.removeEventListener("click", clicked);
      win.removeEventListener("hashchange", hashChanged);
      const previous = active?.name;
      active = null;
      invoke(controllers[previous]?.deactivate, controllers[previous], token);
    },
  };
}
