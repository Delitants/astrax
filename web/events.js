// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const eventNames = [
  "dvb.stream.changed", "dvb.stream.removed",
  "dvb.card.changed", "dvb.card.removed",
  "dvb.group.changed", "dvb.group.removed",
  "dvb.card.operation.changed", "dvb.scan.operation.changed",
  "dvb.collection.changed", "resync_required",
];
const retryDelays = [1000, 2000, 4000, 8000, 15000];
const readyTimeout = 15000;
const queueLimit = 64;
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isRevision = (value) => Number.isSafeInteger(value) && value >= 0;
const matchesID = (message, id) => !message.lastEventId || message.lastEventId === String(id);

function validEnvelope(event, name, message) {
  if (!isObject(event) || event.kind !== name || !isRevision(event.id) || event.id === 0 ||
      !matchesID(message, event.id) || !isRevision(event.revision) ||
      typeof event.at !== "string" || !Number.isFinite(Date.parse(event.at))) return false;
  if (name === "resync_required") {
    return event.revision === 0 && (event.resource_id === undefined || event.resource_id === "") && event.payload == null;
  }
  if (event.revision === 0 || !isObject(event.payload)) return false;
  const payload = event.payload;
  if (name === "dvb.collection.changed") {
    return (event.resource_id === undefined || event.resource_id === "") && payload.mode === "invalidate" &&
      [payload.streams, payload.groups, payload.cards].every((value) => typeof value === "boolean");
  }
  if (typeof event.resource_id !== "string" || !event.resource_id) return false;
  if (name.endsWith(".removed")) {
    return payload.mode === "remove" && Object.keys(payload).length === 1;
  }
  if (payload.mode === "replace") return isObject(payload.resource);
  if (payload.mode === "runtime") return name === "dvb.stream.changed" && isObject(payload.runtime);
  if (payload.mode === "ownership") return name === "dvb.card.changed" && isObject(payload.ownership);
  return false;
}

export function createEventClient({url = "/api/v1/events", onEvent, onResync, onState} = {}) {
  let running = false;
  let epoch = 0;
  let current = null;
  let retryTimer;
  let failures = 0;
  const active = (connection) => running && current === connection;

  function release(connection) {
    // Invalidate before close/abort: consumer abort handlers may stop/start us.
    current = null;
    clearTimeout(connection.readyTimer);
    connection.queue.length = 0;
    connection.source?.close();
    connection.controller?.abort();
  }

  function recover(connection, reason) {
    if (!active(connection)) return;
    const previousEpoch = epoch;
    release(connection);
    if (!running || previousEpoch !== epoch || current) return;
    const delay = retryDelays[Math.min(failures++, retryDelays.length - 1)];
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      if (running && previousEpoch === epoch) connect(reason);
    }, delay);
    // Recovery is already scheduled; a broken state observer must not recurse.
    settledState({state: "reconnecting", reason, delay});
  }

  function settledState(info) {
    try {
      Promise.resolve(onState?.(info)).catch(() => {});
    } catch {
      // There is no live transport to invalidate in reconnecting/stopped state.
    }
  }

  function notify(connection, state, details = {}) {
    try {
      const result = onState?.({state, ...details});
      Promise.resolve(result).catch(() => recover(connection, "callback_error"));
    } catch {
      recover(connection, "callback_error");
    }
    return active(connection);
  }

  function deliver(connection, event) {
    if (!active(connection)) return;
    const family = event.kind.slice(0, event.kind.lastIndexOf("."));
    const key = `${family}\0${event.resource_id || ""}`;
    if (event.revision <= (connection.revisions.get(key) || 0)) return;
    connection.revisions.set(key, event.revision);
    try {
      const result = onEvent?.(event);
      // Consumers are synchronous; do not let an accidental async consumer
      // race later deltas or produce an unhandled promise rejection.
      if (result && typeof result.then === "function") {
        Promise.resolve(result).catch(() => {});
        recover(connection, "callback_error");
      }
    } catch {
      recover(connection, "callback_error");
    }
  }

  function receive(connection, name, message) {
    if (!active(connection)) return;
    let event;
    try { event = JSON.parse(message.data); } catch {
      recover(connection, "invalid_event");
      return;
    }
    if (!connection.ready || !validEnvelope(event, name, message)) {
      recover(connection, "invalid_event");
      return;
    }
    if (event.id <= connection.lastID) return;
    if (name === "resync_required") {
      recover(connection, "resync_required");
      return;
    }
    if (event.id !== connection.lastID + 1) {
      recover(connection, "gap");
      return;
    }
    // Check global continuity on arrival, including while sync is pending;
    // resource revisions are checked by the same delivery path when draining.
    connection.lastID = event.id;
    if (connection.syncing) {
      if (connection.queue.length === queueLimit) recover(connection, "queue_overflow");
      else connection.queue.push(event);
    } else {
      deliver(connection, event);
    }
  }

  function ready(connection, message, reason) {
    if (!active(connection)) return;
    let boundary;
    try { boundary = JSON.parse(message.data); } catch {
      recover(connection, "invalid_event");
      return;
    }
    if (connection.ready || !isObject(boundary) || !isRevision(boundary.revision) || !matchesID(message, boundary.revision)) {
      recover(connection, "invalid_event");
      return;
    }
    clearTimeout(connection.readyTimer);
    connection.ready = true;
    connection.lastID = boundary.revision;
    connection.syncing = true;
    connection.controller = new AbortController();
    if (!notify(connection, "syncing", {reason, revision: boundary.revision})) return;
    let synchronization;
    try {
      synchronization = onResync?.({reason, revision: boundary.revision, signal: connection.controller.signal});
    } catch {
      recover(connection, "callback_error");
      return;
    }
    Promise.resolve(synchronization).then(() => {
      if (!active(connection)) return;
      while (connection.queue.length && active(connection)) deliver(connection, connection.queue.shift());
      if (!active(connection)) return;
      connection.syncing = false;
      failures = 0;
      notify(connection, "live", {revision: connection.lastID});
    }).catch(() => recover(connection, "callback_error"));
  }

  function connect(reason) {
    const connection = {source: null, controller: null, ready: false, syncing: false,
      readyTimer: undefined, queue: [], revisions: new Map(), lastID: 0};
    current = connection;
    if (!notify(connection, "connecting", {reason})) return;
    try {
      connection.source = new globalThis.EventSource(url);
      connection.source.addEventListener("ready", (message) => ready(connection, message, reason));
      for (const name of eventNames) {
        connection.source.addEventListener(name, (message) => receive(connection, name, message));
      }
      connection.source.addEventListener("error", () => recover(connection, "disconnect"));
      connection.source.addEventListener("message", () => recover(connection, "invalid_event"));
      connection.readyTimer = setTimeout(() => recover(connection, "ready_timeout"), readyTimeout);
    } catch {
      recover(connection, "disconnect");
    }
  }

  return {
    start() {
      if (running) return;
      running = true;
      epoch++;
      failures = 0;
      connect("initial");
    },
    stop() {
      if (!running) return;
      running = false;
      epoch++;
      clearTimeout(retryTimer);
      retryTimer = undefined;
      const stoppedEpoch = epoch;
      if (current) release(current);
      if (!running && epoch === stoppedEpoch) settledState({state: "stopped"});
    },
  };
}

// One transport at a time: DVB pages consume deltas; other pages keep the
// External-only legacy snapshot contract. Closing a transport fences callbacks.
export function createPageEventFeed({controllers = {}, onSnapshot, onState, onError} = {}) {
  let current, epoch = 0;
  const notify = (info, controller) => {
    controller?.setLiveState?.(info);
    onState?.(info);
  };
  function release() {
    const previous = current;
    current = undefined;
    ++epoch;
    if (!previous) return;
    clearTimeout(previous.timer);
    previous.source?.close();
    previous.client?.stop();
  }
  function legacy(connection) {
    const active = () => current === connection;
    const recover = () => {
      if (!active()) return;
      connection.source?.close();
      connection.source = undefined;
      clearTimeout(connection.timer);
      connection.timer = setTimeout(() => {if (active()) legacy(connection);}, 2000);
      notify({state:'reconnecting',reason:'disconnect'});
    };
    notify({state:'connecting'});
    if (!active()) return;
    let source;
    try {source = new globalThis.EventSource('/api/v1/events?snapshot=1&scope=external');}
    catch {recover();return;}
    connection.source = source;
    const owns = () => active() && connection.source === source;
    source.onopen = () => {if (owns()) notify({state:'live'});};
    source.addEventListener('snapshot', message => {
      if (!owns()) return;
      try {
        onSnapshot?.(JSON.parse(message.data));
        if (owns()) notify({state:'live'});
      } catch (error) {
        try {onError?.(error);} finally {if (owns()) recover();}
      }
    });
    source.onerror = () => {if (owns()) recover();};
  }
  return {
    select(name) {
      const controller = controllers[name];
      if (!controller && current?.mode === 'legacy') return;
      release();
      const token = epoch;
      const connection = {mode:controller ? 'delta' : 'legacy'};
      current = connection;
      if (!controller) {legacy(connection);return;}
      const owns = () => current === connection && epoch === token;
      connection.client = createEventClient({
        onState(info) {if (owns()) notify(info,controller);},
        async onResync(info) {
          const result = await controller.synchronize(info);
          if (!owns() || info.signal.aborted || result === false) throw new Error('DVB snapshot was not synchronized');
        },
        onEvent(event) {
          if (!owns()) return;
          const interested = name === 'dvb-streams' || event.kind.startsWith('dvb.card.') ||
            event.kind === 'dvb.collection.changed' && event.payload.cards;
          if (interested) controller.applyEvent(event);
        },
      });
      connection.client.start();
    },
    stop() {release();notify({state:'stopped'});},
  };
}
