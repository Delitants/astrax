// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const safeError = value => typeof value === 'string' && value.length <= 4096 && !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value);

// A broken envelope never turns missing, duplicate or foreign items into success.
export function analyzeBulkResult(body, ids) {
  const items = Array.isArray(body?.results) ? body.results : [];
  const expected = new Set(ids), occurrences = new Map();
  for (const item of items) if (item && typeof item.id === 'string') occurrences.set(item.id, (occurrences.get(item.id) || 0) + 1);
  const valid = items.filter(item => item && expected.has(item.id) && occurrences.get(item.id) === 1 && typeof item.ok === 'boolean'
    && (item.ok ? item.error === undefined || item.error === '' : safeError(item.error) && !!item.error.trim()));
  const results = ids.flatMap(id => valid.filter(item => item.id === id));
  const succeeded = results.filter(item => item.ok).length, failed = results.length - succeeded, unknown = ids.length - results.length;
  const complete = expected.size === ids.length && ids.length > 0 && items.length === ids.length && unknown === 0
    && body.succeeded === succeeded && body.failed === failed;
  return {complete, results, succeeded, failed, unknown};
}

// Resource/runtime conflicts may happen after admission; never classify them by status alone.
export const bulkRejected = reason => !Object.hasOwn(reason?.body || {}, 'results') && [400,401,403,405,413,415,422].includes(reason?.status);

export const bulkErrorText = body => {
  const error = typeof body?.error === 'string' ? body.error : body?.error?.message;
  return safeError(error) ? error : '';
};

export async function loadBulkCards(requestJSON, options = {}) {
  const cards = [], seen = new Set(); let total;
  for (let page = 1; page <= 25; page++) {
    options.signal?.throwIfAborted();
    const result = await requestJSON(`/api/v1/dvb-cards?page=${page}&limit=200`,options);
    if (!result || !Array.isArray(result.items) || result.stale || result.refresh_error || !Number.isSafeInteger(result.total)
      || result.total < 0 || result.total > 5000 || result.page !== page || result.limit !== 200
      || total !== undefined && total !== result.total || result.items.length !== Math.min(200,result.total - cards.length)) {
      throw Error('Card inventory unavailable, stale or incomplete; reload before assigning a fixed card.');
    }
    total = result.total;
    for (const card of result.items) {
      if (!card || typeof card.device_key !== 'string' || !card.device_key || seen.has(card.device_key)
        || card.delivery_systems !== undefined && (!Array.isArray(card.delivery_systems) || card.delivery_systems.some(value => typeof value !== 'string'))) {
        throw Error('Card inventory contains ambiguous keys or delivery capabilities.');
      }
      seen.add(card.device_key);cards.push(card);
    }
    if (cards.length === total) return cards;
  }
  throw Error('Card inventory exceeds the bounded snapshot limit.');
}
