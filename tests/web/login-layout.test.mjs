// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('login offers username and password with credential autofill semantics', async () => {
  const html = await readFile(new URL('../../web/index.html', import.meta.url), 'utf8');
  const login = html.match(/<form id="authLoginForm"[\s\S]*?<\/form>/)?.[0];
  assert.ok(login);
  assert.match(login, /<input[^>]*name="username"[^>]*autocomplete="username"[^>]*required/);
  assert.match(login, /<input[^>]*name="password"[^>]*autocomplete="current-password"[^>]*required/);
  assert.match(login, /type="button"[^>]*id="authPasswordToggle"/);
});

test('blocks do not use one-sided decorative accent borders', async () => {
  for (const name of ['app.css', 'api-management.css', 'dvb-management.css']) {
    const css = await readFile(new URL(`../../web/${name}`, import.meta.url), 'utf8');
    assert.equal(/border-(?:top|right|bottom|left)\s*:[^;{}]*var\(--(?:brand(?:-2)?|danger|accent)\)/.test(css), false, name);
  }
});
