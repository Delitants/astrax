// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const fragmentURL = new URL('../../web/index.html', import.meta.url);
const moduleURL = new URL('../../web/users.js', import.meta.url);
const deferred = () => Promise.withResolvers();
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise(setImmediate); };
const admin = {username:'fixture-admin', role:'administrator', enabled:true};
const sampleUsers = [admin, {username:'fixture-operator', role:'operator', enabled:true},
  {username:'fixture-viewer', role:'viewer', enabled:false}];

test('Users fixture is the shipped markup, not a private development artifact', () => {
  assert.equal(fragmentURL.href, new URL('../../web/index.html', import.meta.url).href);
});

function nodeList(nodes) {
  return Object.assign({length:nodes.length, item:index => nodes[index] || null,
    forEach:fn => nodes.forEach(fn), [Symbol.iterator]:() => nodes[Symbol.iterator]()}, nodes);
}

// Parse the delivered fragment instead of maintaining a second, drifting fixture.
class Element {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase(); this.ownerDocument = doc; this.children = [];
    this.parentElement = null; this.attributes = new Map(); this.listeners = new Map();
    this.value = ''; this.defaultValue = ''; this.checked = false; this.defaultChecked = false;
    this.disabled = false; this.hidden = false; this.open = false; this.readOnly = false;
    this.required = false; this._text = '';
  }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  set innerHTML(_) { throw new Error('Unsafe HTML insertion is not supported by this fixture.'); }
  get className() { return this.getAttribute('class') || ''; }
  set className(value) { this.setAttribute('class', value); }
  get id() { return this.getAttribute('id') || ''; }
  set id(value) { this.setAttribute('id', value); }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (['hidden','disabled','required','checked','open'].includes(name)) this[name] = true;
    if (name === 'checked') this.defaultChecked = true;
    if (name === 'readonly') this.readOnly = true;
    if (name === 'value') this.value = this.defaultValue = String(value);
    if (name === 'type') this.type = String(value);
  }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  append(...nodes) {
    for (const node of nodes) {
      assert.ok(node instanceof Element, 'Fixture only supports element appends.');
      if (node.parentElement) node.parentElement.children = node.parentElement.children.filter(child => child !== node);
      node.parentElement = this; this.children.push(node);
    }
  }
  replaceChildren(...nodes) {
    for (const child of this.children) child.parentElement = null;
    this.children = []; this._text = ''; this.append(...nodes);
  }
  contains(node) { return this === node || this.children.some(child => child.contains(node)); }
  matches(selector) {
    if (/^[a-z]+$/i.test(selector)) return this.tagName === selector.toUpperCase();
    if (/^#[\w-]+$/.test(selector)) return this.id === selector.slice(1);
    const attr = selector.match(/^\[([\w-]+)(?:=["']?([^"'\]]+)["']?)?\]$/);
    if (attr) return attr[2] === undefined ? this.attributes.has(attr[1]) : this.getAttribute(attr[1]) === attr[2];
    throw new Error(`Unsupported fixture selector: ${selector}`);
  }
  querySelectorAll(selector) {
    const selectors = selector.split(',').map(part => part.trim()), found = [];
    const visit = node => { for (const child of node.children) {
      if (selectors.some(part => child.matches(part))) found.push(child);
      visit(child);
    }};
    visit(this); return nodeList(found);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener(name, fn) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(fn); }
  async emit(name, properties = {}) {
    const event = {target:this, currentTarget:this, defaultPrevented:false,
      preventDefault() { this.defaultPrevented = true; }, ...properties};
    for (const fn of this.listeners.get(name) || []) await fn(event);
    if (name === 'cancel' && !event.defaultPrevented) this.close();
    return event;
  }
  showModal() { assert.equal(this.open, false, 'Dialog cannot be opened twice.'); this.open = true; }
  close() {
    if (!this.open) return;
    this.open = false;
    for (const fn of this.listeners.get('close') || []) fn({target:this});
  }
  focus() { if (!this.disabled) this.ownerDocument.activeElement = this; }
  reset() {
    for (const field of this.querySelectorAll('input, select')) {
      field.checked = field.defaultChecked; field.value = field.defaultValue;
      if (field.tagName === 'SELECT') {
        const options = Array.from(field.querySelectorAll('option'));
        field.value = (options.find(option => option.attributes.has('selected')) || options[0])?.value || '';
      }
    }
  }
}

function parseFragment(html) {
  const doc = {activeElement:null, createElement(tag) { return new Element(tag, doc); }};
  const container = doc.createElement('main'), stack = [container];
  for (const token of html.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || []) {
    if (token.startsWith('<!--')) continue;
    if (token.startsWith('</')) {
      assert.equal(stack.pop().tagName, token.slice(2,-1).trim().toUpperCase(), 'Fragment tags must balance.');
    } else if (token.startsWith('<')) {
      const tag = token.match(/^<([\w-]+)/)?.[1]; assert.ok(tag, 'Expected an HTML tag.');
      const node = doc.createElement(tag);
      for (const attr of token.slice(tag.length + 1, -1).matchAll(/([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
        node.setAttribute(attr[1], attr[2] ?? attr[3] ?? attr[4] ?? '');
      }
      stack.at(-1).append(node);
      if (!['input','br','hr','meta','link'].includes(tag)) stack.push(node);
    } else stack.at(-1)._text += token.replaceAll('&amp;', '&');
  }
  assert.equal(stack.length, 1, 'Fragment must not leave unclosed tags.');
  const root = container.querySelector('[data-panel="users"]'); assert.ok(root);
  root.querySelector('[data-users="form"]').reset();
  doc.getElementById = id => container.querySelector(`#${id}`);
  return {doc, root};
}

const snapshot = node => JSON.stringify({tag:node.tagName, text:node._text, value:node.value, checked:node.checked,
  disabled:node.disabled, hidden:node.hidden, open:node.open, attrs:[...node.attributes], children:node.children.map(snapshot)});

async function harness({users = sampleUsers, principal = admin, confirm = async () => true, revoked} = {}) {
  const {createUsersController} = await import(moduleURL.href);
  assert.equal(typeof createUsersController, 'function', 'Export the isolated Users controller.');
  const html = await readFile(fragmentURL, 'utf8');
  const fragment = html.match(/<section data-panel="users"[\s\S]*?<\/section>/)?.[0];
  assert.ok(fragment, 'The shipped index must contain the Users panel.');
  const {doc, root} = parseFragment(fragment);
  const calls = [], confirmations = [], reads = [], writes = [];
  let actor = principal, server = structuredClone(users);
  const request = async (path, options = {}) => {
    calls.push({path, options});
    if (!options.method || options.method === 'GET') {
      return reads.length ? reads.shift()(path, options) : {users:structuredClone(server)};
    }
    if (writes.length) return writes.shift()(path, options);
    const payload = options.body ? JSON.parse(options.body) : undefined;
    if (options.method === 'POST') server.push({username:payload.username, role:payload.role, enabled:true});
    else {
      const username = decodeURIComponent(path.slice('/api/v1/users/'.length));
      if (options.method === 'DELETE') server = server.filter(user => user.username !== username);
      else server = server.map(user => user.username === username ? {...user,
        ...(payload.role === undefined ? {} : {role:payload.role}),
        ...(payload.enabled === undefined ? {} : {enabled:payload.enabled})} : user);
    }
    return null;
  };
  const controller = createUsersController({root, request,
    confirmAction:async message => { confirmations.push(message); return confirm(message); },
    currentUser:() => actor, ...(revoked ? {onSessionRevoked:revoked} : {})});
  const get = name => { const found = root.querySelector(`[data-users="${name}"]`); assert.ok(found, `Missing fragment control: ${name}`); return found; };
  const row = username => get('list').children.find(item => item.getAttribute('data-username') === username);
  const action = (username, kind) => { const button = row(username)?.querySelector(`[data-user-action="${kind}"]`); assert.ok(button, `Missing ${kind} action for ${username}`); return button; };
  return {controller, root, doc, calls, confirmations, get, row, action,
    read:fn => reads.push(fn), write:fn => writes.push(fn), setPrincipal:value => {actor = value;},
    async create(username = 'fixture-new') {
      await get('create').emit('click'); get('username').value = username;
      get('password').value = ' fixture-only secret '; get('password-confirm').value = ' fixture-only secret ';
    },
    submit:() => get('form').emit('submit'),
  };
}

test('fragment and controller expose the isolated integration contract', async () => {
  const h = await harness();
  assert.deepEqual(Object.keys(h.controller).sort(), ['activate','clear','deactivate']);
  assert.ok(['SECTION','ARTICLE'].includes(h.root.tagName));
  const dialog = h.get('dialog');
  assert.equal(dialog.tagName, 'DIALOG');
  assert.ok(h.doc.getElementById(dialog.getAttribute('aria-labelledby')));
  assert.ok(h.doc.getElementById(dialog.getAttribute('aria-describedby')));
  for (const name of ['username','role','enabled','reset-password','password','password-confirm']) {
    const input = h.get(name); assert.ok(input.id);
    assert.ok(Array.from(h.root.querySelectorAll('label')).some(label => label.getAttribute('for') === input.id), `${name} needs an explicit label`);
  }
  assert.equal(h.get('password').type, 'password');
  assert.equal(h.get('password').getAttribute('autocomplete'), 'new-password');
  assert.equal(h.get('password-confirm').type, 'password');
  assert.equal(h.calls.length, 0, 'Constructing a controller must not make a request.');
});

for (const principal of [null, {username:'fixture-op',role:'operator',enabled:true},
  {username:'fixture-view',role:'viewer',enabled:true}, {...admin,enabled:false}]) {
  test(`non-administrator ${principal?.role || 'missing'} cannot load or mutate accounts`, async () => {
    const h = await harness({principal}); await h.controller.activate();
    await h.get('create').emit('click'); await h.submit(); await h.get('refresh').emit('click');
    assert.equal(h.calls.length, 0); assert.equal(h.get('dialog').open, false);
    assert.equal(h.get('list').children.length, 0); assert.equal(h.get('create').disabled, true);
  });
}

test('activation lists only safe public user fields and search matches username, role, and status', async () => {
  const unsafe = '<img src=x onerror=alert(1)>';
  const h = await harness({users:[...sampleUsers, {username:unsafe,role:'viewer',enabled:true,password:'NEVER RENDER THIS',verifier:'OR THIS'}]});
  await h.controller.activate();
  assert.equal(h.calls[0].path, '/api/v1/users'); assert.ok(h.calls[0].options.signal instanceof AbortSignal);
  assert.equal(h.get('list').children.length, 4);
  assert.match(h.row('fixture-operator').textContent, /Operator/);
  assert.match(h.row('fixture-viewer').textContent, /Disabled/);
  assert.match(h.row(unsafe).textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(h.root.querySelectorAll('img').length, 0);
  assert.doesNotMatch(h.root.textContent, /NEVER RENDER THIS|OR THIS/);
  for (const [query, expected] of [[' OPERATOR ', 'fixture-operator'], ['disabled','fixture-viewer'], [unsafe.toUpperCase(), unsafe]]) {
    h.get('search').value = query; await h.get('search').emit('input');
    assert.equal(h.get('list').children.length, 1); assert.ok(h.row(expected));
  }
  h.get('search').value = 'no match'; await h.get('search').emit('input');
  assert.equal(h.get('empty').hidden, false); assert.match(h.get('empty').textContent, /No accounts match/);
  assert.equal(h.calls.length, 1, 'Searching is local and read-only.');
});

test('an empty account list never creates default accounts', async () => {
  const h = await harness({users:[]}); await h.controller.activate();
  assert.match(h.get('empty').textContent, /No accounts/); assert.equal(h.get('create').disabled, false);
  assert.equal(h.calls.length, 1);
});

test('one active list read fences duplicate activation and refresh', async () => {
  const h = await harness(), held = deferred(); h.read(() => held.promise);
  const first = h.controller.activate(), again = h.controller.activate();
  await h.get('refresh').emit('click');
  assert.equal(h.calls.length, 1); assert.equal(h.get('create').disabled, true);
  assert.match(h.get('list-notice').textContent, /Loading/);
  held.resolve({users:sampleUsers}); await Promise.all([first, again]);
  assert.equal(h.get('create').disabled, false);
});

for (const result of [{}, {users:[{username:'bad',role:'root',enabled:true}]},
  {users:[{username:'bad',role:'viewer',enabled:'false'}]}, {users:[admin,admin]}]) {
  test(`invalid account response is an error, not a partial or empty list: ${JSON.stringify(result)}`, async () => {
    const h = await harness(); h.read(async () => result); await h.controller.activate();
    assert.match(h.get('list-notice').textContent, /incomplete|invalid/i);
    assert.equal(h.get('list-notice').getAttribute('role'), 'alert');
    assert.equal(h.get('list').children.length, 0); assert.equal(h.get('create').disabled, true);
  });
}

test('a failed list refresh is recoverable without a write or an invented empty state', async () => {
  const h = await harness(); h.read(async () => {throw Object.assign(new Error('Read unavailable <b>literal</b>'),{status:503});});
  await h.controller.activate(); assert.match(h.get('list-notice').textContent, /Read unavailable <b>literal<\/b>/);
  assert.equal(h.get('empty').hidden, true); await h.get('refresh').emit('click');
  assert.equal(h.get('list').children.length, 3); assert.equal(h.get('create').disabled, false);
  assert.equal(h.get('list-notice').hidden, true);
});

test('list replacement preserves keyboard focus using native NodeList-compatible queries', async () => {
  const h = await harness(); await h.controller.activate();
  h.action('fixture-operator','edit').focus();
  await h.get('refresh').emit('click');
  assert.equal(h.get('list-notice').hidden, true);
  assert.ok(h.doc.activeElement === h.action('fixture-operator','edit'), 'Focus must move to the replacement action, not a detached button.');
});

test('successful edits return keyboard focus to the replacement account action', async () => {
  const h = await harness(); await h.controller.activate(); await h.action('fixture-operator','edit').emit('click');
  h.get('role').value = 'viewer'; await h.submit();
  assert.ok(h.doc.activeElement === h.action('fixture-operator','edit'), 'Saving must restore focus to the edited account.');
});

test('create defaults to Viewer and sends exactly the JSON contract without trimming passwords', async () => {
  const h = await harness(); await h.controller.activate(); await h.create(' fixture-new ');
  assert.equal(h.get('role').value, 'viewer'); assert.equal(h.doc.activeElement, h.get('username'));
  await h.submit();
  const call = h.calls.find(call => call.options.method === 'POST');
  assert.equal(call.path, '/api/v1/users');
  assert.deepEqual(JSON.parse(call.options.body), {username:'fixture-new',password:' fixture-only secret ',role:'viewer'});
  assert.equal(new Headers(call.options.headers).get('Content-Type'), 'application/json');
  assert.ok(call.options.signal instanceof AbortSignal);
  assert.equal(h.get('dialog').open, false); assert.equal(h.get('password').value, '');
  assert.equal(h.get('password-confirm').value, ''); assert.match(h.get('notice').textContent, /created|saved/i);
  assert.ok(h.row('fixture-new')); assert.equal(h.doc.activeElement, h.get('create'));
});

test('create rejects missing username, unknown role, empty password, and mismatched confirmation locally', async () => {
  const h = await harness(); await h.controller.activate(); await h.create('');
  await h.submit(); assert.match(h.get('form-notice').textContent, /username/i);
  h.get('username').value = 'fixture-new'; h.get('role').value = 'root';
  await h.submit(); assert.match(h.get('form-notice').textContent, /role/i);
  h.get('role').value = 'viewer'; h.get('password').value = '';
  await h.submit(); assert.match(h.get('form-notice').textContent, /password/i);
  h.get('password').value = 'one'; h.get('password-confirm').value = 'two';
  await h.submit(); assert.match(h.get('form-notice').textContent, /match/i);
  assert.equal(h.calls.length, 1);
});

test('edit never hydrates passwords and omits unchanged fields and optional password reset', async () => {
  const h = await harness({users:[admin,{username:'fixture/a?b#c',role:'operator',enabled:true,password:'not-public',new_password:'not-public'}]});
  await h.controller.activate(); await h.action('fixture/a?b#c','edit').emit('click');
  assert.equal(h.get('username').readOnly, true); assert.equal(h.get('password').value, '');
  assert.equal(h.get('password-fields').hidden, true); assert.equal(h.get('reset-password').checked, false);
  h.get('enabled').checked = false; await h.submit();
  const call = h.calls.find(call => call.options.method === 'PUT');
  assert.equal(call.path, '/api/v1/users/fixture%2Fa%3Fb%23c');
  assert.deepEqual(JSON.parse(call.options.body), {enabled:false});
  assert.match(h.get('notice').textContent, /saved/i); assert.match(h.row('fixture/a?b#c').textContent, /Disabled/);
});

test('unchanged edit does not revoke a session or send an empty update', async () => {
  const h = await harness(); await h.controller.activate(); await h.action(admin.username,'edit').emit('click');
  await h.submit(); assert.equal(h.calls.length, 1); assert.equal(h.confirmations.length, 0);
  assert.match(h.get('form-notice').textContent, /No changes/);
});

test('password reset is explicit, confirmable, and never leaks into a later edit', async () => {
  const h = await harness(); await h.controller.activate(); await h.action('fixture-operator','reset').emit('click');
  assert.equal(h.get('reset-password').checked, true); assert.equal(h.get('password-fields').hidden, false);
  assert.equal(h.doc.activeElement, h.get('password'));
  h.get('password').value = 'new fixture secret'; h.get('password-confirm').value = 'new fixture secret'; await h.submit();
  const call = h.calls.find(call => call.options.method === 'PUT');
  assert.deepEqual(JSON.parse(call.options.body), {new_password:'new fixture secret'});
  assert.match(h.get('notice').textContent, /password/i);
  await h.action('fixture-operator','edit').emit('click');
  assert.equal(h.get('password').value, ''); assert.equal(h.get('password-confirm').value, '');
  assert.equal(h.get('reset-password').checked, false); assert.equal(h.get('password-fields').hidden, true);
});

test('unchecking optional reset immediately clears secrets and excludes new_password', async () => {
  const h = await harness(); await h.controller.activate(); await h.action('fixture-operator','reset').emit('click');
  h.get('password').value = 'discard me'; h.get('password-confirm').value = 'discard me';
  h.get('reset-password').checked = false; await h.get('reset-password').emit('change');
  assert.equal(h.get('password').value, ''); assert.equal(h.get('password-confirm').value, '');
  assert.equal(h.get('password').disabled, true);
  h.get('role').value = 'viewer'; await h.submit();
  assert.deepEqual(JSON.parse(h.calls.find(call => call.options.method === 'PUT').options.body), {role:'viewer'});
});

for (const close of ['cancel-button','escape','external-close','deactivate','clear']) {
  test(`${close} closes the dialog and resets both passwords and reset mode`, async () => {
    const h = await harness(); await h.controller.activate(); await h.action('fixture-operator','reset').emit('click');
    h.get('password').value = 'discard'; h.get('password-confirm').value = 'discard';
    if (close === 'cancel-button') await h.get('cancel').emit('click');
    else if (close === 'escape') await h.get('dialog').emit('cancel');
    else if (close === 'external-close') h.get('dialog').close();
    else h.controller[close]();
    assert.equal(h.get('dialog').open, false); assert.equal(h.get('password').value, '');
    assert.equal(h.get('password-confirm').value, ''); assert.equal(h.get('reset-password').checked, false);
  });
}

test('pending mutation disables controls and blocks duplicate submit, opens, deletion, Cancel, and Escape', async () => {
  const h = await harness(), held = deferred(); await h.controller.activate(); await h.create(); h.write(() => held.promise);
  const saving = h.submit(); await flush();
  assert.equal(h.get('form').getAttribute('aria-busy'), 'true'); assert.equal(h.get('save').disabled, true);
  assert.equal(h.get('cancel').disabled, true); assert.equal(h.get('password').value, '');
  assert.match(h.get('form-notice').textContent, /pending|Creating|Saving/i);
  await h.submit(); await h.get('create').emit('click'); await h.action('fixture-operator','delete').emit('click');
  await h.get('cancel').emit('click'); const escape = await h.get('dialog').emit('cancel');
  assert.equal(escape.defaultPrevented, true); assert.equal(h.get('dialog').open, true);
  assert.equal(h.calls.length, 2);
  held.reject(Object.assign(new Error('Username already exists <b>literal</b>'),{status:409})); await saving;
  assert.equal(h.get('save').disabled, false); assert.equal(h.get('cancel').disabled, false);
  assert.equal(h.get('form').getAttribute('aria-busy'), null);
  assert.equal(h.get('form-notice').getAttribute('role'), 'alert');
  assert.match(h.get('form-notice').textContent, /Username already exists <b>literal<\/b>/);
  assert.equal(h.get('password').value, ''); assert.equal(h.get('password-confirm').value, '');
});

test('an ambiguous transport failure says unconfirmed and requires list readback before another write', async () => {
  const h = await harness(); await h.controller.activate(); await h.create();
  h.write(async () => {throw new Error('connection lost');}); await h.submit();
  assert.match(h.get('form-notice').textContent, /not confirmed/i);
  assert.match(h.get('form-notice').textContent, /refresh/i); assert.equal(h.get('save').disabled, true);
  assert.doesNotMatch(h.get('notice').textContent, /saved|created/i);
  await h.submit(); assert.equal(h.calls.length, 2);
  await h.get('cancel').emit('click'); await h.get('refresh').emit('click');
  assert.equal(h.get('create').disabled, false);
});

test('delete asks for named confirmation and cancellation never sends a mutation', async () => {
  const h = await harness({confirm:async () => false}); await h.controller.activate();
  await h.action('fixture-operator','delete').emit('click');
  assert.equal(h.calls.length, 1); assert.match(h.confirmations[0], /fixture-operator/);
  assert.match(h.confirmations[0], /session/i); assert.ok(h.row('fixture-operator'));
});

test('failed confirmation clearly says no request was sent and does not require readback', async () => {
  const h = await harness({confirm:async () => {throw new Error('Confirmation unavailable');}});
  await h.controller.activate(); await h.action('fixture-operator','delete').emit('click');
  assert.equal(h.calls.length, 1); assert.match(h.get('notice').textContent, /No request was sent/);
  assert.match(h.get('notice').textContent, /Confirmation unavailable/); assert.equal(h.get('create').disabled, false);
});

test('deletion fences asynchronous confirmation and repeated clicks until acknowledgement', async () => {
  const confirmation = deferred(), write = deferred(), h = await harness({confirm:() => confirmation.promise});
  await h.controller.activate(); const deleting = h.action('fixture-operator','delete').emit('click');
  await h.action('fixture-operator','delete').emit('click');
  assert.equal(h.confirmations.length, 1); assert.equal(h.calls.length, 1);
  h.write(() => write.promise); confirmation.resolve(true); await flush();
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].options.method, 'DELETE');
  assert.equal(h.calls[1].path, '/api/v1/users/fixture-operator');
  assert.equal(h.calls[1].options.body, undefined); assert.match(h.get('notice').textContent, /Deleting/);
  write.resolve(null); await deleting; assert.match(h.get('notice').textContent, /deleted/i);
});

test('last enabled administrator cannot be deleted, disabled, or demoted locally', async () => {
  const h = await harness(); await h.controller.activate(); await h.action(admin.username,'delete').emit('click');
  assert.match(h.get('notice').textContent, /last enabled administrator/i);
  await h.action(admin.username,'edit').emit('click'); h.get('enabled').checked = false;
  await h.submit(); assert.match(h.get('form-notice').textContent, /last enabled administrator/i);
  h.get('enabled').checked = true; h.get('role').value = 'viewer'; await h.submit();
  assert.match(h.get('form-notice').textContent, /last enabled administrator/i);
  assert.equal(h.calls.length, 1);
});

test('server rejection of a concurrent last-admin change remains a visible error', async () => {
  const h = await harness({users:[...sampleUsers,{username:'fixture-admin-two',role:'administrator',enabled:true}]});
  await h.controller.activate(); await h.action('fixture-admin-two','edit').emit('click'); h.get('role').value = 'viewer';
  h.write(async () => {throw Object.assign(new Error('Cannot demote the last enabled administrator.'),{status:409});});
  await h.submit(); assert.match(h.get('form-notice').textContent, /last enabled administrator/);
  assert.equal(h.get('dialog').open, true); assert.equal(h.get('save').disabled, false);
});

for (const operation of ['edit','reset','delete']) {
  test(`successful own-account ${operation} clears sensitive UI and invokes session revocation once`, async () => {
    let revoked = 0;
    const h = await harness({users:[...sampleUsers,{username:'fixture-admin-two',role:'administrator',enabled:true}],revoked:() => {revoked++;}});
    await h.controller.activate();
    if (operation === 'delete') await h.action(admin.username,'delete').emit('click');
    else {
      await h.action(admin.username,operation).emit('click');
      if (operation === 'edit') h.get('role').value = 'viewer';
      else {h.get('password').value = 'new fixture'; h.get('password-confirm').value = 'new fixture';}
      await h.submit();
    }
    assert.equal(revoked, 1); assert.match(h.confirmations[0], /sign.*out|own account/i);
    assert.equal(h.get('list').children.length, 0); assert.equal(h.get('dialog').open, false);
    assert.equal(h.get('password').value, ''); assert.equal(h.get('create').disabled, true);
    assert.equal(h.calls.filter(call => !call.options.method || call.options.method === 'GET').length, 1, 'No read with the revoked session.');
  });
}

test('editing somebody else never revokes the current principal', async () => {
  let revoked = 0; const h = await harness({revoked:() => {revoked++;}}); await h.controller.activate();
  await h.action('fixture-operator','edit').emit('click'); h.get('role').value = 'viewer'; await h.submit();
  assert.equal(revoked, 0); assert.equal(h.confirmations.length, 0);
});

for (const approved of [false,true]) test(`${approved ? 'rejected' : 'cancelled'} own-account save does not revoke the session`, async () => {
  let revoked = 0;
  const h = await harness({confirm:async () => approved, revoked:() => {revoked++;}});
  await h.controller.activate(); await h.action(admin.username,'reset').emit('click');
  h.get('password').value = 'fixture secret'; h.get('password-confirm').value = 'fixture secret';
  if (approved) h.write(async () => {throw Object.assign(new Error('Password rejected'),{status:400});});
  await h.submit(); assert.equal(revoked, 0); assert.equal(h.get('dialog').open, true);
  assert.equal(h.get('password').value, ''); assert.equal(h.get('password-confirm').value, '');
  assert.equal(h.calls.length, approved ? 2 : 1);
});

test('own-account session revocation callback is optional', async () => {
  const h = await harness(); await h.controller.activate(); await h.action(admin.username,'reset').emit('click');
  h.get('password').value = 'fixture secret'; h.get('password-confirm').value = 'fixture secret';
  await h.submit(); assert.equal(h.get('dialog').open, false); assert.equal(h.get('list').children.length, 0);
});

test('a queued native close event cannot erase a newly opened account dialog', async () => {
  const h = await harness(); await h.controller.activate(); await h.create(); await h.get('cancel').emit('click');
  await h.create('fresh fixture'); const before = snapshot(h.get('dialog'));
  await h.get('dialog').emit('close'); assert.equal(snapshot(h.get('dialog')), before);
});

for (const failed of [false,true]) {
  test(`late list ${failed ? 'error' : 'success'} after clear cannot repopulate or change expired DOM`, async () => {
    const h = await harness(), held = deferred(); h.read(() => held.promise); const loading = h.controller.activate();
    h.controller.clear(); const expired = snapshot(h.root); assert.equal(h.calls[0].options.signal.aborted, true);
    if (failed) held.reject(new Error('late read error')); else held.resolve({users:sampleUsers});
    await loading; assert.equal(snapshot(h.root), expired);
  });
}

test('a new activation owns its read even if an old aborted read finishes later', async () => {
  const h = await harness(), old = deferred(); h.read(() => old.promise); const first = h.controller.activate();
  h.controller.deactivate(); await h.controller.activate(); const current = snapshot(h.root);
  old.resolve({users:[{username:'stale',role:'viewer',enabled:true}]}); await first;
  assert.equal(snapshot(h.root), current); assert.ok(h.row(admin.username));
});

for (const operation of ['create','edit','delete']) for (const failed of [false,true]) {
  test(`late ${operation} ${failed ? 'error' : 'success'} after deactivation changes no expired DOM`, async () => {
    let revoked = 0; const h = await harness({revoked:() => {revoked++;}}), held = deferred();
    await h.controller.activate(); h.write(() => held.promise);
    let saving;
    if (operation === 'create') {await h.create(); saving = h.submit();}
    else if (operation === 'edit') {await h.action('fixture-operator','edit').emit('click'); h.get('role').value = 'viewer'; saving = h.submit();}
    else saving = h.action('fixture-operator','delete').emit('click');
    await flush(); h.controller.deactivate(); const expired = snapshot(h.root);
    assert.equal(h.calls.at(-1).options.signal.aborted, true);
    if (failed) held.reject(Object.assign(new Error('late mutation error'),{status:409})); else held.resolve(null);
    await saving; assert.equal(snapshot(h.root), expired); assert.equal(revoked, 0);
  });
}

test('deactivation during delete confirmation prevents the request entirely', async () => {
  const confirmation = deferred(), h = await harness({confirm:() => confirmation.promise}); await h.controller.activate();
  const deleting = h.action('fixture-operator','delete').emit('click'); h.controller.deactivate(); const expired = snapshot(h.root);
  confirmation.resolve(true); await deleting; assert.equal(h.calls.length, 1); assert.equal(snapshot(h.root), expired);
});

test('reactivation waits for an unresolved old write and independently reads current state', async () => {
  const held = deferred(), h = await harness(); await h.controller.activate(); await h.create(); h.write(() => held.promise);
  const saving = h.submit(); await flush(); h.controller.clear(); const activated = h.controller.activate(); await flush();
  assert.equal(h.get('create').disabled, true); assert.equal(h.calls.length, 2);
  await h.submit(); held.resolve(null); await Promise.all([saving, activated]);
  assert.equal(h.calls.length, 3); assert.equal(h.calls[2].path, '/api/v1/users');
  assert.equal(h.get('create').disabled, false); assert.equal(h.get('notice').textContent, '');
});

test('a late own-account save cannot invoke revocation or clear a new principal activation', async () => {
  let revoked = 0;
  const h = await harness({revoked:() => {revoked++;}}), held = deferred();
  await h.controller.activate(); await h.action(admin.username,'reset').emit('click');
  h.get('password').value = 'fixture secret'; h.get('password-confirm').value = 'fixture secret';
  h.write(() => held.promise); const saving = h.submit(); await flush();
  h.controller.clear(); h.setPrincipal({...admin,username:'next-fixture-admin'});
  const activated = h.controller.activate(); held.resolve(null); await Promise.all([saving, activated]);
  assert.equal(revoked, 0); assert.equal(h.get('list').children.length, 3);
  assert.equal(h.get('create').disabled, false); assert.equal(h.get('notice').textContent, '');
});

test('principal changes fence old completion even without parent clear, and next activation refuses access', async () => {
  const held = deferred(), h = await harness(); h.read(() => held.promise); const loading = h.controller.activate();
  h.setPrincipal({username:'new-viewer',role:'viewer',enabled:true}); const before = snapshot(h.root);
  held.resolve({users:sampleUsers}); await loading; assert.equal(snapshot(h.root), before);
  await h.controller.activate(); assert.equal(h.get('list').children.length, 0); assert.equal(h.calls.length, 1);
});

for (const status of [401,403]) test(`${status} clears account data and password drafts without a saved confirmation`, async () => {
  const h = await harness(); await h.controller.activate(); await h.create();
  h.write(async () => {throw Object.assign(new Error('Access expired'),{status});}); await h.submit();
  assert.equal(h.get('list').children.length, 0); assert.equal(h.get('dialog').open, false);
  assert.equal(h.get('password').value, ''); assert.equal(h.get('notice').textContent, '');
  assert.equal(h.get('create').disabled, true);
});

test('capacity is communicated without sending an over-limit create', async () => {
  const users = [admin,...Array.from({length:63}, (_,index) => ({username:`fixture-${index}`,role:'viewer',enabled:true}))];
  const h = await harness({users}); await h.controller.activate();
  assert.match(h.get('count').textContent, /64/); assert.equal(h.get('create').disabled, true);
  await h.get('create').emit('click'); assert.equal(h.get('dialog').open, false); assert.equal(h.calls.length, 1);
});

test('saved confirmation survives a failed post-mutation list readback', async () => {
  const h = await harness(); await h.controller.activate(); await h.create();
  h.read(async () => {throw Object.assign(new Error('readback unavailable'),{status:503});}); await h.submit();
  assert.match(h.get('notice').textContent, /created|saved/i); assert.equal(h.get('dialog').open, false);
  assert.match(h.get('list-notice').textContent, /readback unavailable/); assert.equal(h.get('create').disabled, true);
  assert.equal(h.get('password').value, '');
});

test('Users styles are scoped, inherit typography, and use full neutral borders and mobile wrapping', async () => {
  const css = await readFile(new URL('../../web/users.css', import.meta.url), 'utf8');
  assert.doesNotMatch(css, /border-(?:left|right|inline-start|inline-end)\s*:/i);
  assert.match(css, /border:\s*1px solid var\(--line\)/);
  assert.match(css, /font:\s*inherit/); assert.match(css, /overflow-wrap:\s*anywhere/);
  assert.match(css, /@media\s*\(max-width:\s*680px\)/);
  assert.match(css, /minmax\(0,\s*1fr\)/); assert.match(css, /min-height:\s*44px/);
});

test('dialog title and grid shrink safely for an unbroken username at mobile widths', async () => {
  const css = await readFile(new URL('../../web/users.css', import.meta.url), 'utf8');
  assert.match(css, /\.users-page\s*\{[^}]*overflow-wrap:\s*anywhere/s);
  assert.match(css, /\.users-page \.users-dialog form\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)/s);
});
