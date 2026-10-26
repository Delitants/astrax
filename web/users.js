// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const roleLabels = new Map([['administrator', 'Administrator'], ['operator', 'Operator'], ['viewer', 'Viewer']]);
const maxUsers = 64;

export function createUsersController({root, request, confirmAction, currentUser, onSessionRevoked}) {
  if (!root?.ownerDocument || typeof request !== 'function' || typeof confirmAction !== 'function' || typeof currentUser !== 'function') {
    throw new TypeError('Users requires a panel root, request, confirmAction, and currentUser.');
  }
  const doc = root.ownerDocument;
  const names = ['create', 'refresh', 'search', 'count', 'list', 'empty', 'notice', 'list-notice', 'dialog', 'form',
    'fields', 'dialog-title', 'username', 'role', 'enabled', 'enabled-row', 'reset-password', 'reset-row',
    'password', 'password-confirm', 'password-fields', 'self-warning', 'form-notice', 'save', 'cancel'];
  const el = Object.fromEntries(names.map(name => {
    const element = root.querySelector(`[data-users="${name}"]`);
    if (!element) throw new TypeError(`Users panel is missing ${name}.`);
    return [name, element];
  }));
  let active = false, generation = 0, principal = '', ready = false;
  let users = [], reading = null, pending = null, activation = null, editing = null, focusReturn = null;
  const administrator = user => user?.role === 'administrator' && user.enabled === true && typeof user.username === 'string' && !!user.username;
  const current = (owner = generation) => {
    if (!active || owner !== generation) return false;
    const actor = currentUser();
    return administrator(actor) && actor.username === principal;
  };
  const canWrite = () => current() && ready && !reading && !pending;
  const message = error => typeof error?.message === 'string' && error.message ? error.message : 'Request failed.';
  const node = (tag, text = '', className = '') => {
    const element = doc.createElement(tag); element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  function notice(target, text = '', kind = 'status') {
    target.textContent = text; target.hidden = !text;
    target.setAttribute('data-kind', kind);
    target.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    target.setAttribute('aria-live', kind === 'error' ? 'assertive' : 'polite');
  }
  function clearPasswords() {
    el.password.value = ''; el['password-confirm'].value = '';
  }
  function controls() {
    const allowed = current(), usable = canWrite(), open = el.dialog.open;
    const passwordWanted = open && (!editing || el['reset-password'].checked);
    root.setAttribute('data-users-state', !allowed ? 'inactive' : pending ? 'pending' : reading ? 'loading' : ready ? 'ready' : 'error');
    if (allowed && (reading || pending)) root.setAttribute('aria-busy', 'true');
    else root.removeAttribute('aria-busy');
    el.create.disabled = !usable || open || users.length >= maxUsers;
    el.create.setAttribute('title', users.length >= maxUsers ? 'The 64-account limit has been reached.' : 'Create an account');
    el.refresh.disabled = !allowed || !!reading || !!pending || open;
    el.search.disabled = !usable || open;
    el.fields.disabled = !usable || !open;
    for (const input of el.fields.querySelectorAll('input, select')) input.disabled = el.fields.disabled;
    el['reset-password'].disabled = el.fields.disabled || !editing;
    el.enabled.disabled = el.fields.disabled || !editing;
    el['password-fields'].hidden = !passwordWanted;
    el['reset-password'].setAttribute('aria-expanded', String(passwordWanted && !!editing));
    for (const password of [el.password, el['password-confirm']]) {
      password.disabled = el.fields.disabled || !passwordWanted; password.required = passwordWanted;
    }
    el.save.disabled = !usable || !open;
    el.cancel.disabled = !allowed || !!pending;
    if (allowed && pending?.fromDialog) el.form.setAttribute('aria-busy', 'true');
    else el.form.removeAttribute('aria-busy');
    for (const button of el.list.querySelectorAll('button')) button.disabled = !usable || open;
  }
  function resetDialog() {
    editing = null; el.form.reset(); clearPasswords();
    el.username.readOnly = false; el.role.value = 'viewer'; el.enabled.checked = true;
    el['reset-password'].checked = false; el['self-warning'].hidden = true;
    el['enabled-row'].hidden = true; el['reset-row'].hidden = true;
    el['dialog-title'].textContent = 'Create account'; el.save.textContent = 'Create account';
    notice(el['form-notice']);
  }
  function restoreFocus() {
    if (!current() || el.dialog.open) return;
    if (focusReturn && !root.contains(focusReturn) && focusReturn.getAttribute('data-user-action')) {
      const username = focusReturn.getAttribute('data-username'), action = focusReturn.getAttribute('data-user-action');
      focusReturn = Array.from(el.list.querySelectorAll('[data-user-action]')).find(button => button.getAttribute('data-username') === username && button.getAttribute('data-user-action') === action) || null;
    }
    const target = focusReturn && root.contains(focusReturn) && !focusReturn.disabled ? focusReturn
      : !el.create.disabled ? el.create : el.refresh;
    if (!target.disabled) target.focus({preventScroll:true});
  }
  function closeDialog(force = false, restore = true) {
    if (pending && !force) return;
    if (el.dialog.open) el.dialog.close();
    resetDialog(); controls();
    if (restore) restoreFocus();
  }
  function deactivate() {
    active = false; ++generation; principal = ''; activation = null; ready = false;
    reading?.controller.abort(); reading = null;
    // Aborting a fetch does not prove the server cancelled its write. Keep its fence until settlement.
    pending?.controller.abort();
    users = []; focusReturn = null; el.list.replaceChildren(); el.search.value = '';
    el.count.textContent = 'Accounts not loaded'; el.empty.hidden = true;
    notice(el.notice); notice(el['list-notice']); closeDialog(true, false);
  }
  function validateUsers(value) {
    if (!Array.isArray(value?.users) || value.users.length > maxUsers) throw new Error('Account list response is incomplete or invalid.');
    const names = new Set();
    return value.users.map(user => {
      if (!user || typeof user.username !== 'string' || !user.username.trim() || !roleLabels.has(user.role)
        || typeof user.enabled !== 'boolean' || names.has(user.username)) throw new Error('Account list response is incomplete or invalid.');
      names.add(user.username);
      return {username:user.username, role:user.role, enabled:user.enabled};
    });
  }
  function render() {
    const focused = el.list.contains(doc.activeElement) ? doc.activeElement : null;
    const focusedUser = focused?.getAttribute('data-username'), focusedAction = focused?.getAttribute('data-user-action');
    const query = el.search.value.trim().toLowerCase();
    const visible = users.filter(user => `${user.username} ${roleLabels.get(user.role)} ${user.enabled ? 'enabled' : 'disabled'}`.toLowerCase().includes(query));
    el.list.replaceChildren();
    for (const user of visible) {
      const row = node('li', '', 'users-row'), identity = node('div', '', 'users-identity');
      row.setAttribute('data-username', user.username);
      identity.append(node('strong', user.username, 'users-username'));
      if (user.username === principal) identity.append(node('small', 'Your account', 'users-you'));
      const role = node('div', '', 'users-role'), status = node('div');
      role.append(node('span', 'Role', 'users-cell-label'), node('span', roleLabels.get(user.role)));
      const enabled = node('span', user.enabled ? 'Enabled' : 'Disabled', 'users-status');
      enabled.setAttribute('data-enabled', String(user.enabled));
      status.append(node('span', 'Status', 'users-cell-label'), enabled);
      const actions = node('div', '', 'users-actions');
      for (const [action, label] of [['edit', 'Edit'], ['reset', 'Reset password'], ['delete', 'Delete']]) {
        const button = node('button', label, action === 'delete' ? 'users-delete' : ''); button.type = 'button';
        button.setAttribute('data-user-action', action); button.setAttribute('data-username', user.username);
        button.setAttribute('aria-label', `${label} account ${user.username}`);
        button.addEventListener('click', () => action === 'delete' ? deleteAccount(user) : openAccount(user, action === 'reset', button));
        actions.append(button);
      }
      row.append(identity, role, status, actions); el.list.append(row);
    }
    el.count.textContent = query ? `${visible.length} of ${users.length} accounts (64 maximum)` : `${users.length} of 64 accounts`;
    el.empty.textContent = query ? 'No accounts match your search.' : 'No accounts. Create a named account to get started.';
    el.empty.hidden = !ready || visible.length > 0;
    controls();
    if (focused) {
      const replacement = Array.from(el.list.querySelectorAll('[data-user-action]')).find(button => button.getAttribute('data-username') === focusedUser && button.getAttribute('data-user-action') === focusedAction);
      focusReturn = replacement || el.create; restoreFocus();
    }
  }
  function loadUsers(owner = generation) {
    if (!current(owner) || pending) return Promise.resolve();
    if (reading) return reading.promise;
    const job = {controller:new AbortController(), promise:null,
      restoreFocus:el.list.contains(doc.activeElement) || doc.activeElement === el.refresh};
    if (job.restoreFocus) focusReturn = doc.activeElement;
    reading = job; ready = false;
    el.empty.hidden = true; notice(el['list-notice'], 'Loading accounts...'); controls();
    job.promise = (async () => {
      try {
        const value = await request('/api/v1/users', {signal:job.controller.signal});
        if (!current(owner) || reading !== job) return;
        users = validateUsers(value); ready = true; notice(el['list-notice']); render();
      } catch (error) {
        if (!current(owner) || reading !== job) return;
        if (error?.status === 401 || error?.status === 403) {deactivate(); return;}
        ready = false;
        notice(el['list-notice'], `Could not load accounts. ${message(error)} Refresh the list before making changes.`, 'error');
      } finally {
        if (current(owner) && reading === job) {
          reading = null; controls(); if (job.restoreFocus) restoreFocus();
        }
      }
    })();
    return job.promise;
  }
  function activate() {
    const actor = currentUser();
    if (!administrator(actor)) {deactivate(); return Promise.resolve();}
    if (active && principal === actor.username) return activation;
    deactivate(); active = true; principal = actor.username;
    const owner = generation;
    activation = (async () => {
      if (pending) {
        notice(el['list-notice'], 'Waiting for the previous account request to finish before loading current accounts.'); controls();
        await pending.done;
      }
      if (current(owner)) await loadUsers(owner);
    })();
    return activation;
  }
  function openAccount(user = null, reset = false, trigger = el.create) {
    if (!canWrite() || el.dialog.open || (!user && users.length >= maxUsers)) return;
    resetDialog(); focusReturn = trigger;
    editing = user ? {...user} : null;
    el['dialog-title'].textContent = user ? `Edit account: ${user.username}` : 'Create account';
    el.save.textContent = user ? 'Save changes' : 'Create account';
    el.username.value = user?.username || ''; el.username.readOnly = !!user;
    el.role.value = user?.role || 'viewer'; el.enabled.checked = user?.enabled ?? true;
    el['enabled-row'].hidden = !user; el['reset-row'].hidden = !user;
    el['reset-password'].checked = !!user && reset;
    el['self-warning'].hidden = !user || user.username !== principal;
    el.dialog.showModal(); controls();
    (reset ? el.password : user ? el.role : el.username).focus({preventScroll:true});
  }
  const lastAdministrator = user => user.enabled && user.role === 'administrator'
    && users.filter(account => account.enabled && account.role === 'administrator').length <= 1;
  async function writeAccount({path, method, body, confirmation, pendingText, savedText, own = false, fromDialog = false}) {
    if (!canWrite()) return;
    const owner = generation, target = fromDialog ? el['form-notice'] : el.notice;
    let settled;
    const operation = {controller:new AbortController(), fromDialog, done:new Promise(resolve => {settled = resolve;})};
    pending = operation; clearPasswords();
    notice(target, confirmation ? 'Confirmation pending. Wait for the result; do not repeat this request.' : pendingText);
    controls();
    let saved = false, revoked = false, dispatched = false;
    try {
      if (confirmation) {
        const approved = await confirmAction(confirmation);
        if (!current(owner)) return;
        if (!approved) {notice(target, 'Change cancelled. No request was sent.'); return;}
      }
      if (!current(owner)) return;
      notice(target, pendingText);
      dispatched = true;
      await request(path, {method, signal:operation.controller.signal, headers:{'Content-Type':'application/json'},
        ...(body === undefined ? {} : {body:JSON.stringify(body)})});
      if (!current(owner)) return;
      saved = true;
      if (own) {deactivate(); revoked = true;}
      else {
        notice(el.notice, savedText);
        if (fromDialog) closeDialog(true, false);
      }
    } catch (error) {
      if (!current(owner)) return;
      if (!dispatched) {notice(target, `No request was sent. ${message(error)}`, 'error'); return;}
      if (error?.status === 401 || error?.status === 403) {deactivate(); return;}
      const rejected = error?.status >= 400 && error.status < 500 && error.status !== 408;
      if (!rejected) ready = false;
      notice(target, rejected ? `Not saved. ${message(error)}`
        : `Result not confirmed. ${message(error)} ${fromDialog ? 'Close this dialog and refresh' : 'Refresh'} the list before retrying; the request may have reached the server.`, 'error');
    } finally {
      if (pending === operation) pending = null;
      settled();
      if (current(owner)) controls();
    }
    if (revoked) {onSessionRevoked?.(); return;}
    if (saved && current(owner)) {await loadUsers(owner); if (current(owner)) restoreFocus();}
  }
  async function deleteAccount(user) {
    if (!canWrite() || el.dialog.open) return;
    if (lastAdministrator(user)) {notice(el.notice, 'Keep the last enabled administrator. Enable another administrator before deleting this account.', 'error'); return;}
    const own = user.username === principal;
    await writeAccount({path:`/api/v1/users/${encodeURIComponent(user.username)}`, method:'DELETE', own,
      confirmation:`Delete account "${user.username}"? All of its sessions will be revoked. ${own ? 'This is your own account; you will be signed out. ' : ''}This cannot be undone.`,
      pendingText:`Deleting account "${user.username}"... Wait for the result; do not repeat this request.`,
      savedText:`Account "${user.username}" deleted. Its sessions have been revoked.`});
  }
  el.create.addEventListener('click', () => openAccount());
  el.refresh.addEventListener('click', () => {if (current() && !el.dialog.open && !reading && !pending) return loadUsers();});
  el.search.addEventListener('input', () => {if (current() && ready && !pending) render();});
  el.cancel.addEventListener('click', () => {if (current()) closeDialog();});
  el.dialog.addEventListener('cancel', event => {
    if (pending) {event.preventDefault(); return;}
    // Close explicitly so secrets are removed synchronously, before the native close event.
    event.preventDefault(); closeDialog();
  });
  el.dialog.addEventListener('close', () => {
    if (el.dialog.open) return;
    resetDialog(); controls(); if (!pending) restoreFocus();
  });
  el['reset-password'].addEventListener('change', () => {
    if (!canWrite() || !el.dialog.open) return;
    clearPasswords(); controls();
    if (el['reset-password'].checked) el.password.focus({preventScroll:true});
  });
  el.form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!canWrite() || !el.dialog.open) return;
    const invalid = (text, input) => {notice(el['form-notice'], text, 'error'); input.focus({preventScroll:true});};
    const username = editing?.username || el.username.value.trim(), role = el.role.value;
    if (!username) return invalid('Enter a username.', el.username);
    if (!roleLabels.has(role)) return invalid('Select a valid role.', el.role);
    const reset = !editing || el['reset-password'].checked;
    if (reset && !el.password.value) return invalid('Enter a new password.', el.password);
    if (reset && el.password.value !== el['password-confirm'].value) return invalid('The passwords must match.', el['password-confirm']);
    if (editing && lastAdministrator(editing) && (role !== 'administrator' || !el.enabled.checked)) {
      return invalid('Keep the last enabled administrator. Enable another administrator before disabling or demoting this account.', el.role);
    }
    const body = editing ? {
      ...(role === editing.role ? {} : {role}),
      ...(el.enabled.checked === editing.enabled ? {} : {enabled:el.enabled.checked}),
      ...(reset ? {new_password:el.password.value} : {}),
    } : {username, password:el.password.value, role};
    if (editing && !Object.keys(body).length) {notice(el['form-notice'], 'No changes to save.'); return;}
    const own = !!editing && username === principal;
    await writeAccount({path:editing ? `/api/v1/users/${encodeURIComponent(username)}` : '/api/v1/users',
      method:editing ? 'PUT' : 'POST', body, own, fromDialog:true,
      confirmation:own ? `Save changes to your own account "${username}"? You will be signed out of all sessions immediately.` : undefined,
      pendingText:`${editing ? 'Saving' : 'Creating'} account "${username}"... Wait for the result; do not repeat this request.`,
      savedText:editing ? `Account "${username}" saved.${reset ? ' Password reset.' : ''} Its sessions have been revoked.` : `Account "${username}" created.`,
    });
  });
  deactivate();
  return {activate, deactivate, clear:deactivate};
}
