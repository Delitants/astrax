// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

let csrf = null;
let generation = 0;
let authenticated = false;
let principal = null;
let requiresFreshDocument = false;
let documentRef = null;
let authenticatedCallback = () => {};
let expiredCallback = () => {};
const bindings = new WeakMap();

const node = id => documentRef?.getElementById(id);
const authError = (message) => {
  const notice = node('authNotice');
  if (!notice) return;
  notice.textContent = message;
  notice.hidden = false;
  notice.setAttribute('role','alert');
};

function authStatus(message = '') {
  const status = node('authStatus');
  if (status) {status.textContent = message; status.hidden = !message;}
}

function passwordVisible(visible) {
  const input = node('authLoginForm')?.elements?.password;
  if (input) input.type = visible ? 'text' : 'password';
  const toggle = node('authPasswordToggle');
  if (!toggle) return;
  toggle.textContent = visible ? 'Hide' : 'Show';
  toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  toggle.setAttribute('aria-pressed', String(visible));
}

function bind(id, type, listener) {
  const target = node(id);
  if (!target) return;
  const existing = bindings.get(target) || new Set();
  if (existing.has(type)) return;
  existing.add(type); bindings.set(target,existing);
  target.addEventListener(type,listener);
}

function showLogin(setupPending = false) {
  node('authLoginForm')?.reset();
  node('authSetupForm')?.reset();
  node('changePasswordForm')?.reset();
  node('dashboard').hidden = true;
  node('authView').hidden = false;
  node('authLoginForm').hidden = setupPending;
  node('authSetupForm').hidden = !setupPending;
  node('logoutButton').hidden = true;
  if (node('authTitle')) node('authTitle').textContent = setupPending ? 'Create administrator' : 'Sign in';
  if (node('authLede')) node('authLede').textContent = setupPending
    ? 'Create the initial account to manage AstraX.' : 'Manage your streams, DVB cards and settings.';
  authStatus();
  passwordVisible(false);
  const notice = node('authNotice');
  if (notice) {notice.hidden = true;notice.textContent = '';}
  node(setupPending ? 'authSetupForm' : 'authLoginForm')?.elements?.[setupPending ? 'secret' : 'username']?.focus();
}

function showDashboard() {
  node('authView').hidden = true;
  node('dashboard').hidden = false;
  node('logoutButton').hidden = false;
  authStatus();
  passwordVisible(false);
}

export function csrfHeader() {return csrf;}
export function authGeneration() {return generation;}
export function authenticatedUser() {return principal;}

function sessionUser(body) {
  const user = body?.user;
  if (!user || typeof user.username !== 'string' || !user.username || user.enabled !== true ||
      !['administrator','operator','viewer'].includes(user.role)) throw new Error('Invalid account session');
  return Object.freeze({username:user.username,role:user.role,enabled:true});
}

export function onUnauthorized() {
  if (!authenticated) return;
  authenticated = false;
  principal = null;
  csrf = null;
  requiresFreshDocument = true;
  generation++;
  node('dashboard').hidden = true;
  const expiredGeneration = generation;
  const expiredDocument = documentRef;
  try {expiredCallback();} catch { /* The login boundary must stay closed even if cleanup fails. */ }
  if (generation === expiredGeneration && documentRef === expiredDocument) showLogin(false);
}

async function authRequest(path, payload, token = null) {
  const started = generation;
  const headers = {'Content-Type':'application/json'};
  if (token) headers['X-AstraX-CSRF'] = token;
  const response = await fetch(path,{method:'POST',headers,body:JSON.stringify(payload),cache:'no-store'});
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && started === generation && authenticated) onUnauthorized();
    throw Object.assign(new Error(typeof body?.error === 'string' ? body.error : `Request failed (${response.status})`),{status:response.status});
  }
  return body;
}

async function submit(form, path, payload) {
  const started = generation;
  const button = form.querySelector?.('button[type=submit]');
  if (button?.disabled) return;
  const originalLabel = button?.textContent;
  if (button) button.disabled = true;
  if (button) button.textContent = path.endsWith('/setup') ? 'Creating administrator...' : 'Signing in...';
  form.setAttribute('aria-busy','true');
  const notice = node('authNotice');
  if (notice) {notice.hidden = true; notice.textContent = '';}
  authStatus(path.endsWith('/setup') ? 'Creating your administrator account...' : 'Verifying your credentials...');
  try {
    const result = await authRequest(path,payload);
    if (started !== generation) return;
    if (!result?.authenticated || typeof result.csrf_token !== 'string' || !result.csrf_token) throw new Error('Invalid session response');
    const user = sessionUser(result);
    // Hidden panels can still hold data from the prior session; only a new document may reveal them.
    if (requiresFreshDocument) {
      generation++;
      form.reset();
      try {documentRef.defaultView.location.reload();}
      catch {authError('Sign-in succeeded. Reload this page to open management.');}
      return;
    }
    csrf = result.csrf_token;
    principal = user;
    authenticated = true;
    generation++;
    form.reset();
    showDashboard();
    authenticatedCallback(principal);
  } catch (error) {if (started === generation) authError(error.message);}
  finally {
    if (button) {button.disabled = false; button.textContent = originalLabel;}
    form.removeAttribute('aria-busy');
    if (started === generation) authStatus();
  }
}

function bindForms() {
  bind('authLoginForm','submit',event => {
    event.preventDefault();
    const form = event.currentTarget;
    void submit(form,'/api/v1/auth/login',{username:form.elements.username.value.trim(),password:form.elements.password.value});
  });
  bind('authPasswordToggle','click',() => {passwordVisible(node('authLoginForm')?.elements?.password?.type === 'password');});
  bind('authSetupForm','submit',event => {
    event.preventDefault();
    const form = event.currentTarget;
    if (form.elements.password.value !== form.elements.confirm_password.value) return authError('Passwords do not match.');
    void submit(form,'/api/v1/auth/setup',{secret:form.elements.secret.value,password:form.elements.password.value});
  });
  bind('logoutButton','click',() => {void logout().catch(error => {
    const notice = node('globalActionNotice');
    if (authenticated && notice) {notice.textContent = error.message; notice.hidden = false; notice.setAttribute('role','alert');}
    else authError(error.message);
  });});
  bind('changePasswordForm','submit',event => {
    event.preventDefault();
    const form = event.currentTarget;
    const notice = node('passwordNotice');
    if (form.elements.new_password.value !== form.elements.confirm_password.value) {
      if (notice) notice.textContent = 'Passwords do not match.';
      return;
    }
    const oldPassword = form.elements.old_password.value;
    const newPassword = form.elements.new_password.value;
    const started = generation;
    const button = form.querySelector?.('button[type=submit]');
    if (button?.disabled) return;
    if (button) button.disabled = true;
    if (notice) notice.textContent = 'Saving password...';
    void authRequest('/api/v1/auth/password',{old_password:oldPassword,new_password:newPassword},csrf).then(() => {
      if (started !== generation) return;
      form.reset();
      onUnauthorized();
      authStatus('Your password changed. Sign in again.');
    }).catch(error => {if (notice && started === generation) notice.textContent = error.message;}).finally(() => {if (button) button.disabled = false;});
  });
}

export async function bootstrapAuth({document: doc = globalThis.document,onAuthenticated = () => {},onExpired = () => {}} = {}) {
  if (doc !== documentRef) requiresFreshDocument = false;
  documentRef = doc;
  authenticatedCallback = onAuthenticated;
  expiredCallback = onExpired;
  csrf = null;
  authenticated = false;
  principal = null;
  const attempt = ++generation;
  node('dashboard').hidden = true;
  node('authView').hidden = false;
  node('authLoginForm').hidden = true;
  node('authSetupForm').hidden = true;
  node('logoutButton').hidden = true;
  authStatus('Checking your session...');
  passwordVisible(false);
  const origin = doc.defaultView?.location?.origin || globalThis.location?.origin || '';
  node('authManagementAddress').textContent = origin;
  node('managementAddress').textContent = origin;
  bindForms();
  try {
    const response = await fetch('/api/v1/auth/session',{cache:'no-store'});
    const body = await response.json();
    if (attempt !== generation) return false;
    if (response.status === 401) {showLogin(body?.setup_pending === true);return false;}
    if (!response.ok || body?.authenticated !== true || typeof body.csrf_token !== 'string' || !body.csrf_token) throw new Error('Session inspection failed');
    principal = sessionUser(body);
    csrf = body.csrf_token;
    authenticated = true;
    showDashboard();
    authenticatedCallback(principal);
    return true;
  } catch {
    if (attempt === generation) authStatus();
    if (attempt === generation) authError('Cannot check your account session. Retry by reloading this page.');
    return false;
  }
}

export async function logout() {
  if (!authenticated) return;
  const started = generation;
  await authRequest('/api/v1/auth/logout',{},csrf);
  if (started === generation) onUnauthorized();
}

export async function fetchProtected(path,options = {}) {
  const started = generation;
  const response = await fetch(path,options);
  if (response.status === 401 && started === generation) onUnauthorized();
  if (started !== generation || response.status === 401) throw Object.assign(new Error('Administrator session expired'),{status:401});
  return response;
}

export async function verifyEventSession() {
  const started = generation;
  try {
    const response = await fetch('/api/v1/auth/session',{cache:'no-store'});
    if (started !== generation) return false;
    if (response.status === 401) {onUnauthorized();return false;}
    return authenticated && started === generation;
  } catch {
    return authenticated && started === generation;
  }
}
