// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import test from 'node:test';
import assert from 'node:assert/strict';
import {bootstrapAuth, csrfHeader, onUnauthorized, logout, fetchProtected, verifyEventSession} from '../../web/auth.js';
import {requestJSON} from '../../web/ui-common.js';

function element() {
  return {hidden:false, value:'', textContent:'', disabled:false, listeners:{}, attributes:{},
    addEventListener(name, fn) {this.listeners[name] = fn;},
    reset() {for (const field of Object.values(this.elements || {})) field.value = '';}, focus() {this.focused = true;},
    setAttribute(name, value) {this.attributes[name] = String(value);}, removeAttribute(name) {delete this.attributes[name];}};
}
function documentFixture() {
  const ids = ['authView','authLoginForm','authSetupForm','authNotice','dashboard','logoutButton',
    'changePasswordForm','passwordNotice','managementAddress','authManagementAddress','statusPill',
    'settingsForm','epgForm','epgHealthSources','epgHealthSnapshot','apiSettingsForm',
    'apiListenerStatus','apiOperationDescription','authTitle','authLede','authStatus','authPasswordToggle'];
  const nodes = Object.fromEntries(ids.map(id => [id, element()]));
  nodes.authLoginForm.elements = {username:element(),password:element()};
  nodes.authLoginForm.elements.password.type = 'password';
  nodes.authSetupForm.elements = {secret:element(),password:element(),confirm_password:element()};
  nodes.changePasswordForm.elements = {old_password:element(),new_password:element(),confirm_password:element()};
  nodes.settingsForm.elements = {control_listen:element()};
  nodes.epgForm.elements = {epg_source_urls:element()};
  nodes.apiSettingsForm.elements = {listen_address:element()};
  const location = {origin:'https://astrax.test', reloads:0, reload() {this.reloads++;}};
  return {nodes, location, doc:{getElementById:id => nodes[id], defaultView:{location}}};
}

test('unauthenticated first run shows setup before any dashboard callback', async t => {
  const {doc,nodes} = documentFixture();
  const paths = [];
  t.mock.method(globalThis,'fetch', async path => {
    paths.push(path);
    return Response.json({authenticated:false,setup_pending:true},{status:401});
  });
  let started = 0;
  await bootstrapAuth({document:doc,onAuthenticated:()=>started++});
  assert.deepEqual(paths,['/api/v1/auth/session']);
  assert.equal(started,0);
  assert.equal(nodes.authSetupForm.hidden,false);
  assert.equal(nodes.authLoginForm.hidden,true);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(nodes.authManagementAddress.textContent,'https://astrax.test');
});

test('session boot keeps CSRF in memory and mutation sends it without changing caller options', async t => {
  const {doc,nodes} = documentFixture();
  const calls = [];
  t.mock.method(globalThis,'fetch',async (path,options={}) => {
    calls.push({path,options});
    return Response.json(path === '/api/v1/auth/session' ? {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'token-one'} : {ok:true});
  });
  let started = 0;
  await bootstrapAuth({document:doc,onAuthenticated:()=>started++});
  assert.equal(started,1);
  assert.equal(nodes.dashboard.hidden,false);
  assert.equal(csrfHeader(),'token-one');
  const options = Object.freeze({method:'PATCH',headers:Object.freeze({'X-Test':'value'}),body:'{}'});
  await requestJSON('/api/v1/settings',options);
  assert.equal(new Headers(calls[1].options.headers).get('X-AstraX-CSRF'),'token-one');
  assert.equal(new Headers(calls[1].options.headers).get('X-Test'),'value');
  assert.equal(options.headers['X-AstraX-CSRF'],undefined);
  await requestJSON('/api/v1/status');
  assert.equal(new Headers(calls[2].options.headers).has('X-AstraX-CSRF'),false);
});

test('a management 401 transitions once, clears CSRF, and fences stale responses', async t => {
  const {doc,nodes} = documentFixture();
  let expired = 0;
  t.mock.method(globalThis,'fetch',async path => Response.json(path === '/api/v1/auth/session'
    ? {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'token-two'} : {error:'authentication required'},
    {status:path === '/api/v1/auth/session' ? 200 : 401}));
  await bootstrapAuth({document:doc,onExpired:()=>expired++});
  await assert.rejects(requestJSON('/api/v1/status'),error => error.status === 401);
  onUnauthorized();
  assert.equal(expired,1);
  assert.equal(csrfHeader(),null);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(nodes.authLoginForm.hidden,false);
});

test('logout sends CSRF and clears the authenticated shell', async t => {
  const {doc,nodes} = documentFixture();
  const calls = [];
  t.mock.method(globalThis,'fetch',async (path,options) => {
    calls.push({path,options});
    return Response.json(path === '/api/v1/auth/session'
      ? {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'token-three'} : {authenticated:false});
  });
  await bootstrapAuth({document:doc});
  await logout();
  assert.equal(calls[1].path,'/api/v1/auth/logout');
  assert.equal(new Headers(calls[1].options.headers).get('X-AstraX-CSRF'),'token-three');
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(csrfHeader(),null);
});

const flush = async () => {for (let i=0;i<8;i++) await new Promise(setImmediate);};

test('login submits the entered username instead of a hard-coded administrator', async t => {
  const {doc,nodes} = documentFixture();
  const calls = [];
  t.mock.method(globalThis,'fetch',async (path,options) => {
    calls.push({path,options});
    return path === '/api/v1/auth/session' ? Response.json({authenticated:false},{status:401})
      : Response.json({error:'invalid credentials'},{status:401});
  });
  await bootstrapAuth({document:doc});
  const form = nodes.authLoginForm;
  form.elements.username.value = 'operator-one';
  form.elements.password.value = 'test-only-password';
  form.listeners.submit({preventDefault(){},currentTarget:form});
  await flush();
  assert.deepEqual(JSON.parse(calls[1].options.body),{username:'operator-one',password:'test-only-password'});
  assert.equal(nodes.authLoginForm.elements.username.focused,true);
});

test('password visibility toggle makes no request and resets at the login boundary', async t => {
  const {doc,nodes} = documentFixture();
  let calls = 0;
  t.mock.method(globalThis,'fetch',async () => {calls++; return Response.json({authenticated:false},{status:401});});
  await bootstrapAuth({document:doc});
  const toggle = nodes.authPasswordToggle;
  toggle.listeners.click();
  assert.equal(nodes.authLoginForm.elements.password.type,'text');
  assert.equal(toggle.attributes['aria-label'],'Hide password');
  assert.equal(toggle.attributes['aria-pressed'],'true');
  assert.equal(calls,1);
  await bootstrapAuth({document:documentFixture().doc});
  const next = documentFixture();
  await bootstrapAuth({document:next.doc});
  assert.equal(next.nodes.authLoginForm.elements.password.type,'password');
  assert.equal(next.nodes.authPasswordToggle.attributes['aria-pressed'],'false');
});

test('expire then login keeps populated settings, EPG, and API pages hidden until a clean boot', async t => {
  const oldPage = documentFixture();
  const {doc,nodes,location} = oldPage;
  nodes.settingsForm.elements.control_listen.value = 'private listener';
  nodes.epgForm.elements.epg_source_urls.value = 'https://private.invalid/guide.xml';
  nodes.epgHealthSources.textContent = 'private source health';
  nodes.epgHealthSnapshot.textContent = 'private snapshot';
  nodes.apiSettingsForm.elements.listen_address.value = 'private API address';
  nodes.apiListenerStatus.textContent = 'private listener status';
  nodes.apiOperationDescription.textContent = 'private API details';
  let starts = 0, finishOldRefresh, finishFreshSession, finishFreshRefresh;
  let sessionChecks = 0;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/api/v1/auth/session') {
      sessionChecks++;
      return sessionChecks === 1 ? Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'old-csrf'})
        : new Promise(resolve => {finishFreshSession = resolve;});
    }
    if (path === '/slow-refresh') return new Promise(resolve => {finishOldRefresh = resolve;});
    if (path === '/fresh-refresh') return new Promise(resolve => {finishFreshRefresh = resolve;});
    if (path === '/expired') return Response.json({error:'expired'},{status:401});
    if (path === '/api/v1/auth/login') return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'login-csrf'});
    throw new Error(`unexpected ${path}`);
  });
  await bootstrapAuth({document:doc,onAuthenticated:()=>starts++});
  const oldRefresh = requestJSON('/slow-refresh');
  await flush();
  await assert.rejects(requestJSON('/expired'),error => error.status === 401);
  assert.equal(nodes.dashboard.hidden,true);
  const login = nodes.authLoginForm;
  login.elements.password.value = 'password';
  login.listeners.submit({preventDefault(){},currentTarget:login});
  await flush();
  assert.equal(location.reloads,1);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(starts,1);
  assert.equal(nodes.settingsForm.elements.control_listen.value,'private listener');
  assert.equal(nodes.epgForm.elements.epg_source_urls.value,'https://private.invalid/guide.xml');
  assert.equal(nodes.epgHealthSources.textContent,'private source health');
  assert.equal(nodes.apiSettingsForm.elements.listen_address.value,'private API address');
  assert.equal(nodes.apiListenerStatus.textContent,'private listener status');
  finishOldRefresh(Response.json({stale:true}));
  await assert.rejects(oldRefresh,error => error.status === 401);

  const freshPage = documentFixture();
  let freshRefresh;
  const boot = bootstrapAuth({document:freshPage.doc,onAuthenticated:() => {
    starts++;
    freshRefresh = requestJSON('/fresh-refresh');
  }});
  assert.equal(freshPage.nodes.dashboard.hidden,true);
  assert.equal(freshPage.nodes.settingsForm.elements.control_listen.value,'');
  finishFreshSession(Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'fresh-csrf'}));
  await boot;
  assert.equal(starts,2);
  assert.equal(freshPage.nodes.dashboard.hidden,false);
  assert.equal(freshPage.nodes.settingsForm.elements.control_listen.value,'');
  assert.equal(freshPage.nodes.epgForm.elements.epg_source_urls.value,'');
  assert.equal(freshPage.nodes.epgHealthSources.textContent,'');
  assert.equal(freshPage.nodes.epgHealthSnapshot.textContent,'');
  assert.equal(freshPage.nodes.apiSettingsForm.elements.listen_address.value,'');
  assert.equal(freshPage.nodes.apiListenerStatus.textContent,'');
  assert.equal(freshPage.nodes.apiOperationDescription.textContent,'');
  finishFreshRefresh(Response.json({error:'refresh failed'},{status:503}));
  await assert.rejects(freshRefresh,error => error.status === 503);
  assert.equal(freshPage.nodes.settingsForm.elements.control_listen.value,'');
  assert.equal(freshPage.nodes.epgForm.elements.epg_source_urls.value,'');
  assert.equal(freshPage.nodes.epgHealthSources.textContent,'');
  assert.equal(freshPage.nodes.apiSettingsForm.elements.listen_address.value,'');
  assert.equal(freshPage.nodes.apiListenerStatus.textContent,'');
});

test('successful password change signs out and clears the password form', async t => {
  const {doc,nodes} = documentFixture();
  const calls = [];
  t.mock.method(globalThis,'fetch',async (path,options={}) => {
    calls.push({path,options});
    return Response.json(path === '/api/v1/auth/session'
      ? {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'change-csrf'} : {authenticated:false});
  });
  await bootstrapAuth({document:doc});
  const form = nodes.changePasswordForm;
  form.elements.old_password.value = 'old-password';
  form.elements.new_password.value = form.elements.confirm_password.value = 'new-password';
  form.listeners.submit({preventDefault(){},currentTarget:form});
  await flush();
  assert.equal(calls[1].path,'/api/v1/auth/password');
  assert.equal(new Headers(calls[1].options.headers).get('X-AstraX-CSRF'),'change-csrf');
  assert.deepEqual(JSON.parse(calls[1].options.body),{old_password:'old-password',new_password:'new-password'});
  assert.equal(form.elements.old_password.value,'');
  assert.equal(form.elements.new_password.value,'');
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(nodes.authLoginForm.hidden,false);
  assert.equal(csrfHeader(),null);
});

test('setup submits secret once, and a later login waits for clean dashboard boot', async t => {
  const {doc,nodes,location} = documentFixture();
  const calls = [];
  let sessionChecks = 0;
  t.mock.method(globalThis,'fetch',async (path,options={}) => {
    calls.push({path,options});
    if (path === '/api/v1/auth/session') return ++sessionChecks === 1
      ? Response.json({setup_pending:true},{status:401})
      : Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'fresh-csrf'});
    return Response.json(path === '/api/v1/auth/logout' ? {authenticated:false} : {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'fresh-csrf'});
  });
  let started = 0;
  await bootstrapAuth({document:doc,onAuthenticated:()=>started++});
  const setup = nodes.authSetupForm;
  setup.elements.secret.value = 'one-time';
  setup.elements.password.value = setup.elements.confirm_password.value = 'Strong-Password-2026!';
  setup.listeners.submit({preventDefault(){},currentTarget:setup});
  await flush();
  assert.equal(calls[1].path,'/api/v1/auth/setup');
  assert.deepEqual(JSON.parse(calls[1].options.body),{secret:'one-time',password:'Strong-Password-2026!'});
  assert.equal(setup.elements.secret.value,'');
  assert.equal(started,1);
  await logout();
  const login = nodes.authLoginForm;
  login.elements.password.value = 'Strong-Password-2026!';
  login.listeners.submit({preventDefault(){},currentTarget:login});
  await flush();
  assert.equal(calls.at(-1).path,'/api/v1/auth/login');
  assert.equal(login.elements.password.value,'');
  assert.equal(location.reloads,1);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(started,1);
  const freshPage = documentFixture();
  await bootstrapAuth({document:freshPage.doc,onAuthenticated:()=>started++});
  assert.equal(started,2);
  assert.equal(freshPage.nodes.dashboard.hidden,false);
});

test('direct EPG 401 and SSE session expiry share the same transition', async t => {
  const {doc,nodes} = documentFixture();
  let expired = 0, sessionChecks = 0;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/api/v1/auth/session') {
      sessionChecks++;
      return sessionChecks === 1 ? Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'epg-csrf'})
        : Response.json({authenticated:false,setup_pending:false},{status:401});
    }
    return new Response('private EPG',{status:401});
  });
  await bootstrapAuth({document:doc,onExpired:()=>expired++});
  await assert.rejects(fetchProtected('/api/v1/epg'),error => error.status === 401);
  assert.equal(expired,1);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(await verifyEventSession(),false);
  assert.equal(expired,1);
});

test('a parsed success cannot rehydrate the dashboard after a concurrent 401', async t => {
  const {doc} = documentFixture();
  let finishJSON;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/api/v1/auth/session') return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'race-csrf'});
    if (path === '/slow') return {status:200,ok:true,json:() => new Promise(resolve => {finishJSON = resolve;})};
    return Response.json({error:'authentication required'},{status:401});
  });
  await bootstrapAuth({document:doc});
  const pending = requestJSON('/slow');
  await flush();
  await assert.rejects(requestJSON('/expired'),error => error.status === 401);
  finishJSON({private:'stale'});
  await assert.rejects(pending,error => error.status === 401);
});

test('transient session-probe failure permits SSE retry without logging out', async t => {
  const {doc,nodes} = documentFixture();
  let checks = 0;
  t.mock.method(globalThis,'fetch',async () => {
    checks++;
    return checks === 1 ? Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'sse-csrf'})
      : Response.json({error:'temporarily unavailable'},{status:503});
  });
  await bootstrapAuth({document:doc});
  assert.equal(await verifyEventSession(),true);
  assert.equal(nodes.dashboard.hidden,false);
});

test('late 401 from an old session cannot evict a newer login', async t => {
  const {doc,nodes,location} = documentFixture();
  let oldReply;
  let loggedIn = false;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/old') return new Promise(resolve => {oldReply = resolve;});
    if (path === '/api/v1/auth/session') return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:loggedIn ? 'new-csrf' : 'old-csrf'});
    if (path === '/api/v1/auth/logout') return Response.json({authenticated:false});
    if (path === '/api/v1/auth/login') {loggedIn = true;return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'new-csrf'});}
    throw new Error(`unexpected ${path}`);
  });
  await bootstrapAuth({document:doc});
  const old = requestJSON('/old');
  await logout();
  const login = nodes.authLoginForm;
  login.elements.password.value = 'new password';
  login.listeners.submit({preventDefault(){},currentTarget:login});
  await flush();
  oldReply(Response.json({error:'expired'},{status:401}));
  await assert.rejects(old,error => error.status === 401);
  assert.equal(location.reloads,1);
  assert.equal(nodes.dashboard.hidden,true);
  const freshPage = documentFixture();
  await bootstrapAuth({document:freshPage.doc});
  assert.equal(csrfHeader(),'new-csrf');
  assert.equal(freshPage.nodes.dashboard.hidden,false);
});

test('late EventSource auth probe cannot expire a newer login', async t => {
  const {doc,nodes,location} = documentFixture();
  let inspectCount = 0, finishProbe;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/api/v1/auth/session') {
      inspectCount++;
      return inspectCount === 1 ? Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'old-csrf'})
        : inspectCount === 2 ? new Promise(resolve => {finishProbe = resolve;})
        : Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'new-csrf'});
    }
    if (path === '/api/v1/auth/logout') return Response.json({authenticated:false});
    if (path === '/api/v1/auth/login') return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'new-csrf'});
    throw new Error(`unexpected ${path}`);
  });
  await bootstrapAuth({document:doc});
  const probe = verifyEventSession();
  await logout();
  const login = nodes.authLoginForm;
  login.elements.password.value = 'new password';
  login.listeners.submit({preventDefault(){},currentTarget:login});
  await flush();
  finishProbe(Response.json({authenticated:false},{status:401}));
  assert.equal(await probe,false);
  assert.equal(location.reloads,1);
  assert.equal(nodes.dashboard.hidden,true);
  const freshPage = documentFixture();
  await bootstrapAuth({document:freshPage.doc});
  assert.equal(csrfHeader(),'new-csrf');
  assert.equal(freshPage.nodes.dashboard.hidden,false);
});

test('late password-change completion cannot sign out a newer session', async t => {
  const {doc,nodes,location} = documentFixture();
  let finishChange;
  let loggedIn = false;
  t.mock.method(globalThis,'fetch',async path => {
    if (path === '/api/v1/auth/session') return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:loggedIn ? 'new-csrf' : 'old-csrf'});
    if (path === '/api/v1/auth/password') return new Promise(resolve => {finishChange = resolve;});
    if (path === '/api/v1/auth/logout') return Response.json({authenticated:false});
    if (path === '/api/v1/auth/login') {loggedIn = true;return Response.json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'new-csrf'});}
    throw new Error(`unexpected ${path}`);
  });
  await bootstrapAuth({document:doc});
  const change = nodes.changePasswordForm;
  change.elements.old_password.value = 'old';
  change.elements.new_password.value = change.elements.confirm_password.value = 'new';
  change.listeners.submit({preventDefault(){},currentTarget:change});
  await logout();
  const login = nodes.authLoginForm;
  login.elements.password.value = 'new';
  login.listeners.submit({preventDefault(){},currentTarget:login});
  await flush();
  finishChange(Response.json({authenticated:false}));
  await flush();
  assert.equal(location.reloads,1);
  assert.equal(nodes.dashboard.hidden,true);
  const freshPage = documentFixture();
  await bootstrapAuth({document:freshPage.doc});
  assert.equal(csrfHeader(),'new-csrf');
  assert.equal(freshPage.nodes.dashboard.hidden,false);
});

test('cleanup failure cannot keep the protected dashboard visible after 401', async t => {
  const {doc,nodes} = documentFixture();
  t.mock.method(globalThis,'fetch',async path => Response.json(path === '/api/v1/auth/session'
    ? {authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'csrf'} : {error:'expired'},
    {status:path === '/api/v1/auth/session' ? 200 : 401}));
  await bootstrapAuth({document:doc,onExpired:()=>{throw new Error('cleanup failed');}});
  await assert.rejects(requestJSON('/api/v1/status'),error => error.status === 401);
  assert.equal(nodes.dashboard.hidden,true);
  assert.equal(nodes.authLoginForm.hidden,false);
});


test('an authenticated response without a named valid role never reveals management', async t => {
  const {doc,nodes} = documentFixture();
  t.mock.method(globalThis,'fetch', async () => Response.json({authenticated:true,csrf_token:'missing-principal'}));
  assert.equal(await bootstrapAuth({document:doc}),false);
  assert.equal(nodes.dashboard.hidden,true);
});
