// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';

const {chromium} = createRequire(import.meta.url)(process.env.ASTRAX_PLAYWRIGHT_MODULE || 'playwright');
const root = new URL('../../web/', import.meta.url);
const timestamp = '2026-10-24T20:00:00Z';

test('real app composition gates navigation, controls and account management by role', async () => {
  const browser = await chromium.launch({executablePath:process.env.ASTRAX_BROWSER_EXECUTABLE || undefined,headless:true});
  try {
    for (const role of ['administrator','operator','viewer']) {
      const context = await browser.newContext({serviceWorkers:'block',viewport:{width:1280,height:900}});
      const page = await context.newPage();
      const errors = [], calls = [];
      page.on('pageerror',error => errors.push(error.message));
      await page.addInitScript(() => {window.EventSource = class {addEventListener() {} close() {}};});
      let authenticated = false;
      let accounts = [{username:'admin',role:'administrator',enabled:true}];
      await context.route('**/*',async route => {
        const request = route.request(), url = new URL(request.url()), method = request.method();
        if (url.origin !== 'https://astrax.test') return route.abort();
        if (url.pathname === '/favicon.ico') return route.fulfill({status:204});
        if (method === 'GET' && (url.pathname === '/' || /^\/[a-z0-9-]+\.(js|css)$/.test(url.pathname))) {
          return route.fulfill({status:200,contentType:url.pathname.endsWith('.css')?'text/css':url.pathname.endsWith('.js')?'text/javascript':'text/html',body:await readFile(new URL(url.pathname === '/'?'index.html':url.pathname.slice(1),root))});
        }
        calls.push({path:url.pathname,method});
        const json = (body,status=200) => route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
        const session = () => ({authenticated:true,csrf_token:'account-browser-csrf',user:{username:role === 'administrator'?'admin':role,role,enabled:true}});
        if (url.pathname === '/api/v1/auth/session') return authenticated?json(session()):json({authenticated:false,setup_pending:false},401);
        if (url.pathname === '/api/v1/auth/login') {
          assert.equal(request.postDataJSON().username,role === 'administrator'?'admin':role);
          authenticated=true; return json(session());
        }
        if (!authenticated) return json({error:'authentication required'},401);
        if (method !== 'GET') assert.equal(request.headers()['x-astrax-csrf'],'account-browser-csrf');
        if (url.pathname === '/api/v1/users') {
          assert.equal(role,'administrator');
          if (method === 'POST') {const input=request.postDataJSON();assert.equal(input.role,'viewer');assert.equal(input.username,'qa-viewer');accounts.push({username:input.username,role:input.role,enabled:true});return json(accounts.at(-1),201);}
          return json({users:accounts});
        }
        if (url.pathname === '/api/v1/status') return json({version:'fixture',uptime_seconds:1,total_streams:0,enabled_streams:0,running_streams:0});
        if (url.pathname === '/api/v1/streams') return json({streams:[]});
        if (url.pathname === '/api/v1/adapters') return json({adapters:[]});
        if (url.pathname === '/api/v1/dvb-cards') return json({items:[],total:0,page:1,limit:100,summary:{total:0,available:0,active:0,busy_external:0,error:0,offline:0,disabled:0},refreshed_at:timestamp,refresh_error:'',stale:false,facets:{models:[],delivery_systems:[]}});
        if (url.pathname === '/api/v1/dvb-streams') return json({items:[],total:0,page:1,limit:100,facets:{groups:{},statuses:{},requested_adapters:{},actual_adapters:{},delivery_systems:{},protocols:{}}});
        if (url.pathname === '/api/v1/dvb-groups') return json({groups:[],counts:{all:0,ungrouped:0}});
        if (role !== 'administrator') {errors.push(`unexpected private endpoint: ${method} ${url.pathname}`);return json({error:'forbidden'},403);}
        if (url.pathname === '/api/v1/settings') return json({control_listen:'127.0.0.1:8080'});
        if (url.pathname === '/api/v1/softcams') return json({softcams:[]});
        if (url.pathname === '/api/v1/logs') return json({logs:[]});
        if (url.pathname === '/api/v1/certificates/status') return json({exists:false});
        return json({});
      });
      await page.goto('https://astrax.test/');
      await page.locator('#authLoginForm:visible').waitFor();
      await page.locator('#authLoginForm [name=username]').fill(role === 'administrator'?'admin':role);
      await page.locator('#authLoginForm [name=password]').fill('Synthetic-Passphrase_2026!');
      await page.locator('#authLoginForm button[type=submit]').click();
      await page.locator('#dashboard:visible').waitFor();
      assert.match(await page.locator('#currentUserLabel').textContent(),new RegExp(role,'i'));
      assert.equal(await page.locator('#navTabs [data-tab=users]').isVisible(),role === 'administrator');
      await page.locator('#navTabs [data-tab=streams]').click();
      assert.equal(await page.locator('#addStreamBtn').isVisible(),role === 'administrator');
      await Promise.all([page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/dvb-streams'),page.locator('#navTabs [data-tab=dvb-streams]').click()]);
      assert.equal(await page.locator('#addDVBStreamBtn').isVisible(),role === 'administrator');
      if (role === 'administrator') {
        await page.locator('#navTabs [data-tab=users]').click();
        await page.locator('[data-users=create]:enabled').waitFor();
        await page.locator('[data-users=create]').click();
        await page.locator('[data-users=dialog][open]').waitFor();
        await page.locator('[data-users=username]').fill('qa-viewer');
        assert.equal(await page.locator('[data-users=role]').inputValue(),'viewer');
        await page.locator('[data-users=password]').fill('Synthetic-Passphrase_2026!');
        await page.locator('[data-users=password-confirm]').fill('Synthetic-Passphrase_2026!');
        await page.locator('[data-users=form] button[type=submit]').click();
        await page.locator('[data-users=list]').getByText('qa-viewer',{exact:true}).waitFor();
        assert.equal(accounts.length,2);
        await page.setViewportSize({width:390,height:844});
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true);
      } else {
        assert.equal(await page.locator('#openDVBScanBtn').isVisible(),false);
        assert.equal(await page.locator('#addDVBGroupBtn').isVisible(),false);
        await page.goto('https://astrax.test/#settings');
        await page.locator('#dashboard:visible').waitFor();
        await page.waitForURL('https://astrax.test/#overview');
        assert.equal(await page.locator('[data-panel=settings]').isVisible(),false);
      }
      if (await page.locator('#menuToggle').isVisible()) await page.locator('#menuToggle').click();
      await page.locator('#navTabs [data-tab=account]').click();
      assert.equal(await page.locator('#changePasswordForm').isVisible(),true);
      assert.equal(await page.locator('#accountRole').textContent(),role[0].toUpperCase()+role.slice(1));
      assert.deepEqual(errors,[]);
      await context.close();
    }
  } finally {await browser.close();}
});
