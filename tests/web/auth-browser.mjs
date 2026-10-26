// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';

const {chromium} = createRequire(import.meta.url)(process.env.ASTRAX_PLAYWRIGHT_MODULE || 'playwright');
const root = new URL('../../web/', import.meta.url);

test('setup, login, logout, expiry and keyboard/mobile auth shell in real app composition', async () => {
  const browser = await chromium.launch({executablePath:process.env.ASTRAX_BROWSER_EXECUTABLE || undefined,headless:true});
  try {
    const context = await browser.newContext({serviceWorkers:'block'});
    const page = await context.newPage();
    await page.addInitScript(() => {
      window.__eventSources = [];
      window.EventSource = class {
        constructor(url) {this.url = url;this.listeners = new Map();window.__eventSources.push(this);}
        addEventListener(name,fn) {this.listeners.set(name,fn);}
        close() {this.closed = true;}
        triggerError() {this.onerror?.();this.listeners.get('error')?.();}
      };
    });
    const calls = [];
    let enrolled = false, authenticated = false, expired = false;
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.origin !== 'https://astrax.test') return route.abort();
      if (url.pathname === '/favicon.ico') return route.fulfill({status:204});
      if (request.method() === 'GET' && (url.pathname === '/' || /^\/[a-z0-9-]+\.(js|css)$/.test(url.pathname))) {
        const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
        const data = await readFile(new URL(name,root));
        return route.fulfill({status:200,contentType:name.endsWith('.html') ? 'text/html' : name.endsWith('.css') ? 'text/css' : 'text/javascript',body:data});
      }
      calls.push({path:url.pathname,method:request.method(),headers:request.headers(),body:request.postData()});
      const json = (body,status=200) => route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
      if (url.pathname === '/api/v1/auth/session') return authenticated && !expired
        ? json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'browser-csrf'})
        : json({authenticated:false,setup_pending:!enrolled},401);
      if (url.pathname === '/api/v1/auth/setup') {
        assert.deepEqual(request.postDataJSON(),{secret:'one-time-secret',password:'Long-Test-Password-2026!'});
        enrolled = authenticated = true;
        return json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'browser-csrf'});
      }
      if (url.pathname === '/api/v1/auth/login') {
        assert.equal(request.postDataJSON().password,'Long-Test-Password-2026!');
        assert.equal(request.postDataJSON().username,'admin');
        authenticated = true; expired = false;
        return json({authenticated:true,user:{username:'admin',role:'administrator',enabled:true},csrf_token:'browser-csrf'});
      }
      if (url.pathname === '/api/v1/auth/logout') {
        assert.equal(request.headers()['x-astrax-csrf'],'browser-csrf');
        authenticated = false;
        return json({authenticated:false});
      }
      if (expired || !authenticated) return json({error:'authentication required'},401);
      if (url.pathname === '/api/v1/status') return json({version:'fixture',uptime_seconds:1,control_endpoint:'127.0.0.1:8080',running_streams:0,enabled_streams:0,total_streams:0});
      if (url.pathname === '/api/v1/streams') return json({streams:[]});
      if (url.pathname === '/api/v1/adapters') return json({adapters:[]});
      if (url.pathname === '/api/v1/softcams') return json({softcams:[]});
      if (url.pathname === '/api/v1/settings') return json({control_listen:'127.0.0.1:8080'});
      if (url.pathname === '/api/v1/logs') return json({logs:[]});
      if (url.pathname === '/api/v1/certificates/status') return json({exists:false});
      if (url.pathname === '/api/v1/epg') return route.fulfill({status:200,contentType:'application/xml',body:'<tv />'});
      return json({});
    });
    await page.goto('https://astrax.test/');
    await page.waitForSelector('#authSetupForm:visible');
    assert.deepEqual(calls.map(call => call.path),['/api/v1/auth/session']);
    assert.equal(await page.locator('#dashboard').isVisible(),false);
    assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('name')),'secret');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    assert.equal(await page.locator('#authManagementAddress').textContent(),'https://astrax.test');
    await page.locator('#authSetupForm [name=secret]').fill('one-time-secret');
    await page.locator('#authSetupForm [name=password]').fill('Long-Test-Password-2026!');
    await page.locator('#authSetupForm [name=confirm_password]').fill('Long-Test-Password-2026!');
    await page.locator('#authSetupForm button[type=submit]').press('Enter');
    await page.waitForSelector('#dashboard:visible');
    assert.equal(await page.locator('#authSetupForm [name=secret]').inputValue(),'');
    assert.equal(await page.evaluate(() => JSON.stringify([localStorage,sessionStorage]).includes('one-time-secret') || JSON.stringify([localStorage,sessionStorage]).includes('browser-csrf')),false);
    await page.waitForFunction(() => document.getElementById('managementAddress').textContent.includes('127.0.0.1:8080'));
    await page.locator('#logoutButton').click();
    await page.waitForSelector('#authLoginForm:visible');
    assert.equal(await page.locator('#dashboard').isVisible(),false);
    await page.locator('#authLoginForm [name=username]').fill('admin');
    await page.locator('#authLoginForm [name=password]').fill('Long-Test-Password-2026!');
    await page.locator('#authLoginForm [name=password]').press('Enter');
    await page.waitForSelector('#dashboard:visible');
    await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/epg/status'),
      page.locator('#navTabs [data-tab=epg]').click(),
    ]);
    expired = true;
    await page.locator('#refreshEpgBtn').click();
    await page.waitForSelector('#authLoginForm:visible');
    assert.equal(await page.locator('#dashboard').isVisible(),false);
    await page.locator('#authLoginForm [name=username]').fill('admin');
    await page.locator('#authLoginForm [name=password]').fill('Long-Test-Password-2026!');
    await Promise.all([
      page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/epg/status'),
      page.locator('#authLoginForm [name=password]').press('Enter'),
    ]);
    await page.waitForSelector('#dashboard:visible');
    expired = true;
    const sourceCount = await page.evaluate(() => {const n = window.__eventSources.length;window.__eventSources.at(-1).triggerError();return n;});
    await page.waitForSelector('#authLoginForm:visible');
    await page.waitForTimeout(2200);
    assert.equal(await page.evaluate(() => window.__eventSources.length),sourceCount);
    await page.setViewportSize({width:375,height:750});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    assert.equal(await page.locator('#authLoginForm [name=password]').isVisible(),true);
    await context.close();
  } finally {await browser.close();}
});
