// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head']);
const pretty = value => JSON.stringify(value ?? null, null, 2);
const scopeNames = ['read', 'streams:control', 'admin'];

export function listAPIOperations(doc) {
  return Object.entries(doc.paths || {}).flatMap(([path, item]) => Object.entries(item)
    .filter(([method]) => methods.has(method)).map(([method, operation]) => ({method: method.toUpperCase(), path, operation})));
}

export function resolveAPIReference(doc, value, seen = new Set(), depth = 0) {
  if (!value || typeof value !== 'object' || depth > 12) return value;
  if (Array.isArray(value)) return value.map(v => resolveAPIReference(doc, v, seen, depth + 1));
  if (typeof value.$ref === 'string' && value.$ref.startsWith('#/') && !seen.has(value.$ref)) {
    const keys = value.$ref.slice(2).split('/').map(k => k.replace(/~1/g, '/').replace(/~0/g, '~'));
    const target = keys.reduce((v, k) => v && Object.hasOwn(v, k) ? v[k] : undefined, doc);
    if (target) return resolveAPIReference(doc, target, new Set([...seen, value.$ref]), depth + 1);
  }
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolveAPIReference(doc, v, seen, depth + 1)]));
}

export function buildAPIRequest(selected, values, bodyText) {
  if (!selected || !selected.path.startsWith('/api/v1/')) throw new Error('Use the OpenAPI download link for this operation.');
  let path = selected.path;
  const query = new URLSearchParams();
  for (const param of selected.operation.parameters || []) {
    const value = String(values[`${param.in}:${param.name}`] ?? '');
    if (param.required && !value) throw new Error(`Enter ${param.name}.`);
    if (param.in === 'path') path = path.replaceAll(`{${param.name}}`, encodeURIComponent(value));
    else if (param.in === 'query' && value !== '') query.append(param.name, value);
  }
  if (query.size) path += `?${query}`;
  let body;
  if (selected.method !== 'GET' && bodyText.trim()) {
    try { JSON.parse(bodyText); } catch { throw new Error('Enter valid JSON in the request body.'); }
    // Parse only for syntax validation; keep the original number lexemes.
    body = bodyText;
  }
  return {method: selected.method, path, ...(body === undefined ? {} : {bodyText:body})};
}

export function apiCurlSample(request) {
  const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
  return `curl --request ${request.method} --url "$ASTRAX_API_URL"${quote(request.path)} \\\n  --header "Authorization: Bearer $ASTRAX_API_TOKEN"${request.bodyText === undefined ? '' : ' \\\n  --header "Content-Type: application/json" --data-binary @request.json'}`;
}

export function isLoopbackAddress(address) {
  if (address === '::1') return true;
  const parts = address.split('.');
  return parts.length === 4 && parts[0] === '127' && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

export function createAPIManagementController({requestJSON, confirmAction, document: doc = globalThis.document, pollInterval = 10000}) {
  const ids = ['apiSettingsForm','apiSettingsFields','apiApply','apiListenerStatus','apiBaseURL','apiCheckedAt','apiStatusNotice','apiSettingsNotice','apiRefresh','apiTokensBody','apiTokensNotice','apiTokenNew','apiTokenCreateDialog','apiTokenCreateForm','apiTokenCreateNotice','apiTokenCreateSubmit','apiTokenCreateCancel','apiTokenSecretDialog','apiTokenSecret','apiTokenSecretTitle','apiTokenSecretClose','apiTokenCopy','apiTokenCopyNotice','apiDocsNotice','apiDocTag','apiDocSearch','apiDocOperation','apiOperationTitle','apiOperationPath','apiOperationScope','apiOperationDescription','apiDocParameters','apiDocRequest','apiDocResponses','apiCurl','apiTryForm','apiTryParameters','apiTryToken','apiTryBody','apiTrySubmit','apiTryNotice','apiTryResult','apiTryResultTitle','apiTryResponse'];
  const el = Object.fromEntries(ids.map(id => [id, doc.getElementById(id)]));
  let active = false, epoch = 0, timer, reads, settingsReady = false, dirty = false;
  let stateSequence = 0, tokenSequence = 0, stateReading = null, tokenReading = null;
  let definition, operations = [], selected, tokenDialogSession = 0;
  const pending = new Set();
  const current = owner => active && epoch === owner;
  const field = name => el.apiSettingsForm.elements.namedItem(name);
  const notice = (target, message = '', error = false) => {
    target.textContent = message; target.hidden = !message;
    target.className = `notice ${error ? 'err' : 'ok'}`; target.setAttribute('role', error ? 'alert' : 'status');
  };
  const message = error => error?.message || 'Request failed. Refresh to inspect current state before retrying.';
  const node = (tag, text) => { const n = doc.createElement(tag); n.textContent = text; return n; };
  function controls() {
    el.apiApply.disabled = !settingsReady || pending.has('settings');
    el.apiSettingsFields.disabled = !settingsReady || pending.has('settings');
    el.apiTokenNew.disabled = pending.has('create');
    el.apiTokenCreateSubmit.disabled = pending.has('create');
    const trying = pending.has('try');
    el.apiTrySubmit.disabled = trying || !selected?.path.startsWith('/api/v1/');
    for (const input of [el.apiDocOperation, el.apiDocTag, el.apiDocSearch, el.apiTryToken, ...el.apiTryParameters.querySelectorAll('input')]) input.disabled = trying;
    el.apiTryBody.disabled = trying || !selected || selected.method === 'GET';
  }
  function showState(value, hydrate = false) {
    if (!value?.settings || typeof value.status?.running !== 'boolean' || typeof value.status?.enabled !== 'boolean') throw new Error('Listener status response is incomplete.');
    const {settings, status} = value;
    el.apiListenerStatus.textContent = status.running ? 'Running' : status.enabled ? 'Enabled / stopped' : 'Disabled';
    el.apiBaseURL.textContent = status.running && status.base_url ? status.base_url : 'Not running';
    el.apiCheckedAt.textContent = new Date().toLocaleTimeString();
    notice(el.apiStatusNotice, status.last_error || '', !!status.last_error);
    if (hydrate && !dirty && !pending.has('settings')) {
      field('enabled').checked = !!settings.enabled; field('listen_address').value = settings.listen_address;
      field('port').value = settings.port; field('tls').checked = !!settings.tls;
      field('allowed_origins').value = (settings.allowed_origins || []).join('\n');
    }
    settingsReady = true; controls();
  }
  async function loadState(owner = epoch) {
    if (!current(owner) || stateReading === owner) return;
    stateReading = owner; const sequence = ++stateSequence;
    try {
      const value = await requestJSON('/api/v1/api/status', {signal: reads.signal});
      if (current(owner) && sequence === stateSequence) showState(value, true);
    } catch (error) {
      if (current(owner) && sequence === stateSequence) {
        el.apiListenerStatus.textContent = 'Status unavailable'; el.apiBaseURL.textContent = 'Not verified';
        notice(el.apiStatusNotice, message(error), true);
      }
    } finally { if (stateReading === owner) stateReading = null; }
  }
  const date = value => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : 'Never';
  function renderTokens(tokens) {
    if (!Array.isArray(tokens)) throw new Error('Token list response is incomplete.');
    const focusedID = el.apiTokensBody.contains(doc.activeElement) ? doc.activeElement.dataset.tokenId : undefined;
    let restoreFocus;
    el.apiTokensBody.replaceChildren();
    if (!tokens.length) {
      const row = node('tr',''), cell = node('td','No tokens yet. Create a scoped token to enable integrations.'); cell.colSpan = 4; row.append(cell); el.apiTokensBody.append(row);
    }
    for (const token of tokens) {
      const row = node('tr',''), identity = node('td',token.name), scopes = node('td',(token.scopes || []).join(', ')), dates = node('td',date(token.created_at)), action = node('td',token.revoked_at ? `Revoked ${date(token.revoked_at)}` : 'Active');
      identity.append(node('code',token.prefix)); dates.append(node('small',`Last used: ${date(token.last_used_at)}`));
      if (!token.revoked_at) {
        const button = node('button','Revoke'); button.type = 'button'; button.className = 'secondary'; button.disabled = pending.has(`revoke:${token.id}`);
        button.dataset.tokenId = token.id;
        if (token.id === focusedID && !button.disabled) restoreFocus = button;
        button.setAttribute('aria-label', `Revoke ${token.name}`); button.addEventListener('click', () => revoke(token, button)); action.append(button);
      }
      row.append(identity,scopes,dates,action); el.apiTokensBody.append(row);
    }
    if (focusedID !== undefined) (restoreFocus || el.apiTokenNew).focus({preventScroll:true});
  }
  async function loadTokens(owner = epoch) {
    if (!current(owner) || tokenReading === owner) return;
    tokenReading = owner; const sequence = ++tokenSequence;
    try {
      const value = await requestJSON('/api/v1/api/tokens', {signal: reads.signal});
      if (current(owner) && sequence === tokenSequence) renderTokens(value.tokens);
    } catch (error) { if (current(owner) && sequence === tokenSequence) notice(el.apiTokensNotice,message(error),true); }
    finally { if (tokenReading === owner) tokenReading = null; }
  }
  const mutate = (path, method, body, options = {}) => requestJSON(path, {...options, method, headers: {'X-AstraX-Request':'1'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
  el.apiSettingsForm.addEventListener('input', () => {dirty = true;});
  el.apiSettingsForm.addEventListener('submit', async event => {
    event.preventDefault(); if (!active || pending.has('settings') || !settingsReady) return;
    const owner = epoch;
    const settings = {enabled:field('enabled').checked, listen_address:field('listen_address').value.trim(), port:Number(field('port').value), tls:field('tls').checked, allowed_origins:field('allowed_origins').value.split('\n').map(v=>v.trim()).filter(Boolean)};
    pending.add('settings'); ++stateSequence; controls();
    try {
      if (settings.enabled && !settings.tls && !isLoopbackAddress(settings.listen_address)) {
        if (!await confirmAction(`Enable unencrypted external API on ${settings.listen_address}:${settings.port}? Bearer tokens travel in plaintext. Use TLS or a trusted protected network.`) || !current(owner)) return;
      }
      notice(el.apiSettingsNotice,'Applying listener settings...');
      const value = await mutate('/api/v1/api/settings','PUT',settings);
      if (current(owner)) {
        showState(value); dirty = false;
        notice(el.apiSettingsNotice,`Settings saved. External listener ${value.status.running ? 'running' : value.status.enabled ? 'enabled but stopped' : 'disabled'}.`);
      } else notice(el.apiSettingsNotice,'Listener settings changed while away. Refresh status before another change.');
    } catch (error) {
      if (current(owner)) {
        if (error.body?.status && error.body?.settings) showState(error.body);
        notice(el.apiSettingsNotice,`${message(error)} Your draft is retained; inspect status before retrying.`,true);
      }
    } finally { pending.delete('settings'); ++stateSequence; controls(); }
  });
  async function revoke(token, button) {
    const owner = epoch, key = `revoke:${token.id}`;
    if (!active || pending.has(key)) return;
    pending.add(key); button.disabled = true; ++tokenSequence;
    try {
      if (!await confirmAction(`Revoke token "${token.name}"? Integrations using it will immediately lose access.`) || !current(owner)) return;
      await mutate(`/api/v1/api/tokens/${encodeURIComponent(token.id)}/revoke`,'POST');
      if (current(owner)) notice(el.apiTokensNotice,`Token "${token.name}" revoked.`);
    } catch(error) { if(current(owner)) notice(el.apiTokensNotice,message(error),true); }
    finally { pending.delete(key); button.disabled = false; tokenReading = null; if(current(owner)) await loadTokens(owner); }
  }
  el.apiTokenNew.addEventListener('click', () => {
    if (!active || pending.has('create')) return;
    ++tokenDialogSession; el.apiTokenCreateForm.reset(); notice(el.apiTokenCreateNotice); el.apiTokenCreateDialog.showModal();
  });
  el.apiTokenCreateCancel.addEventListener('click', () => el.apiTokenCreateDialog.close());
  el.apiTokenCreateDialog.addEventListener('close', () => {++tokenDialogSession; el.apiTokenCreateForm.reset();});
  const clearSecret = () => {el.apiTokenSecret.value = ''; notice(el.apiTokenCopyNotice);};
  el.apiTokenSecretDialog.addEventListener('close', clearSecret);
  el.apiTokenSecretDialog.addEventListener('cancel', clearSecret);
  el.apiTokenSecretClose.addEventListener('click', () => {clearSecret(); el.apiTokenSecretDialog.close();});
  el.apiTokenCopy.addEventListener('click', async () => {
    const owner = epoch, secret = el.apiTokenSecret.value;
    try {
      if (!secret) return;
      await globalThis.navigator.clipboard.writeText(secret);
      if(current(owner) && el.apiTokenSecretDialog.open && el.apiTokenSecret.value === secret) notice(el.apiTokenCopyNotice,'Copied. Store the token securely.');
    } catch { if(current(owner) && el.apiTokenSecretDialog.open) notice(el.apiTokenCopyNotice,'Copy unavailable. Select and copy the token manually before closing.',true); }
  });
  el.apiTokenCreateForm.addEventListener('submit', async event => {
    event.preventDefault(); if (!active || pending.has('create')) return;
    const owner = epoch, session = tokenDialogSession;
    const name = el.apiTokenCreateForm.elements.namedItem('name').value.trim();
    const scopes = Array.from(el.apiTokenCreateForm.querySelectorAll('[name=scope]:checked'), input=>input.value).filter(v=>scopeNames.includes(v));
    if (!name || !scopes.length) {notice(el.apiTokenCreateNotice,'Enter a name and select at least one scope.',true); return;}
    pending.add('create'); ++tokenSequence; controls(); notice(el.apiTokenCreateNotice,'Creating token...');
    try {
      const value = await mutate('/api/v1/api/tokens','POST',{name,scopes});
      if (current(owner) && session === tokenDialogSession && el.apiTokenCreateDialog.open) {
        el.apiTokenCreateDialog.close(); clearSecret();
        if (typeof value.plaintext !== 'string' || !value.plaintext.startsWith('ax_')) throw new Error('Token created but its one-time value is unavailable. Revoke it and create a new token.');
        el.apiTokenSecret.value = value.plaintext; el.apiTokenSecretDialog.showModal(); el.apiTokenSecretTitle.focus();
        notice(el.apiTokensNotice,'Token created. Its plaintext is shown only in the one-time dialog.');
      } else notice(el.apiTokensNotice,'Token created after the dialog closed. Its plaintext was discarded; revoke it and create a replacement.',true);
    } catch(error) {
      if(current(owner)) notice(el.apiTokenCreateDialog.open ? el.apiTokenCreateNotice : el.apiTokensNotice,message(error),true);
    } finally {pending.delete('create');controls();tokenReading = null;if(current(owner)) await loadTokens(owner);}
  });
  function parameterValues() {
    return Object.fromEntries(Array.from(el.apiTryParameters.querySelectorAll('[data-parameter]'), input=>[input.dataset.parameter,input.value]));
  }
  function updateCurl() {
    try {el.apiCurl.textContent = apiCurlSample(buildAPIRequest(selected,parameterValues(),el.apiTryBody.value));}
    catch {el.apiCurl.textContent = selected ? apiCurlSample({method:selected.method,path:selected.path}) : '';}
  }
  function selectOperation() {
    selected = operations.find(item=>item.operation.operationId === el.apiDocOperation.value);
    el.apiTryParameters.replaceChildren(); el.apiTryResult.hidden = true; el.apiTryResponse.textContent = ''; notice(el.apiTryNotice);
    if (!selected) {
      el.apiOperationTitle.textContent = 'No matching operation';
      for (const target of [el.apiOperationPath,el.apiOperationScope,el.apiOperationDescription,el.apiDocParameters,el.apiDocRequest,el.apiDocResponses,el.apiCurl]) target.textContent = '';
      el.apiTryBody.value = '';controls();return;
    }
    const {method,path,operation} = selected;
    el.apiOperationTitle.textContent = operation.summary || operation.operationId;
    el.apiOperationPath.textContent = `${method} ${path}`;
    el.apiOperationScope.textContent = `Required scope: ${operation['x-required-scope'] || 'See documentation'}`;
    el.apiOperationDescription.textContent = operation.description || '';
    el.apiDocParameters.textContent = pretty(resolveAPIReference(definition,operation.parameters || []));
    el.apiDocRequest.textContent = pretty(resolveAPIReference(definition,operation.requestBody || {description:'No JSON body required.'}));
    el.apiDocResponses.textContent = pretty(resolveAPIReference(definition,operation.responses));
    for(const param of operation.parameters || []) {
      if (!['path','query'].includes(param.in)) continue;
      const label = node('label',`${param.name} (${param.in}${param.required ? ', required' : ', optional'})`), input = doc.createElement('input');
      input.dataset.parameter = `${param.in}:${param.name}`; input.required = !!param.required;
      input.placeholder = param.schema?.enum ? param.schema.enum.join(', ') : param.schema?.default !== undefined ? `Default: ${param.schema.default}` : '';
      input.addEventListener('input',updateCurl); label.append(input); el.apiTryParameters.append(label);
    }
    el.apiTryBody.disabled = method === 'GET';
    el.apiTryBody.value = method === 'GET' ? '' : pretty(operation.requestBody?.content?.['application/json']?.example || {});
    controls(); updateCurl();
  }
  function filterOperations() {
    const previous = selected?.operation.operationId, q = el.apiDocSearch.value.toLowerCase(), tag = el.apiDocTag.value;
    const visible = operations.filter(item=>(!tag || item.operation.tags?.includes(tag)) && `${item.method} ${item.path} ${item.operation.summary || ''}`.toLowerCase().includes(q));
    el.apiDocOperation.replaceChildren(...visible.map(item=>{const option = node('option',`${item.method} ${item.path}`);option.value = item.operation.operationId;return option;}));
    if(visible.some(item=>item.operation.operationId === previous)) el.apiDocOperation.value = previous;
    else if(visible.length) el.apiDocOperation.selectedIndex = 0;
    selectOperation();
  }
  async function loadDocs(owner = epoch) {
    if (definition) {filterOperations();return;}
    try {
      const value = await requestJSON('/api/v1/api/openapi.json',{signal:reads.signal});
      if(!current(owner)) return;
      if(value.openapi !== '3.1.0' || !value.paths || !listAPIOperations(value).length) throw new Error('OpenAPI documentation is unavailable.');
      definition = value; operations = listAPIOperations(value);
      el.apiDocTag.replaceChildren(node('option','All groups'));el.apiDocTag.firstChild.value = '';
      for(const tag of [...new Set(operations.flatMap(item=>item.operation.tags || []))]) {const option = node('option',tag);option.value = tag;el.apiDocTag.append(option);}
      notice(el.apiDocsNotice);filterOperations();
    } catch(error) {if(current(owner)) notice(el.apiDocsNotice,message(error),true);}
  }
  el.apiDocTag.addEventListener('change',filterOperations); el.apiDocSearch.addEventListener('input',filterOperations); el.apiDocOperation.addEventListener('change',selectOperation);el.apiTryBody.addEventListener('input',updateCurl);
  el.apiTryForm.addEventListener('submit', async event => {
    event.preventDefault();if(!active || pending.has('try')) return;
    const owner = epoch; let request, payload;
    try {request = {...buildAPIRequest(selected,parameterValues(),el.apiTryBody.value),token:el.apiTryToken.value};}
    catch(error) {notice(el.apiTryNotice,message(error),true);return;}
    const envelope = JSON.stringify({method:request.method,path:request.path,token:request.token});
    // Only the syntax-validated body is spliced in; metadata remains JSON-escaped.
    payload = request.bodyText === undefined ? envelope : envelope.slice(0,-1)+',"body":'+request.bodyText+'}';
    if(new TextEncoder().encode(payload).length > 1048576) {notice(el.apiTryNotice,'Request exceeds the 1 MiB limit.',true);return;}
    pending.add('try');controls();el.apiTryResult.hidden = true;
    try {
      if(request.method !== 'GET' && (!await confirmAction(`Execute ${request.method} ${request.path}? This is not a dry run and may change configuration or running streams.`) || !current(owner))) return;
      notice(el.apiTryNotice,'Running request...');
      const {body:response, text} = await requestJSON('/api/v1/api/try',{method:'POST',headers:{'X-AstraX-Request':'1'},body:payload,includeResponseText:true});
      if(current(owner)) {
        if(!Number.isInteger(response.status)) throw new Error('Try response is incomplete.');
        el.apiTryResultTitle.textContent = `Response: HTTP ${response.status}`; el.apiTryResponse.textContent = text;el.apiTryResult.hidden = false;
        notice(el.apiTryNotice,`External handler returned HTTP ${response.status}.`,response.status >= 400);
      }
    } catch(error) {if(current(owner)) notice(el.apiTryNotice,`${message(error)} A mutation may have completed; inspect state before retrying.`,true);}
    finally {request.token = '';payload = '';pending.delete('try');controls();}
  });
  el.apiRefresh.addEventListener('click', () => {if(active) {loadState();loadTokens();if(!definition) loadDocs();}});
  return {
    activate() {
      active = true; ++epoch;reads?.abort();reads = new AbortController();stateReading = tokenReading = null;
      controls();loadState();loadTokens();loadDocs();
      clearInterval(timer);timer = setInterval(()=>{loadState();loadTokens();},pollInterval);
    },
    deactivate() {
      active = false;++epoch;reads?.abort();clearInterval(timer);stateReading = tokenReading = null;
      el.apiTryToken.value = '';el.apiTryBody.value = '';el.apiTryResponse.textContent = '';el.apiTryResult.hidden = true;el.apiCurl.textContent = '';
      clearSecret();++tokenDialogSession;
      for(const dialog of [el.apiTokenCreateDialog,el.apiTokenSecretDialog]) if(dialog.open) dialog.close();
    },
  };
}
