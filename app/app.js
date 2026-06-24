/**
 * GameAnalytics JS SDK — Test App
 * All SDK functions exercised through a visual dashboard.
 */

'use strict';

// ─── Log interception ──────────────────────────────────────────────────────

const originalConsole = {
  log:   console.log.bind(console),
  warn:  console.warn.bind(console),
  error: console.error.bind(console),
  debug: console.debug.bind(console),
};

let logLineCount = 0;

function classifyGALog(msg) {
  if (msg.includes('Debug/')) return 'log-debug';
  if (msg.includes('Info/'))  return 'log-info';
  if (msg.includes('Warning/') || msg.includes('WARN')) return 'log-warn';
  if (msg.includes('Error/') || msg.includes('ERROR')) return 'log-error';
  return 'log-verbose';
}

function addLogLine(text, cssClass) {
  const showVerbose = document.getElementById('log-verbose').checked;
  if (!showVerbose && cssClass === 'log-verbose') return;

  const el = document.getElementById('log');
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-ts">${ts}</span><span class="${cssClass}">${escapeHtml(text)}</span>`;
  el.appendChild(line);

  logLineCount++;
  document.getElementById('log-count').textContent = logLineCount + ' lines';

  if (document.getElementById('log-autoscroll').checked) {
    el.scrollTop = el.scrollHeight;
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Override console methods to capture SDK log output
['log', 'warn', 'error', 'debug'].forEach(method => {
  console[method] = (...args) => {
    originalConsole[method](...args);
    const msg = args.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
    let cls = 'log-verbose';
    if (method === 'warn')  cls = 'log-warn';
    if (method === 'error') cls = 'log-error';
    if (method === 'debug') cls = classifyGALog(msg);
    if (method === 'log')   cls = classifyGALog(msg);
    addLogLine(msg, cls);
  };
});

function clearLog() {
  document.getElementById('log').innerHTML = '';
  logLineCount = 0;
  document.getElementById('log-count').textContent = '0 lines';
}

// ─── App log helper ────────────────────────────────────────────────────────

function appLog(msg, type = 'info') {
  const cls = type === 'sent' ? 'log-sent' : type === 'warn' ? 'log-warn' : 'log-info';
  addLogLine('▸ ' + msg, cls);
}

// ─── Navigation ────────────────────────────────────────────────────────────

function showPanel(btn) {
  document.querySelectorAll('#nav button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + btn.dataset.panel).classList.add('active');
}

// ─── Status badge ──────────────────────────────────────────────────────────

function setStatus(state) {
  const badge = document.getElementById('status-badge');
  if (state === 'ok') {
    badge.textContent = '⬤ Initialized';
    badge.className = 'badge badge-ok';
  } else if (state === 'err') {
    badge.textContent = '⬤ Error';
    badge.className = 'badge badge-err';
  } else {
    badge.textContent = '⬤ Not initialized';
    badge.className = 'badge badge-err';
  }
}

// ─── SDK helpers ───────────────────────────────────────────────────────────

/** Thin wrapper so we can log every GA call */
function GA(method, ...args) {
  appLog(`GameAnalytics("${method}", ${args.map(a => JSON.stringify(a)).join(', ')})`, 'sent');
  GameAnalytics(method, ...args);
}

function parseFields(fieldStr) {
  try {
    const parsed = JSON.parse(fieldStr || '{}');
    return typeof parsed === 'object' && parsed !== null ? parsed : {};
  } catch (e) {
    appLog('Invalid JSON for custom fields — using {}', 'warn');
    return {};
  }
}

function csvToArray(val) {
  return val.split(',').map(s => s.trim()).filter(Boolean);
}

// ─── Initialize ────────────────────────────────────────────────────────────

function doInitialize() {
  const key    = document.getElementById('game-key').value.trim();
  const secret = document.getElementById('secret-key').value.trim();
  if (!key || !secret) {
    appLog('Game key and secret key are required', 'warn');
    return;
  }
  appLog(`Calling initialize("${key}", "***")`, 'sent');
  GameAnalytics('initialize', key, secret);

  // Optimistically flip the badge; the SDK will log if it actually fails
  setTimeout(() => setStatus('ok'), 800);
}

function doStop()   { GA('onStop'); setStatus(''); }
function doResume() { GA('onResume'); }

// ─── Pre-Init Config ───────────────────────────────────────────────────────

function applyIdentityConfig() {
  const build   = document.getElementById('cfg-build').value.trim();
  const userId  = document.getElementById('cfg-userid').value.trim();
  const extUser = document.getElementById('cfg-extuser').value.trim();
  const engine  = document.getElementById('cfg-engine').value.trim();

  if (build)   GA('configureBuild', build);
  if (userId)  GA('configureUserId', userId);
  if (extUser) GA('configureExternalUserId', extUser);
  if (engine)  GA('configureGameEngineVersion', engine);
}

function applyDimensionConfig() {
  GA('configureAvailableCustomDimensions01', csvToArray(document.getElementById('cfg-dim01').value));
  GA('configureAvailableCustomDimensions02', csvToArray(document.getElementById('cfg-dim02').value));
  GA('configureAvailableCustomDimensions03', csvToArray(document.getElementById('cfg-dim03').value));
}

function applyResourceConfig() {
  GA('configureAvailableResourceCurrencies', csvToArray(document.getElementById('cfg-currencies').value));
  GA('configureAvailableResourceItemTypes',  csvToArray(document.getElementById('cfg-itemtypes').value));
}

function applyAdvancedConfig() {
  const endpoint = document.getElementById('cfg-endpoint').value.trim();
  const interval = parseInt(document.getElementById('cfg-interval').value, 10);
  if (endpoint) GA('configureCustomEndpoint', endpoint);
  if (!isNaN(interval) && interval > 0) GA('setEventProcessInterval', interval);
}

// ─── Business ──────────────────────────────────────────────────────────────

function sendBusiness() {
  const currency = document.getElementById('biz-currency').value.trim();
  const amount   = parseInt(document.getElementById('biz-amount').value, 10);
  const itemType = document.getElementById('biz-itemtype').value.trim();
  const itemId   = document.getElementById('biz-itemid').value.trim();
  const cart     = document.getElementById('biz-cart').value.trim();
  const fields   = parseFields(document.getElementById('biz-fields').value);
  GA('addBusinessEvent', currency, amount, itemType, itemId, cart, fields);
}

// ─── Resource ──────────────────────────────────────────────────────────────

function sendResource() {
  const flow     = parseInt(document.getElementById('res-flow').value, 10);
  const currency = document.getElementById('res-currency').value.trim();
  const amount   = parseFloat(document.getElementById('res-amount').value);
  const itemType = document.getElementById('res-itemtype').value.trim();
  const itemId   = document.getElementById('res-itemid').value.trim();
  const fields   = parseFields(document.getElementById('res-fields').value);
  GA('addResourceEvent', flow, currency, amount, itemType, itemId, fields);
}

// ─── Progression ───────────────────────────────────────────────────────────

function buildProgressionArgs(statusOverride) {
  const status = parseInt(statusOverride || document.getElementById('prog-status').value, 10);
  const p01    = document.getElementById('prog-01').value.trim();
  const p02    = document.getElementById('prog-02').value.trim();
  const p03    = document.getElementById('prog-03').value.trim();
  const scoreStr = document.getElementById('prog-score').value.trim();
  const score  = scoreStr !== '' ? parseFloat(scoreStr) : undefined;
  const fields = parseFields(document.getElementById('prog-fields').value);
  return { status, p01, p02, p03, score, fields };
}

function sendProgression(statusOverride) {
  const { status, p01, p02, p03, score, fields } = buildProgressionArgs(statusOverride);
  if (score !== undefined) {
    GA('addProgressionEvent', status, p01, p02 || undefined, p03 || undefined, score, fields);
  } else {
    GA('addProgressionEvent', status, p01, p02 || undefined, p03 || undefined, undefined, fields);
  }
}

function sendProgressionCustom() { sendProgression(null); }

// ─── Design ────────────────────────────────────────────────────────────────

function sendDesign() {
  const eventId = document.getElementById('des-id').value.trim();
  const valStr  = document.getElementById('des-value').value.trim();
  const value   = valStr !== '' ? parseFloat(valStr) : undefined;
  const fields  = parseFields(document.getElementById('des-fields').value);
  if (value !== undefined) {
    GA('addDesignEvent', eventId, value, fields);
  } else {
    GA('addDesignEvent', eventId, undefined, fields);
  }
}

// ─── Error ─────────────────────────────────────────────────────────────────

function sendError() {
  const severity = parseInt(document.getElementById('err-severity').value, 10);
  const message  = document.getElementById('err-message').value;
  const fields   = parseFields(document.getElementById('err-fields').value);
  GA('addErrorEvent', severity, message, fields);
}

// ─── Ad ────────────────────────────────────────────────────────────────────

function sendAd() {
  const action    = parseInt(document.getElementById('ad-action').value, 10);
  const type      = parseInt(document.getElementById('ad-type').value, 10);
  const sdkName   = document.getElementById('ad-sdk').value.trim();
  const placement = document.getElementById('ad-placement').value.trim();
  GA('addAdEvent', action, type, sdkName, placement);
}

function sendAdWithDuration() {
  const action    = parseInt(document.getElementById('ad-action').value, 10);
  const type      = parseInt(document.getElementById('ad-type').value, 10);
  const sdkName   = document.getElementById('ad-sdk').value.trim();
  const placement = document.getElementById('ad-placement').value.trim();
  appLog(`GameAnalytics("addAdEventWithDuration", ${action}, ${type}, "${sdkName}", "${placement}", 5000)`, 'sent');
  gameanalytics.GameAnalytics.addAdEventWithDuration(action, type, sdkName, placement, 5000);
}

function sendAdFailed() {
  const type      = parseInt(document.getElementById('ad-type').value, 10);
  const sdkName   = document.getElementById('ad-sdk').value.trim();
  const placement = document.getElementById('ad-placement').value.trim();
  // EGAAdAction.FailedShow = 3, EGAAdError.NoFill = 3
  appLog(`GameAnalytics("addAdEventWithNoAdReason", FailedShow, ${type}, "${sdkName}", "${placement}", NoFill)`, 'sent');
  gameanalytics.GameAnalytics.addAdEventWithNoAdReason(3, type, sdkName, placement, 3);
}

// ─── Dimensions ────────────────────────────────────────────────────────────

function setDimensions() {
  const d1 = document.getElementById('dim01-val').value;
  const d2 = document.getElementById('dim02-val').value;
  const d3 = document.getElementById('dim03-val').value;
  if (d1) GA('setCustomDimension01', d1);
  if (d2) GA('setCustomDimension02', d2);
  if (d3) GA('setCustomDimension03', d3);
}

function setGlobalFields() {
  const fields = parseFields(document.getElementById('global-fields').value);
  GA('setGlobalCustomEventFields', fields);
}

// ─── Remote Configs ────────────────────────────────────────────────────────

const rcListener = {
  onRemoteConfigsUpdated: function () {
    appLog('onRemoteConfigsUpdated fired!', 'info');
    document.getElementById('rc-display').textContent =
      'UPDATED: ' + (gameanalytics.GameAnalytics.getRemoteConfigsContentAsString() || '(empty)');
  }
};

function getRCValue() {
  const key = document.getElementById('rc-key').value.trim();
  const def = document.getElementById('rc-default').value.trim();
  const val = gameanalytics.GameAnalytics.getRemoteConfigsValueAsString(key, def);
  appLog(`getRemoteConfigsValueAsString("${key}", "${def}") → "${val}"`, 'info');
  document.getElementById('rc-display').textContent = `Key: ${key}\nValue: ${val}`;
}

function showRCContent() {
  const content = gameanalytics.GameAnalytics.getRemoteConfigsContentAsString();
  appLog('getRemoteConfigsContentAsString() → ' + content, 'info');
  try {
    document.getElementById('rc-display').textContent =
      content ? JSON.stringify(JSON.parse(content), null, 2) : '(empty — not yet fetched)';
  } catch {
    document.getElementById('rc-display').textContent = content || '(empty)';
  }
}

function checkRCReady() {
  const ready = gameanalytics.GameAnalytics.isRemoteConfigsReady();
  appLog('isRemoteConfigsReady() → ' + ready, 'info');
  document.getElementById('rc-display').textContent = 'Ready: ' + ready;
}

function addRCListener() {
  GA('addRemoteConfigsListener', rcListener);
}

function removeRCListener() {
  GA('removeRemoteConfigsListener', rcListener);
}

// ─── New Features ──────────────────────────────────────────────────────────

function showHealthSnapshot() {
  if (typeof gameanalytics !== 'undefined' && gameanalytics.health && gameanalytics.health.GAHealth) {
    const snap = gameanalytics.health.GAHealth.getSnapshot();
    appLog('Health snapshot: ' + JSON.stringify(snap), 'info');
    originalConsole.log('[Health snapshot]', snap);
    const el = document.getElementById('health-snapshot-display');
    if (el) {
      el.textContent = JSON.stringify(snap, null, 2);
      el.style.display = '';
    }
  } else {
    appLog('GAHealth not available (browser only)', 'warn');
  }
}

function sendHealthEventNow() {
  try {
    gameanalytics.events.GAEvents.addHealthEvent();
    appLog('Health event added to queue', 'info');
  } catch (e) {
    appLog('sendHealthEventNow failed: ' + e, 'warn');
  }
}

function sendSdkInitEventNow() {
  try {
    gameanalytics.events.GAEvents.addSDKInitEvent();
    appLog('SDK init event added to queue', 'info');
  } catch (e) {
    appLog('sendSdkInitEventNow failed: ' + e, 'warn');
  }
}

function useLocalStorage() {
  if (typeof gameanalytics !== 'undefined' && gameanalytics.store && gameanalytics.store.LocalStorageAdapter) {
    const adapter = new gameanalytics.store.LocalStorageAdapter();
    GA('configureStorageAdapter', adapter);
    appLog('Switched to LocalStorageAdapter', 'info');
  } else {
    appLog('LocalStorageAdapter not available', 'warn');
  }
}

function useInMemoryStorage() {
  if (typeof gameanalytics !== 'undefined' && gameanalytics.store && gameanalytics.store.InMemoryAdapter) {
    const adapter = new gameanalytics.store.InMemoryAdapter();
    GA('configureStorageAdapter', adapter);
    appLog('Switched to InMemoryAdapter (data will not persist across reloads)', 'warn');
  } else {
    appLog('InMemoryAdapter not available', 'warn');
  }
}

// Logging HTTP interceptor — forwards requests then calls the real XHR
function installHttpInterceptor() {
  const handler = (url, payload, authHeader, callback) => {
    appLog(`[HTTP interceptor] POST ${url}`, 'sent');
    appLog(`[HTTP interceptor] payload length: ${payload.length} bytes`, 'verbose');

    // Forward via fetch (keeps the interceptor chain intact)
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
      body: payload,
    })
      .then(r => r.text().then(body => {
        appLog(`[HTTP interceptor] response ${r.status}`, r.ok ? 'info' : 'warn');
        callback(r.status, body);
      }))
      .catch(err => {
        appLog(`[HTTP interceptor] network error: ${err}`, 'warn');
        callback(0, '');
      });
  };

  GA('configureCustomHttpHandler', handler);
  appLog('HTTP interceptor installed (logs every request + response)', 'info');
}

function clearHttpInterceptor() {
  GA('configureCustomHttpHandler', null);
  appLog('HTTP interceptor cleared — SDK will use native XHR', 'info');
}

function setExternalUserId() {
  const id = document.getElementById('ext-user-id').value.trim();
  GA('configureExternalUserId', id);
}

function setEventInterval() {
  const val = parseInt(document.getElementById('backoff-interval').value, 10);
  if (!isNaN(val) && val > 0) GA('setEventProcessInterval', val);
}

// ─── Local proxy ──────────────────────────────────────────────────────────

/**
 * Route all SDK HTTP traffic through the local dev-server proxy
 * (GET /ga-proxy/* → https://api.gameanalytics.com/*).
 *
 * This completely avoids browser CORS restrictions because the XHR goes to
 * the same origin as the page (127.0.0.1:PORT) and the server forwards it
 * server-side.  Must be called before initialize().
 */
function useLocalProxy() {
  const proxyBase = window.location.origin + '/ga-proxy';
  const GA_API    = /^https?:\/\/api\.gameanalytics\.com/;

  // Patch XHR at the prototype level so every SDK request is intercepted
  // regardless of when it's created.  The SDK uses raw XMLHttpRequest — there
  // is no configureCustomHttpHandler hook in this build.
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var rest = Array.prototype.slice.call(arguments, 2);
    if (typeof url === 'string' && GA_API.test(url)) {
      url = url.replace(GA_API, proxyBase);
    }
    return _open.apply(this, [method, url].concat(rest));
  };

  document.getElementById('proxy-notice').style.display = '';
  document.getElementById('proxy-url-display').textContent = proxyBase;
  document.getElementById('cors-notice').style.display = 'none';
  document.getElementById('proxy-badge').style.display = '';

  appLog('Local proxy configured: ' + proxyBase + ' → api.gameanalytics.com', 'info');
  appLog('All SDK requests will now go through the local server (no CORS restrictions).', 'info');
}

// ─── Init ─────────────────────────────────────────────────────────────────

appLog('Test dashboard ready. Configure options in Pre-Init Config, then Initialize.', 'info');
appLog('SDK loaded: gameanalytics namespace ' + (typeof gameanalytics !== 'undefined' ? '✓' : '✗'), 'info');

// Enable info logging by default so we can see events in the log
GameAnalytics('setEnabledInfoLog', true);

// Auto-activate the proxy when served from the local dev server.
// The proxy must be configured before initialize(), so we do it eagerly.
if (window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost') {
  useLocalProxy();
}
