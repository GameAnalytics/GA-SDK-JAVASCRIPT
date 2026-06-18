#!/usr/bin/env node
/**
 * Dev server for the GA SDK test app.
 *
 * • Builds dist/GameAnalytics.debug.js from src/ on startup via `gulp debug`.
 * • Watches src/**\/*.ts and rebuilds on change.
 * • Serves the whole repo root so the app can load ../dist/... correctly.
 * • Proxies /ga-proxy/* → https://api.gameanalytics.com/* (avoids CORS).
 * • Pushes a live-reload SSE event to the browser after each successful build.
 *
 * Usage:  node app/server.js          (default port 3000)
 *         node app/server.js 8080     (custom port)
 */

'use strict';

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const { spawn } = require('child_process');

const PORT    = parseInt(process.argv[2], 10) || 3000;
const ROOT    = path.join(__dirname, '..');
const SRC_DIR = path.join(ROOT, 'src');

// ─── Build pipeline ───────────────────────────────────────────────────────────

let building        = false;
let buildQueued     = false;
let lastBuildResult = null;
let buildLog        = [];
const sseClients    = new Set();

function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch (_) { sseClients.delete(res); }
  }
}

function runBuild() {
  if (building) { buildQueued = true; return; }
  building    = true;
  buildQueued = false;
  buildLog    = ['[build] compiling src → dist/GameAnalytics.debug.js …'];

  console.log('\n  [build] compiling src → dist/GameAnalytics.debug.js …');
  broadcast('building', { ts: Date.now() });

  const isWin = process.platform === 'win32';
  const proc  = spawn(isWin ? 'npx.cmd' : 'npx', ['gulp', 'debug'], {
    cwd:   ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let output = '';
  proc.stdout.on('data', d => {
    output += d;
    process.stdout.write('  ' + d);
    String(d).split('\n').forEach(l => { if (l.trim()) buildLog.push(l); });
  });
  proc.stderr.on('data', d => {
    output += d;
    process.stderr.write('  ' + d);
    String(d).split('\n').forEach(l => { if (l.trim()) buildLog.push(l); });
  });

  proc.on('close', code => {
    building = false;
    const clean = output.replace(/\x1b\[[0-9;]*m/g, '');

    if (code === 0) {
      console.log('  [build] ✓ done\n');
      const summary = clean.split('\n')
        .filter(l => l.includes('Finished') || l.includes('✓') || l.includes('done'))
        .slice(-4).join('\n').trim();
      lastBuildResult = { status: 'done', summary };
      broadcast('reload', { ts: Date.now(), summary });
    } else {
      console.error(`  [build] ✗ failed (exit ${code})\n`);
      const lines = clean.split('\n');
      const errors = lines.filter(l =>
        /error TS\d+|^\s+\^|\.ts\(\d+,\d+\)/.test(l) ||
        (l.includes('error') && l.includes('.ts'))
      );
      const message = errors.length > 0 ? errors.join('\n') : clean.slice(-3000);
      lastBuildResult = { status: 'failed', message };
      broadcast('build-failed', { ts: Date.now(), message });
    }

    if (buildQueued) runBuild();
  });
}

// Build once on startup, then watch src/ for TS changes
runBuild();

let debounceTimer = null;
try {
  fs.watch(SRC_DIR, { recursive: true }, (_, filename) => {
    if (!filename || !filename.endsWith('.ts')) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      console.log(`  [watch] changed: ${filename}`);
      runBuild();
    }, 150);
  });
} catch (e) {
  console.warn('  [watch] fs.watch unavailable — manual refresh required:', e.message);
}

// ─── GA API proxy ─────────────────────────────────────────────────────────────

function handleProxy(req, res, urlPath) {
  const gaPath = urlPath.slice('/ga-proxy'.length) || '/';
  const gaUrl  = 'https://api.gameanalytics.com' + gaPath;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'content-type, authorization',
    });
    res.end();
    return;
  }

  const chunks = [];
  req.on('data', d => chunks.push(d));
  req.on('end', () => {
    const body    = Buffer.concat(chunks);
    const target  = new URL(gaUrl);
    const opts    = {
      hostname: target.hostname,
      path:     target.pathname + (target.search || ''),
      method:   req.method,
      headers: {
        'content-type':   req.headers['content-type']   || 'application/json',
        'content-length': body.length,
        ...(req.headers['authorization']
          ? { 'authorization': req.headers['authorization'] }
          : {}),
      },
    };

    const proxyReq = https.request(opts, proxyRes => {
      res.writeHead(proxyRes.statusCode, {
        'Content-Type':                proxyRes.headers['content-type'] || 'application/json',
        'Access-Control-Allow-Origin': '*',
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', err => {
      console.error('  [proxy] error:', err.message);
      if (!res.headersSent) { res.writeHead(502); }
      res.end('Proxy error: ' + err.message);
    });

    if (body.length) proxyReq.write(body);
    proxyReq.end();
  });
}

// ─── Static file server ───────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.map':  'application/json',
  '.wasm': 'application/wasm',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
};

const server = http.createServer((req, res) => {
  let urlPath = req.url.split('?')[0];

  // ── Manual rebuild trigger ──────────────────────────────────────────────────
  if (urlPath === '/rebuild' && req.method === 'POST') {
    lastBuildResult = null;
    if (!building) runBuild();
    res.writeHead(202, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'started' }));
    return;
  }

  // ── Build status poll ───────────────────────────────────────────────────────
  if (urlPath === '/build-status' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ building, result: lastBuildResult, log: buildLog }));
    return;
  }

  // ── Live-reload SSE ─────────────────────────────────────────────────────────
  if (urlPath === '/__livereload') {
    res.writeHead(200, {
      'Content-Type':                'text/event-stream',
      'Cache-Control':               'no-cache',
      'Connection':                  'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write('retry: 2000\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // ── GA API proxy ────────────────────────────────────────────────────────────
  if (urlPath.startsWith('/ga-proxy/') || urlPath === '/ga-proxy') {
    handleProxy(req, res, req.url);
    return;
  }

  // ── Static files ────────────────────────────────────────────────────────────
  if (urlPath === '/' || urlPath === '') urlPath = '/app/index.html';
  else if (urlPath.endsWith('/')) urlPath += 'index.html';

  const filePath = path.join(ROOT, urlPath);

  // Security: stay inside repo root
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found: ' + urlPath);
      return;
    }

    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type':                mime,
      'Cache-Control':               'no-store',
      'Access-Control-Allow-Origin': '*',
    });

    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  GA SDK Test App`);
  console.log(`  ─────────────────────────────────────────────────────`);
  console.log(`  Local:    http://127.0.0.1:${PORT}/app/`);
  console.log(`  Watching: src/**/*.ts  →  dist/GameAnalytics.debug.js`);
  console.log(`  Proxy:    /ga-proxy/*  →  api.gameanalytics.com`);
  console.log(`\n  Ctrl+C to stop\n`);
});
