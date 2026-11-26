#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');

const GAME_KEY   = process.env.GA_GAME_KEY   || 'c6cfc80ff69d1e7316bf1e0c8194eda6';
const SECRET_KEY = process.env.GA_SECRET_KEY || 'e0ae4809f70e2fa96916c7060f417ae53895f18d';
const MAX_WAIT_MS = 10000;

function command() {
    const started = Date.now();
    process.stdout.write('{"ok":true}\n');

    const helper = spawn(process.execPath, [__filename, '--send'], {
        detached: true,
        stdio: ['pipe', 'ignore', 'ignore'],
        windowsHide: true,
    });
    helper.on('error', () => {});
    helper.stdin.on('error', () => {});
    helper.stdin.end(JSON.stringify({ event: 'app_node:command', ms: Date.now() - started }));
    helper.unref();
}

async function send() {
    let input = '';
    for await (const chunk of process.stdin) input += chunk;
    const { event, ms } = JSON.parse(input);

    const { GameAnalytics } = require('..');
    GameAnalytics.configureLogHandler(() => {});
    GameAnalytics.configureBuild('app_node 1.0.0');
    GameAnalytics.initialize(GAME_KEY, SECRET_KEY);
    GameAnalytics.addDesignEvent(event, ms);
    await GameAnalytics.onQuit(MAX_WAIT_MS);
}

if (process.argv[2] === '--send') {
    send().catch(() => {});
} else {
    command();
}
