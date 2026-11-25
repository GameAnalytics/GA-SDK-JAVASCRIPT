#!/usr/bin/env node
/**
 * GameAnalytics JavaScript SDK — Node (headless) sample.
 *
 * The CLI counterpart of app/ (the browser test app). It consumes the SDK the
 * way a real Node package would — through the package's `exports` map, with
 * automatic sessions, an awaitable shutdown, and no browser globals — and it
 * exercises every headless-specific behaviour in headless_specs.md.
 *
 * Status: headless is implemented and this sample is its acceptance harness;
 * every mode below is verified in CI on Node 18, 20 and 22. If a build
 * regresses to the old module-load ReferenceError, the sample exits 2 with a
 * pointer to the spec instead of a bare stack trace.
 *
 * Usage:
 *   node app_node/index.js                 happy path: init, events, await onQuit()
 *   node app_node/index.js --no-quit       exit without onQuit(); relies on beforeExit
 *   node app_node/index.js --crash         uncaught throw after events (exit 1)
 *   node app_node/index.js --progression   start + fail x2 (tries persisted)
 *   node app_node/index.js --progression-complete   complete -> attempt_num 3, from disk
 *   node app_node/index.js --manual-session  explicit startSession()/endSession()
 *   node app_node/index.js --verbose       SDK verbose log
 *
 * Keys: GA_GAME_KEY / GA_SECRET_KEY, else the same test pair as app/index.html.
 */

'use strict';

const os = require('os');

// Same test game as the browser sample. Override with env for a real game.
const GAME_KEY   = process.env.GA_GAME_KEY   || 'c6cfc80ff69d1e7316bf1e0c8194eda6';
const SECRET_KEY = process.env.GA_SECRET_KEY || 'e0ae4809f70e2fa96916c7060f417ae53895f18d';

const args = new Set(process.argv.slice(2));
if (args.has('--help') || args.has('-h')) {
    process.stdout.write(require('fs').readFileSync(__filename, 'utf8').split('*/')[0].split('\n').slice(2).map(l => l.replace(/^ \* ?/, '')).join('\n').trimEnd() + '\n');
    process.exit(0);
}
const MODE = {
    crash:         args.has('--crash'),
    noQuit:        args.has('--no-quit'),
    progression:   args.has('--progression'),
    progressionComplete: args.has('--progression-complete'),
    manualSession: args.has('--manual-session'),
    verbose:       args.has('--verbose'),
};

const log = (...a) => console.log('[app_node]', ...a);

// ── Load the SDK the way a consumer does ──────────────────────────────────────
// `require('..')` resolves through package.json's `exports` map to
// dist/GameAnalytics.node.js — identical to `require('gameanalytics')` from an
// installed package. No shims: if the SDK needs a browser global, that is the
// bug headless_specs.md exists to fix, and hiding it here would hide the bug.
function loadSdk() {
    try {
        return require('..');
    } catch (e) {
        if (e instanceof ReferenceError && /\b(window|navigator|document|localStorage|screen)\b/.test(e.message)) {
            console.error(`[app_node] The SDK cannot load in Node yet: ${e.message}`);
            console.error('[app_node] This is the module-load-time browser access described in');
            console.error('[app_node] headless_specs.md ("Current state"); it is fixed by Phase 1.');
            process.exit(2);
        }
        throw e;
    }
}

// Calls a method the spec defines but the SDK may not have yet. Logs instead
// of throwing so this sample is honest in both worlds.
function optional(GameAnalytics, name, ...callArgs) {
    if (typeof GameAnalytics[name] === 'function') {
        return GameAnalytics[name](...callArgs);
    }
    log(`${name}() is not available in this build yet (headless_specs.md) — skipped`);
    return undefined;
}

async function main() {
    const { GameAnalytics, EGAProgressionStatus, EGAErrorSeverity } = loadSdk();
    log(`node ${process.version} on ${process.platform}/${os.arch()}, mode:`,
        Object.entries(MODE).filter(([, v]) => v).map(([k]) => k).join(' ') || 'default');

    // ── Configure (before initialize) ────────────────────────────────────────
    GameAnalytics.setEnabledInfoLog(true);
    GameAnalytics.setEnabledVerboseLog(MODE.verbose);
    GameAnalytics.configureBuild('app_node 1.0.0');
    // Not called: configureSdkGameEngineVersion / configureGameEngineVersion are
    // for engine wrappers (unity, godot, …) and reject anything else. A direct
    // Node consumer reports sdk_version "javascript <sdk version>", which is right.
    GameAnalytics.configureAvailableCustomDimensions01(['cli', 'ci']);
    GameAnalytics.setGlobalCustomEventFields({ runtime: 'node', platform: process.platform });

    // Spec: off by default; opt in to exercise uncaughtExceptionMonitor (--crash).
    optional(GameAnalytics, 'setEnabledErrorReporting', true);

    GameAnalytics.addRemoteConfigsListener({
        onRemoteConfigsUpdated() {
            log('remote configs ready:', GameAnalytics.isRemoteConfigsReady());
            log('remote configs:', GameAnalytics.getRemoteConfigsContentAsString());
            log('example key:', GameAnalytics.getRemoteConfigsValueAsString('app_node_example', '<default>'));
        },
    });

    // Spec: sessions are automatic in headless (ended on beforeExit / onQuit).
    // --manual-session demonstrates the explicit alternative.
    if (MODE.manualSession) GameAnalytics.setEnabledManualSessionHandling(true);

    GameAnalytics.initialize(GAME_KEY, SECRET_KEY);
    if (MODE.manualSession) GameAnalytics.startSession();

    GameAnalytics.setCustomDimension01('cli');

    // ── Events ──────────────────────────────────────────────────────────────
    GameAnalytics.addDesignEvent('app_node:started', 1, { mode: Object.keys(MODE).filter(k => MODE[k]).join(',') || 'default' });
    GameAnalytics.addBusinessEvent('USD', 499, 'iap', 'starter_pack', 'shop');
    GameAnalytics.addErrorEvent(EGAErrorSeverity.Warning, 'app_node: sample warning event');

    // Attempt counting lives in the PERSISTENT tier (headless_specs.md,
    // Storage) and survives across runs:
    //   --progression          Start, Fail, Fail  -> tries = 2 written to disk
    //   --progression-complete Complete           -> attempt_num 3, read from
    //                                                disk, then the row is cleared
    const P = EGAProgressionStatus;
    if (MODE.progression) {
        GameAnalytics.addProgressionEvent(P.Start, 'world01', 'level01', '', 0);
        GameAnalytics.addProgressionEvent(P.Fail,  'world01', 'level01', '', 10);
        GameAnalytics.addProgressionEvent(P.Fail,  'world01', 'level01', '', 20);
    }
    if (MODE.progressionComplete) {
        GameAnalytics.addProgressionEvent(P.Complete, 'world01', 'level01', '', 100);
    }

    // ── Shutdown ─────────────────────────────────────────────────────────────
    if (MODE.crash) {
        // Thrown from a timer so it is genuinely UNCAUGHT (main's own promise
        // would otherwise catch a synchronous throw). Exercises
        // uncaughtExceptionMonitor: the process still exits 1, the error event
        // is persisted (not sent), and the session cache is left as an orphan
        // in tmp for the next run's sweep — headless_specs.md, Shutdown.
        // 1.5 s: after the queued initialize() has run and the session exists,
        // so the error event is persisted rather than dropped as "not initialized".
        log('throwing an uncaught exception in 1.5 s; expect exit code 1');
        setTimeout(() => { throw new Error('app_node: deliberate uncaught exception'); }, 1500);
        return;
    }

    if (MODE.manualSession) GameAnalytics.endSession();

    if (MODE.noQuit) {
        // Nothing drains explicitly. Spec: the guarded beforeExit handler ends
        // the session and drains once the event loop empties, and the unref'd
        // task pump lets the process exit on its own.
        log('exiting without onQuit(); relying on beforeExit auto-drain');
        return;
    }

    // Spec: onQuit() resolves once the queue has drained and the session
    // cache file is deleted. No busy-wait — see "Port onQuit(), but not its spin".
    log('awaiting onQuit() ...');
    await optional(GameAnalytics, 'onQuit');
    log(process.env.GA_GAME_KEY ? 'done' : 'done (using the bundled test keys; set GA_GAME_KEY / GA_SECRET_KEY for your game)');
}

main().catch((e) => {
    console.error('[app_node] failed:', e);
    process.exit(1);
});
