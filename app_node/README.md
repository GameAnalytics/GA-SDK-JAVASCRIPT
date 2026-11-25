# app_node — Node (headless) sample

The CLI counterpart of [`app/`](../app), the browser test app. It consumes the
SDK as a real Node package would and exercises every headless-specific
behaviour in [`headless_specs.md`](../headless_specs.md).

```sh
npm run dev:node              # or: node app_node/index.js
GA_GAME_KEY=… GA_SECRET_KEY=… npm run dev:node
```

Without env vars it uses the same test game as `app/index.html`.

## Status

**It runs.** All four phases of the spec are implemented; every mode below is
verified locally and in CI on Node 18, 20 and 22. The sample still detects the
specific module-load `ReferenceError` that headless fixed and exits `2` with a
pointer to the spec — now a safety net for a regressed build rather than the
expected outcome. Methods the spec added (`setEnabledErrorReporting`,
`onQuit`) are called through a guard that logs if a build lacks them.

## Event timing

Events can be added right after `initialize()`. The SDK holds its task queue
while the init request is in flight and runs the queued calls, in order, once
the response (or a failure) arrives.

## Short commands

[`command.js`](command.js) shows the pattern for a command that must not wait
for the network: it prints its result, hands one event to a detached helper
process on stdin and exits. The helper runs the SDK and waits at most 10 s.

```sh
node app_node/command.js
```

## Modes, and what each exercises

| Flag | Spec section | Expected once implemented |
|---|---|---|
| *(none)* | Shutdown → *Port `onQuit()`* | queue drains, session cache deleted, exit 0 |
| `--no-quit` | Shutdown → *Session end: `beforeExit`* | same outcome with no explicit call; process exits on its own |
| `--crash` | Platform → *crash reporting*; Storage → sweep | exit **1** (not 0); error event persisted; orphan cache in tmp, swept by the next run |
| `--progression` | Storage → *persistent tier* | Start + Fail + Fail; `tries: 2` written to `persistent.json` |
| `--progression-complete` | Storage → *persistent tier* | run after the above: `Complete` logs `attempt:3`, read from disk; row then cleared |
| `--manual-session` | Shutdown → *Recommendation* | explicit `startSession()`/`endSession()` still works |
| `--verbose` | — | SDK verbose log |

`--crash` throws from a timer so the exception is genuinely uncaught. With
`setEnabledErrorReporting(true)` the monitor reports it; with it off (the
default) the process must still exit 1 — that is the guarantee
`uncaughtExceptionMonitor` gives and `uncaughtException` would not.

## Phase checklist

- **Phase 1** — `node app_node/index.js` gets past `require()` and `initialize()`.
- **Phase 2** — device/health annotations come from `GAPlatformNode`, not `navigator`.
- **Phase 3** — events are drained to the collector endpoint, and `--progression` then `--progression-complete` shows `attempt:3` across runs. The bundled test pair is accepted by the collector, so every mode shows `N events sent`; it is a shared demo game, so use `GA_GAME_KEY` / `GA_SECRET_KEY` for real data.
- **Phase 4** — default mode exits cleanly via `onQuit()`; `--no-quit` exits on its own.
