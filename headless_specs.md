# Headless mode

**Status:** draft · **Owner:** TBD · **Target:** TBD · **Node:** ≥ 18

## Abstract

The JavaScript SDK assumes a browser. This blocks the CLI/Node package: today
`require('gameanalytics')` does not merely degrade, it throws before any user
code runs.

```
$ node -e "require('gameanalytics')"
ReferenceError: window is not defined
```

The `main` entry point declared in `package.json` is therefore unusable in
Node. This document specifies what "headless mode" means, what has to be
abstracted, and in what order.

The design team outlined three dependencies — `window`, `localStorage`,
`XMLHttpRequest`. The actual surface is wider; the inventory below is taken
from the current `src/`.

**Architecture:** this ports the C++ SDK's `GAPlatform` design rather than
inventing a new one — same interface, same required/optional split, same
sentinel conventions, same build-time selection. All C++ references below are
to `gameanalytics-sdk-cpp` at `e342bf6`. Where the browser runtime makes the
C++ shape impossible, the divergence is called out under
[Divergences](#divergences-from-the-c-sdk) rather than quietly papered over.

## Current state

Two browser accesses run at **module load time**, before any API call:

| Location | Access | Effect |
|---|---|---|
| `src/GameAnalytics.ts:84` | `window.addEventListener("beforeunload", …)` | Throws on import in Node |
| `src/device/GADevice.ts:34-38` | `navigator.platform/userAgent/appVersion/vendor` in a `static readonly` initializer | Throws on import in Node |

Both sit next to code that already guards correctly — `getGlobalObject()` at
`src/GameAnalytics.ts:20` falls back through `globalThis → self → window →
global`, and every browser access in `GAHealth` is wrapped in
`typeof x !== 'undefined'`. The pattern exists in the codebase; it simply is
not applied uniformly. That inconsistency, not a missing design, is what
breaks Node today.

## Browser surface inventory

Counted across `src/`:

| Global | Uses | Files | Maps to |
|---|---|---|---|
| `navigator` | 17 | `GADevice.ts`, `GAHealth.ts` | `GAPlatform` |
| `localStorage` | 11 | `GAStore.ts` | `IGAStorage` (divergence 1) |
| `performance` | 10 | `GAHealth.ts` | `GAPlatform` memory/timing |
| `screen` | 8 | `GAHealth.ts` | Not in `GAPlatform` — see Health |
| `XMLHttpRequest` | 7 | `GAHTTPApi.ts`, `SdkErrorTask.ts` | `IGAHttpClient` (divergence 2) |
| `window` | 3 | `GameAnalytics.ts` | Global object + `beforeunload` (browser-only) |
| `document` | 2 | `GAHealth.ts` | `GAPlatform.getGpuModel` |

## Design

### The platform interface

Port of `Platform/GAPlatform.h`. Expressed as an abstract class so the
pure-virtual / defaulted-virtual split survives: abstract members must be
implemented, concrete members return the same sentinels the C++ base does
(`GAPlatform.cpp`).

```ts
abstract class GAPlatform {
    // Pure virtual in C++ — every platform must implement
    abstract getOSVersion(): string;
    abstract getDeviceManufacturer(): string;
    abstract getBuildPlatform(): string;
    abstract getPersistentPath(): string;
    abstract getDeviceModel(): string;
    abstract getConnectionType(): string;

    // Virtual with defaults — override where the runtime can answer
    getAdvertisingId(): string { return ""; }
    getDeviceId(): string      { return ""; }

    getCpuModel(): string          { return ""; }
    getGpuModel(): string          { return ""; }
    getNumCpuCores(): number       { return -1; }
    getTotalDeviceMemory(): number { return -1; }
    getAppMemoryUsage(): number    { return -1; }
    getSysMemoryUsage(): number    { return -1; }
    getBootTime(): number          { return -1; }

    onInit(): void {}                        // NOT empty in C++ — see below
    setupUncaughtExceptionHandler(): void {}
}
```

*As implemented:* one JS-only defaulted member is added, `getBrowserVersion()`
returning `""` — `browser_version` is on the wire and C++ has no browser.
Node inherits the sentinel; the browser platform overrides it.

**The sentinel convention is load-bearing.** `-1` for unavailable numerics and
`""` for unavailable strings is how the C++ SDK distinguishes "not measurable
on this platform" from a real reading. Adopting it settles what headless
should report for browser-only metrics: not `0`, which is indistinguishable
from a genuine measurement downstream.

**`onInit()` is not a no-op in C++.** `GAPlatform::onInit()` installs a
`std::terminate` handler when `GAState::useErrorReporting()` is on; the
handler captures a stack trace, submits
`addErrorEvent(EGAErrorSeverity::Critical, …)` and caps itself at 5 reports.
`setupUncaughtExceptionHandler()` is the member that defaults to empty.

The JavaScript SDK has **no automatic uncaught-error reporting at all** —
no `window.onerror`, no `unhandledrejection`, no `process.on('uncaughtException')`.
Porting `onInit()` faithfully would therefore add a capability rather than
move an existing one.

**Decided: ported for Node, via `uncaughtExceptionMonitor`.**

The obvious spelling is the wrong one. Adding `process.on('uncaughtException')`
**suppresses Node's default termination** — the process survives an uncaught
throw and exits `0` instead of `1`. Measured on Node 24:

| Listener | crash reported | exit code |
|---|---|---|
| none | — | 1 |
| `process.on('uncaughtException')` | yes | **0** — crash swallowed |
| `process.on('uncaughtExceptionMonitor')` | yes | 1 — preserved |

An SDK that silently turns a failing process into a passing one is a worse
bug than the missing telemetry it set out to fix: a crashing CI job would go
green. `uncaughtExceptionMonitor` (Node 12+) exists for exactly this role — it
observes and then lets the default behaviour proceed untouched. It is the same
distinction drawn for `'exit'` versus `SIGINT` above: monitor, never intercept.

Constraints that follow:

- **Persist, do not send.** The monitor runs synchronously as the process
  dies, so no HTTP request can complete. Write the error event to the store
  with `addEventToStore` and let the next run deliver it — the same fallback
  the Ctrl-C path relies on.
- **Cap the reports**, matching C++'s `MAX_ERROR_TYPE_COUNT` of 5.
- **Node only, for now.** `GAPlatformBrowser.setupUncaughtExceptionHandler()`
  stays a no-op; adding `window.onerror` / `unhandledrejection` is a separate
  decision with its own noise profile, and nothing forces the two platforms to
  land together.
- **Decided: gated, off by default.** Add `setEnabledErrorReporting(flag = false)` to
  the public API — a port of C++'s `GameAnalytics.h:105`. **This default is a
  deliberate divergence**: C++ initialises `_enableErrorReporting = true`
  (`GAState.h:281`). The JavaScript SDK has never reported crashes, so
  defaulting on would change behaviour for every existing caller on upgrade;
  off preserves current behaviour and makes reporting an opt-in.
- **Install at init, gate at crash time.** C++ installs its signal handler only
  if the flag is true when `initPlatform()` runs (`GADevice.cpp:52`), once.
  With a `true` default that is harmless; with a `false` default it means
  `setEnabledErrorReporting(true)` *after* `initialize()` silently installs
  nothing. Avoid that trap by porting the pattern C++ already uses for its
  terminate handler. Keep the registration where C++ keeps it —
  `setupUncaughtExceptionHandler()` installs the `uncaughtExceptionMonitor`
  listener — but have `GAPlatformNode.onInit()` call that method
  **unconditionally**, where C++'s `initPlatform()` gates the call. The
  listener then checks the flag when it fires.
  A monitor listener never alters termination, so an idle one is invisible —
  "off by default" holds in every observable way, and late enable just works.

### Ownership and wiring of the platform object

Mirror the C++ relationships exactly — they are the part most likely to drift.

| C++ | JavaScript |
|---|---|
| `GADevice` holds `std::unique_ptr<GAPlatform> _platform` | `GADevice` owns the instance |
| `static GAPlatform* GADevice::getPlatform()` | `GADevice.getPlatform()` |
| `GADevice::getWritablePath()` wraps `getPersistentPath()` | same wrapper |
| `GAHealth(GAPlatform* platform)` — constructor injection | `new GAHealth(platform)` |
| `GAHealth` caches cpu/cores/hardware/gpu/totalMemory at construction | same, read once |

`GAHealth` reads five values once in its constructor behind a null check, and
calls `_platform->` live only for `getBootTime()`, `getAppMemoryUsage()` and
`getSysMemoryUsage()`. Keep that split; it is what makes the per-reading path
cheap.

### Platform implementations

| C++ | JavaScript |
|---|---|
| `GAPlatformWin32`, `GAPlatformLinux`, `GAPlatformMacOS`, `GAPlatformUwp` | `GAPlatformNode`, `GAPlatformBrowser` |

`GAPlatformBrowser` holds the existing UA-matching logic from `GADevice`
unchanged. `GAPlatformNode` answers from `os` and `process`:

| Method | Node source | C++ reference |
|---|---|---|
| `getOSVersion()` | `getBuildPlatform() + " " + os.release()` — e.g. `mac_osx 25.6.0` | `uname` on Linux |
| `getDeviceManufacturer()` | `""` (sentinel) | |
| `getBuildPlatform()` | `os.platform()` mapped to the collector's names: `darwin→mac_osx`, `win32→windows`, `linux→linux`, `android→android`, else `unknown` | |
| `getPersistentPath()` | `$HOME/GameAnalytics` (persistent tier; the session cache is `os.tmpdir()`, inside `IGAStorage`) | `GALinux.cpp:118` uses exactly this |
| `getDeviceModel()` | `os.arch()` or `""` | |
| `getConnectionType()` | `"lan"`, `"offline"` if no non-loopback interface | `GACommon.h:104-107` |
| `getCpuModel()` | `os.cpus()[0].model` | |
| `getNumCpuCores()` | `os.cpus().length` | |
| `getTotalDeviceMemory()` | `os.totalmem()` | |
| `getAppMemoryUsage()` | `process.memoryUsage().rss` | |
| `getSysMemoryUsage()` | `os.totalmem() - os.freemem()` | |
| `getBootTime()` | `process.uptime() * 1000` — ms since process start | `GAWin32.cpp:446`, `GAMacOS.cpp:240` |
| `getGpuModel()` | `""` (sentinel) | Linux overrides this natively |
| `setupUncaughtExceptionHandler()` | `process.on('uncaughtExceptionMonitor', …)` | always installed; gated at fire time; never `uncaughtException` |

Connection values are fixed vocabulary: `"offline"`, `"lan"`, `"wifi"`,
`"wwan"` (`GACommon.h:104-107`). The JS SDK already emits `"lan"` and
`"wwan"` from `GADevice.updateConnectionType()`, so this maps without a
vocabulary change.

*Tested against the collector:* an earlier draft of this table sent raw
`os.platform()`. The events endpoint answered `400` with `/platform
not_in_range` and `/os_version no_match` — nothing else; `manufacturer` and
`browser_version` as `""` were accepted, so the sentinel convention holds on
the wire and only the platform name needed mapping.

### Storage

```ts
interface IGAStorage {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
    isAvailable(): boolean;
}
```

*As implemented:* two JS-port methods are added — `getSizeBytes()` (-1 when the
backend cannot measure, so the browser falls back to the entry count and only
Node uses bytes, as decided below) and `deleteSessionCache()` (the cache lives
inside `IGAStorage`, and `onQuit()` must delete it after a successful drain).

- **Browser:** wraps `localStorage`. `getPersistentPath()` returns `""`.
- **Node:** file-backed, in **two tiers** with different lifetimes — see
  below. The split is forced by what the four stores hold, not by taste.

**Decided: a per-session cache in tmp, cleaned on session end — plus a
persistent tier for the state that cannot live there.**

The four stores have two lifetimes:

| Store | Holds | Lifetime | Tier |
|---|---|---|---|
| `ga_event` | queued events | one session | session cache |
| `ga_session` | sessions awaiting `session_end` | one session | session cache |
| `ga_progression` | `{progression → tries}` for `attempt_num` | across sessions | persistent |
| items (`storeItems`) | generated user ID, cached remote config, custom dimensions 01–03, last-used identifier | across sessions | persistent |

The persistent tier is mandatory, and items is the stronger reason than
progression: it holds the **generated user ID** (`GameAnalytics.ts:703`).
A cache wiped every session would make every CLI invocation a brand-new user,
which is dataset corruption rather than a bug. Progression is cross-session in
both SDKs by design — JS loads every `{progression, tries}` row into memory
at init (`GAState.ts:694–703`), and C++'s only `DELETE` on `ga_progression`
is the per-progression clear on complete (`GAState.cpp:299`). Items has no C++
precedent at all; it is JS-only.

**Session cache** — `os.tmpdir()/GameAnalytics/<gameKey>/<pid>-<session_id>.json`,
holding that session's `ga_event` and `ga_session` rows. Written on every
event (above). Concurrency-safe by construction: session IDs are UUIDs, so two
processes never share a file and no locking is needed.

- **Deleted as the last step of a successful drain** — inside `onQuit()` or
  the `beforeExit` handler, *after* the final send resolves. Never at the
  moment `endSession()` is called: the send is asynchronous, and deleting
  first loses in-flight events on a network failure. "Successful" means no
  event rows remain: a `NoResponse` puts them back as `new` and the cache is
  kept for the next run's sweep; a definite collector rejection (4xx) discards
  them, as the SDK always has, and the cache is then deleted.
- **On a dirty exit the file survives**, and the next `initialize()` sweeps
  the game-key directory from `GAStore.load()` (`GAState.ts:613`), which runs
  before the first tick. Orphan rows are loaded into memory; the existing
  `fixMissingSessionEndEvents()` (`GAEvents.ts:816`) then synthesises their
  `session_end`, and their events join the queue. *Found by the sample:* that
  function runs only from the 8-second tick (`GAThreading.ts:88`), which a
  process exiting in a second never reaches — the adopted session was sent but
  never closed. `onQuit()` therefore runs one cleanup pass itself before ending
  the session; the browser, which never calls `onQuit()`, is unchanged. The orphan file is deleted after *its* drain. This routes
  through a mechanism the SDK already has rather than adding one.
- **The sweep must distinguish orphans from live sessions, and the recovery
  function cannot.** `fixMissingSessionEndEvents()` filters only
  `session_id != current`; every other row in memory gets a synthesised
  `session_end`. Load a concurrent *live* session's rows and the first tick
  kills it in the dataset — a spurious end with a wrong length, then the real
  one later. The browser never met this because one page is one session. Hence
  the PID in the filename: before loading a candidate, `process.kill(pid, 0)`
  — silent if that process is alive, `ESRCH` if it is gone (measured). Only
  `ESRCH` files are orphans. Skip the rest.

**Persistent tier** — `getPersistentPath()` = `$HOME/GameAnalytics/<gameKey>/`,
C++'s own location (`GALinux.cpp:118`), holding `ga_progression` and items as
one small JSON map. Written rarely (progression fail or complete, a dimension
set, init), read once at load. Concurrent processes *can* race on it; the
split confines contention to a low-frequency file where a lost write is an
off-by-one attempt count, not lost events. Write it atomically (temp file +
`rename`) so a race can clobber a value but never corrupt the file.

`getPersistentPath()` keeps its C++ meaning — the SDK's persistent directory,
which C++ also uses for its log file (`GALogger.cpp:87`). The tmp cache is an
`IGAStorage` detail, not a new platform method.

**Decided: one SDK instance per process.** Each CLI invocation gets its own
SDK instance, so the existing singleton stands. Cross-process safety comes
from the per-session cache above, not from a lock.

`GAStore` persists four stores (`ga_event`, `ga_session`, `ga_progression`,
`ga_items`) under `GA::{gameKey}::{store}`. It already tracks a
`storageAvailable` flag and keeps working without `localStorage`, but
"working" means in-memory only, so a CLI process loses every queued event on
exit. That is a correctness problem for headless, not a missing nicety:
short-lived CLI runs are exactly the case where the queue never gets to flush.

**Decided: write synchronously on every event, matching C++.**

This is not a change — both SDKs already do it. C++ `addEventToStore`
(`GAEvents.cpp:755`) runs `executeQuerySync(INSERT …)` inside `BEGIN`/`COMMIT`
on SQLite's default `journal_mode=DELETE`, `synchronous=FULL`, so each event is
fsync'd before the call returns. JS `addEventToStore` (`GAEvents.ts:859`) is a
line-for-line port and ends with `GAStore.save()`, which writes all four stores
to `localStorage` synchronously. Neither SDK debounces or defers to shutdown.

Headless therefore changes only *where* `save()` writes, not *when*: the Node
`IGAStorage` backs `setItem` with `fs.writeFileSync`. This is also what the
`beforeExit`, Ctrl-C and `uncaughtExceptionMonitor` paths all depend on — each
one assumes the event is already on disk by the time it runs.

One thing to carry across deliberately: `save()` has no `try`/`catch`, so a
`QuotaExceededError` from `localStorage.setItem` propagates into
`addEventToStore`'s outer `catch (e)` and is swallowed — the event is silently
dropped. An `ENOSPC` from `writeFileSync` takes the same path. Log it rather
than inherit the silence.

**Size management exists in both SDKs, but they measure differently and only
C++ trims.**

| | C++ (`GAStore.cpp`) | JS (`GAStore.ts`) |
|---|---|---|
| Measure | raw file bytes (`getDbSizeBytes`, `GAStore.cpp:348`) | entry count (`eventsStore.length + sessionsStore.length`) |
| Block threshold | `MaxDbSizeBytes = 6291456` (6 MB) | `MaxNumberOfEntries = 2000` |
| Trim threshold | `MaxDbSizeBytesBeforeTrim = 5242880` (5 MB) | none |
| Trim policy | delete the 3 oldest sessions' events (`trimEventTable`, `GAStore.cpp:366`) | none — blocks until the queue sends |
| Exempt when full | `^(user|session_end|business)$` | same |

Both fire a `DatabaseTooLarge` SDK error on block. The C++ source comment
says "10mb"; the constants say 6 MB and 5 MB — the comment is stale.

The JS behaviour was designed for a browser, where a 2000-entry queue that
never drains is a connectivity problem the next page load resolves. A
long-running headless process with intermittent connectivity hits the cap and
then drops every non-exempt event indefinitely, because nothing frees space.
That is the gap to close, and it is a *trim* gap, not a *cap* gap.

**Decided: keep the C++ size logic.** The Node store adopts C++'s constants
and policy as-is:

- measure by raw file size — `fs.statSync(path).size`, the exact analogue of
  `getDbSizeBytes()`'s `ifstream ... tellg()`;
- trim when the **game-key tmp directory** exceeds `MaxDbSizeBytesBeforeTrim`
  (5,242,880 bytes) in aggregate, at sweep time: delete the 3 orphan files
  whose newest event is oldest. With one session per file, C++'s "3 oldest
  sessions" becomes "3 oldest orphan files" — same policy, different unit. A
  live session's own file is never trimmed, only blocked;
- block when it exceeds `MaxDbSizeBytes` (6,291,456 bytes), exempting
  `^(user|session_end|business)$` and firing the `DatabaseTooLarge` SDK
  error, exactly as both SDKs do today.

C++'s trim query orders by the bare `client_ts` column while selecting
`Max(client_ts)`. SQLite resolves a bare column in an aggregate query to the
row where a lone `Max()`/`Min()` was found, so this *is* a correct "oldest
session by its newest event" ordering — measured: the exact C++ query returns
the right three sessions, and the same query with `Max()` dropped from the
select list does not. The rule is real but easy to break by editing the
select list, so the JS port should sort by max `client_ts` per session
explicitly rather than inherit it.

The 2000-entry count check stays in the browser, where there is no file to
measure. Only the Node `IGAStorage` switches to bytes.

Aggregate across processes is bounded by construction: live sessions × 6 MB,
plus orphans — which every `initialize()` sweeps and the OS reaps on its own
schedule. C++ never meets this because its SQLite file is shared and
serialised; the per-session layout trades that single shared bound for
per-session bounds plus a sweep.

### HTTP

Port of `include/GameAnalytics/GAHttpClient.h`:

```ts
interface IGAHttpClient {
    initialize(): void;
    cleanup(): void;
    sendRequest(
        url: string,
        auth: string,
        payload: Uint8Array,
        useGzip: boolean,
    ): Promise<{ code: number; packet: Uint8Array }>;   // code = -1 on failure
}
```

*As implemented:* the response carries an optional `statusText`, used only for
log lines, and the Node client bounds each request with a 10 s
`AbortController` timeout — `fetch` has none, and without one an unreachable
collector would stall `onQuit()` for the TCP timeout. An abort is `code -1`,
the same `NoResponse` path as offline.

Matching the C++ signature matters in three places that a generic
`post(url, body, headers)` would lose:

- `auth` is its own parameter, not a headers-map entry. The HMAC-SHA256 of the
  payload is the one header every call sets.
- `useGzip` is first-class. C++ implements it (via the `miniz` dependency);
  the JS SDK has `throw new Error("gzip not supported")` on that branch in
  `GAHTTPApi.sendRequest`. Headless is the point to implement it with Node's
  built-in `zlib` or delete the parameter — but the interface should keep it,
  because C++ has it.
- `code = -1` is the failure sentinel, consistent with the rest of the port.

Implementations mirror `source/gameanalytics/Http/`, which pairs a real client
(`GAHttpCurl`) with a no-op (`GAHttpStub`). A stub is worth having for tests
and for `setEnabledEventSubmission(false)`.

- **Browser:** `XMLHttpRequest` (current behaviour), or `fetch`.
- **Node:** global `fetch`, available since Node 18 — no dependency needed.

**Decided: Node 18 is the minimum.** The floor exists because of `fetch`;
every other runtime API this spec relies on predates it
(`uncaughtExceptionMonitor` is 12+, `beforeExit`, `timer.unref()`, `os`,
`fs` and `process.memoryUsage()` are older still). 18 is already the lowest
version in the CI matrix (`gulp.yml`: 18, 20, 22), so the floor is tested on
every push today.

Enforce it, do not just document it: `package.json` currently has no
`engines` field, so add `"engines": { "node": ">=18" }`. Without it the floor
is advisory and a consumer on 16 fails at runtime on the first `fetch` with no
hint why.

One thing to confirm on the 18 leg of CI rather than assume: `fetch` was
experimental in the 18.x line and early releases printed an
`ExperimentalWarning` to stderr on first use. If the leg shows it, the SDK
should document it as expected on 18 rather than suppress it — suppression
would mean either a dependency (`undici`) or a process-wide flag the SDK
has no business setting.

### Shutdown

**No lifecycle abstraction.** An earlier draft specced an `IGALifecycle`
interface wrapping `beforeunload` and `process.on(SIGINT|SIGTERM)`. That was
wrong on two counts: it merged three separate concerns, and it had the SDK
installing process-level signal handlers — poor citizenship in a library,
since Node applications manage their own signals for graceful shutdown.

The C++ SDK already separates these cleanly, and headless should follow it:

| Concern | C++ mechanism | JavaScript |
|---|---|---|
| Session boundary | `setEnabledManualSessionHandling(true)` | stays automatic, ended on `beforeExit` |
| Drain before exit | `GameAnalytics::onQuit()`, blocks | `await GameAnalytics.onQuit()` |
| Crash reporting | platform handlers under `useErrorReporting()` | `GAPlatform` (above) |

#### Session end: `beforeExit`, not `exit`

The browser ends sessions on `beforeunload`. The question is whether Node has
an equivalent good enough to keep **automatic** session handling in headless,
rather than forcing callers to manage sessions by hand.

Measured on Node 24:

| Scenario | `beforeExit` | `exit` | async work can complete |
|---|---|---|---|
| Natural exit (loop empties) | fires | fires | yes, in `beforeExit` |
| `process.exit()` | — | fires | no |
| Uncaught exception | — | fires | no |
| SIGINT (Ctrl-C) | — | — | no |
| SIGTERM (`kill`) | — | — | no |

**`'exit'` cannot end a session.** Its handlers run synchronously during
teardown. Already-resolved promise microtasks still drain, which makes it look
usable in a quick test, but timers and I/O do not run — and the session-end
path needs both: `addSessionEndEvent()` finishes with `processEvents()`, which
issues an HTTP request. The request is created and then abandoned. `'exit'`
can diagnose; it cannot deliver.

**`'beforeExit'` can.** It fires when the event loop empties, and work
scheduled inside it runs to completion — the loop is re-entered afterwards.
That is a genuine `beforeunload` analogue and it covers the common CLI shape:
do some work, fall off the end of `main`, exit.

Two conditions on using it:

1. **Guard against re-entry.** `beforeExit` fires again after the work it
   scheduled completes. An unguarded handler that always schedules a drain
   loops forever — verified, it does not self-limit. A `draining` flag is
   mandatory, not defensive styling.
2. **Never call `process.exit()` from SDK code**, which would suppress the
   very hook being relied on.

#### What `beforeExit` does not cover

Ctrl-C is not an edge case for a CLI, and neither `beforeExit` nor `exit`
fires on SIGINT or SIGTERM. Nor do they help on `process.exit()` or an
uncaught throw. Covering those would mean installing signal handlers, which is
rejected above on citizenship grounds.

For those paths, delivery falls back to **durability**: `addEventToStore`
persists before the send, so a synchronous file-backed Node store leaves the
events in the tmp session cache for the next run to sweep (Storage, above). That is exactly the browser's
model. It works for a CLI invoked repeatedly; a genuinely one-shot tool killed
with Ctrl-C loses that tail, and no design short of signal handlers recovers
it.

#### Recommendation

Keep **automatic** session handling in headless, ended via a guarded
`beforeExit` handler — the same default as the browser, with a different
trigger. Do not force manual session handling. On this path, as in `onQuit()`,
the session cache file is deleted only after the final send resolves
(Storage, above); a failed send leaves it for the next run to sweep.

`onQuit()` remains, for callers who need determinism rather than best effort:
a daemon that installs its own SIGTERM handler, or a tool that calls
`process.exit()` explicitly, should `await ga.GameAnalytics.onQuit()` first.
This makes manual control available without making it mandatory, which also
keeps the headless and browser APIs behaving the same way.

#### Port `onQuit()` — but not its spin

`GameAnalytics::onQuit()` (`GameAnalytics.cpp:959`) queues the shutdown task,
then busy-waits:

```cpp
threading::GAThreading::performTaskOnGAThread([](){
    _endThread = true;
    state::GAState::endSessionAndStopQueue(true);
});

while (!threading::GAThreading::isThreadFinished())
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
```

**The spin must not be ported, and not merely on taste.** It is safe in C++
only because `GAThreading` owns a real `std::thread _thread`
(`GAThreading.h:74`): the calling thread sleeps while a *different* thread
drains the queue.

JavaScript has no such thread. `GAThreading` there is
`setInterval(GAThreading.run, 100)` on the one and only thread. A busy-wait
would block the very loop responsible for draining, so the condition it waits
on could never become true — a guaranteed deadlock, not a slow shutdown.

The contract survives; the mechanism does not:

```ts
static onQuit(): Promise<void>;   // resolves once the queue has drained
                                  // and the session cache file is deleted
```

```js
await ga.GameAnalytics.onQuit();
process.exit(0);
```

#### Event timing in headless

Discovered implementing the sample: `initAuthorized` (`GAState.ts:243`) has no
initializer, so `isEnabled()` is false until the init callback runs, and every
`add*Event` called before the init response is dropped with "SDK is disabled".
A browser page rarely hits that window; a CLI that does `initialize();
addEvent(); await onQuit()` hits it every time. The behaviour is pre-existing
and stays — changing existing calls is out of scope — so the headless idiom is
to add events from `onRemoteConfigsUpdated`, which `populateConfigurations()`
(`GameAnalytics.ts:822`) fires on every init outcome, after `initAuthorized`
is set and before the session starts; queued event tasks then run with the
session live. A dedicated "initialized" hook would be clearer and is a
candidate follow-up, but it is new API.

#### A dropped `session_end`, found by the sample

`GAEvents.processEvents` built the payload behind `if (eventDict.length != 0)`
— meant as a non-empty check, but a session_end event carries its own
`length` (session seconds), so any session under one second had its
`session_end` silently skipped, logged as sent, and deleted. The Node sample
showed it as "Sending 4 events" answered by "3 events sent". Latent in the
browser, where sessions are rarely that short; systematic for a CLI. Fixed by
checking for an object; the browser's only visible change is that sub-second
sessions now end.

#### "Enforcing" the call

The application must call `onQuit()` — the SDK will not hook process exit. But
a library cannot *make* a caller invoke a function, so enforcement here means
**making omission loud and cheap to diagnose**, not impossible.

This matters because the fix for the hang works against us. Once the task pump
is `unref()`'d so a process can exit naturally, a CLI that forgets `onQuit()`
exits *silently* with the tail of its queue unsent. The failure is invisible
at exactly the moment it costs data.

Recommended:

1. **Document `onQuit()` as required** in headless, in the README and the
   TypeScript doc comment.
2. **Warn on undrained exit.** Register a passive `process.on('exit')`
   listener that logs a warning naming the number of unsent events.
3. **Do not attempt to send from that listener.** `'exit'` handlers run
   synchronously during teardown; no async work can complete there. The
   listener diagnoses, it does not rescue.

`process.on('exit')` is deliberately not the thing rejected above. Adding a
`SIGINT` or `SIGTERM` listener *suppresses* Node's default termination and
takes over behaviour the host application expects to own. `'exit'` is a
passive notification: listeners coexist, nothing is intercepted, and the
process still exits exactly when it would have.

One mitigation comes free: an in-flight `fetch` holds a ref'd socket handle,
so a request already on the wire keeps the process alive until it completes.
The exposed window is events that are queued but whose send has not yet been
initiated — which is precisely what `onQuit()` closes.

`beforeunload` stays a browser-only detail registered inside the browser
platform, where `GameAnalytics.ts:84` does it today — not promoted to a
cross-platform interface. Both platforms keep automatic session handling;
only the end trigger differs.

#### The process will not exit regardless

Independent of the session model, `GAThreading.ts:19` starts a 100 ms task
pump in its constructor, and `instance` is a static field initialised at
**module load**:

```ts
private static readonly instance:GAThreading = new GAThreading();
// constructor:
setInterval(GAThreading.run, 100);
```

`stopEventQueue()` clears only `eventIntervalId`, the 8-second processing
interval — never this one. A Node process therefore stays alive forever after
merely importing the SDK, before `initialize()` is called, and regardless of
whether sessions are manual. Fixing this is mandatory: `unref()` the interval
and clear it in `onQuit()`, so a process can exit naturally while `onQuit()`
remains authoritative.

## Platform selection

C++ selects at compile time: `Platform/GADevicePlatform.h` aliases the right
subclass behind `IS_WIN32` / `IS_UWP` / `IS_LINUX` / `IS_MAC`, `#error`s on
anything unrecognised, and exposes `MakePlatform()` returning
`std::unique_ptr<GAPlatform>`.

The JavaScript analogue is the `exports` map. `package.json` already has an
`exports` block with `import`, `require` and `types`; this adds a `node`
condition:

```json
"exports": {
  ".": {
    "node":    "./dist/GameAnalytics.node.js",
    "import":  "./dist/GameAnalytics.esm.js",
    "require": "./dist/GameAnalytics.node.js",
    "types":   "./dist/GameAnalytics.d.ts"
  }
}
```

Plus a `makePlatform()` factory mirroring `MakePlatform()`, resolved per build
target. This keeps the C++ architecture intact and avoids `typeof` ladders in
shared code. Cost is one more gulp target and a second artifact to keep in
sync.

One deliberate difference: C++ hard-fails unknown platforms with
`#error unsupported platform!`. JavaScript cannot fail a consumer's build that
way, so unknown runtimes fall back to `GAPlatformBrowser` — safe precisely
because of the inherited sentinels.

## Health events

The two SDKs already disagree on this payload, so headless should not assume
parity. Current keys:

| C++ (`GAHealth.cpp`) | JS (`GAHealth.ts`) |
|---|---|
| `cpu_model`, `gpu_model`, `hardware` | same three |
| `cpu_num_cores` | `hardware_concurrency` |
| `memory_sys_total` | `memory_used_mb` |
| `app_boot_time` | — |
| `fps_data_table`, `memory_app_data_table`, `memory_sys_data_table` | — |
| — | `screen_width`, `screen_height`, `screen_resolution` |

`cpu_num_cores` and `hardware_concurrency` are the same measurement under two
names, and `GAPlatform.getNumCpuCores()` is the shared interface name for it.

**Decided: optional.** Renaming the JS payload key to match C++ is a nice-to-
have, not a blocker, and it would be a breaking change to the event schema.
Keep `hardware_concurrency` on the wire; the divergence is cosmetic and the
shared interface name already carries the intent.

C++ declares `_screenResolution` in `GAHealth.h:49` but never populates or
sends it — the screen fields are a JS-only addition. Headless has no screen,
so report `-1` / `""` rather than extending `GAPlatform` with a browser-only
concept.

Everything else moves to the platform object: `getGpuModel()`,
`getNumCpuCores()`, `getAppMemoryUsage()`, `getTotalDeviceMemory()`. The
existing `typeof` guards make `GAHealth` degrade rather than throw, but it
degrades to zeros — switch those to the sentinels.

## Divergences from the C++ SDK

Five places where the port departs from the C++ SDK. The first three are
forced by the runtime; the last two are choices, and each says so:

1. **Storage is an interface, not a path.** C++ models persistence purely as
   `getPersistentPath()`, because every supported platform has a filesystem,
   and `GAStore` is then a SQLite database (`sqlite3`, `GAStore.h`) at
   `<path>/<gameKey>/ga.sqlite3`. The browser has no filesystem, so a path
   cannot be the abstraction. `getPersistentPath()` stays on `GAPlatform` for
   parity and the Node *persistent tier* roots itself there — the session
   cache is in tmp (divergence 5) — but the read/write call shape has to be a
   key/value interface. The JS store also remains JSON rather than SQL
   rows — matching the C++ storage *engine* is out of scope.
2. **Blocking calls become promises.** `GAHttpClient::sendRequest` returns a
   `Response` synchronously, and `onQuit()` spins until the worker thread
   finishes. JavaScript has neither a usable synchronous HTTP nor a way to
   block, so both return promises. Parameter lists, the failure sentinel and
   the caller's contract are otherwise unchanged.
3. **No build-time hard failure.** `#error unsupported platform!` has no
   JavaScript equivalent; unknown runtimes fall back to the browser platform.
4. **Error reporting defaults off** — by choice, not constraint. C++ defaults
   `_enableErrorReporting = true`; the JS SDK has never reported crashes and
   defaulting on would change behaviour on upgrade. Opt-in via
   `setEnabledErrorReporting(true)`.
5. **The event queue lives in tmp, not the persistent path** — by choice.
   C++ keeps its whole store in `$HOME/GameAnalytics`, which survives until
   the user deletes it. The JS session cache is in `os.tmpdir()` — on macOS a
   per-user `/var/folders/…/T` directory, not `/tmp` — which the OS reaps on
   its own schedule. A crashed session's unsent tail therefore survives until
   the next run *or* the next tmp cleanup, whichever comes first. Accepted
   because the cache is meant to be ephemeral; the state that must outlive a
   session is in the persistent tier.

## Phasing

1. **Unblock import.** Guard `GameAnalytics.ts:84`, move `GADevice`'s static
   initializer. `require()` stops throwing. No new interfaces.
2. **`GAPlatform` + the two implementations.** `GADevice` takes ownership,
   `GAHealth` takes it by constructor injection.
3. **Storage + HTTP**, including store size management and the gzip decision.
4. **Shutdown.** Automatic sessions ended on a guarded `beforeExit`, port
   `onQuit()` as an awaitable, `unref()` the task pump.

Phase 1 is worth shipping alone — it converts a hard crash into a degraded but
working SDK, and it is a prerequisite for testing anything else.

## Testing

Current tests run under karma/Chrome headless, which is still a browser and
will not catch Node regressions. Headless needs a separate Node test target —
at minimum a smoke test asserting `require()` succeeds, `initialize()` runs,
and the process exits cleanly — run on the Node 18 leg specifically, since
that is where any API newer than the floor would surface. That test would have caught the current
breakage.

## Command-line clients

Added after running the Node build the way a bundled CLI would use it. Where an
item contradicts earlier text in this document, this section is the current
behaviour.

- **The retry tick skips while a request is in flight.** The 8 s tick used to
  start a new upload while the previous one was still waiting out its 10 s
  timeout, so with a collector that never answers there was always a request in
  flight, `beforeExit` never fired and `onQuit()` never resolved.
- **`onQuit(timeoutMs)` caps the wait.** When the time is up the Node HTTP
  client aborts open requests and fails later ones at once; the existing
  `NoResponse` path keeps the events in the session cache for a later run.
  Without an argument it waits for delivery, as before.
- **Tasks are held while the init request is in flight** and run in order when
  it resolves. `initialize(); addDesignEvent(); await onQuit()` now records the
  event. This replaces "Event timing in headless" above and applies to the
  browser build too.
- **`configureLogHandler(handler)`** routes every log line to the host instead
  of the console. **`configureWritablePath(dir)`** keeps both storage tiers
  under `dir/<gameKey>/`, the session cache in `sessions/`.
- **Orphan session caches are claimed by rename** to the adopting process's
  pid before they are read, so concurrent processes cannot adopt and resend
  the same file.
- **Nothing is written before `initialize()`.** The automatic drain on
  `beforeExit` used to save an empty store under an empty game key.
- **The Node build exports `gameanalytics`, `GameAnalytics` and `default` by
  name**, so named imports work from Node ESM; the declaration file exports the
  whole namespace and passes a strict check.

A command that must not wait for the network hands its event to a detached
helper process and exits; the helper runs the SDK with `onQuit(10000)`
(`app_node/command.js`). A long-running interactive tool uses the SDK
in-process and calls `onQuit(1000)` when it closes.

## Out of scope

- Porting the SQLite storage engine; the JS store stays key/value
- Deno / Bun / edge runtimes — the interfaces should not preclude them, but no
  adapters are planned
- Changing the *existing* public API; headless must behave identically for
  every current call. Two methods are **added**, both ports of public C++ API:
  `onQuit()` (`GameAnalytics.h:149`) and `setEnabledErrorReporting()`
  (`GameAnalytics.h:105`)
- **Browser crash reporting.** Node gets `uncaughtExceptionMonitor` (above);
  adding `window.onerror` / `unhandledrejection` to the browser platform is
  deferred, not rejected.
- **Signal-based crash capture.** C++ installs `SIGSEGV`-style handlers per
  platform; Node cannot meaningfully recover from those and installing signal
  handlers is rejected above.