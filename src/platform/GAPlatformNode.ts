module gameanalytics
{
    export module platform
    {
        import GALogger = gameanalytics.logging.GALogger;

        export class GAPlatformNode extends GAPlatform
        {
            private static readonly MaxErrorReports:number = 5;   // GAPlatform.cpp MAX_ERROR_TYPE_COUNT
            private os:any; private fs:any; private path:any;
            private errorCount:number = 0;
            private draining:boolean = false;

            public constructor()
            {
                super();
                this.os = require("os"); this.fs = require("fs"); this.path = require("path");
            }

            public getOSVersion(): string { return this.os.platform() + " " + this.os.release(); }
            public getDeviceManufacturer(): string { return ""; }
            public getBuildPlatform(): string { return this.os.platform(); }
            public getDeviceModel(): string { return this.os.arch() || ""; }

            // $HOME/GameAnalytics, created on demand — GALinux.cpp:118 does exactly this.
            public getPersistentPath(): string
            {
                var p:string = this.path.join(this.os.homedir(), "GameAnalytics");
                try { this.fs.mkdirSync(p, {recursive: true}); } catch (e) {}
                return p;
            }

            public getConnectionType(): string
            {
                try
                {
                    var ifs:any = this.os.networkInterfaces();
                    for (var name in ifs) { for (var i = 0; i < ifs[name].length; ++i) { if (!ifs[name][i].internal) { return "lan"; } } }
                }
                catch (e) {}
                return "offline";
            }

            public getCpuModel(): string { var c = this.os.cpus(); return c && c.length ? c[0].model : ""; }
            public getNumCpuCores(): number { var c = this.os.cpus(); return c && c.length ? c.length : -1; }
            public getTotalDeviceMemory(): number { return this.os.totalmem(); }
            public getAppMemoryUsage(): number { return process.memoryUsage().rss; }
            public getSysMemoryUsage(): number { return this.os.totalmem() - this.os.freemem(); }
            public getBootTime(): number { return Date.now() - Math.round(this.os.uptime() * 1000); }

            // Called unconditionally (where C++'s initPlatform() gates the call) so that
            // enabling error reporting after initialize() still works: the monitor is
            // idle until the flag is on, and a monitor never alters termination.
            public onInit(): void
            {
                this.setupUncaughtExceptionHandler();

                // Session end for headless (spec, "Session end: beforeExit, not exit").
                // Not gated on sessionIsStarted(): with the pump unref'd this can fire
                // before a queued initialize() has run; onQuit() flushes the queue.
                process.on("beforeExit", () => {
                    if (this.draining) { return; }             // re-entry guard, mandatory
                    this.draining = true;
                    gameanalytics.GameAnalytics.onQuit().catch((e:any) => GALogger.e("onQuit failed: " + e));
                });

                // Passive diagnosis only; 'exit' cannot complete async work.
                process.on("exit", () => {
                    try
                    {
                        var pending = gameanalytics.store.GAStore.select(gameanalytics.store.EGAStore.Events);
                        if (pending && pending.length > 0)
                        {
                            GALogger.w("Exiting with " + pending.length + " unsent event(s); call `await GameAnalytics.onQuit()` before exit.");
                        }
                    }
                    catch (e) {}
                });
            }

            // uncaughtExceptionMonitor, never uncaughtException: the latter suppresses
            // Node's default termination and would turn a crash into exit 0.
            public setupUncaughtExceptionHandler(): void
            {
                process.on("uncaughtExceptionMonitor", (err:any) => {
                    if (!gameanalytics.state.GAState.useErrorReporting()) { return; }
                    if (++this.errorCount > GAPlatformNode.MaxErrorReports) { return; }
                    try
                    {
                        // Persist only: the process is dying, no send can complete.
                        var msg:string = "Uncaught exception\n" + (err && err.stack ? err.stack : String(err));
                        gameanalytics.events.GAEvents.addErrorEvent(gameanalytics.EGAErrorSeverity.Critical, msg, {}, false);
                    }
                    catch (e) {}
                });
            }
        }
    }
}
