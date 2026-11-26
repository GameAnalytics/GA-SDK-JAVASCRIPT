module gameanalytics
{
    export module storage
    {
        import GALogger = gameanalytics.logging.GALogger;

        // Two-tier file store (spec, "Storage"):
        //   session cache   os.tmpdir()/GameAnalytics/<gameKey>/<pid>-<sessionId>.json
        //                   holds ga_event + ga_session; one file per session, so
        //                   concurrent processes never share a file; deleted after a
        //                   clean drain; a dirty exit leaves it for the next run.
        //   persistent      <getPersistentPath()>/<gameKey>/persistent.json
        //                   holds ga_progression + items (generated user id, cached
        //                   remote config, dimensions). Atomic temp+rename writes.
        // GAStore keeps writing its four keys exactly as before; this class routes
        // them by the key's store suffix.
        export class GAStorageNode implements IGAStorage
        {
            private static readonly MaxDbSizeBytesBeforeTrim:number = 5242880; // GAStore.cpp:20
            private static readonly TrimOrphanCount:number = 3;                // trimEventTable: 3 oldest sessions

            private fs:any; private os:any; private path:any;
            private gameKey:string = null;
            private sessionTier:{[store:string]: string} = {};
            private persistentTier:{[store:string]: string} = {};
            private lastPersistentWrite:string = null;
            private persistentLoaded:boolean = false;
            private swept:boolean = false;
            private sessionFile:string = null;
            private adoptedOrphans:string[] = [];

            public constructor()
            {
                this.fs = require("fs"); this.os = require("os"); this.path = require("path");
            }

            public isAvailable(): boolean { return true; }

            // ---- key routing --------------------------------------------------
            private static parse(key:string): {gameKey:string, store:string}
            {
                var parts:string[] = key.split("::");               // GA::{gameKey}::{store}
                return parts.length === 3 ? {gameKey: parts[1], store: parts[2]} : {gameKey: "", store: key};
            }
            private static isSessionStore(store:string): boolean { return store === "ga_event" || store === "ga_session"; }

            private tmpDir(): string
            {
                var custom:string = gameanalytics.device.GADevice.writablePath;
                return custom ? this.path.join(custom, this.gameKey, "sessions") : this.path.join(this.os.tmpdir(), "GameAnalytics", this.gameKey);
            }
            private persistDir(): string
            {
                return this.path.join(gameanalytics.device.GADevice.getWritablePath(), this.gameKey);
            }
            private persistFile(): string { return this.path.join(this.persistDir(), "persistent.json"); }

            // ---- reads ----------------------------------------------------------
            public getItem(key:string): string | null
            {
                var k = GAStorageNode.parse(key); this.gameKey = this.gameKey || k.gameKey;
                if (GAStorageNode.isSessionStore(k.store))
                {
                    this.sweepOrphans();
                    return k.store in this.sessionTier ? this.sessionTier[k.store] : null;
                }
                this.loadPersistent();
                return k.store in this.persistentTier ? this.persistentTier[k.store] : null;
            }

            private loadPersistent(): void
            {
                if (this.persistentLoaded) { return; }
                this.persistentLoaded = true;
                try
                {
                    var f:string = this.persistFile();
                    if (this.fs.existsSync(f))
                    {
                        var obj:any = JSON.parse(this.fs.readFileSync(f, "utf8"));
                        for (var s in obj) { this.persistentTier[s] = obj[s]; }
                        this.lastPersistentWrite = JSON.stringify(this.persistentTier);
                    }
                }
                catch (e) { GALogger.w("Persistent store unreadable, starting empty: " + e); }
            }

            // Runs once, from GAStore.load() before the first tick. Orphan = a session
            // file whose pid is gone (process.kill(pid, 0) -> ESRCH). Live sessions of
            // other processes are skipped: fixMissingSessionEndEvents() would otherwise
            // synthesise a session_end for a session that is still running.
            private sweepOrphans(): void
            {
                if (this.swept) { return; }
                this.swept = true;
                var dir:string = this.tmpDir();
                var orphans:Array<{file:string, events:any[], sessions:any[], newest:number, size:number}> = [];
                try
                {
                    if (!this.fs.existsSync(dir)) { return; }
                    var names:string[] = this.fs.readdirSync(dir);
                    for (var i = 0; i < names.length; ++i)
                    {
                        var match = /^(\d+)-(.+)\.json$/.exec(names[i]);
                        if (!match) { continue; }
                        var pid:number = parseInt(match[1], 10);
                        var alive:boolean = pid !== process.pid;
                        if (alive) { try { process.kill(pid, 0); } catch (e) { alive = (e && e.code !== "ESRCH"); } }
                        if (alive) { continue; }
                        var claimed:string = this.path.join(dir, process.pid + "-" + match[2] + ".json");
                        try { this.fs.renameSync(this.path.join(dir, names[i]), claimed); } catch (e) { continue; }
                        try
                        {
                            var obj:any = JSON.parse(this.fs.readFileSync(claimed, "utf8"));
                            var events:any[] = JSON.parse(obj["ga_event"] || "[]");
                            var sessions:any[] = JSON.parse(obj["ga_session"] || "[]");
                            var newest:number = 0;
                            for (var j = 0; j < events.length; ++j) { newest = Math.max(newest, Number(events[j]["client_ts"]) || 0); }
                            orphans.push({file: claimed, events: events, sessions: sessions, newest: newest, size: this.fs.statSync(claimed).size});
                        }
                        catch (e) { GALogger.w("Orphan session cache unreadable, deleting: " + claimed); try { this.fs.unlinkSync(claimed); } catch (_) {} }
                    }
                }
                catch (e) { GALogger.w("Session cache sweep failed: " + e); return; }

                // Trim (spec, "keep the C++ size logic"): if the orphans exceed the trim
                // threshold in aggregate, drop the 3 whose newest event is oldest.
                var total:number = 0; for (var o = 0; o < orphans.length; ++o) { total += orphans[o].size; }
                if (total > GAStorageNode.MaxDbSizeBytesBeforeTrim)
                {
                    orphans.sort((a, b) => a.newest - b.newest);
                    var drop = orphans.splice(0, GAStorageNode.TrimOrphanCount);
                    for (var d = 0; d < drop.length; ++d)
                    {
                        GALogger.w("Session cache over trim threshold; dropping oldest orphan: " + drop[d].file);
                        try { this.fs.unlinkSync(drop[d].file); } catch (_) {}
                    }
                }

                if (orphans.length === 0) { return; }
                var allEvents:any[] = [], allSessions:any[] = [];
                for (var a = 0; a < orphans.length; ++a)
                {
                    allEvents = allEvents.concat(orphans[a].events);
                    allSessions = allSessions.concat(orphans[a].sessions);
                    this.adoptedOrphans.push(orphans[a].file);   // released on first persist
                }
                this.sessionTier["ga_event"] = JSON.stringify(allEvents);
                this.sessionTier["ga_session"] = JSON.stringify(allSessions);
                GALogger.i("Adopted " + orphans.length + " orphan session cache(s): " + allEvents.length + " event(s), " + allSessions.length + " session(s)");
            }

            // ---- writes ---------------------------------------------------------
            public setItem(key:string, value:string): void
            {
                var k = GAStorageNode.parse(key); this.gameKey = this.gameKey || k.gameKey;
                if (GAStorageNode.isSessionStore(k.store)) { this.sessionTier[k.store] = value; this.flushSession(); }
                else { this.loadPersistent(); this.persistentTier[k.store] = value; this.flushPersistent(); }
            }

            public removeItem(key:string): void
            {
                var k = GAStorageNode.parse(key);
                if (GAStorageNode.isSessionStore(k.store)) { delete this.sessionTier[k.store]; this.flushSession(); }
                else { delete this.persistentTier[k.store]; this.flushPersistent(); }
            }

            // Named lazily: the session id exists only after the init round-trip.
            private flushSession(): void
            {
                if (!this.sessionFile)
                {
                    var sid:string = gameanalytics.state.GAState.getSessionId();
                    if (!sid) { return; }                              // memory only until a session exists
                    this.sessionFile = this.path.join(this.tmpDir(), process.pid + "-" + sid + ".json");
                }
                try
                {
                    this.fs.mkdirSync(this.tmpDir(), {recursive: true});
                    this.fs.writeFileSync(this.sessionFile, JSON.stringify({
                        ga_event: this.sessionTier["ga_event"] || "[]",
                        ga_session: this.sessionTier["ga_session"] || "[]"
                    }));
                    // Adopted orphan rows are now durable in this session's file.
                    while (this.adoptedOrphans.length) { try { this.fs.unlinkSync(this.adoptedOrphans.pop()); } catch (_) {} }
                }
                catch (e) { GALogger.w("Session cache write failed (" + (e && e.code) + "): events stay in memory"); }
            }

            private flushPersistent(): void
            {
                var json:string = JSON.stringify(this.persistentTier);
                if (json === this.lastPersistentWrite) { return; }     // written rarely, as the spec says
                try
                {
                    var dir:string = this.persistDir(); this.fs.mkdirSync(dir, {recursive: true});
                    var f:string = this.persistFile(), tmp:string = f + "." + process.pid + ".tmp";
                    this.fs.writeFileSync(tmp, json); this.fs.renameSync(tmp, f);
                    this.lastPersistentWrite = json;
                }
                catch (e) { GALogger.w("Persistent store write failed (" + (e && e.code) + ")"); }
            }

            public getSizeBytes(): number
            {
                try { return this.sessionFile && this.fs.existsSync(this.sessionFile) ? this.fs.statSync(this.sessionFile).size : 0; }
                catch (e) { return 0; }
            }

            public deleteSessionCache(): void
            {
                if (this.sessionFile) { try { this.fs.unlinkSync(this.sessionFile); } catch (_) {} }
                this.sessionTier = {};
            }
        }
    }
}
