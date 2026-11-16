module gameanalytics
{
    export module threading
    {
        import GALogger = gameanalytics.logging.GALogger;
        import GAState = gameanalytics.state.GAState;
        import GAEvents = gameanalytics.events.GAEvents;

        export class GAThreading
        {
            private static readonly instance:GAThreading = new GAThreading();
            private readonly taskQueue:Array<() => void> = [];
            private static eventIntervalId:ReturnType<typeof setInterval>;
            private static pumpId:ReturnType<typeof setInterval>;

            // In Node, an active interval keeps the process alive; unref() lets it exit
            // naturally once the application is done. No-op in the browser.
            private static unref(t:any): void { if (t && typeof t.unref === 'function') { t.unref(); } }
            private static ProcessEventsIntervalInSeconds:number = 8.0;
            private isRunning:boolean = false;

            private constructor()
            {
                GAThreading.pumpId = setInterval(GAThreading.run, 100);
                GAThreading.unref(GAThreading.pumpId);
            }

            // Run every queued task now. onQuit() uses this instead of waiting for the
            // 100 ms tick; the C++ busy-wait cannot be ported (spec, "not its spin").
            public static flush(): void { GAThreading.run(); }
            public static pendingTaskCount(): number { return GAThreading.instance.taskQueue.length; }
            public static stopPump(): void { clearInterval(GAThreading.pumpId); }

            public static performTaskOnGAThread(taskBlock:() => void): void
            {
                GAThreading.instance.taskQueue.push(taskBlock);
            }

            public static ensureEventQueueIsRunning(): void
            {
                if (!GAThreading.instance.isRunning)
                {
                    GAThreading.instance.isRunning = true;
                    GAThreading.eventIntervalId = setInterval(
                        () => GAThreading.performTaskOnGAThread(GAThreading.processEventQueue),
                        GAThreading.ProcessEventsIntervalInSeconds * 1000
                    );
                    GAThreading.unref(GAThreading.eventIntervalId);
                }
            }

            public static endSessionAndStopQueue(): void
            {
                if (GAState.isInitialized())
                {
                    GALogger.i("Ending session.");
                    GAThreading.stopEventQueue();
                    if (GAState.isEnabled() && GAState.sessionIsStarted())
                    {
                        GAEvents.addHealthEvent();
                        GAEvents.addSessionEndEvent();
                        GAState.instance.sessionStart = 0;
                    }
                }
            }

            public static stopEventQueue(): void
            {
                clearInterval(GAThreading.eventIntervalId);
                GAThreading.instance.isRunning = false;
            }

            public static setEventProcessInterval(interval:number): void
            {
                if (interval > 0)
                {
                    GAThreading.ProcessEventsIntervalInSeconds = interval;
                }
            }

            private static run(): void
            {
                while (GAThreading.instance.taskQueue.length > 0)
                {
                    const task = GAThreading.instance.taskQueue.shift();
                    if (task)
                    {
                        try { task(); }
                        catch (e: any)
                        {
                            GALogger.e("Error on GA thread");
                            GALogger.e(e.stack);
                        }
                    }
                }
            }

            private static processEventQueue(): void
            {
                GALogger.d("Processing event queue...");
                GAEvents.processEvents("", true);
            }
        }
    }
}
