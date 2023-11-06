module gameanalytics
{
    export module threading
    {
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GAStore = gameanalytics.store.GAStore;
        import EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        import EGAStore = gameanalytics.store.EGAStore;
        import GAState = gameanalytics.state.GAState;
        import GAEvents = gameanalytics.events.GAEvents;
        import GAHTTPApi = gameanalytics.http.GAHTTPApi;

        export class GAThreading
        {
            private static readonly instance:GAThreading = new GAThreading();
            public readonly blocks:PriorityQueue<TimedBlock> = new PriorityQueue<TimedBlock>(<IComparer<number>>{
                compare: (x:number, y:number) => {
                    return x - y;
                }
            });
            private readonly id2TimedBlockMap:{[key:number]: TimedBlock} = {};
            private static runTimeoutId:NodeJS.Timeout;
            private static readonly ThreadWaitTimeInMs:number = 1000;
            private static ProcessEventsIntervalInSeconds:number = 8.0;
            private keepRunning:boolean;
            private isRunning:boolean;

            private constructor()
            {
                GALogger.d("Initializing GA thread...");
                GAThreading.startThread();
            }

            public static createTimedBlock(delayInSeconds:number = 0): TimedBlock
            {
                var time:Date = new Date();
                time.setUTCSeconds(time.getUTCSeconds() + delayInSeconds);

                var timedBlock:TimedBlock = new TimedBlock(time);
                return timedBlock;
            }

            public static performTaskOnGAThread(taskBlock:() => void, delayInSeconds:number = 0): void
            {
                var time:Date = new Date();
                time.setUTCSeconds(time.getUTCSeconds() + delayInSeconds);

                var timedBlock:TimedBlock = new TimedBlock(time);
                timedBlock.block = taskBlock;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            }

            public static performTimedBlockOnGAThread(timedBlock:TimedBlock): void
            {
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            }

            public static scheduleTimer(interval:number, callback:() => void): number
            {
                var time:Date = new Date();
                time.setUTCSeconds(time.getUTCSeconds() + interval);

                var timedBlock:TimedBlock = new TimedBlock(time);
                timedBlock.block = callback;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);

                return timedBlock.id;
            }

            public static getTimedBlockById(blockIdentifier:number): TimedBlock
            {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap)
                {
                    return GAThreading.instance.id2TimedBlockMap[blockIdentifier]
                }
                else
                {
                    return null;
                }
            }

            public static ensureEventQueueIsRunning(): void
            {
                GAThreading.instance.keepRunning = true;

                if(!GAThreading.instance.isRunning)
                {
                    GAThreading.instance.isRunning = true;
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
            }

            public static endSessionAndStopQueue(): void
            {
                if(GAState.isInitialized())
                {
                    GALogger.i("Ending session.");
                    GAThreading.stopEventQueue();
                    if (GAState.isEnabled() && GAState.sessionIsStarted())
                    {
                        GAEvents.addSessionEndEvent();
                        GAState.instance.sessionStart = 0;
                    }
                }
            }

            public static stopEventQueue(): void
            {
                GAThreading.instance.keepRunning = false;
            }

            public static ignoreTimer(blockIdentifier:number): void
            {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap)
                {
                    GAThreading.instance.id2TimedBlockMap[blockIdentifier].ignore = true;
                }
            }

            public static setEventProcessInterval(interval:number): void
            {
                if (interval > 0)
                {
                    GAThreading.ProcessEventsIntervalInSeconds = interval;
                }
            }

            private addTimedBlock(timedBlock:TimedBlock): void
            {
                this.blocks.enqueue(timedBlock.deadline.getTime(), timedBlock);
            }

            private static run(): void
            {
                clearTimeout(GAThreading.runTimeoutId);

                try
                {
                    var timedBlock:TimedBlock;

                    while ((timedBlock = GAThreading.getNextBlock()))
                    {
                        if (!timedBlock.ignore)
                        {
                            if(timedBlock.async)
                            {
                                if(!timedBlock.running)
                                {
                                    timedBlock.running = true;
                                    timedBlock.block();
                                    break;
                                }
                            }
                            else
                            {
                                timedBlock.block();
                            }
                        }
                    }

                    GAThreading.runTimeoutId = setTimeout(GAThreading.run, GAThreading.ThreadWaitTimeInMs);
                    return;
                }
                catch (e)
                {
                    GALogger.e("Error on GA thread");
                    GALogger.e(e.stack);
                }
                GALogger.d("Ending GA thread");
            }

            private static startThread(): void
            {
                GALogger.d("Starting GA thread");
                GAThreading.runTimeoutId = setTimeout(GAThreading.run, 0);
            }

            private static getNextBlock(): TimedBlock
            {
                var now:Date = new Date();

                if (GAThreading.instance.blocks.hasItems() && GAThreading.instance.blocks.peek().deadline.getTime() <= now.getTime())
                {
                    if(GAThreading.instance.blocks.peek().async)
                    {
                        if(GAThreading.instance.blocks.peek().running)
                        {
                            return GAThreading.instance.blocks.peek();
                        }
                        else
                        {
                            return GAThreading.instance.blocks.dequeue();
                        }
                    }
                    else
                    {
                        return GAThreading.instance.blocks.dequeue();
                    }
                }

                return null;
            }

            private static processEventQueue(): void
            {
                GAEvents.processEvents("", true);
                if(GAThreading.instance.keepRunning)
                {
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
                else
                {
                    GAThreading.instance.isRunning = false;
                }
            }
        }
    }
}
