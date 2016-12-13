module gameanalytics
{
    export module threading
    {
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;

        export class GAThreading
        {
            private static readonly instance:GAThreading = new GAThreading();
            private readonly blocks:PriorityQueue<TimedBlock> = new PriorityQueue<TimedBlock>(<IComparer<number>>{
                compare: (x:number, y:number) => {
                    return x - y;
                }
            });
            private readonly id2TimedBlockMap:{[key:number]: TimedBlock} = {};
            private static runTimeoutId:number;
            private static readonly ThreadWaitTimeInMs:number = 1000;
            private static readonly ProcessEventsIntervalInSeconds:number = 8.0;
            private keepRunning:boolean;
            private isRunning:boolean;

            private constructor()
            {
                GALogger.d("Initializing GA thread...");
                GAThreading.startThread();
            }

            public static performTaskOnGAThread(blockName:string, taskBlock:() => void, delayInSeconds:number = 0): void
            {
                var time:Date = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);

                var timedBlock = new TimedBlock(time, taskBlock, blockName);
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            }

            public static scheduleTimer(interval:number, blockName:string, callback:() => void): number
            {
                var time:Date = new Date();
                time.setSeconds(time.getSeconds() + interval);

                var timedBlock:TimedBlock = new TimedBlock(time, callback, blockName);
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);

                return timedBlock.id;
            }

            public static ensureEventQueueIsRunning(): void
            {
                GAThreading.instance.keepRunning = true;

                if(!GAThreading.instance.isRunning)
                {
                    GAThreading.instance.isRunning = true;
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, "processEventQueue", GAThreading.processEventQueue);
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
                            timedBlock.block();
                        }
                    }

                    GAThreading.runTimeoutId = setTimeout(GAThreading.run, GAThreading.ThreadWaitTimeInMs);
                    return;
                }
                catch (e)
                {
                    GALogger.e("Error on GA thread");
                    GALogger.e(e);
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
                    return GAThreading.instance.blocks.dequeue();
                }

                return null;
            }

            private static processEventQueue(): void
            {
                GAThreading.processEvents("", true);
                if(GAThreading.instance.keepRunning)
                {
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, "processEventQueue", GAThreading.processEventQueue);
                }
                else
                {
                    GAThreading.instance.isRunning = false;
                }
            }

            private static processEvents(category:string, performCleanUp:boolean): void
            {
                throw new Error("processEvents not implemented");
                // try
                // {
                //     var requestIdentifier:string = GAUtilities Guid.NewGuid().ToString();
                //
                //     string selectSql;
                //     string updateSql;
                //     string deleteSql = "DELETE FROM ga_events WHERE status = '" + requestIdentifier + "'";
                //     string putbackSql = "UPDATE ga_events SET status = 'new' WHERE status = '" + requestIdentifier + "';";
                //
                //     // Cleanup
                //     if(performCleanUp)
                //     {
                //         CleanupEvents();
                //         FixMissingSessionEndEvents();
                //     }
                //
                //     // Prepare SQL
                //     string andCategory = "";
                //     if(!string.IsNullOrEmpty(category))
                //     {
                //         andCategory = " AND category='" + category + "' ";
                //     }
                //     selectSql = "SELECT event FROM ga_events WHERE status = 'new' " + andCategory + ";";
                //     updateSql = "UPDATE ga_events SET status = '" + requestIdentifier + "' WHERE status = 'new' " + andCategory + ";";
                //
                //     // Get events to process
                //     JSONArray events = GAStore.ExecuteQuerySync(selectSql);
                //
                //     // Check for errors or empty
                //     if(events == null)
                //     {
                //         GALogger.I("Event queue: No events to send");
                //         return;
                //     }
                //
                //     // Check number of events and take some action if there are too many?
                //     if(events.Count > MaxEventCount)
                //     {
                //         // Make a limit request
                //         selectSql = "SELECT client_ts FROM ga_events WHERE status = 'new' " + andCategory + " ORDER BY client_ts ASC LIMIT 0," + MaxEventCount + ";";
                //         events = GAStore.ExecuteQuerySync(selectSql);
                //         if(events == null)
                //         {
                //             return;
                //         }
                //
                //         // Get last timestamp
                //         JSONNode lastItem = events[events.Count - 1];
                //         string lastTimestamp = lastItem["client_ts"].AsString;
                //
                //         // Select again
                //         selectSql = "SELECT event FROM ga_events WHERE status = 'new' " + andCategory + " AND client_ts<='" + lastTimestamp + "';";
                //         events = GAStore.ExecuteQuerySync(selectSql);
                //         if (events == null)
                //         {
                //             return;
                //         }
                //
                //         // Update sql
                //         updateSql = "UPDATE ga_events SET status='" + requestIdentifier + "' WHERE status='new' " + andCategory + " AND client_ts<='" + lastTimestamp + "';";
                //     }
                //
                //     // Log
                //     GALogger.I("Event queue: Sending " + events.Count + " events.");
                //
                //     // Set status of events to 'sending' (also check for error)
                //     if (GAStore.ExecuteQuerySync(updateSql) == null)
                //     {
                //         return;
                //     }
                //
                //     // Create payload data from events
                //     var payloadArray:Array<{[key:string]: any}> = [];
                //
                //     for (var i:number = 0; i < events.Count; ++i)
                //     {
                //         var ev:{[key:string]: any} = events[i];
                //         var eventDict = JSONNode.LoadFromBase64(ev["event"] as string);
                //         if (eventDict.Count != 0)
                //         {
                //             payloadArray.Add(eventDict);
                //         }
                //     }
                //
                //     GAHTTPApi.Instance.SendEventsInArray(payloadArray, putbackSql, deleteSql);
                // }
                // catch (e)
                // {
                //     GALogger.e("Error during ProcessEvents(): " + e);
                // }
            }
        }
    }
}
