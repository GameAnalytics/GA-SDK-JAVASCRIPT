module gameanalytics
{
    export module events
    {
        import GAStore = gameanalytics.store.GAStore;
        import EGAStore = gameanalytics.store.EGAStore;
        import EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        import GAState = gameanalytics.state.GAState;
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
        import GAHTTPApi = gameanalytics.http.GAHTTPApi;
        import GAValidator = gameanalytics.validators.GAValidator;
        import EGASdkErrorType = gameanalytics.http.EGASdkErrorType;

        export class GAEvents
        {
            private static readonly instance:GAEvents = new GAEvents();
            private static readonly CategorySessionStart:string = "user";
            private static readonly CategorySessionEnd:string = "session_end";
            private static readonly CategoryDesign:string = "design";
            private static readonly CategoryBusiness:string = "business";
            private static readonly CategoryProgression:string = "progression";
            private static readonly CategoryResource:string = "resource";
            private static readonly CategoryError:string = "error";
            private static readonly MaxEventCount:number = 500;

            private constructor()
            {

            }

            public static addSessionStartEvent(): void
            {
                // Event specific data
                var eventDict:{[key:string]: any} = {};
                eventDict["category"] = GAEvents.CategorySessionStart;

                // Increment session number  and persist
                GAState.incrementSessionNum();
                GAStore.setState(GAState.SessionNumKey, GAState.getSessionNum().toString());

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                // Add to store
                GAEvents.addEventToStore(eventDict);

                // Log
                GALogger.i("Add SESSION START event");

                // Send event right away
                GAEvents.processEvents(GAEvents.CategorySessionStart, false);
            }

            public static addSessionEndEvent(): void
            {
                var session_start_ts:number = GAState.getSessionStart();
                var client_ts_adjusted:number = GAState.getClientTsAdjusted();
                var sessionLength:number = client_ts_adjusted - session_start_ts;

                if(sessionLength < 0)
                {
                    // Should never happen.
                    // Could be because of edge cases regarding time altering on device.
                    GALogger.w("Session length was calculated to be less then 0. Should not be possible. Resetting to 0.");
                    sessionLength = 0;
                }

                // Event specific data
                var eventDict:{[key:string]: any} = {};
                eventDict["category"] = GAEvents.CategorySessionEnd;
                eventDict["length"] = sessionLength;

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                // Add to store
                GAEvents.addEventToStore(eventDict);

                // Log
                GALogger.i("Add SESSION END event.");

                // Send all event right away
                GAEvents.processEvents("", false);
            }

            public static addBusinessEvent(currency:string, amount:number, itemType:string, itemId:string, cartType:string = null): void
            {
                // Validate event params
                if (!GAValidator.validateBusinessEvent(currency, amount, cartType, itemType, itemId))
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }

                // Create empty eventData
                var eventDict:{[key:string]: any} = {};

                // Increment transaction number and persist
                GAState.incrementTransactionNum();
                GAStore.setState(GAState.TransactionNumKey, GAState.getTransactionNum().toString());

                // Required
                eventDict["event_id"] = itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryBusiness;
                eventDict["currency"] = currency;
                eventDict["amount"] = amount;
                eventDict[GAState.TransactionNumKey] = GAState.getTransactionNum();

                // Optional
                if (cartType)
                {
                    eventDict["cart_type"] = cartType;
                }

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                // Log
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            private static processEventsCallback(responseEnum:EGAHTTPApiResponse, dataDict:{[key:string]: any},  requestId:string, eventCount:number): void
            {
                // var requestIdWhereArgs:Array<[string, EGAStoreArgsOperator, string]> = [];
                // requestIdWhereArgs.push(["status", EGAStoreArgsOperator.Equal, requestId]);
                throw new Error("processEvents not implemented");
            }

            private static cleanupEvents(): void
            {
                GAStore.update(EGAStore.Events, [["status" , "new"]]);
            }

            public static processEvents(category:string, performCleanUp:boolean): void
            {
                // throw new Error("processEvents not implemented");
                try
                {
                    var requestIdentifier:string = GAUtilities.createGuid();

                    // Cleanup
                    if(performCleanUp)
                    {
                        GAEvents.cleanupEvents();
                        GAEvents.fixMissingSessionEndEvents();
                    }

                    // Prepare SQL
                    var selectArgs:Array<[string, EGAStoreArgsOperator, string]> = [];
                    selectArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);

                    var updateWhereArgs:Array<[string, EGAStoreArgsOperator, string]> = [];
                    updateWhereArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);
                    if(category)
                    {
                        selectArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                        updateWhereArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                    }

                    var updateSetArgs:Array<[string, string]> = [];
                    updateSetArgs.push(["status", requestIdentifier]);

                    // Get events to process
                    var events:Array<{[key:string]: any}> = GAStore.select(EGAStore.Events, selectArgs);

                    // Check for errors or empty
                    if(!events)
                    {
                        GALogger.i("Event queue: No events to send");
                        return;
                    }

                    // Check number of events and take some action if there are too many?
                    if(events.length > GAEvents.MaxEventCount)
                    {
                        // Make a limit request
                        events = GAStore.select(EGAStore.Events, selectArgs, true, GAEvents.MaxEventCount);
                        if(!events)
                        {
                            return;
                        }

                        // Get last timestamp
                        var lastItem:{[key:string]: any} = events[events.length - 1];
                        var lastTimestamp:string = lastItem["client_ts"] as string;

                        selectArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);

                        // Select again
                        events = GAStore.select(EGAStore.Events, selectArgs);
                        if (!events)
                        {
                            return;
                        }

                        updateWhereArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);
                    }

                    // Log
                    GALogger.i("Event queue: Sending " + events.length + " events.");

                    // Set status of events to 'sending' (also check for error)
                    if (!GAStore.update(EGAStore.Events, updateSetArgs, updateWhereArgs))
                    {
                        return;
                    }

                    // Create payload data from events
                    var payloadArray:Array<{[key:string]: any}> = [];

                    for (var i:number = 0; i < events.length; ++i)
                    {
                        var ev:{[key:string]: any} = events[i];
                        var eventDict = JSON.parse(atob(ev["event"]));
                        if (eventDict.length != 0)
                        {
                            payloadArray.push(eventDict);
                        }
                    }

                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e)
                {
                    GALogger.e("Error during ProcessEvents(): " + e);
                }
            }

            private static fixMissingSessionEndEvents(): void
            {
                // Get all sessions that are not current
                var args:Array<[string, EGAStoreArgsOperator, string]> = [];
                args.push(["session_id", EGAStoreArgsOperator.NotEqual, GAState.getSessionId()]);

                var sessions:Array<{[key:string]: any}> = GAStore.select(EGAStore.Sessions, args);

                if (!sessions)
                {
                    return;
                }

                GALogger.i(sessions.length + " session(s) located with missing session_end event.");

                // Add missing session_end events
                for (let session in sessions)
                {
                    var sessionEndEvent:{[key:string]: any} = JSON.parse(GAUtilities.decode64(session["event"] as string));
                    var event_ts:number = sessionEndEvent["client_ts"] as number;
                    var start_ts:number = session["timestamp"] as number;

                    var length:number = event_ts - start_ts;
                    length = Math.max(0, length);

                    GALogger.d("fixMissingSessionEndEvents length calculated: " + length);

                    sessionEndEvent["category"] = GAEvents.CategorySessionEnd;
                    sessionEndEvent["length"] = length;

                    // Add to store
                    GAEvents.addEventToStore(sessionEndEvent);
                }
            }

            private static addEventToStore(event:{[key:string]: any}): void
            {
                throw new Error("addEventToStore not implemented");
            }
        }
    }
}
