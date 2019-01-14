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
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Event specific data
                var eventDict:{[key:string]: any} = {};
                eventDict["category"] = GAEvents.CategorySessionStart;

                // Increment session number  and persist
                GAState.incrementSessionNum();
                GAStore.setItem(GAState.SessionNumKey, GAState.getSessionNum().toString());

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
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

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

            public static addBusinessEvent(currency:string, amount:number, itemType:string, itemId:string, cartType:string = null, fields:{[id:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

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
                GAStore.setItem(GAState.TransactionNumKey, GAState.getTransactionNum().toString());

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

                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));

                // Log
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addResourceEvent(flowType:EGAResourceFlowType, currency:string, amount:number, itemType:string, itemId:string, fields:{[id:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate event params
                if (!GAValidator.validateResourceEvent(flowType, currency, amount, itemType, itemId, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()))
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }

                // If flow type is sink reverse amount
                if (flowType === EGAResourceFlowType.Sink)
                {
                    amount *= -1;
                }

                // Create empty eventData
                var eventDict:{[key:string]: any} = {};

                // insert event specific values
                var flowTypeString:string = GAEvents.resourceFlowTypeToString(flowType);
                eventDict["event_id"] = flowTypeString + ":" + currency + ":" + itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryResource;
                eventDict["amount"] = amount;

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));

                // Log
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addProgressionEvent(progressionStatus:EGAProgressionStatus, progression01:string, progression02:string, progression03:string, score:number, sendScore:boolean, fields:{[id:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var progressionStatusString:string = GAEvents.progressionStatusToString(progressionStatus);

                // Validate event params
                if (!GAValidator.validateProgressionEvent(progressionStatus, progression01, progression02, progression03))
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }

                // Create empty eventData
                var eventDict:{[key:string]: any} = {};

                // Progression identifier
                var progressionIdentifier:string;

                if (!progression02)
                {
                    progressionIdentifier = progression01;
                }
                else if (!progression03)
                {
                    progressionIdentifier = progression01 + ":" + progression02;
                }
                else
                {
                    progressionIdentifier = progression01 + ":" + progression02 + ":" + progression03;
                }

                // Append event specifics
                eventDict["category"] = GAEvents.CategoryProgression;
                eventDict["event_id"] = progressionStatusString + ":" + progressionIdentifier;

                // Attempt
                var attempt_num:number = 0;

                // Add score if specified and status is not start
                if (sendScore && progressionStatus != EGAProgressionStatus.Start)
                {
                    eventDict["score"] = score;
                }

                // Count attempts on each progression fail and persist
                if (progressionStatus === EGAProgressionStatus.Fail)
                {
                    // Increment attempt number
                    GAState.incrementProgressionTries(progressionIdentifier);
                }

                // increment and add attempt_num on complete and delete persisted
                if (progressionStatus === EGAProgressionStatus.Complete)
                {
                    // Increment attempt number
                    GAState.incrementProgressionTries(progressionIdentifier);

                    // Add to event
                    attempt_num = GAState.getProgressionTries(progressionIdentifier);
                    eventDict["attempt_num"] = attempt_num;

                    // Clear
                    GAState.clearProgressionTries(progressionIdentifier);
                }

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));

                // Log
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addDesignEvent(eventId:string, value:number, sendValue:boolean, fields:{[id:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate
                if (!GAValidator.validateDesignEvent(eventId, value))
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }

                // Create empty eventData
                var eventData:{[key:string]: any} = {};

                // Append event specifics
                eventData["category"] = GAEvents.CategoryDesign;
                eventData["event_id"] = eventId;

                if(sendValue)
                {
                    eventData["value"] = value;
                }

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventData);

                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));

                // Log
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");

                // Send to store
                GAEvents.addEventToStore(eventData);
            }

            public static addErrorEvent(severity:EGAErrorSeverity, message:string, fields:{[id:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var severityString:string = GAEvents.errorSeverityToString(severity);

                // Validate
                if (!GAValidator.validateErrorEvent(severity, message))
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }

                // Create empty eventData
                var eventData:{[key:string]: any} = {};

                // Append event specifics
                eventData["category"] = GAEvents.CategoryError;
                eventData["severity"] = severityString;
                eventData["message"] = message;

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventData);

                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));

                // Log
                GALogger.i("Add ERROR event: {severity:" + severityString + ", message:" + message + "}");

                // Send to store
                GAEvents.addEventToStore(eventData);
            }

            public static processEvents(category:string, performCleanUp:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

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
                    if(!events || events.length == 0)
                    {
                        GALogger.i("Event queue: No events to send");
                        GAEvents.updateSessionStore();
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
                        var eventDict = JSON.parse(GAUtilities.decode64(ev["event"]));
                        if (eventDict.length != 0)
                        {
                            payloadArray.push(eventDict);
                        }
                    }

                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e)
                {
                    GALogger.e("Error during ProcessEvents(): " + e.stack);
                }
            }

            private static processEventsCallback(responseEnum:EGAHTTPApiResponse, dataDict:{[key:string]: any},  requestId:string, eventCount:number): void
            {
                var requestIdWhereArgs:Array<[string, EGAStoreArgsOperator, string]> = [];
                requestIdWhereArgs.push(["status", EGAStoreArgsOperator.Equal, requestId]);

                if(responseEnum === EGAHTTPApiResponse.Ok)
                {
                    // Delete events
                    GAStore.delete(EGAStore.Events, requestIdWhereArgs);
                    GALogger.i("Event queue: " + eventCount + " events sent.");
                }
                else
                {
                    // Put events back (Only in case of no response)
                    if(responseEnum === EGAHTTPApiResponse.NoResponse)
                    {
                        var setArgs:Array<[string, string]> = [];
                        setArgs.push(["status", "new"]);

                        GALogger.w("Event queue: Failed to send events to collector - Retrying next time");
                        GAStore.update(EGAStore.Events, setArgs, requestIdWhereArgs);
                        // Delete events (When getting some anwser back always assume events are processed)
                    }
                    else
                    {
                        if(dataDict)
                        {
                            var json:any;
                            var count:number = 0;
                            for(let j in dataDict)
                            {
                                if(count == 0)
                                {
                                    json = dataDict[j];
                                }
                                ++count;
                            }

                            if(responseEnum === EGAHTTPApiResponse.BadRequest && json.constructor === Array)
                            {
                                GALogger.w("Event queue: " + eventCount + " events sent. " + count + " events failed GA server validation.");
                            }
                            else
                            {
                                GALogger.w("Event queue: Failed to send events.");
                            }
                        }
                        else
                        {
                            GALogger.w("Event queue: Failed to send events.");
                        }

                        GAStore.delete(EGAStore.Events, requestIdWhereArgs);
                    }
                }
            }

            private static cleanupEvents(): void
            {
                GAStore.update(EGAStore.Events, [["status" , "new"]]);
            }

            private static fixMissingSessionEndEvents(): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Get all sessions that are not current
                var args:Array<[string, EGAStoreArgsOperator, string]> = [];
                args.push(["session_id", EGAStoreArgsOperator.NotEqual, GAState.getSessionId()]);

                var sessions:Array<{[key:string]: any}> = GAStore.select(EGAStore.Sessions, args);

                if (!sessions || sessions.length == 0)
                {
                    return;
                }

                GALogger.i(sessions.length + " session(s) located with missing session_end event.");

                // Add missing session_end events
                for (let i = 0; i < sessions.length; ++i)
                {
                    var sessionEndEvent:{[key:string]: any} = JSON.parse(GAUtilities.decode64(sessions[i]["event"] as string));
                    var event_ts:number = sessionEndEvent["client_ts"] as number;
                    var start_ts:number = sessions[i]["timestamp"] as number;

                    var length:number = event_ts - start_ts;
                    length = Math.max(0, length);

                    GALogger.d("fixMissingSessionEndEvents length calculated: " + length);

                    sessionEndEvent["category"] = GAEvents.CategorySessionEnd;
                    sessionEndEvent["length"] = length;

                    // Add to store
                    GAEvents.addEventToStore(sessionEndEvent);
                }
            }

            private static addEventToStore(eventData:{[key:string]: any}): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }
                
                // Check if we are initialized
                if (!GAState.isInitialized())
                {
                    GALogger.w("Could not add event: SDK is not initialized");
                    return;
                }

                try
                {
                    // Check db size limits (10mb)
                    // If database is too large block all except user, session and business
                    if (GAStore.isStoreTooLargeForEvents() && !GAUtilities.stringMatch(eventData["category"] as string, /^(user|session_end|business)$/))
                    {
                        GALogger.w("Database too large. Event has been blocked.");
                        return;
                    }

                    // Get default annotations
                    var ev:{[key:string]: any} = GAState.getEventAnnotations();

                    // Create json with only default annotations
                    var jsonDefaults:string = GAUtilities.encode64(JSON.stringify(ev));

                    // Merge with eventData
                    for(let e in eventData)
                    {
                        ev[e] = eventData[e];
                    }

                    // Create json string representation
                    var json:string = JSON.stringify(ev);

                    // output if VERBOSE LOG enabled

                    GALogger.ii("Event added to queue: " + json);

                    // Add to store
                    var values:{[key:string]: any} = {};
                    values["status"] = "new";
                    values["category"] = ev["category"];
                    values["session_id"] = ev["session_id"];
                    values["client_ts"] = ev["client_ts"];
                    values["event"] = GAUtilities.encode64(JSON.stringify(ev));

                    GAStore.insert(EGAStore.Events, values);

                    // Add to session store if not last
                    if (eventData["category"] == GAEvents.CategorySessionEnd)
                    {
                        GAStore.delete(EGAStore.Sessions, [["session_id", EGAStoreArgsOperator.Equal, ev["session_id"] as string]]);
                    }
                    else
                    {
                        values = {};
                        values["session_id"] = ev["session_id"];
                        values["timestamp"] = GAState.getSessionStart();
                        values["event"] = jsonDefaults;
                        GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    }

                    if(GAStore.isStorageAvailable())
                    {
                        GAStore.save();
                    }
                }
                catch (e)
                {
                    GALogger.e("addEventToStore: error");
                    GALogger.e(e.stack);
                }
            }

            private static updateSessionStore(): void
            {
                if(GAState.sessionIsStarted())
                {
                    var values:{[key:string]: any} = {};
                    values["session_id"] = GAState.instance.sessionId;
                    values["timestamp"] = GAState.getSessionStart();
                    values["event"] = GAUtilities.encode64(JSON.stringify(GAState.getEventAnnotations()));
                    GAStore.insert(EGAStore.Sessions, values, true, "session_id");

                    if(GAStore.isStorageAvailable())
                    {
                        GAStore.save();
                    }
                }
            }

            private static addDimensionsToEvent(eventData:{[key:string]: any}): void
            {
                if (!eventData)
                {
                    return;
                }
                // add to dict (if not nil)
                if (GAState.getCurrentCustomDimension01())
                {
                    eventData["custom_01"] = GAState.getCurrentCustomDimension01();
                }
                if (GAState.getCurrentCustomDimension02())
                {
                    eventData["custom_02"] = GAState.getCurrentCustomDimension02();
                }
                if (GAState.getCurrentCustomDimension03())
                {
                    eventData["custom_03"] = GAState.getCurrentCustomDimension03();
                }
            }

            private static addFieldsToEvent(eventData:{[key:string]: any}, fields:{[key:string]: any}):void
            {
                if(!eventData)
                {
                    return;
                }

                if(fields && Object.keys(fields).length > 0)
                {
                    eventData["custom_fields"] = fields;
                }
            }

            private static resourceFlowTypeToString(value:any): string
            {
                if(value == EGAResourceFlowType.Source || value == EGAResourceFlowType[EGAResourceFlowType.Source])
                {
                    return "Source";
                }
                else if(value == EGAResourceFlowType.Sink || value == EGAResourceFlowType[EGAResourceFlowType.Sink])
                {
                    return "Sink";
                }
                else
                {
                    return "";
                }
            }

            private static progressionStatusToString(value:any): string
            {
                if(value == EGAProgressionStatus.Start || value == EGAProgressionStatus[EGAProgressionStatus.Start])
                {
                    return "Start";
                }
                else if(value == EGAProgressionStatus.Complete || value == EGAProgressionStatus[EGAProgressionStatus.Complete])
                {
                    return "Complete";
                }
                else if(value == EGAProgressionStatus.Fail || value == EGAProgressionStatus[EGAProgressionStatus.Fail])
                {
                    return "Fail";
                }
                else
                {
                    return "";
                }
            }

            private static errorSeverityToString(value:any): string
            {
                if(value == EGAErrorSeverity.Debug || value == EGAErrorSeverity[EGAErrorSeverity.Debug])
                {
                    return "debug";
                }
                else if(value == EGAErrorSeverity.Info || value == EGAErrorSeverity[EGAErrorSeverity.Info])
                {
                    return "info";
                }
                else if(value == EGAErrorSeverity.Warning || value == EGAErrorSeverity[EGAErrorSeverity.Warning])
                {
                    return "warning";
                }
                else if(value == EGAErrorSeverity.Error || value == EGAErrorSeverity[EGAErrorSeverity.Error])
                {
                    return "error";
                }
                else if(value == EGAErrorSeverity.Critical || value == EGAErrorSeverity[EGAErrorSeverity.Critical])
                {
                    return "critical";
                }
                else
                {
                    return "";
                }
            }
        }
    }
}
