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
        import ValidationResult = gameanalytics.validators.ValidationResult;

        export class GAEvents
        {
            private static readonly CategorySessionStart:string = "user";
            private static readonly CategorySessionEnd:string = "session_end";
            private static readonly CategoryDesign:string = "design";
            private static readonly CategoryBusiness:string = "business";
            private static readonly CategoryProgression:string = "progression";
            private static readonly CategoryResource:string = "resource";
            private static readonly CategoryError:string = "error";
            private static readonly CategoryAds:string = "ads";
            private static readonly MaxEventCount:number = 500;

            private static readonly MAX_ERROR_COUNT:number = 10;
            private static readonly countMap: { [key: string]: number } = {};
            private static readonly timestampMap: { [key: string]: Date } = {};

            private constructor()
            {

            }

            private static customEventFieldsErrorCallback(baseMessage:string, message:string): void
            {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }

                var now: Date = new Date();

                if (!GAEvents.timestampMap[baseMessage]) {
                    GAEvents.timestampMap[baseMessage] = now;
                }
                if (!GAEvents.countMap[baseMessage]) {
                    GAEvents.countMap[baseMessage] = 0;
                }
                var diff: number = now.getTime() - GAEvents.timestampMap[baseMessage].getTime();
                var diffSeconds: number = diff / 1000;
                if (diffSeconds >= 3600) {
                    GAEvents.timestampMap[baseMessage] = now;
                    GAEvents.countMap[baseMessage] = 0;
                }

                if (GAEvents.countMap[baseMessage] >= GAEvents.MAX_ERROR_COUNT) {
                    return;
                }

                gameanalytics.threading.GAThreading.performTaskOnGAThread(() => {
                    GAEvents.addErrorEvent(EGAErrorSeverity.Warning, message, null, true);
                    GAEvents.countMap[baseMessage] = GAEvents.countMap[baseMessage] + 1;
                });
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
                GAStore.setItem(GAState.getGameKey(), GAState.SessionNumKey, GAState.getSessionNum().toString());

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventDict);

                var fieldsToUse: { [id: string]: any } = GAState.instance.currentGlobalCustomEventFields;

                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

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

                var fieldsToUse: { [id: string]: any } = GAState.instance.currentGlobalCustomEventFields;

                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Add to store
                GAEvents.addEventToStore(eventDict);

                // Log
                GALogger.i("Add SESSION END event.");

                // Send all event right away
                GAEvents.processEvents("", false);
            }

            public static addBusinessEvent(currency:string, amount:number, itemType:string, itemId:string, cartType:string = null, fields:{[id:string]: any}, mergeFields:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate event params
                var validationResult:ValidationResult = GAValidator.validateBusinessEvent(currency, amount, cartType, itemType, itemId);
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }

                // Create empty eventData
                var eventDict:{[key:string]: any} = {};

                // Increment transaction number and persist
                GAState.incrementTransactionNum();
                GAStore.setItem(GAState.getGameKey(), GAState.TransactionNumKey, GAState.getTransactionNum().toString());

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

                var fieldsToUse: { [id: string]: any } = {};
                if(fields && Object.keys(fields).length > 0)
                {
                    for (let key in fields)
                    {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else
                {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }

                if (mergeFields && fields && Object.keys(fields).length > 0)
                {
                    for (let key in GAState.instance.currentGlobalCustomEventFields)
                    {
                        if (!fieldsToUse[key])
                        {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }

                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Log
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addResourceEvent(flowType:EGAResourceFlowType, currency:string, amount:number, itemType:string, itemId:string, fields:{[id:string]: any}, mergeFields:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate event params
                var validationResult:ValidationResult = GAValidator.validateResourceEvent(flowType, currency, amount, itemType, itemId, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes());
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
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

                var fieldsToUse: { [id: string]: any } = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (let key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }

                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }

                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Log
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addProgressionEvent(progressionStatus:EGAProgressionStatus, progression01:string, progression02:string, progression03:string, score:number, sendScore:boolean, fields:{[id:string]: any}, mergeFields:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var progressionStatusString:string = GAEvents.progressionStatusToString(progressionStatus);

                // Validate event params
                var validationResult:ValidationResult = GAValidator.validateProgressionEvent(progressionStatus, progression01, progression02, progression03);
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
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
                    eventDict["score"] = Math.round(score);
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

                var fieldsToUse: { [id: string]: any } = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (let key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }

                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }

                GAEvents.addCustomFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Log
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");

                // Send to store
                GAEvents.addEventToStore(eventDict);
            }

            public static addDesignEvent(eventId:string, value:number, sendValue:boolean, fields:{[id:string]: any}, mergeFields:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate
                var validationResult:ValidationResult = GAValidator.validateDesignEvent(eventId);
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
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

                var fieldsToUse: { [id: string]: any } = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (let key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }

                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }

                GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Log
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");

                // Send to store
                GAEvents.addEventToStore(eventData);
            }

            public static addErrorEvent(severity:EGAErrorSeverity, message:string, fields:{[id:string]: any}, mergeFields:boolean, skipAddingFields:boolean=false): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var severityString:string = GAEvents.errorSeverityToString(severity);

                // Validate
                var validationResult:ValidationResult = GAValidator.validateErrorEvent(severity, message);
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
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

                if(!skipAddingFields)
                {
                    var fieldsToUse: { [id: string]: any } = {};
                    if (fields && Object.keys(fields).length > 0) {
                        for (let key in fields) {
                            fieldsToUse[key] = fields[key];
                        }
                    }
                    else {
                        for (let key in GAState.instance.currentGlobalCustomEventFields) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }

                    if (mergeFields && fields && Object.keys(fields).length > 0) {
                        for (let key in GAState.instance.currentGlobalCustomEventFields) {
                            if (!fieldsToUse[key]) {
                                fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                            }
                        }
                    }

                    GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));
                }

                // Log
                GALogger.i("Add ERROR event: {severity:" + severityString + ", message:" + message + "}");

                // Send to store
                GAEvents.addEventToStore(eventData);
            }

            public static addAdEvent(adAction:EGAAdAction, adType:EGAAdType, adSdkName:string, adPlacement:string, noAdReason:EGAAdError, duration:number, sendDuration:boolean, fields:{[id:string]: any}, mergeFields:boolean): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var adActionString:string = GAEvents.adActionToString(adAction);
                var adTypeString:string = GAEvents.adTypeToString(adType);
                var noAdReasonString:string = GAEvents.adErrorToString(noAdReason);

                // Validate
                var validationResult:ValidationResult = GAValidator.validateAdEvent(adAction, adType, adSdkName, adPlacement);
                if (validationResult != null)
                {
                    GAHTTPApi.instance.sendSdkErrorEvent(validationResult.category, validationResult.area, validationResult.action, validationResult.parameter, validationResult.reason, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }

                // Create empty eventData
                var eventData:{[key:string]: any} = {};

                // Append event specifics
                eventData["category"] = GAEvents.CategoryAds;
                eventData["ad_sdk_name"] = adSdkName;
                eventData["ad_placement"] = adPlacement;
                eventData["ad_type"] = adTypeString;
                eventData["ad_action"] = adActionString;

                if(adAction == EGAAdAction.FailedShow && noAdReasonString.length > 0)
                {
                    eventData["ad_fail_show_reason"] = noAdReasonString;
                }

                if(sendDuration && (adType == EGAAdType.RewardedVideo || adType == EGAAdType.Video))
                {
                    eventData["ad_duration"] = duration;
                }

                // Add custom dimensions
                GAEvents.addDimensionsToEvent(eventData);

                var fieldsToUse: { [id: string]: any } = {};
                if (fields && Object.keys(fields).length > 0) {
                    for (let key in fields) {
                        fieldsToUse[key] = fields[key];
                    }
                }
                else {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                    }
                }

                if (mergeFields && fields && Object.keys(fields).length > 0) {
                    for (let key in GAState.instance.currentGlobalCustomEventFields) {
                        if (!fieldsToUse[key]) {
                            fieldsToUse[key] = GAState.instance.currentGlobalCustomEventFields[key];
                        }
                    }
                }

                GAEvents.addCustomFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                // Log
                GALogger.i("Add AD event: {ad_sdk_name:" + adSdkName + ", ad_placement:" + adPlacement + ", ad_type:" + adTypeString + ", ad_action:" + adActionString + ((adAction == EGAAdAction.FailedShow && noAdReasonString.length > 0) ? (", ad_fail_show_reason:" + noAdReasonString) : "") + ((sendDuration && (adType == EGAAdType.RewardedVideo || adType == EGAAdType.Video)) ? (", ad_duration:" + duration) : "") + "}");

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
                            var clientTs: number = eventDict["client_ts"] as number;
                            if (clientTs && !GAValidator.validateClientTs(clientTs))
                            {
                                delete eventDict["client_ts"];
                            }
                            payloadArray.push(eventDict);
                        }
                    }

                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e)
                {
                    GALogger.e("Error during ProcessEvents(): " + e.stack);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Json, EGASdkErrorArea.ProcessEvents, EGASdkErrorAction.JsonError, EGASdkErrorParameter.Undefined, e.stack, GAState.getGameKey(), GAState.getGameSecret());
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
                        GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Database, EGASdkErrorArea.AddEventsToStore, EGASdkErrorAction.DatabaseTooLarge, EGASdkErrorParameter.Undefined, "", GAState.getGameKey(), GAState.getGameSecret());
                        return;
                    }

                    // Get default annotations
                    var ev:{[key:string]: any} = GAState.getEventAnnotations();

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
                        GAEvents.updateSessionStore();
                    }

                    if(GAStore.isStorageAvailable())
                    {
                        GAStore.save(GAState.getGameKey());
                    }
                }
                catch (e)
                {
                    GALogger.e("addEventToStore: error");
                    GALogger.e(e.stack);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Database, EGASdkErrorArea.AddEventsToStore, EGASdkErrorAction.DatabaseTooLarge, EGASdkErrorParameter.Undefined, e.stack, GAState.getGameKey(), GAState.getGameSecret());
                }
            }

            private static updateSessionStore(): void
            {
                if(GAState.sessionIsStarted())
                {
                    var values:{[key:string]: any} = {};
                    values["session_id"] = GAState.instance.sessionId;
                    values["timestamp"] = GAState.getSessionStart();

                    var ev: { [key: string]: any } = GAState.getEventAnnotations();

                    // Add custom dimensions
                    GAEvents.addDimensionsToEvent(ev);

                    var fieldsToUse: { [id: string]: any } = GAState.instance.currentGlobalCustomEventFields;

                    GAEvents.addCustomFieldsToEvent(ev, GAState.validateAndCleanCustomFields(fieldsToUse, GAEvents.customEventFieldsErrorCallback));

                    values["event"] = GAUtilities.encode64(JSON.stringify(ev));
                    GAStore.insert(EGAStore.Sessions, values, true, "session_id");

                    if(GAStore.isStorageAvailable())
                    {
                        GAStore.save(GAState.getGameKey());
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

            private static addCustomFieldsToEvent(eventData:{[key:string]: any}, fields:{[key:string]: any}):void
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

            private static adActionToString(value:any): string
            {
                if(value == EGAAdAction.Clicked || value == EGAAdAction[EGAAdAction.Clicked])
                {
                    return "clicked";
                }
                else if(value == EGAAdAction.Show || value == EGAAdAction[EGAAdAction.Show])
                {
                    return "show";
                }
                else if(value == EGAAdAction.FailedShow || value == EGAAdAction[EGAAdAction.FailedShow])
                {
                    return "failed_show";
                }
                else if(value == EGAAdAction.RewardReceived || value == EGAAdAction[EGAAdAction.RewardReceived])
                {
                    return "reward_received";
                }
                else
                {
                    return "";
                }
            }

            private static adErrorToString(value:any): string
            {
                if(value == EGAAdError.Unknown || value == EGAAdError[EGAAdError.Unknown])
                {
                    return "unknown";
                }
                else if(value == EGAAdError.Offline || value == EGAAdError[EGAAdError.Offline])
                {
                    return "offline";
                }
                else if(value == EGAAdError.NoFill || value == EGAAdError[EGAAdError.NoFill])
                {
                    return "no_fill";
                }
                else if(value == EGAAdError.InternalError || value == EGAAdError[EGAAdError.InternalError])
                {
                    return "internal_error";
                }
                else if(value == EGAAdError.InvalidRequest || value == EGAAdError[EGAAdError.InvalidRequest])
                {
                    return "invalid_request";
                }
                else if(value == EGAAdError.UnableToPrecache || value == EGAAdError[EGAAdError.UnableToPrecache])
                {
                    return "unable_to_precache";
                }
                else
                {
                    return "";
                }
            }

            private static adTypeToString(value:any): string
            {
                if(value == EGAAdType.Video || value == EGAAdType[EGAAdType.Video])
                {
                    return "video";
                }
                else if(value == EGAAdType.RewardedVideo || value == EGAAdError[EGAAdType.RewardedVideo])
                {
                    return "rewarded_video";
                }
                else if(value == EGAAdType.Playable || value == EGAAdError[EGAAdType.Playable])
                {
                    return "playable";
                }
                else if(value == EGAAdType.Interstitial || value == EGAAdError[EGAAdType.Interstitial])
                {
                    return "interstitial";
                }
                else if(value == EGAAdType.OfferWall || value == EGAAdError[EGAAdType.OfferWall])
                {
                    return "offer_wall";
                }
                else if(value == EGAAdType.Banner || value == EGAAdError[EGAAdType.Banner])
                {
                    return "banner";
                }
                else
                {
                    return "";
                }
            }
        }
    }
}
