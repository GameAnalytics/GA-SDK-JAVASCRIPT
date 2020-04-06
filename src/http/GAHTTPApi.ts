module gameanalytics
{
    export module http
    {
        import GAState = gameanalytics.state.GAState;
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GAValidator = gameanalytics.validators.GAValidator;
        import SdkErrorTask = gameanalytics.tasks.SdkErrorTask;
        import EGASdkErrorCategory = gameanalytics.events.EGASdkErrorCategory;
        import EGASdkErrorArea = gameanalytics.events.EGASdkErrorArea;
        import EGASdkErrorAction = gameanalytics.events.EGASdkErrorAction;
        import EGASdkErrorParameter = gameanalytics.events.EGASdkErrorParameter;

        export class GAHTTPApi
        {
            public static readonly instance:GAHTTPApi = new GAHTTPApi();
            private protocol:string;
            private hostName:string;
            private version:string;
            private remoteConfigsVersion:string;
            private baseUrl:string;
            private remoteConfigsBaseUrl:string;
            private initializeUrlPath:string;
            private eventsUrlPath:string;
            private useGzip:boolean;
            private static readonly MAX_ERROR_MESSAGE_LENGTH:number = 256;

            private constructor()
            {
                // base url settings
                this.protocol = "https";
                this.hostName = "api.gameanalytics.com";
                this.version = "v2";
                this.remoteConfigsVersion = "v1";

                // create base url
                this.baseUrl = this.protocol + "://" + this.hostName + "/" + this.version;
                this.remoteConfigsBaseUrl = this.protocol + "://" + this.hostName + "/remote_configs/" + this.remoteConfigsVersion;

                this.initializeUrlPath = "init";
                this.eventsUrlPath = "events";

                this.useGzip = false;
            }

            public requestInit(configsHash:string, callback:(response:EGAHTTPApiResponse, json:{[key:string]: any}) => void): void
            {
                var gameKey:string = GAState.getGameKey();

                // Generate URL
                var url:string = this.remoteConfigsBaseUrl + "/" + this.initializeUrlPath + "?game_key=" + gameKey + "&interval_seconds=0&configs_hash=" + configsHash;
                GALogger.d("Sending 'init' URL: " + url);

                var initAnnotations:{[key:string]: any} = GAState.getInitAnnotations();

                // make JSON string from data
                var JSONstring:string = JSON.stringify(initAnnotations);

                if(!JSONstring)
                {
                    callback(EGAHTTPApiResponse.JsonEncodeFailed, null);
                    return;
                }

                var payloadData:string = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs:Array<string> = [];
                extraArgs.push(JSONstring);
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.initRequestCallback, callback);
            }

            public sendEventsInArray(eventArray:Array<{[key:string]: any}>, requestId:string, callback:(response:EGAHTTPApiResponse, json:{[key:string]: any}, requestId:string, eventCount:number) => void): void
            {
                if(eventArray.length == 0)
                {
                    GALogger.d("sendEventsInArray called with missing eventArray");
                    return;
                }

                var gameKey:string = GAState.getGameKey();

                // Generate URL
                var url:string = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);

                // make JSON string from data
                var JSONstring:string = JSON.stringify(eventArray);

                if(!JSONstring)
                {
                    GALogger.d("sendEventsInArray JSON encoding failed of eventArray");
                    callback(EGAHTTPApiResponse.JsonEncodeFailed, null, requestId, eventArray.length);
                    return;
                }

                var payloadData = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs:Array<string> = [];
                extraArgs.push(JSONstring);
                extraArgs.push(requestId);
                extraArgs.push(eventArray.length.toString());
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.sendEventInArrayRequestCallback, callback);
            }

            public sendSdkErrorEvent(category:EGASdkErrorCategory, area:EGASdkErrorArea, action:EGASdkErrorAction, parameter:EGASdkErrorParameter, reason:string, gameKey:string, secretKey:string): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                // Validate
                if (!GAValidator.validateSdkErrorEvent(gameKey, secretKey, category, area, action))
                {
                    return;
                }

                // Generate URL
                var url:string = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);

                var payloadJSONString:string = "";
                var errorType:string = ""

                var json:{[key:string]: any} = GAState.getSdkErrorEventAnnotations();

                var categoryString:string = GAHTTPApi.sdkErrorCategoryString(category);
                json["error_category"] = categoryString;
                errorType += categoryString;

                var areaString:string = GAHTTPApi.sdkErrorAreaString(area);
                json["error_area"] = areaString;
                errorType += ":" + areaString;

                var actionString:string = GAHTTPApi.sdkErrorActionString(action);
                json["error_action"] = actionString;

                var parameterString:string = GAHTTPApi.sdkErrorParameterString(parameter);
                if(parameterString.length > 0)
                {
                    json["error_parameter"] = parameterString;
                }

                if(reason.length > 0)
                {
                    var reasonTrimmed = reason;
                    if(reason.length > GAHTTPApi.MAX_ERROR_MESSAGE_LENGTH)
                    {
                        var reasonTrimmed = reason.substring(0, GAHTTPApi.MAX_ERROR_MESSAGE_LENGTH);
                    }
                    json["reason"] = reasonTrimmed;
                }

                var eventArray:Array<{[key:string]: any}> = [];
                eventArray.push(json);
                payloadJSONString = JSON.stringify(eventArray);

                if(!payloadJSONString)
                {
                    GALogger.w("sendSdkErrorEvent: JSON encoding failed.");
                    return;
                }

                GALogger.d("sendSdkErrorEvent json: " + payloadJSONString);
                SdkErrorTask.execute(url, errorType, payloadJSONString, secretKey);
            }

            private static sendEventInArrayRequestCallback(request:XMLHttpRequest, url:string, callback:(response:EGAHTTPApiResponse, json:{[key:string]: any}, requestId:string, eventCount:number) => void, extra:Array<string> = null): void
            {
                var authorization:string = extra[0];
                var JSONstring:string = extra[1];
                var requestId:string = extra[2];
                var eventCount:number = parseInt(extra[3]);
                var body:string = "";
                var responseCode:number = 0;

                body = request.responseText;
                responseCode = request.status;

                GALogger.d("events request content: " + body);

                var requestResponseEnum:EGAHTTPApiResponse = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Events");

                // if not 200 result
                if(requestResponseEnum != EGAHTTPApiResponse.Ok && requestResponseEnum != EGAHTTPApiResponse.Created && requestResponseEnum != EGAHTTPApiResponse.BadRequest)
                {
                    GALogger.d("Failed events Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, requestId, eventCount);
                    return;
                }

                // decode JSON
                var requestJsonDict:{[key:string]: any} = body ? JSON.parse(body) : {};

                if(requestJsonDict == null)
                {
                    callback(EGAHTTPApiResponse.JsonDecodeFailed, null, requestId, eventCount);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Http, EGASdkErrorArea.EventsHttp, EGASdkErrorAction.FailHttpJsonDecode, EGASdkErrorParameter.Undefined, body, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }

                // print reason if bad request
                if(requestResponseEnum == EGAHTTPApiResponse.BadRequest)
                {
                    GALogger.d("Failed Events Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                }

                // return response
                callback(requestResponseEnum, requestJsonDict, requestId, eventCount);
            }

            private static sendRequest(url:string, payloadData:string, extraArgs:Array<string>, gzip:boolean, callback:(request:XMLHttpRequest, url:string, callback:(response:EGAHTTPApiResponse, json:{[key:string]: any}, requestId:string, eventCount:number) => void, extra:Array<string>) => void, callback2:(response:EGAHTTPApiResponse, json:{[key:string]: any}, requestId:string, eventCount:number) => void): void
            {
                var request:XMLHttpRequest = new XMLHttpRequest();

                // create authorization hash
                var key:string = GAState.getGameSecret();
                var authorization:string = GAUtilities.getHmac(key, payloadData);

                var args:Array<string> = [];
                args.push(authorization);

                for(let s in extraArgs)
                {
                    args.push(extraArgs[s]);
                }

                request.onreadystatechange = () => {
                    if(request.readyState === 4)
                    {
                        callback(request, url, callback2, args);
                    }
                };

                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");

                request.setRequestHeader("Authorization", authorization);

                if(gzip)
                {
                    throw new Error("gzip not supported");
                    //request.setRequestHeader("Content-Encoding", "gzip");
                }

                try
                {
                    request.send(payloadData);
                }
                catch(e)
                {
                    console.error(e.stack);
                }
            }

            private static initRequestCallback(request:XMLHttpRequest, url:string, callback:(response:EGAHTTPApiResponse, json:{[key:string]: any}, requestId:string, eventCount:number) => void, extra:Array<string> = null): void
            {
                var authorization:string = extra[0];
                var JSONstring:string = extra[1];
                var body:string = "";
                var responseCode:number = 0;

                body = request.responseText;
                responseCode = request.status;

                // process the response
                GALogger.d("init request content : " + body + ", JSONstring: " + JSONstring);

                var requestJsonDict:{[key:string]: any} = body ? JSON.parse(body) : {};
                var requestResponseEnum:EGAHTTPApiResponse = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Init");

                // if not 200 result
                if(requestResponseEnum != EGAHTTPApiResponse.Ok && requestResponseEnum != EGAHTTPApiResponse.Created && requestResponseEnum != EGAHTTPApiResponse.BadRequest)
                {
                    GALogger.d("Failed Init Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }

                if(requestJsonDict == null)
                {
                    GALogger.d("Failed Init Call. Json decoding failed");
                    callback(EGAHTTPApiResponse.JsonDecodeFailed, null, "", 0);
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorCategory.Http, EGASdkErrorArea.InitHttp, EGASdkErrorAction.FailHttpJsonDecode, EGASdkErrorParameter.Undefined, body, GAState.getGameKey(), GAState.getGameSecret());
                    return;
                }

                // print reason if bad request
                if(requestResponseEnum === EGAHTTPApiResponse.BadRequest)
                {
                    GALogger.d("Failed Init Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                    // return bad request result
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }

                // validate Init call values
                var validatedInitValues:{[key:string]: any} = GAValidator.validateAndCleanInitRequestResponse(requestJsonDict, requestResponseEnum === EGAHTTPApiResponse.Created);

                if(!validatedInitValues)
                {
                    callback(EGAHTTPApiResponse.BadResponse, null, "", 0);
                    return;
                }

                // all ok
                callback(requestResponseEnum, validatedInitValues, "", 0);
            }

            private createPayloadData(payload:string, gzip:boolean): string
            {
                var payloadData:string;

                if(gzip)
                {
                    // payloadData = GAUtilities.GzipCompress(payload);
                    // GALogger.D("Gzip stats. Size: " + Encoding.UTF8.GetBytes(payload).Length + ", Compressed: " + payloadData.Length + ", Content: " + payload);
                    throw new Error("gzip not supported");
                }
                else
                {
                    payloadData = payload;
                }

                return payloadData;
            }

            private processRequestResponse(responseCode:number, responseMessage:string, body:string, requestId:string): EGAHTTPApiResponse
            {
                // if no result - often no connection
                if(!body)
                {
                    GALogger.d(requestId + " request. failed. Might be no connection. Description: " + responseMessage + ", Status code: " + responseCode);
                    return EGAHTTPApiResponse.NoResponse;
                }

                // ok
                if (responseCode === 200)
                {
                    return EGAHTTPApiResponse.Ok;
                }
                // created
                if (responseCode === 201)
                {
                    return EGAHTTPApiResponse.Created;
                }

                // 401 can return 0 status
                if (responseCode === 0 || responseCode === 401)
                {
                    GALogger.d(requestId + " request. 401 - Unauthorized.");
                    return EGAHTTPApiResponse.Unauthorized;
                }

                if (responseCode === 400)
                {
                    GALogger.d(requestId + " request. 400 - Bad Request.");
                    return EGAHTTPApiResponse.BadRequest;
                }

                if (responseCode === 500)
                {
                    GALogger.d(requestId + " request. 500 - Internal Server Error.");
                    return EGAHTTPApiResponse.InternalServerError;
                }

                return EGAHTTPApiResponse.UnknownResponseCode;
            }

            private static sdkErrorCategoryString(value:EGASdkErrorCategory): string
            {
                switch (value)
                {
                    case EGASdkErrorCategory.EventValidation:
                        return "event_validation";
                    case EGASdkErrorCategory.Database:
                        return "db";
                    case EGASdkErrorCategory.Init:
                        return "init";
                    case EGASdkErrorCategory.Http:
                        return "http";
                    case EGASdkErrorCategory.Json:
                        return "json";
                    default:
                        break;
                }
                return "";
            }

            private static sdkErrorAreaString(value:EGASdkErrorArea): string
            {
                switch (value)
                {
                    case EGASdkErrorArea.BusinessEvent:
                        return "business";
                    case EGASdkErrorArea.ResourceEvent:
                        return "resource";
                    case EGASdkErrorArea.ProgressionEvent:
                        return "progression";
                    case EGASdkErrorArea.DesignEvent:
                        return "design";
                    case EGASdkErrorArea.ErrorEvent:
                        return "error";
                    case EGASdkErrorArea.InitHttp:
                        return "init_http";
                    case EGASdkErrorArea.EventsHttp:
                        return "events_http";
                    case EGASdkErrorArea.ProcessEvents:
                        return "process_events";
                    case EGASdkErrorArea.AddEventsToStore:
                        return "add_events_to_store";
                    default:
                        break;
                }
                return "";
            }

            private static sdkErrorActionString(value:EGASdkErrorAction): string
            {
                switch (value)
                {
                    case EGASdkErrorAction.InvalidCurrency:
                        return "invalid_currency";
                    case EGASdkErrorAction.InvalidShortString:
                        return "invalid_short_string";
                    case EGASdkErrorAction.InvalidEventPartLength:
                        return "invalid_event_part_length";
                    case EGASdkErrorAction.InvalidEventPartCharacters:
                        return "invalid_event_part_characters";
                    case EGASdkErrorAction.InvalidStore:
                        return "invalid_store";
                    case EGASdkErrorAction.InvalidFlowType:
                        return "invalid_flow_type";
                    case EGASdkErrorAction.StringEmptyOrNull:
                        return "string_empty_or_null";
                    case EGASdkErrorAction.NotFoundInAvailableCurrencies:
                        return "not_found_in_available_currencies";
                    case EGASdkErrorAction.InvalidAmount:
                        return "invalid_amount";
                    case EGASdkErrorAction.NotFoundInAvailableItemTypes:
                        return "not_found_in_available_item_types";
                    case EGASdkErrorAction.WrongProgressionOrder:
                        return "wrong_progression_order";
                    case EGASdkErrorAction.InvalidEventIdLength:
                        return "invalid_event_id_length";
                    case EGASdkErrorAction.InvalidEventIdCharacters:
                        return "invalid_event_id_characters";
                    case EGASdkErrorAction.InvalidProgressionStatus:
                        return "invalid_progression_status";
                    case EGASdkErrorAction.InvalidSeverity:
                        return "invalid_severity";
                    case EGASdkErrorAction.InvalidLongString:
                        return "invalid_long_string";
                    case EGASdkErrorAction.DatabaseTooLarge:
                        return "db_too_large";
                    case EGASdkErrorAction.DatabaseOpenOrCreate:
                        return "db_open_or_create";
                    case EGASdkErrorAction.JsonError:
                        return "json_error";
                    case EGASdkErrorAction.FailHttpJsonDecode:
                        return "fail_http_json_decode";
                    case EGASdkErrorAction.FailHttpJsonEncode:
                        return "fail_http_json_encode";
                    default:
                        break;
                }
                return "";
            }

            private static sdkErrorParameterString(value:EGASdkErrorParameter): string
            {
                switch (value)
                {
                    case EGASdkErrorParameter.Currency:
                        return "currency";
                    case EGASdkErrorParameter.CartType:
                        return "cart_type";
                    case EGASdkErrorParameter.ItemType:
                        return "item_type";
                    case EGASdkErrorParameter.ItemId:
                        return "item_id";
                    case EGASdkErrorParameter.Store:
                        return "store";
                    case EGASdkErrorParameter.FlowType:
                        return "flow_type";
                    case EGASdkErrorParameter.Amount:
                        return "amount";
                    case EGASdkErrorParameter.Progression01:
                        return "progression01";
                    case EGASdkErrorParameter.Progression02:
                        return "progression02";
                    case EGASdkErrorParameter.Progression03:
                        return "progression03";
                    case EGASdkErrorParameter.EventId:
                        return "event_id";
                    case EGASdkErrorParameter.ProgressionStatus:
                        return "progression_status";
                    case EGASdkErrorParameter.Severity:
                        return "severity";
                    case EGASdkErrorParameter.Message:
                        return "message";
                    default:
                        break;
                }
                return "";
            }
        }
    }
}
