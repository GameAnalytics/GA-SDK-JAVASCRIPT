module gameanalytics
{
    export module http
    {
        import GAState = gameanalytics.state.GAState;
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GAValidator = gameanalytics.validators.GAValidator;
        import SdkErrorTask = gameanalytics.tasks.SdkErrorTask;

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

            public sendSdkErrorEvent(type:EGASdkErrorType): void
            {
                if(!GAState.isEventSubmissionEnabled())
                {
                    return;
                }

                var gameKey:string = GAState.getGameKey();
                var secretKey:string = GAState.getGameSecret();

                // Validate
                if (!GAValidator.validateSdkErrorEvent(gameKey, secretKey, type))
                {
                    return;
                }

                // Generate URL
                var url:string = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);

                var payloadJSONString:string = "";

                var json:{[key:string]: any} = GAState.getSdkErrorEventAnnotations();

                var typeString:string = GAHTTPApi.sdkErrorTypeToString(type);
                json["type"] = typeString;

                var eventArray:Array<{[key:string]: any}> = [];
                eventArray.push(json);
                payloadJSONString = JSON.stringify(eventArray);

                if(!payloadJSONString)
                {
                    GALogger.w("sendSdkErrorEvent: JSON encoding failed.");
                    return;
                }

                GALogger.d("sendSdkErrorEvent json: " + payloadJSONString);
                SdkErrorTask.execute(url, type, payloadJSONString, secretKey);
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

            private static sdkErrorTypeToString(value:EGASdkErrorType): string
            {
                switch(value)
                {
                    case EGASdkErrorType.Rejected:
                        {
                            return "rejected";
                        }

                    default:
                        {
                            return "";
                        }
                }
            }
        }
    }
}
