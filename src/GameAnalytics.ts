module gameanalytics
{
    import GAThreading = gameanalytics.threading.GAThreading;
    import GALogger = gameanalytics.logging.GALogger;
    import GAStore = gameanalytics.store.GAStore;
    import GAState = gameanalytics.state.GAState;
    import GAHTTPApi = gameanalytics.http.GAHTTPApi;
    import GADevice = gameanalytics.device.GADevice;
    import GAValidator = gameanalytics.validators.GAValidator;
    import EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
    import GAUtilities = gameanalytics.utilities.GAUtilities;
    import GAEvents = gameanalytics.events.GAEvents;

    export class GameAnalytics
    {
        public static test(): void
        {
            var d:{[key:string]: any} = {};

            d["test"] = 2;
            d["hello"] = "world";
            d["123"] = "345";
            d["uuu"] = 100;

            var a:Array<{[key:string]: any}> = [];

            a.push(d);
            a.push(d);
            a.push(d);

            GALogger.d(JSON.stringify(a));

            for(let key in d)
            {
                console.log(key);
            }

            var s:string = JSON.stringify(d);
            gameanalytics.logging.GALogger.i(gameanalytics.utilities.GAUtilities.getHmac("test", s));
        }

        public static init(): void
        {
            GADevice.touch();
        }

        public static configureAvailableCustomDimensions01(customDimensions:Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableCustomDimensions01", () =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions01(customDimensions);
            });
        }

        public static configureAvailableCustomDimensions02(customDimensions:Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableCustomDimensions02", () =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions02(customDimensions);
            });
        }

        public static configureAvailableCustomDimensions03(customDimensions:Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableCustomDimensions03", () =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions03(customDimensions);
            });
        }

        public static configureAvailableResourceCurrencies(resourceCurrencies:Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableResourceCurrencies", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available resource currencies must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceCurrencies(resourceCurrencies);
            });
        }

        public static configureAvailableResourceItemTypes(resourceItemTypes:Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableResourceItemTypes", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available resource item types must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceItemTypes(resourceItemTypes);
            });
        }

        public static configureBuild(build:string): void
        {
            GAThreading.performTaskOnGAThread("configureBuild", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Build version must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateBuild(build))
                {
                    GALogger.i("Validation fail - configure build: Cannot be null, empty or above 32 length. String: " + build);
                    return;
                }
                GAState.setBuild(build);
            });
        }

        public static configureSdkGameEngineVersion(sdkGameEngineVersion:string): void
        {
            GAThreading.performTaskOnGAThread("configureSdkGameEngineVersion", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    return;
                }
                if (!GAValidator.validateSdkWrapperVersion(sdkGameEngineVersion))
                {
                    GALogger.i("Validation fail - configure sdk version: Sdk version not supported. String: " + sdkGameEngineVersion);
                    return;
                }
                GADevice.sdkGameEngineVersion = sdkGameEngineVersion;
            });
        }

        public static configureGameEngineVersion(gameEngineVersion:string): void
        {
            GAThreading.performTaskOnGAThread("configureGameEngineVersion", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    return;
                }
                if (!GAValidator.validateEngineVersion(gameEngineVersion))
                {
                    GALogger.i("Validation fail - configure sdk version: Sdk version not supported. String: " + gameEngineVersion);
                    return;
                }
                GADevice.gameEngineVersion = gameEngineVersion;
            });
        }

        public static configureUserId(uId:string): void
        {
            GAThreading.performTaskOnGAThread("configureUserId", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("A custom user id must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateUserId(uId))
                {
                    GALogger.i("Validation fail - configure user_id: Cannot be null, empty or above 64 length. Will use default user_id method. Used string: " + uId);
                    return;
                }

                GAState.setUserId(uId);
            });
        }

        public static initialize(gameKey:string, gameSecret:string): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread("initialize", () =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("SDK already initialized. Can only be called once.");
                    return;
                }
                if (!GAValidator.validateKeys(gameKey, gameSecret))
                {
                    GALogger.w("SDK failed initialize. Game key or secret key is invalid. Can only contain characters A-z 0-9, gameKey is 32 length, gameSecret is 40 length. Failed keys - gameKey: " + gameKey + ", secretKey: " + gameSecret);
                    return;
                }

                GAState.setKeys(gameKey, gameSecret);

                GameAnalytics.internalInitialize();
            });
        }

        public static addBusinessEvent(currency:string, amount:number, itemType:string, itemId:string, cartType:string): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread("addBusinessEvent", () =>
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event"))
                {
                    return;
                }
                // Send to events
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType);
            });
        }

        private static internalInitialize(): void
        {
            GAState.ensurePersistedStates();
            GAStore.setItem(GAState.DefaultUserIdKey, GAState.getDefaultId());

            GAState.setInitialized(true);

            GameAnalytics.newSession();

            if (GAState.isEnabled())
            {
                GAThreading.ensureEventQueueIsRunning();
            }
        }

        private static newSession(): void
        {
            GALogger.i("Starting a new session.");

            // make sure the current custom dimensions are valid
            GAState.validateAndFixCurrentDimensions();

            GAHTTPApi.instance.requestInit(GameAnalytics.startNewSessionCallback);
        }

        private static startNewSessionCallback(initResponse:EGAHTTPApiResponse, initResponseDict:{[key:string]: any}): void
        {
            // init is ok
            if(initResponse === EGAHTTPApiResponse.Ok && initResponseDict)
            {
                // set the time offset - how many seconds the local time is different from servertime
                var timeOffsetSeconds:number = 0;
                if(initResponseDict["server_ts"])
                {
                    var serverTs:number = initResponseDict["server_ts"] as number;
                    timeOffsetSeconds = GAState.calculateServerTimeOffset(serverTs);
                }
                initResponseDict["time_offset"] = timeOffsetSeconds;

                // insert new config in sql lite cross session storage
                GAStore.setItem(GAState.SdkConfigCachedKey, btoa(JSON.stringify(initResponseDict)));

                // set new config and cache in memory
                GAState.instance.sdkConfigCached = initResponseDict;
                GAState.instance.sdkConfig = initResponseDict;

                GAState.instance.initAuthorized = true;
            }
            else if(initResponse == EGAHTTPApiResponse.Unauthorized)
            {
                GALogger.w("Initialize SDK failed - Unauthorized");
                GAState.instance.initAuthorized = false;
            }
            else
            {
                // log the status if no connection
                if(initResponse === EGAHTTPApiResponse.NoResponse || initResponse === EGAHTTPApiResponse.RequestTimeout)
                {
                    GALogger.i("Init call (session start) failed - no response. Could be offline or timeout.");
                }
                else if(initResponse === EGAHTTPApiResponse.BadResponse || initResponse === EGAHTTPApiResponse.JsonEncodeFailed || initResponse === EGAHTTPApiResponse.JsonDecodeFailed)
                {
                    GALogger.i("Init call (session start) failed - bad response. Could be bad response from proxy or GA servers.");
                }
                else if(initResponse === EGAHTTPApiResponse.BadRequest || initResponse === EGAHTTPApiResponse.UnknownResponseCode)
                {
                    GALogger.i("Init call (session start) failed - bad request or unknown response.");
                }

                // init call failed (perhaps offline)
                if(GAState.instance.sdkConfig == null)
                {
                    if(GAState.instance.sdkConfigCached != null)
                    {
                        GALogger.i("Init call (session start) failed - using cached init values.");
                        // set last cross session stored config init values
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigCached;
                    }
                    else
                    {
                        GALogger.i("Init call (session start) failed - using default init values.");
                        // set default init values
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigDefault;
                    }
                }
                else
                {
                    GALogger.i("Init call (session start) failed - using cached init values.");
                }
                GAState.instance.initAuthorized = true;
            }

            // set offset in state (memory) from current config (config could be from cache etc.)
            GAState.instance.clientServerTimeOffset = GAState.instance.sdkConfig["time_offset"] ? GAState.instance.sdkConfig["time_offset"] as number : 0;

            // if SDK is disabled in config
            if(!GAState.isEnabled())
            {
                GALogger.w("Could not start session: SDK is disabled.");
                // stop event queue
                // + make sure it's able to restart if another session detects it's enabled again
                GAThreading.stopEventQueue();
                return;
            }
            else
            {
                GAThreading.ensureEventQueueIsRunning();
            }

            // generate the new session
            var newSessionId:string = GAUtilities.createGuid();

            // Set session id
            GAState.instance.sessionId = newSessionId;

            // Set session start
            GAState.instance.sessionStart = GAState.getClientTsAdjusted();

            // Add session start event
            GAEvents.addSessionStartEvent();
        }

        private static resumeSessionAndStartQueue(): void
        {
            if(!GAState.isInitialized())
            {
                return;
            }
            GALogger.i("Resuming session.");
            if(!GAState.sessionIsStarted())
            {
                GameAnalytics.newSession();
            }
        }

        private static isSdkReady(needsInitialized:boolean, warn:boolean = true, message:string = ""): boolean
        {
            if(message)
            {
                message = message + ": ";
            }

            // Is SDK initialized
            if (needsInitialized && !GAState.isInitialized())
            {
                if (warn)
                {
                    GALogger.w(message + "SDK is not initialized");
                }
                return false;
            }
            // Is SDK enabled
            if (needsInitialized && !GAState.isEnabled())
            {
                if (warn)
                {
                    GALogger.w(message + "SDK is disabled");
                }
                return false;
            }
            return true;
        }
    }

    GameAnalytics.init();
}
