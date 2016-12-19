module ga
{
    import GAThreading = ga.threading.GAThreading;
    import GALogger = ga.logging.GALogger;
    import GAStore = ga.store.GAStore;
    import GAState = ga.state.GAState;
    import GAHTTPApi = ga.http.GAHTTPApi;
    import GADevice = ga.device.GADevice;
    import GAValidator = ga.validators.GAValidator;
    import EGAHTTPApiResponse = ga.http.EGAHTTPApiResponse;
    import GAUtilities = ga.utilities.GAUtilities;
    import GAEvents = ga.events.GAEvents;

    export class GameAnalytics
    {
        public static init(): void
        {
            GADevice.touch();
        }

        public static configureAvailableCustomDimensions01(customDimensions:Array<string> = []): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions01(customDimensions);
            });
        }

        public static configureAvailableCustomDimensions02(customDimensions:Array<string> = []): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions02(customDimensions);
            });
        }

        public static configureAvailableCustomDimensions03(customDimensions:Array<string> = []): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions03(customDimensions);
            });
        }

        public static configureAvailableResourceCurrencies(resourceCurrencies:Array<string> = []): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available resource currencies must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceCurrencies(resourceCurrencies);
            });
        }

        public static configureAvailableResourceItemTypes(resourceItemTypes:Array<string> = []): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available resource item types must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceItemTypes(resourceItemTypes);
            });
        }

        public static configureBuild(build:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
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

        public static configureSdkGameEngineVersion(sdkGameEngineVersion:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
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

        public static configureGameEngineVersion(gameEngineVersion:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
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

        public static configureUserId(uId:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
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

        public static initialize(gameKey:string = "", gameSecret:string = ""): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
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

        public static addBusinessEvent(currency:string = "", amount:number = 0, itemType:string = "", itemId:string = "", cartType:string = ""): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event"))
                {
                    return;
                }
                // Send to events
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType);
            });
        }

        public static addResourceEvent(flowType:EGAResourceFlowType = EGAResourceFlowType.Undefined, currency:string = "", amount:number = 0, itemType:string = "", itemId:string = ""): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event"))
                {
                    return;
                }

                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId);
            });
        }

        public static addProgressionEvent(progressionStatus:EGAProgressionStatus = EGAProgressionStatus.Undefined, progression01:string = "", progression02:string = "", progression03:string = "", score?:number): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
            {
                if(!GameAnalytics.isSdkReady(true, true, "Could not add progression event"))
                {
                    return;
                }

                // Send to events
                var sendScore:boolean = typeof score != "undefined";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore);
            });
        }

        public static addDesignEvent(eventId:string, value?:number): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
            {
                if(!GameAnalytics.isSdkReady(true, true, "Could not add design event"))
                {
                    return;
                }
                var sendValue:boolean = typeof value != "undefined";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue);
            });
        }

        public static addErrorEvent(severity:EGAErrorSeverity = EGAErrorSeverity.Undefined, message:string = ""): void
        {
            GADevice.updateConnectionType();

            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add error event"))
                {
                    return;
                }
                GAEvents.addErrorEvent(severity, message);
            });
        }

        public static setEnabledInfoLog(flag:boolean = false): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (flag)
                {
                    GALogger.setInfoLog(flag);
                    GALogger.i("Info logging enabled");
                }
                else
                {
                    GALogger.i("Info logging disabled");
                    GALogger.setInfoLog(flag);
                }
            });
        }

        public static setEnabledVerboseLog(flag:boolean = false): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (flag)
                {
                    GALogger.setVerboseLog(flag);
                    GALogger.i("Verbose logging enabled");
                }
                else
                {
                    GALogger.i("Verbose logging disabled");
                    GALogger.setVerboseLog(flag);
                }
            });
        }

        public static setEnabledManualSessionHandling(flag:boolean = false): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                GAState.setManualSessionHandling(flag);
            });
        }

        public static setCustomDimension01(dimension:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GAValidator.validateDimension01(dimension, GAState.getAvailableCustomDimensions01()))
                {
                    GALogger.w("Could not set custom01 dimension value to '" + dimension + "'. Value not found in available custom01 dimension values");
                    return;
                }
                GAState.setCustomDimension01(dimension);
            });
        }

        public static setCustomDimension02(dimension:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GAValidator.validateDimension02(dimension, GAState.getAvailableCustomDimensions02()))
                {
                    GALogger.w("Could not set custom02 dimension value to '" + dimension + "'. Value not found in available custom02 dimension values");
                    return;
                }
                GAState.setCustomDimension02(dimension);
            });
        }

        public static setCustomDimension03(dimension:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (!GAValidator.validateDimension03(dimension, GAState.getAvailableCustomDimensions03()))
                {
                    GALogger.w("Could not set custom03 dimension value to '" + dimension + "'. Value not found in available custom03 dimension values");
                    return;
                }
                GAState.setCustomDimension03(dimension);
            });
        }

        public static setFacebookId(facebookId:string = ""): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (GAValidator.validateFacebookId(facebookId))
                {
                    GAState.setFacebookId(facebookId);
                }
            });
        }

        public static setGender(gender:EGAGender = EGAGender.Undefined): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (GAValidator.validateGender(gender))
                {
                    GAState.setGender(gender);
                }
            });
        }

        public static setBirthYear(birthYear:number = 0): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (GAValidator.validateBirthyear(birthYear))
                {
                    GAState.setBirthYear(birthYear);
                }
            });
        }

        public static startSession(): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if(GAState.getUseManualSessionHandling())
                {
                    if(!GAState.isInitialized())
                    {
                        return;
                    }

                    if(GAState.isEnabled() && GAState.sessionIsStarted())
                    {
                        GAThreading.endSessionAndStopQueue();
                    }

                    GameAnalytics.resumeSessionAndStartQueue();
                }
            });
        }

        public static endSession(): void
        {
            if(GAState.getUseManualSessionHandling())
            {
                GameAnalytics.onStop();
            }
        }

        public static onStop(): void
        {
            try
            {
                GAThreading.endSessionAndStopQueue();
            }
            catch (Exception)
            {
            }
        }

        public static onResume(): void
        {
            GameAnalytics.resumeSessionAndStartQueue();
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
                GAStore.setItem(GAState.SdkConfigCachedKey, GAUtilities.encode64(JSON.stringify(initResponseDict)));

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
