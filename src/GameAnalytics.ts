module gameanalytics
{
    import GAThreading = gameanalytics.threading.GAThreading;
    import TimedBlock = gameanalytics.threading.TimedBlock;
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
        private static initTimedBlockId:number = -1;
        public static methodMap:{[id:string]: (...args: any[]) => void} = {};

        private static getGlobalObject(): any
        {
            if (typeof globalThis !== 'undefined') { return globalThis; }
            if (typeof self !== 'undefined') { return self; }
            if (typeof window !== 'undefined') { return window; }
            if (typeof global !== 'undefined') { return global; }
            return undefined;
        }

        public static init(): void
        {
            GADevice.touch();
            GameAnalytics.methodMap['configureAvailableCustomDimensions01'] = GameAnalytics.configureAvailableCustomDimensions01;
            GameAnalytics.methodMap['configureAvailableCustomDimensions02'] = GameAnalytics.configureAvailableCustomDimensions02;
            GameAnalytics.methodMap['configureAvailableCustomDimensions03'] = GameAnalytics.configureAvailableCustomDimensions03;
            GameAnalytics.methodMap['configureAvailableResourceCurrencies'] = GameAnalytics.configureAvailableResourceCurrencies;
            GameAnalytics.methodMap['configureAvailableResourceItemTypes'] = GameAnalytics.configureAvailableResourceItemTypes;
            GameAnalytics.methodMap['configureBuild'] = GameAnalytics.configureBuild;
            GameAnalytics.methodMap['configureSdkGameEngineVersion'] = GameAnalytics.configureSdkGameEngineVersion;
            GameAnalytics.methodMap['configureGameEngineVersion'] = GameAnalytics.configureGameEngineVersion;
            GameAnalytics.methodMap['configureUserId'] = GameAnalytics.configureUserId;
            GameAnalytics.methodMap['initialize'] = GameAnalytics.initialize;
            GameAnalytics.methodMap['addBusinessEvent'] = GameAnalytics.addBusinessEvent;
            GameAnalytics.methodMap['addResourceEvent'] = GameAnalytics.addResourceEvent;
            GameAnalytics.methodMap['addProgressionEvent'] = GameAnalytics.addProgressionEvent;
            GameAnalytics.methodMap['addDesignEvent'] = GameAnalytics.addDesignEvent;
            GameAnalytics.methodMap['addErrorEvent'] = GameAnalytics.addErrorEvent;
            GameAnalytics.methodMap['addAdEvent'] = GameAnalytics.addAdEvent;
            GameAnalytics.methodMap['setEnabledInfoLog'] = GameAnalytics.setEnabledInfoLog;
            GameAnalytics.methodMap['setEnabledVerboseLog'] = GameAnalytics.setEnabledVerboseLog;
            GameAnalytics.methodMap['setEnabledManualSessionHandling'] = GameAnalytics.setEnabledManualSessionHandling;
            GameAnalytics.methodMap['setEnabledEventSubmission'] = GameAnalytics.setEnabledEventSubmission;
            GameAnalytics.methodMap['setCustomDimension01'] = GameAnalytics.setCustomDimension01;
            GameAnalytics.methodMap['setCustomDimension02'] = GameAnalytics.setCustomDimension02;
            GameAnalytics.methodMap['setCustomDimension03'] = GameAnalytics.setCustomDimension03;
            GameAnalytics.methodMap['setGlobalCustomEventFields'] = GameAnalytics.setGlobalCustomEventFields;
            GameAnalytics.methodMap['setEventProcessInterval'] = GameAnalytics.setEventProcessInterval;
            GameAnalytics.methodMap['startSession'] = GameAnalytics.startSession;
            GameAnalytics.methodMap['endSession'] = GameAnalytics.endSession;
            GameAnalytics.methodMap['onStop'] = GameAnalytics.onStop;
            GameAnalytics.methodMap['onResume'] = GameAnalytics.onResume;
            GameAnalytics.methodMap['addRemoteConfigsListener'] = GameAnalytics.addRemoteConfigsListener;
            GameAnalytics.methodMap['removeRemoteConfigsListener'] = GameAnalytics.removeRemoteConfigsListener;
            GameAnalytics.methodMap['getRemoteConfigsValueAsString'] = GameAnalytics.getRemoteConfigsValueAsString;
            GameAnalytics.methodMap['isRemoteConfigsReady'] = GameAnalytics.isRemoteConfigsReady;
            GameAnalytics.methodMap['getRemoteConfigsContentAsString'] = GameAnalytics.getRemoteConfigsContentAsString;
            GameAnalytics.methodMap['addOnBeforeUnloadListener'] = GameAnalytics.addOnBeforeUnloadListener;
            GameAnalytics.methodMap['removeOnBeforeUnloadListener'] = GameAnalytics.removeOnBeforeUnloadListener;

            if (typeof GameAnalytics.getGlobalObject() !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics'] !== 'undefined' && typeof GameAnalytics.getGlobalObject()['GameAnalytics']['q'] !== 'undefined')
            {
                var q: any[] = GameAnalytics.getGlobalObject()['GameAnalytics']['q'];
                for (let i in q)
                {
                    GameAnalytics.gaCommand.apply(null, q[i]);
                }
            }


            window.addEventListener("beforeunload", (e) => {
                console.log('addEventListener unload');
                GAState.instance.isUnloading = true;
                GAState.notifyBeforeUnloadListeners();
                GAThreading.endSessionAndStopQueue();
                GAState.instance.isUnloading = false;
            });
        }

        public static gaCommand(...args: any[]): void
        {
            if(args.length > 0)
            {
                if(args[0] in gameanalytics.GameAnalytics.methodMap)
                {
                    if(args.length > 1)
                    {
                        gameanalytics.GameAnalytics.methodMap[args[0]].apply(null, Array.prototype.slice.call(args, 1));
                    }
                    else
                    {
                        gameanalytics.GameAnalytics.methodMap[args[0]]();
                    }
                }
            }
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
                    GALogger.i("Validation fail - configure game engine version: Game engine version not supported. String: " + gameEngineVersion);
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

            var timedBlock:TimedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = () =>
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
            };

            GAThreading.performTimedBlockOnGAThread(timedBlock);
        }

        public static addBusinessEvent(currency:string = "", amount:number = 0, itemType:string = "", itemId:string = "", cartType:string = "", customFields:{[id:string]: any} = {}, mergeFields:boolean = false): void
        {
            GADevice.updateConnectionType();

            if(!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                        return;
                    }
                    // Send to events
                    GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                    return;
                }
                // Send to events
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, customFields, mergeFields);
            }
        }

        public static addResourceEvent(flowType:EGAResourceFlowType = EGAResourceFlowType.Undefined, currency:string = "", amount:number = 0, itemType:string = "", itemId:string = "", customFields:{[id:string]: any} = {}, mergeFields:boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                        return;
                    }

                    GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                    return;
                }

                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, customFields, mergeFields);
            }
        }

        public static addProgressionEvent(progressionStatus: EGAProgressionStatus = EGAProgressionStatus.Undefined, progression01: string = "", progression02: string = "", progression03: string = "", score?: number, customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                        return;
                    }

                    // Send to events
                    var sendScore: boolean = typeof score === "number";
                    GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                    return;
                }

                // Send to events
                var sendScore: boolean = typeof score === "number";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, customFields, mergeFields);
            }
        }

        public static addDesignEvent(eventId: string, value?: number, customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                        return;
                    }
                    var sendValue: boolean = typeof value === "number";
                    GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                    return;
                }
                var sendValue: boolean = typeof value === "number";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, customFields, mergeFields);
            }
        }

        public static addErrorEvent(severity: EGAErrorSeverity = EGAErrorSeverity.Undefined, message: string = "", customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                        return;
                    }
                    GAEvents.addErrorEvent(severity, message, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                    return;
                }
                GAEvents.addErrorEvent(severity, message, customFields, mergeFields);
            }
        }

        public static addAdEventWithNoAdReason(adAction: EGAAdAction = EGAAdAction.Undefined, adType: EGAAdType = EGAAdType.Undefined, adSdkName: string = "", adPlacement: string = "", noAdReason: EGAAdError = EGAAdError.Undefined, customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, noAdReason, 0, false, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, noAdReason, 0, false, customFields, mergeFields);
            }
        }

        public static addAdEventWithDuration(adAction: EGAAdAction = EGAAdAction.Undefined, adType: EGAAdType = EGAAdType.Undefined, adSdkName: string = "", adPlacement: string = "", duration: number = 0, customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, EGAAdError.Undefined, duration, true, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, EGAAdError.Undefined, duration, true, customFields, mergeFields);
            }
        }

        public static addAdEvent(adAction: EGAAdAction = EGAAdAction.Undefined, adType: EGAAdType = EGAAdType.Undefined, adSdkName: string = "", adPlacement: string = "", customFields: { [id: string]: any } = {}, mergeFields: boolean = false): void
        {
            GADevice.updateConnectionType();

            if (!GAState.instance.isUnloading)
            {
                GAThreading.performTaskOnGAThread(() => {
                    if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                        return;
                    }
                    GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, EGAAdError.Undefined, 0, false, customFields, mergeFields);
                });
            }
            else
            {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add ad event")) {
                    return;
                }
                GAEvents.addAdEvent(adAction, adType, adSdkName, adPlacement, EGAAdError.Undefined, 0, false, customFields, mergeFields);
            }
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

        public static setEnabledEventSubmission(flag:boolean = false): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                if (flag)
                {
                    GAState.setEnabledEventSubmission(flag);
                    GALogger.i("Event submission enabled");
                }
                else
                {
                    GALogger.i("Event submission disabled");
                    GAState.setEnabledEventSubmission(flag);
                }
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

        public static setGlobalCustomEventFields(customFields: { [id: string]: any } = {}): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                GALogger.i("Set global custom event fields: " + JSON.stringify(customFields));
                GAState.instance.currentGlobalCustomEventFields = customFields;
            });
        }

        public static setEventProcessInterval(intervalInSeconds:number): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                GAThreading.setEventProcessInterval(intervalInSeconds);
            });
        }

        public static startSession(): void
        {
            //if(GAState.getUseManualSessionHandling())
            {
                if(!GAState.isInitialized())
                {
                    return;
                }

                var timedBlock:TimedBlock = GAThreading.createTimedBlock();
                timedBlock.async = true;
                GameAnalytics.initTimedBlockId = timedBlock.id;
                timedBlock.block = () =>
                {
                    if(GAState.isEnabled() && GAState.sessionIsStarted())
                    {
                        GAThreading.endSessionAndStopQueue();
                    }

                    GameAnalytics.resumeSessionAndStartQueue();
                };

                GAThreading.performTimedBlockOnGAThread(timedBlock);
            }
        }

        public static endSession(): void
        {
            //if(GAState.getUseManualSessionHandling())
            {
                GameAnalytics.onStop();
            }
        }

        public static onStop(): void
        {
            GAThreading.performTaskOnGAThread(() =>
            {
                try
                {
                    GAThreading.endSessionAndStopQueue();
                }
                catch (Exception)
                {
                }
            });
        }

        public static onResume(): void
        {
            var timedBlock:TimedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = () =>
            {
                GameAnalytics.resumeSessionAndStartQueue();
            };

            GAThreading.performTimedBlockOnGAThread(timedBlock);
        }

        public static getRemoteConfigsValueAsString(key:string, defaultValue:string = null):string
        {
            return GAState.getConfigurationStringValue(key, defaultValue);
        }

        public static isRemoteConfigsReady():boolean
        {
            return GAState.isRemoteConfigsReady();
        }

        public static addRemoteConfigsListener(listener:{ onRemoteConfigsUpdated:() => void }):void
        {
            GAState.addRemoteConfigsListener(listener);
        }

        public static removeRemoteConfigsListener(listener:{ onRemoteConfigsUpdated:() => void }):void
        {
            GAState.removeRemoteConfigsListener(listener);
        }

        public static getRemoteConfigsContentAsString():string
        {
            return GAState.getRemoteConfigsContentAsString();
        }

        public static getABTestingId():string
        {
            return GAState.getABTestingId();
        }

        public static getABTestingVariantId():string
        {
            return GAState.getABTestingVariantId();
        }

        public static addOnBeforeUnloadListener(listener: { onBeforeUnload: () => void }): void
        {
            GAState.addOnBeforeUnloadListener(listener);
        }

        public static removeOnBeforeUnloadListener(listener: { onBeforeUnload: () => void }): void
        {
            GAState.removeOnBeforeUnloadListener(listener);
        }

        private static internalInitialize(): void
        {
            GAState.ensurePersistedStates();
            GAStore.setItem(GAState.getGameKey(), GAState.DefaultUserIdKey, GAState.getDefaultId());

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

            GAHTTPApi.instance.requestInit(GAState.instance.configsHash, GameAnalytics.startNewSessionCallback);
        }

        private static startNewSessionCallback(initResponse:EGAHTTPApiResponse, initResponseDict:{[key:string]: any}): void
        {
            // init is ok
            if((initResponse === EGAHTTPApiResponse.Ok || initResponse === EGAHTTPApiResponse.Created) && initResponseDict)
            {
                // set the time offset - how many seconds the local time is different from servertime
                var timeOffsetSeconds:number = 0;
                if(initResponseDict["server_ts"])
                {
                    var serverTs:number = initResponseDict["server_ts"] as number;
                    timeOffsetSeconds = GAState.calculateServerTimeOffset(serverTs);
                }
                initResponseDict["time_offset"] = timeOffsetSeconds;

                if(initResponse != EGAHTTPApiResponse.Created)
                {
                    var currentSdkConfig:{[key:string]: any} = GAState.getSdkConfig();
                    // use cached if not Created
                    if(currentSdkConfig["configs"])
                    {
                        initResponseDict["configs"] = currentSdkConfig["configs"];
                    }
                    if(currentSdkConfig["configs_hash"])
                    {
                        initResponseDict["configs_hash"] = currentSdkConfig["configs_hash"];
                    }
                    if(currentSdkConfig["ab_id"])
                    {
                        initResponseDict["ab_id"] = currentSdkConfig["ab_id"];
                    }
                    if(currentSdkConfig["ab_variant_id"])
                    {
                        initResponseDict["ab_variant_id"] = currentSdkConfig["ab_variant_id"];
                    }
                }

                GAState.instance.configsHash = initResponseDict["configs_hash"] ? initResponseDict["configs_hash"] : "";
                GAState.instance.abId = initResponseDict["ab_id"] ? initResponseDict["ab_id"] : "";
                GAState.instance.abVariantId = initResponseDict["ab_variant_id"] ? initResponseDict["ab_variant_id"] : "";

                // insert new config in sql lite cross session storage
                GAStore.setItem(GAState.getGameKey(), GAState.SdkConfigCachedKey, GAUtilities.encode64(JSON.stringify(initResponseDict)));

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
            GAState.instance.clientServerTimeOffset = GAState.getSdkConfig()["time_offset"] ? GAState.getSdkConfig()["time_offset"] as number : 0;

            // populate configurations
            GAState.populateConfigurations(GAState.getSdkConfig());

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

            var timedBlock:TimedBlock = GAThreading.getTimedBlockById(GameAnalytics.initTimedBlockId);

            if(timedBlock != null)
            {
                timedBlock.running = false;
            }

            GameAnalytics.initTimedBlockId = -1;
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
            // Is session started
            if (needsInitialized && !GAState.sessionIsStarted())
            {
                if (warn)
                {
                    GALogger.w(message + "Session has not started yet");
                }
                return false;
            }
            return true;
        }
    }
}
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;
