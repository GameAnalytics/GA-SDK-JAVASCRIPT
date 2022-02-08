module gameanalytics
{
    export module state
    {
        import GAValidator = gameanalytics.validators.GAValidator;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GALogger = gameanalytics.logging.GALogger;
        import GAStore = gameanalytics.store.GAStore;
        import GADevice = gameanalytics.device.GADevice;
        import EGAStore = gameanalytics.store.EGAStore;
        import EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;

        export class GAState
        {
            private static readonly CategorySdkError:string = "sdk_error";
            private static readonly MAX_CUSTOM_FIELDS_COUNT:number = 50;
            private static readonly MAX_CUSTOM_FIELDS_KEY_LENGTH:number = 64;
            private static readonly MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH:number = 256;

            public static readonly instance:GAState = new GAState();

            private constructor()
            {
                this._isEventSubmissionEnabled = true;
                this.isUnloading = false;
            }

            private userId:string;
            public static setUserId(userId:string): void
            {
                GAState.instance.userId = userId;
                GAState.cacheIdentifier();
            }

            private identifier:string;
            public static getIdentifier(): string
            {
                return GAState.instance.identifier;
            }

            private initialized:boolean;
            public static isInitialized(): boolean
            {
                return GAState.instance.initialized;
            }
            public static setInitialized(value:boolean): void
            {
                GAState.instance.initialized = value;
            }

            public sessionStart:number;
            public static getSessionStart(): number
            {
                return GAState.instance.sessionStart;
            }

            private sessionNum:number;
            public static getSessionNum(): number
            {
                return GAState.instance.sessionNum;
            }

            public isUnloading:boolean;

            private transactionNum:number;
            public static getTransactionNum(): number
            {
                return GAState.instance.transactionNum;
            }

            public sessionId:string;
            public static getSessionId(): string
            {
                return GAState.instance.sessionId;
            }

            private currentCustomDimension01:string;
            public static getCurrentCustomDimension01(): string
            {
                return GAState.instance.currentCustomDimension01;
            }

            private currentCustomDimension02:string;
            public static getCurrentCustomDimension02(): string
            {
                return GAState.instance.currentCustomDimension02;
            }

            private currentCustomDimension03:string;
            public static getCurrentCustomDimension03(): string
            {
                return GAState.instance.currentCustomDimension03;
            }

            private gameKey:string;
            public static getGameKey(): string
            {
                return GAState.instance.gameKey;
            }

            private gameSecret:string;
            public static getGameSecret(): string
            {
                return GAState.instance.gameSecret;
            }

            private availableCustomDimensions01:Array<string> = [];
            public static getAvailableCustomDimensions01(): Array<string>
            {
                return GAState.instance.availableCustomDimensions01;
            }
            public static setAvailableCustomDimensions01(value:Array<string>): void
            {
                // Validate
                if(!GAValidator.validateCustomDimensions(value))
                {
                    return;
                }
                GAState.instance.availableCustomDimensions01 = value;

                // validate current dimension values
                GAState.validateAndFixCurrentDimensions();

                GALogger.i("Set available custom01 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            }

            private availableCustomDimensions02:Array<string> = [];
            public static getAvailableCustomDimensions02(): Array<string>
            {
                return GAState.instance.availableCustomDimensions02;
            }
            public static setAvailableCustomDimensions02(value:Array<string>): void
            {
                // Validate
                if(!GAValidator.validateCustomDimensions(value))
                {
                    return;
                }
                GAState.instance.availableCustomDimensions02 = value;

                // validate current dimension values
                GAState.validateAndFixCurrentDimensions();

                GALogger.i("Set available custom02 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            }

            private availableCustomDimensions03:Array<string> = [];
            public static getAvailableCustomDimensions03(): Array<string>
            {
                return GAState.instance.availableCustomDimensions03;
            }
            public static setAvailableCustomDimensions03(value:Array<string>): void
            {
                // Validate
                if(!GAValidator.validateCustomDimensions(value))
                {
                    return;
                }
                GAState.instance.availableCustomDimensions03 = value;

                // validate current dimension values
                GAState.validateAndFixCurrentDimensions();

                GALogger.i("Set available custom03 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            }

            public currentGlobalCustomEventFields: { [key: string]: any } = {};

            private availableResourceCurrencies:Array<string> = [];
            public static getAvailableResourceCurrencies(): Array<string>
            {
                return GAState.instance.availableResourceCurrencies;
            }
            public static setAvailableResourceCurrencies(value:Array<string>): void
            {
                // Validate
                if(!GAValidator.validateResourceCurrencies(value))
                {
                    return;
                }
                GAState.instance.availableResourceCurrencies = value;

                GALogger.i("Set available resource currencies: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            }

            private availableResourceItemTypes:Array<string> = [];
            public static getAvailableResourceItemTypes(): Array<string>
            {
                return GAState.instance.availableResourceItemTypes;
            }
            public static setAvailableResourceItemTypes(value:Array<string>): void
            {
                // Validate
                if(!GAValidator.validateResourceItemTypes(value))
                {
                    return;
                }
                GAState.instance.availableResourceItemTypes = value;

                GALogger.i("Set available resource item types: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            }

            private build:string;
            public static getBuild(): string
            {
                return GAState.instance.build;
            }
            public static setBuild(value:string): void
            {
                GAState.instance.build = value;
                GALogger.i("Set build version: " + value);
            }

            private useManualSessionHandling:boolean;
            public static getUseManualSessionHandling(): boolean
            {
                return GAState.instance.useManualSessionHandling;
            }

            private _isEventSubmissionEnabled:boolean;
            public static isEventSubmissionEnabled(): boolean
            {
                return GAState.instance._isEventSubmissionEnabled;
            }

            public sdkConfigCached:{[key:string]: any};
            private configurations:{[key:string]: any} = {};
            private remoteConfigsIsReady:boolean;
            private remoteConfigsListeners:Array<{ onRemoteConfigsUpdated:() => void }> = [];
            private beforeUnloadListeners: Array<{ onBeforeUnload: () => void }> = [];
            public initAuthorized:boolean;
            public clientServerTimeOffset:number;
            public configsHash:string;

            public abId:string;
            public static getABTestingId(): string
            {
                return GAState.instance.abId;
            }
            public abVariantId:string;
            public static getABTestingVariantId(): string
            {
                return GAState.instance.abVariantId;
            }

            private defaultUserId:string;
            private setDefaultId(value:string): void
            {
                this.defaultUserId = !value ? "" : value;
                GAState.cacheIdentifier();
            }
            public static getDefaultId(): string
            {
                return GAState.instance.defaultUserId;
            }

            public sdkConfigDefault:{[key:string]: string} = {};

            public sdkConfig:{[key:string]: any} = {};
            public static getSdkConfig(): {[key:string]: any}
            {
                {
                    var first:string;
                    var count:number = 0;
                    for(let json in GAState.instance.sdkConfig)
                    {
                        if(count === 0)
                        {
                            first = json;
                        }
                        ++count;
                    }

                    if(first && count > 0)
                    {
                        return GAState.instance.sdkConfig;
                    }
                }
                {
                    var first:string;
                    var count:number = 0;
                    for(let json in GAState.instance.sdkConfigCached)
                    {
                        if(count === 0)
                        {
                            first = json;
                        }
                        ++count;
                    }

                    if(first && count > 0)
                    {
                        return GAState.instance.sdkConfigCached;
                    }
                }

                return GAState.instance.sdkConfigDefault;
            }

            private progressionTries:{[key:string]: number} = {};
            public static readonly DefaultUserIdKey:string = "default_user_id";
            public static readonly SessionNumKey:string = "session_num";
            public static readonly TransactionNumKey:string = "transaction_num";
            private static readonly Dimension01Key:string = "dimension01";
            private static readonly Dimension02Key:string = "dimension02";
            private static readonly Dimension03Key:string = "dimension03";
            public static readonly SdkConfigCachedKey:string = "sdk_config_cached";
            public static readonly LastUsedIdentifierKey: string = "last_used_identifier";

            public static isEnabled(): boolean
            {
                if (!GAState.instance.initAuthorized)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }

            public static setCustomDimension01(dimension:string): void
            {
                GAState.instance.currentCustomDimension01 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension01Key, dimension);
                GALogger.i("Set custom01 dimension value: " + dimension);
            }

            public static setCustomDimension02(dimension:string): void
            {
                GAState.instance.currentCustomDimension02 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension02Key, dimension);
                GALogger.i("Set custom02 dimension value: " + dimension);
            }

            public static setCustomDimension03(dimension:string): void
            {
                GAState.instance.currentCustomDimension03 = dimension;
                GAStore.setItem(GAState.getGameKey(), GAState.Dimension03Key, dimension);
                GALogger.i("Set custom03 dimension value: " + dimension);
            }

            public static incrementSessionNum(): void
            {
                var sessionNumInt:number = GAState.getSessionNum() + 1;
                GAState.instance.sessionNum = sessionNumInt;
            }

            public static incrementTransactionNum(): void
            {
                var transactionNumInt:number = GAState.getTransactionNum() + 1;
                GAState.instance.transactionNum = transactionNumInt;
            }

            public static incrementProgressionTries(progression:string): void
            {
                var tries:number = GAState.getProgressionTries(progression) + 1;
                GAState.instance.progressionTries[progression] = tries;

                // Persist
                var values:{[key:string]: any} = {};
                values["progression"] = progression;
                values["tries"] = tries;
                GAStore.insert(EGAStore.Progression, values, true, "progression");
            }

            public static getProgressionTries(progression:string): number
            {
                if(progression in GAState.instance.progressionTries)
                {
                    return GAState.instance.progressionTries[progression];
                }
                else
                {
                    return 0;
                }
            }

            public static clearProgressionTries(progression:string): void
            {
                if(progression in GAState.instance.progressionTries)
                {
                    delete GAState.instance.progressionTries[progression];
                }

                // Delete
                var parms:Array<[string, EGAStoreArgsOperator, string]> = [];
                parms.push(["progression", EGAStoreArgsOperator.Equal, progression]);
                GAStore.delete(EGAStore.Progression, parms);
            }

            public static setKeys(gameKey:string, gameSecret:string): void
            {
                GAState.instance.gameKey = gameKey;
                GAState.instance.gameSecret = gameSecret;
            }

            public static setManualSessionHandling(flag:boolean): void
            {
                GAState.instance.useManualSessionHandling = flag;
                GALogger.i("Use manual session handling: " + flag);
            }

            public static setEnabledEventSubmission(flag:boolean): void
            {
                GAState.instance._isEventSubmissionEnabled = flag;
            }

            public static getEventAnnotations(): {[key:string]: any}
            {
                var annotations:{[key:string]: any} = {};

                // ---- REQUIRED ---- //

                // collector event API version
                annotations["v"] = 2;
                // Event UUID
                annotations["event_uuid"] = GAUtilities.createGuid();
                // User identifier
                annotations["user_id"] = GAState.instance.identifier;

                // Client Timestamp (the adjusted timestamp)
                annotations["client_ts"] = GAState.getClientTsAdjusted();
                // SDK version
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                // Operation system version
                annotations["os_version"] = GADevice.osVersion;
                // Device make (hardcoded to apple)
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                // Device version
                annotations["device"] = GADevice.deviceModel;
                // Browser version
                annotations["browser_version"] = GADevice.browserVersion;
                // Platform (operating system)
                annotations["platform"] = GADevice.buildPlatform;
                // Session identifier
                annotations["session_id"] = GAState.instance.sessionId;
                // Session number
                annotations[GAState.SessionNumKey] = GAState.instance.sessionNum;

                // type of connection the user is currently on (add if valid)
                var connection_type:string = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type))
                {
                    annotations["connection_type"] = connection_type;
                }

                if (GADevice.gameEngineVersion)
                {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }

                // remote configs
                if(GAState.instance.configurations)
                {
                    var count:number = 0;
                    for(let _ in GAState.instance.configurations)
                    {
                        count++;
                        break;
                    }
                    if(count > 0)
                    {
                        annotations["configurations"] = GAState.instance.configurations;
                    }
                }

                // A/B testing
                if(GAState.instance.abId)
                {
                    annotations["ab_id"] = GAState.instance.abId;
                }
                if(GAState.instance.abVariantId)
                {
                    annotations["ab_variant_id"] = GAState.instance.abVariantId;
                }

                // ---- CONDITIONAL ---- //

                // App build version (use if not nil)
                if (GAState.instance.build)
                {
                    annotations["build"] = GAState.instance.build;
                }

                return annotations;
            }

            public static getSdkErrorEventAnnotations(): {[key:string]: any}
            {
                var annotations:{[key:string]: any} = {};

                // ---- REQUIRED ---- //

                // collector event API version
                annotations["v"] = 2;
                // Event UUID
                annotations["event_uuid"] = GAUtilities.createGuid();

                // Category
                annotations["category"] = GAState.CategorySdkError;
                // SDK version
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                // Operation system version
                annotations["os_version"] = GADevice.osVersion;
                // Device make (hardcoded to apple)
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                // Device version
                annotations["device"] = GADevice.deviceModel;
                // Platform (operating system)
                annotations["platform"] = GADevice.buildPlatform;

                // type of connection the user is currently on (add if valid)
                var connection_type:string = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type))
                {
                    annotations["connection_type"] = connection_type;
                }

                if (GADevice.gameEngineVersion)
                {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }

                return annotations;
            }

            public static getInitAnnotations(): {[key:string]: any}
            {
                var initAnnotations:{[key:string]: any} = {};

                if(!GAState.getIdentifier())
                {
                    GAState.cacheIdentifier();
                }

                GAStore.setItem(GAState.getGameKey(), GAState.LastUsedIdentifierKey, GAState.getIdentifier());

                initAnnotations["user_id"] = GAState.getIdentifier();

                // SDK version
                initAnnotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                // Operation system version
                initAnnotations["os_version"] = GADevice.osVersion;

                // Platform (operating system)
                initAnnotations["platform"] = GADevice.buildPlatform;

                // Build
                if(GAState.getBuild())
                {
                    initAnnotations["build"] = GAState.getBuild();
                }
                else
                {
                    initAnnotations["build"] = null;
                }

                initAnnotations["session_num"] = GAState.getSessionNum();
                initAnnotations["random_salt"] = GAState.getSessionNum();

                return initAnnotations;
            }

            public static getClientTsAdjusted(): number
            {
                var clientTs:number = GAUtilities.timeIntervalSince1970();
                var clientTsAdjustedInteger:number = clientTs + GAState.instance.clientServerTimeOffset;

                if(GAValidator.validateClientTs(clientTsAdjustedInteger))
                {
                    return clientTsAdjustedInteger;
                }
                else
                {
                    return clientTs;
                }
            }

            public static sessionIsStarted(): boolean
            {
                return GAState.instance.sessionStart != 0;
            }

            private static cacheIdentifier(): void
            {
                if(GAState.instance.userId)
                {
                    GAState.instance.identifier = GAState.instance.userId;
                }
                else if(GAState.instance.defaultUserId)
                {
                    GAState.instance.identifier = GAState.instance.defaultUserId;
                }

                GALogger.d("identifier, {clean:" + GAState.instance.identifier + "}");
            }

            public static ensurePersistedStates(): void
            {
                // get and extract stored states
                if(GAStore.isStorageAvailable())
                {
                    GAStore.load(GAState.getGameKey());
                }

                // insert into GAState instance
                var instance:GAState = GAState.instance;

                instance.setDefaultId(GAStore.getItem(GAState.getGameKey(), GAState.DefaultUserIdKey) != null ? GAStore.getItem(GAState.getGameKey(), GAState.DefaultUserIdKey) : GAUtilities.createGuid());

                instance.sessionNum = GAStore.getItem(GAState.getGameKey(), GAState.SessionNumKey) != null ? Number(GAStore.getItem(GAState.getGameKey(), GAState.SessionNumKey)) : 0.0;

                instance.transactionNum = GAStore.getItem(GAState.getGameKey(), GAState.TransactionNumKey) != null ? Number(GAStore.getItem(GAState.getGameKey(), GAState.TransactionNumKey)) : 0.0;

                // restore dimension settings
                if(instance.currentCustomDimension01)
                {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension01Key, instance.currentCustomDimension01);
                }
                else
                {
                    instance.currentCustomDimension01 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension01Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension01Key) : "";
                    if(instance.currentCustomDimension01)
                    {
                        GALogger.d("Dimension01 found in cache: " + instance.currentCustomDimension01);
                    }
                }

                if(instance.currentCustomDimension02)
                {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension02Key, instance.currentCustomDimension02);
                }
                else
                {
                    instance.currentCustomDimension02 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension02Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension02Key) : "";
                    if(instance.currentCustomDimension02)
                    {
                        GALogger.d("Dimension02 found in cache: " + instance.currentCustomDimension02);
                    }
                }

                if(instance.currentCustomDimension03)
                {
                    GAStore.setItem(GAState.getGameKey(), GAState.Dimension03Key, instance.currentCustomDimension03);
                }
                else
                {
                    instance.currentCustomDimension03 = GAStore.getItem(GAState.getGameKey(), GAState.Dimension03Key) != null ? GAStore.getItem(GAState.getGameKey(), GAState.Dimension03Key) : "";
                    if(instance.currentCustomDimension03)
                    {
                        GALogger.d("Dimension03 found in cache: " + instance.currentCustomDimension03);
                    }
                }

                // get cached init call values
                var sdkConfigCachedString:string = GAStore.getItem(GAState.getGameKey(), GAState.SdkConfigCachedKey) != null ? GAStore.getItem(GAState.getGameKey(), GAState.SdkConfigCachedKey) : "";
                if (sdkConfigCachedString)
                {
                    // decode JSON
                    var sdkConfigCached = JSON.parse(GAUtilities.decode64(sdkConfigCachedString));
                    if (sdkConfigCached)
                    {
                        var lastUsedIdentifier:string = GAStore.getItem(GAState.getGameKey(), GAState.LastUsedIdentifierKey);
                        GALogger.d("lastUsedIdentifier=" + lastUsedIdentifier + ", GAState.getIdentifier()=" + GAState.getIdentifier());
                        if (lastUsedIdentifier != null && lastUsedIdentifier != GAState.getIdentifier())
                        {
                            GALogger.w("New identifier spotted compared to last one used, clearing cached configs hash!!");
                            if (sdkConfigCached["configs_hash"])
                            {
                                delete sdkConfigCached["configs_hash"];
                            }
                        }
                        instance.sdkConfigCached = sdkConfigCached;
                    }
                }

                {
                    var currentSdkConfig:{[key:string]: any} = GAState.getSdkConfig();
                    instance.configsHash = currentSdkConfig["configs_hash"] ? currentSdkConfig["configs_hash"] : "";
                    instance.abId = currentSdkConfig["ab_id"] ? currentSdkConfig["ab_id"] : "";
                    instance.abVariantId = currentSdkConfig["ab_variant_id"] ? currentSdkConfig["ab_variant_id"] : "";
                }

                var results_ga_progression:Array<{[key:string]: any}> = GAStore.select(EGAStore.Progression);

                if (results_ga_progression)
                {
                    for (let i = 0; i < results_ga_progression.length; ++i)
                    {
                        var result:{[key:string]: any} = results_ga_progression[i];
                        if (result)
                        {
                            instance.progressionTries[result["progression"] as string] = result["tries"] as number;
                        }
                    }
                }
            }

            public static calculateServerTimeOffset(serverTs:number): number
            {
                var clientTs:number = GAUtilities.timeIntervalSince1970();
                return serverTs - clientTs;
            }

            private static formatString(s:string, args:Array<string>): string
            {
                var formatted: string = s;
                for (var i = 0; i < args.length; i++)
                {
                    var regexp = new RegExp('\\{' + i + '\\}', 'gi');
                    formatted = formatted.replace(regexp, arguments[i]);
                }
                return formatted;
            }

            public static validateAndCleanCustomFields(fields:{[id:string]: any}, errorCallback:(baseMessage:string, message:string) => void=null): {[id:string]: any}
            {
                var result:{[id:string]: any} = {};

                if(fields)
                {
                    var count:number = 0;

                    for(var key in fields)
                    {
                        var value:any = fields[key];

                        if(!key || !value)
                        {
                            var baseMessage:string = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its key or value is null";
                            var message:string = GAState.formatString(baseMessage, [key, value]);
                            GALogger.w(message);
                            if (errorCallback)
                            {
                                errorCallback(baseMessage, message);
                            }
                        }
                        else if(count < GAState.MAX_CUSTOM_FIELDS_COUNT)
                        {
                            var regex = new RegExp("^[a-zA-Z0-9_]{1," + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + "}$");
                            if(GAUtilities.stringMatch(key, regex))
                            {
                                var type = typeof value;
                                if(type === "string" || value instanceof String)
                                {
                                    var valueAsString:string = value as string;

                                    if(valueAsString.length <= GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH && valueAsString.length > 0)
                                    {
                                        result[key] = valueAsString;
                                        ++count;
                                    }
                                    else
                                    {
                                        var baseMessage: string = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its value is an empty string or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH + ")";
                                        var message: string = GAState.formatString(baseMessage, [key, value]);
                                        GALogger.w(message);
                                        if (errorCallback) {
                                            errorCallback(baseMessage, message);
                                        }
                                    }
                                }
                                else if(type === "number" || value instanceof Number)
                                {
                                    var valueAsNumber:number = value as number;

                                    result[key] = valueAsNumber;
                                    ++count;
                                }
                                else
                                {
                                    var baseMessage: string = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its value is not a string or number";
                                    var message: string = GAState.formatString(baseMessage, [key, value]);
                                    GALogger.w(message);
                                    if (errorCallback) {
                                        errorCallback(baseMessage, message);
                                    }
                                }
                            }
                            else
                            {
                                var baseMessage: string = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because its key contains illegal character, is empty or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + ")";
                                var message: string = GAState.formatString(baseMessage, [key, value]);
                                GALogger.w(message);
                                if (errorCallback) {
                                    errorCallback(baseMessage, message);
                                }
                            }
                        }
                        else
                        {
                            var baseMessage: string = "validateAndCleanCustomFields: entry with key={0}, value={1} has been omitted because it exceeds the max number of custom fields (" + GAState.MAX_CUSTOM_FIELDS_COUNT + ")";
                            var message: string = GAState.formatString(baseMessage, [key, value]);
                            GALogger.w(message);
                            if (errorCallback) {
                                errorCallback(baseMessage, message);
                            }
                        }
                    }
                }

                return result;
            }

            public static validateAndFixCurrentDimensions(): void
            {
                // validate that there are no current dimension01 not in list
                if (!GAValidator.validateDimension01(GAState.getCurrentCustomDimension01(), GAState.getAvailableCustomDimensions01()))
                {
                    GALogger.d("Invalid dimension01 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension01());
                    GAState.setCustomDimension01("");
                }
                // validate that there are no current dimension02 not in list
                if (!GAValidator.validateDimension02(GAState.getCurrentCustomDimension02(), GAState.getAvailableCustomDimensions02()))
                {
                    GALogger.d("Invalid dimension02 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension02());
                    GAState.setCustomDimension02("");
                }
                // validate that there are no current dimension03 not in list
                if (!GAValidator.validateDimension03(GAState.getCurrentCustomDimension03(), GAState.getAvailableCustomDimensions03()))
                {
                    GALogger.d("Invalid dimension03 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension03());
                    GAState.setCustomDimension03("");
                }
            }

            public static getConfigurationStringValue(key:string, defaultValue:string):string
            {
                if(GAState.instance.configurations[key])
                {
                    return GAState.instance.configurations[key].toString();
                }
                else
                {
                    return defaultValue;
                }
            }

            public static isRemoteConfigsReady():boolean
            {
                return GAState.instance.remoteConfigsIsReady;
            }

            public static addRemoteConfigsListener(listener:{ onRemoteConfigsUpdated:() => void }):void
            {
                if(GAState.instance.remoteConfigsListeners.indexOf(listener) < 0)
                {
                    GAState.instance.remoteConfigsListeners.push(listener);
                }
            }

            public static removeRemoteConfigsListener(listener:{ onRemoteConfigsUpdated:() => void }):void
            {
                var index = GAState.instance.remoteConfigsListeners.indexOf(listener);
                if(index > -1)
                {
                    GAState.instance.remoteConfigsListeners.splice(index, 1);
                }
            }

            public static getRemoteConfigsContentAsString():string
            {
                return JSON.stringify(GAState.instance.configurations);
            }

            public static populateConfigurations(sdkConfig:{[key:string]: any}):void
            {
                var configurations:any[] = sdkConfig["configs"];

                if(configurations)
                {
                    GAState.instance.configurations = {};
                    for(let i = 0; i < configurations.length; ++i)
                    {
                        var configuration:{[key:string]: any} = configurations[i];

                        if(configuration)
                        {
                            var key:string = configuration["key"];
                            var value:any = configuration["value"];
                            var start_ts:number = configuration["start_ts"] ? configuration["start_ts"] : Number.MIN_VALUE;
                            var end_ts:number = configuration["end_ts"] ? configuration["end_ts"] : Number.MAX_VALUE;

                            var client_ts_adjusted:number = GAState.getClientTsAdjusted();

                            if(key && value && client_ts_adjusted > start_ts && client_ts_adjusted < end_ts)
                            {
                                GAState.instance.configurations[key] = value;
                                GALogger.d("configuration added: " + JSON.stringify(configuration));
                            }
                        }
                    }
                }
                GAState.instance.remoteConfigsIsReady = true;

                var listeners:Array<{ onRemoteConfigsUpdated:() => void }> = GAState.instance.remoteConfigsListeners;

                for(let i = 0; i < listeners.length; ++i)
                {
                    if(listeners[i])
                    {
                        listeners[i].onRemoteConfigsUpdated();
                    }
                }
            }

            public static addOnBeforeUnloadListener(listener: { onBeforeUnload: () => void }): void
            {
                if (GAState.instance.beforeUnloadListeners.indexOf(listener) < 0)
                {
                    GAState.instance.beforeUnloadListeners.push(listener);
                }
            }

            public static removeOnBeforeUnloadListener(listener: { onBeforeUnload: () => void }): void
            {
                var index = GAState.instance.beforeUnloadListeners.indexOf(listener);
                if (index > -1)
                {
                    GAState.instance.beforeUnloadListeners.splice(index, 1);
                }
            }

            public static notifyBeforeUnloadListeners(): void
            {
                var listeners: Array<{ onBeforeUnload: () => void }> = GAState.instance.beforeUnloadListeners;

                for (let i = 0; i < listeners.length; ++i)
                {
                    if (listeners[i])
                    {
                        listeners[i].onBeforeUnload();
                    }
                }
            }
        }
    }
}
