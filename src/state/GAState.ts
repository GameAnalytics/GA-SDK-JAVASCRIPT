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

            public static readonly instance:GAState = new GAState();

            private constructor()
            {
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
            }

            private useManualSessionHandling:boolean;
            public static getUseManualSessionHandling(): boolean
            {
                return GAState.instance.useManualSessionHandling;
            }

            private facebookId:string;
            private gender:string;
            private birthYear:number;
            public sdkConfigCached:{[key:string]: any};
            public initAuthorized:boolean;
            public clientServerTimeOffset:number;

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
            private static getSdkConfig(): {[key:string]: any}
            {
                {
                    var first;
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
                    var first;
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
            private static readonly FacebookIdKey:string = "facebook_id";
            private static readonly GenderKey:string = "gender";
            private static readonly BirthYearKey:string = "birth_year";
            private static readonly Dimension01Key:string = "dimension01";
            private static readonly Dimension02Key:string = "dimension02";
            private static readonly Dimension03Key:string = "dimension03";
            public static readonly SdkConfigCachedKey:string = "sdk_config_cached";

            public static isEnabled(): boolean
            {
                var currentSdkConfig:{[key:string]: any} = GAState.getSdkConfig();

                if (currentSdkConfig["enabled"] && currentSdkConfig["enabled"] == "false")
                {
                    return false;
                }
                else if (!GAState.instance.initAuthorized)
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
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.Dimension01Key, dimension);
                }
                GALogger.i("Set custom01 dimension value: " + dimension);
            }

            public static setCustomDimension02(dimension:string): void
            {
                GAState.instance.currentCustomDimension02 = dimension;
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.Dimension02Key, dimension);
                }
                GALogger.i("Set custom02 dimension value: " + dimension);
            }

            public static setCustomDimension03(dimension:string): void
            {
                GAState.instance.currentCustomDimension03 = dimension;
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.Dimension03Key, dimension);
                }
                GALogger.i("Set custom03 dimension value: " + dimension);
            }

            public static setFacebookId(facebookId:string): void
            {
                GAState.instance.facebookId = facebookId;
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.FacebookIdKey, facebookId);
                }
                GALogger.i("Set facebook id: " + facebookId);
            }

            public static setGender(gender:EGAGender): void
            {
                GAState.instance.gender = gender.toString().toLowerCase();
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.GenderKey, GAState.instance.gender);
                }
                GALogger.i("Set gender: " + gender);
            }

            public static setBirthYear(birthYear:number): void
            {
                GAState.instance.birthYear = birthYear;
                if(GAStore.isStorageAvailable())
                {
                    GAStore.setItem(GAState.BirthYearKey, birthYear.toString());
                }
                GALogger.i("Set birth year: " + birthYear);
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

            public static getEventAnnotations(): {[key:string]: any}
            {
                var annotations:{[key:string]: any} = {};

                // ---- REQUIRED ---- //

                // collector event API version
                annotations["v"] = 2;
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

                // ---- CONDITIONAL ---- //

                // App build version (use if not nil)
                if (GAState.instance.build)
                {
                    annotations["build"] = GAState.instance.build;
                }

                // ---- OPTIONAL cross-session ---- //

                // facebook id (optional)
                if (GAState.instance.facebookId)
                {
                    annotations[GAState.FacebookIdKey] = GAState.instance.facebookId;
                }
                // gender (optional)
                if (GAState.instance.gender)
                {
                    annotations[GAState.GenderKey] = GAState.instance.gender;
                }
                // birth_year (optional)
                if (GAState.instance.birthYear != 0)
                {
                    annotations[GAState.BirthYearKey] = GAState.instance.birthYear;
                }

                return annotations;
            }

            public static getSdkErrorEventAnnotations(): {[key:string]: any}
            {
                var annotations:{[key:string]: any} = {};

                // ---- REQUIRED ---- //

                // collector event API version
                annotations["v"] = 2;

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

                // SDK version
                initAnnotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                // Operation system version
                initAnnotations["os_version"] = GADevice.osVersion;

                // Platform (operating system)
                initAnnotations["platform"] = GADevice.buildPlatform;

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
                if(!GAState.instance.userId)
                {
                    GAState.instance.identifier = GAState.instance.userId;
                }
                else if(!GAState.instance.defaultUserId)
                {
                    GAState.instance.identifier = GAState.instance.defaultUserId;
                }

                GALogger.d("identifier, {clean:" + GAState.instance.identifier + "}");
            }

            public static ensurePersistedStates(): void
            {
                throw new Error("ensurePersistedStates not implemented");
                // get and extract stored states
            //     JSONClass state_dict = new JSONClass();
            //     JSONArray results_ga_state = GAStore.ExecuteQuerySync("SELECT * FROM ga_state;");
            //
            //     if (results_ga_state != null && results_ga_state.Count != 0)
            //     {
            //         for (int i = 0; i < results_ga_state.Count; ++i)
            //         {
            //             JSONNode result = results_ga_state[i];
            //             state_dict.Add(result["key"], result["value"]);
            //         }
            //     }
            //
            //     // insert into GAState instance
            //     GAState instance = GAState.Instance;
            //
            //     instance.DefaultUserId = state_dict[DefaultUserIdKey] != null ? state_dict[DefaultUserIdKey].AsString : Guid.NewGuid().ToString();
            //
            //     SessionNum = state_dict[SessionNumKey] != null ? state_dict[SessionNumKey].AsDouble : 0.0;
            //
            //     TransactionNum = state_dict[TransactionNumKey] != null ? state_dict[TransactionNumKey].AsDouble : 0.0;
            //
            //     // restore cross session user values
            //     if(!string.IsNullOrEmpty(instance.FacebookId))
            //     {
            //         GAStore.SetState(FacebookIdKey, instance.FacebookId);
            //     }
            //     else
            //     {
            //         instance.FacebookId = state_dict[FacebookIdKey] != null ? state_dict[FacebookIdKey].AsString : "";
            //         if(!string.IsNullOrEmpty(instance.FacebookId))
            //         {
            //             GALogger.D("facebookid found in DB: " + instance.FacebookId);
            //         }
            //     }
            //
            //     if(!string.IsNullOrEmpty(instance.FacebookId))
            //     {
            //         GAStore.SetState(FacebookIdKey, instance.FacebookId);
            //     }
            //     else
            //     {
            //         instance.Gender = state_dict[GenderKey] != null ? state_dict[GenderKey].AsString : "";
            //         if(!string.IsNullOrEmpty(instance.Gender))
            //         {
            //             GALogger.D("gender found in DB: " + instance.Gender);
            //         }
            //     }
            //
            //     if(instance.BirthYear != 0)
            //     {
            //         GAStore.SetState(BirthYearKey, instance.BirthYear.ToString());
            //     }
            //     else
            //     {
            //         instance.BirthYear = state_dict[BirthYearKey] != null ? state_dict[BirthYearKey].AsInt : 0;
            //         if(instance.BirthYear != 0)
            //         {
            //             GALogger.D("birthYear found in DB: " + instance.BirthYear);
            //         }
            //     }
            //
            //     // restore dimension settings
            //     if(!string.IsNullOrEmpty(CurrentCustomDimension01))
            //     {
            //         GAStore.SetState(Dimension01Key, CurrentCustomDimension01);
            //     }
            //     else
            //     {
            //         CurrentCustomDimension01 = state_dict[Dimension01Key] != null ? state_dict[Dimension01Key].AsString : "";
            //         if(!string.IsNullOrEmpty(CurrentCustomDimension01))
            //         {
            //             GALogger.D("Dimension01 found in cache: " + CurrentCustomDimension01);
            //         }
            //     }
            //
            //     if(!string.IsNullOrEmpty(CurrentCustomDimension02))
            //     {
            //         GAStore.SetState(Dimension02Key, CurrentCustomDimension02);
            //     }
            //     else
            //     {
            //         CurrentCustomDimension02 = state_dict[Dimension02Key] != null ? state_dict[Dimension02Key].AsString : "";
            //         if(!string.IsNullOrEmpty(CurrentCustomDimension02))
            //         {
            //             GALogger.D("Dimension02 found in cache: " + CurrentCustomDimension02);
            //         }
            //     }
            //
            //     if(!string.IsNullOrEmpty(CurrentCustomDimension03))
            //     {
            //         GAStore.SetState(Dimension03Key, CurrentCustomDimension03);
            //     }
            //     else
            //     {
            //         CurrentCustomDimension03 = state_dict[Dimension03Key] != null ? state_dict[Dimension03Key].AsString : "";
            //         if(!string.IsNullOrEmpty(CurrentCustomDimension03))
            //         {
            //             GALogger.D("Dimension03 found in cache: " + CurrentCustomDimension03);
            //         }
            //     }
            //
            //     // get cached init call values
            //     string sdkConfigCachedString = state_dict[SdkConfigCachedKey] != null ? state_dict[SdkConfigCachedKey].AsString : "";
            //     if (!string.IsNullOrEmpty(sdkConfigCachedString))
            //     {
            //         // decode JSON
            //         JSONNode sdkConfigCached = JSONNode.LoadFromBase64(sdkConfigCachedString);
            //         if (sdkConfigCached != null && sdkConfigCached.Count != 0)
            //         {
            //             instance.SdkConfigCached = sdkConfigCached;
            //         }
            //     }
            //
            //     JSONArray results_ga_progression = GAStore.ExecuteQuerySync("SELECT * FROM ga_progression;");
            //
            //     if (results_ga_progression != null && results_ga_progression.Count != 0)
            //     {
            //         for (int i = 0; i < results_ga_progression.Count; ++i)
            //         {
            //             JSONNode result = results_ga_progression[i];
            //             if (result != null && result.Count != 0)
            //             {
            //                 instance.progressionTries[result["progression"].AsString] = result["tries"].AsInt;
            //             }
            //         }
            //     }
            }

            public static calculateServerTimeOffset(serverTs:number): number
            {
                var clientTs:number = GAUtilities.timeIntervalSince1970();
                return serverTs - clientTs;
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
        }
    }
}
