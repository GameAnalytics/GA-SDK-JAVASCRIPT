module gameanalytics
{
    export module state
    {
        import GAValidator = gameanalytics.validators.GAValidator;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GALogger = gameanalytics.logging.GALogger;
        import GAStore = gameanalytics.store.GAStore;

        export class GAState
        {
            private static readonly CategorySdkError:string = "sdk_error";

            private static readonly instance:GAState = new GAState();

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

            private sessionStart:number;
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

            private sessionId:string;
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
            private sdkConfigCached:{[key:string]: any};
            private initAuthorized:boolean;
            private clientServerTimeOffset:number;

            private defaultUserId:string;
            private setDefaultId(value:string): void
            {
                this.defaultUserId = !value ? "" : value;
                GAState.cacheIdentifier();
            }

            private sdkConfigDefault:{[key:string]: string} = {};

            private sdkConfig:{[key:string]: any} = {};
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
            private static readonly DefaultUserIdKey:string = "default_user_id";
            public static readonly SessionNumKey:string = "session_num";
            public static readonly TransactionNumKey:string = "transaction_num";
            private static readonly FacebookIdKey:string = "facebook_id";
            private static readonly GenderKey:string = "gender";
            private static readonly BirthYearKey:string = "birth_year";
            private static readonly Dimension01Key:string = "dimension01";
            private static readonly Dimension02Key:string = "dimension02";
            private static readonly Dimension03Key:string = "dimension03";
            private static readonly SdkConfigCachedKey:string = "sdk_config_cached";

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
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.Dimension01Key, dimension);
                }
                GALogger.i("Set custom01 dimension value: " + dimension);
            }

            public static setCustomDimension02(dimension:string): void
            {
                GAState.instance.currentCustomDimension02 = dimension;
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.Dimension02Key, dimension);
                }
                GALogger.i("Set custom02 dimension value: " + dimension);
            }

            public static setCustomDimension03(dimension:string): void
            {
                GAState.instance.currentCustomDimension03 = dimension;
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.Dimension03Key, dimension);
                }
                GALogger.i("Set custom03 dimension value: " + dimension);
            }

            public static setFacebookId(facebookId:string): void
            {
                GAState.instance.facebookId = facebookId;
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.FacebookIdKey, facebookId);
                }
                GALogger.i("Set facebook id: " + facebookId);
            }

            public static setGender(gender:EGAGender): void
            {
                GAState.instance.gender = gender.toString().toLowerCase();
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.GenderKey, GAState.instance.gender);
                }
                GALogger.i("Set gender: " + gender);
            }

            public static setBirthYear(birthYear:number): void
            {
                GAState.instance.birthYear = birthYear;
                if(GAStore.isTableReady())
                {
                    GAStore.setState(GAState.BirthYearKey, birthYear.toString());
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

            // public static incrementProgressionTries(progression:string): void
            // {
            //     var tries:number = GAState.getProgressionTries(progression) + 1;
            //     GAState.instance.progressionTries[progression] = tries;
            //
            //     // Persist
            //     var parms:{[key:string]: any} = {};
            //     parms["$progression"] = progression;
            //     parms["$tries"] = tries;
            //     GAStore.ExecuteQuerySync("INSERT OR REPLACE INTO ga_progression (progression, tries) VALUES($progression, $tries);", parms);
            // }

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

            // public static void ClearProgressionTries(string progression)
            // {
            //     Dictionary<string, int> progressionTries = Instance.progressionTries;
            //     if(progressionTries.ContainsKey(progression))
            //     {
            //         progressionTries.Remove(progression);
            //     }
            //
            //     if(GAStore.InMemory)
            //     {
            //         GALogger.D("Trying to ClearProgressionTries with InMemory=true - cannot. Skipping.");
            //     }
            //     else
            //     {
            //         // Delete
            //         Dictionary<string, object> parms = new Dictionary<string, object>();
            //         parms.Add("$progression", progression);
            //         GAStore.ExecuteQuerySync("DELETE FROM ga_progression WHERE progression = $progression;", parms);
            //     }
            // }

            public static hasAvailableCustomDimensions01(dimension1:string): boolean
            {
                return GAUtilities.stringArrayContainsString(GAState.getAvailableCustomDimensions01(), dimension1);
            }

            public static hasAvailableCustomDimensions02(dimension2:string): boolean
            {
                return GAUtilities.stringArrayContainsString(GAState.getAvailableCustomDimensions02(), dimension2);
            }

            public static hasAvailableCustomDimensions03(dimension3:string): boolean
            {
                return GAUtilities.stringArrayContainsString(GAState.getAvailableCustomDimensions03(), dimension3);
            }

            public static hasAvailableResourceCurrency(currency:string): boolean
            {
                return GAUtilities.stringArrayContainsString(GAState.getAvailableResourceCurrencies(), currency);
            }

            public static hasAvailableResourceItemType(itemType:string): boolean
            {
                return GAUtilities.stringArrayContainsString(GAState.getAvailableResourceItemTypes(), itemType);
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

            private static validateAndFixCurrentDimensions(): void
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
