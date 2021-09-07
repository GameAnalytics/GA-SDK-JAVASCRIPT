module gameanalytics
{
    export module validators
    {
        import GALogger = gameanalytics.logging.GALogger;
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import EGASdkErrorCategory = gameanalytics.events.EGASdkErrorCategory;
        import EGASdkErrorArea = gameanalytics.events.EGASdkErrorArea;
        import EGASdkErrorAction = gameanalytics.events.EGASdkErrorAction;
        import EGASdkErrorParameter = gameanalytics.events.EGASdkErrorParameter;

        export class ValidationResult
        {
            public category:EGASdkErrorCategory;
            public area:EGASdkErrorArea;
            public action:EGASdkErrorAction;
            public parameter:EGASdkErrorParameter;
            public reason:string;

            public constructor(category:EGASdkErrorCategory, area:EGASdkErrorArea, action:EGASdkErrorAction, parameter:EGASdkErrorParameter, reason:string)
            {
                this.category = category;
                this.area = area;
                this.action = action;
                this.parameter = parameter;
                this.reason = reason;
            }
        }

        export class GAValidator
        {
            public static validateBusinessEvent(currency:string, amount:number, cartType:string, itemType:string, itemId:string): ValidationResult
            {
                // validate currency
                if (!GAValidator.validateCurrency(currency))
                {
                    GALogger.w("Validation fail - business event - currency: Cannot be (null) and need to be A-Z, 3 characters and in the standard at openexchangerates.org. Failed currency: " + currency);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidCurrency, EGASdkErrorParameter.Currency, currency);
                }

                if (amount < 0)
                {
                    GALogger.w("Validation fail - business event - amount. Cannot be less than 0. Failed amount: " + amount);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidAmount, EGASdkErrorParameter.Amount, amount + "");
                }

                // validate cartType
                if (!GAValidator.validateShortString(cartType, true))
                {
                    GALogger.w("Validation fail - business event - cartType. Cannot be above 32 length. String: " + cartType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidShortString, EGASdkErrorParameter.CartType, cartType);
                }

                // validate itemType length
                if (!GAValidator.validateEventPartLength(itemType, false))
                {
                    GALogger.w("Validation fail - business event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemType, itemType);
                }

                // validate itemType chars
                if (!GAValidator.validateEventPartCharacters(itemType))
                {
                    GALogger.w("Validation fail - business event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemType, itemType);
                }

                // validate itemId
                if (!GAValidator.validateEventPartLength(itemId, false))
                {
                    GALogger.w("Validation fail - business event - itemId. Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemId, itemId);
                }

                if (!GAValidator.validateEventPartCharacters(itemId))
                {
                    GALogger.w("Validation fail - business event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.BusinessEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemId, itemId);
                }

                return null;
            }

            public static validateResourceEvent(flowType:EGAResourceFlowType, currency:string, amount:number, itemType:string, itemId:string, availableCurrencies:Array<string>, availableItemTypes:Array<string>): ValidationResult
            {
                if (flowType == EGAResourceFlowType.Undefined)
                {
                    GALogger.w("Validation fail - resource event - flowType: Invalid flow type.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidFlowType, EGASdkErrorParameter.FlowType, "");
                }
                if (!currency)
                {
                    GALogger.w("Validation fail - resource event - currency: Cannot be (null)");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.StringEmptyOrNull, EGASdkErrorParameter.Currency, "");
                }
                if (!GAUtilities.stringArrayContainsString(availableCurrencies, currency))
                {
                    GALogger.w("Validation fail - resource event - currency: Not found in list of pre-defined available resource currencies. String: " + currency);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.NotFoundInAvailableCurrencies, EGASdkErrorParameter.Currency, currency);
                }
                if (!(amount > 0))
                {
                    GALogger.w("Validation fail - resource event - amount: Float amount cannot be 0 or negative. Value: " + amount);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidAmount, EGASdkErrorParameter.Amount, amount + "");
                }
                if (!itemType)
                {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null)");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.StringEmptyOrNull, EGASdkErrorParameter.ItemType, "");
                }
                if (!GAValidator.validateEventPartLength(itemType, false))
                {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartCharacters(itemType))
                {
                    GALogger.w("Validation fail - resource event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAUtilities.stringArrayContainsString(availableItemTypes, itemType))
                {
                    GALogger.w("Validation fail - resource event - itemType: Not found in list of pre-defined available resource itemTypes. String: " + itemType);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.NotFoundInAvailableItemTypes, EGASdkErrorParameter.ItemType, itemType);
                }
                if (!GAValidator.validateEventPartLength(itemId, false))
                {
                    GALogger.w("Validation fail - resource event - itemId: Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.ItemId, itemId);
                }
                if (!GAValidator.validateEventPartCharacters(itemId))
                {
                    GALogger.w("Validation fail - resource event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.ItemId, itemId);
                }
                return null;
            }

            public static validateProgressionEvent(progressionStatus:EGAProgressionStatus, progression01:string, progression02:string, progression03:string): ValidationResult
            {
                if (progressionStatus == EGAProgressionStatus.Undefined)
                {
                    GALogger.w("Validation fail - progression event: Invalid progression status.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidProgressionStatus, EGASdkErrorParameter.ProgressionStatus, "");
                }

                // Make sure progressions are defined as either 01, 01+02 or 01+02+03
                if (progression03 && !(progression02 || !progression01))
                {
                    GALogger.w("Validation fail - progression event: 03 found but 01+02 are invalid. Progression must be set as either 01, 01+02 or 01+02+03.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, progression01 + ":" + progression02 + ":" + progression03);
                }
                else if (progression02 && !progression01)
                {
                    GALogger.w("Validation fail - progression event: 02 found but not 01. Progression must be set as either 01, 01+02 or 01+02+03");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, progression01 + ":" + progression02 + ":" + progression03);
                }
                else if (!progression01)
                {
                    GALogger.w("Validation fail - progression event: progression01 not valid. Progressions must be set as either 01, 01+02 or 01+02+03");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.WrongProgressionOrder, EGASdkErrorParameter.Undefined, (progression01 ? progression01 : "") + ":" + (progression02 ? progression02 : "") + ":" + (progression03 ? progression03 : ""));
                }

                // progression01 (required)
                if (!GAValidator.validateEventPartLength(progression01, false))
                {
                    GALogger.w("Validation fail - progression event - progression01: Cannot be (null), empty or above 64 characters. String: " + progression01);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression01, progression01);
                }
                if (!GAValidator.validateEventPartCharacters(progression01))
                {
                    GALogger.w("Validation fail - progression event - progression01: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression01);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression01, progression01);
                }
                // progression02
                if (progression02)
                {
                    if (!GAValidator.validateEventPartLength(progression02, true))
                    {
                        GALogger.w("Validation fail - progression event - progression02: Cannot be empty or above 64 characters. String: " + progression02);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression02, progression02);
                    }
                    if (!GAValidator.validateEventPartCharacters(progression02))
                    {
                        GALogger.w("Validation fail - progression event - progression02: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression02);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression02, progression02);
                    }
                }
                // progression03
                if (progression03)
                {
                    if (!GAValidator.validateEventPartLength(progression03, true))
                    {
                        GALogger.w("Validation fail - progression event - progression03: Cannot be empty or above 64 characters. String: " + progression03);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartLength, EGASdkErrorParameter.Progression03, progression03);
                    }
                    if (!GAValidator.validateEventPartCharacters(progression03))
                    {
                        GALogger.w("Validation fail - progression event - progression03: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression03);
                        return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ProgressionEvent, EGASdkErrorAction.InvalidEventPartCharacters, EGASdkErrorParameter.Progression03, progression03);
                    }
                }
                return null;
            }

            public static validateDesignEvent(eventId:string): ValidationResult
            {
                if (!GAValidator.validateEventIdLength(eventId))
                {
                    GALogger.w("Validation fail - design event - eventId: Cannot be (null) or empty. Only 5 event parts allowed seperated by :. Each part need to be 64 characters or less. String: " + eventId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.DesignEvent, EGASdkErrorAction.InvalidEventIdLength, EGASdkErrorParameter.EventId, eventId);
                }
                if (!GAValidator.validateEventIdCharacters(eventId))
                {
                    GALogger.w("Validation fail - design event - eventId: Non valid characters. Only allowed A-z, 0-9, -_., ()!?. String: " + eventId);
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.DesignEvent, EGASdkErrorAction.InvalidEventIdCharacters, EGASdkErrorParameter.EventId, eventId);
                }
                // value: allow 0, negative and nil (not required)
                return null;
            }

            public static validateErrorEvent(severity:EGAErrorSeverity, message:string): ValidationResult
            {
                if (severity == EGAErrorSeverity.Undefined)
                {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ErrorEvent, EGASdkErrorAction.InvalidSeverity, EGASdkErrorParameter.Severity, "");
                }
                if (!GAValidator.validateLongString(message, true))
                {
                    GALogger.w("Validation fail - error event - message: Message cannot be above 8192 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ErrorEvent, EGASdkErrorAction.InvalidLongString, EGASdkErrorParameter.Message, message);
                }
                return null;
            }

            public static validateAdEvent(adAction:EGAAdAction, adType:EGAAdType, adSdkName:string, adPlacement:string): ValidationResult
            {
                if (adAction == EGAAdAction.Undefined)
                {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidAdAction, EGASdkErrorParameter.AdAction, "");
                }
                if (adType == EGAAdType.Undefined)
                {
                    GALogger.w("Validation fail - ad event - adType: Ad type was unsupported value.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidAdType, EGASdkErrorParameter.AdType, "");
                }
                if (!GAValidator.validateShortString(adSdkName, false))
                {
                    GALogger.w("Validation fail - ad event - message: Ad SDK name cannot be above 32 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidShortString, EGASdkErrorParameter.AdSdkName, adSdkName);
                }
                if (!GAValidator.validateString(adPlacement, false))
                {
                    GALogger.w("Validation fail - ad event - message: Ad placement cannot be above 64 characters.");
                    return new ValidationResult(EGASdkErrorCategory.EventValidation, EGASdkErrorArea.AdEvent, EGASdkErrorAction.InvalidString, EGASdkErrorParameter.AdPlacement, adPlacement);
                }
                return null;
            }

            public static validateSdkErrorEvent(gameKey:string, gameSecret:string, category:EGASdkErrorCategory, area:EGASdkErrorArea, action:EGASdkErrorAction): boolean
            {
                if(!GAValidator.validateKeys(gameKey, gameSecret))
                {
                    return false;
                }

                if (category === EGASdkErrorCategory.Undefined)
                {
                    GALogger.w("Validation fail - sdk error event - type: Category was unsupported value.");
                    return false;
                }
                if (area === EGASdkErrorArea.Undefined)
                {
                    GALogger.w("Validation fail - sdk error event - type: Area was unsupported value.");
                    return false;
                }
                if (action === EGASdkErrorAction.Undefined)
                {
                    GALogger.w("Validation fail - sdk error event - type: Action was unsupported value.");
                    return false;
                }
                return true;
            }

            public static validateKeys(gameKey:string, gameSecret:string): boolean
            {
                if (GAUtilities.stringMatch(gameKey, /^[A-z0-9]{32}$/))
                {
                    if (GAUtilities.stringMatch(gameSecret, /^[A-z0-9]{40}$/))
                    {
                        return true;
                    }
                }
                return false;
            }

            public static validateCurrency(currency:string): boolean
            {
                if (!currency)
                {
                    return false;
                }
                if (!GAUtilities.stringMatch(currency, /^[A-Z]{3}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateEventPartLength(eventPart:string, allowNull:boolean): boolean
            {
                if (allowNull && !eventPart)
                {
                    return true;
                }

                if (!eventPart)
                {
                    return false;
                }

                if (eventPart.length > 64)
                {
                    return false;
                }
                return true;
            }

            public static validateEventPartCharacters(eventPart:string): boolean
            {
                if (!GAUtilities.stringMatch(eventPart, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateEventIdLength(eventId:string): boolean
            {
                if (!eventId)
                {
                    return false;
                }

                if (!GAUtilities.stringMatch(eventId, /^[^:]{1,64}(?::[^:]{1,64}){0,4}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateEventIdCharacters(eventId:string): boolean
            {
                if (!eventId)
                {
                    return false;
                }

                if (!GAUtilities.stringMatch(eventId, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}(:[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}){0,4}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateAndCleanInitRequestResponse(initResponse:{[key:string]: any}, configsCreated:boolean): {[key:string]: any}
            {
                // make sure we have a valid dict
                if (initResponse == null)
                {
                    GALogger.w("validateInitRequestResponse failed - no response dictionary.");
                    return null;
                }

                var validatedDict:{[key:string]: any} = {};

                // validate server_ts
                try
                {
                    var serverTsNumber:number = initResponse["server_ts"];
                    if (serverTsNumber > 0)
                    {
                        validatedDict["server_ts"] = serverTsNumber;
                    }
                    else
                    {
                        GALogger.w("validateInitRequestResponse failed - invalid value in 'server_ts' field.");
                        return null;
                    }
                }
                catch (e)
                {
                    GALogger.w("validateInitRequestResponse failed - invalid type in 'server_ts' field. type=" + typeof initResponse["server_ts"] + ", value=" + initResponse["server_ts"] + ", " + e);
                    return null;
                }

                if(configsCreated)
                {
                    // validate configs field
                    try
                    {
                        var configurations:any[] = initResponse["configs"];
                        validatedDict["configs"] = configurations;
                    }
                    catch (e)
                    {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs' field. type=" + typeof initResponse["configs"] + ", value=" + initResponse["configs"] + ", " + e);
                        return null;
                    }

                    try
                    {
                        var configs_hash:string = initResponse["configs_hash"];
                        validatedDict["configs_hash"] = configs_hash;
                    }
                    catch (e)
                    {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs_hash' field. type=" + typeof initResponse["configs_hash"] + ", value=" + initResponse["configs_hash"] + ", " + e);
                        return null;
                    }

                    // validate ab_id field
                    try
                    {
                        var ab_id:string = initResponse["ab_id"];
                        validatedDict["ab_id"] = ab_id;
                    }
                    catch (e)
                    {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_id' field. type=" + typeof initResponse["ab_id"] + ", value=" + initResponse["ab_id"] + ", " + e);
                        return null;
                    }

                    // validate ab_variant_id field
                    try
                    {
                        var ab_variant_id:string = initResponse["ab_variant_id"];
                        validatedDict["ab_variant_id"] = ab_variant_id;
                    }
                    catch (e)
                    {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_variant_id' field. type=" + typeof initResponse["ab_variant_id"] + ", value=" + initResponse["ab_variant_id"] + ", " + e);
                        return null;
                    }
                }


                return validatedDict;
            }

            public static validateBuild(build:string): boolean
            {
                if (!GAValidator.validateShortString(build, false))
                {
                    return false;
                }
                return true;
            }

            public static validateSdkWrapperVersion(wrapperVersion:string): boolean
            {
                if (!GAUtilities.stringMatch(wrapperVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold|godot|flutter) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateEngineVersion(engineVersion:string): boolean
            {
                if (!engineVersion || !GAUtilities.stringMatch(engineVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold|godot) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/))
                {
                    return false;
                }
                return true;
            }

            public static validateUserId(uId:string): boolean
            {
                if (!GAValidator.validateString(uId, false))
                {
                    GALogger.w("Validation fail - user id: id cannot be (null), empty or above 64 characters.");
                    return false;
                }
                return true;
            }

            public static validateShortString(shortString:string, canBeEmpty:boolean): boolean
            {
                // String is allowed to be empty or nil
                if (canBeEmpty && !shortString)
                {
                    return true;
                }

                if (!shortString || shortString.length > 32)
                {
                    return false;
                }
                return true;
            }

            public static validateString(s:string, canBeEmpty:boolean): boolean
            {
                // String is allowed to be empty or nil
                if (canBeEmpty && !s)
                {
                    return true;
                }

                if (!s || s.length > 64)
                {
                    return false;
                }
                return true;
            }

            public static validateLongString(longString:string, canBeEmpty:boolean): boolean
            {
                // String is allowed to be empty
                if (canBeEmpty && !longString)
                {
                    return true;
                }

                if (!longString || longString.length > 8192)
                {
                    return false;
                }
                return true;
            }

            public static validateConnectionType(connectionType:string): boolean
            {
                return GAUtilities.stringMatch(connectionType, /^(wwan|wifi|lan|offline)$/);
            }

            public static validateCustomDimensions(customDimensions:Array<string>): boolean
            {
                return GAValidator.validateArrayOfStrings(20, 32, false, "custom dimensions", customDimensions);
            }

            public static validateResourceCurrencies(resourceCurrencies:Array<string>): boolean
            {
                if (!GAValidator.validateArrayOfStrings(20, 64, false, "resource currencies", resourceCurrencies))
                {
                    return false;
                }

                // validate each string for regex
                for (let i = 0; i < resourceCurrencies.length; ++i)
                {
                    if (!GAUtilities.stringMatch(resourceCurrencies[i], /^[A-Za-z]+$/))
                    {
                        GALogger.w("resource currencies validation failed: a resource currency can only be A-Z, a-z. String was: " + resourceCurrencies[i]);
                        return false;
                    }
                }
                return true;
            }

            public static validateResourceItemTypes(resourceItemTypes:Array<string>): boolean
            {
                if (!GAValidator.validateArrayOfStrings(20, 32, false, "resource item types", resourceItemTypes))
                {
                    return false;
                }

                // validate each resourceItemType for eventpart validation
                for (let i = 0; i < resourceItemTypes.length; ++i)
                {
                    if (!GAValidator.validateEventPartCharacters(resourceItemTypes[i]))
                    {
                        GALogger.w("resource item types validation failed: a resource item type cannot contain other characters than A-z, 0-9, -_., ()!?. String was: " + resourceItemTypes[i]);
                        return false;
                    }
                }
                return true;
            }

            public static validateDimension01(dimension01:string, availableDimensions:Array<string>): boolean
            {
                // allow nil
                if (!dimension01)
                {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension01))
                {
                    return false;
                }
                return true;
            }

            public static validateDimension02(dimension02:string, availableDimensions:Array<string>): boolean
            {
                // allow nil
                if (!dimension02)
                {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension02))
                {
                    return false;
                }
                return true;
            }

            public static validateDimension03(dimension03:string, availableDimensions:Array<string>): boolean
            {
                // allow nil
                if (!dimension03)
                {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension03))
                {
                    return false;
                }
                return true;
            }

            public static validateArrayOfStrings(maxCount:number, maxStringLength:number, allowNoValues:boolean, logTag:string, arrayOfStrings:Array<string>): boolean
            {
                var arrayTag:string = logTag;

                // use arrayTag to annotate warning log
                if (!arrayTag)
                {
                    arrayTag = "Array";
                }

                if(!arrayOfStrings)
                {
                    GALogger.w(arrayTag + " validation failed: array cannot be null. ");
                    return false;
                }

                // check if empty
                if (allowNoValues == false && arrayOfStrings.length == 0)
                {
                    GALogger.w(arrayTag + " validation failed: array cannot be empty. ");
                    return false;
                }

                // check if exceeding max count
                if (maxCount > 0 && arrayOfStrings.length > maxCount)
                {
                    GALogger.w(arrayTag + " validation failed: array cannot exceed " + maxCount + " values. It has " + arrayOfStrings.length + " values.");
                    return false;
                }

                // validate each string
                for (let i = 0; i < arrayOfStrings.length; ++i)
                {
                    var stringLength:number = !arrayOfStrings[i] ? 0 : arrayOfStrings[i].length;
                    // check if empty (not allowed)
                    if (stringLength === 0)
                    {
                        GALogger.w(arrayTag + " validation failed: contained an empty string. Array=" + JSON.stringify(arrayOfStrings));
                        return false;
                    }

                    // check if exceeding max length
                    if (maxStringLength > 0 && stringLength > maxStringLength)
                    {
                        GALogger.w(arrayTag + " validation failed: a string exceeded max allowed length (which is: " + maxStringLength + "). String was: " + arrayOfStrings[i]);
                        return false;
                    }
                }
                return true;
            }

            public static validateClientTs(clientTs:number): boolean
            {
                if (clientTs < (0) || clientTs > (99999999999))
                {
                    return false;
                }
                return true;
            }
        }
    }
}
