module ga
{
    export module validators
    {
        import GALogger = ga.logging.GALogger;
        import EGASdkErrorType = ga.http.EGASdkErrorType;
        import GAUtilities = ga.utilities.GAUtilities;

        export class GAValidator
        {
            public static validateBusinessEvent(currency:string, amount:number, cartType:string, itemType:string, itemId:string): boolean
            {
                return true;
            }

            public static validateResourceEvent(flowType:EGAResourceFlowType, currency:string, amount:number, itemType:string, itemId:string, availableCurrencies:Array<string>, availableItemTypes:Array<string>): boolean
            {
                return true;
            }

            public static validateProgressionEvent(progressionStatus:EGAProgressionStatus, progression01:string, progression02:string, progression03:string): boolean
            {
                return true;
            }

            public static validateDesignEvent(eventId:string, value:number): boolean
            {
                return true;
            }

            public static validateErrorEvent(severity:EGAErrorSeverity, message:string): boolean
            {
                return true;
            }

            public static validateSdkErrorEvent(gameKey:string, gameSecret:string, type:EGASdkErrorType): boolean
            {
                return true;
            }

            public static validateKeys(gameKey:string, gameSecret:string): boolean
            {
                return false;
            }

            public static validateCurrency(currency:string): boolean
            {
                return true;
            }

            public static validateEventPartLength(eventPart:string, allowNull:boolean): boolean
            {
                return true;
            }

            public static validateEventPartCharacters(eventPart:string): boolean
            {
                return true;
            }

            public static validateEventIdLength(eventId:string): boolean
            {
                return true;
            }

            public static validateEventIdCharacters(eventId:string): boolean
            {
                return true;
            }

            public static validateAndCleanInitRequestResponse(initResponse:{[key:string]: any}): {[key:string]: any}
            {
                return initResponse;
            }

            public static validateBuild(build:string): boolean
            {
                return true;
            }

            public static validateSdkWrapperVersion(wrapperVersion:string): boolean
            {
                return true;
            }

            public static validateEngineVersion(engineVersion:string): boolean
            {
                return true;
            }

            public static validateUserId(uId:string): boolean
            {
                return true;
            }

            public static validateShortString(shortString:string, canBeEmpty:boolean): boolean
            {
                return true;
            }

            public static validateString(s:string, canBeEmpty:boolean): boolean
            {
                return true;
            }

            public static validateLongString(longString:string, canBeEmpty:boolean): boolean
            {
                return true;
            }

            public static validateConnectionType(connectionType:string): boolean
            {
                return true;
            }

            public static validateCustomDimensions(customDimensions:Array<string>): boolean
            {
                return true;
            }

            public static validateResourceCurrencies(resourceCurrencies:Array<string>): boolean
            {
                return true;
            }

            public static validateResourceItemTypes(resourceItemTypes:Array<string>): boolean
            {
                return true;
            }

            public static validateDimension01(dimension01:string, availableDimensions:Array<string>): boolean
            {
                return true;
            }

            public static validateDimension02(dimension02:string, availableDimensions:Array<string>): boolean
            {
                return true;
            }

            public static validateDimension03(dimension03:string, availableDimensions:Array<string>): boolean
            {
                return true;
            }

            public static validateArrayOfStrings(maxCount:number, maxStringLength:number, allowNoValues:boolean, logTag:string, arrayOfStrings:Array<string>): boolean
            {
                return true;
            }

            public static validateFacebookId(facebookId:string): boolean
            {
                return true;
            }

            public static validateGender(gender:EGAGender): boolean
            {
                return true;
            }

            public static validateBirthyear(birthYear:number): boolean
            {
                return true;
            }

            public static validateClientTs(clientTs:number): boolean
            {
                return true;
            }
        }
    }
}
