var gameanalytics;
(function (gameanalytics) {
    var EGAErrorSeverity;
    (function (EGAErrorSeverity) {
        EGAErrorSeverity[EGAErrorSeverity["Undefined"] = 0] = "Undefined";
        EGAErrorSeverity[EGAErrorSeverity["Debug"] = 1] = "Debug";
        EGAErrorSeverity[EGAErrorSeverity["Info"] = 2] = "Info";
        EGAErrorSeverity[EGAErrorSeverity["Warning"] = 3] = "Warning";
        EGAErrorSeverity[EGAErrorSeverity["Error"] = 4] = "Error";
        EGAErrorSeverity[EGAErrorSeverity["Critical"] = 5] = "Critical";
    })(EGAErrorSeverity = gameanalytics.EGAErrorSeverity || (gameanalytics.EGAErrorSeverity = {}));
    var EGAProgressionStatus;
    (function (EGAProgressionStatus) {
        EGAProgressionStatus[EGAProgressionStatus["Undefined"] = 0] = "Undefined";
        EGAProgressionStatus[EGAProgressionStatus["Start"] = 1] = "Start";
        EGAProgressionStatus[EGAProgressionStatus["Complete"] = 2] = "Complete";
        EGAProgressionStatus[EGAProgressionStatus["Fail"] = 3] = "Fail";
    })(EGAProgressionStatus = gameanalytics.EGAProgressionStatus || (gameanalytics.EGAProgressionStatus = {}));
    var EGAResourceFlowType;
    (function (EGAResourceFlowType) {
        EGAResourceFlowType[EGAResourceFlowType["Undefined"] = 0] = "Undefined";
        EGAResourceFlowType[EGAResourceFlowType["Source"] = 1] = "Source";
        EGAResourceFlowType[EGAResourceFlowType["Sink"] = 2] = "Sink";
    })(EGAResourceFlowType = gameanalytics.EGAResourceFlowType || (gameanalytics.EGAResourceFlowType = {}));
    var http;
    (function (http) {
        var EGASdkErrorType;
        (function (EGASdkErrorType) {
            EGASdkErrorType[EGASdkErrorType["Undefined"] = 0] = "Undefined";
            EGASdkErrorType[EGASdkErrorType["Rejected"] = 1] = "Rejected";
        })(EGASdkErrorType = http.EGASdkErrorType || (http.EGASdkErrorType = {}));
        var EGAHTTPApiResponse;
        (function (EGAHTTPApiResponse) {
            EGAHTTPApiResponse[EGAHTTPApiResponse["NoResponse"] = 0] = "NoResponse";
            EGAHTTPApiResponse[EGAHTTPApiResponse["BadResponse"] = 1] = "BadResponse";
            EGAHTTPApiResponse[EGAHTTPApiResponse["RequestTimeout"] = 2] = "RequestTimeout";
            EGAHTTPApiResponse[EGAHTTPApiResponse["JsonEncodeFailed"] = 3] = "JsonEncodeFailed";
            EGAHTTPApiResponse[EGAHTTPApiResponse["JsonDecodeFailed"] = 4] = "JsonDecodeFailed";
            EGAHTTPApiResponse[EGAHTTPApiResponse["InternalServerError"] = 5] = "InternalServerError";
            EGAHTTPApiResponse[EGAHTTPApiResponse["BadRequest"] = 6] = "BadRequest";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Unauthorized"] = 7] = "Unauthorized";
            EGAHTTPApiResponse[EGAHTTPApiResponse["UnknownResponseCode"] = 8] = "UnknownResponseCode";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Ok"] = 9] = "Ok";
            EGAHTTPApiResponse[EGAHTTPApiResponse["Created"] = 10] = "Created";
        })(EGAHTTPApiResponse = http.EGAHTTPApiResponse || (http.EGAHTTPApiResponse = {}));
    })(http = gameanalytics.http || (gameanalytics.http = {}));
})(gameanalytics || (gameanalytics = {}));
var EGAErrorSeverity = gameanalytics.EGAErrorSeverity;
var EGAProgressionStatus = gameanalytics.EGAProgressionStatus;
var EGAResourceFlowType = gameanalytics.EGAResourceFlowType;
var gameanalytics;
(function (gameanalytics) {
    var logging;
    (function (logging) {
        var EGALoggerMessageType;
        (function (EGALoggerMessageType) {
            EGALoggerMessageType[EGALoggerMessageType["Error"] = 0] = "Error";
            EGALoggerMessageType[EGALoggerMessageType["Warning"] = 1] = "Warning";
            EGALoggerMessageType[EGALoggerMessageType["Info"] = 2] = "Info";
            EGALoggerMessageType[EGALoggerMessageType["Debug"] = 3] = "Debug";
        })(EGALoggerMessageType || (EGALoggerMessageType = {}));
        var GALogger = (function () {
            function GALogger() {
                GALogger.debugEnabled = true;
            }
            GALogger.setInfoLog = function (value) {
                GALogger.instance.infoLogEnabled = value;
            };
            GALogger.setVerboseLog = function (value) {
                GALogger.instance.infoLogVerboseEnabled = value;
            };
            GALogger.i = function (format) {
                if (!GALogger.instance.infoLogEnabled) {
                    return;
                }
                var message = "Info/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            };
            GALogger.w = function (format) {
                var message = "Warning/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Warning);
            };
            GALogger.e = function (format) {
                var message = "Error/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Error);
            };
            GALogger.ii = function (format) {
                if (!GALogger.instance.infoLogVerboseEnabled) {
                    return;
                }
                var message = "Verbose/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            };
            GALogger.d = function (format) {
                if (!GALogger.debugEnabled) {
                    return;
                }
                var message = "Debug/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Debug);
            };
            GALogger.prototype.sendNotificationMessage = function (message, type) {
                switch (type) {
                    case EGALoggerMessageType.Error:
                        {
                            console.error(message);
                        }
                        break;
                    case EGALoggerMessageType.Warning:
                        {
                            console.warn(message);
                        }
                        break;
                    case EGALoggerMessageType.Debug:
                        {
                            if (typeof console.debug === "function") {
                                console.debug(message);
                            }
                            else {
                                console.log(message);
                            }
                        }
                        break;
                    case EGALoggerMessageType.Info:
                        {
                            console.log(message);
                        }
                        break;
                }
            };
            GALogger.instance = new GALogger();
            GALogger.Tag = "GameAnalytics";
            return GALogger;
        }());
        logging.GALogger = GALogger;
    })(logging = gameanalytics.logging || (gameanalytics.logging = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var utilities;
    (function (utilities) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = (function () {
            function GAUtilities() {
            }
            GAUtilities.getHmac = function (key, data) {
                var encryptedMessage = CryptoJS.HmacSHA256(data, key);
                return CryptoJS.enc.Base64.stringify(encryptedMessage);
            };
            GAUtilities.stringMatch = function (s, pattern) {
                if (!s || !pattern) {
                    return false;
                }
                return pattern.test(s);
            };
            GAUtilities.joinStringArray = function (v, delimiter) {
                var result = "";
                for (var i = 0, il = v.length; i < il; i++) {
                    if (i > 0) {
                        result += delimiter;
                    }
                    result += v[i];
                }
                return result;
            };
            GAUtilities.stringArrayContainsString = function (array, search) {
                if (array.length === 0) {
                    return false;
                }
                for (var s in array) {
                    if (array[s] === search) {
                        return true;
                    }
                }
                return false;
            };
            GAUtilities.encode64 = function (input) {
                input = encodeURI(input);
                var output = "";
                var chr1, chr2, chr3 = 0;
                var enc1, enc2, enc3, enc4 = 0;
                var i = 0;
                do {
                    chr1 = input.charCodeAt(i++);
                    chr2 = input.charCodeAt(i++);
                    chr3 = input.charCodeAt(i++);
                    enc1 = chr1 >> 2;
                    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                    enc4 = chr3 & 63;
                    if (isNaN(chr2)) {
                        enc3 = enc4 = 64;
                    }
                    else if (isNaN(chr3)) {
                        enc4 = 64;
                    }
                    output = output +
                        GAUtilities.keyStr.charAt(enc1) +
                        GAUtilities.keyStr.charAt(enc2) +
                        GAUtilities.keyStr.charAt(enc3) +
                        GAUtilities.keyStr.charAt(enc4);
                    chr1 = chr2 = chr3 = 0;
                    enc1 = enc2 = enc3 = enc4 = 0;
                } while (i < input.length);
                return output;
            };
            GAUtilities.decode64 = function (input) {
                var output = "";
                var chr1, chr2, chr3 = 0;
                var enc1, enc2, enc3, enc4 = 0;
                var i = 0;
                var base64test = /[^A-Za-z0-9\+\/\=]/g;
                if (base64test.exec(input)) {
                    GALogger.w("There were invalid base64 characters in the input text. Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='. Expect errors in decoding.");
                }
                input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
                do {
                    enc1 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc2 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc3 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    enc4 = GAUtilities.keyStr.indexOf(input.charAt(i++));
                    chr1 = (enc1 << 2) | (enc2 >> 4);
                    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                    chr3 = ((enc3 & 3) << 6) | enc4;
                    output = output + String.fromCharCode(chr1);
                    if (enc3 != 64) {
                        output = output + String.fromCharCode(chr2);
                    }
                    if (enc4 != 64) {
                        output = output + String.fromCharCode(chr3);
                    }
                    chr1 = chr2 = chr3 = 0;
                    enc1 = enc2 = enc3 = enc4 = 0;
                } while (i < input.length);
                return decodeURI(output);
            };
            GAUtilities.timeIntervalSince1970 = function () {
                var date = new Date();
                return Math.round(date.getTime() / 1000);
            };
            GAUtilities.createGuid = function () {
                return (GAUtilities.s4() + GAUtilities.s4() + "-" + GAUtilities.s4() + "-4" + GAUtilities.s4().substr(0, 3) + "-" + GAUtilities.s4() + "-" + GAUtilities.s4() + GAUtilities.s4() + GAUtilities.s4()).toLowerCase();
            };
            GAUtilities.s4 = function () {
                return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
            };
            GAUtilities.keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            return GAUtilities;
        }());
        utilities.GAUtilities = GAUtilities;
    })(utilities = gameanalytics.utilities || (gameanalytics.utilities = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var validators;
    (function (validators) {
        var GALogger = gameanalytics.logging.GALogger;
        var EGASdkErrorType = gameanalytics.http.EGASdkErrorType;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GAValidator = (function () {
            function GAValidator() {
            }
            GAValidator.validateBusinessEvent = function (currency, amount, cartType, itemType, itemId) {
                if (!GAValidator.validateCurrency(currency)) {
                    GALogger.w("Validation fail - business event - currency: Cannot be (null) and need to be A-Z, 3 characters and in the standard at openexchangerates.org. Failed currency: " + currency);
                    return false;
                }
                if (amount < 0) {
                    GALogger.w("Validation fail - business event - amount. Cannot be less than 0. Failed amount: " + amount);
                    return false;
                }
                if (!GAValidator.validateShortString(cartType, true)) {
                    GALogger.w("Validation fail - business event - cartType. Cannot be above 32 length. String: " + cartType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - business event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - business event - itemId. Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - business event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateResourceEvent = function (flowType, currency, amount, itemType, itemId, availableCurrencies, availableItemTypes) {
                if (flowType == gameanalytics.EGAResourceFlowType.Undefined) {
                    GALogger.w("Validation fail - resource event - flowType: Invalid flow type.");
                    return false;
                }
                if (!currency) {
                    GALogger.w("Validation fail - resource event - currency: Cannot be (null)");
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableCurrencies, currency)) {
                    GALogger.w("Validation fail - resource event - currency: Not found in list of pre-defined available resource currencies. String: " + currency);
                    return false;
                }
                if (!(amount > 0)) {
                    GALogger.w("Validation fail - resource event - amount: Float amount cannot be 0 or negative. Value: " + amount);
                    return false;
                }
                if (!itemType) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null)");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemType, false)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot be (null), empty or above 64 characters. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemType);
                    return false;
                }
                if (!GAUtilities.stringArrayContainsString(availableItemTypes, itemType)) {
                    GALogger.w("Validation fail - resource event - itemType: Not found in list of pre-defined available resource itemTypes. String: " + itemType);
                    return false;
                }
                if (!GAValidator.validateEventPartLength(itemId, false)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot be (null), empty or above 64 characters. String: " + itemId);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(itemId)) {
                    GALogger.w("Validation fail - resource event - itemId: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + itemId);
                    return false;
                }
                return true;
            };
            GAValidator.validateProgressionEvent = function (progressionStatus, progression01, progression02, progression03) {
                if (progressionStatus == gameanalytics.EGAProgressionStatus.Undefined) {
                    GALogger.w("Validation fail - progression event: Invalid progression status.");
                    return false;
                }
                if (progression03 && !(progression02 || !progression01)) {
                    GALogger.w("Validation fail - progression event: 03 found but 01+02 are invalid. Progression must be set as either 01, 01+02 or 01+02+03.");
                    return false;
                }
                else if (progression02 && !progression01) {
                    GALogger.w("Validation fail - progression event: 02 found but not 01. Progression must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                else if (!progression01) {
                    GALogger.w("Validation fail - progression event: progression01 not valid. Progressions must be set as either 01, 01+02 or 01+02+03");
                    return false;
                }
                if (!GAValidator.validateEventPartLength(progression01, false)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot be (null), empty or above 64 characters. String: " + progression01);
                    return false;
                }
                if (!GAValidator.validateEventPartCharacters(progression01)) {
                    GALogger.w("Validation fail - progression event - progression01: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression01);
                    return false;
                }
                if (progression02) {
                    if (!GAValidator.validateEventPartLength(progression02, true)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot be empty or above 64 characters. String: " + progression02);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression02)) {
                        GALogger.w("Validation fail - progression event - progression02: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression02);
                        return false;
                    }
                }
                if (progression03) {
                    if (!GAValidator.validateEventPartLength(progression03, true)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot be empty or above 64 characters. String: " + progression03);
                        return false;
                    }
                    if (!GAValidator.validateEventPartCharacters(progression03)) {
                        GALogger.w("Validation fail - progression event - progression03: Cannot contain other characters than A-z, 0-9, -_., ()!?. String: " + progression03);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateDesignEvent = function (eventId, value) {
                if (!GAValidator.validateEventIdLength(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Cannot be (null) or empty. Only 5 event parts allowed seperated by :. Each part need to be 32 characters or less. String: " + eventId);
                    return false;
                }
                if (!GAValidator.validateEventIdCharacters(eventId)) {
                    GALogger.w("Validation fail - design event - eventId: Non valid characters. Only allowed A-z, 0-9, -_., ()!?. String: " + eventId);
                    return false;
                }
                return true;
            };
            GAValidator.validateErrorEvent = function (severity, message) {
                if (severity == gameanalytics.EGAErrorSeverity.Undefined) {
                    GALogger.w("Validation fail - error event - severity: Severity was unsupported value.");
                    return false;
                }
                if (!GAValidator.validateLongString(message, true)) {
                    GALogger.w("Validation fail - error event - message: Message cannot be above 8192 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateSdkErrorEvent = function (gameKey, gameSecret, type) {
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    return false;
                }
                if (type === EGASdkErrorType.Undefined) {
                    GALogger.w("Validation fail - sdk error event - type: Type was unsupported value.");
                    return false;
                }
                return true;
            };
            GAValidator.validateKeys = function (gameKey, gameSecret) {
                if (GAUtilities.stringMatch(gameKey, /^[A-z0-9]{32}$/)) {
                    if (GAUtilities.stringMatch(gameSecret, /^[A-z0-9]{40}$/)) {
                        return true;
                    }
                }
                return false;
            };
            GAValidator.validateCurrency = function (currency) {
                if (!currency) {
                    return false;
                }
                if (!GAUtilities.stringMatch(currency, /^[A-Z]{3}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventPartLength = function (eventPart, allowNull) {
                if (allowNull && !eventPart) {
                    return true;
                }
                if (!eventPart) {
                    return false;
                }
                if (eventPart.length > 64) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventPartCharacters = function (eventPart) {
                if (!GAUtilities.stringMatch(eventPart, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventIdLength = function (eventId) {
                if (!eventId) {
                    return false;
                }
                if (!GAUtilities.stringMatch(eventId, /^[^:]{1,64}(?::[^:]{1,64}){0,4}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEventIdCharacters = function (eventId) {
                if (!eventId) {
                    return false;
                }
                if (!GAUtilities.stringMatch(eventId, /^[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}(:[A-Za-z0-9\s\-_\.\(\)\!\?]{1,64}){0,4}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateAndCleanInitRequestResponse = function (initResponse, configsCreated) {
                if (initResponse == null) {
                    GALogger.w("validateInitRequestResponse failed - no response dictionary.");
                    return null;
                }
                var validatedDict = {};
                try {
                    var serverTsNumber = initResponse["server_ts"];
                    if (serverTsNumber > 0) {
                        validatedDict["server_ts"] = serverTsNumber;
                    }
                    else {
                        GALogger.w("validateInitRequestResponse failed - invalid value in 'server_ts' field.");
                        return null;
                    }
                }
                catch (e) {
                    GALogger.w("validateInitRequestResponse failed - invalid type in 'server_ts' field. type=" + typeof initResponse["server_ts"] + ", value=" + initResponse["server_ts"] + ", " + e);
                    return null;
                }
                if (configsCreated) {
                    try {
                        var configurations = initResponse["configs"];
                        validatedDict["configs"] = configurations;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs' field. type=" + typeof initResponse["configs"] + ", value=" + initResponse["configs"] + ", " + e);
                        return null;
                    }
                    try {
                        var configs_hash = initResponse["configs_hash"];
                        validatedDict["configs_hash"] = configs_hash;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'configs_hash' field. type=" + typeof initResponse["configs_hash"] + ", value=" + initResponse["configs_hash"] + ", " + e);
                        return null;
                    }
                    try {
                        var ab_id = initResponse["ab_id"];
                        validatedDict["ab_id"] = ab_id;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_id' field. type=" + typeof initResponse["ab_id"] + ", value=" + initResponse["ab_id"] + ", " + e);
                        return null;
                    }
                    try {
                        var ab_variant_id = initResponse["ab_variant_id"];
                        validatedDict["ab_variant_id"] = ab_variant_id;
                    }
                    catch (e) {
                        GALogger.w("validateInitRequestResponse failed - invalid type in 'ab_variant_id' field. type=" + typeof initResponse["ab_variant_id"] + ", value=" + initResponse["ab_variant_id"] + ", " + e);
                        return null;
                    }
                }
                return validatedDict;
            };
            GAValidator.validateBuild = function (build) {
                if (!GAValidator.validateShortString(build, false)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateSdkWrapperVersion = function (wrapperVersion) {
                if (!GAUtilities.stringMatch(wrapperVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateEngineVersion = function (engineVersion) {
                if (!engineVersion || !GAUtilities.stringMatch(engineVersion, /^(unity|unreal|gamemaker|cocos2d|construct|defold) [0-9]{0,5}(\.[0-9]{0,5}){0,2}$/)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateUserId = function (uId) {
                if (!GAValidator.validateString(uId, false)) {
                    GALogger.w("Validation fail - user id: id cannot be (null), empty or above 64 characters.");
                    return false;
                }
                return true;
            };
            GAValidator.validateShortString = function (shortString, canBeEmpty) {
                if (canBeEmpty && !shortString) {
                    return true;
                }
                if (!shortString || shortString.length > 32) {
                    return false;
                }
                return true;
            };
            GAValidator.validateString = function (s, canBeEmpty) {
                if (canBeEmpty && !s) {
                    return true;
                }
                if (!s || s.length > 64) {
                    return false;
                }
                return true;
            };
            GAValidator.validateLongString = function (longString, canBeEmpty) {
                if (canBeEmpty && !longString) {
                    return true;
                }
                if (!longString || longString.length > 8192) {
                    return false;
                }
                return true;
            };
            GAValidator.validateConnectionType = function (connectionType) {
                return GAUtilities.stringMatch(connectionType, /^(wwan|wifi|lan|offline)$/);
            };
            GAValidator.validateCustomDimensions = function (customDimensions) {
                return GAValidator.validateArrayOfStrings(20, 32, false, "custom dimensions", customDimensions);
            };
            GAValidator.validateResourceCurrencies = function (resourceCurrencies) {
                if (!GAValidator.validateArrayOfStrings(20, 64, false, "resource currencies", resourceCurrencies)) {
                    return false;
                }
                for (var i = 0; i < resourceCurrencies.length; ++i) {
                    if (!GAUtilities.stringMatch(resourceCurrencies[i], /^[A-Za-z]+$/)) {
                        GALogger.w("resource currencies validation failed: a resource currency can only be A-Z, a-z. String was: " + resourceCurrencies[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateResourceItemTypes = function (resourceItemTypes) {
                if (!GAValidator.validateArrayOfStrings(20, 32, false, "resource item types", resourceItemTypes)) {
                    return false;
                }
                for (var i = 0; i < resourceItemTypes.length; ++i) {
                    if (!GAValidator.validateEventPartCharacters(resourceItemTypes[i])) {
                        GALogger.w("resource item types validation failed: a resource item type cannot contain other characters than A-z, 0-9, -_., ()!?. String was: " + resourceItemTypes[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateDimension01 = function (dimension01, availableDimensions) {
                if (!dimension01) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension01)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateDimension02 = function (dimension02, availableDimensions) {
                if (!dimension02) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension02)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateDimension03 = function (dimension03, availableDimensions) {
                if (!dimension03) {
                    return true;
                }
                if (!GAUtilities.stringArrayContainsString(availableDimensions, dimension03)) {
                    return false;
                }
                return true;
            };
            GAValidator.validateArrayOfStrings = function (maxCount, maxStringLength, allowNoValues, logTag, arrayOfStrings) {
                var arrayTag = logTag;
                if (!arrayTag) {
                    arrayTag = "Array";
                }
                if (!arrayOfStrings) {
                    GALogger.w(arrayTag + " validation failed: array cannot be null. ");
                    return false;
                }
                if (allowNoValues == false && arrayOfStrings.length == 0) {
                    GALogger.w(arrayTag + " validation failed: array cannot be empty. ");
                    return false;
                }
                if (maxCount > 0 && arrayOfStrings.length > maxCount) {
                    GALogger.w(arrayTag + " validation failed: array cannot exceed " + maxCount + " values. It has " + arrayOfStrings.length + " values.");
                    return false;
                }
                for (var i = 0; i < arrayOfStrings.length; ++i) {
                    var stringLength = !arrayOfStrings[i] ? 0 : arrayOfStrings[i].length;
                    if (stringLength === 0) {
                        GALogger.w(arrayTag + " validation failed: contained an empty string. Array=" + JSON.stringify(arrayOfStrings));
                        return false;
                    }
                    if (maxStringLength > 0 && stringLength > maxStringLength) {
                        GALogger.w(arrayTag + " validation failed: a string exceeded max allowed length (which is: " + maxStringLength + "). String was: " + arrayOfStrings[i]);
                        return false;
                    }
                }
                return true;
            };
            GAValidator.validateClientTs = function (clientTs) {
                if (clientTs < (-4294967295 + 1) || clientTs > (4294967295 - 1)) {
                    return false;
                }
                return true;
            };
            return GAValidator;
        }());
        validators.GAValidator = GAValidator;
    })(validators = gameanalytics.validators || (gameanalytics.validators = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var device;
    (function (device) {
        var NameValueVersion = (function () {
            function NameValueVersion(name, value, version) {
                this.name = name;
                this.value = value;
                this.version = version;
            }
            return NameValueVersion;
        }());
        device.NameValueVersion = NameValueVersion;
        var NameVersion = (function () {
            function NameVersion(name, version) {
                this.name = name;
                this.version = version;
            }
            return NameVersion;
        }());
        device.NameVersion = NameVersion;
        var GADevice = (function () {
            function GADevice() {
            }
            GADevice.touch = function () {
            };
            GADevice.getRelevantSdkVersion = function () {
                if (GADevice.sdkGameEngineVersion) {
                    return GADevice.sdkGameEngineVersion;
                }
                return GADevice.sdkWrapperVersion;
            };
            GADevice.getConnectionType = function () {
                return GADevice.connectionType;
            };
            GADevice.updateConnectionType = function () {
                if (navigator.onLine) {
                    if (GADevice.buildPlatform === "ios" || GADevice.buildPlatform === "android") {
                        GADevice.connectionType = "wwan";
                    }
                    else {
                        GADevice.connectionType = "lan";
                    }
                }
                else {
                    GADevice.connectionType = "offline";
                }
            };
            GADevice.getOSVersionString = function () {
                return GADevice.buildPlatform + " " + GADevice.osVersionPair.version;
            };
            GADevice.runtimePlatformToString = function () {
                return GADevice.osVersionPair.name;
            };
            GADevice.getBrowserVersionString = function () {
                var ua = navigator.userAgent;
                var tem;
                var M = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident|fbav(?=\/))\/?\s*(\d+)/i) || [];
                if (M.length == 0) {
                    if (GADevice.buildPlatform === "ios") {
                        return "webkit_" + GADevice.osVersion;
                    }
                }
                if (/trident/i.test(M[1])) {
                    tem = /\brv[ :]+(\d+)/g.exec(ua) || [];
                    return 'IE ' + (tem[1] || '');
                }
                if (M[1] === 'Chrome') {
                    tem = ua.match(/\b(OPR|Edge|UBrowser)\/(\d+)/);
                    if (tem != null) {
                        return tem.slice(1).join(' ').replace('OPR', 'Opera').replace('UBrowser', 'UC').toLowerCase();
                    }
                }
                if (M[1] && M[1].toLowerCase() === 'fbav') {
                    M[1] = "facebook";
                    if (M[2]) {
                        return "facebook " + M[2];
                    }
                }
                var MString = M[2] ? [M[1], M[2]] : [navigator.appName, navigator.appVersion, '-?'];
                if ((tem = ua.match(/version\/(\d+)/i)) != null) {
                    MString.splice(1, 1, tem[1]);
                }
                return MString.join(' ').toLowerCase();
            };
            GADevice.getDeviceModel = function () {
                var result = "unknown";
                return result;
            };
            GADevice.getDeviceManufacturer = function () {
                var result = "unknown";
                return result;
            };
            GADevice.matchItem = function (agent, data) {
                var result = new NameVersion("unknown", "0.0.0");
                var i = 0;
                var j = 0;
                var regex;
                var regexv;
                var match;
                var matches;
                var mathcesResult;
                var version;
                for (i = 0; i < data.length; i += 1) {
                    regex = new RegExp(data[i].value, 'i');
                    match = regex.test(agent);
                    if (match) {
                        regexv = new RegExp(data[i].version + '[- /:;]([\\d._]+)', 'i');
                        matches = agent.match(regexv);
                        version = '';
                        if (matches) {
                            if (matches[1]) {
                                mathcesResult = matches[1];
                            }
                        }
                        if (mathcesResult) {
                            var matchesArray = mathcesResult.split(/[._]+/);
                            for (j = 0; j < Math.min(matchesArray.length, 3); j += 1) {
                                version += matchesArray[j] + (j < Math.min(matchesArray.length, 3) - 1 ? '.' : '');
                            }
                        }
                        else {
                            version = '0.0.0';
                        }
                        result.name = data[i].name;
                        result.version = version;
                        return result;
                    }
                }
                return result;
            };
            GADevice.sdkWrapperVersion = "javascript 4.0.7";
            GADevice.osVersionPair = GADevice.matchItem([
                navigator.platform,
                navigator.userAgent,
                navigator.appVersion,
                navigator.vendor
            ].join(' '), [
                new NameValueVersion("windows_phone", "Windows Phone", "OS"),
                new NameValueVersion("windows", "Win", "NT"),
                new NameValueVersion("ios", "iPhone", "OS"),
                new NameValueVersion("ios", "iPad", "OS"),
                new NameValueVersion("ios", "iPod", "OS"),
                new NameValueVersion("android", "Android", "Android"),
                new NameValueVersion("blackBerry", "BlackBerry", "/"),
                new NameValueVersion("mac_osx", "Mac", "OS X"),
                new NameValueVersion("tizen", "Tizen", "Tizen"),
                new NameValueVersion("linux", "Linux", "rv")
            ]);
            GADevice.buildPlatform = GADevice.runtimePlatformToString();
            GADevice.deviceModel = GADevice.getDeviceModel();
            GADevice.deviceManufacturer = GADevice.getDeviceManufacturer();
            GADevice.osVersion = GADevice.getOSVersionString();
            GADevice.browserVersion = GADevice.getBrowserVersionString();
            GADevice.maxSafeInteger = Math.pow(2, 53) - 1;
            return GADevice;
        }());
        device.GADevice = GADevice;
    })(device = gameanalytics.device || (gameanalytics.device = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var TimedBlock = (function () {
            function TimedBlock(deadline) {
                this.deadline = deadline;
                this.ignore = false;
                this.async = false;
                this.running = false;
                this.id = ++TimedBlock.idCounter;
            }
            TimedBlock.idCounter = 0;
            return TimedBlock;
        }());
        threading.TimedBlock = TimedBlock;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var PriorityQueue = (function () {
            function PriorityQueue(priorityComparer) {
                this.comparer = priorityComparer;
                this._subQueues = {};
                this._sortedKeys = [];
            }
            PriorityQueue.prototype.enqueue = function (priority, item) {
                if (this._sortedKeys.indexOf(priority) === -1) {
                    this.addQueueOfPriority(priority);
                }
                this._subQueues[priority].push(item);
            };
            PriorityQueue.prototype.addQueueOfPriority = function (priority) {
                var _this = this;
                this._sortedKeys.push(priority);
                this._sortedKeys.sort(function (x, y) { return _this.comparer.compare(x, y); });
                this._subQueues[priority] = [];
            };
            PriorityQueue.prototype.peek = function () {
                if (this.hasItems()) {
                    return this._subQueues[this._sortedKeys[0]][0];
                }
                else {
                    throw new Error("The queue is empty");
                }
            };
            PriorityQueue.prototype.hasItems = function () {
                return this._sortedKeys.length > 0;
            };
            PriorityQueue.prototype.dequeue = function () {
                if (this.hasItems()) {
                    return this.dequeueFromHighPriorityQueue();
                }
                else {
                    throw new Error("The queue is empty");
                }
            };
            PriorityQueue.prototype.dequeueFromHighPriorityQueue = function () {
                var firstKey = this._sortedKeys[0];
                var nextItem = this._subQueues[firstKey].shift();
                if (this._subQueues[firstKey].length === 0) {
                    this._sortedKeys.shift();
                    delete this._subQueues[firstKey];
                }
                return nextItem;
            };
            return PriorityQueue;
        }());
        threading.PriorityQueue = PriorityQueue;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var store;
    (function (store_1) {
        var GALogger = gameanalytics.logging.GALogger;
        var EGAStoreArgsOperator;
        (function (EGAStoreArgsOperator) {
            EGAStoreArgsOperator[EGAStoreArgsOperator["Equal"] = 0] = "Equal";
            EGAStoreArgsOperator[EGAStoreArgsOperator["LessOrEqual"] = 1] = "LessOrEqual";
            EGAStoreArgsOperator[EGAStoreArgsOperator["NotEqual"] = 2] = "NotEqual";
        })(EGAStoreArgsOperator = store_1.EGAStoreArgsOperator || (store_1.EGAStoreArgsOperator = {}));
        var EGAStore;
        (function (EGAStore) {
            EGAStore[EGAStore["Events"] = 0] = "Events";
            EGAStore[EGAStore["Sessions"] = 1] = "Sessions";
            EGAStore[EGAStore["Progression"] = 2] = "Progression";
        })(EGAStore = store_1.EGAStore || (store_1.EGAStore = {}));
        var GAStore = (function () {
            function GAStore() {
                this.eventsStore = [];
                this.sessionsStore = [];
                this.progressionStore = [];
                this.storeItems = {};
                try {
                    if (typeof localStorage === 'object') {
                        localStorage.setItem('testingLocalStorage', 'yes');
                        localStorage.removeItem('testingLocalStorage');
                        GAStore.storageAvailable = true;
                    }
                    else {
                        GAStore.storageAvailable = false;
                    }
                }
                catch (e) {
                }
                GALogger.d("Storage is available?: " + GAStore.storageAvailable);
            }
            GAStore.isStorageAvailable = function () {
                return GAStore.storageAvailable;
            };
            GAStore.isStoreTooLargeForEvents = function () {
                return GAStore.instance.eventsStore.length + GAStore.instance.sessionsStore.length > GAStore.MaxNumberOfEntries;
            };
            GAStore.select = function (store, args, sort, maxCount) {
                if (args === void 0) { args = []; }
                if (sort === void 0) { sort = false; }
                if (maxCount === void 0) { maxCount = 0; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return null;
                }
                var result = [];
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var add = true;
                    for (var j = 0; j < args.length; ++j) {
                        var argsEntry = args[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        add = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        add = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        add = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        add = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            add = false;
                        }
                        if (!add) {
                            break;
                        }
                    }
                    if (add) {
                        result.push(entry);
                    }
                }
                if (sort) {
                    result.sort(function (a, b) {
                        return a["client_ts"] - b["client_ts"];
                    });
                }
                if (maxCount > 0 && result.length > maxCount) {
                    result = result.slice(0, maxCount + 1);
                }
                return result;
            };
            GAStore.update = function (store, setArgs, whereArgs) {
                if (whereArgs === void 0) { whereArgs = []; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return false;
                }
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var update = true;
                    for (var j = 0; j < whereArgs.length; ++j) {
                        var argsEntry = whereArgs[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        update = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        update = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        update = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        update = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            update = false;
                        }
                        if (!update) {
                            break;
                        }
                    }
                    if (update) {
                        for (var j = 0; j < setArgs.length; ++j) {
                            var setArgsEntry = setArgs[j];
                            entry[setArgsEntry[0]] = setArgsEntry[1];
                        }
                    }
                }
                return true;
            };
            GAStore["delete"] = function (store, args) {
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return;
                }
                for (var i = 0; i < currentStore.length; ++i) {
                    var entry = currentStore[i];
                    var del = true;
                    for (var j = 0; j < args.length; ++j) {
                        var argsEntry = args[j];
                        if (entry[argsEntry[0]]) {
                            switch (argsEntry[1]) {
                                case EGAStoreArgsOperator.Equal:
                                    {
                                        del = entry[argsEntry[0]] == argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.LessOrEqual:
                                    {
                                        del = entry[argsEntry[0]] <= argsEntry[2];
                                    }
                                    break;
                                case EGAStoreArgsOperator.NotEqual:
                                    {
                                        del = entry[argsEntry[0]] != argsEntry[2];
                                    }
                                    break;
                                default:
                                    {
                                        del = false;
                                    }
                                    break;
                            }
                        }
                        else {
                            del = false;
                        }
                        if (!del) {
                            break;
                        }
                    }
                    if (del) {
                        currentStore.splice(i, 1);
                        --i;
                    }
                }
            };
            GAStore.insert = function (store, newEntry, replace, replaceKey) {
                if (replace === void 0) { replace = false; }
                if (replaceKey === void 0) { replaceKey = null; }
                var currentStore = GAStore.getStore(store);
                if (!currentStore) {
                    return;
                }
                if (replace) {
                    if (!replaceKey) {
                        return;
                    }
                    var replaced = false;
                    for (var i = 0; i < currentStore.length; ++i) {
                        var entry = currentStore[i];
                        if (entry[replaceKey] == newEntry[replaceKey]) {
                            for (var s in newEntry) {
                                entry[s] = newEntry[s];
                            }
                            replaced = true;
                            break;
                        }
                    }
                    if (!replaced) {
                        currentStore.push(newEntry);
                    }
                }
                else {
                    currentStore.push(newEntry);
                }
            };
            GAStore.save = function () {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot save.");
                    return;
                }
                localStorage.setItem(GAStore.KeyPrefix + GAStore.EventsStoreKey, JSON.stringify(GAStore.instance.eventsStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.SessionsStoreKey, JSON.stringify(GAStore.instance.sessionsStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.ProgressionStoreKey, JSON.stringify(GAStore.instance.progressionStore));
                localStorage.setItem(GAStore.KeyPrefix + GAStore.ItemsStoreKey, JSON.stringify(GAStore.instance.storeItems));
            };
            GAStore.load = function () {
                if (!GAStore.isStorageAvailable()) {
                    GALogger.w("Storage is not available, cannot load.");
                    return;
                }
                try {
                    GAStore.instance.eventsStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.EventsStoreKey));
                    if (!GAStore.instance.eventsStore) {
                        GAStore.instance.eventsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'events' store. Using empty store.");
                    GAStore.instance.eventsStore = [];
                }
                try {
                    GAStore.instance.sessionsStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.SessionsStoreKey));
                    if (!GAStore.instance.sessionsStore) {
                        GAStore.instance.sessionsStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'sessions' store. Using empty store.");
                    GAStore.instance.sessionsStore = [];
                }
                try {
                    GAStore.instance.progressionStore = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.ProgressionStoreKey));
                    if (!GAStore.instance.progressionStore) {
                        GAStore.instance.progressionStore = [];
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'progression' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
                try {
                    GAStore.instance.storeItems = JSON.parse(localStorage.getItem(GAStore.KeyPrefix + GAStore.ItemsStoreKey));
                    if (!GAStore.instance.storeItems) {
                        GAStore.instance.storeItems = {};
                    }
                }
                catch (e) {
                    GALogger.w("Load failed for 'items' store. Using empty store.");
                    GAStore.instance.progressionStore = [];
                }
            };
            GAStore.setItem = function (key, value) {
                var keyWithPrefix = GAStore.KeyPrefix + key;
                if (!value) {
                    if (keyWithPrefix in GAStore.instance.storeItems) {
                        delete GAStore.instance.storeItems[keyWithPrefix];
                    }
                }
                else {
                    GAStore.instance.storeItems[keyWithPrefix] = value;
                }
            };
            GAStore.getItem = function (key) {
                var keyWithPrefix = GAStore.KeyPrefix + key;
                if (keyWithPrefix in GAStore.instance.storeItems) {
                    return GAStore.instance.storeItems[keyWithPrefix];
                }
                else {
                    return null;
                }
            };
            GAStore.getStore = function (store) {
                switch (store) {
                    case EGAStore.Events:
                        {
                            return GAStore.instance.eventsStore;
                        }
                    case EGAStore.Sessions:
                        {
                            return GAStore.instance.sessionsStore;
                        }
                    case EGAStore.Progression:
                        {
                            return GAStore.instance.progressionStore;
                        }
                    default:
                        {
                            GALogger.w("GAStore.getStore(): Cannot find store: " + store);
                            return null;
                        }
                }
            };
            GAStore.instance = new GAStore();
            GAStore.MaxNumberOfEntries = 2000;
            GAStore.KeyPrefix = "GA::";
            GAStore.EventsStoreKey = "ga_event";
            GAStore.SessionsStoreKey = "ga_session";
            GAStore.ProgressionStoreKey = "ga_progression";
            GAStore.ItemsStoreKey = "ga_items";
            return GAStore;
        }());
        store_1.GAStore = GAStore;
    })(store = gameanalytics.store || (gameanalytics.store = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var state;
    (function (state) {
        var GAValidator = gameanalytics.validators.GAValidator;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GALogger = gameanalytics.logging.GALogger;
        var GAStore = gameanalytics.store.GAStore;
        var GADevice = gameanalytics.device.GADevice;
        var EGAStore = gameanalytics.store.EGAStore;
        var EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        var GAState = (function () {
            function GAState() {
                this.availableCustomDimensions01 = [];
                this.availableCustomDimensions02 = [];
                this.availableCustomDimensions03 = [];
                this.availableResourceCurrencies = [];
                this.availableResourceItemTypes = [];
                this.configurations = {};
                this.remoteConfigsListeners = [];
                this.sdkConfigDefault = {};
                this.sdkConfig = {};
                this.progressionTries = {};
                this._isEventSubmissionEnabled = true;
            }
            GAState.setUserId = function (userId) {
                GAState.instance.userId = userId;
                GAState.cacheIdentifier();
            };
            GAState.getIdentifier = function () {
                return GAState.instance.identifier;
            };
            GAState.isInitialized = function () {
                return GAState.instance.initialized;
            };
            GAState.setInitialized = function (value) {
                GAState.instance.initialized = value;
            };
            GAState.getSessionStart = function () {
                return GAState.instance.sessionStart;
            };
            GAState.getSessionNum = function () {
                return GAState.instance.sessionNum;
            };
            GAState.getTransactionNum = function () {
                return GAState.instance.transactionNum;
            };
            GAState.getSessionId = function () {
                return GAState.instance.sessionId;
            };
            GAState.getCurrentCustomDimension01 = function () {
                return GAState.instance.currentCustomDimension01;
            };
            GAState.getCurrentCustomDimension02 = function () {
                return GAState.instance.currentCustomDimension02;
            };
            GAState.getCurrentCustomDimension03 = function () {
                return GAState.instance.currentCustomDimension03;
            };
            GAState.getGameKey = function () {
                return GAState.instance.gameKey;
            };
            GAState.getGameSecret = function () {
                return GAState.instance.gameSecret;
            };
            GAState.getAvailableCustomDimensions01 = function () {
                return GAState.instance.availableCustomDimensions01;
            };
            GAState.setAvailableCustomDimensions01 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions01 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom01 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableCustomDimensions02 = function () {
                return GAState.instance.availableCustomDimensions02;
            };
            GAState.setAvailableCustomDimensions02 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions02 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom02 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableCustomDimensions03 = function () {
                return GAState.instance.availableCustomDimensions03;
            };
            GAState.setAvailableCustomDimensions03 = function (value) {
                if (!GAValidator.validateCustomDimensions(value)) {
                    return;
                }
                GAState.instance.availableCustomDimensions03 = value;
                GAState.validateAndFixCurrentDimensions();
                GALogger.i("Set available custom03 dimension values: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableResourceCurrencies = function () {
                return GAState.instance.availableResourceCurrencies;
            };
            GAState.setAvailableResourceCurrencies = function (value) {
                if (!GAValidator.validateResourceCurrencies(value)) {
                    return;
                }
                GAState.instance.availableResourceCurrencies = value;
                GALogger.i("Set available resource currencies: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getAvailableResourceItemTypes = function () {
                return GAState.instance.availableResourceItemTypes;
            };
            GAState.setAvailableResourceItemTypes = function (value) {
                if (!GAValidator.validateResourceItemTypes(value)) {
                    return;
                }
                GAState.instance.availableResourceItemTypes = value;
                GALogger.i("Set available resource item types: (" + GAUtilities.joinStringArray(value, ", ") + ")");
            };
            GAState.getBuild = function () {
                return GAState.instance.build;
            };
            GAState.setBuild = function (value) {
                GAState.instance.build = value;
                GALogger.i("Set build version: " + value);
            };
            GAState.getUseManualSessionHandling = function () {
                return GAState.instance.useManualSessionHandling;
            };
            GAState.isEventSubmissionEnabled = function () {
                return GAState.instance._isEventSubmissionEnabled;
            };
            GAState.getABTestingId = function () {
                return GAState.instance.abId;
            };
            GAState.getABTestingVariantId = function () {
                return GAState.instance.abVariantId;
            };
            GAState.prototype.setDefaultId = function (value) {
                this.defaultUserId = !value ? "" : value;
                GAState.cacheIdentifier();
            };
            GAState.getDefaultId = function () {
                return GAState.instance.defaultUserId;
            };
            GAState.getSdkConfig = function () {
                {
                    var first;
                    var count = 0;
                    for (var json in GAState.instance.sdkConfig) {
                        if (count === 0) {
                            first = json;
                        }
                        ++count;
                    }
                    if (first && count > 0) {
                        return GAState.instance.sdkConfig;
                    }
                }
                {
                    var first;
                    var count = 0;
                    for (var json in GAState.instance.sdkConfigCached) {
                        if (count === 0) {
                            first = json;
                        }
                        ++count;
                    }
                    if (first && count > 0) {
                        return GAState.instance.sdkConfigCached;
                    }
                }
                return GAState.instance.sdkConfigDefault;
            };
            GAState.isEnabled = function () {
                if (!GAState.instance.initAuthorized) {
                    return false;
                }
                else {
                    return true;
                }
            };
            GAState.setCustomDimension01 = function (dimension) {
                GAState.instance.currentCustomDimension01 = dimension;
                GAStore.setItem(GAState.Dimension01Key, dimension);
                GALogger.i("Set custom01 dimension value: " + dimension);
            };
            GAState.setCustomDimension02 = function (dimension) {
                GAState.instance.currentCustomDimension02 = dimension;
                GAStore.setItem(GAState.Dimension02Key, dimension);
                GALogger.i("Set custom02 dimension value: " + dimension);
            };
            GAState.setCustomDimension03 = function (dimension) {
                GAState.instance.currentCustomDimension03 = dimension;
                GAStore.setItem(GAState.Dimension03Key, dimension);
                GALogger.i("Set custom03 dimension value: " + dimension);
            };
            GAState.incrementSessionNum = function () {
                var sessionNumInt = GAState.getSessionNum() + 1;
                GAState.instance.sessionNum = sessionNumInt;
            };
            GAState.incrementTransactionNum = function () {
                var transactionNumInt = GAState.getTransactionNum() + 1;
                GAState.instance.transactionNum = transactionNumInt;
            };
            GAState.incrementProgressionTries = function (progression) {
                var tries = GAState.getProgressionTries(progression) + 1;
                GAState.instance.progressionTries[progression] = tries;
                var values = {};
                values["progression"] = progression;
                values["tries"] = tries;
                GAStore.insert(EGAStore.Progression, values, true, "progression");
            };
            GAState.getProgressionTries = function (progression) {
                if (progression in GAState.instance.progressionTries) {
                    return GAState.instance.progressionTries[progression];
                }
                else {
                    return 0;
                }
            };
            GAState.clearProgressionTries = function (progression) {
                if (progression in GAState.instance.progressionTries) {
                    delete GAState.instance.progressionTries[progression];
                }
                var parms = [];
                parms.push(["progression", EGAStoreArgsOperator.Equal, progression]);
                GAStore["delete"](EGAStore.Progression, parms);
            };
            GAState.setKeys = function (gameKey, gameSecret) {
                GAState.instance.gameKey = gameKey;
                GAState.instance.gameSecret = gameSecret;
            };
            GAState.setManualSessionHandling = function (flag) {
                GAState.instance.useManualSessionHandling = flag;
                GALogger.i("Use manual session handling: " + flag);
            };
            GAState.setEnabledEventSubmission = function (flag) {
                GAState.instance._isEventSubmissionEnabled = flag;
            };
            GAState.getEventAnnotations = function () {
                var annotations = {};
                annotations["v"] = 2;
                annotations["user_id"] = GAState.instance.identifier;
                annotations["client_ts"] = GAState.getClientTsAdjusted();
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                annotations["os_version"] = GADevice.osVersion;
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                annotations["device"] = GADevice.deviceModel;
                annotations["browser_version"] = GADevice.browserVersion;
                annotations["platform"] = GADevice.buildPlatform;
                annotations["session_id"] = GAState.instance.sessionId;
                annotations[GAState.SessionNumKey] = GAState.instance.sessionNum;
                var connection_type = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type)) {
                    annotations["connection_type"] = connection_type;
                }
                if (GADevice.gameEngineVersion) {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }
                if (GAState.instance.configurations) {
                    var count = 0;
                    for (var _ in GAState.instance.configurations) {
                        count++;
                        break;
                    }
                    if (count > 0) {
                        annotations["configurations"] = GAState.instance.configurations;
                    }
                }
                if (GAState.instance.abId) {
                    annotations["ab_id"] = GAState.instance.abId;
                }
                if (GAState.instance.abVariantId) {
                    annotations["ab_variant_id"] = GAState.instance.abVariantId;
                }
                if (GAState.instance.build) {
                    annotations["build"] = GAState.instance.build;
                }
                return annotations;
            };
            GAState.getSdkErrorEventAnnotations = function () {
                var annotations = {};
                annotations["v"] = 2;
                annotations["category"] = GAState.CategorySdkError;
                annotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                annotations["os_version"] = GADevice.osVersion;
                annotations["manufacturer"] = GADevice.deviceManufacturer;
                annotations["device"] = GADevice.deviceModel;
                annotations["platform"] = GADevice.buildPlatform;
                var connection_type = GADevice.getConnectionType();
                if (GAValidator.validateConnectionType(connection_type)) {
                    annotations["connection_type"] = connection_type;
                }
                if (GADevice.gameEngineVersion) {
                    annotations["engine_version"] = GADevice.gameEngineVersion;
                }
                return annotations;
            };
            GAState.getInitAnnotations = function () {
                var initAnnotations = {};
                if (!GAState.getIdentifier()) {
                    GAState.cacheIdentifier();
                }
                initAnnotations["user_id"] = GAState.getIdentifier();
                initAnnotations["sdk_version"] = GADevice.getRelevantSdkVersion();
                initAnnotations["os_version"] = GADevice.osVersion;
                initAnnotations["platform"] = GADevice.buildPlatform;
                if (GAState.getBuild()) {
                    initAnnotations["build"] = GAState.getBuild();
                }
                else {
                    initAnnotations["build"] = null;
                }
                initAnnotations["session_num"] = GAState.getSessionNum();
                initAnnotations["random_salt"] = GAState.getSessionNum();
                return initAnnotations;
            };
            GAState.getClientTsAdjusted = function () {
                var clientTs = GAUtilities.timeIntervalSince1970();
                var clientTsAdjustedInteger = clientTs + GAState.instance.clientServerTimeOffset;
                if (GAValidator.validateClientTs(clientTsAdjustedInteger)) {
                    return clientTsAdjustedInteger;
                }
                else {
                    return clientTs;
                }
            };
            GAState.sessionIsStarted = function () {
                return GAState.instance.sessionStart != 0;
            };
            GAState.cacheIdentifier = function () {
                if (GAState.instance.userId) {
                    GAState.instance.identifier = GAState.instance.userId;
                }
                else if (GAState.instance.defaultUserId) {
                    GAState.instance.identifier = GAState.instance.defaultUserId;
                }
                GALogger.d("identifier, {clean:" + GAState.instance.identifier + "}");
            };
            GAState.ensurePersistedStates = function () {
                if (GAStore.isStorageAvailable()) {
                    GAStore.load();
                }
                var instance = GAState.instance;
                instance.setDefaultId(GAStore.getItem(GAState.DefaultUserIdKey) != null ? GAStore.getItem(GAState.DefaultUserIdKey) : GAUtilities.createGuid());
                instance.sessionNum = GAStore.getItem(GAState.SessionNumKey) != null ? Number(GAStore.getItem(GAState.SessionNumKey)) : 0.0;
                instance.transactionNum = GAStore.getItem(GAState.TransactionNumKey) != null ? Number(GAStore.getItem(GAState.TransactionNumKey)) : 0.0;
                if (instance.currentCustomDimension01) {
                    GAStore.setItem(GAState.Dimension01Key, instance.currentCustomDimension01);
                }
                else {
                    instance.currentCustomDimension01 = GAStore.getItem(GAState.Dimension01Key) != null ? GAStore.getItem(GAState.Dimension01Key) : "";
                    if (instance.currentCustomDimension01) {
                        GALogger.d("Dimension01 found in cache: " + instance.currentCustomDimension01);
                    }
                }
                if (instance.currentCustomDimension02) {
                    GAStore.setItem(GAState.Dimension02Key, instance.currentCustomDimension02);
                }
                else {
                    instance.currentCustomDimension02 = GAStore.getItem(GAState.Dimension02Key) != null ? GAStore.getItem(GAState.Dimension02Key) : "";
                    if (instance.currentCustomDimension02) {
                        GALogger.d("Dimension02 found in cache: " + instance.currentCustomDimension02);
                    }
                }
                if (instance.currentCustomDimension03) {
                    GAStore.setItem(GAState.Dimension03Key, instance.currentCustomDimension03);
                }
                else {
                    instance.currentCustomDimension03 = GAStore.getItem(GAState.Dimension03Key) != null ? GAStore.getItem(GAState.Dimension03Key) : "";
                    if (instance.currentCustomDimension03) {
                        GALogger.d("Dimension03 found in cache: " + instance.currentCustomDimension03);
                    }
                }
                var sdkConfigCachedString = GAStore.getItem(GAState.SdkConfigCachedKey) != null ? GAStore.getItem(GAState.SdkConfigCachedKey) : "";
                if (sdkConfigCachedString) {
                    var sdkConfigCached = JSON.parse(GAUtilities.decode64(sdkConfigCachedString));
                    if (sdkConfigCached) {
                        instance.sdkConfigCached = sdkConfigCached;
                    }
                }
                {
                    var currentSdkConfig = GAState.getSdkConfig();
                    instance.configsHash = currentSdkConfig["configs_hash"] ? currentSdkConfig["configs_hash"] : "";
                    instance.abId = currentSdkConfig["ab_id"] ? currentSdkConfig["ab_id"] : "";
                    instance.abVariantId = currentSdkConfig["ab_variant_id"] ? currentSdkConfig["ab_variant_id"] : "";
                }
                var results_ga_progression = GAStore.select(EGAStore.Progression);
                if (results_ga_progression) {
                    for (var i = 0; i < results_ga_progression.length; ++i) {
                        var result = results_ga_progression[i];
                        if (result) {
                            instance.progressionTries[result["progression"]] = result["tries"];
                        }
                    }
                }
            };
            GAState.calculateServerTimeOffset = function (serverTs) {
                var clientTs = GAUtilities.timeIntervalSince1970();
                return serverTs - clientTs;
            };
            GAState.validateAndCleanCustomFields = function (fields) {
                var result = {};
                if (fields) {
                    var count = 0;
                    for (var key in fields) {
                        var value = fields[key];
                        if (!key || !value) {
                            GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value +
                                " has been omitted because its key or value is null");
                        }
                        else if (count < GAState.MAX_CUSTOM_FIELDS_COUNT) {
                            var regex = new RegExp("^[a-zA-Z0-9_]{1," + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + "}$");
                            if (GAUtilities.stringMatch(key, regex)) {
                                var type = typeof value;
                                if (type === "string" || value instanceof String) {
                                    var valueAsString = value;
                                    if (valueAsString.length <= GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH && valueAsString.length > 0) {
                                        result[key] = valueAsString;
                                        ++count;
                                    }
                                    else {
                                        GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its value is an empty string or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH + ")");
                                    }
                                }
                                else if (type === "number" || value instanceof Number) {
                                    var valueAsNumber = value;
                                    result[key] = valueAsNumber;
                                    ++count;
                                }
                                else {
                                    GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its value is not a string or number");
                                }
                            }
                            else {
                                GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because its key contains illegal character, is empty or exceeds the max number of characters (" + GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH + ")");
                            }
                        }
                        else {
                            GALogger.w("validateAndCleanCustomFields: entry with key=" + key + ", value=" + value + " has been omitted because it exceeds the max number of custom fields (" + GAState.MAX_CUSTOM_FIELDS_COUNT + ")");
                        }
                    }
                }
                return result;
            };
            GAState.validateAndFixCurrentDimensions = function () {
                if (!GAValidator.validateDimension01(GAState.getCurrentCustomDimension01(), GAState.getAvailableCustomDimensions01())) {
                    GALogger.d("Invalid dimension01 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension01());
                    GAState.setCustomDimension01("");
                }
                if (!GAValidator.validateDimension02(GAState.getCurrentCustomDimension02(), GAState.getAvailableCustomDimensions02())) {
                    GALogger.d("Invalid dimension02 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension02());
                    GAState.setCustomDimension02("");
                }
                if (!GAValidator.validateDimension03(GAState.getCurrentCustomDimension03(), GAState.getAvailableCustomDimensions03())) {
                    GALogger.d("Invalid dimension03 found in variable. Setting to nil. Invalid dimension: " + GAState.getCurrentCustomDimension03());
                    GAState.setCustomDimension03("");
                }
            };
            GAState.getConfigurationStringValue = function (key, defaultValue) {
                if (GAState.instance.configurations[key]) {
                    return GAState.instance.configurations[key].toString();
                }
                else {
                    return defaultValue;
                }
            };
            GAState.isRemoteConfigsReady = function () {
                return GAState.instance.remoteConfigsIsReady;
            };
            GAState.addRemoteConfigsListener = function (listener) {
                if (GAState.instance.remoteConfigsListeners.indexOf(listener) < 0) {
                    GAState.instance.remoteConfigsListeners.push(listener);
                }
            };
            GAState.removeRemoteConfigsListener = function (listener) {
                var index = GAState.instance.remoteConfigsListeners.indexOf(listener);
                if (index > -1) {
                    GAState.instance.remoteConfigsListeners.splice(index, 1);
                }
            };
            GAState.getRemoteConfigsContentAsString = function () {
                return JSON.stringify(GAState.instance.configurations);
            };
            GAState.populateConfigurations = function (sdkConfig) {
                var configurations = sdkConfig["configs"];
                if (configurations) {
                    GAState.instance.configurations = {};
                    for (var i = 0; i < configurations.length; ++i) {
                        var configuration = configurations[i];
                        if (configuration) {
                            var key = configuration["key"];
                            var value = configuration["value"];
                            var start_ts = configuration["start_ts"] ? configuration["start_ts"] : Number.MIN_VALUE;
                            var end_ts = configuration["end_ts"] ? configuration["end_ts"] : Number.MAX_VALUE;
                            var client_ts_adjusted = GAState.getClientTsAdjusted();
                            if (key && value && client_ts_adjusted > start_ts && client_ts_adjusted < end_ts) {
                                GAState.instance.configurations[key] = value;
                                GALogger.d("configuration added: " + JSON.stringify(configuration));
                            }
                        }
                    }
                }
                GAState.instance.remoteConfigsIsReady = true;
                var listeners = GAState.instance.remoteConfigsListeners;
                for (var i = 0; i < listeners.length; ++i) {
                    if (listeners[i]) {
                        listeners[i].onRemoteConfigsUpdated();
                    }
                }
            };
            GAState.CategorySdkError = "sdk_error";
            GAState.MAX_CUSTOM_FIELDS_COUNT = 50;
            GAState.MAX_CUSTOM_FIELDS_KEY_LENGTH = 64;
            GAState.MAX_CUSTOM_FIELDS_VALUE_STRING_LENGTH = 256;
            GAState.instance = new GAState();
            GAState.DefaultUserIdKey = "default_user_id";
            GAState.SessionNumKey = "session_num";
            GAState.TransactionNumKey = "transaction_num";
            GAState.Dimension01Key = "dimension01";
            GAState.Dimension02Key = "dimension02";
            GAState.Dimension03Key = "dimension03";
            GAState.SdkConfigCachedKey = "sdk_config_cached";
            return GAState;
        }());
        state.GAState = GAState;
    })(state = gameanalytics.state || (gameanalytics.state = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var tasks;
    (function (tasks) {
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GALogger = gameanalytics.logging.GALogger;
        var SdkErrorTask = (function () {
            function SdkErrorTask() {
            }
            SdkErrorTask.execute = function (url, type, payloadData, secretKey) {
                if (!SdkErrorTask.countMap[type]) {
                    SdkErrorTask.countMap[type] = 0;
                }
                if (SdkErrorTask.countMap[type] >= SdkErrorTask.MaxCount) {
                    return;
                }
                var hashHmac = GAUtilities.getHmac(secretKey, payloadData);
                var request = new XMLHttpRequest();
                request.onreadystatechange = function () {
                    if (request.readyState === 4) {
                        if (!request.responseText) {
                            GALogger.d("sdk error failed. Might be no connection. Description: " + request.statusText + ", Status code: " + request.status);
                            return;
                        }
                        if (request.status != 200) {
                            GALogger.w("sdk error failed. response code not 200. status code: " + request.status + ", description: " + request.statusText + ", body: " + request.responseText);
                            return;
                        }
                        else {
                            SdkErrorTask.countMap[type] = SdkErrorTask.countMap[type] + 1;
                        }
                    }
                };
                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");
                request.setRequestHeader("Authorization", hashHmac);
                try {
                    request.send(payloadData);
                }
                catch (e) {
                    console.error(e);
                }
            };
            SdkErrorTask.MaxCount = 10;
            SdkErrorTask.countMap = {};
            return SdkErrorTask;
        }());
        tasks.SdkErrorTask = SdkErrorTask;
    })(tasks = gameanalytics.tasks || (gameanalytics.tasks = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var http;
    (function (http) {
        var GAState = gameanalytics.state.GAState;
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var GAValidator = gameanalytics.validators.GAValidator;
        var SdkErrorTask = gameanalytics.tasks.SdkErrorTask;
        var GAHTTPApi = (function () {
            function GAHTTPApi() {
                this.protocol = "https";
                this.hostName = "api.gameanalytics.com";
                this.version = "v2";
                this.remoteConfigsVersion = "v1";
                this.baseUrl = this.protocol + "://" + this.hostName + "/" + this.version;
                this.remoteConfigsBaseUrl = this.protocol + "://" + this.hostName + "/remote_configs/" + this.remoteConfigsVersion;
                this.initializeUrlPath = "init";
                this.eventsUrlPath = "events";
                this.useGzip = false;
            }
            GAHTTPApi.prototype.requestInit = function (configsHash, callback) {
                var gameKey = GAState.getGameKey();
                var url = this.remoteConfigsBaseUrl + "/" + this.initializeUrlPath + "?game_key=" + gameKey + "&interval_seconds=0&configs_hash=" + configsHash;
                GALogger.d("Sending 'init' URL: " + url);
                var initAnnotations = GAState.getInitAnnotations();
                var JSONstring = JSON.stringify(initAnnotations);
                if (!JSONstring) {
                    callback(http.EGAHTTPApiResponse.JsonEncodeFailed, null);
                    return;
                }
                var payloadData = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs = [];
                extraArgs.push(JSONstring);
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.initRequestCallback, callback);
            };
            GAHTTPApi.prototype.sendEventsInArray = function (eventArray, requestId, callback) {
                if (eventArray.length == 0) {
                    GALogger.d("sendEventsInArray called with missing eventArray");
                    return;
                }
                var gameKey = GAState.getGameKey();
                var url = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);
                var JSONstring = JSON.stringify(eventArray);
                if (!JSONstring) {
                    GALogger.d("sendEventsInArray JSON encoding failed of eventArray");
                    callback(http.EGAHTTPApiResponse.JsonEncodeFailed, null, requestId, eventArray.length);
                    return;
                }
                var payloadData = this.createPayloadData(JSONstring, this.useGzip);
                var extraArgs = [];
                extraArgs.push(JSONstring);
                extraArgs.push(requestId);
                extraArgs.push(eventArray.length.toString());
                GAHTTPApi.sendRequest(url, payloadData, extraArgs, this.useGzip, GAHTTPApi.sendEventInArrayRequestCallback, callback);
            };
            GAHTTPApi.prototype.sendSdkErrorEvent = function (type) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var gameKey = GAState.getGameKey();
                var secretKey = GAState.getGameSecret();
                if (!GAValidator.validateSdkErrorEvent(gameKey, secretKey, type)) {
                    return;
                }
                var url = this.baseUrl + "/" + gameKey + "/" + this.eventsUrlPath;
                GALogger.d("Sending 'events' URL: " + url);
                var payloadJSONString = "";
                var json = GAState.getSdkErrorEventAnnotations();
                var typeString = GAHTTPApi.sdkErrorTypeToString(type);
                json["type"] = typeString;
                var eventArray = [];
                eventArray.push(json);
                payloadJSONString = JSON.stringify(eventArray);
                if (!payloadJSONString) {
                    GALogger.w("sendSdkErrorEvent: JSON encoding failed.");
                    return;
                }
                GALogger.d("sendSdkErrorEvent json: " + payloadJSONString);
                SdkErrorTask.execute(url, type, payloadJSONString, secretKey);
            };
            GAHTTPApi.sendEventInArrayRequestCallback = function (request, url, callback, extra) {
                if (extra === void 0) { extra = null; }
                var authorization = extra[0];
                var JSONstring = extra[1];
                var requestId = extra[2];
                var eventCount = parseInt(extra[3]);
                var body = "";
                var responseCode = 0;
                body = request.responseText;
                responseCode = request.status;
                GALogger.d("events request content: " + body);
                var requestResponseEnum = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Events");
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.Created && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed events Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, requestId, eventCount);
                    return;
                }
                var requestJsonDict = body ? JSON.parse(body) : {};
                if (requestJsonDict == null) {
                    callback(http.EGAHTTPApiResponse.JsonDecodeFailed, null, requestId, eventCount);
                    return;
                }
                if (requestResponseEnum == http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Events Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                }
                callback(requestResponseEnum, requestJsonDict, requestId, eventCount);
            };
            GAHTTPApi.sendRequest = function (url, payloadData, extraArgs, gzip, callback, callback2) {
                var request = new XMLHttpRequest();
                var key = GAState.getGameSecret();
                var authorization = GAUtilities.getHmac(key, payloadData);
                var args = [];
                args.push(authorization);
                for (var s in extraArgs) {
                    args.push(extraArgs[s]);
                }
                request.onreadystatechange = function () {
                    if (request.readyState === 4) {
                        callback(request, url, callback2, args);
                    }
                };
                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");
                request.setRequestHeader("Authorization", authorization);
                if (gzip) {
                    throw new Error("gzip not supported");
                }
                try {
                    request.send(payloadData);
                }
                catch (e) {
                    console.error(e.stack);
                }
            };
            GAHTTPApi.initRequestCallback = function (request, url, callback, extra) {
                if (extra === void 0) { extra = null; }
                var authorization = extra[0];
                var JSONstring = extra[1];
                var body = "";
                var responseCode = 0;
                body = request.responseText;
                responseCode = request.status;
                GALogger.d("init request content : " + body + ", JSONstring: " + JSONstring);
                var requestJsonDict = body ? JSON.parse(body) : {};
                var requestResponseEnum = GAHTTPApi.instance.processRequestResponse(responseCode, request.statusText, body, "Init");
                if (requestResponseEnum != http.EGAHTTPApiResponse.Ok && requestResponseEnum != http.EGAHTTPApiResponse.Created && requestResponseEnum != http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. URL: " + url + ", Authorization: " + authorization + ", JSONString: " + JSONstring);
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }
                if (requestJsonDict == null) {
                    GALogger.d("Failed Init Call. Json decoding failed");
                    callback(http.EGAHTTPApiResponse.JsonDecodeFailed, null, "", 0);
                    return;
                }
                if (requestResponseEnum === http.EGAHTTPApiResponse.BadRequest) {
                    GALogger.d("Failed Init Call. Bad request. Response: " + JSON.stringify(requestJsonDict));
                    callback(requestResponseEnum, null, "", 0);
                    return;
                }
                var validatedInitValues = GAValidator.validateAndCleanInitRequestResponse(requestJsonDict, requestResponseEnum === http.EGAHTTPApiResponse.Created);
                if (!validatedInitValues) {
                    callback(http.EGAHTTPApiResponse.BadResponse, null, "", 0);
                    return;
                }
                callback(requestResponseEnum, validatedInitValues, "", 0);
            };
            GAHTTPApi.prototype.createPayloadData = function (payload, gzip) {
                var payloadData;
                if (gzip) {
                    throw new Error("gzip not supported");
                }
                else {
                    payloadData = payload;
                }
                return payloadData;
            };
            GAHTTPApi.prototype.processRequestResponse = function (responseCode, responseMessage, body, requestId) {
                if (!body) {
                    GALogger.d(requestId + " request. failed. Might be no connection. Description: " + responseMessage + ", Status code: " + responseCode);
                    return http.EGAHTTPApiResponse.NoResponse;
                }
                if (responseCode === 200) {
                    return http.EGAHTTPApiResponse.Ok;
                }
                if (responseCode === 201) {
                    return http.EGAHTTPApiResponse.Created;
                }
                if (responseCode === 0 || responseCode === 401) {
                    GALogger.d(requestId + " request. 401 - Unauthorized.");
                    return http.EGAHTTPApiResponse.Unauthorized;
                }
                if (responseCode === 400) {
                    GALogger.d(requestId + " request. 400 - Bad Request.");
                    return http.EGAHTTPApiResponse.BadRequest;
                }
                if (responseCode === 500) {
                    GALogger.d(requestId + " request. 500 - Internal Server Error.");
                    return http.EGAHTTPApiResponse.InternalServerError;
                }
                return http.EGAHTTPApiResponse.UnknownResponseCode;
            };
            GAHTTPApi.sdkErrorTypeToString = function (value) {
                switch (value) {
                    case http.EGASdkErrorType.Rejected:
                        {
                            return "rejected";
                        }
                    default:
                        {
                            return "";
                        }
                }
            };
            GAHTTPApi.instance = new GAHTTPApi();
            return GAHTTPApi;
        }());
        http.GAHTTPApi = GAHTTPApi;
    })(http = gameanalytics.http || (gameanalytics.http = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var events;
    (function (events_1) {
        var GAStore = gameanalytics.store.GAStore;
        var EGAStore = gameanalytics.store.EGAStore;
        var EGAStoreArgsOperator = gameanalytics.store.EGAStoreArgsOperator;
        var GAState = gameanalytics.state.GAState;
        var GALogger = gameanalytics.logging.GALogger;
        var GAUtilities = gameanalytics.utilities.GAUtilities;
        var EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
        var GAHTTPApi = gameanalytics.http.GAHTTPApi;
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGASdkErrorType = gameanalytics.http.EGASdkErrorType;
        var GAEvents = (function () {
            function GAEvents() {
            }
            GAEvents.addSessionStartEvent = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var eventDict = {};
                eventDict["category"] = GAEvents.CategorySessionStart;
                GAState.incrementSessionNum();
                GAStore.setItem(GAState.SessionNumKey, GAState.getSessionNum().toString());
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addEventToStore(eventDict);
                GALogger.i("Add SESSION START event");
                GAEvents.processEvents(GAEvents.CategorySessionStart, false);
            };
            GAEvents.addSessionEndEvent = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var session_start_ts = GAState.getSessionStart();
                var client_ts_adjusted = GAState.getClientTsAdjusted();
                var sessionLength = client_ts_adjusted - session_start_ts;
                if (sessionLength < 0) {
                    GALogger.w("Session length was calculated to be less then 0. Should not be possible. Resetting to 0.");
                    sessionLength = 0;
                }
                var eventDict = {};
                eventDict["category"] = GAEvents.CategorySessionEnd;
                eventDict["length"] = sessionLength;
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addEventToStore(eventDict);
                GALogger.i("Add SESSION END event.");
                GAEvents.processEvents("", false);
            };
            GAEvents.addBusinessEvent = function (currency, amount, itemType, itemId, cartType, fields) {
                if (cartType === void 0) { cartType = null; }
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateBusinessEvent(currency, amount, cartType, itemType, itemId)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventDict = {};
                GAState.incrementTransactionNum();
                GAStore.setItem(GAState.TransactionNumKey, GAState.getTransactionNum().toString());
                eventDict["event_id"] = itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryBusiness;
                eventDict["currency"] = currency;
                eventDict["amount"] = amount;
                eventDict[GAState.TransactionNumKey] = GAState.getTransactionNum();
                if (cartType) {
                    eventDict["cart_type"] = cartType;
                }
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add BUSINESS event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + ", cartType:" + cartType + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addResourceEvent = function (flowType, currency, amount, itemType, itemId, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateResourceEvent(flowType, currency, amount, itemType, itemId, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes())) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                if (flowType === gameanalytics.EGAResourceFlowType.Sink) {
                    amount *= -1;
                }
                var eventDict = {};
                var flowTypeString = GAEvents.resourceFlowTypeToString(flowType);
                eventDict["event_id"] = flowTypeString + ":" + currency + ":" + itemType + ":" + itemId;
                eventDict["category"] = GAEvents.CategoryResource;
                eventDict["amount"] = amount;
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add RESOURCE event: {currency:" + currency + ", amount:" + amount + ", itemType:" + itemType + ", itemId:" + itemId + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score, sendScore, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var progressionStatusString = GAEvents.progressionStatusToString(progressionStatus);
                if (!GAValidator.validateProgressionEvent(progressionStatus, progression01, progression02, progression03)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventDict = {};
                var progressionIdentifier;
                if (!progression02) {
                    progressionIdentifier = progression01;
                }
                else if (!progression03) {
                    progressionIdentifier = progression01 + ":" + progression02;
                }
                else {
                    progressionIdentifier = progression01 + ":" + progression02 + ":" + progression03;
                }
                eventDict["category"] = GAEvents.CategoryProgression;
                eventDict["event_id"] = progressionStatusString + ":" + progressionIdentifier;
                var attempt_num = 0;
                if (sendScore && progressionStatus != gameanalytics.EGAProgressionStatus.Start) {
                    eventDict["score"] = score;
                }
                if (progressionStatus === gameanalytics.EGAProgressionStatus.Fail) {
                    GAState.incrementProgressionTries(progressionIdentifier);
                }
                if (progressionStatus === gameanalytics.EGAProgressionStatus.Complete) {
                    GAState.incrementProgressionTries(progressionIdentifier);
                    attempt_num = GAState.getProgressionTries(progressionIdentifier);
                    eventDict["attempt_num"] = attempt_num;
                    GAState.clearProgressionTries(progressionIdentifier);
                }
                GAEvents.addDimensionsToEvent(eventDict);
                GAEvents.addFieldsToEvent(eventDict, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add PROGRESSION event: {status:" + progressionStatusString + ", progression01:" + progression01 + ", progression02:" + progression02 + ", progression03:" + progression03 + ", score:" + score + ", attempt:" + attempt_num + "}");
                GAEvents.addEventToStore(eventDict);
            };
            GAEvents.addDesignEvent = function (eventId, value, sendValue, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAValidator.validateDesignEvent(eventId, value)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryDesign;
                eventData["event_id"] = eventId;
                if (sendValue) {
                    eventData["value"] = value;
                }
                GAEvents.addDimensionsToEvent(eventData);
                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add DESIGN event: {eventId:" + eventId + ", value:" + value + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.addErrorEvent = function (severity, message, fields) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var severityString = GAEvents.errorSeverityToString(severity);
                if (!GAValidator.validateErrorEvent(severity, message)) {
                    GAHTTPApi.instance.sendSdkErrorEvent(EGASdkErrorType.Rejected);
                    return;
                }
                var eventData = {};
                eventData["category"] = GAEvents.CategoryError;
                eventData["severity"] = severityString;
                eventData["message"] = message;
                GAEvents.addDimensionsToEvent(eventData);
                GAEvents.addFieldsToEvent(eventData, GAState.validateAndCleanCustomFields(fields));
                GALogger.i("Add ERROR event: {severity:" + severityString + ", message:" + message + "}");
                GAEvents.addEventToStore(eventData);
            };
            GAEvents.processEvents = function (category, performCleanUp) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                try {
                    var requestIdentifier = GAUtilities.createGuid();
                    if (performCleanUp) {
                        GAEvents.cleanupEvents();
                        GAEvents.fixMissingSessionEndEvents();
                    }
                    var selectArgs = [];
                    selectArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);
                    var updateWhereArgs = [];
                    updateWhereArgs.push(["status", EGAStoreArgsOperator.Equal, "new"]);
                    if (category) {
                        selectArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                        updateWhereArgs.push(["category", EGAStoreArgsOperator.Equal, category]);
                    }
                    var updateSetArgs = [];
                    updateSetArgs.push(["status", requestIdentifier]);
                    var events = GAStore.select(EGAStore.Events, selectArgs);
                    if (!events || events.length == 0) {
                        GALogger.i("Event queue: No events to send");
                        GAEvents.updateSessionStore();
                        return;
                    }
                    if (events.length > GAEvents.MaxEventCount) {
                        events = GAStore.select(EGAStore.Events, selectArgs, true, GAEvents.MaxEventCount);
                        if (!events) {
                            return;
                        }
                        var lastItem = events[events.length - 1];
                        var lastTimestamp = lastItem["client_ts"];
                        selectArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);
                        events = GAStore.select(EGAStore.Events, selectArgs);
                        if (!events) {
                            return;
                        }
                        updateWhereArgs.push(["client_ts", EGAStoreArgsOperator.LessOrEqual, lastTimestamp]);
                    }
                    GALogger.i("Event queue: Sending " + events.length + " events.");
                    if (!GAStore.update(EGAStore.Events, updateSetArgs, updateWhereArgs)) {
                        return;
                    }
                    var payloadArray = [];
                    for (var i = 0; i < events.length; ++i) {
                        var ev = events[i];
                        var eventDict = JSON.parse(GAUtilities.decode64(ev["event"]));
                        if (eventDict.length != 0) {
                            payloadArray.push(eventDict);
                        }
                    }
                    GAHTTPApi.instance.sendEventsInArray(payloadArray, requestIdentifier, GAEvents.processEventsCallback);
                }
                catch (e) {
                    GALogger.e("Error during ProcessEvents(): " + e.stack);
                }
            };
            GAEvents.processEventsCallback = function (responseEnum, dataDict, requestId, eventCount) {
                var requestIdWhereArgs = [];
                requestIdWhereArgs.push(["status", EGAStoreArgsOperator.Equal, requestId]);
                if (responseEnum === EGAHTTPApiResponse.Ok) {
                    GAStore["delete"](EGAStore.Events, requestIdWhereArgs);
                    GALogger.i("Event queue: " + eventCount + " events sent.");
                }
                else {
                    if (responseEnum === EGAHTTPApiResponse.NoResponse) {
                        var setArgs = [];
                        setArgs.push(["status", "new"]);
                        GALogger.w("Event queue: Failed to send events to collector - Retrying next time");
                        GAStore.update(EGAStore.Events, setArgs, requestIdWhereArgs);
                    }
                    else {
                        if (dataDict) {
                            var json;
                            var count = 0;
                            for (var j in dataDict) {
                                if (count == 0) {
                                    json = dataDict[j];
                                }
                                ++count;
                            }
                            if (responseEnum === EGAHTTPApiResponse.BadRequest && json.constructor === Array) {
                                GALogger.w("Event queue: " + eventCount + " events sent. " + count + " events failed GA server validation.");
                            }
                            else {
                                GALogger.w("Event queue: Failed to send events.");
                            }
                        }
                        else {
                            GALogger.w("Event queue: Failed to send events.");
                        }
                        GAStore["delete"](EGAStore.Events, requestIdWhereArgs);
                    }
                }
            };
            GAEvents.cleanupEvents = function () {
                GAStore.update(EGAStore.Events, [["status", "new"]]);
            };
            GAEvents.fixMissingSessionEndEvents = function () {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                var args = [];
                args.push(["session_id", EGAStoreArgsOperator.NotEqual, GAState.getSessionId()]);
                var sessions = GAStore.select(EGAStore.Sessions, args);
                if (!sessions || sessions.length == 0) {
                    return;
                }
                GALogger.i(sessions.length + " session(s) located with missing session_end event.");
                for (var i = 0; i < sessions.length; ++i) {
                    var sessionEndEvent = JSON.parse(GAUtilities.decode64(sessions[i]["event"]));
                    var event_ts = sessionEndEvent["client_ts"];
                    var start_ts = sessions[i]["timestamp"];
                    var length = event_ts - start_ts;
                    length = Math.max(0, length);
                    GALogger.d("fixMissingSessionEndEvents length calculated: " + length);
                    sessionEndEvent["category"] = GAEvents.CategorySessionEnd;
                    sessionEndEvent["length"] = length;
                    GAEvents.addEventToStore(sessionEndEvent);
                }
            };
            GAEvents.addEventToStore = function (eventData) {
                if (!GAState.isEventSubmissionEnabled()) {
                    return;
                }
                if (!GAState.isInitialized()) {
                    GALogger.w("Could not add event: SDK is not initialized");
                    return;
                }
                try {
                    if (GAStore.isStoreTooLargeForEvents() && !GAUtilities.stringMatch(eventData["category"], /^(user|session_end|business)$/)) {
                        GALogger.w("Database too large. Event has been blocked.");
                        return;
                    }
                    var ev = GAState.getEventAnnotations();
                    var jsonDefaults = GAUtilities.encode64(JSON.stringify(ev));
                    for (var e in eventData) {
                        ev[e] = eventData[e];
                    }
                    var json = JSON.stringify(ev);
                    GALogger.ii("Event added to queue: " + json);
                    var values = {};
                    values["status"] = "new";
                    values["category"] = ev["category"];
                    values["session_id"] = ev["session_id"];
                    values["client_ts"] = ev["client_ts"];
                    values["event"] = GAUtilities.encode64(JSON.stringify(ev));
                    GAStore.insert(EGAStore.Events, values);
                    if (eventData["category"] == GAEvents.CategorySessionEnd) {
                        GAStore["delete"](EGAStore.Sessions, [["session_id", EGAStoreArgsOperator.Equal, ev["session_id"]]]);
                    }
                    else {
                        values = {};
                        values["session_id"] = ev["session_id"];
                        values["timestamp"] = GAState.getSessionStart();
                        values["event"] = jsonDefaults;
                        GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    }
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save();
                    }
                }
                catch (e) {
                    GALogger.e("addEventToStore: error");
                    GALogger.e(e.stack);
                }
            };
            GAEvents.updateSessionStore = function () {
                if (GAState.sessionIsStarted()) {
                    var values = {};
                    values["session_id"] = GAState.instance.sessionId;
                    values["timestamp"] = GAState.getSessionStart();
                    values["event"] = GAUtilities.encode64(JSON.stringify(GAState.getEventAnnotations()));
                    GAStore.insert(EGAStore.Sessions, values, true, "session_id");
                    if (GAStore.isStorageAvailable()) {
                        GAStore.save();
                    }
                }
            };
            GAEvents.addDimensionsToEvent = function (eventData) {
                if (!eventData) {
                    return;
                }
                if (GAState.getCurrentCustomDimension01()) {
                    eventData["custom_01"] = GAState.getCurrentCustomDimension01();
                }
                if (GAState.getCurrentCustomDimension02()) {
                    eventData["custom_02"] = GAState.getCurrentCustomDimension02();
                }
                if (GAState.getCurrentCustomDimension03()) {
                    eventData["custom_03"] = GAState.getCurrentCustomDimension03();
                }
            };
            GAEvents.addFieldsToEvent = function (eventData, fields) {
                if (!eventData) {
                    return;
                }
                if (fields && Object.keys(fields).length > 0) {
                    eventData["custom_fields"] = fields;
                }
            };
            GAEvents.resourceFlowTypeToString = function (value) {
                if (value == gameanalytics.EGAResourceFlowType.Source || value == gameanalytics.EGAResourceFlowType[gameanalytics.EGAResourceFlowType.Source]) {
                    return "Source";
                }
                else if (value == gameanalytics.EGAResourceFlowType.Sink || value == gameanalytics.EGAResourceFlowType[gameanalytics.EGAResourceFlowType.Sink]) {
                    return "Sink";
                }
                else {
                    return "";
                }
            };
            GAEvents.progressionStatusToString = function (value) {
                if (value == gameanalytics.EGAProgressionStatus.Start || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Start]) {
                    return "Start";
                }
                else if (value == gameanalytics.EGAProgressionStatus.Complete || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Complete]) {
                    return "Complete";
                }
                else if (value == gameanalytics.EGAProgressionStatus.Fail || value == gameanalytics.EGAProgressionStatus[gameanalytics.EGAProgressionStatus.Fail]) {
                    return "Fail";
                }
                else {
                    return "";
                }
            };
            GAEvents.errorSeverityToString = function (value) {
                if (value == gameanalytics.EGAErrorSeverity.Debug || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Debug]) {
                    return "debug";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Info || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Info]) {
                    return "info";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Warning || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Warning]) {
                    return "warning";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Error || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Error]) {
                    return "error";
                }
                else if (value == gameanalytics.EGAErrorSeverity.Critical || value == gameanalytics.EGAErrorSeverity[gameanalytics.EGAErrorSeverity.Critical]) {
                    return "critical";
                }
                else {
                    return "";
                }
            };
            GAEvents.instance = new GAEvents();
            GAEvents.CategorySessionStart = "user";
            GAEvents.CategorySessionEnd = "session_end";
            GAEvents.CategoryDesign = "design";
            GAEvents.CategoryBusiness = "business";
            GAEvents.CategoryProgression = "progression";
            GAEvents.CategoryResource = "resource";
            GAEvents.CategoryError = "error";
            GAEvents.MaxEventCount = 500;
            return GAEvents;
        }());
        events_1.GAEvents = GAEvents;
    })(events = gameanalytics.events || (gameanalytics.events = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var threading;
    (function (threading) {
        var GALogger = gameanalytics.logging.GALogger;
        var GAState = gameanalytics.state.GAState;
        var GAEvents = gameanalytics.events.GAEvents;
        var GAThreading = (function () {
            function GAThreading() {
                this.blocks = new threading.PriorityQueue({
                    compare: function (x, y) {
                        return x - y;
                    }
                });
                this.id2TimedBlockMap = {};
                GALogger.d("Initializing GA thread...");
                GAThreading.startThread();
            }
            GAThreading.createTimedBlock = function (delayInSeconds) {
                if (delayInSeconds === void 0) { delayInSeconds = 0; }
                var time = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);
                var timedBlock = new threading.TimedBlock(time);
                return timedBlock;
            };
            GAThreading.performTaskOnGAThread = function (taskBlock, delayInSeconds) {
                if (delayInSeconds === void 0) { delayInSeconds = 0; }
                var time = new Date();
                time.setSeconds(time.getSeconds() + delayInSeconds);
                var timedBlock = new threading.TimedBlock(time);
                timedBlock.block = taskBlock;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            };
            GAThreading.performTimedBlockOnGAThread = function (timedBlock) {
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
            };
            GAThreading.scheduleTimer = function (interval, callback) {
                var time = new Date();
                time.setSeconds(time.getSeconds() + interval);
                var timedBlock = new threading.TimedBlock(time);
                timedBlock.block = callback;
                GAThreading.instance.id2TimedBlockMap[timedBlock.id] = timedBlock;
                GAThreading.instance.addTimedBlock(timedBlock);
                return timedBlock.id;
            };
            GAThreading.getTimedBlockById = function (blockIdentifier) {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap) {
                    return GAThreading.instance.id2TimedBlockMap[blockIdentifier];
                }
                else {
                    return null;
                }
            };
            GAThreading.ensureEventQueueIsRunning = function () {
                GAThreading.instance.keepRunning = true;
                if (!GAThreading.instance.isRunning) {
                    GAThreading.instance.isRunning = true;
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
            };
            GAThreading.endSessionAndStopQueue = function () {
                if (GAState.isInitialized()) {
                    GALogger.i("Ending session.");
                    GAThreading.stopEventQueue();
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAEvents.addSessionEndEvent();
                        GAState.instance.sessionStart = 0;
                    }
                }
            };
            GAThreading.stopEventQueue = function () {
                GAThreading.instance.keepRunning = false;
            };
            GAThreading.ignoreTimer = function (blockIdentifier) {
                if (blockIdentifier in GAThreading.instance.id2TimedBlockMap) {
                    GAThreading.instance.id2TimedBlockMap[blockIdentifier].ignore = true;
                }
            };
            GAThreading.setEventProcessInterval = function (interval) {
                if (interval > 0) {
                    GAThreading.ProcessEventsIntervalInSeconds = interval;
                }
            };
            GAThreading.prototype.addTimedBlock = function (timedBlock) {
                this.blocks.enqueue(timedBlock.deadline.getTime(), timedBlock);
            };
            GAThreading.run = function () {
                clearTimeout(GAThreading.runTimeoutId);
                try {
                    var timedBlock;
                    while ((timedBlock = GAThreading.getNextBlock())) {
                        if (!timedBlock.ignore) {
                            if (timedBlock.async) {
                                if (!timedBlock.running) {
                                    timedBlock.running = true;
                                    timedBlock.block();
                                    break;
                                }
                            }
                            else {
                                timedBlock.block();
                            }
                        }
                    }
                    GAThreading.runTimeoutId = setTimeout(GAThreading.run, GAThreading.ThreadWaitTimeInMs);
                    return;
                }
                catch (e) {
                    GALogger.e("Error on GA thread");
                    GALogger.e(e.stack);
                }
                GALogger.d("Ending GA thread");
            };
            GAThreading.startThread = function () {
                GALogger.d("Starting GA thread");
                GAThreading.runTimeoutId = setTimeout(GAThreading.run, 0);
            };
            GAThreading.getNextBlock = function () {
                var now = new Date();
                if (GAThreading.instance.blocks.hasItems() && GAThreading.instance.blocks.peek().deadline.getTime() <= now.getTime()) {
                    if (GAThreading.instance.blocks.peek().async) {
                        if (GAThreading.instance.blocks.peek().running) {
                            return GAThreading.instance.blocks.peek();
                        }
                        else {
                            return GAThreading.instance.blocks.dequeue();
                        }
                    }
                    else {
                        return GAThreading.instance.blocks.dequeue();
                    }
                }
                return null;
            };
            GAThreading.processEventQueue = function () {
                GAEvents.processEvents("", true);
                if (GAThreading.instance.keepRunning) {
                    GAThreading.scheduleTimer(GAThreading.ProcessEventsIntervalInSeconds, GAThreading.processEventQueue);
                }
                else {
                    GAThreading.instance.isRunning = false;
                }
            };
            GAThreading.instance = new GAThreading();
            GAThreading.ThreadWaitTimeInMs = 1000;
            GAThreading.ProcessEventsIntervalInSeconds = 8.0;
            return GAThreading;
        }());
        threading.GAThreading = GAThreading;
    })(threading = gameanalytics.threading || (gameanalytics.threading = {}));
})(gameanalytics || (gameanalytics = {}));
var gameanalytics;
(function (gameanalytics) {
    var GAThreading = gameanalytics.threading.GAThreading;
    var GALogger = gameanalytics.logging.GALogger;
    var GAStore = gameanalytics.store.GAStore;
    var GAState = gameanalytics.state.GAState;
    var GAHTTPApi = gameanalytics.http.GAHTTPApi;
    var GADevice = gameanalytics.device.GADevice;
    var GAValidator = gameanalytics.validators.GAValidator;
    var EGAHTTPApiResponse = gameanalytics.http.EGAHTTPApiResponse;
    var GAUtilities = gameanalytics.utilities.GAUtilities;
    var GAEvents = gameanalytics.events.GAEvents;
    var GameAnalytics = (function () {
        function GameAnalytics() {
        }
        GameAnalytics.init = function () {
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
            GameAnalytics.methodMap['addErrorEvent'] = GameAnalytics.addErrorEvent;
            GameAnalytics.methodMap['setEnabledInfoLog'] = GameAnalytics.setEnabledInfoLog;
            GameAnalytics.methodMap['setEnabledVerboseLog'] = GameAnalytics.setEnabledVerboseLog;
            GameAnalytics.methodMap['setEnabledManualSessionHandling'] = GameAnalytics.setEnabledManualSessionHandling;
            GameAnalytics.methodMap['setEnabledEventSubmission'] = GameAnalytics.setEnabledEventSubmission;
            GameAnalytics.methodMap['setCustomDimension01'] = GameAnalytics.setCustomDimension01;
            GameAnalytics.methodMap['setCustomDimension02'] = GameAnalytics.setCustomDimension02;
            GameAnalytics.methodMap['setCustomDimension03'] = GameAnalytics.setCustomDimension03;
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
            if (typeof window !== 'undefined' && typeof window['GameAnalytics'] !== 'undefined' && typeof window['GameAnalytics']['q'] !== 'undefined') {
                var q = window['GameAnalytics']['q'];
                for (var i in q) {
                    GameAnalytics.gaCommand.apply(null, q[i]);
                }
            }
        };
        GameAnalytics.gaCommand = function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            if (args.length > 0) {
                if (args[0] in gameanalytics.GameAnalytics.methodMap) {
                    if (args.length > 1) {
                        gameanalytics.GameAnalytics.methodMap[args[0]].apply(null, Array.prototype.slice.call(args, 1));
                    }
                    else {
                        gameanalytics.GameAnalytics.methodMap[args[0]]();
                    }
                }
            }
        };
        GameAnalytics.configureAvailableCustomDimensions01 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions01(customDimensions);
            });
        };
        GameAnalytics.configureAvailableCustomDimensions02 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions02(customDimensions);
            });
        };
        GameAnalytics.configureAvailableCustomDimensions03 = function (customDimensions) {
            if (customDimensions === void 0) { customDimensions = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableCustomDimensions03(customDimensions);
            });
        };
        GameAnalytics.configureAvailableResourceCurrencies = function (resourceCurrencies) {
            if (resourceCurrencies === void 0) { resourceCurrencies = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available resource currencies must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceCurrencies(resourceCurrencies);
            });
        };
        GameAnalytics.configureAvailableResourceItemTypes = function (resourceItemTypes) {
            if (resourceItemTypes === void 0) { resourceItemTypes = []; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Available resource item types must be set before SDK is initialized");
                    return;
                }
                GAState.setAvailableResourceItemTypes(resourceItemTypes);
            });
        };
        GameAnalytics.configureBuild = function (build) {
            if (build === void 0) { build = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("Build version must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateBuild(build)) {
                    GALogger.i("Validation fail - configure build: Cannot be null, empty or above 32 length. String: " + build);
                    return;
                }
                GAState.setBuild(build);
            });
        };
        GameAnalytics.configureSdkGameEngineVersion = function (sdkGameEngineVersion) {
            if (sdkGameEngineVersion === void 0) { sdkGameEngineVersion = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    return;
                }
                if (!GAValidator.validateSdkWrapperVersion(sdkGameEngineVersion)) {
                    GALogger.i("Validation fail - configure sdk version: Sdk version not supported. String: " + sdkGameEngineVersion);
                    return;
                }
                GADevice.sdkGameEngineVersion = sdkGameEngineVersion;
            });
        };
        GameAnalytics.configureGameEngineVersion = function (gameEngineVersion) {
            if (gameEngineVersion === void 0) { gameEngineVersion = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    return;
                }
                if (!GAValidator.validateEngineVersion(gameEngineVersion)) {
                    GALogger.i("Validation fail - configure game engine version: Game engine version not supported. String: " + gameEngineVersion);
                    return;
                }
                GADevice.gameEngineVersion = gameEngineVersion;
            });
        };
        GameAnalytics.configureUserId = function (uId) {
            if (uId === void 0) { uId = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("A custom user id must be set before SDK is initialized.");
                    return;
                }
                if (!GAValidator.validateUserId(uId)) {
                    GALogger.i("Validation fail - configure user_id: Cannot be null, empty or above 64 length. Will use default user_id method. Used string: " + uId);
                    return;
                }
                GAState.setUserId(uId);
            });
        };
        GameAnalytics.initialize = function (gameKey, gameSecret) {
            if (gameKey === void 0) { gameKey = ""; }
            if (gameSecret === void 0) { gameSecret = ""; }
            GADevice.updateConnectionType();
            var timedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = function () {
                if (GameAnalytics.isSdkReady(true, false)) {
                    GALogger.w("SDK already initialized. Can only be called once.");
                    return;
                }
                if (!GAValidator.validateKeys(gameKey, gameSecret)) {
                    GALogger.w("SDK failed initialize. Game key or secret key is invalid. Can only contain characters A-z 0-9, gameKey is 32 length, gameSecret is 40 length. Failed keys - gameKey: " + gameKey + ", secretKey: " + gameSecret);
                    return;
                }
                GAState.setKeys(gameKey, gameSecret);
                GameAnalytics.internalInitialize();
            };
            GAThreading.performTimedBlockOnGAThread(timedBlock);
        };
        GameAnalytics.addBusinessEvent = function (currency, amount, itemType, itemId, cartType) {
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            if (cartType === void 0) { cartType = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add business event")) {
                    return;
                }
                GAEvents.addBusinessEvent(currency, amount, itemType, itemId, cartType, {});
            });
        };
        GameAnalytics.addResourceEvent = function (flowType, currency, amount, itemType, itemId) {
            if (flowType === void 0) { flowType = gameanalytics.EGAResourceFlowType.Undefined; }
            if (currency === void 0) { currency = ""; }
            if (amount === void 0) { amount = 0; }
            if (itemType === void 0) { itemType = ""; }
            if (itemId === void 0) { itemId = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add resource event")) {
                    return;
                }
                GAEvents.addResourceEvent(flowType, currency, amount, itemType, itemId, {});
            });
        };
        GameAnalytics.addProgressionEvent = function (progressionStatus, progression01, progression02, progression03, score) {
            if (progressionStatus === void 0) { progressionStatus = gameanalytics.EGAProgressionStatus.Undefined; }
            if (progression01 === void 0) { progression01 = ""; }
            if (progression02 === void 0) { progression02 = ""; }
            if (progression03 === void 0) { progression03 = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add progression event")) {
                    return;
                }
                var sendScore = typeof score === "number";
                GAEvents.addProgressionEvent(progressionStatus, progression01, progression02, progression03, sendScore ? score : 0, sendScore, {});
            });
        };
        GameAnalytics.addDesignEvent = function (eventId, value) {
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add design event")) {
                    return;
                }
                var sendValue = typeof value === "number";
                GAEvents.addDesignEvent(eventId, sendValue ? value : 0, sendValue, {});
            });
        };
        GameAnalytics.addErrorEvent = function (severity, message) {
            if (severity === void 0) { severity = gameanalytics.EGAErrorSeverity.Undefined; }
            if (message === void 0) { message = ""; }
            GADevice.updateConnectionType();
            GAThreading.performTaskOnGAThread(function () {
                if (!GameAnalytics.isSdkReady(true, true, "Could not add error event")) {
                    return;
                }
                GAEvents.addErrorEvent(severity, message, {});
            });
        };
        GameAnalytics.setEnabledInfoLog = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GALogger.setInfoLog(flag);
                    GALogger.i("Info logging enabled");
                }
                else {
                    GALogger.i("Info logging disabled");
                    GALogger.setInfoLog(flag);
                }
            });
        };
        GameAnalytics.setEnabledVerboseLog = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GALogger.setVerboseLog(flag);
                    GALogger.i("Verbose logging enabled");
                }
                else {
                    GALogger.i("Verbose logging disabled");
                    GALogger.setVerboseLog(flag);
                }
            });
        };
        GameAnalytics.setEnabledManualSessionHandling = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                GAState.setManualSessionHandling(flag);
            });
        };
        GameAnalytics.setEnabledEventSubmission = function (flag) {
            if (flag === void 0) { flag = false; }
            GAThreading.performTaskOnGAThread(function () {
                if (flag) {
                    GAState.setEnabledEventSubmission(flag);
                    GALogger.i("Event submission enabled");
                }
                else {
                    GALogger.i("Event submission disabled");
                    GAState.setEnabledEventSubmission(flag);
                }
            });
        };
        GameAnalytics.setCustomDimension01 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension01(dimension, GAState.getAvailableCustomDimensions01())) {
                    GALogger.w("Could not set custom01 dimension value to '" + dimension + "'. Value not found in available custom01 dimension values");
                    return;
                }
                GAState.setCustomDimension01(dimension);
            });
        };
        GameAnalytics.setCustomDimension02 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension02(dimension, GAState.getAvailableCustomDimensions02())) {
                    GALogger.w("Could not set custom02 dimension value to '" + dimension + "'. Value not found in available custom02 dimension values");
                    return;
                }
                GAState.setCustomDimension02(dimension);
            });
        };
        GameAnalytics.setCustomDimension03 = function (dimension) {
            if (dimension === void 0) { dimension = ""; }
            GAThreading.performTaskOnGAThread(function () {
                if (!GAValidator.validateDimension03(dimension, GAState.getAvailableCustomDimensions03())) {
                    GALogger.w("Could not set custom03 dimension value to '" + dimension + "'. Value not found in available custom03 dimension values");
                    return;
                }
                GAState.setCustomDimension03(dimension);
            });
        };
        GameAnalytics.setEventProcessInterval = function (intervalInSeconds) {
            GAThreading.performTaskOnGAThread(function () {
                GAThreading.setEventProcessInterval(intervalInSeconds);
            });
        };
        GameAnalytics.startSession = function () {
            {
                if (!GAState.isInitialized()) {
                    return;
                }
                var timedBlock = GAThreading.createTimedBlock();
                timedBlock.async = true;
                GameAnalytics.initTimedBlockId = timedBlock.id;
                timedBlock.block = function () {
                    if (GAState.isEnabled() && GAState.sessionIsStarted()) {
                        GAThreading.endSessionAndStopQueue();
                    }
                    GameAnalytics.resumeSessionAndStartQueue();
                };
                GAThreading.performTimedBlockOnGAThread(timedBlock);
            }
        };
        GameAnalytics.endSession = function () {
            {
                GameAnalytics.onStop();
            }
        };
        GameAnalytics.onStop = function () {
            GAThreading.performTaskOnGAThread(function () {
                try {
                    GAThreading.endSessionAndStopQueue();
                }
                catch (Exception) {
                }
            });
        };
        GameAnalytics.onResume = function () {
            var timedBlock = GAThreading.createTimedBlock();
            timedBlock.async = true;
            GameAnalytics.initTimedBlockId = timedBlock.id;
            timedBlock.block = function () {
                GameAnalytics.resumeSessionAndStartQueue();
            };
            GAThreading.performTimedBlockOnGAThread(timedBlock);
        };
        GameAnalytics.getRemoteConfigsValueAsString = function (key, defaultValue) {
            if (defaultValue === void 0) { defaultValue = null; }
            return GAState.getConfigurationStringValue(key, defaultValue);
        };
        GameAnalytics.isRemoteConfigsReady = function () {
            return GAState.isRemoteConfigsReady();
        };
        GameAnalytics.addRemoteConfigsListener = function (listener) {
            GAState.addRemoteConfigsListener(listener);
        };
        GameAnalytics.removeRemoteConfigsListener = function (listener) {
            GAState.removeRemoteConfigsListener(listener);
        };
        GameAnalytics.getRemoteConfigsContentAsString = function () {
            return GAState.getRemoteConfigsContentAsString();
        };
        GameAnalytics.getABTestingId = function () {
            return GAState.getABTestingId();
        };
        GameAnalytics.getABTestingVariantId = function () {
            return GAState.getABTestingVariantId();
        };
        GameAnalytics.internalInitialize = function () {
            GAState.ensurePersistedStates();
            GAStore.setItem(GAState.DefaultUserIdKey, GAState.getDefaultId());
            GAState.setInitialized(true);
            GameAnalytics.newSession();
            if (GAState.isEnabled()) {
                GAThreading.ensureEventQueueIsRunning();
            }
        };
        GameAnalytics.newSession = function () {
            GALogger.i("Starting a new session.");
            GAState.validateAndFixCurrentDimensions();
            GAHTTPApi.instance.requestInit(GAState.instance.configsHash, GameAnalytics.startNewSessionCallback);
        };
        GameAnalytics.startNewSessionCallback = function (initResponse, initResponseDict) {
            if ((initResponse === EGAHTTPApiResponse.Ok || initResponse === EGAHTTPApiResponse.Created) && initResponseDict) {
                var timeOffsetSeconds = 0;
                if (initResponseDict["server_ts"]) {
                    var serverTs = initResponseDict["server_ts"];
                    timeOffsetSeconds = GAState.calculateServerTimeOffset(serverTs);
                }
                initResponseDict["time_offset"] = timeOffsetSeconds;
                if (initResponse != EGAHTTPApiResponse.Created) {
                    var currentSdkConfig = GAState.getSdkConfig();
                    if (currentSdkConfig["configs"]) {
                        initResponseDict["configs"] = currentSdkConfig["configs"];
                    }
                    if (currentSdkConfig["configs_hash"]) {
                        initResponseDict["configs_hash"] = currentSdkConfig["configs_hash"];
                    }
                    if (currentSdkConfig["ab_id"]) {
                        initResponseDict["ab_id"] = currentSdkConfig["ab_id"];
                    }
                    if (currentSdkConfig["ab_variant_id"]) {
                        initResponseDict["ab_variant_id"] = currentSdkConfig["ab_variant_id"];
                    }
                }
                GAState.instance.configsHash = initResponseDict["configs_hash"] ? initResponseDict["configs_hash"] : "";
                GAState.instance.abId = initResponseDict["ab_id"] ? initResponseDict["ab_id"] : "";
                GAState.instance.abVariantId = initResponseDict["ab_variant_id"] ? initResponseDict["ab_variant_id"] : "";
                GAStore.setItem(GAState.SdkConfigCachedKey, GAUtilities.encode64(JSON.stringify(initResponseDict)));
                GAState.instance.sdkConfigCached = initResponseDict;
                GAState.instance.sdkConfig = initResponseDict;
                GAState.instance.initAuthorized = true;
            }
            else if (initResponse == EGAHTTPApiResponse.Unauthorized) {
                GALogger.w("Initialize SDK failed - Unauthorized");
                GAState.instance.initAuthorized = false;
            }
            else {
                if (initResponse === EGAHTTPApiResponse.NoResponse || initResponse === EGAHTTPApiResponse.RequestTimeout) {
                    GALogger.i("Init call (session start) failed - no response. Could be offline or timeout.");
                }
                else if (initResponse === EGAHTTPApiResponse.BadResponse || initResponse === EGAHTTPApiResponse.JsonEncodeFailed || initResponse === EGAHTTPApiResponse.JsonDecodeFailed) {
                    GALogger.i("Init call (session start) failed - bad response. Could be bad response from proxy or GA servers.");
                }
                else if (initResponse === EGAHTTPApiResponse.BadRequest || initResponse === EGAHTTPApiResponse.UnknownResponseCode) {
                    GALogger.i("Init call (session start) failed - bad request or unknown response.");
                }
                if (GAState.instance.sdkConfig == null) {
                    if (GAState.instance.sdkConfigCached != null) {
                        GALogger.i("Init call (session start) failed - using cached init values.");
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigCached;
                    }
                    else {
                        GALogger.i("Init call (session start) failed - using default init values.");
                        GAState.instance.sdkConfig = GAState.instance.sdkConfigDefault;
                    }
                }
                else {
                    GALogger.i("Init call (session start) failed - using cached init values.");
                }
                GAState.instance.initAuthorized = true;
            }
            GAState.instance.clientServerTimeOffset = GAState.getSdkConfig()["time_offset"] ? GAState.getSdkConfig()["time_offset"] : 0;
            GAState.populateConfigurations(GAState.getSdkConfig());
            if (!GAState.isEnabled()) {
                GALogger.w("Could not start session: SDK is disabled.");
                GAThreading.stopEventQueue();
                return;
            }
            else {
                GAThreading.ensureEventQueueIsRunning();
            }
            var newSessionId = GAUtilities.createGuid();
            GAState.instance.sessionId = newSessionId;
            GAState.instance.sessionStart = GAState.getClientTsAdjusted();
            GAEvents.addSessionStartEvent();
            var timedBlock = GAThreading.getTimedBlockById(GameAnalytics.initTimedBlockId);
            if (timedBlock != null) {
                timedBlock.running = false;
            }
            GameAnalytics.initTimedBlockId = -1;
        };
        GameAnalytics.resumeSessionAndStartQueue = function () {
            if (!GAState.isInitialized()) {
                return;
            }
            GALogger.i("Resuming session.");
            if (!GAState.sessionIsStarted()) {
                GameAnalytics.newSession();
            }
        };
        GameAnalytics.isSdkReady = function (needsInitialized, warn, message) {
            if (warn === void 0) { warn = true; }
            if (message === void 0) { message = ""; }
            if (message) {
                message = message + ": ";
            }
            if (needsInitialized && !GAState.isInitialized()) {
                if (warn) {
                    GALogger.w(message + "SDK is not initialized");
                }
                return false;
            }
            if (needsInitialized && !GAState.isEnabled()) {
                if (warn) {
                    GALogger.w(message + "SDK is disabled");
                }
                return false;
            }
            if (needsInitialized && !GAState.sessionIsStarted()) {
                if (warn) {
                    GALogger.w(message + "Session has not started yet");
                }
                return false;
            }
            return true;
        };
        GameAnalytics.initTimedBlockId = -1;
        GameAnalytics.methodMap = {};
        return GameAnalytics;
    }());
    gameanalytics.GameAnalytics = GameAnalytics;
})(gameanalytics || (gameanalytics = {}));
gameanalytics.GameAnalytics.init();
var GameAnalytics = gameanalytics.GameAnalytics.gaCommand;

//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNyYy9FbnVtcy50cyIsInNyYy9sb2dnaW5nL0dBTG9nZ2VyLnRzIiwic3JjL3V0aWxpdGllcy9HQVV0aWxpdGllcy50cyIsInNyYy92YWxpZGF0b3JzL0dBVmFsaWRhdG9yLnRzIiwic3JjL2RldmljZS9HQURldmljZS50cyIsInNyYy90aHJlYWRpbmcvVGltZWRCbG9jay50cyIsInNyYy90aHJlYWRpbmcvUHJpb3JpdHlRdWV1ZS50cyIsInNyYy9zdG9yZS9HQVN0b3JlLnRzIiwic3JjL3N0YXRlL0dBU3RhdGUudHMiLCJzcmMvdGFza3MvU2RrRXJyb3JUYXNrLnRzIiwic3JjL2h0dHAvR0FIVFRQQXBpLnRzIiwic3JjL2V2ZW50cy9HQUV2ZW50cy50cyIsInNyYy90aHJlYWRpbmcvR0FUaHJlYWRpbmcudHMiLCJzcmMvR2FtZUFuYWx5dGljcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxJQUFPLGFBQWEsQ0FvRG5CO0FBcERELFdBQU8sYUFBYTtJQUVoQixJQUFZLGdCQVFYO0lBUkQsV0FBWSxnQkFBZ0I7UUFFeEIsaUVBQWEsQ0FBQTtRQUNiLHlEQUFTLENBQUE7UUFDVCx1REFBUSxDQUFBO1FBQ1IsNkRBQVcsQ0FBQTtRQUNYLHlEQUFTLENBQUE7UUFDVCwrREFBWSxDQUFBO0lBQ2hCLENBQUMsRUFSVyxnQkFBZ0IsR0FBaEIsOEJBQWdCLEtBQWhCLDhCQUFnQixRQVEzQjtJQUVELElBQVksb0JBTVg7SUFORCxXQUFZLG9CQUFvQjtRQUU1Qix5RUFBYSxDQUFBO1FBQ2IsaUVBQVMsQ0FBQTtRQUNULHVFQUFZLENBQUE7UUFDWiwrREFBUSxDQUFBO0lBQ1osQ0FBQyxFQU5XLG9CQUFvQixHQUFwQixrQ0FBb0IsS0FBcEIsa0NBQW9CLFFBTS9CO0lBRUQsSUFBWSxtQkFLWDtJQUxELFdBQVksbUJBQW1CO1FBRTNCLHVFQUFhLENBQUE7UUFDYixpRUFBVSxDQUFBO1FBQ1YsNkRBQVEsQ0FBQTtJQUNaLENBQUMsRUFMVyxtQkFBbUIsR0FB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QUE7QUFDTCxDQUFDLEVBeHVCTSxhQUFhLEtBQWIsYUFBYSxRQXd1Qm5CO0FBQ0QsYUFBYSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUNuQyxJQUFJLGFBQWEsR0FBRyxhQUFhLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyIsImZpbGUiOiJkaXN0L0dhbWVBbmFseXRpY3MuZGVidWcuanMiLCJzb3VyY2VzQ29udGVudCI6WyJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBlbnVtIEVHQUVycm9yU2V2ZXJpdHlcbiAgICB7XG4gICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgIERlYnVnID0gMSxcbiAgICAgICAgSW5mbyA9IDIsXG4gICAgICAgIFdhcm5pbmcgPSAzLFxuICAgICAgICBFcnJvciA9IDQsXG4gICAgICAgIENyaXRpY2FsID0gNVxuICAgIH1cblxuICAgIGV4cG9ydCBlbnVtIEVHQVByb2dyZXNzaW9uU3RhdHVzXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTdGFydCA9IDEsXG4gICAgICAgIENvbXBsZXRlID0gMixcbiAgICAgICAgRmFpbCA9IDNcbiAgICB9XG5cbiAgICBleHBvcnQgZW51bSBFR0FSZXNvdXJjZUZsb3dUeXBlXG4gICAge1xuICAgICAgICBVbmRlZmluZWQgPSAwLFxuICAgICAgICBTb3VyY2UgPSAxLFxuICAgICAgICBTaW5rID0gMlxuICAgIH1cblxuICAgIGV4cG9ydCBtb2R1bGUgaHR0cFxuICAgIHtcbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU2RrRXJyb3JUeXBlXG4gICAgICAgIHtcbiAgICAgICAgICAgIFVuZGVmaW5lZCA9IDAsXG4gICAgICAgICAgICBSZWplY3RlZCA9IDFcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQUhUVFBBcGlSZXNwb25zZVxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBjbGllbnRcbiAgICAgICAgICAgIE5vUmVzcG9uc2UsXG4gICAgICAgICAgICBCYWRSZXNwb25zZSxcbiAgICAgICAgICAgIFJlcXVlc3RUaW1lb3V0LCAvLyA0MDhcbiAgICAgICAgICAgIEpzb25FbmNvZGVGYWlsZWQsXG4gICAgICAgICAgICBKc29uRGVjb2RlRmFpbGVkLFxuICAgICAgICAgICAgLy8gc2VydmVyXG4gICAgICAgICAgICBJbnRlcm5hbFNlcnZlckVycm9yLFxuICAgICAgICAgICAgQmFkUmVxdWVzdCwgLy8gNDAwXG4gICAgICAgICAgICBVbmF1dGhvcml6ZWQsIC8vIDQwMVxuICAgICAgICAgICAgVW5rbm93blJlc3BvbnNlQ29kZSxcbiAgICAgICAgICAgIE9rLFxuICAgICAgICAgICAgQ3JlYXRlZFxuICAgICAgICB9XG4gICAgfVxufVxudmFyIEVHQUVycm9yU2V2ZXJpdHkgPSBnYW1lYW5hbHl0aWNzLkVHQUVycm9yU2V2ZXJpdHk7XG52YXIgRUdBUHJvZ3Jlc3Npb25TdGF0dXMgPSBnYW1lYW5hbHl0aWNzLkVHQVByb2dyZXNzaW9uU3RhdHVzO1xudmFyIEVHQVJlc291cmNlRmxvd1R5cGUgPSBnYW1lYW5hbHl0aWNzLkVHQVJlc291cmNlRmxvd1R5cGU7XG4iLCIvL0dBTE9HR0VSX1NUQVJUXG5tb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgbG9nZ2luZ1xuICAgIHtcbiAgICAgICAgZW51bSBFR0FMb2dnZXJNZXNzYWdlVHlwZVxuICAgICAgICB7XG4gICAgICAgICAgICBFcnJvciA9IDAsXG4gICAgICAgICAgICBXYXJuaW5nID0gMSxcbiAgICAgICAgICAgIEluZm8gPSAyLFxuICAgICAgICAgICAgRGVidWcgPSAzXG4gICAgICAgIH1cblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FMb2dnZXJcbiAgICAgICAge1xuICAgICAgICAgICAgLy8gRmllbGRzIGFuZCBwcm9wZXJ0aWVzOiBTVEFSVFxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQUxvZ2dlciA9IG5ldyBHQUxvZ2dlcigpO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBpbmZvTG9nVmVyYm9zZUVuYWJsZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGRlYnVnRW5hYmxlZDpib29sZWFuO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgVGFnOnN0cmluZyA9IFwiR2FtZUFuYWx5dGljc1wiO1xuXG4gICAgICAgICAgICAvLyBGaWVsZHMgYW5kIHByb3BlcnRpZXM6IEVORFxuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kZWJ1Z0VuYWJsZWQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNZXRob2RzOiBTVEFSVFxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluZm9Mb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nRW5hYmxlZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldFZlcmJvc2VMb2codmFsdWU6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpKGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBTG9nZ2VyLmluc3RhbmNlLmluZm9Mb2dFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiSW5mby9cIiArIEdBTG9nZ2VyLlRhZyArIFwiOiBcIiArIGZvcm1hdDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pbnN0YW5jZS5zZW5kTm90aWZpY2F0aW9uTWVzc2FnZShtZXNzYWdlLCBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB3KGZvcm1hdDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJXYXJuaW5nL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGUoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbWVzc2FnZTpzdHJpbmcgPSBcIkVycm9yL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkVycm9yKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpaShmb3JtYXQ6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQUxvZ2dlci5pbnN0YW5jZS5pbmZvTG9nVmVyYm9zZUVuYWJsZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIG1lc3NhZ2U6c3RyaW5nID0gXCJWZXJib3NlL1wiICsgR0FMb2dnZXIuVGFnICsgXCI6IFwiICsgZm9ybWF0O1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmluc3RhbmNlLnNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2UsIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkluZm8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGQoZm9ybWF0OnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FMb2dnZXIuZGVidWdFbmFibGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBtZXNzYWdlOnN0cmluZyA9IFwiRGVidWcvXCIgKyBHQUxvZ2dlci5UYWcgKyBcIjogXCIgKyBmb3JtYXQ7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaW5zdGFuY2Uuc2VuZE5vdGlmaWNhdGlvbk1lc3NhZ2UobWVzc2FnZSwgRUdBTG9nZ2VyTWVzc2FnZVR5cGUuRGVidWcpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHNlbmROb3RpZmljYXRpb25NZXNzYWdlKG1lc3NhZ2U6c3RyaW5nLCB0eXBlOkVHQUxvZ2dlck1lc3NhZ2VUeXBlKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh0eXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5FcnJvcjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLldhcm5pbmc6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQUxvZ2dlck1lc3NhZ2VUeXBlLkRlYnVnOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZih0eXBlb2YgY29uc29sZS5kZWJ1ZyA9PT0gXCJmdW5jdGlvblwiKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZGVidWcobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FMb2dnZXJNZXNzYWdlVHlwZS5JbmZvOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ldGhvZHM6IEVORFxuICAgICAgICB9XG4gICAgfVxufVxuLy9HQUxPR0dFUl9FTkRcbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB1dGlsaXRpZXNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FVdGlsaXRpZXNcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRIbWFjKGtleTpzdHJpbmcsIGRhdGE6c3RyaW5nKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGVuY3J5cHRlZE1lc3NhZ2UgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KGRhdGEsIGtleSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHN0cmluZ01hdGNoKHM6c3RyaW5nLCBwYXR0ZXJuOlJlZ0V4cCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighcyB8fCAhcGF0dGVybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcGF0dGVybi50ZXN0KHMpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGpvaW5TdHJpbmdBcnJheSh2OkFycmF5PHN0cmluZz4sIGRlbGltaXRlcjpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwiXCI7XG5cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMCwgaWwgPSB2Lmxlbmd0aDsgaSA8IGlsOyBpKyspXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoaSA+IDApXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSBkZWxpbWl0ZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IHZbaV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhcnJheTpBcnJheTxzdHJpbmc+LCBzZWFyY2g6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChhcnJheS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBzIGluIGFycmF5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoYXJyYXlbc10gPT09IHNlYXJjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBrZXlTdHI6c3RyaW5nID0gXCJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlucHV0ID0gZW5jb2RlVVJJKGlucHV0KTtcbiAgICAgICAgICAgICAgICB2YXIgb3V0cHV0OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIGNocjE6bnVtYmVyLCBjaHIyOm51bWJlciwgY2hyMzpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgIHZhciBlbmMxOm51bWJlciwgZW5jMjpudW1iZXIsIGVuYzM6bnVtYmVyLCBlbmM0Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGkgPSAwO1xuXG4gICAgICAgICAgICAgICAgZG9cbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGlucHV0LmNoYXJDb2RlQXQoaSsrKTtcbiAgICAgICAgICAgICAgICAgICBjaHIyID0gaW5wdXQuY2hhckNvZGVBdChpKyspO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSBpbnB1dC5jaGFyQ29kZUF0KGkrKyk7XG5cbiAgICAgICAgICAgICAgICAgICBlbmMxID0gY2hyMSA+PiAyO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSAoKGNocjEgJiAzKSA8PCA0KSB8IChjaHIyID4+IDQpO1xuICAgICAgICAgICAgICAgICAgIGVuYzMgPSAoKGNocjIgJiAxNSkgPDwgMikgfCAoY2hyMyA+PiA2KTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gY2hyMyAmIDYzO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGlzTmFOKGNocjIpKVxuICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICBlbmMzID0gZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBlbHNlIGlmIChpc05hTihjaHIzKSlcbiAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgZW5jNCA9IDY0O1xuICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMxKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMyKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmMzKSArXG4gICAgICAgICAgICAgICAgICAgICAgR0FVdGlsaXRpZXMua2V5U3RyLmNoYXJBdChlbmM0KTtcbiAgICAgICAgICAgICAgICAgICBjaHIxID0gY2hyMiA9IGNocjMgPSAwO1xuICAgICAgICAgICAgICAgICAgIGVuYzEgPSBlbmMyID0gZW5jMyA9IGVuYzQgPSAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gb3V0cHV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlY29kZTY0KGlucHV0OnN0cmluZyk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBvdXRwdXQ6c3RyaW5nID0gXCJcIjtcbiAgICAgICAgICAgICAgICB2YXIgY2hyMTpudW1iZXIsIGNocjI6bnVtYmVyLCBjaHIzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGVuYzE6bnVtYmVyLCBlbmMyOm51bWJlciwgZW5jMzpudW1iZXIsIGVuYzQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgaSA9IDA7XG5cbiAgICAgICAgICAgICAgICAvLyByZW1vdmUgYWxsIGNoYXJhY3RlcnMgdGhhdCBhcmUgbm90IEEtWiwgYS16LCAwLTksICssIC8sIG9yID1cbiAgICAgICAgICAgICAgICB2YXIgYmFzZTY0dGVzdCA9IC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZztcbiAgICAgICAgICAgICAgICBpZiAoYmFzZTY0dGVzdC5leGVjKGlucHV0KSkge1xuICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJUaGVyZSB3ZXJlIGludmFsaWQgYmFzZTY0IGNoYXJhY3RlcnMgaW4gdGhlIGlucHV0IHRleHQuIFZhbGlkIGJhc2U2NCBjaGFyYWN0ZXJzIGFyZSBBLVosIGEteiwgMC05LCAnKycsICcvJyxhbmQgJz0nLiBFeHBlY3QgZXJyb3JzIGluIGRlY29kaW5nLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaW5wdXQgPSBpbnB1dC5yZXBsYWNlKC9bXkEtWmEtejAtOVxcK1xcL1xcPV0vZywgXCJcIik7XG5cbiAgICAgICAgICAgICAgICBkb1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuICAgICAgICAgICAgICAgICAgIGVuYzIgPSBHQVV0aWxpdGllcy5rZXlTdHIuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSsrKSk7XG4gICAgICAgICAgICAgICAgICAgZW5jMyA9IEdBVXRpbGl0aWVzLmtleVN0ci5pbmRleE9mKGlucHV0LmNoYXJBdChpKyspKTtcbiAgICAgICAgICAgICAgICAgICBlbmM0ID0gR0FVdGlsaXRpZXMua2V5U3RyLmluZGV4T2YoaW5wdXQuY2hhckF0KGkrKykpO1xuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IChlbmMxIDw8IDIpIHwgKGVuYzIgPj4gNCk7XG4gICAgICAgICAgICAgICAgICAgY2hyMiA9ICgoZW5jMiAmIDE1KSA8PCA0KSB8IChlbmMzID4+IDIpO1xuICAgICAgICAgICAgICAgICAgIGNocjMgPSAoKGVuYzMgJiAzKSA8PCA2KSB8IGVuYzQ7XG5cbiAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjEpO1xuXG4gICAgICAgICAgICAgICAgICAgaWYgKGVuYzMgIT0gNjQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBvdXRwdXQgPSBvdXRwdXQgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGNocjIpO1xuICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICBpZiAoZW5jNCAhPSA2NCkge1xuICAgICAgICAgICAgICAgICAgICAgIG91dHB1dCA9IG91dHB1dCArIFN0cmluZy5mcm9tQ2hhckNvZGUoY2hyMyk7XG4gICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgY2hyMSA9IGNocjIgPSBjaHIzID0gMDtcbiAgICAgICAgICAgICAgICAgICBlbmMxID0gZW5jMiA9IGVuYzMgPSBlbmM0ID0gMDtcblxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB3aGlsZSAoaSA8IGlucHV0Lmxlbmd0aCk7XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gZGVjb2RlVVJJKG91dHB1dCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdGltZUludGVydmFsU2luY2UxOTcwKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBkYXRlOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBNYXRoLnJvdW5kKGRhdGUuZ2V0VGltZSgpIC8gMTAwMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgY3JlYXRlR3VpZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItXCIgKyBHQVV0aWxpdGllcy5zNCgpICsgXCItNFwiICsgR0FVdGlsaXRpZXMuczQoKS5zdWJzdHIoMCwzKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIFwiLVwiICsgR0FVdGlsaXRpZXMuczQoKSArIEdBVXRpbGl0aWVzLnM0KCkgKyBHQVV0aWxpdGllcy5zNCgpKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzNCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gKCgoMStNYXRoLnJhbmRvbSgpKSoweDEwMDAwKXwwKS50b1N0cmluZygxNikuc3Vic3RyaW5nKDEpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHZhbGlkYXRvcnNcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FTZGtFcnJvclR5cGU7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBHQVZhbGlkYXRvclxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQnVzaW5lc3NFdmVudChjdXJyZW5jeTpzdHJpbmcsIGFtb3VudDpudW1iZXIsIGNhcnRUeXBlOnN0cmluZywgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbmN5XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1cnJlbmN5KGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGN1cnJlbmN5OiBDYW5ub3QgYmUgKG51bGwpIGFuZCBuZWVkIHRvIGJlIEEtWiwgMyBjaGFyYWN0ZXJzIGFuZCBpbiB0aGUgc3RhbmRhcmQgYXQgb3BlbmV4Y2hhbmdlcmF0ZXMub3JnLiBGYWlsZWQgY3VycmVuY3k6IFwiICsgY3VycmVuY3kpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGFtb3VudCA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBhbW91bnQuIENhbm5vdCBiZSBsZXNzIHRoYW4gMC4gRmFpbGVkIGFtb3VudDogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY2FydFR5cGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoY2FydFR5cGUsIHRydWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gY2FydFR5cGUuIENhbm5vdCBiZSBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBjYXJ0VHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBpdGVtVHlwZSBsZW5ndGhcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gYnVzaW5lc3MgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGl0ZW1UeXBlIGNoYXJzXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbVR5cGU6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgaXRlbVR5cGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgaXRlbUlkXG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBidXNpbmVzcyBldmVudCAtIGl0ZW1JZC4gQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtSWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGJ1c2luZXNzIGV2ZW50IC0gaXRlbUlkOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSwgY3VycmVuY3k6c3RyaW5nLCBhbW91bnQ6bnVtYmVyLCBpdGVtVHlwZTpzdHJpbmcsIGl0ZW1JZDpzdHJpbmcsIGF2YWlsYWJsZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiwgYXZhaWxhYmxlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGZsb3dUeXBlID09IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gZmxvd1R5cGU6IEludmFsaWQgZmxvdyB0eXBlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWN1cnJlbmN5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gY3VycmVuY3k6IENhbm5vdCBiZSAobnVsbClcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUN1cnJlbmNpZXMsIGN1cnJlbmN5KSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGN1cnJlbmN5OiBOb3QgZm91bmQgaW4gbGlzdCBvZiBwcmUtZGVmaW5lZCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcy4gU3RyaW5nOiBcIiArIGN1cnJlbmN5KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIShhbW91bnQgPiAwKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGFtb3VudDogRmxvYXQgYW1vdW50IGNhbm5vdCBiZSAwIG9yIG5lZ2F0aXZlLiBWYWx1ZTogXCIgKyBhbW91bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghaXRlbVR5cGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKGl0ZW1UeXBlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1UeXBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0Q2hhcmFjdGVycyhpdGVtVHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcmVzb3VyY2UgZXZlbnQgLSBpdGVtVHlwZTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZUl0ZW1UeXBlcywgaXRlbVR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHJlc291cmNlIGV2ZW50IC0gaXRlbVR5cGU6IE5vdCBmb3VuZCBpbiBsaXN0IG9mIHByZS1kZWZpbmVkIGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtVHlwZXMuIFN0cmluZzogXCIgKyBpdGVtVHlwZSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydExlbmd0aChpdGVtSWQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIGl0ZW1JZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMoaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSByZXNvdXJjZSBldmVudCAtIGl0ZW1JZDogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBpdGVtSWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiBJbnZhbGlkIHByb2dyZXNzaW9uIHN0YXR1cy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBNYWtlIHN1cmUgcHJvZ3Jlc3Npb25zIGFyZSBkZWZpbmVkIGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMyAmJiAhKHByb2dyZXNzaW9uMDIgfHwgIXByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50OiAwMyBmb3VuZCBidXQgMDErMDIgYXJlIGludmFsaWQuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKHByb2dyZXNzaW9uMDIgJiYgIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IDAyIGZvdW5kIGJ1dCBub3QgMDEuIFByb2dyZXNzaW9uIG11c3QgYmUgc2V0IGFzIGVpdGhlciAwMSwgMDErMDIgb3IgMDErMDIrMDNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoIXByb2dyZXNzaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQ6IHByb2dyZXNzaW9uMDEgbm90IHZhbGlkLiBQcm9ncmVzc2lvbnMgbXVzdCBiZSBzZXQgYXMgZWl0aGVyIDAxLCAwMSswMiBvciAwMSswMiswM1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDEgKHJlcXVpcmVkKVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGJlIChudWxsKSwgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHByb2dyZXNzaW9uIGV2ZW50IC0gcHJvZ3Jlc3Npb24wMTogQ2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZzogXCIgKyBwcm9ncmVzc2lvbjAxKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBwcm9ncmVzc2lvbjAyXG4gICAgICAgICAgICAgICAgaWYgKHByb2dyZXNzaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRQYXJ0TGVuZ3RoKHByb2dyZXNzaW9uMDIsIHRydWUpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgYmUgZW1wdHkgb3IgYWJvdmUgNjQgY2hhcmFjdGVycy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKHByb2dyZXNzaW9uMDIpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gcHJvZ3Jlc3Npb24gZXZlbnQgLSBwcm9ncmVzc2lvbjAyOiBDYW5ub3QgY29udGFpbiBvdGhlciBjaGFyYWN0ZXJzIHRoYW4gQS16LCAwLTksIC1fLiwgKCkhPy4gU3RyaW5nOiBcIiArIHByb2dyZXNzaW9uMDIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHByb2dyZXNzaW9uMDNcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudFBhcnRMZW5ndGgocHJvZ3Jlc3Npb24wMywgdHJ1ZSkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBiZSBlbXB0eSBvciBhYm92ZSA2NCBjaGFyYWN0ZXJzLiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJWYWxpZGF0aW9uIGZhaWwgLSBwcm9ncmVzc2lvbiBldmVudCAtIHByb2dyZXNzaW9uMDM6IENhbm5vdCBjb250YWluIG90aGVyIGNoYXJhY3RlcnMgdGhhbiBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgcHJvZ3Jlc3Npb24wMyk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEZXNpZ25FdmVudChldmVudElkOnN0cmluZywgdmFsdWU6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFdmVudElkTGVuZ3RoKGV2ZW50SWQpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGRlc2lnbiBldmVudCAtIGV2ZW50SWQ6IENhbm5vdCBiZSAobnVsbCkgb3IgZW1wdHkuIE9ubHkgNSBldmVudCBwYXJ0cyBhbGxvd2VkIHNlcGVyYXRlZCBieSA6LiBFYWNoIHBhcnQgbmVlZCB0byBiZSAzMiBjaGFyYWN0ZXJzIG9yIGxlc3MuIFN0cmluZzogXCIgKyBldmVudElkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZGVzaWduIGV2ZW50IC0gZXZlbnRJZDogTm9uIHZhbGlkIGNoYXJhY3RlcnMuIE9ubHkgYWxsb3dlZCBBLXosIDAtOSwgLV8uLCAoKSE/LiBTdHJpbmc6IFwiICsgZXZlbnRJZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsdWU6IGFsbG93IDAsIG5lZ2F0aXZlIGFuZCBuaWwgKG5vdCByZXF1aXJlZClcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKHNldmVyaXR5ID09IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIGVycm9yIGV2ZW50IC0gc2V2ZXJpdHk6IFNldmVyaXR5IHdhcyB1bnN1cHBvcnRlZCB2YWx1ZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUxvbmdTdHJpbmcobWVzc2FnZSwgdHJ1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gZXJyb3IgZXZlbnQgLSBtZXNzYWdlOiBNZXNzYWdlIGNhbm5vdCBiZSBhYm92ZSA4MTkyIGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHR5cGUgPT09IEVHQVNka0Vycm9yVHlwZS5VbmRlZmluZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiVmFsaWRhdGlvbiBmYWlsIC0gc2RrIGVycm9yIGV2ZW50IC0gdHlwZTogVHlwZSB3YXMgdW5zdXBwb3J0ZWQgdmFsdWUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlS2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVLZXksIC9eW0EtejAtOV17MzJ9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGdhbWVTZWNyZXQsIC9eW0EtejAtOV17NDB9JC8pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDdXJyZW5jeShjdXJyZW5jeTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFjdXJyZW5jeSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChjdXJyZW5jeSwgL15bQS1aXXszfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRMZW5ndGgoZXZlbnRQYXJ0OnN0cmluZywgYWxsb3dOdWxsOmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKGFsbG93TnVsbCAmJiAhZXZlbnRQYXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFldmVudFBhcnQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50UGFydC5sZW5ndGggPiA2NClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFdmVudFBhcnRDaGFyYWN0ZXJzKGV2ZW50UGFydDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaChldmVudFBhcnQsIC9eW0EtWmEtejAtOVxcc1xcLV9cXC5cXChcXClcXCFcXD9dezEsNjR9JC8pKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUV2ZW50SWRMZW5ndGgoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bXjpdezEsNjR9KD86OlteOl17MSw2NH0pezAsNH0kLykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRXZlbnRJZENoYXJhY3RlcnMoZXZlbnRJZDpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFldmVudElkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnRJZCwgL15bQS1aYS16MC05XFxzXFwtX1xcLlxcKFxcKVxcIVxcP117MSw2NH0oOltBLVphLXowLTlcXHNcXC1fXFwuXFwoXFwpXFwhXFw/XXsxLDY0fSl7MCw0fSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVBbmRDbGVhbkluaXRSZXF1ZXN0UmVzcG9uc2UoaW5pdFJlc3BvbnNlOntba2V5OnN0cmluZ106IGFueX0sIGNvbmZpZ3NDcmVhdGVkOmJvb2xlYW4pOiB7W2tleTpzdHJpbmddOiBhbnl9XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gbWFrZSBzdXJlIHdlIGhhdmUgYSB2YWxpZCBkaWN0XG4gICAgICAgICAgICAgICAgaWYgKGluaXRSZXNwb25zZSA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBubyByZXNwb25zZSBkaWN0aW9uYXJ5LlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRlZERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgc2VydmVyX3RzXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyVHNOdW1iZXI6bnVtYmVyID0gaW5pdFJlc3BvbnNlW1wic2VydmVyX3RzXCJdO1xuICAgICAgICAgICAgICAgICAgICBpZiAoc2VydmVyVHNOdW1iZXIgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWxpZGF0ZWREaWN0W1wic2VydmVyX3RzXCJdID0gc2VydmVyVHNOdW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdmFsdWUgaW4gJ3NlcnZlcl90cycgZmllbGQuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnc2VydmVyX3RzJyBmaWVsZC4gdHlwZT1cIiArIHR5cGVvZiBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJzZXJ2ZXJfdHNcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoY29uZmlnc0NyZWF0ZWQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjb25maWdzIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29uZmlndXJhdGlvbnM6YW55W10gPSBpbml0UmVzcG9uc2VbXCJjb25maWdzXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImNvbmZpZ3NcIl0gPSBjb25maWd1cmF0aW9ucztcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcInZhbGlkYXRlSW5pdFJlcXVlc3RSZXNwb25zZSBmYWlsZWQgLSBpbnZhbGlkIHR5cGUgaW4gJ2NvbmZpZ3MnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImNvbmZpZ3NcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJjb25maWdzXCJdICsgXCIsIFwiICsgZSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29uZmlnc19oYXNoOnN0cmluZyA9IGluaXRSZXNwb25zZVtcImNvbmZpZ3NfaGFzaFwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbGlkYXRlZERpY3RbXCJjb25maWdzX2hhc2hcIl0gPSBjb25maWdzX2hhc2g7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdjb25maWdzX2hhc2gnIGZpZWxkLiB0eXBlPVwiICsgdHlwZW9mIGluaXRSZXNwb25zZVtcImNvbmZpZ3NfaGFzaFwiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImNvbmZpZ3NfaGFzaFwiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBhYl9pZCBmaWVsZFxuICAgICAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGFiX2lkOnN0cmluZyA9IGluaXRSZXNwb25zZVtcImFiX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImFiX2lkXCJdID0gYWJfaWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUluaXRSZXF1ZXN0UmVzcG9uc2UgZmFpbGVkIC0gaW52YWxpZCB0eXBlIGluICdhYl9pZCcgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiYWJfaWRcIl0gKyBcIiwgdmFsdWU9XCIgKyBpbml0UmVzcG9uc2VbXCJhYl9pZFwiXSArIFwiLCBcIiArIGUpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBhYl92YXJpYW50X2lkIGZpZWxkXG4gICAgICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYWJfdmFyaWFudF9pZDpzdHJpbmcgPSBpbml0UmVzcG9uc2VbXCJhYl92YXJpYW50X2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsaWRhdGVkRGljdFtcImFiX3ZhcmlhbnRfaWRcIl0gPSBhYl92YXJpYW50X2lkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwidmFsaWRhdGVJbml0UmVxdWVzdFJlc3BvbnNlIGZhaWxlZCAtIGludmFsaWQgdHlwZSBpbiAnYWJfdmFyaWFudF9pZCcgZmllbGQuIHR5cGU9XCIgKyB0eXBlb2YgaW5pdFJlc3BvbnNlW1wiYWJfdmFyaWFudF9pZFwiXSArIFwiLCB2YWx1ZT1cIiArIGluaXRSZXNwb25zZVtcImFiX3ZhcmlhbnRfaWRcIl0gKyBcIiwgXCIgKyBlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG5cbiAgICAgICAgICAgICAgICByZXR1cm4gdmFsaWRhdGVkRGljdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUJ1aWxkKGJ1aWxkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2hvcnRTdHJpbmcoYnVpbGQsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTZGtXcmFwcGVyVmVyc2lvbih3cmFwcGVyVmVyc2lvbjpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdNYXRjaCh3cmFwcGVyVmVyc2lvbiwgL14odW5pdHl8dW5yZWFsfGdhbWVtYWtlcnxjb2NvczJkfGNvbnN0cnVjdHxkZWZvbGQpIFswLTldezAsNX0oXFwuWzAtOV17MCw1fSl7MCwyfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVFbmdpbmVWZXJzaW9uKGVuZ2luZVZlcnNpb246c3RyaW5nKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghZW5naW5lVmVyc2lvbiB8fCAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZW5naW5lVmVyc2lvbiwgL14odW5pdHl8dW5yZWFsfGdhbWVtYWtlcnxjb2NvczJkfGNvbnN0cnVjdHxkZWZvbGQpIFswLTldezAsNX0oXFwuWzAtOV17MCw1fSl7MCwyfSQvKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVVc2VySWQodUlkOnN0cmluZyk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU3RyaW5nKHVJZCwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlZhbGlkYXRpb24gZmFpbCAtIHVzZXIgaWQ6IGlkIGNhbm5vdCBiZSAobnVsbCksIGVtcHR5IG9yIGFib3ZlIDY0IGNoYXJhY3RlcnMuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlU2hvcnRTdHJpbmcoc2hvcnRTdHJpbmc6c3RyaW5nLCBjYW5CZUVtcHR5OmJvb2xlYW4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gU3RyaW5nIGlzIGFsbG93ZWQgdG8gYmUgZW1wdHkgb3IgbmlsXG4gICAgICAgICAgICAgICAgaWYgKGNhbkJlRW1wdHkgJiYgIXNob3J0U3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFzaG9ydFN0cmluZyB8fCBzaG9ydFN0cmluZy5sZW5ndGggPiAzMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVTdHJpbmcoczpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eSBvciBuaWxcbiAgICAgICAgICAgICAgICBpZiAoY2FuQmVFbXB0eSAmJiAhcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmICghcyB8fCBzLmxlbmd0aCA+IDY0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUxvbmdTdHJpbmcobG9uZ1N0cmluZzpzdHJpbmcsIGNhbkJlRW1wdHk6Ym9vbGVhbik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBTdHJpbmcgaXMgYWxsb3dlZCB0byBiZSBlbXB0eVxuICAgICAgICAgICAgICAgIGlmIChjYW5CZUVtcHR5ICYmICFsb25nU3RyaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKCFsb25nU3RyaW5nIHx8IGxvbmdTdHJpbmcubGVuZ3RoID4gODE5MilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVDb25uZWN0aW9uVHlwZShjb25uZWN0aW9uVHlwZTpzdHJpbmcpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKGNvbm5lY3Rpb25UeXBlLCAvXih3d2FufHdpZml8bGFufG9mZmxpbmUpJC8pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyhjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDMyLCBmYWxzZSwgXCJjdXN0b20gZGltZW5zaW9uc1wiLCBjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQXJyYXlPZlN0cmluZ3MoMjAsIDY0LCBmYWxzZSwgXCJyZXNvdXJjZSBjdXJyZW5jaWVzXCIsIHJlc291cmNlQ3VycmVuY2llcykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgZWFjaCBzdHJpbmcgZm9yIHJlZ2V4XG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXNvdXJjZUN1cnJlbmNpZXMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ01hdGNoKHJlc291cmNlQ3VycmVuY2llc1tpXSwgL15bQS1aYS16XSskLykpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJyZXNvdXJjZSBjdXJyZW5jaWVzIHZhbGlkYXRpb24gZmFpbGVkOiBhIHJlc291cmNlIGN1cnJlbmN5IGNhbiBvbmx5IGJlIEEtWiwgYS16LiBTdHJpbmcgd2FzOiBcIiArIHJlc291cmNlQ3VycmVuY2llc1tpXSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVSZXNvdXJjZUl0ZW1UeXBlcyhyZXNvdXJjZUl0ZW1UeXBlczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVBcnJheU9mU3RyaW5ncygyMCwgMzIsIGZhbHNlLCBcInJlc291cmNlIGl0ZW0gdHlwZXNcIiwgcmVzb3VyY2VJdGVtVHlwZXMpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGVhY2ggcmVzb3VyY2VJdGVtVHlwZSBmb3IgZXZlbnRwYXJ0IHZhbGlkYXRpb25cbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc291cmNlSXRlbVR5cGVzLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUV2ZW50UGFydENoYXJhY3RlcnMocmVzb3VyY2VJdGVtVHlwZXNbaV0pKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwicmVzb3VyY2UgaXRlbSB0eXBlcyB2YWxpZGF0aW9uIGZhaWxlZDogYSByZXNvdXJjZSBpdGVtIHR5cGUgY2Fubm90IGNvbnRhaW4gb3RoZXIgY2hhcmFjdGVycyB0aGFuIEEteiwgMC05LCAtXy4sICgpIT8uIFN0cmluZyB3YXM6IFwiICsgcmVzb3VyY2VJdGVtVHlwZXNbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlRGltZW5zaW9uMDEoZGltZW5zaW9uMDE6c3RyaW5nLCBhdmFpbGFibGVEaW1lbnNpb25zOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gYWxsb3cgbmlsXG4gICAgICAgICAgICAgICAgaWYgKCFkaW1lbnNpb24wMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIUdBVXRpbGl0aWVzLnN0cmluZ0FycmF5Q29udGFpbnNTdHJpbmcoYXZhaWxhYmxlRGltZW5zaW9ucywgZGltZW5zaW9uMDEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbjAyOnN0cmluZywgYXZhaWxhYmxlRGltZW5zaW9uczpBcnJheTxzdHJpbmc+KTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGFsbG93IG5pbFxuICAgICAgICAgICAgICAgIGlmICghZGltZW5zaW9uMDIpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVV0aWxpdGllcy5zdHJpbmdBcnJheUNvbnRhaW5zU3RyaW5nKGF2YWlsYWJsZURpbWVuc2lvbnMsIGRpbWVuc2lvbjAyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgdmFsaWRhdGVEaW1lbnNpb24wMyhkaW1lbnNpb24wMzpzdHJpbmcsIGF2YWlsYWJsZURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPik6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBhbGxvdyBuaWxcbiAgICAgICAgICAgICAgICBpZiAoIWRpbWVuc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FVdGlsaXRpZXMuc3RyaW5nQXJyYXlDb250YWluc1N0cmluZyhhdmFpbGFibGVEaW1lbnNpb25zLCBkaW1lbnNpb24wMykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQXJyYXlPZlN0cmluZ3MobWF4Q291bnQ6bnVtYmVyLCBtYXhTdHJpbmdMZW5ndGg6bnVtYmVyLCBhbGxvd05vVmFsdWVzOmJvb2xlYW4sIGxvZ1RhZzpzdHJpbmcsIGFycmF5T2ZTdHJpbmdzOkFycmF5PHN0cmluZz4pOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGFycmF5VGFnOnN0cmluZyA9IGxvZ1RhZztcblxuICAgICAgICAgICAgICAgIC8vIHVzZSBhcnJheVRhZyB0byBhbm5vdGF0ZSB3YXJuaW5nIGxvZ1xuICAgICAgICAgICAgICAgIGlmICghYXJyYXlUYWcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhcnJheVRhZyA9IFwiQXJyYXlcIjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZighYXJyYXlPZlN0cmluZ3MpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KGFycmF5VGFnICsgXCIgdmFsaWRhdGlvbiBmYWlsZWQ6IGFycmF5IGNhbm5vdCBiZSBudWxsLiBcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBlbXB0eVxuICAgICAgICAgICAgICAgIGlmIChhbGxvd05vVmFsdWVzID09IGZhbHNlICYmIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgYmUgZW1wdHkuIFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGV4Y2VlZGluZyBtYXggY291bnRcbiAgICAgICAgICAgICAgICBpZiAobWF4Q291bnQgPiAwICYmIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCA+IG1heENvdW50KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBhcnJheSBjYW5ub3QgZXhjZWVkIFwiICsgbWF4Q291bnQgKyBcIiB2YWx1ZXMuIEl0IGhhcyBcIiArIGFycmF5T2ZTdHJpbmdzLmxlbmd0aCArIFwiIHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBlYWNoIHN0cmluZ1xuICAgICAgICAgICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYXJyYXlPZlN0cmluZ3MubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc3RyaW5nTGVuZ3RoOm51bWJlciA9ICFhcnJheU9mU3RyaW5nc1tpXSA/IDAgOiBhcnJheU9mU3RyaW5nc1tpXS5sZW5ndGg7XG4gICAgICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIGVtcHR5IChub3QgYWxsb3dlZClcbiAgICAgICAgICAgICAgICAgICAgaWYgKHN0cmluZ0xlbmd0aCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhhcnJheVRhZyArIFwiIHZhbGlkYXRpb24gZmFpbGVkOiBjb250YWluZWQgYW4gZW1wdHkgc3RyaW5nLiBBcnJheT1cIiArIEpTT04uc3RyaW5naWZ5KGFycmF5T2ZTdHJpbmdzKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBleGNlZWRpbmcgbWF4IGxlbmd0aFxuICAgICAgICAgICAgICAgICAgICBpZiAobWF4U3RyaW5nTGVuZ3RoID4gMCAmJiBzdHJpbmdMZW5ndGggPiBtYXhTdHJpbmdMZW5ndGgpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoYXJyYXlUYWcgKyBcIiB2YWxpZGF0aW9uIGZhaWxlZDogYSBzdHJpbmcgZXhjZWVkZWQgbWF4IGFsbG93ZWQgbGVuZ3RoICh3aGljaCBpczogXCIgKyBtYXhTdHJpbmdMZW5ndGggKyBcIikuIFN0cmluZyB3YXM6IFwiICsgYXJyYXlPZlN0cmluZ3NbaV0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHZhbGlkYXRlQ2xpZW50VHMoY2xpZW50VHM6bnVtYmVyKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChjbGllbnRUcyA8ICgtNDI5NDk2NzI5NSsxKSB8fCBjbGllbnRUcyA+ICg0Mjk0OTY3Mjk1LTEpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBkZXZpY2VcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgTmFtZVZhbHVlVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmFsdWU6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHZlcnNpb246c3RyaW5nO1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IobmFtZTpzdHJpbmcsIHZhbHVlOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZhbHVlID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gdmVyc2lvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBOYW1lVmVyc2lvblxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgbmFtZTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgdmVyc2lvbjpzdHJpbmc7XG5cbiAgICAgICAgICAgIHB1YmxpYyBjb25zdHJ1Y3RvcihuYW1lOnN0cmluZywgdmVyc2lvbjpzdHJpbmcpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5uYW1lID0gbmFtZTtcbiAgICAgICAgICAgICAgICB0aGlzLnZlcnNpb24gPSB2ZXJzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBRGV2aWNlXG4gICAgICAgIHtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IHNka1dyYXBwZXJWZXJzaW9uOnN0cmluZyA9IFwiamF2YXNjcmlwdCA0LjAuN1wiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgb3NWZXJzaW9uUGFpcjpOYW1lVmVyc2lvbiA9IEdBRGV2aWNlLm1hdGNoSXRlbShbXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnBsYXRmb3JtLFxuICAgICAgICAgICAgICAgIG5hdmlnYXRvci51c2VyQWdlbnQsXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLmFwcFZlcnNpb24sXG4gICAgICAgICAgICAgICAgbmF2aWdhdG9yLnZlbmRvclxuICAgICAgICAgICAgXS5qb2luKCcgJyksIFtcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIndpbmRvd3NfcGhvbmVcIiwgXCJXaW5kb3dzIFBob25lXCIsIFwiT1NcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJ3aW5kb3dzXCIsIFwiV2luXCIsIFwiTlRcIiksXG4gICAgICAgICAgICAgICAgbmV3IE5hbWVWYWx1ZVZlcnNpb24oXCJpb3NcIiwgXCJpUGhvbmVcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQYWRcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImlvc1wiLCBcImlQb2RcIiwgXCJPU1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImFuZHJvaWRcIiwgXCJBbmRyb2lkXCIsIFwiQW5kcm9pZFwiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcImJsYWNrQmVycnlcIiwgXCJCbGFja0JlcnJ5XCIsIFwiL1wiKSxcbiAgICAgICAgICAgICAgICBuZXcgTmFtZVZhbHVlVmVyc2lvbihcIm1hY19vc3hcIiwgXCJNYWNcIiwgXCJPUyBYXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwidGl6ZW5cIiwgXCJUaXplblwiLCBcIlRpemVuXCIpLFxuICAgICAgICAgICAgICAgIG5ldyBOYW1lVmFsdWVWZXJzaW9uKFwibGludXhcIiwgXCJMaW51eFwiLCBcInJ2XCIpXG4gICAgICAgICAgICBdKTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBidWlsZFBsYXRmb3JtOnN0cmluZyA9IEdBRGV2aWNlLnJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1vZGVsOnN0cmluZyA9IEdBRGV2aWNlLmdldERldmljZU1vZGVsKCk7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IGRldmljZU1hbnVmYWN0dXJlcjpzdHJpbmcgPSBHQURldmljZS5nZXREZXZpY2VNYW51ZmFjdHVyZXIoKTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgb3NWZXJzaW9uOnN0cmluZyA9IEdBRGV2aWNlLmdldE9TVmVyc2lvblN0cmluZygpO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBicm93c2VyVmVyc2lvbjpzdHJpbmcgPSBHQURldmljZS5nZXRCcm93c2VyVmVyc2lvblN0cmluZygpO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNka0dhbWVFbmdpbmVWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY29ubmVjdGlvblR5cGU6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgbWF4U2FmZUludGVnZXI6bnVtYmVyID0gTWF0aC5wb3coMiwgNTMpIC0gMTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB0b3VjaCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVsZXZhbnRTZGtWZXJzaW9uKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FEZXZpY2Uuc2RrV3JhcHBlclZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q29ubmVjdGlvblR5cGUoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihuYXZpZ2F0b3Iub25MaW5lKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYoR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybSA9PT0gXCJpb3NcIiB8fCBHQURldmljZS5idWlsZFBsYXRmb3JtID09PSBcImFuZHJvaWRcIilcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FEZXZpY2UuY29ubmVjdGlvblR5cGUgPSBcInd3YW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRGV2aWNlLmNvbm5lY3Rpb25UeXBlID0gXCJsYW5cIjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAvLyBUT0RPOiBEZXRlY3Qgd2lmaSB1c2FnZVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQURldmljZS5jb25uZWN0aW9uVHlwZSA9IFwib2ZmbGluZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0T1NWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5idWlsZFBsYXRmb3JtICsgXCIgXCIgKyBHQURldmljZS5vc1ZlcnNpb25QYWlyLnZlcnNpb247XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1bnRpbWVQbGF0Zm9ybVRvU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQURldmljZS5vc1ZlcnNpb25QYWlyLm5hbWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldEJyb3dzZXJWZXJzaW9uU3RyaW5nKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB1YTpzdHJpbmcgPSBuYXZpZ2F0b3IudXNlckFnZW50O1xuICAgICAgICAgICAgICAgIHZhciB0ZW06UmVnRXhwTWF0Y2hBcnJheTtcbiAgICAgICAgICAgICAgICB2YXIgTTpSZWdFeHBNYXRjaEFycmF5ID0gdWEubWF0Y2goLyhvcGVyYXxjaHJvbWV8c2FmYXJpfGZpcmVmb3h8dWJyb3dzZXJ8bXNpZXx0cmlkZW50fGZiYXYoPz1cXC8pKVxcLz9cXHMqKFxcZCspL2kpIHx8IFtdO1xuXG4gICAgICAgICAgICAgICAgaWYoTS5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm0gPT09IFwiaW9zXCIpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIndlYmtpdF9cIiArIEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKC90cmlkZW50L2kudGVzdChNWzFdKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRlbSA9IC9cXGJydlsgOl0rKFxcZCspL2cuZXhlYyh1YSkgfHwgW107XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAnSUUgJyArICh0ZW1bMV0gfHwgJycpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKE1bMV0gPT09ICdDaHJvbWUnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdGVtID0gdWEubWF0Y2goL1xcYihPUFJ8RWRnZXxVQnJvd3NlcilcXC8oXFxkKykvKTtcbiAgICAgICAgICAgICAgICAgICAgaWYodGVtIT0gbnVsbClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRlbS5zbGljZSgxKS5qb2luKCcgJykucmVwbGFjZSgnT1BSJywgJ09wZXJhJykucmVwbGFjZSgnVUJyb3dzZXInLCAnVUMnKS50b0xvd2VyQ2FzZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoTVsxXSAmJiBNWzFdLnRvTG93ZXJDYXNlKCkgPT09ICdmYmF2JylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIE1bMV0gPSBcImZhY2Vib29rXCI7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoTVsyXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZmFjZWJvb2sgXCIgKyBNWzJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIE1TdHJpbmc6c3RyaW5nW10gPSBNWzJdPyBbTVsxXSwgTVsyXV06IFtuYXZpZ2F0b3IuYXBwTmFtZSwgbmF2aWdhdG9yLmFwcFZlcnNpb24sICctPyddO1xuXG4gICAgICAgICAgICAgICAgaWYoKHRlbSA9IHVhLm1hdGNoKC92ZXJzaW9uXFwvKFxcZCspL2kpKSAhPSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgTVN0cmluZy5zcGxpY2UoMSwgMSwgdGVtWzFdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gTVN0cmluZy5qb2luKCcgJykudG9Mb3dlckNhc2UoKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTW9kZWwoKTpzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OnN0cmluZyA9IFwidW5rbm93blwiO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0RGV2aWNlTWFudWZhY3R1cmVyKCk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpzdHJpbmcgPSBcInVua25vd25cIjtcblxuICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIG1hdGNoSXRlbShhZ2VudDpzdHJpbmcsIGRhdGE6QXJyYXk8TmFtZVZhbHVlVmVyc2lvbj4pOk5hbWVWZXJzaW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpOYW1lVmVyc2lvbiA9IG5ldyBOYW1lVmVyc2lvbihcInVua25vd25cIiwgXCIwLjAuMFwiKTtcblxuICAgICAgICAgICAgICAgIHZhciBpOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgdmFyIGo6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICB2YXIgcmVnZXg6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciByZWdleHY6UmVnRXhwO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaDpib29sZWFuO1xuICAgICAgICAgICAgICAgIHZhciBtYXRjaGVzOlJlZ0V4cE1hdGNoQXJyYXk7XG4gICAgICAgICAgICAgICAgdmFyIG1hdGhjZXNSZXN1bHQ6c3RyaW5nO1xuICAgICAgICAgICAgICAgIHZhciB2ZXJzaW9uOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGZvciAoaSA9IDA7IGkgPCBkYXRhLmxlbmd0aDsgaSArPSAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVnZXggPSBuZXcgUmVnRXhwKGRhdGFbaV0udmFsdWUsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgIG1hdGNoID0gcmVnZXgudGVzdChhZ2VudCk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmVnZXh2ID0gbmV3IFJlZ0V4cChkYXRhW2ldLnZlcnNpb24gKyAnWy0gLzo7XShbXFxcXGQuX10rKScsICdpJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBtYXRjaGVzID0gYWdlbnQubWF0Y2gocmVnZXh2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZlcnNpb24gPSAnJztcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChtYXRjaGVzWzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWF0aGNlc1Jlc3VsdCA9IG1hdGNoZXNbMV07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKG1hdGhjZXNSZXN1bHQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1hdGNoZXNBcnJheTpzdHJpbmdbXSA9IG1hdGhjZXNSZXN1bHQuc3BsaXQoL1suX10rLyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gMDsgaiA8IE1hdGgubWluKG1hdGNoZXNBcnJheS5sZW5ndGgsIDMpOyBqICs9IDEpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uICs9IG1hdGNoZXNBcnJheVtqXSArIChqIDwgTWF0aC5taW4obWF0Y2hlc0FycmF5Lmxlbmd0aCwgMykgLSAxID8gJy4nIDogJycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJzaW9uID0gJzAuMC4wJztcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lm5hbWUgPSBkYXRhW2ldLm5hbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQudmVyc2lvbiA9IHZlcnNpb247XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICDCoMKgwqDCoMKgwqDCoMKgfVxuICAgICAgICAgICAgwqDCoMKgwqB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgZXhwb3J0IGNsYXNzIFRpbWVkQmxvY2tcbiAgICAgICAge1xuICAgICAgICAgICAgcHVibGljIHJlYWRvbmx5IGRlYWRsaW5lOkRhdGU7XG4gICAgICAgICAgICBwdWJsaWMgYmxvY2s6KCkgPT4gdm9pZDtcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBpZDpudW1iZXI7XG4gICAgICAgICAgICBwdWJsaWMgaWdub3JlOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgYXN5bmM6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBydW5uaW5nOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBpZENvdW50ZXI6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgcHVibGljIGNvbnN0cnVjdG9yKGRlYWRsaW5lOkRhdGUpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5kZWFkbGluZSA9IGRlYWRsaW5lO1xuICAgICAgICAgICAgICAgIHRoaXMuaWdub3JlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgdGhpcy5hc3luYyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHRoaXMucnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHRoaXMuaWQgPSArK1RpbWVkQmxvY2suaWRDb3VudGVyO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHRocmVhZGluZ1xuICAgIHtcbiAgICAgICAgZXhwb3J0IGludGVyZmFjZSBJQ29tcGFyZXI8VD5cbiAgICAgICAge1xuICAgICAgICAgICAgY29tcGFyZSh4OlQsIHk6VCk6IG51bWJlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIGV4cG9ydCBjbGFzcyBQcmlvcml0eVF1ZXVlPFRJdGVtPlxuICAgICAgICB7XG4gICAgICAgICAgICBwdWJsaWMgX3N1YlF1ZXVlczp7W2tleTpudW1iZXJdOiBBcnJheTxUSXRlbT59O1xuICAgICAgICAgICAgcHVibGljIF9zb3J0ZWRLZXlzOkFycmF5PG51bWJlcj47XG4gICAgICAgICAgICBwcml2YXRlIGNvbXBhcmVyOklDb21wYXJlcjxudW1iZXI+O1xuXG4gICAgICAgICAgICBwdWJsaWMgY29uc3RydWN0b3IocHJpb3JpdHlDb21wYXJlcjpJQ29tcGFyZXI8bnVtYmVyPilcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLmNvbXBhcmVyID0gcHJpb3JpdHlDb21wYXJlcjtcbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXMgPSB7fTtcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzID0gW107XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBlbnF1ZXVlKHByaW9yaXR5Om51bWJlciwgaXRlbTpUSXRlbSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih0aGlzLl9zb3J0ZWRLZXlzLmluZGV4T2YocHJpb3JpdHkpID09PSAtMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuYWRkUXVldWVPZlByaW9yaXR5KHByaW9yaXR5KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0aGlzLl9zdWJRdWV1ZXNbcHJpb3JpdHldLnB1c2goaXRlbSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYWRkUXVldWVPZlByaW9yaXR5KHByaW9yaXR5Om51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnB1c2gocHJpb3JpdHkpO1xuICAgICAgICAgICAgICAgIHRoaXMuX3NvcnRlZEtleXMuc29ydCgoeDpudW1iZXIsIHk6bnVtYmVyKSA9PiB0aGlzLmNvbXBhcmVyLmNvbXBhcmUoeCwgeSkpO1xuICAgICAgICAgICAgICAgIHRoaXMuX3N1YlF1ZXVlc1twcmlvcml0eV0gPSBbXTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHBlZWsoKTogVEl0ZW1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih0aGlzLmhhc0l0ZW1zKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5fc3ViUXVldWVzW3RoaXMuX3NvcnRlZEtleXNbMF1dWzBdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgcXVldWUgaXMgZW1wdHlcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgaGFzSXRlbXMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLl9zb3J0ZWRLZXlzLmxlbmd0aCA+IDA7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBkZXF1ZXVlKCk6IFRJdGVtXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5oYXNJdGVtcygpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuZGVxdWV1ZUZyb21IaWdoUHJpb3JpdHlRdWV1ZSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUaGUgcXVldWUgaXMgZW1wdHlcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGRlcXVldWVGcm9tSGlnaFByaW9yaXR5UXVldWUoKTogVEl0ZW1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RLZXk6bnVtYmVyID0gdGhpcy5fc29ydGVkS2V5c1swXTtcbiAgICAgICAgICAgICAgICB2YXIgbmV4dEl0ZW06VEl0ZW0gPSB0aGlzLl9zdWJRdWV1ZXNbZmlyc3RLZXldLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgaWYodGhpcy5fc3ViUXVldWVzW2ZpcnN0S2V5XS5sZW5ndGggPT09IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLl9zb3J0ZWRLZXlzLnNoaWZ0KCk7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSB0aGlzLl9zdWJRdWV1ZXNbZmlyc3RLZXldO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBuZXh0SXRlbTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSBzdG9yZVxuICAgIHtcbiAgICAgICAgaW1wb3J0IEdBTG9nZ2VyID0gZ2FtZWFuYWx5dGljcy5sb2dnaW5nLkdBTG9nZ2VyO1xuXG4gICAgICAgIGV4cG9ydCBlbnVtIEVHQVN0b3JlQXJnc09wZXJhdG9yXG4gICAgICAgIHtcbiAgICAgICAgICAgIEVxdWFsLFxuICAgICAgICAgICAgTGVzc09yRXF1YWwsXG4gICAgICAgICAgICBOb3RFcXVhbFxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGVudW0gRUdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgRXZlbnRzID0gMCxcbiAgICAgICAgICAgIFNlc3Npb25zID0gMSxcbiAgICAgICAgICAgIFByb2dyZXNzaW9uID0gMlxuICAgICAgICB9XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIEdBU3RvcmVcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FTdG9yZSA9IG5ldyBHQVN0b3JlKCk7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzdG9yYWdlQXZhaWxhYmxlOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhOdW1iZXJPZkVudHJpZXM6bnVtYmVyID0gMjAwMDtcbiAgICAgICAgICAgIHByaXZhdGUgZXZlbnRzU3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcbiAgICAgICAgICAgIHByaXZhdGUgc2Vzc2lvbnNTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm9ncmVzc2lvblN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICBwcml2YXRlIHN0b3JlSXRlbXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgS2V5UHJlZml4OnN0cmluZyA9IFwiR0E6OlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRXZlbnRzU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9ldmVudFwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgU2Vzc2lvbnNTdG9yZUtleTpzdHJpbmcgPSBcImdhX3Nlc3Npb25cIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IFByb2dyZXNzaW9uU3RvcmVLZXk6c3RyaW5nID0gXCJnYV9wcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgSXRlbXNTdG9yZUtleTpzdHJpbmcgPSBcImdhX2l0ZW1zXCI7XG5cbiAgICAgICAgICAgIHByaXZhdGUgY29uc3RydWN0b3IoKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBsb2NhbFN0b3JhZ2UgPT09ICdvYmplY3QnKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndGVzdGluZ0xvY2FsU3RvcmFnZScsICd5ZXMnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCd0ZXN0aW5nTG9jYWxTdG9yYWdlJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnN0b3JhZ2VBdmFpbGFibGUgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTdG9yYWdlIGlzIGF2YWlsYWJsZT86IFwiICsgR0FTdG9yZS5zdG9yYWdlQXZhaWxhYmxlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JhZ2VBdmFpbGFibGUoKTpib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuc3RvcmFnZUF2YWlsYWJsZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlLmxlbmd0aCArIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZS5sZW5ndGggPiBHQVN0b3JlLk1heE51bWJlck9mRW50cmllcztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZWxlY3Qoc3RvcmU6RUdBU3RvcmUsIGFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0+ID0gW10sIHNvcnQ6Ym9vbGVhbiA9IGZhbHNlLCBtYXhDb3VudDpudW1iZXIgPSAwKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHJlc3VsdDpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IFtdO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGN1cnJlbnRTdG9yZS5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgIHZhciBhZGQ6Ym9vbGVhbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBhcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gYXJnc1tqXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZW50cnlbYXJnc0VudHJ5WzBdXSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzd2l0Y2goYXJnc0VudHJ5WzFdKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA9PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSA8PSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZW50cnlbYXJnc0VudHJ5WzBdXSAhPSBhcmdzRW50cnlbMl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYWRkID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFkZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZighYWRkKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoYWRkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQucHVzaChlbnRyeSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihzb3J0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnNvcnQoKGE6e1trZXk6c3RyaW5nXTogYW55fSwgYjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKGFbXCJjbGllbnRfdHNcIl0gYXMgbnVtYmVyKSAtIChiW1wiY2xpZW50X3RzXCJdIGFzIG51bWJlcilcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYobWF4Q291bnQgPiAwICYmIHJlc3VsdC5sZW5ndGggPiBtYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHJlc3VsdC5zbGljZSgwLCBtYXhDb3VudCArIDEpXG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB1cGRhdGUoc3RvcmU6RUdBU3RvcmUsIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgYW55XT4sIHdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4gPSBbXSk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgY3VycmVudFN0b3JlOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5nZXRTdG9yZShzdG9yZSk7XG5cbiAgICAgICAgICAgICAgICBpZighY3VycmVudFN0b3JlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgZW50cnk6e1trZXk6c3RyaW5nXTogYW55fSA9IGN1cnJlbnRTdG9yZVtpXTtcblxuICAgICAgICAgICAgICAgICAgICB2YXIgdXBkYXRlOmJvb2xlYW4gPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGogPSAwOyBqIDwgd2hlcmVBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXJnc0VudHJ5OltzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBhbnldID0gd2hlcmVBcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdXBkYXRlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCF1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZih1cGRhdGUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiA9IDA7IGogPCBzZXRBcmdzLmxlbmd0aDsgKytqKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBzZXRBcmdzRW50cnk6W3N0cmluZywgYW55XSA9IHNldEFyZ3Nbal07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZW50cnlbc2V0QXJnc0VudHJ5WzBdXSA9IHNldEFyZ3NFbnRyeVsxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGRlbGV0ZShzdG9yZTpFR0FTdG9yZSwgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgYW55XT4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGN1cnJlbnRTdG9yZTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuZ2V0U3RvcmUoc3RvcmUpO1xuXG4gICAgICAgICAgICAgICAgaWYoIWN1cnJlbnRTdG9yZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY3VycmVudFN0b3JlLmxlbmd0aDsgKytpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGVudHJ5Ontba2V5OnN0cmluZ106IGFueX0gPSBjdXJyZW50U3RvcmVbaV07XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGRlbDpib29sZWFuID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqID0gMDsgaiA8IGFyZ3MubGVuZ3RoOyArK2opXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcmdzRW50cnk6W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIGFueV0gPSBhcmdzW2pdO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVthcmdzRW50cnlbMF1dKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN3aXRjaChhcmdzRW50cnlbMV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dID09IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLkxlc3NPckVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dIDw9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlQXJnc09wZXJhdG9yLk5vdEVxdWFsOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBlbnRyeVthcmdzRW50cnlbMF1dICE9IGFyZ3NFbnRyeVsyXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWwgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVsID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFkZWwpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihkZWwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5zcGxpY2UoaSwgMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAtLWk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5zZXJ0KHN0b3JlOkVHQVN0b3JlLCBuZXdFbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9LCByZXBsYWNlOmJvb2xlYW4gPSBmYWxzZSwgcmVwbGFjZUtleTpzdHJpbmcgPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U3RvcmU6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBHQVN0b3JlLmdldFN0b3JlKHN0b3JlKTtcblxuICAgICAgICAgICAgICAgIGlmKCFjdXJyZW50U3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYocmVwbGFjZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKCFyZXBsYWNlS2V5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICB2YXIgcmVwbGFjZWQ6Ym9vbGVhbiA9IGZhbHNlO1xuXG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaSA9IDA7IGkgPCBjdXJyZW50U3RvcmUubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBlbnRyeTp7W2tleTpzdHJpbmddOiBhbnl9ID0gY3VycmVudFN0b3JlW2ldO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBpZihlbnRyeVtyZXBsYWNlS2V5XSA9PSBuZXdFbnRyeVtyZXBsYWNlS2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb3IobGV0IHMgaW4gbmV3RW50cnkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbnRyeVtzXSA9IG5ld0VudHJ5W3NdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXBsYWNlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZighcmVwbGFjZWQpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRTdG9yZS5wdXNoKG5ld0VudHJ5KTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjdXJyZW50U3RvcmUucHVzaChuZXdFbnRyeSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNhdmUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlN0b3JhZ2UgaXMgbm90IGF2YWlsYWJsZSwgY2Fubm90IHNhdmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkV2ZW50c1N0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKSk7XG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLlNlc3Npb25zU3RvcmVLZXksIEpTT04uc3RyaW5naWZ5KEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSkpO1xuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5LCBKU09OLnN0cmluZ2lmeShHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUpKTtcbiAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuSXRlbXNTdG9yZUtleSwgSlNPTi5zdHJpbmdpZnkoR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgbG9hZCgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU3RvcmFnZSBpcyBub3QgYXZhaWxhYmxlLCBjYW5ub3QgbG9hZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5FdmVudHNTdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLmV2ZW50c1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ2V2ZW50cycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5ldmVudHNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gSlNPTi5wYXJzZShsb2NhbFN0b3JhZ2UuZ2V0SXRlbShHQVN0b3JlLktleVByZWZpeCArIEdBU3RvcmUuU2Vzc2lvbnNTdG9yZUtleSkpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKCFHQVN0b3JlLmluc3RhbmNlLnNlc3Npb25zU3RvcmUpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc2Vzc2lvbnNTdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiTG9hZCBmYWlsZWQgZm9yICdzZXNzaW9ucycgc3RvcmUuIFVzaW5nIGVtcHR5IHN0b3JlLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlID0gW107XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdHJ5XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBKU09OLnBhcnNlKGxvY2FsU3RvcmFnZS5nZXRJdGVtKEdBU3RvcmUuS2V5UHJlZml4ICsgR0FTdG9yZS5Qcm9ncmVzc2lvblN0b3JlS2V5KSk7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoIUdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnN0YW5jZS5wcm9ncmVzc2lvblN0b3JlID0gW107XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJMb2FkIGZhaWxlZCBmb3IgJ3Byb2dyZXNzaW9uJyBzdG9yZS4gVXNpbmcgZW1wdHkgc3RvcmUuXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnByb2dyZXNzaW9uU3RvcmUgPSBbXTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcyA9IEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oR0FTdG9yZS5LZXlQcmVmaXggKyBHQVN0b3JlLkl0ZW1zU3RvcmVLZXkpKTtcblxuICAgICAgICAgICAgICAgICAgICBpZighR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkxvYWQgZmFpbGVkIGZvciAnaXRlbXMnIHN0b3JlLiBVc2luZyBlbXB0eSBzdG9yZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZSA9IFtdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRJdGVtKGtleTpzdHJpbmcsIHZhbHVlOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLktleVByZWZpeCArIGtleTtcblxuICAgICAgICAgICAgICAgIGlmKCF2YWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGtleVdpdGhQcmVmaXggaW4gR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBkZWxldGUgR0FTdG9yZS5pbnN0YW5jZS5zdG9yZUl0ZW1zW2tleVdpdGhQcmVmaXhdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtc1trZXlXaXRoUHJlZml4XSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRJdGVtKGtleTpzdHJpbmcpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIga2V5V2l0aFByZWZpeDpzdHJpbmcgPSBHQVN0b3JlLktleVByZWZpeCArIGtleTtcbiAgICAgICAgICAgICAgICBpZihrZXlXaXRoUHJlZml4IGluIEdBU3RvcmUuaW5zdGFuY2Uuc3RvcmVJdGVtcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBHQVN0b3JlLmluc3RhbmNlLnN0b3JlSXRlbXNba2V5V2l0aFByZWZpeF0gYXMgc3RyaW5nO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGdldFN0b3JlKHN0b3JlOkVHQVN0b3JlKTogQXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBzd2l0Y2goc3RvcmUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLkV2ZW50czpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UuZXZlbnRzU3RvcmU7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBjYXNlIEVHQVN0b3JlLlNlc3Npb25zOlxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdG9yZS5pbnN0YW5jZS5zZXNzaW9uc1N0b3JlO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgY2FzZSBFR0FTdG9yZS5Qcm9ncmVzc2lvbjpcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RvcmUuaW5zdGFuY2UucHJvZ3Jlc3Npb25TdG9yZTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJHQVN0b3JlLmdldFN0b3JlKCk6IENhbm5vdCBmaW5kIHN0b3JlOiBcIiArIHN0b3JlKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIHN0YXRlXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5HQVN0b3JlO1xuICAgICAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYW1lYW5hbHl0aWNzLmRldmljZS5HQURldmljZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FTdGF0ZVxuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeVNka0Vycm9yOnN0cmluZyA9IFwic2RrX2Vycm9yXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19DT1VOVDpudW1iZXIgPSA1MDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEg6bnVtYmVyID0gNjQ7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNQVhfQ1VTVE9NX0ZJRUxEU19WQUxVRV9TVFJJTkdfTEVOR1RIOm51bWJlciA9IDI1NjtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBpbnN0YW5jZTpHQVN0YXRlID0gbmV3IEdBU3RhdGUoKTtcblxuICAgICAgICAgICAgcHJpdmF0ZSBjb25zdHJ1Y3RvcigpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5faXNFdmVudFN1Ym1pc3Npb25FbmFibGVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSB1c2VySWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRVc2VySWQodXNlcklkOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnVzZXJJZCA9IHVzZXJJZDtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGlkZW50aWZpZXI6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRJZGVudGlmaWVyKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmlkZW50aWZpZXI7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZWQ6Ym9vbGVhbjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaXNJbml0aWFsaXplZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuaW5pdGlhbGl6ZWQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEluaXRpYWxpemVkKHZhbHVlOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0aWFsaXplZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2Vzc2lvblN0YXJ0Om51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvblN0YXJ0KCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzZXNzaW9uTnVtOm51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2Vzc2lvbk51bSgpOiBudW1iZXJcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uTnVtO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHRyYW5zYWN0aW9uTnVtOm51bWJlcjtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VHJhbnNhY3Rpb25OdW0oKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW07XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZXNzaW9uSWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRTZXNzaW9uSWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbklkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGN1cnJlbnRDdXN0b21EaW1lbnNpb24wMTpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDE7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3VycmVudEN1c3RvbURpbWVuc2lvbjAyOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBjdXJyZW50Q3VzdG9tRGltZW5zaW9uMDM6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGdhbWVLZXk6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRHYW1lS2V5KCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmdhbWVLZXk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgZ2FtZVNlY3JldDpzdHJpbmc7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEdhbWVTZWNyZXQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZ2FtZVNlY3JldDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDE6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVDdXN0b21EaW1lbnNpb25zKHZhbHVlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEgPSB2YWx1ZTtcblxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIGN1cnJlbnQgZGltZW5zaW9uIHZhbHVlc1xuICAgICAgICAgICAgICAgIEdBU3RhdGUudmFsaWRhdGVBbmRGaXhDdXJyZW50RGltZW5zaW9ucygpO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMjpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMigpOiBBcnJheTxzdHJpbmc+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAyO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIodmFsdWU6QXJyYXk8c3RyaW5nPik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmKCFHQVZhbGlkYXRvci52YWxpZGF0ZUN1c3RvbURpbWVuc2lvbnModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMiA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgY3VycmVudCBkaW1lbnNpb24gdmFsdWVzXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS52YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKCk6IEFycmF5PHN0cmluZz5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlQ3VzdG9tRGltZW5zaW9ucyh2YWx1ZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBjdXJyZW50IGRpbWVuc2lvbiB2YWx1ZXNcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgYXZhaWxhYmxlIGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZXM6IChcIiArIEdBVXRpbGl0aWVzLmpvaW5TdHJpbmdBcnJheSh2YWx1ZSwgXCIsIFwiKSArIFwiKVwiKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBhdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHZhbHVlOkFycmF5PHN0cmluZz4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZighR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUN1cnJlbmNpZXModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyA9IHZhbHVlO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBhdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llczogKFwiICsgR0FVdGlsaXRpZXMuam9pblN0cmluZ0FycmF5KHZhbHVlLCBcIiwgXCIpICsgXCIpXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzOkFycmF5PHN0cmluZz4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMoKTogQXJyYXk8c3RyaW5nPlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRBdmFpbGFibGVSZXNvdXJjZUl0ZW1UeXBlcyh2YWx1ZTpBcnJheTxzdHJpbmc+KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlXG4gICAgICAgICAgICAgICAgaWYoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUmVzb3VyY2VJdGVtVHlwZXModmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzID0gdmFsdWU7XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGF2YWlsYWJsZSByZXNvdXJjZSBpdGVtIHR5cGVzOiAoXCIgKyBHQVV0aWxpdGllcy5qb2luU3RyaW5nQXJyYXkodmFsdWUsIFwiLCBcIikgKyBcIilcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYnVpbGQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRCdWlsZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5idWlsZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0QnVpbGQodmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQgPSB2YWx1ZTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGJ1aWxkIHZlcnNpb246IFwiICsgdmFsdWUpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHVzZU1hbnVhbFNlc3Npb25IYW5kbGluZzpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKTogYm9vbGVhblxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLnVzZU1hbnVhbFNlc3Npb25IYW5kbGluZztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBfaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkOmJvb2xlYW47XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuX2lzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZ0NhY2hlZDp7W2tleTpzdHJpbmddOiBhbnl9O1xuICAgICAgICAgICAgcHJpdmF0ZSBjb25maWd1cmF0aW9uczp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NJc1JlYWR5OmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnM6QXJyYXk8eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfT4gPSBbXTtcbiAgICAgICAgICAgIHB1YmxpYyBpbml0QXV0aG9yaXplZDpib29sZWFuO1xuICAgICAgICAgICAgcHVibGljIGNsaWVudFNlcnZlclRpbWVPZmZzZXQ6bnVtYmVyO1xuICAgICAgICAgICAgcHVibGljIGNvbmZpZ3NIYXNoOnN0cmluZztcblxuICAgICAgICAgICAgcHVibGljIGFiSWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdJZCgpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5hYklkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIGFiVmFyaWFudElkOnN0cmluZztcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0QUJUZXN0aW5nVmFyaWFudElkKCk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBHQVN0YXRlLmluc3RhbmNlLmFiVmFyaWFudElkO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIGRlZmF1bHRVc2VySWQ6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBzZXREZWZhdWx0SWQodmFsdWU6c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHRoaXMuZGVmYXVsdFVzZXJJZCA9ICF2YWx1ZSA/IFwiXCIgOiB2YWx1ZTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmNhY2hlSWRlbnRpZmllcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXREZWZhdWx0SWQoKTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHNka0NvbmZpZ0RlZmF1bHQ6e1trZXk6c3RyaW5nXTogc3RyaW5nfSA9IHt9O1xuXG4gICAgICAgICAgICBwdWJsaWMgc2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrQ29uZmlnKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBmaXJzdDtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQganNvbiBpbiBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPT09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmlyc3QgPSBqc29uO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIGlmKGZpcnN0ICYmIGNvdW50ID4gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGZpcnN0O1xuICAgICAgICAgICAgICAgICAgICB2YXIgY291bnQ6bnVtYmVyID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZm9yKGxldCBqc29uIGluIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihjb3VudCA9PT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmaXJzdCA9IGpzb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgaWYoZmlyc3QgJiYgY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdEZWZhdWx0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHByb2dyZXNzaW9uVHJpZXM6e1trZXk6c3RyaW5nXTogbnVtYmVyfSA9IHt9O1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBEZWZhdWx0VXNlcklkS2V5OnN0cmluZyA9IFwiZGVmYXVsdF91c2VyX2lkXCI7XG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlYWRvbmx5IFNlc3Npb25OdW1LZXk6c3RyaW5nID0gXCJzZXNzaW9uX251bVwiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBUcmFuc2FjdGlvbk51bUtleTpzdHJpbmcgPSBcInRyYW5zYWN0aW9uX251bVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDFLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMVwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDJLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wMlwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgRGltZW5zaW9uMDNLZXk6c3RyaW5nID0gXCJkaW1lbnNpb24wM1wiO1xuICAgICAgICAgICAgcHVibGljIHN0YXRpYyByZWFkb25seSBTZGtDb25maWdDYWNoZWRLZXk6c3RyaW5nID0gXCJzZGtfY29uZmlnX2NhY2hlZFwiO1xuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGlzRW5hYmxlZCgpOiBib29sZWFuXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSA9IGRpbWVuc2lvbjtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgZGltZW5zaW9uKTtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiU2V0IGN1c3RvbTAxIGRpbWVuc2lvbiB2YWx1ZTogXCIgKyBkaW1lbnNpb24pO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAyKGRpbWVuc2lvbjpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIgPSBkaW1lbnNpb247XG4gICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGRpbWVuc2lvbik7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWU6IFwiICsgZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMyhkaW1lbnNpb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAzID0gZGltZW5zaW9uO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBkaW1lbnNpb24pO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJTZXQgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlOiBcIiArIGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50U2Vzc2lvbk51bSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25OdW1JbnQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRTZXNzaW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IHNlc3Npb25OdW1JbnQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0cmFuc2FjdGlvbk51bUludDpudW1iZXIgPSBHQVN0YXRlLmdldFRyYW5zYWN0aW9uTnVtKCkgKyAxO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSB0cmFuc2FjdGlvbk51bUludDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uOnN0cmluZyk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdHJpZXM6bnVtYmVyID0gR0FTdGF0ZS5nZXRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uKSArIDE7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzW3Byb2dyZXNzaW9uXSA9IHRyaWVzO1xuXG4gICAgICAgICAgICAgICAgLy8gUGVyc2lzdFxuICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIHZhbHVlc1tcInByb2dyZXNzaW9uXCJdID0gcHJvZ3Jlc3Npb247XG4gICAgICAgICAgICAgICAgdmFsdWVzW1widHJpZXNcIl0gPSB0cmllcztcbiAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5Qcm9ncmVzc2lvbiwgdmFsdWVzLCB0cnVlLCBcInByb2dyZXNzaW9uXCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGdldFByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYocHJvZ3Jlc3Npb24gaW4gR0FTdGF0ZS5pbnN0YW5jZS5wcm9ncmVzc2lvblRyaWVzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25Ucmllc1twcm9ncmVzc2lvbl07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAwO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjbGVhclByb2dyZXNzaW9uVHJpZXMocHJvZ3Jlc3Npb246c3RyaW5nKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKHByb2dyZXNzaW9uIGluIEdBU3RhdGUuaW5zdGFuY2UucHJvZ3Jlc3Npb25UcmllcylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSBHQVN0YXRlLmluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcHJvZ3Jlc3Npb25dO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIERlbGV0ZVxuICAgICAgICAgICAgICAgIHZhciBwYXJtczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBwYXJtcy5wdXNoKFtcInByb2dyZXNzaW9uXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBwcm9ncmVzc2lvbl0pO1xuICAgICAgICAgICAgICAgIEdBU3RvcmUuZGVsZXRlKEVHQVN0b3JlLlByb2dyZXNzaW9uLCBwYXJtcyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0S2V5cyhnYW1lS2V5OnN0cmluZywgZ2FtZVNlY3JldDpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5nYW1lS2V5ID0gZ2FtZUtleTtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmdhbWVTZWNyZXQgPSBnYW1lU2VjcmV0O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS51c2VNYW51YWxTZXNzaW9uSGFuZGxpbmcgPSBmbGFnO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJVc2UgbWFudWFsIHNlc3Npb24gaGFuZGxpbmc6IFwiICsgZmxhZyk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnOmJvb2xlYW4pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5faXNFdmVudFN1Ym1pc3Npb25FbmFibGVkID0gZmxhZztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuICAgICAgICAgICAgICAgIC8vIFVzZXIgaWRlbnRpZmllclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1widXNlcl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllcjtcblxuICAgICAgICAgICAgICAgIC8vIENsaWVudCBUaW1lc3RhbXAgKHRoZSBhZGp1c3RlZCB0aW1lc3RhbXApXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJjbGllbnRfdHNcIl0gPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcbiAgICAgICAgICAgICAgICAvLyBTREsgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wic2RrX3ZlcnNpb25cIl0gPSBHQURldmljZS5nZXRSZWxldmFudFNka1ZlcnNpb24oKTtcbiAgICAgICAgICAgICAgICAvLyBPcGVyYXRpb24gc3lzdGVtIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XG4gICAgICAgICAgICAgICAgLy8gRGV2aWNlIG1ha2UgKGhhcmRjb2RlZCB0byBhcHBsZSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcIm1hbnVmYWN0dXJlclwiXSA9IEdBRGV2aWNlLmRldmljZU1hbnVmYWN0dXJlcjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZGV2aWNlXCJdID0gR0FEZXZpY2UuZGV2aWNlTW9kZWw7XG4gICAgICAgICAgICAgICAgLy8gQnJvd3NlciB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJicm93c2VyX3ZlcnNpb25cIl0gPSBHQURldmljZS5icm93c2VyVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcbiAgICAgICAgICAgICAgICAvLyBTZXNzaW9uIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInNlc3Npb25faWRcIl0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25JZDtcbiAgICAgICAgICAgICAgICAvLyBTZXNzaW9uIG51bWJlclxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW0dBU3RhdGUuU2Vzc2lvbk51bUtleV0gPSBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25OdW07XG5cbiAgICAgICAgICAgICAgICAvLyB0eXBlIG9mIGNvbm5lY3Rpb24gdGhlIHVzZXIgaXMgY3VycmVudGx5IG9uIChhZGQgaWYgdmFsaWQpXG4gICAgICAgICAgICAgICAgdmFyIGNvbm5lY3Rpb25fdHlwZTpzdHJpbmcgPSBHQURldmljZS5nZXRDb25uZWN0aW9uVHlwZSgpO1xuICAgICAgICAgICAgICAgIGlmIChHQVZhbGlkYXRvci52YWxpZGF0ZUNvbm5lY3Rpb25UeXBlKGNvbm5lY3Rpb25fdHlwZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbm5lY3Rpb25fdHlwZVwiXSA9IGNvbm5lY3Rpb25fdHlwZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImVuZ2luZV92ZXJzaW9uXCJdID0gR0FEZXZpY2UuZ2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcmVtb3RlIGNvbmZpZ3NcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgICAgIGZvcihsZXQgXyBpbiBHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb3VudCsrO1xuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgaWYoY291bnQgPiAwKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNvbmZpZ3VyYXRpb25zXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9ucztcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEEvQiB0ZXN0aW5nXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5hYklkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJhYl9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYWJJZDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5hYlZhcmlhbnRJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiYWJfdmFyaWFudF9pZFwiXSA9IEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBDT05ESVRJT05BTCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBBcHAgYnVpbGQgdmVyc2lvbiAodXNlIGlmIG5vdCBuaWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuaW5zdGFuY2UuYnVpbGQpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImJ1aWxkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5idWlsZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0U2RrRXJyb3JFdmVudEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gLS0tLSBSRVFVSVJFRCAtLS0tIC8vXG5cbiAgICAgICAgICAgICAgICAvLyBjb2xsZWN0b3IgZXZlbnQgQVBJIHZlcnNpb25cbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInZcIl0gPSAyO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcImNhdGVnb3J5XCJdID0gR0FTdGF0ZS5DYXRlZ29yeVNka0Vycm9yO1xuICAgICAgICAgICAgICAgIC8vIFNESyB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wib3NfdmVyc2lvblwiXSA9IEdBRGV2aWNlLm9zVmVyc2lvbjtcbiAgICAgICAgICAgICAgICAvLyBEZXZpY2UgbWFrZSAoaGFyZGNvZGVkIHRvIGFwcGxlKVxuICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wibWFudWZhY3R1cmVyXCJdID0gR0FEZXZpY2UuZGV2aWNlTWFudWZhY3R1cmVyO1xuICAgICAgICAgICAgICAgIC8vIERldmljZSB2ZXJzaW9uXG4gICAgICAgICAgICAgICAgYW5ub3RhdGlvbnNbXCJkZXZpY2VcIl0gPSBHQURldmljZS5kZXZpY2VNb2RlbDtcbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBhbm5vdGF0aW9uc1tcInBsYXRmb3JtXCJdID0gR0FEZXZpY2UuYnVpbGRQbGF0Zm9ybTtcblxuICAgICAgICAgICAgICAgIC8vIHR5cGUgb2YgY29ubmVjdGlvbiB0aGUgdXNlciBpcyBjdXJyZW50bHkgb24gKGFkZCBpZiB2YWxpZClcbiAgICAgICAgICAgICAgICB2YXIgY29ubmVjdGlvbl90eXBlOnN0cmluZyA9IEdBRGV2aWNlLmdldENvbm5lY3Rpb25UeXBlKCk7XG4gICAgICAgICAgICAgICAgaWYgKEdBVmFsaWRhdG9yLnZhbGlkYXRlQ29ubmVjdGlvblR5cGUoY29ubmVjdGlvbl90eXBlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiY29ubmVjdGlvbl90eXBlXCJdID0gY29ubmVjdGlvbl90eXBlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmIChHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGFubm90YXRpb25zW1wiZW5naW5lX3ZlcnNpb25cIl0gPSBHQURldmljZS5nYW1lRW5naW5lVmVyc2lvbjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gYW5ub3RhdGlvbnM7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0SW5pdEFubm90YXRpb25zKCk6IHtba2V5OnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgaW5pdEFubm90YXRpb25zOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmdldElkZW50aWZpZXIoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuY2FjaGVJZGVudGlmaWVyKCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1widXNlcl9pZFwiXSA9IEdBU3RhdGUuZ2V0SWRlbnRpZmllcigpO1xuXG4gICAgICAgICAgICAgICAgLy8gU0RLIHZlcnNpb25cbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJzZGtfdmVyc2lvblwiXSA9IEdBRGV2aWNlLmdldFJlbGV2YW50U2RrVmVyc2lvbigpO1xuICAgICAgICAgICAgICAgIC8vIE9wZXJhdGlvbiBzeXN0ZW0gdmVyc2lvblxuICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcIm9zX3ZlcnNpb25cIl0gPSBHQURldmljZS5vc1ZlcnNpb247XG5cbiAgICAgICAgICAgICAgICAvLyBQbGF0Zm9ybSAob3BlcmF0aW5nIHN5c3RlbSlcbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJwbGF0Zm9ybVwiXSA9IEdBRGV2aWNlLmJ1aWxkUGxhdGZvcm07XG5cbiAgICAgICAgICAgICAgICAvLyBCdWlsZFxuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuZ2V0QnVpbGQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluaXRBbm5vdGF0aW9uc1tcImJ1aWxkXCJdID0gR0FTdGF0ZS5nZXRCdWlsZCgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJidWlsZFwiXSA9IG51bGw7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaW5pdEFubm90YXRpb25zW1wic2Vzc2lvbl9udW1cIl0gPSBHQVN0YXRlLmdldFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBpbml0QW5ub3RhdGlvbnNbXCJyYW5kb21fc2FsdFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvbk51bSgpO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIGluaXRBbm5vdGF0aW9ucztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDbGllbnRUc0FkanVzdGVkKCk6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICB2YXIgY2xpZW50VHNBZGp1c3RlZEludGVnZXI6bnVtYmVyID0gY2xpZW50VHMgKyBHQVN0YXRlLmluc3RhbmNlLmNsaWVudFNlcnZlclRpbWVPZmZzZXQ7XG5cbiAgICAgICAgICAgICAgICBpZihHQVZhbGlkYXRvci52YWxpZGF0ZUNsaWVudFRzKGNsaWVudFRzQWRqdXN0ZWRJbnRlZ2VyKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBjbGllbnRUc0FkanVzdGVkSW50ZWdlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNsaWVudFRzO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBzZXNzaW9uSXNTdGFydGVkKCk6IGJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uU3RhcnQgIT0gMDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgY2FjaGVJZGVudGlmaWVyKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmluc3RhbmNlLnVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UudXNlcklkO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuaWRlbnRpZmllciA9IEdBU3RhdGUuaW5zdGFuY2UuZGVmYXVsdFVzZXJJZDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiaWRlbnRpZmllciwge2NsZWFuOlwiICsgR0FTdGF0ZS5pbnN0YW5jZS5pZGVudGlmaWVyICsgXCJ9XCIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGVuc3VyZVBlcnNpc3RlZFN0YXRlcygpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gZ2V0IGFuZCBleHRyYWN0IHN0b3JlZCBzdGF0ZXNcbiAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5sb2FkKCk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5zZXJ0IGludG8gR0FTdGF0ZSBpbnN0YW5jZVxuICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZTpHQVN0YXRlID0gR0FTdGF0ZS5pbnN0YW5jZTtcblxuICAgICAgICAgICAgICAgIGluc3RhbmNlLnNldERlZmF1bHRJZChHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EZWZhdWx0VXNlcklkS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSkgOiBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCkpO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2Vzc2lvbk51bSA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNlc3Npb25OdW1LZXkpICE9IG51bGwgPyBOdW1iZXIoR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuU2Vzc2lvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgaW5zdGFuY2UudHJhbnNhY3Rpb25OdW0gPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkgIT0gbnVsbCA/IE51bWJlcihHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSkpIDogMC4wO1xuXG4gICAgICAgICAgICAgICAgLy8gcmVzdG9yZSBkaW1lbnNpb24gc2V0dGluZ3NcbiAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSwgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAxID0gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDFLZXkpICE9IG51bGwgPyBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wMUtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpZihpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJEaW1lbnNpb24wMSBmb3VuZCBpbiBjYWNoZTogXCIgKyBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDEpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXksIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMiA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAyS2V5KSAhPSBudWxsID8gR0FTdG9yZS5nZXRJdGVtKEdBU3RhdGUuRGltZW5zaW9uMDJLZXkpIDogXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgaWYoaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiRGltZW5zaW9uMDIgZm91bmQgaW4gY2FjaGU6IFwiICsgaW5zdGFuY2UuY3VycmVudEN1c3RvbURpbWVuc2lvbjAyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5LCBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5jdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMgPSBHQVN0b3JlLmdldEl0ZW0oR0FTdGF0ZS5EaW1lbnNpb24wM0tleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLkRpbWVuc2lvbjAzS2V5KSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGlmKGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMylcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkRpbWVuc2lvbjAzIGZvdW5kIGluIGNhY2hlOiBcIiArIGluc3RhbmNlLmN1cnJlbnRDdXN0b21EaW1lbnNpb24wMyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBnZXQgY2FjaGVkIGluaXQgY2FsbCB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkU3RyaW5nOnN0cmluZyA9IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgIT0gbnVsbCA/IEdBU3RvcmUuZ2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSkgOiBcIlwiO1xuICAgICAgICAgICAgICAgIGlmIChzZGtDb25maWdDYWNoZWRTdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgICAgICB2YXIgc2RrQ29uZmlnQ2FjaGVkID0gSlNPTi5wYXJzZShHQVV0aWxpdGllcy5kZWNvZGU2NChzZGtDb25maWdDYWNoZWRTdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKHNka0NvbmZpZ0NhY2hlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkID0gc2RrQ29uZmlnQ2FjaGVkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICB2YXIgY3VycmVudFNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9ID0gR0FTdGF0ZS5nZXRTZGtDb25maWcoKTtcbiAgICAgICAgICAgICAgICAgICAgaW5zdGFuY2UuY29uZmlnc0hhc2ggPSBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImNvbmZpZ3NfaGFzaFwiXSA6IFwiXCI7XG4gICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLmFiSWQgPSBjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl0gPyBjdXJyZW50U2RrQ29uZmlnW1wiYWJfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgICAgICBpbnN0YW5jZS5hYlZhcmlhbnRJZCA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdID8gY3VycmVudFNka0NvbmZpZ1tcImFiX3ZhcmlhbnRfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciByZXN1bHRzX2dhX3Byb2dyZXNzaW9uOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuUHJvZ3Jlc3Npb24pO1xuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb24pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb24ubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByZXN1bHQ6e1trZXk6c3RyaW5nXTogYW55fSA9IHJlc3VsdHNfZ2FfcHJvZ3Jlc3Npb25baV07XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAocmVzdWx0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGluc3RhbmNlLnByb2dyZXNzaW9uVHJpZXNbcmVzdWx0W1wicHJvZ3Jlc3Npb25cIl0gYXMgc3RyaW5nXSA9IHJlc3VsdFtcInRyaWVzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBjYWxjdWxhdGVTZXJ2ZXJUaW1lT2Zmc2V0KHNlcnZlclRzOm51bWJlcik6IG51bWJlclxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBjbGllbnRUczpudW1iZXIgPSBHQVV0aWxpdGllcy50aW1lSW50ZXJ2YWxTaW5jZTE5NzAoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gc2VydmVyVHMgLSBjbGllbnRUcztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB7W2lkOnN0cmluZ106IGFueX1cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgcmVzdWx0OntbaWQ6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgaWYoZmllbGRzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNvdW50Om51bWJlciA9IDA7XG5cbiAgICAgICAgICAgICAgICAgICAgZm9yKHZhciBrZXkgaW4gZmllbGRzKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWU6YW55ID0gZmllbGRzW2tleV07XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFrZXkgfHwgIXZhbHVlKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT1cIiArIGtleSArIFwiLCB2YWx1ZT1cIiArIHZhbHVlICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcIiBoYXMgYmVlbiBvbWl0dGVkIGJlY2F1c2UgaXRzIGtleSBvciB2YWx1ZSBpcyBudWxsXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZihjb3VudCA8IEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfQ09VTlQpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHJlZ2V4ID0gbmV3IFJlZ0V4cChcIl5bYS16QS1aMC05X117MSxcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfS0VZX0xFTkdUSCArIFwifSRcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYoR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goa2V5LCByZWdleCkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdHlwZSA9IHR5cGVvZiB2YWx1ZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgaWYodHlwZSA9PT0gXCJzdHJpbmdcIiB8fCB2YWx1ZSBpbnN0YW5jZW9mIFN0cmluZylcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlQXNTdHJpbmc6c3RyaW5nID0gdmFsdWUgYXMgc3RyaW5nO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZih2YWx1ZUFzU3RyaW5nLmxlbmd0aCA8PSBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX1ZBTFVFX1NUUklOR19MRU5HVEggJiYgdmFsdWVBc1N0cmluZy5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdFtrZXldID0gdmFsdWVBc1N0cmluZztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT1cIiArIGtleSArIFwiLCB2YWx1ZT1cIiArIHZhbHVlICsgXCIgaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyB2YWx1ZSBpcyBhbiBlbXB0eSBzdHJpbmcgb3IgZXhjZWVkcyB0aGUgbWF4IG51bWJlciBvZiBjaGFyYWN0ZXJzIChcIiArIEdBU3RhdGUuTUFYX0NVU1RPTV9GSUVMRFNfVkFMVUVfU1RSSU5HX0xFTkdUSCArIFwiKVwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmKHR5cGUgPT09IFwibnVtYmVyXCIgfHwgdmFsdWUgaW5zdGFuY2VvZiBOdW1iZXIpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZUFzTnVtYmVyOm51bWJlciA9IHZhbHVlIGFzIG51bWJlcjtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0W2tleV0gPSB2YWx1ZUFzTnVtYmVyO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKytjb3VudDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT1cIiArIGtleSArIFwiLCB2YWx1ZT1cIiArIHZhbHVlICsgXCIgaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyB2YWx1ZSBpcyBub3QgYSBzdHJpbmcgb3IgbnVtYmVyXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT1cIiArIGtleSArIFwiLCB2YWx1ZT1cIiArIHZhbHVlICsgXCIgaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0cyBrZXkgY29udGFpbnMgaWxsZWdhbCBjaGFyYWN0ZXIsIGlzIGVtcHR5IG9yIGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY2hhcmFjdGVycyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0tFWV9MRU5HVEggKyBcIilcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJ2YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzOiBlbnRyeSB3aXRoIGtleT1cIiArIGtleSArIFwiLCB2YWx1ZT1cIiArIHZhbHVlICsgXCIgaGFzIGJlZW4gb21pdHRlZCBiZWNhdXNlIGl0IGV4Y2VlZHMgdGhlIG1heCBudW1iZXIgb2YgY3VzdG9tIGZpZWxkcyAoXCIgKyBHQVN0YXRlLk1BWF9DVVNUT01fRklFTERTX0NPVU5UICsgXCIpXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyB2YWxpZGF0ZUFuZEZpeEN1cnJlbnREaW1lbnNpb25zKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSB0aGF0IHRoZXJlIGFyZSBubyBjdXJyZW50IGRpbWVuc2lvbjAxIG5vdCBpbiBsaXN0XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAxKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCksIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkludmFsaWQgZGltZW5zaW9uMDEgZm91bmQgaW4gdmFyaWFibGUuIFNldHRpbmcgdG8gbmlsLiBJbnZhbGlkIGRpbWVuc2lvbjogXCIgKyBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMShcIlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gdmFsaWRhdGUgdGhhdCB0aGVyZSBhcmUgbm8gY3VycmVudCBkaW1lbnNpb24wMiBub3QgaW4gbGlzdFxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMihHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMigpLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMigpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJJbnZhbGlkIGRpbWVuc2lvbjAyIGZvdW5kIGluIHZhcmlhYmxlLiBTZXR0aW5nIHRvIG5pbC4gSW52YWxpZCBkaW1lbnNpb246IFwiICsgR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSk7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDIoXCJcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIHZhbGlkYXRlIHRoYXQgdGhlcmUgYXJlIG5vIGN1cnJlbnQgZGltZW5zaW9uMDMgbm90IGluIGxpc3RcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKSwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDMoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW52YWxpZCBkaW1lbnNpb24wMyBmb3VuZCBpbiB2YXJpYWJsZS4gU2V0dGluZyB0byBuaWwuIEludmFsaWQgZGltZW5zaW9uOiBcIiArIEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAzKCkpO1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKFwiXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBnZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyk6c3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaW5zdGFuY2UuY29uZmlndXJhdGlvbnNba2V5XS50b1N0cmluZygpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZGVmYXVsdFZhbHVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBpc1JlbW90ZUNvbmZpZ3NSZWFkeSgpOmJvb2xlYW5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzSXNSZWFkeTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2UucmVtb3RlQ29uZmlnc0xpc3RlbmVycy5pbmRleE9mKGxpc3RlbmVyKSA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcjp7IG9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQ6KCkgPT4gdm9pZCB9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGluZGV4ID0gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzLmluZGV4T2YobGlzdGVuZXIpO1xuICAgICAgICAgICAgICAgIGlmKGluZGV4ID4gLTEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnJlbW90ZUNvbmZpZ3NMaXN0ZW5lcnMuc3BsaWNlKGluZGV4LCAxKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZygpOnN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShHQVN0YXRlLmluc3RhbmNlLmNvbmZpZ3VyYXRpb25zKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwb3B1bGF0ZUNvbmZpZ3VyYXRpb25zKHNka0NvbmZpZzp7W2tleTpzdHJpbmddOiBhbnl9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIGNvbmZpZ3VyYXRpb25zOmFueVtdID0gc2RrQ29uZmlnW1wiY29uZmlnc1wiXTtcblxuICAgICAgICAgICAgICAgIGlmKGNvbmZpZ3VyYXRpb25zKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9ucyA9IHt9O1xuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGkgPSAwOyBpIDwgY29uZmlndXJhdGlvbnMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb25maWd1cmF0aW9uOntba2V5OnN0cmluZ106IGFueX0gPSBjb25maWd1cmF0aW9uc1tpXTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYoY29uZmlndXJhdGlvbilcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIga2V5OnN0cmluZyA9IGNvbmZpZ3VyYXRpb25bXCJrZXlcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHZhbHVlOmFueSA9IGNvbmZpZ3VyYXRpb25bXCJ2YWx1ZVwiXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgc3RhcnRfdHM6bnVtYmVyID0gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdID8gY29uZmlndXJhdGlvbltcInN0YXJ0X3RzXCJdIDogTnVtYmVyLk1JTl9WQUxVRTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgZW5kX3RzOm51bWJlciA9IGNvbmZpZ3VyYXRpb25bXCJlbmRfdHNcIl0gPyBjb25maWd1cmF0aW9uW1wiZW5kX3RzXCJdIDogTnVtYmVyLk1BWF9WQUxVRTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjbGllbnRfdHNfYWRqdXN0ZWQ6bnVtYmVyID0gR0FTdGF0ZS5nZXRDbGllbnRUc0FkanVzdGVkKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZihrZXkgJiYgdmFsdWUgJiYgY2xpZW50X3RzX2FkanVzdGVkID4gc3RhcnRfdHMgJiYgY2xpZW50X3RzX2FkanVzdGVkIDwgZW5kX3RzKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWd1cmF0aW9uc1trZXldID0gdmFsdWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJjb25maWd1cmF0aW9uIGFkZGVkOiBcIiArIEpTT04uc3RyaW5naWZ5KGNvbmZpZ3VyYXRpb24pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzSXNSZWFkeSA9IHRydWU7XG5cbiAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXJzOkFycmF5PHsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0+ID0gR0FTdGF0ZS5pbnN0YW5jZS5yZW1vdGVDb25maWdzTGlzdGVuZXJzO1xuXG4gICAgICAgICAgICAgICAgZm9yKGxldCBpID0gMDsgaSA8IGxpc3RlbmVycy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGxpc3RlbmVyc1tpXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGlzdGVuZXJzW2ldLm9uUmVtb3RlQ29uZmlnc1VwZGF0ZWQoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgZXhwb3J0IG1vZHVsZSB0YXNrc1xuICAgIHtcbiAgICAgICAgaW1wb3J0IEVHQVNka0Vycm9yVHlwZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FTZGtFcnJvclR5cGU7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG5cbiAgICAgICAgZXhwb3J0IGNsYXNzIFNka0Vycm9yVGFza1xuICAgICAgICB7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBNYXhDb3VudDpudW1iZXIgPSAxMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IGNvdW50TWFwOntba2V5Om51bWJlcl06IG51bWJlcn0gPSB7fTtcblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBleGVjdXRlKHVybDpzdHJpbmcsIHR5cGU6RUdBU2RrRXJyb3JUeXBlLCBwYXlsb2FkRGF0YTpzdHJpbmcsIHNlY3JldEtleTpzdHJpbmcpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIVNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIFNka0Vycm9yVGFzay5jb3VudE1hcFt0eXBlXSA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYoU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID49IFNka0Vycm9yVGFzay5NYXhDb3VudClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmFyIGhhc2hIbWFjOnN0cmluZyA9IEdBVXRpbGl0aWVzLmdldEhtYWMoc2VjcmV0S2V5LCBwYXlsb2FkRGF0YSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdDpYTUxIdHRwUmVxdWVzdCA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGlmKHJlcXVlc3QucmVhZHlTdGF0ZSA9PT0gNClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoIXJlcXVlc3QucmVzcG9uc2VUZXh0KVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZGsgZXJyb3IgZmFpbGVkLiBNaWdodCBiZSBubyBjb25uZWN0aW9uLiBEZXNjcmlwdGlvbjogXCIgKyByZXF1ZXN0LnN0YXR1c1RleHQgKyBcIiwgU3RhdHVzIGNvZGU6IFwiICsgcmVxdWVzdC5zdGF0dXMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5zdGF0dXMgIT0gMjAwKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJzZGsgZXJyb3IgZmFpbGVkLiByZXNwb25zZSBjb2RlIG5vdCAyMDAuIHN0YXR1cyBjb2RlOiBcIiArIHJlcXVlc3Quc3RhdHVzICsgXCIsIGRlc2NyaXB0aW9uOiBcIiArIHJlcXVlc3Quc3RhdHVzVGV4dCArIFwiLCBib2R5OiBcIiArIHJlcXVlc3QucmVzcG9uc2VUZXh0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdID0gU2RrRXJyb3JUYXNrLmNvdW50TWFwW3R5cGVdICsgMTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9wZW4oXCJQT1NUXCIsIHVybCwgdHJ1ZSk7XG4gICAgICAgICAgICAgICAgcmVxdWVzdC5zZXRSZXF1ZXN0SGVhZGVyKFwiQ29udGVudC1UeXBlXCIsIFwiYXBwbGljYXRpb24vanNvblwiKTtcbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGhhc2hIbWFjKTtcblxuICAgICAgICAgICAgICAgIHRyeVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmVxdWVzdC5zZW5kKHBheWxvYWREYXRhKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2goZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxufVxuIiwibW9kdWxlIGdhbWVhbmFseXRpY3NcbntcbiAgICBleHBvcnQgbW9kdWxlIGh0dHBcbiAgICB7XG4gICAgICAgIGltcG9ydCBHQVN0YXRlID0gZ2FtZWFuYWx5dGljcy5zdGF0ZS5HQVN0YXRlO1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgICAgIGltcG9ydCBTZGtFcnJvclRhc2sgPSBnYW1lYW5hbHl0aWNzLnRhc2tzLlNka0Vycm9yVGFzaztcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FIVFRQQXBpXG4gICAgICAgIHtcbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FIVFRQQXBpID0gbmV3IEdBSFRUUEFwaSgpO1xuICAgICAgICAgICAgcHJpdmF0ZSBwcm90b2NvbDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIGhvc3ROYW1lOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdmVyc2lvbjpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NWZXJzaW9uOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgYmFzZVVybDpzdHJpbmc7XG4gICAgICAgICAgICBwcml2YXRlIHJlbW90ZUNvbmZpZ3NCYXNlVXJsOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgaW5pdGlhbGl6ZVVybFBhdGg6c3RyaW5nO1xuICAgICAgICAgICAgcHJpdmF0ZSBldmVudHNVcmxQYXRoOnN0cmluZztcbiAgICAgICAgICAgIHByaXZhdGUgdXNlR3ppcDpib29sZWFuO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBiYXNlIHVybCBzZXR0aW5nc1xuICAgICAgICAgICAgICAgIHRoaXMucHJvdG9jb2wgPSBcImh0dHBzXCI7XG4gICAgICAgICAgICAgICAgdGhpcy5ob3N0TmFtZSA9IFwiYXBpLmdhbWVhbmFseXRpY3MuY29tXCI7XG4gICAgICAgICAgICAgICAgdGhpcy52ZXJzaW9uID0gXCJ2MlwiO1xuICAgICAgICAgICAgICAgIHRoaXMucmVtb3RlQ29uZmlnc1ZlcnNpb24gPSBcInYxXCI7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYmFzZSB1cmxcbiAgICAgICAgICAgICAgICB0aGlzLmJhc2VVcmwgPSB0aGlzLnByb3RvY29sICsgXCI6Ly9cIiArIHRoaXMuaG9zdE5hbWUgKyBcIi9cIiArIHRoaXMudmVyc2lvbjtcbiAgICAgICAgICAgICAgICB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsID0gdGhpcy5wcm90b2NvbCArIFwiOi8vXCIgKyB0aGlzLmhvc3ROYW1lICsgXCIvcmVtb3RlX2NvbmZpZ3MvXCIgKyB0aGlzLnJlbW90ZUNvbmZpZ3NWZXJzaW9uO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5pbml0aWFsaXplVXJsUGF0aCA9IFwiaW5pdFwiO1xuICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzVXJsUGF0aCA9IFwiZXZlbnRzXCI7XG5cbiAgICAgICAgICAgICAgICB0aGlzLnVzZUd6aXAgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHJlcXVlc3RJbml0KGNvbmZpZ3NIYXNoOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9KSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLnJlbW90ZUNvbmZpZ3NCYXNlVXJsICsgXCIvXCIgKyB0aGlzLmluaXRpYWxpemVVcmxQYXRoICsgXCI/Z2FtZV9rZXk9XCIgKyBnYW1lS2V5ICsgXCImaW50ZXJ2YWxfc2Vjb25kcz0wJmNvbmZpZ3NfaGFzaD1cIiArIGNvbmZpZ3NIYXNoO1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJTZW5kaW5nICdpbml0JyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIHZhciBpbml0QW5ub3RhdGlvbnM6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0SW5pdEFubm90YXRpb25zKCk7XG5cbiAgICAgICAgICAgICAgICAvLyBtYWtlIEpTT04gc3RyaW5nIGZyb20gZGF0YVxuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IEpTT04uc3RyaW5naWZ5KGluaXRBbm5vdGF0aW9ucyk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRW5jb2RlRmFpbGVkLCBudWxsKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YTpzdHJpbmcgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgR0FIVFRQQXBpLnNlbmRSZXF1ZXN0KHVybCwgcGF5bG9hZERhdGEsIGV4dHJhQXJncywgdGhpcy51c2VHemlwLCBHQUhUVFBBcGkuaW5pdFJlcXVlc3RDYWxsYmFjaywgY2FsbGJhY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc2VuZEV2ZW50c0luQXJyYXkoZXZlbnRBcnJheTpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiwgcmVxdWVzdElkOnN0cmluZywgY2FsbGJhY2s6KHJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwganNvbjp7W2tleTpzdHJpbmddOiBhbnl9LCByZXF1ZXN0SWQ6c3RyaW5nLCBldmVudENvdW50Om51bWJlcikgPT4gdm9pZCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihldmVudEFycmF5Lmxlbmd0aCA9PSAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcInNlbmRFdmVudHNJbkFycmF5IGNhbGxlZCB3aXRoIG1pc3NpbmcgZXZlbnRBcnJheVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBnYW1lS2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZUtleSgpO1xuXG4gICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgVVJMXG4gICAgICAgICAgICAgICAgdmFyIHVybDpzdHJpbmcgPSB0aGlzLmJhc2VVcmwgKyBcIi9cIiArIGdhbWVLZXkgKyBcIi9cIiArIHRoaXMuZXZlbnRzVXJsUGF0aDtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU2VuZGluZyAnZXZlbnRzJyBVUkw6IFwiICsgdXJsKTtcblxuICAgICAgICAgICAgICAgIC8vIG1ha2UgSlNPTiBzdHJpbmcgZnJvbSBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIEpTT05zdHJpbmc6c3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighSlNPTnN0cmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kRXZlbnRzSW5BcnJheSBKU09OIGVuY29kaW5nIGZhaWxlZCBvZiBldmVudEFycmF5XCIpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCwgbnVsbCwgcmVxdWVzdElkLCBldmVudEFycmF5Lmxlbmd0aCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZERhdGEgPSB0aGlzLmNyZWF0ZVBheWxvYWREYXRhKEpTT05zdHJpbmcsIHRoaXMudXNlR3ppcCk7XG4gICAgICAgICAgICAgICAgdmFyIGV4dHJhQXJnczpBcnJheTxzdHJpbmc+ID0gW107XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2goSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgZXh0cmFBcmdzLnB1c2gocmVxdWVzdElkKTtcbiAgICAgICAgICAgICAgICBleHRyYUFyZ3MucHVzaChldmVudEFycmF5Lmxlbmd0aC50b1N0cmluZygpKTtcbiAgICAgICAgICAgICAgICBHQUhUVFBBcGkuc2VuZFJlcXVlc3QodXJsLCBwYXlsb2FkRGF0YSwgZXh0cmFBcmdzLCB0aGlzLnVzZUd6aXAsIEdBSFRUUEFwaS5zZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrLCBjYWxsYmFjayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzZW5kU2RrRXJyb3JFdmVudCh0eXBlOkVHQVNka0Vycm9yVHlwZSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgZ2FtZUtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVLZXkoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2VjcmV0S2V5OnN0cmluZyA9IEdBU3RhdGUuZ2V0R2FtZVNlY3JldCgpO1xuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlU2RrRXJyb3JFdmVudChnYW1lS2V5LCBzZWNyZXRLZXksIHR5cGUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEdlbmVyYXRlIFVSTFxuICAgICAgICAgICAgICAgIHZhciB1cmw6c3RyaW5nID0gdGhpcy5iYXNlVXJsICsgXCIvXCIgKyBnYW1lS2V5ICsgXCIvXCIgKyB0aGlzLmV2ZW50c1VybFBhdGg7XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIlNlbmRpbmcgJ2V2ZW50cycgVVJMOiBcIiArIHVybCk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcGF5bG9hZEpTT05TdHJpbmc6c3RyaW5nID0gXCJcIjtcblxuICAgICAgICAgICAgICAgIHZhciBqc29uOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0Vycm9yRXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHR5cGVTdHJpbmc6c3RyaW5nID0gR0FIVFRQQXBpLnNka0Vycm9yVHlwZVRvU3RyaW5nKHR5cGUpO1xuICAgICAgICAgICAgICAgIGpzb25bXCJ0eXBlXCJdID0gdHlwZVN0cmluZztcblxuICAgICAgICAgICAgICAgIHZhciBldmVudEFycmF5OkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gW107XG4gICAgICAgICAgICAgICAgZXZlbnRBcnJheS5wdXNoKGpzb24pO1xuICAgICAgICAgICAgICAgIHBheWxvYWRKU09OU3RyaW5nID0gSlNPTi5zdHJpbmdpZnkoZXZlbnRBcnJheSk7XG5cbiAgICAgICAgICAgICAgICBpZighcGF5bG9hZEpTT05TdHJpbmcpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwic2VuZFNka0Vycm9yRXZlbnQ6IEpTT04gZW5jb2RpbmcgZmFpbGVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJzZW5kU2RrRXJyb3JFdmVudCBqc29uOiBcIiArIHBheWxvYWRKU09OU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBTZGtFcnJvclRhc2suZXhlY3V0ZSh1cmwsIHR5cGUsIHBheWxvYWRKU09OU3RyaW5nLCBzZWNyZXRLZXkpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBzZW5kRXZlbnRJbkFycmF5UmVxdWVzdENhbGxiYWNrKHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4gPSBudWxsKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBhdXRob3JpemF0aW9uOnN0cmluZyA9IGV4dHJhWzBdO1xuICAgICAgICAgICAgICAgIHZhciBKU09Oc3RyaW5nOnN0cmluZyA9IGV4dHJhWzFdO1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWQ6c3RyaW5nID0gZXh0cmFbMl07XG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50Q291bnQ6bnVtYmVyID0gcGFyc2VJbnQoZXh0cmFbM10pO1xuICAgICAgICAgICAgICAgIHZhciBib2R5OnN0cmluZyA9IFwiXCI7XG4gICAgICAgICAgICAgICAgdmFyIHJlc3BvbnNlQ29kZTpudW1iZXIgPSAwO1xuXG4gICAgICAgICAgICAgICAgYm9keSA9IHJlcXVlc3QucmVzcG9uc2VUZXh0O1xuICAgICAgICAgICAgICAgIHJlc3BvbnNlQ29kZSA9IHJlcXVlc3Quc3RhdHVzO1xuXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImV2ZW50cyByZXF1ZXN0IGNvbnRlbnQ6IFwiICsgYm9keSk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdFJlc3BvbnNlRW51bTpFR0FIVFRQQXBpUmVzcG9uc2UgPSBHQUhUVFBBcGkuaW5zdGFuY2UucHJvY2Vzc1JlcXVlc3RSZXNwb25zZShyZXNwb25zZUNvZGUsIHJlcXVlc3Quc3RhdHVzVGV4dCwgYm9keSwgXCJFdmVudHNcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBpZiBub3QgMjAwIHJlc3VsdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgZXZlbnRzIENhbGwuIFVSTDogXCIgKyB1cmwgKyBcIiwgQXV0aG9yaXphdGlvbjogXCIgKyBhdXRob3JpemF0aW9uICsgXCIsIEpTT05TdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKHJlcXVlc3RSZXNwb25zZUVudW0sIG51bGwsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBkZWNvZGUgSlNPTlxuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SnNvbkRpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IGJvZHkgPyBKU09OLnBhcnNlKGJvZHkpIDoge307XG5cbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0SnNvbkRpY3QgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkLCBudWxsLCByZXF1ZXN0SWQsIGV2ZW50Q291bnQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gcHJpbnQgcmVhc29uIGlmIGJhZCByZXF1ZXN0XG4gICAgICAgICAgICAgICAgaWYocmVxdWVzdFJlc3BvbnNlRW51bSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgRXZlbnRzIENhbGwuIEJhZCByZXF1ZXN0LiBSZXNwb25zZTogXCIgKyBKU09OLnN0cmluZ2lmeShyZXF1ZXN0SnNvbkRpY3QpKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyByZXR1cm4gcmVzcG9uc2VcbiAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCByZXF1ZXN0SnNvbkRpY3QsIHJlcXVlc3RJZCwgZXZlbnRDb3VudCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNlbmRSZXF1ZXN0KHVybDpzdHJpbmcsIHBheWxvYWREYXRhOnN0cmluZywgZXh0cmFBcmdzOkFycmF5PHN0cmluZz4sIGd6aXA6Ym9vbGVhbiwgY2FsbGJhY2s6KHJlcXVlc3Q6WE1MSHR0cFJlcXVlc3QsIHVybDpzdHJpbmcsIGNhbGxiYWNrOihyZXNwb25zZTpFR0FIVFRQQXBpUmVzcG9uc2UsIGpzb246e1trZXk6c3RyaW5nXTogYW55fSwgcmVxdWVzdElkOnN0cmluZywgZXZlbnRDb3VudDpudW1iZXIpID0+IHZvaWQsIGV4dHJhOkFycmF5PHN0cmluZz4pID0+IHZvaWQsIGNhbGxiYWNrMjoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7XG5cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGUgYXV0aG9yaXphdGlvbiBoYXNoXG4gICAgICAgICAgICAgICAgdmFyIGtleTpzdHJpbmcgPSBHQVN0YXRlLmdldEdhbWVTZWNyZXQoKTtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBHQVV0aWxpdGllcy5nZXRIbWFjKGtleSwgcGF5bG9hZERhdGEpO1xuXG4gICAgICAgICAgICAgICAgdmFyIGFyZ3M6QXJyYXk8c3RyaW5nPiA9IFtdO1xuICAgICAgICAgICAgICAgIGFyZ3MucHVzaChhdXRob3JpemF0aW9uKTtcblxuICAgICAgICAgICAgICAgIGZvcihsZXQgcyBpbiBleHRyYUFyZ3MpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBhcmdzLnB1c2goZXh0cmFBcmdzW3NdKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0Lm9ucmVhZHlzdGF0ZWNoYW5nZSA9ICgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYocmVxdWVzdC5yZWFkeVN0YXRlID09PSA0KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0LCB1cmwsIGNhbGxiYWNrMiwgYXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgICAgcmVxdWVzdC5vcGVuKFwiUE9TVFwiLCB1cmwsIHRydWUpO1xuICAgICAgICAgICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihcIkNvbnRlbnQtVHlwZVwiLCBcImFwcGxpY2F0aW9uL2pzb25cIik7XG5cbiAgICAgICAgICAgICAgICByZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJBdXRob3JpemF0aW9uXCIsIGF1dGhvcml6YXRpb24pO1xuXG4gICAgICAgICAgICAgICAgaWYoZ3ppcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImd6aXAgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgLy9yZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoXCJDb250ZW50LUVuY29kaW5nXCIsIFwiZ3ppcFwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJlcXVlc3Quc2VuZChwYXlsb2FkRGF0YSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoKGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFJlcXVlc3RDYWxsYmFjayhyZXF1ZXN0OlhNTEh0dHBSZXF1ZXN0LCB1cmw6c3RyaW5nLCBjYWxsYmFjazoocmVzcG9uc2U6RUdBSFRUUEFwaVJlc3BvbnNlLCBqc29uOntba2V5OnN0cmluZ106IGFueX0sIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKSA9PiB2b2lkLCBleHRyYTpBcnJheTxzdHJpbmc+ID0gbnVsbCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgYXV0aG9yaXphdGlvbjpzdHJpbmcgPSBleHRyYVswXTtcbiAgICAgICAgICAgICAgICB2YXIgSlNPTnN0cmluZzpzdHJpbmcgPSBleHRyYVsxXTtcbiAgICAgICAgICAgICAgICB2YXIgYm9keTpzdHJpbmcgPSBcIlwiO1xuICAgICAgICAgICAgICAgIHZhciByZXNwb25zZUNvZGU6bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIGJvZHkgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgICAgICAgICByZXNwb25zZUNvZGUgPSByZXF1ZXN0LnN0YXR1cztcblxuICAgICAgICAgICAgICAgIC8vIHByb2Nlc3MgdGhlIHJlc3BvbnNlXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcImluaXQgcmVxdWVzdCBjb250ZW50IDogXCIgKyBib2R5ICsgXCIsIEpTT05zdHJpbmc6IFwiICsgSlNPTnN0cmluZyk7XG5cbiAgICAgICAgICAgICAgICB2YXIgcmVxdWVzdEpzb25EaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSBib2R5ID8gSlNPTi5wYXJzZShib2R5KSA6IHt9O1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0UmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSA9IEdBSFRUUEFwaS5pbnN0YW5jZS5wcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZSwgcmVxdWVzdC5zdGF0dXNUZXh0LCBib2R5LCBcIkluaXRcIik7XG5cbiAgICAgICAgICAgICAgICAvLyBpZiBub3QgMjAwIHJlc3VsdFxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rICYmIHJlcXVlc3RSZXNwb25zZUVudW0gIT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQgJiYgcmVxdWVzdFJlc3BvbnNlRW51bSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgSW5pdCBDYWxsLiBVUkw6IFwiICsgdXJsICsgXCIsIEF1dGhvcml6YXRpb246IFwiICsgYXV0aG9yaXphdGlvbiArIFwiLCBKU09OU3RyaW5nOiBcIiArIEpTT05zdHJpbmcpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhyZXF1ZXN0UmVzcG9uc2VFbnVtLCBudWxsLCBcIlwiLCAwKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGlmKHJlcXVlc3RKc29uRGljdCA9PSBudWxsKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkZhaWxlZCBJbml0IENhbGwuIEpzb24gZGVjb2RpbmcgZmFpbGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkRlY29kZUZhaWxlZCwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBwcmludCByZWFzb24gaWYgYmFkIHJlcXVlc3RcbiAgICAgICAgICAgICAgICBpZihyZXF1ZXN0UmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJGYWlsZWQgSW5pdCBDYWxsLiBCYWQgcmVxdWVzdC4gUmVzcG9uc2U6IFwiICsgSlNPTi5zdHJpbmdpZnkocmVxdWVzdEpzb25EaWN0KSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIHJldHVybiBiYWQgcmVxdWVzdCByZXN1bHRcbiAgICAgICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgbnVsbCwgXCJcIiwgMCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB2YWxpZGF0ZSBJbml0IGNhbGwgdmFsdWVzXG4gICAgICAgICAgICAgICAgdmFyIHZhbGlkYXRlZEluaXRWYWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBVmFsaWRhdG9yLnZhbGlkYXRlQW5kQ2xlYW5Jbml0UmVxdWVzdFJlc3BvbnNlKHJlcXVlc3RKc29uRGljdCwgcmVxdWVzdFJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkNyZWF0ZWQpO1xuXG4gICAgICAgICAgICAgICAgaWYoIXZhbGlkYXRlZEluaXRWYWx1ZXMpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBjYWxsYmFjayhFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVzcG9uc2UsIG51bGwsIFwiXCIsIDApO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gYWxsIG9rXG4gICAgICAgICAgICAgICAgY2FsbGJhY2socmVxdWVzdFJlc3BvbnNlRW51bSwgdmFsaWRhdGVkSW5pdFZhbHVlcywgXCJcIiwgMCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgY3JlYXRlUGF5bG9hZERhdGEocGF5bG9hZDpzdHJpbmcsIGd6aXA6Ym9vbGVhbik6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkRGF0YTpzdHJpbmc7XG5cbiAgICAgICAgICAgICAgICBpZihnemlwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gcGF5bG9hZERhdGEgPSBHQVV0aWxpdGllcy5HemlwQ29tcHJlc3MocGF5bG9hZCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIEdBTG9nZ2VyLkQoXCJHemlwIHN0YXRzLiBTaXplOiBcIiArIEVuY29kaW5nLlVURjguR2V0Qnl0ZXMocGF5bG9hZCkuTGVuZ3RoICsgXCIsIENvbXByZXNzZWQ6IFwiICsgcGF5bG9hZERhdGEuTGVuZ3RoICsgXCIsIENvbnRlbnQ6IFwiICsgcGF5bG9hZCk7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImd6aXAgbm90IHN1cHBvcnRlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcGF5bG9hZERhdGEgPSBwYXlsb2FkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBwYXlsb2FkRGF0YTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBwcm9jZXNzUmVxdWVzdFJlc3BvbnNlKHJlc3BvbnNlQ29kZTpudW1iZXIsIHJlc3BvbnNlTWVzc2FnZTpzdHJpbmcsIGJvZHk6c3RyaW5nLCByZXF1ZXN0SWQ6c3RyaW5nKTogRUdBSFRUUEFwaVJlc3BvbnNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgLy8gaWYgbm8gcmVzdWx0IC0gb2Z0ZW4gbm8gY29ubmVjdGlvblxuICAgICAgICAgICAgICAgIGlmKCFib2R5KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiBmYWlsZWQuIE1pZ2h0IGJlIG5vIGNvbm5lY3Rpb24uIERlc2NyaXB0aW9uOiBcIiArIHJlc3BvbnNlTWVzc2FnZSArIFwiLCBTdGF0dXMgY29kZTogXCIgKyByZXNwb25zZUNvZGUpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLk5vUmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gb2tcbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSAyMDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLk9rO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBjcmVhdGVkXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMjAxKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5DcmVhdGVkO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIDQwMSBjYW4gcmV0dXJuIDAgc3RhdHVzXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gMCB8fCByZXNwb25zZUNvZGUgPT09IDQwMSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQocmVxdWVzdElkICsgXCIgcmVxdWVzdC4gNDAxIC0gVW5hdXRob3JpemVkLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEVHQUhUVFBBcGlSZXNwb25zZS5VbmF1dGhvcml6ZWQ7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlQ29kZSA9PT0gNDAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZChyZXF1ZXN0SWQgKyBcIiByZXF1ZXN0LiA0MDAgLSBCYWQgUmVxdWVzdC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVxdWVzdDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAocmVzcG9uc2VDb2RlID09PSA1MDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKHJlcXVlc3RJZCArIFwiIHJlcXVlc3QuIDUwMCAtIEludGVybmFsIFNlcnZlciBFcnJvci5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBFR0FIVFRQQXBpUmVzcG9uc2UuSW50ZXJuYWxTZXJ2ZXJFcnJvcjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICByZXR1cm4gRUdBSFRUUEFwaVJlc3BvbnNlLlVua25vd25SZXNwb25zZUNvZGU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHNka0Vycm9yVHlwZVRvU3RyaW5nKHZhbHVlOkVHQVNka0Vycm9yVHlwZSk6IHN0cmluZ1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHN3aXRjaCh2YWx1ZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGNhc2UgRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkOlxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcInJlamVjdGVkXCI7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgZXZlbnRzXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICAgICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgICAgIGltcG9ydCBFR0FIVFRQQXBpUmVzcG9uc2UgPSBnYW1lYW5hbHl0aWNzLmh0dHAuRUdBSFRUUEFwaVJlc3BvbnNlO1xuICAgICAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcbiAgICAgICAgaW1wb3J0IEdBVmFsaWRhdG9yID0gZ2FtZWFuYWx5dGljcy52YWxpZGF0b3JzLkdBVmFsaWRhdG9yO1xuICAgICAgICBpbXBvcnQgRUdBU2RrRXJyb3JUeXBlID0gZ2FtZWFuYWx5dGljcy5odHRwLkVHQVNka0Vycm9yVHlwZTtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FFdmVudHNcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FFdmVudHMgPSBuZXcgR0FFdmVudHMoKTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5U2Vzc2lvblN0YXJ0OnN0cmluZyA9IFwidXNlclwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlTZXNzaW9uRW5kOnN0cmluZyA9IFwic2Vzc2lvbl9lbmRcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5RGVzaWduOnN0cmluZyA9IFwiZGVzaWduXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUJ1c2luZXNzOnN0cmluZyA9IFwiYnVzaW5lc3NcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IENhdGVnb3J5UHJvZ3Jlc3Npb246c3RyaW5nID0gXCJwcm9ncmVzc2lvblwiO1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgQ2F0ZWdvcnlSZXNvdXJjZTpzdHJpbmcgPSBcInJlc291cmNlXCI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBDYXRlZ29yeUVycm9yOnN0cmluZyA9IFwiZXJyb3JcIjtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlYWRvbmx5IE1heEV2ZW50Q291bnQ6bnVtYmVyID0gNTAwO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcblxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFNlc3Npb25TdGFydEV2ZW50KCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBFdmVudCBzcGVjaWZpYyBkYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdDp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVNlc3Npb25TdGFydDtcblxuICAgICAgICAgICAgICAgIC8vIEluY3JlbWVudCBzZXNzaW9uIG51bWJlciAgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluY3JlbWVudFNlc3Npb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5TZXNzaW9uTnVtS2V5LCBHQVN0YXRlLmdldFNlc3Npb25OdW0oKS50b1N0cmluZygpKTtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIC8vIExvZ1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJBZGQgU0VTU0lPTiBTVEFSVCBldmVudFwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgZXZlbnQgcmlnaHQgYXdheVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLnByb2Nlc3NFdmVudHMoR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uU3RhcnQsIGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRTZXNzaW9uRW5kRXZlbnQoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uX3N0YXJ0X3RzOm51bWJlciA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgdmFyIGNsaWVudF90c19hZGp1c3RlZDpudW1iZXIgPSBHQVN0YXRlLmdldENsaWVudFRzQWRqdXN0ZWQoKTtcbiAgICAgICAgICAgICAgICB2YXIgc2Vzc2lvbkxlbmd0aDpudW1iZXIgPSBjbGllbnRfdHNfYWRqdXN0ZWQgLSBzZXNzaW9uX3N0YXJ0X3RzO1xuXG4gICAgICAgICAgICAgICAgaWYoc2Vzc2lvbkxlbmd0aCA8IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBTaG91bGQgbmV2ZXIgaGFwcGVuLlxuICAgICAgICAgICAgICAgICAgICAvLyBDb3VsZCBiZSBiZWNhdXNlIG9mIGVkZ2UgY2FzZXMgcmVnYXJkaW5nIHRpbWUgYWx0ZXJpbmcgb24gZGV2aWNlLlxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU2Vzc2lvbiBsZW5ndGggd2FzIGNhbGN1bGF0ZWQgdG8gYmUgbGVzcyB0aGVuIDAuIFNob3VsZCBub3QgYmUgcG9zc2libGUuIFJlc2V0dGluZyB0byAwLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgc2Vzc2lvbkxlbmd0aCA9IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gRXZlbnQgc3BlY2lmaWMgZGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImxlbmd0aFwiXSA9IHNlc3Npb25MZW5ndGg7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgY3VzdG9tIGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGREaW1lbnNpb25zVG9FdmVudChldmVudERpY3QpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFNFU1NJT04gRU5EIGV2ZW50LlwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgYWxsIGV2ZW50IHJpZ2h0IGF3YXlcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5wcm9jZXNzRXZlbnRzKFwiXCIsIGZhbHNlKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRCdXNpbmVzc0V2ZW50KGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBjYXJ0VHlwZTpzdHJpbmcgPSBudWxsLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVCdXNpbmVzc0V2ZW50KGN1cnJlbmN5LCBhbW91bnQsIGNhcnRUeXBlLCBpdGVtVHlwZSwgaXRlbUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERpY3Q6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IHRyYW5zYWN0aW9uIG51bWJlciBhbmQgcGVyc2lzdFxuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50VHJhbnNhY3Rpb25OdW0oKTtcbiAgICAgICAgICAgICAgICBHQVN0b3JlLnNldEl0ZW0oR0FTdGF0ZS5UcmFuc2FjdGlvbk51bUtleSwgR0FTdGF0ZS5nZXRUcmFuc2FjdGlvbk51bSgpLnRvU3RyaW5nKCkpO1xuXG4gICAgICAgICAgICAgICAgLy8gUmVxdWlyZWRcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGl0ZW1UeXBlICsgXCI6XCIgKyBpdGVtSWQ7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeUJ1c2luZXNzO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImN1cnJlbmN5XCJdID0gY3VycmVuY3k7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtHQVN0YXRlLlRyYW5zYWN0aW9uTnVtS2V5XSA9IEdBU3RhdGUuZ2V0VHJhbnNhY3Rpb25OdW0oKTtcblxuICAgICAgICAgICAgICAgIC8vIE9wdGlvbmFsXG4gICAgICAgICAgICAgICAgaWYgKGNhcnRUeXBlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2FydF90eXBlXCJdID0gY2FydFR5cGU7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEJVU0lORVNTIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIiwgY2FydFR5cGU6XCIgKyBjYXJ0VHlwZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREaWN0KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBhZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlOkVHQVJlc291cmNlRmxvd1R5cGUsIGN1cnJlbmN5OnN0cmluZywgYW1vdW50Om51bWJlciwgaXRlbVR5cGU6c3RyaW5nLCBpdGVtSWQ6c3RyaW5nLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIFZhbGlkYXRlIGV2ZW50IHBhcmFtc1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcygpLCBHQVN0YXRlLmdldEF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBJZiBmbG93IHR5cGUgaXMgc2luayByZXZlcnNlIGFtb3VudFxuICAgICAgICAgICAgICAgIGlmIChmbG93VHlwZSA9PT0gRUdBUmVzb3VyY2VGbG93VHlwZS5TaW5rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgYW1vdW50ICo9IC0xO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBldmVudCBzcGVjaWZpYyB2YWx1ZXNcbiAgICAgICAgICAgICAgICB2YXIgZmxvd1R5cGVTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucmVzb3VyY2VGbG93VHlwZVRvU3RyaW5nKGZsb3dUeXBlKTtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJldmVudF9pZFwiXSA9IGZsb3dUeXBlU3RyaW5nICsgXCI6XCIgKyBjdXJyZW5jeSArIFwiOlwiICsgaXRlbVR5cGUgKyBcIjpcIiArIGl0ZW1JZDtcbiAgICAgICAgICAgICAgICBldmVudERpY3RbXCJjYXRlZ29yeVwiXSA9IEdBRXZlbnRzLkNhdGVnb3J5UmVzb3VyY2U7XG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiYW1vdW50XCJdID0gYW1vdW50O1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFJFU09VUkNFIGV2ZW50OiB7Y3VycmVuY3k6XCIgKyBjdXJyZW5jeSArIFwiLCBhbW91bnQ6XCIgKyBhbW91bnQgKyBcIiwgaXRlbVR5cGU6XCIgKyBpdGVtVHlwZSArIFwiLCBpdGVtSWQ6XCIgKyBpdGVtSWQgKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMTpzdHJpbmcsIHByb2dyZXNzaW9uMDI6c3RyaW5nLCBwcm9ncmVzc2lvbjAzOnN0cmluZywgc2NvcmU6bnVtYmVyLCBzZW5kU2NvcmU6Ym9vbGVhbiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmc6c3RyaW5nID0gR0FFdmVudHMucHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyhwcm9ncmVzc2lvblN0YXR1cyk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZSBldmVudCBwYXJhbXNcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1cywgcHJvZ3Jlc3Npb24wMSwgcHJvZ3Jlc3Npb24wMiwgcHJvZ3Jlc3Npb24wMykpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUhUVFBBcGkuaW5zdGFuY2Uuc2VuZFNka0Vycm9yRXZlbnQoRUdBU2RrRXJyb3JUeXBlLlJlamVjdGVkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBlbXB0eSBldmVudERhdGFcbiAgICAgICAgICAgICAgICB2YXIgZXZlbnREaWN0Ontba2V5OnN0cmluZ106IGFueX0gPSB7fTtcblxuICAgICAgICAgICAgICAgIC8vIFByb2dyZXNzaW9uIGlkZW50aWZpZXJcbiAgICAgICAgICAgICAgICB2YXIgcHJvZ3Jlc3Npb25JZGVudGlmaWVyOnN0cmluZztcblxuICAgICAgICAgICAgICAgIGlmICghcHJvZ3Jlc3Npb24wMilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHByb2dyZXNzaW9uSWRlbnRpZmllciA9IHByb2dyZXNzaW9uMDE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKCFwcm9ncmVzc2lvbjAzKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcHJvZ3Jlc3Npb25JZGVudGlmaWVyID0gcHJvZ3Jlc3Npb24wMSArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMiArIFwiOlwiICsgcHJvZ3Jlc3Npb24wMztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREaWN0W1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeVByb2dyZXNzaW9uO1xuICAgICAgICAgICAgICAgIGV2ZW50RGljdFtcImV2ZW50X2lkXCJdID0gcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIjpcIiArIHByb2dyZXNzaW9uSWRlbnRpZmllcjtcblxuICAgICAgICAgICAgICAgIC8vIEF0dGVtcHRcbiAgICAgICAgICAgICAgICB2YXIgYXR0ZW1wdF9udW06bnVtYmVyID0gMDtcblxuICAgICAgICAgICAgICAgIC8vIEFkZCBzY29yZSBpZiBzcGVjaWZpZWQgYW5kIHN0YXR1cyBpcyBub3Qgc3RhcnRcbiAgICAgICAgICAgICAgICBpZiAoc2VuZFNjb3JlICYmIHByb2dyZXNzaW9uU3RhdHVzICE9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlN0YXJ0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREaWN0W1wic2NvcmVcIl0gPSBzY29yZTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDb3VudCBhdHRlbXB0cyBvbiBlYWNoIHByb2dyZXNzaW9uIGZhaWwgYW5kIHBlcnNpc3RcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkZhaWwpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBJbmNyZW1lbnQgYXR0ZW1wdCBudW1iZXJcbiAgICAgICAgICAgICAgICAgICAgR0FTdGF0ZS5pbmNyZW1lbnRQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gaW5jcmVtZW50IGFuZCBhZGQgYXR0ZW1wdF9udW0gb24gY29tcGxldGUgYW5kIGRlbGV0ZSBwZXJzaXN0ZWRcbiAgICAgICAgICAgICAgICBpZiAocHJvZ3Jlc3Npb25TdGF0dXMgPT09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gSW5jcmVtZW50IGF0dGVtcHQgbnVtYmVyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5jcmVtZW50UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBldmVudFxuICAgICAgICAgICAgICAgICAgICBhdHRlbXB0X251bSA9IEdBU3RhdGUuZ2V0UHJvZ3Jlc3Npb25Ucmllcyhwcm9ncmVzc2lvbklkZW50aWZpZXIpO1xuICAgICAgICAgICAgICAgICAgICBldmVudERpY3RbXCJhdHRlbXB0X251bVwiXSA9IGF0dGVtcHRfbnVtO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENsZWFyXG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuY2xlYXJQcm9ncmVzc2lvblRyaWVzKHByb2dyZXNzaW9uSWRlbnRpZmllcik7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREaWN0KTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREaWN0LCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIFBST0dSRVNTSU9OIGV2ZW50OiB7c3RhdHVzOlwiICsgcHJvZ3Jlc3Npb25TdGF0dXNTdHJpbmcgKyBcIiwgcHJvZ3Jlc3Npb24wMTpcIiArIHByb2dyZXNzaW9uMDEgKyBcIiwgcHJvZ3Jlc3Npb24wMjpcIiArIHByb2dyZXNzaW9uMDIgKyBcIiwgcHJvZ3Jlc3Npb24wMzpcIiArIHByb2dyZXNzaW9uMDMgKyBcIiwgc2NvcmU6XCIgKyBzY29yZSArIFwiLCBhdHRlbXB0OlwiICsgYXR0ZW1wdF9udW0gKyBcIn1cIik7XG5cbiAgICAgICAgICAgICAgICAvLyBTZW5kIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGljdCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkRGVzaWduRXZlbnQoZXZlbnRJZDpzdHJpbmcsIHZhbHVlOm51bWJlciwgc2VuZFZhbHVlOmJvb2xlYW4sIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gVmFsaWRhdGVcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGVzaWduRXZlbnQoZXZlbnRJZCwgdmFsdWUpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRTZGtFcnJvckV2ZW50KEVHQVNka0Vycm9yVHlwZS5SZWplY3RlZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZW1wdHkgZXZlbnREYXRhXG4gICAgICAgICAgICAgICAgdmFyIGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9ID0ge307XG5cbiAgICAgICAgICAgICAgICAvLyBBcHBlbmQgZXZlbnQgc3BlY2lmaWNzXG4gICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPSBHQUV2ZW50cy5DYXRlZ29yeURlc2lnbjtcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJldmVudF9pZFwiXSA9IGV2ZW50SWQ7XG5cbiAgICAgICAgICAgICAgICBpZihzZW5kVmFsdWUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJ2YWx1ZVwiXSA9IHZhbHVlO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEFkZCBjdXN0b20gZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERpbWVuc2lvbnNUb0V2ZW50KGV2ZW50RGF0YSk7XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRGaWVsZHNUb0V2ZW50KGV2ZW50RGF0YSwgR0FTdGF0ZS52YWxpZGF0ZUFuZENsZWFuQ3VzdG9tRmllbGRzKGZpZWxkcykpO1xuXG4gICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkFkZCBERVNJR04gZXZlbnQ6IHtldmVudElkOlwiICsgZXZlbnRJZCArIFwiLCB2YWx1ZTpcIiArIHZhbHVlICsgXCJ9XCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShldmVudERhdGEpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSwgbWVzc2FnZTpzdHJpbmcsIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0pOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdBU3RhdGUuaXNFdmVudFN1Ym1pc3Npb25FbmFibGVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgdmFyIHNldmVyaXR5U3RyaW5nOnN0cmluZyA9IEdBRXZlbnRzLmVycm9yU2V2ZXJpdHlUb1N0cmluZyhzZXZlcml0eSk7XG5cbiAgICAgICAgICAgICAgICAvLyBWYWxpZGF0ZVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFcnJvckV2ZW50KHNldmVyaXR5LCBtZXNzYWdlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBSFRUUEFwaS5pbnN0YW5jZS5zZW5kU2RrRXJyb3JFdmVudChFR0FTZGtFcnJvclR5cGUuUmVqZWN0ZWQpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gQ3JlYXRlIGVtcHR5IGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgIHZhciBldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuXG4gICAgICAgICAgICAgICAgLy8gQXBwZW5kIGV2ZW50IHNwZWNpZmljc1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlFcnJvcjtcbiAgICAgICAgICAgICAgICBldmVudERhdGFbXCJzZXZlcml0eVwiXSA9IHNldmVyaXR5U3RyaW5nO1xuICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcIm1lc3NhZ2VcIl0gPSBtZXNzYWdlO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGN1c3RvbSBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRGltZW5zaW9uc1RvRXZlbnQoZXZlbnREYXRhKTtcblxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEZpZWxkc1RvRXZlbnQoZXZlbnREYXRhLCBHQVN0YXRlLnZhbGlkYXRlQW5kQ2xlYW5DdXN0b21GaWVsZHMoZmllbGRzKSk7XG5cbiAgICAgICAgICAgICAgICAvLyBMb2dcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiQWRkIEVSUk9SIGV2ZW50OiB7c2V2ZXJpdHk6XCIgKyBzZXZlcml0eVN0cmluZyArIFwiLCBtZXNzYWdlOlwiICsgbWVzc2FnZSArIFwifVwiKTtcblxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gc3RvcmVcbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRFdmVudFRvU3RvcmUoZXZlbnREYXRhKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBwcm9jZXNzRXZlbnRzKGNhdGVnb3J5OnN0cmluZywgcGVyZm9ybUNsZWFuVXA6Ym9vbGVhbik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR0FTdGF0ZS5pc0V2ZW50U3VibWlzc2lvbkVuYWJsZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyB0aHJvdyBuZXcgRXJyb3IoXCJwcm9jZXNzRXZlbnRzIG5vdCBpbXBsZW1lbnRlZFwiKTtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRlbnRpZmllcjpzdHJpbmcgPSBHQVV0aWxpdGllcy5jcmVhdGVHdWlkKCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2xlYW51cFxuICAgICAgICAgICAgICAgICAgICBpZihwZXJmb3JtQ2xlYW5VcClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuY2xlYW51cEV2ZW50cygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIFByZXBhcmUgU1FMXG4gICAgICAgICAgICAgICAgICAgIHZhciBzZWxlY3RBcmdzOkFycmF5PFtzdHJpbmcsIEVHQVN0b3JlQXJnc09wZXJhdG9yLCBzdHJpbmddPiA9IFtdO1xuICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIHVwZGF0ZVdoZXJlQXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgdXBkYXRlV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCBcIm5ld1wiXSk7XG4gICAgICAgICAgICAgICAgICAgIGlmKGNhdGVnb3J5KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBzZWxlY3RBcmdzLnB1c2goW1wiY2F0ZWdvcnlcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGNhdGVnb3J5XSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB1cGRhdGVXaGVyZUFyZ3MucHVzaChbXCJjYXRlZ29yeVwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5FcXVhbCwgY2F0ZWdvcnldKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIHZhciB1cGRhdGVTZXRBcmdzOkFycmF5PFtzdHJpbmcsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgcmVxdWVzdElkZW50aWZpZXJdKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZXZlbnRzIHRvIHByb2Nlc3NcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50czpBcnJheTx7W2tleTpzdHJpbmddOiBhbnl9PiA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncyk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgZm9yIGVycm9ycyBvciBlbXB0eVxuICAgICAgICAgICAgICAgICAgICBpZighZXZlbnRzIHx8IGV2ZW50cy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHF1ZXVlOiBObyBldmVudHMgdG8gc2VuZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLnVwZGF0ZVNlc3Npb25TdG9yZSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQ2hlY2sgbnVtYmVyIG9mIGV2ZW50cyBhbmQgdGFrZSBzb21lIGFjdGlvbiBpZiB0aGVyZSBhcmUgdG9vIG1hbnk/XG4gICAgICAgICAgICAgICAgICAgIGlmKGV2ZW50cy5sZW5ndGggPiBHQUV2ZW50cy5NYXhFdmVudENvdW50KVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBNYWtlIGEgbGltaXQgcmVxdWVzdFxuICAgICAgICAgICAgICAgICAgICAgICAgZXZlbnRzID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuRXZlbnRzLCBzZWxlY3RBcmdzLCB0cnVlLCBHQUV2ZW50cy5NYXhFdmVudENvdW50KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmKCFldmVudHMpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBHZXQgbGFzdCB0aW1lc3RhbXBcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYXN0SXRlbTp7W2tleTpzdHJpbmddOiBhbnl9ID0gZXZlbnRzW2V2ZW50cy5sZW5ndGggLSAxXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYXN0VGltZXN0YW1wOnN0cmluZyA9IGxhc3RJdGVtW1wiY2xpZW50X3RzXCJdIGFzIHN0cmluZztcblxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0QXJncy5wdXNoKFtcImNsaWVudF90c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbCwgbGFzdFRpbWVzdGFtcF0pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBTZWxlY3QgYWdhaW5cbiAgICAgICAgICAgICAgICAgICAgICAgIGV2ZW50cyA9IEdBU3RvcmUuc2VsZWN0KEVHQVN0b3JlLkV2ZW50cywgc2VsZWN0QXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWV2ZW50cylcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIHVwZGF0ZVdoZXJlQXJncy5wdXNoKFtcImNsaWVudF90c1wiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5MZXNzT3JFcXVhbCwgbGFzdFRpbWVzdGFtcF0pO1xuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gTG9nXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogU2VuZGluZyBcIiArIGV2ZW50cy5sZW5ndGggKyBcIiBldmVudHMuXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIFNldCBzdGF0dXMgb2YgZXZlbnRzIHRvICdzZW5kaW5nJyAoYWxzbyBjaGVjayBmb3IgZXJyb3IpXG4gICAgICAgICAgICAgICAgICAgIGlmICghR0FTdG9yZS51cGRhdGUoRUdBU3RvcmUuRXZlbnRzLCB1cGRhdGVTZXRBcmdzLCB1cGRhdGVXaGVyZUFyZ3MpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBDcmVhdGUgcGF5bG9hZCBkYXRhIGZyb20gZXZlbnRzXG4gICAgICAgICAgICAgICAgICAgIHZhciBwYXlsb2FkQXJyYXk6QXJyYXk8e1trZXk6c3RyaW5nXTogYW55fT4gPSBbXTtcblxuICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBpOm51bWJlciA9IDA7IGkgPCBldmVudHMubGVuZ3RoOyArK2kpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciBldjp7W2tleTpzdHJpbmddOiBhbnl9ID0gZXZlbnRzW2ldO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50RGljdCA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoZXZbXCJldmVudFwiXSkpO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKGV2ZW50RGljdC5sZW5ndGggIT0gMClcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXlsb2FkQXJyYXkucHVzaChldmVudERpY3QpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnNlbmRFdmVudHNJbkFycmF5KHBheWxvYWRBcnJheSwgcmVxdWVzdElkZW50aWZpZXIsIEdBRXZlbnRzLnByb2Nlc3NFdmVudHNDYWxsYmFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIGR1cmluZyBQcm9jZXNzRXZlbnRzKCk6IFwiICsgZS5zdGFjayk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRzQ2FsbGJhY2socmVzcG9uc2VFbnVtOkVHQUhUVFBBcGlSZXNwb25zZSwgZGF0YURpY3Q6e1trZXk6c3RyaW5nXTogYW55fSwgIHJlcXVlc3RJZDpzdHJpbmcsIGV2ZW50Q291bnQ6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciByZXF1ZXN0SWRXaGVyZUFyZ3M6QXJyYXk8W3N0cmluZywgRUdBU3RvcmVBcmdzT3BlcmF0b3IsIHN0cmluZ10+ID0gW107XG4gICAgICAgICAgICAgICAgcmVxdWVzdElkV2hlcmVBcmdzLnB1c2goW1wic3RhdHVzXCIsIEVHQVN0b3JlQXJnc09wZXJhdG9yLkVxdWFsLCByZXF1ZXN0SWRdKTtcblxuICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLk9rKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gRGVsZXRlIGV2ZW50c1xuICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJFdmVudCBxdWV1ZTogXCIgKyBldmVudENvdW50ICsgXCIgZXZlbnRzIHNlbnQuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAvLyBQdXQgZXZlbnRzIGJhY2sgKE9ubHkgaW4gY2FzZSBvZiBubyByZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAgaWYocmVzcG9uc2VFbnVtID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuTm9SZXNwb25zZSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHNldEFyZ3M6QXJyYXk8W3N0cmluZywgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldEFyZ3MucHVzaChbXCJzdGF0dXNcIiwgXCJuZXdcIl0pO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IEZhaWxlZCB0byBzZW5kIGV2ZW50cyB0byBjb2xsZWN0b3IgLSBSZXRyeWluZyBuZXh0IHRpbWVcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnVwZGF0ZShFR0FTdG9yZS5FdmVudHMsIHNldEFyZ3MsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBEZWxldGUgZXZlbnRzIChXaGVuIGdldHRpbmcgc29tZSBhbndzZXIgYmFjayBhbHdheXMgYXNzdW1lIGV2ZW50cyBhcmUgcHJvY2Vzc2VkKVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYoZGF0YURpY3QpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGpzb246YW55O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjb3VudDpudW1iZXIgPSAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvcihsZXQgaiBpbiBkYXRhRGljdClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKGNvdW50ID09IDApXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGpzb24gPSBkYXRhRGljdFtqXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICArK2NvdW50O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHJlc3BvbnNlRW51bSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLkJhZFJlcXVlc3QgJiYganNvbi5jb25zdHJ1Y3RvciA9PT0gQXJyYXkpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiRXZlbnQgcXVldWU6IFwiICsgZXZlbnRDb3VudCArIFwiIGV2ZW50cyBzZW50LiBcIiArIGNvdW50ICsgXCIgZXZlbnRzIGZhaWxlZCBHQSBzZXJ2ZXIgdmFsaWRhdGlvbi5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJFdmVudCBxdWV1ZTogRmFpbGVkIHRvIHNlbmQgZXZlbnRzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkV2ZW50IHF1ZXVlOiBGYWlsZWQgdG8gc2VuZCBldmVudHMuXCIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5FdmVudHMsIHJlcXVlc3RJZFdoZXJlQXJncyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGNsZWFudXBFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBU3RvcmUudXBkYXRlKEVHQVN0b3JlLkV2ZW50cywgW1tcInN0YXR1c1wiICwgXCJuZXdcIl1dKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZml4TWlzc2luZ1Nlc3Npb25FbmRFdmVudHMoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vIEdldCBhbGwgc2Vzc2lvbnMgdGhhdCBhcmUgbm90IGN1cnJlbnRcbiAgICAgICAgICAgICAgICB2YXIgYXJnczpBcnJheTxbc3RyaW5nLCBFR0FTdG9yZUFyZ3NPcGVyYXRvciwgc3RyaW5nXT4gPSBbXTtcbiAgICAgICAgICAgICAgICBhcmdzLnB1c2goW1wic2Vzc2lvbl9pZFwiLCBFR0FTdG9yZUFyZ3NPcGVyYXRvci5Ob3RFcXVhbCwgR0FTdGF0ZS5nZXRTZXNzaW9uSWQoKV0pO1xuXG4gICAgICAgICAgICAgICAgdmFyIHNlc3Npb25zOkFycmF5PHtba2V5OnN0cmluZ106IGFueX0+ID0gR0FTdG9yZS5zZWxlY3QoRUdBU3RvcmUuU2Vzc2lvbnMsIGFyZ3MpO1xuXG4gICAgICAgICAgICAgICAgaWYgKCFzZXNzaW9ucyB8fCBzZXNzaW9ucy5sZW5ndGggPT0gMClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKHNlc3Npb25zLmxlbmd0aCArIFwiIHNlc3Npb24ocykgbG9jYXRlZCB3aXRoIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnQuXCIpO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIG1pc3Npbmcgc2Vzc2lvbl9lbmQgZXZlbnRzXG4gICAgICAgICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBzZXNzaW9ucy5sZW5ndGg7ICsraSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXNzaW9uRW5kRXZlbnQ6e1trZXk6c3RyaW5nXTogYW55fSA9IEpTT04ucGFyc2UoR0FVdGlsaXRpZXMuZGVjb2RlNjQoc2Vzc2lvbnNbaV1bXCJldmVudFwiXSBhcyBzdHJpbmcpKTtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50X3RzOm51bWJlciA9IHNlc3Npb25FbmRFdmVudFtcImNsaWVudF90c1wiXSBhcyBudW1iZXI7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzdGFydF90czpudW1iZXIgPSBzZXNzaW9uc1tpXVtcInRpbWVzdGFtcFwiXSBhcyBudW1iZXI7XG5cbiAgICAgICAgICAgICAgICAgICAgdmFyIGxlbmd0aDpudW1iZXIgPSBldmVudF90cyAtIHN0YXJ0X3RzO1xuICAgICAgICAgICAgICAgICAgICBsZW5ndGggPSBNYXRoLm1heCgwLCBsZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmQoXCJmaXhNaXNzaW5nU2Vzc2lvbkVuZEV2ZW50cyBsZW5ndGggY2FsY3VsYXRlZDogXCIgKyBsZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgICAgIHNlc3Npb25FbmRFdmVudFtcImNhdGVnb3J5XCJdID0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kO1xuICAgICAgICAgICAgICAgICAgICBzZXNzaW9uRW5kRXZlbnRbXCJsZW5ndGhcIl0gPSBsZW5ndGg7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRvIHN0b3JlXG4gICAgICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZEV2ZW50VG9TdG9yZShzZXNzaW9uRW5kRXZlbnQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgYWRkRXZlbnRUb1N0b3JlKGV2ZW50RGF0YTp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRXZlbnRTdWJtaXNzaW9uRW5hYmxlZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAvLyBDaGVjayBpZiB3ZSBhcmUgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgICAgICBpZiAoIUdBU3RhdGUuaXNJbml0aWFsaXplZCgpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBhZGQgZXZlbnQ6IFNESyBpcyBub3QgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIC8vIENoZWNrIGRiIHNpemUgbGltaXRzICgxMG1iKVxuICAgICAgICAgICAgICAgICAgICAvLyBJZiBkYXRhYmFzZSBpcyB0b28gbGFyZ2UgYmxvY2sgYWxsIGV4Y2VwdCB1c2VyLCBzZXNzaW9uIGFuZCBidXNpbmVzc1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdG9yZS5pc1N0b3JlVG9vTGFyZ2VGb3JFdmVudHMoKSAmJiAhR0FVdGlsaXRpZXMuc3RyaW5nTWF0Y2goZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gYXMgc3RyaW5nLCAvXih1c2VyfHNlc3Npb25fZW5kfGJ1c2luZXNzKSQvKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkRhdGFiYXNlIHRvbyBsYXJnZS4gRXZlbnQgaGFzIGJlZW4gYmxvY2tlZC5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICAvLyBHZXQgZGVmYXVsdCBhbm5vdGF0aW9uc1xuICAgICAgICAgICAgICAgICAgICB2YXIgZXY6e1trZXk6c3RyaW5nXTogYW55fSA9IEdBU3RhdGUuZ2V0RXZlbnRBbm5vdGF0aW9ucygpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBqc29uIHdpdGggb25seSBkZWZhdWx0IGFubm90YXRpb25zXG4gICAgICAgICAgICAgICAgICAgIHZhciBqc29uRGVmYXVsdHM6c3RyaW5nID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoZXYpKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBNZXJnZSB3aXRoIGV2ZW50RGF0YVxuICAgICAgICAgICAgICAgICAgICBmb3IobGV0IGUgaW4gZXZlbnREYXRhKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBldltlXSA9IGV2ZW50RGF0YVtlXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBqc29uIHN0cmluZyByZXByZXNlbnRhdGlvblxuICAgICAgICAgICAgICAgICAgICB2YXIganNvbjpzdHJpbmcgPSBKU09OLnN0cmluZ2lmeShldik7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gb3V0cHV0IGlmIFZFUkJPU0UgTE9HIGVuYWJsZWRcblxuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5paShcIkV2ZW50IGFkZGVkIHRvIHF1ZXVlOiBcIiArIGpzb24pO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vIEFkZCB0byBzdG9yZVxuICAgICAgICAgICAgICAgICAgICB2YXIgdmFsdWVzOntba2V5OnN0cmluZ106IGFueX0gPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wic3RhdHVzXCJdID0gXCJuZXdcIjtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiY2F0ZWdvcnlcIl0gPSBldltcImNhdGVnb3J5XCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gZXZbXCJzZXNzaW9uX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJjbGllbnRfdHNcIl0gPSBldltcImNsaWVudF90c1wiXTtcbiAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBHQVV0aWxpdGllcy5lbmNvZGU2NChKU09OLnN0cmluZ2lmeShldikpO1xuXG4gICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuaW5zZXJ0KEVHQVN0b3JlLkV2ZW50cywgdmFsdWVzKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyBBZGQgdG8gc2Vzc2lvbiBzdG9yZSBpZiBub3QgbGFzdFxuICAgICAgICAgICAgICAgICAgICBpZiAoZXZlbnREYXRhW1wiY2F0ZWdvcnlcIl0gPT0gR0FFdmVudHMuQ2F0ZWdvcnlTZXNzaW9uRW5kKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmRlbGV0ZShFR0FTdG9yZS5TZXNzaW9ucywgW1tcInNlc3Npb25faWRcIiwgRUdBU3RvcmVBcmdzT3BlcmF0b3IuRXF1YWwsIGV2W1wic2Vzc2lvbl9pZFwiXSBhcyBzdHJpbmddXSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXMgPSB7fTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInNlc3Npb25faWRcIl0gPSBldltcInNlc3Npb25faWRcIl07XG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJ0aW1lc3RhbXBcIl0gPSBHQVN0YXRlLmdldFNlc3Npb25TdGFydCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdmFsdWVzW1wiZXZlbnRcIl0gPSBqc29uRGVmYXVsdHM7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLmluc2VydChFR0FTdG9yZS5TZXNzaW9ucywgdmFsdWVzLCB0cnVlLCBcInNlc3Npb25faWRcIik7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBpZihHQVN0b3JlLmlzU3RvcmFnZUF2YWlsYWJsZSgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0b3JlLnNhdmUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCAoZSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmUoXCJhZGRFdmVudFRvU3RvcmU6IGVycm9yXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5lKGUuc3RhY2spO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgdXBkYXRlU2Vzc2lvblN0b3JlKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2YWx1ZXM6e1trZXk6c3RyaW5nXTogYW55fSA9IHt9O1xuICAgICAgICAgICAgICAgICAgICB2YWx1ZXNbXCJzZXNzaW9uX2lkXCJdID0gR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQ7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcInRpbWVzdGFtcFwiXSA9IEdBU3RhdGUuZ2V0U2Vzc2lvblN0YXJ0KCk7XG4gICAgICAgICAgICAgICAgICAgIHZhbHVlc1tcImV2ZW50XCJdID0gR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoR0FTdGF0ZS5nZXRFdmVudEFubm90YXRpb25zKCkpKTtcbiAgICAgICAgICAgICAgICAgICAgR0FTdG9yZS5pbnNlcnQoRUdBU3RvcmUuU2Vzc2lvbnMsIHZhbHVlcywgdHJ1ZSwgXCJzZXNzaW9uX2lkXCIpO1xuXG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RvcmUuaXNTdG9yYWdlQXZhaWxhYmxlKCkpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RvcmUuc2F2ZSgpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBhZGREaW1lbnNpb25zVG9FdmVudChldmVudERhdGE6e1trZXk6c3RyaW5nXTogYW55fSk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIWV2ZW50RGF0YSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gYWRkIHRvIGRpY3QgKGlmIG5vdCBuaWwpXG4gICAgICAgICAgICAgICAgaWYgKEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAxKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBldmVudERhdGFbXCJjdXN0b21fMDFcIl0gPSBHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMSgpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDIoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50RGF0YVtcImN1c3RvbV8wMlwiXSA9IEdBU3RhdGUuZ2V0Q3VycmVudEN1c3RvbURpbWVuc2lvbjAyKCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChHQVN0YXRlLmdldEN1cnJlbnRDdXN0b21EaW1lbnNpb24wMygpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tXzAzXCJdID0gR0FTdGF0ZS5nZXRDdXJyZW50Q3VzdG9tRGltZW5zaW9uMDMoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIGFkZEZpZWxkc1RvRXZlbnQoZXZlbnREYXRhOntba2V5OnN0cmluZ106IGFueX0sIGZpZWxkczp7W2tleTpzdHJpbmddOiBhbnl9KTp2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIWV2ZW50RGF0YSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZihmaWVsZHMgJiYgT2JqZWN0LmtleXMoZmllbGRzKS5sZW5ndGggPiAwKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgZXZlbnREYXRhW1wiY3VzdG9tX2ZpZWxkc1wiXSA9IGZpZWxkcztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJlc291cmNlRmxvd1R5cGVUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlLlNvdXJjZSB8fCB2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlW0VHQVJlc291cmNlRmxvd1R5cGUuU291cmNlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlNvdXJjZVwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQVJlc291cmNlRmxvd1R5cGUuU2luayB8fCB2YWx1ZSA9PSBFR0FSZXNvdXJjZUZsb3dUeXBlW0VHQVJlc291cmNlRmxvd1R5cGUuU2lua10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTaW5rXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIlwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcHJvZ3Jlc3Npb25TdGF0dXNUb1N0cmluZyh2YWx1ZTphbnkpOiBzdHJpbmdcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZih2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydCB8fCB2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1c1tFR0FQcm9ncmVzc2lvblN0YXR1cy5TdGFydF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJTdGFydFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlIHx8IHZhbHVlID09IEVHQVByb2dyZXNzaW9uU3RhdHVzW0VHQVByb2dyZXNzaW9uU3RhdHVzLkNvbXBsZXRlXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIkNvbXBsZXRlXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBUHJvZ3Jlc3Npb25TdGF0dXMuRmFpbCB8fCB2YWx1ZSA9PSBFR0FQcm9ncmVzc2lvblN0YXR1c1tFR0FQcm9ncmVzc2lvblN0YXR1cy5GYWlsXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBcIkZhaWxcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBlcnJvclNldmVyaXR5VG9TdHJpbmcodmFsdWU6YW55KTogc3RyaW5nXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5EZWJ1ZyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuRGVidWddKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZGVidWdcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkluZm8gfHwgdmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eVtFR0FFcnJvclNldmVyaXR5LkluZm9dKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaW5mb1wiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmKHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHkuV2FybmluZyB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuV2FybmluZ10pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJ3YXJuaW5nXCI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYodmFsdWUgPT0gRUdBRXJyb3JTZXZlcml0eS5FcnJvciB8fCB2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5W0VHQUVycm9yU2V2ZXJpdHkuRXJyb3JdKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiZXJyb3JcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZih2YWx1ZSA9PSBFR0FFcnJvclNldmVyaXR5LkNyaXRpY2FsIHx8IHZhbHVlID09IEVHQUVycm9yU2V2ZXJpdHlbRUdBRXJyb3JTZXZlcml0eS5Dcml0aWNhbF0pXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJjcml0aWNhbFwiO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJcIjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG59XG4iLCJtb2R1bGUgZ2FtZWFuYWx5dGljc1xue1xuICAgIGV4cG9ydCBtb2R1bGUgdGhyZWFkaW5nXG4gICAge1xuICAgICAgICBpbXBvcnQgR0FMb2dnZXIgPSBnYW1lYW5hbHl0aWNzLmxvZ2dpbmcuR0FMb2dnZXI7XG4gICAgICAgIGltcG9ydCBHQVV0aWxpdGllcyA9IGdhbWVhbmFseXRpY3MudXRpbGl0aWVzLkdBVXRpbGl0aWVzO1xuICAgICAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlQXJnc09wZXJhdG9yID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZUFyZ3NPcGVyYXRvcjtcbiAgICAgICAgaW1wb3J0IEVHQVN0b3JlID0gZ2FtZWFuYWx5dGljcy5zdG9yZS5FR0FTdG9yZTtcbiAgICAgICAgaW1wb3J0IEdBU3RhdGUgPSBnYW1lYW5hbHl0aWNzLnN0YXRlLkdBU3RhdGU7XG4gICAgICAgIGltcG9ydCBHQUV2ZW50cyA9IGdhbWVhbmFseXRpY3MuZXZlbnRzLkdBRXZlbnRzO1xuICAgICAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcblxuICAgICAgICBleHBvcnQgY2xhc3MgR0FUaHJlYWRpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgcmVhZG9ubHkgaW5zdGFuY2U6R0FUaHJlYWRpbmcgPSBuZXcgR0FUaHJlYWRpbmcoKTtcbiAgICAgICAgICAgIHB1YmxpYyByZWFkb25seSBibG9ja3M6UHJpb3JpdHlRdWV1ZTxUaW1lZEJsb2NrPiA9IG5ldyBQcmlvcml0eVF1ZXVlPFRpbWVkQmxvY2s+KDxJQ29tcGFyZXI8bnVtYmVyPj57XG4gICAgICAgICAgICAgICAgY29tcGFyZTogKHg6bnVtYmVyLCB5Om51bWJlcikgPT4ge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4geCAtIHk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBwcml2YXRlIHJlYWRvbmx5IGlkMlRpbWVkQmxvY2tNYXA6e1trZXk6bnVtYmVyXTogVGltZWRCbG9ja30gPSB7fTtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1blRpbWVvdXRJZDpudW1iZXI7XG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyByZWFkb25seSBUaHJlYWRXYWl0VGltZUluTXM6bnVtYmVyID0gMTAwMDtcbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIFByb2Nlc3NFdmVudHNJbnRlcnZhbEluU2Vjb25kczpudW1iZXIgPSA4LjA7XG4gICAgICAgICAgICBwcml2YXRlIGtlZXBSdW5uaW5nOmJvb2xlYW47XG4gICAgICAgICAgICBwcml2YXRlIGlzUnVubmluZzpib29sZWFuO1xuXG4gICAgICAgICAgICBwcml2YXRlIGNvbnN0cnVjdG9yKClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiSW5pdGlhbGl6aW5nIEdBIHRocmVhZC4uLlwiKTtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdGFydFRocmVhZCgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIGNyZWF0ZVRpbWVkQmxvY2soZGVsYXlJblNlY29uZHM6bnVtYmVyID0gMCk6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgdGltZTpEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICB0aW1lLnNldFNlY29uZHModGltZS5nZXRTZWNvbmRzKCkgKyBkZWxheUluU2Vjb25kcyk7XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gbmV3IFRpbWVkQmxvY2sodGltZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRpbWVkQmxvY2s7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRhc2tPbkdBVGhyZWFkKHRhc2tCbG9jazooKSA9PiB2b2lkLCBkZWxheUluU2Vjb25kczpudW1iZXIgPSAwKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciB0aW1lOkRhdGUgPSBuZXcgRGF0ZSgpO1xuICAgICAgICAgICAgICAgIHRpbWUuc2V0U2Vjb25kcyh0aW1lLmdldFNlY29uZHMoKSArIGRlbGF5SW5TZWNvbmRzKTtcblxuICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2sgPSBuZXcgVGltZWRCbG9jayh0aW1lKTtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLmJsb2NrID0gdGFza0Jsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXBbdGltZWRCbG9jay5pZF0gPSB0aW1lZEJsb2NrO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmFkZFRpbWVkQmxvY2sodGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgcGVyZm9ybVRpbWVkQmxvY2tPbkdBVGhyZWFkKHRpbWVkQmxvY2s6VGltZWRCbG9jayk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW3RpbWVkQmxvY2suaWRdID0gdGltZWRCbG9jaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5hZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2spO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwdWJsaWMgc3RhdGljIHNjaGVkdWxlVGltZXIoaW50ZXJ2YWw6bnVtYmVyLCBjYWxsYmFjazooKSA9PiB2b2lkKTogbnVtYmVyXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHRpbWU6RGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgdGltZS5zZXRTZWNvbmRzKHRpbWUuZ2V0U2Vjb25kcygpICsgaW50ZXJ2YWwpO1xuXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IG5ldyBUaW1lZEJsb2NrKHRpbWUpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSBjYWxsYmFjaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW3RpbWVkQmxvY2suaWRdID0gdGltZWRCbG9jaztcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5hZGRUaW1lZEJsb2NrKHRpbWVkQmxvY2spO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHRpbWVkQmxvY2suaWQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0VGltZWRCbG9ja0J5SWQoYmxvY2tJZGVudGlmaWVyOm51bWJlcik6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmxvY2tJZGVudGlmaWVyIGluIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuaWQyVGltZWRCbG9ja01hcFtibG9ja0lkZW50aWZpZXJdXG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHVibGljIHN0YXRpYyBlbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5rZWVwUnVubmluZyA9IHRydWU7XG5cbiAgICAgICAgICAgICAgICBpZighR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuaW5zdGFuY2UuaXNSdW5uaW5nID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc2NoZWR1bGVUaW1lcihHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMsIEdBVGhyZWFkaW5nLnByb2Nlc3NFdmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbkFuZFN0b3BRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pc0luaXRpYWxpemVkKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiRW5kaW5nIHNlc3Npb24uXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zdG9wRXZlbnRRdWV1ZSgpO1xuICAgICAgICAgICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSAmJiBHQVN0YXRlLnNlc3Npb25Jc1N0YXJ0ZWQoKSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvbkVuZEV2ZW50KCk7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IDA7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc3RvcEV2ZW50UXVldWUoKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmtlZXBSdW5uaW5nID0gZmFsc2U7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgaWdub3JlVGltZXIoYmxvY2tJZGVudGlmaWVyOm51bWJlcik6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoYmxvY2tJZGVudGlmaWVyIGluIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlkMlRpbWVkQmxvY2tNYXApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5pbnN0YW5jZS5pZDJUaW1lZEJsb2NrTWFwW2Jsb2NrSWRlbnRpZmllcl0uaWdub3JlID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWw6bnVtYmVyKTogdm9pZFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChpbnRlcnZhbCA+IDApXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5Qcm9jZXNzRXZlbnRzSW50ZXJ2YWxJblNlY29uZHMgPSBpbnRlcnZhbDtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgYWRkVGltZWRCbG9jayh0aW1lZEJsb2NrOlRpbWVkQmxvY2spOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdGhpcy5ibG9ja3MuZW5xdWV1ZSh0aW1lZEJsb2NrLmRlYWRsaW5lLmdldFRpbWUoKSwgdGltZWRCbG9jayk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHJ1bigpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgY2xlYXJUaW1lb3V0KEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCk7XG5cbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB0aW1lZEJsb2NrOlRpbWVkQmxvY2s7XG5cbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCh0aW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuZ2V0TmV4dEJsb2NrKCkpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoIXRpbWVkQmxvY2suaWdub3JlKVxuICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmKHRpbWVkQmxvY2suYXN5bmMpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZighdGltZWRCbG9jay5ydW5uaW5nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLnJ1bm5pbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jaygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jaygpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCA9IHNldFRpbWVvdXQoR0FUaHJlYWRpbmcucnVuLCBHQVRocmVhZGluZy5UaHJlYWRXYWl0VGltZUluTXMpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIChlKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShcIkVycm9yIG9uIEdBIHRocmVhZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuZShlLnN0YWNrKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FMb2dnZXIuZChcIkVuZGluZyBHQSB0aHJlYWRcIik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHByaXZhdGUgc3RhdGljIHN0YXJ0VGhyZWFkKCk6IHZvaWRcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQUxvZ2dlci5kKFwiU3RhcnRpbmcgR0EgdGhyZWFkXCIpO1xuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnJ1blRpbWVvdXRJZCA9IHNldFRpbWVvdXQoR0FUaHJlYWRpbmcucnVuLCAwKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcHJpdmF0ZSBzdGF0aWMgZ2V0TmV4dEJsb2NrKCk6IFRpbWVkQmxvY2tcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgbm93OkRhdGUgPSBuZXcgRGF0ZSgpO1xuXG4gICAgICAgICAgICAgICAgaWYgKEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5oYXNJdGVtcygpICYmIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCkuZGVhZGxpbmUuZ2V0VGltZSgpIDw9IG5vdy5nZXRUaW1lKCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MucGVlaygpLmFzeW5jKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5ibG9ja3MucGVlaygpLnJ1bm5pbmcpXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5wZWVrKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIEdBVGhyZWFkaW5nLmluc3RhbmNlLmJsb2Nrcy5kZXF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gR0FUaHJlYWRpbmcuaW5zdGFuY2UuYmxvY2tzLmRlcXVldWUoKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBwcml2YXRlIHN0YXRpYyBwcm9jZXNzRXZlbnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FFdmVudHMucHJvY2Vzc0V2ZW50cyhcIlwiLCB0cnVlKTtcbiAgICAgICAgICAgICAgICBpZihHQVRocmVhZGluZy5pbnN0YW5jZS5rZWVwUnVubmluZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnNjaGVkdWxlVGltZXIoR0FUaHJlYWRpbmcuUHJvY2Vzc0V2ZW50c0ludGVydmFsSW5TZWNvbmRzLCBHQVRocmVhZGluZy5wcm9jZXNzRXZlbnRRdWV1ZSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2VcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmluc3RhbmNlLmlzUnVubmluZyA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbn1cbiIsIm1vZHVsZSBnYW1lYW5hbHl0aWNzXG57XG4gICAgaW1wb3J0IEdBVGhyZWFkaW5nID0gZ2FtZWFuYWx5dGljcy50aHJlYWRpbmcuR0FUaHJlYWRpbmc7XG4gICAgaW1wb3J0IFRpbWVkQmxvY2sgPSBnYW1lYW5hbHl0aWNzLnRocmVhZGluZy5UaW1lZEJsb2NrO1xuICAgIGltcG9ydCBHQUxvZ2dlciA9IGdhbWVhbmFseXRpY3MubG9nZ2luZy5HQUxvZ2dlcjtcbiAgICBpbXBvcnQgR0FTdG9yZSA9IGdhbWVhbmFseXRpY3Muc3RvcmUuR0FTdG9yZTtcbiAgICBpbXBvcnQgR0FTdGF0ZSA9IGdhbWVhbmFseXRpY3Muc3RhdGUuR0FTdGF0ZTtcbiAgICBpbXBvcnQgR0FIVFRQQXBpID0gZ2FtZWFuYWx5dGljcy5odHRwLkdBSFRUUEFwaTtcbiAgICBpbXBvcnQgR0FEZXZpY2UgPSBnYW1lYW5hbHl0aWNzLmRldmljZS5HQURldmljZTtcbiAgICBpbXBvcnQgR0FWYWxpZGF0b3IgPSBnYW1lYW5hbHl0aWNzLnZhbGlkYXRvcnMuR0FWYWxpZGF0b3I7XG4gICAgaW1wb3J0IEVHQUhUVFBBcGlSZXNwb25zZSA9IGdhbWVhbmFseXRpY3MuaHR0cC5FR0FIVFRQQXBpUmVzcG9uc2U7XG4gICAgaW1wb3J0IEdBVXRpbGl0aWVzID0gZ2FtZWFuYWx5dGljcy51dGlsaXRpZXMuR0FVdGlsaXRpZXM7XG4gICAgaW1wb3J0IEdBRXZlbnRzID0gZ2FtZWFuYWx5dGljcy5ldmVudHMuR0FFdmVudHM7XG5cbiAgICBleHBvcnQgY2xhc3MgR2FtZUFuYWx5dGljc1xuICAgIHtcbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgaW5pdFRpbWVkQmxvY2tJZDpudW1iZXIgPSAtMTtcbiAgICAgICAgcHVibGljIHN0YXRpYyBtZXRob2RNYXA6e1tpZDpzdHJpbmddOiAoLi4uYXJnczogYW55W10pID0+IHZvaWR9ID0ge307XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpbml0KCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudG91Y2goKTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDEnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMiddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydjb25maWd1cmVBdmFpbGFibGVSZXNvdXJjZUN1cnJlbmNpZXMnXSA9IEdhbWVBbmFseXRpY3MuY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlSXRlbVR5cGVzO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUJ1aWxkJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUJ1aWxkO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZVNka0dhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uJ10gPSBHYW1lQW5hbHl0aWNzLmNvbmZpZ3VyZUdhbWVFbmdpbmVWZXJzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2NvbmZpZ3VyZVVzZXJJZCddID0gR2FtZUFuYWx5dGljcy5jb25maWd1cmVVc2VySWQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnaW5pdGlhbGl6ZSddID0gR2FtZUFuYWx5dGljcy5pbml0aWFsaXplO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEJ1c2luZXNzRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkQnVzaW5lc3NFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRSZXNvdXJjZUV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZFJlc291cmNlRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnYWRkUHJvZ3Jlc3Npb25FdmVudCddID0gR2FtZUFuYWx5dGljcy5hZGRQcm9ncmVzc2lvbkV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZERlc2lnbkV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZERlc2lnbkV2ZW50O1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZEVycm9yRXZlbnQnXSA9IEdhbWVBbmFseXRpY3MuYWRkRXJyb3JFdmVudDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydhZGRFcnJvckV2ZW50J10gPSBHYW1lQW5hbHl0aWNzLmFkZEVycm9yRXZlbnQ7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZEluZm9Mb2cnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZEluZm9Mb2c7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZFZlcmJvc2VMb2cnXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZFZlcmJvc2VMb2c7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsnc2V0RW5hYmxlZE1hbnVhbFNlc3Npb25IYW5kbGluZyddID0gR2FtZUFuYWx5dGljcy5zZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ3NldEVuYWJsZWRFdmVudFN1Ym1pc3Npb24nXSA9IEdhbWVBbmFseXRpY3Muc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRDdXN0b21EaW1lbnNpb24wMSddID0gR2FtZUFuYWx5dGljcy5zZXRDdXN0b21EaW1lbnNpb24wMTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRDdXN0b21EaW1lbnNpb24wMiddID0gR2FtZUFuYWx5dGljcy5zZXRDdXN0b21EaW1lbnNpb24wMjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRDdXN0b21EaW1lbnNpb24wMyddID0gR2FtZUFuYWx5dGljcy5zZXRDdXN0b21EaW1lbnNpb24wMztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzZXRFdmVudFByb2Nlc3NJbnRlcnZhbCddID0gR2FtZUFuYWx5dGljcy5zZXRFdmVudFByb2Nlc3NJbnRlcnZhbDtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydzdGFydFNlc3Npb24nXSA9IEdhbWVBbmFseXRpY3Muc3RhcnRTZXNzaW9uO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2VuZFNlc3Npb24nXSA9IEdhbWVBbmFseXRpY3MuZW5kU2Vzc2lvbjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydvblN0b3AnXSA9IEdhbWVBbmFseXRpY3Mub25TdG9wO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ29uUmVzdW1lJ10gPSBHYW1lQW5hbHl0aWNzLm9uUmVzdW1lO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5tZXRob2RNYXBbJ2FkZFJlbW90ZUNvbmZpZ3NMaXN0ZW5lciddID0gR2FtZUFuYWx5dGljcy5hZGRSZW1vdGVDb25maWdzTGlzdGVuZXI7XG4gICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFsncmVtb3ZlUmVtb3RlQ29uZmlnc0xpc3RlbmVyJ10gPSBHYW1lQW5hbHl0aWNzLnJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcjtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRSZW1vdGVDb25maWdzVmFsdWVBc1N0cmluZyddID0gR2FtZUFuYWx5dGljcy5nZXRSZW1vdGVDb25maWdzVmFsdWVBc1N0cmluZztcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydpc1JlbW90ZUNvbmZpZ3NSZWFkeSddID0gR2FtZUFuYWx5dGljcy5pc1JlbW90ZUNvbmZpZ3NSZWFkeTtcbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubWV0aG9kTWFwWydnZXRSZW1vdGVDb25maWdzQ29udGVudEFzU3RyaW5nJ10gPSBHYW1lQW5hbHl0aWNzLmdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmc7XG5cbiAgICAgICAgICAgIGlmKHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnICYmIHR5cGVvZiB3aW5kb3dbJ0dhbWVBbmFseXRpY3MnXSAhPT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvd1snR2FtZUFuYWx5dGljcyddWydxJ10gIT09ICd1bmRlZmluZWQnKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIHZhciBxOmFueVtdID0gd2luZG93WydHYW1lQW5hbHl0aWNzJ11bJ3EnXTtcbiAgICAgICAgICAgICAgICBmb3IgKGxldCBpIGluIHEpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLmdhQ29tbWFuZC5hcHBseShudWxsLCBxW2ldKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdhQ29tbWFuZCguLi5hcmdzOiBhbnlbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgaWYoYXJncy5sZW5ndGggPiAwKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKGFyZ3NbMF0gaW4gZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKGFyZ3MubGVuZ3RoID4gMSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLm1ldGhvZE1hcFthcmdzWzBdXS5hcHBseShudWxsLCBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChhcmdzLCAxKSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBnYW1lYW5hbHl0aWNzLkdhbWVBbmFseXRpY3MubWV0aG9kTWFwW2FyZ3NbMF1dKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zOkFycmF5PHN0cmluZz4gPSBbXSk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgY3VzdG9tIGRpbWVuc2lvbnMgbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMShjdXN0b21EaW1lbnNpb25zKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBjb25maWd1cmVBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoY3VzdG9tRGltZW5zaW9uczpBcnJheTxzdHJpbmc+ID0gW10pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQXZhaWxhYmxlIGN1c3RvbSBkaW1lbnNpb25zIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoY3VzdG9tRGltZW5zaW9ucyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKGN1c3RvbURpbWVuc2lvbnM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZihHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkF2YWlsYWJsZSBjdXN0b20gZGltZW5zaW9ucyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAzKGN1c3RvbURpbWVuc2lvbnMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUF2YWlsYWJsZVJlc291cmNlQ3VycmVuY2llcyhyZXNvdXJjZUN1cnJlbmNpZXM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgcmVzb3VyY2UgY3VycmVuY2llcyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlUmVzb3VyY2VDdXJyZW5jaWVzKHJlc291cmNlQ3VycmVuY2llcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlQXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXM6QXJyYXk8c3RyaW5nPiA9IFtdKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBdmFpbGFibGUgcmVzb3VyY2UgaXRlbSB0eXBlcyBtdXN0IGJlIHNldCBiZWZvcmUgU0RLIGlzIGluaXRpYWxpemVkXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0QXZhaWxhYmxlUmVzb3VyY2VJdGVtVHlwZXMocmVzb3VyY2VJdGVtVHlwZXMpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGNvbmZpZ3VyZUJ1aWxkKGJ1aWxkOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkJ1aWxkIHZlcnNpb24gbXVzdCBiZSBzZXQgYmVmb3JlIFNESyBpcyBpbml0aWFsaXplZC5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUJ1aWxkKGJ1aWxkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgYnVpbGQ6IENhbm5vdCBiZSBudWxsLCBlbXB0eSBvciBhYm92ZSAzMiBsZW5ndGguIFN0cmluZzogXCIgKyBidWlsZCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRCdWlsZChidWlsZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlU2RrR2FtZUVuZ2luZVZlcnNpb24oc2RrR2FtZUVuZ2luZVZlcnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVTZGtXcmFwcGVyVmVyc2lvbihzZGtHYW1lRW5naW5lVmVyc2lvbikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmFsaWRhdGlvbiBmYWlsIC0gY29uZmlndXJlIHNkayB2ZXJzaW9uOiBTZGsgdmVyc2lvbiBub3Qgc3VwcG9ydGVkLiBTdHJpbmc6IFwiICsgc2RrR2FtZUVuZ2luZVZlcnNpb24pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRGV2aWNlLnNka0dhbWVFbmdpbmVWZXJzaW9uID0gc2RrR2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlR2FtZUVuZ2luZVZlcnNpb24oZ2FtZUVuZ2luZVZlcnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKEdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCBmYWxzZSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVFbmdpbmVWZXJzaW9uKGdhbWVFbmdpbmVWZXJzaW9uKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgZ2FtZSBlbmdpbmUgdmVyc2lvbjogR2FtZSBlbmdpbmUgdmVyc2lvbiBub3Qgc3VwcG9ydGVkLiBTdHJpbmc6IFwiICsgZ2FtZUVuZ2luZVZlcnNpb24pO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBRGV2aWNlLmdhbWVFbmdpbmVWZXJzaW9uID0gZ2FtZUVuZ2luZVZlcnNpb247XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgY29uZmlndXJlVXNlcklkKHVJZDpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIGZhbHNlKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJBIGN1c3RvbSB1c2VyIGlkIG11c3QgYmUgc2V0IGJlZm9yZSBTREsgaXMgaW5pdGlhbGl6ZWQuXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVVc2VySWQodUlkKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJWYWxpZGF0aW9uIGZhaWwgLSBjb25maWd1cmUgdXNlcl9pZDogQ2Fubm90IGJlIG51bGwsIGVtcHR5IG9yIGFib3ZlIDY0IGxlbmd0aC4gV2lsbCB1c2UgZGVmYXVsdCB1c2VyX2lkIG1ldGhvZC4gVXNlZCBzdHJpbmc6IFwiICsgdUlkKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0VXNlcklkKHVJZCk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgaW5pdGlhbGl6ZShnYW1lS2V5OnN0cmluZyA9IFwiXCIsIGdhbWVTZWNyZXQ6c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChHYW1lQW5hbHl0aWNzLmlzU2RrUmVhZHkodHJ1ZSwgZmFsc2UpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIlNESyBhbHJlYWR5IGluaXRpYWxpemVkLiBDYW4gb25seSBiZSBjYWxsZWQgb25jZS5cIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZUtleXMoZ2FtZUtleSwgZ2FtZVNlY3JldCkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiU0RLIGZhaWxlZCBpbml0aWFsaXplLiBHYW1lIGtleSBvciBzZWNyZXQga2V5IGlzIGludmFsaWQuIENhbiBvbmx5IGNvbnRhaW4gY2hhcmFjdGVycyBBLXogMC05LCBnYW1lS2V5IGlzIDMyIGxlbmd0aCwgZ2FtZVNlY3JldCBpcyA0MCBsZW5ndGguIEZhaWxlZCBrZXlzIC0gZ2FtZUtleTogXCIgKyBnYW1lS2V5ICsgXCIsIHNlY3JldEtleTogXCIgKyBnYW1lU2VjcmV0KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0S2V5cyhnYW1lS2V5LCBnYW1lU2VjcmV0KTtcblxuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW50ZXJuYWxJbml0aWFsaXplKCk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGltZWRCbG9ja09uR0FUaHJlYWQodGltZWRCbG9jayk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEJ1c2luZXNzRXZlbnQoY3VycmVuY3k6c3RyaW5nID0gXCJcIiwgYW1vdW50Om51bWJlciA9IDAsIGl0ZW1UeXBlOnN0cmluZyA9IFwiXCIsIGl0ZW1JZDpzdHJpbmcgPSBcIlwiLCBjYXJ0VHlwZTpzdHJpbmcgPSBcIlwiLyosIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSovKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgYnVzaW5lc3MgZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIFNlbmQgdG8gZXZlbnRzXG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkQnVzaW5lc3NFdmVudChjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCBjYXJ0VHlwZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZFJlc291cmNlRXZlbnQoZmxvd1R5cGU6RUdBUmVzb3VyY2VGbG93VHlwZSA9IEVHQVJlc291cmNlRmxvd1R5cGUuVW5kZWZpbmVkLCBjdXJyZW5jeTpzdHJpbmcgPSBcIlwiLCBhbW91bnQ6bnVtYmVyID0gMCwgaXRlbVR5cGU6c3RyaW5nID0gXCJcIiwgaXRlbUlkOnN0cmluZyA9IFwiXCIvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCByZXNvdXJjZSBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRSZXNvdXJjZUV2ZW50KGZsb3dUeXBlLCBjdXJyZW5jeSwgYW1vdW50LCBpdGVtVHlwZSwgaXRlbUlkLCB7fSk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUHJvZ3Jlc3Npb25FdmVudChwcm9ncmVzc2lvblN0YXR1czpFR0FQcm9ncmVzc2lvblN0YXR1cyA9IEVHQVByb2dyZXNzaW9uU3RhdHVzLlVuZGVmaW5lZCwgcHJvZ3Jlc3Npb24wMTpzdHJpbmcgPSBcIlwiLCBwcm9ncmVzc2lvbjAyOnN0cmluZyA9IFwiXCIsIHByb2dyZXNzaW9uMDM6c3RyaW5nID0gXCJcIiwgc2NvcmU/OmFueS8qLCBmaWVsZHM6e1tpZDpzdHJpbmddOiBhbnl9ID0ge30qLyk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FEZXZpY2UudXBkYXRlQ29ubmVjdGlvblR5cGUoKTtcblxuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYoIUdhbWVBbmFseXRpY3MuaXNTZGtSZWFkeSh0cnVlLCB0cnVlLCBcIkNvdWxkIG5vdCBhZGQgcHJvZ3Jlc3Npb24gZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgLy8gU2VuZCB0byBldmVudHNcbiAgICAgICAgICAgICAgICB2YXIgc2VuZFNjb3JlOmJvb2xlYW4gPSB0eXBlb2Ygc2NvcmUgPT09IFwibnVtYmVyXCI7XG4gICAgICAgICAgICAgICAgLy8gaWYodHlwZW9mIHNjb3JlID09PSBcIm9iamVjdFwiKVxuICAgICAgICAgICAgICAgIC8vIHtcbiAgICAgICAgICAgICAgICAvLyAgICAgZmllbGRzID0gc2NvcmUgYXMge1tpZDpzdHJpbmddOiBhbnl9O1xuICAgICAgICAgICAgICAgIC8vIH1cbiAgICAgICAgICAgICAgICBHQUV2ZW50cy5hZGRQcm9ncmVzc2lvbkV2ZW50KHByb2dyZXNzaW9uU3RhdHVzLCBwcm9ncmVzc2lvbjAxLCBwcm9ncmVzc2lvbjAyLCBwcm9ncmVzc2lvbjAzLCBzZW5kU2NvcmUgPyBzY29yZSA6IDAsIHNlbmRTY29yZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZERlc2lnbkV2ZW50KGV2ZW50SWQ6c3RyaW5nLCB2YWx1ZT86YW55LyosIGZpZWxkczp7W2lkOnN0cmluZ106IGFueX0gPSB7fSovKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQURldmljZS51cGRhdGVDb25uZWN0aW9uVHlwZSgpO1xuXG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZighR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBkZXNpZ24gZXZlbnRcIikpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhciBzZW5kVmFsdWU6Ym9vbGVhbiA9IHR5cGVvZiB2YWx1ZSA9PT0gXCJudW1iZXJcIjtcbiAgICAgICAgICAgICAgICAvLyBpZih0eXBlb2YgdmFsdWUgPT09IFwib2JqZWN0XCIpXG4gICAgICAgICAgICAgICAgLy8ge1xuICAgICAgICAgICAgICAgIC8vICAgICBmaWVsZHMgPSB2YWx1ZSBhcyB7W2lkOnN0cmluZ106IGFueX07XG4gICAgICAgICAgICAgICAgLy8gfVxuICAgICAgICAgICAgICAgIEdBRXZlbnRzLmFkZERlc2lnbkV2ZW50KGV2ZW50SWQsIHNlbmRWYWx1ZSA/IHZhbHVlICA6IDAsIHNlbmRWYWx1ZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGFkZEVycm9yRXZlbnQoc2V2ZXJpdHk6RUdBRXJyb3JTZXZlcml0eSA9IEVHQUVycm9yU2V2ZXJpdHkuVW5kZWZpbmVkLCBtZXNzYWdlOnN0cmluZyA9IFwiXCIvKiwgZmllbGRzOntbaWQ6c3RyaW5nXTogYW55fSA9IHt9Ki8pOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBRGV2aWNlLnVwZGF0ZUNvbm5lY3Rpb25UeXBlKCk7XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR2FtZUFuYWx5dGljcy5pc1Nka1JlYWR5KHRydWUsIHRydWUsIFwiQ291bGQgbm90IGFkZCBlcnJvciBldmVudFwiKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FFdmVudHMuYWRkRXJyb3JFdmVudChzZXZlcml0eSwgbWVzc2FnZSwge30pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEVuYWJsZWRJbmZvTG9nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLnNldEluZm9Mb2coZmxhZyk7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbmZvIGxvZ2dpbmcgZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluZm8gbG9nZ2luZyBkaXNhYmxlZFwiKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0SW5mb0xvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RW5hYmxlZFZlcmJvc2VMb2coZmxhZzpib29sZWFuID0gZmFsc2UpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmIChmbGFnKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuc2V0VmVyYm9zZUxvZyhmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIlZlcmJvc2UgbG9nZ2luZyBlbmFibGVkXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiVmVyYm9zZSBsb2dnaW5nIGRpc2FibGVkXCIpO1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5zZXRWZXJib3NlTG9nKGZsYWcpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkTWFudWFsU2Vzc2lvbkhhbmRsaW5nKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldE1hbnVhbFNlc3Npb25IYW5kbGluZyhmbGFnKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRFbmFibGVkRXZlbnRTdWJtaXNzaW9uKGZsYWc6Ym9vbGVhbiA9IGZhbHNlKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoZmxhZylcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnKTtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHN1Ym1pc3Npb24gZW5hYmxlZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkV2ZW50IHN1Ym1pc3Npb24gZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0RW5hYmxlZEV2ZW50U3VibWlzc2lvbihmbGFnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uOnN0cmluZyA9IFwiXCIpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UYXNrT25HQVRocmVhZCgoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICghR0FWYWxpZGF0b3IudmFsaWRhdGVEaW1lbnNpb24wMShkaW1lbnNpb24sIEdBU3RhdGUuZ2V0QXZhaWxhYmxlQ3VzdG9tRGltZW5zaW9uczAxKCkpKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhcIkNvdWxkIG5vdCBzZXQgY3VzdG9tMDEgZGltZW5zaW9uIHZhbHVlIHRvICdcIiArIGRpbWVuc2lvbiArIFwiJy4gVmFsdWUgbm90IGZvdW5kIGluIGF2YWlsYWJsZSBjdXN0b20wMSBkaW1lbnNpb24gdmFsdWVzXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIEdBU3RhdGUuc2V0Q3VzdG9tRGltZW5zaW9uMDEoZGltZW5zaW9uKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBzZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb246c3RyaW5nID0gXCJcIik6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FUaHJlYWRpbmcucGVyZm9ybVRhc2tPbkdBVGhyZWFkKCgpID0+XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgaWYgKCFHQVZhbGlkYXRvci52YWxpZGF0ZURpbWVuc2lvbjAyKGRpbWVuc2lvbiwgR0FTdGF0ZS5nZXRBdmFpbGFibGVDdXN0b21EaW1lbnNpb25zMDIoKSkpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci53KFwiQ291bGQgbm90IHNldCBjdXN0b20wMiBkaW1lbnNpb24gdmFsdWUgdG8gJ1wiICsgZGltZW5zaW9uICsgXCInLiBWYWx1ZSBub3QgZm91bmQgaW4gYXZhaWxhYmxlIGN1c3RvbTAyIGRpbWVuc2lvbiB2YWx1ZXNcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5zZXRDdXN0b21EaW1lbnNpb24wMihkaW1lbnNpb24pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIHNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbjpzdHJpbmcgPSBcIlwiKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAoIUdBVmFsaWRhdG9yLnZhbGlkYXRlRGltZW5zaW9uMDMoZGltZW5zaW9uLCBHQVN0YXRlLmdldEF2YWlsYWJsZUN1c3RvbURpbWVuc2lvbnMwMygpKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc2V0IGN1c3RvbTAzIGRpbWVuc2lvbiB2YWx1ZSB0byAnXCIgKyBkaW1lbnNpb24gKyBcIicuIFZhbHVlIG5vdCBmb3VuZCBpbiBhdmFpbGFibGUgY3VzdG9tMDMgZGltZW5zaW9uIHZhbHVlc1wiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLnNldEN1c3RvbURpbWVuc2lvbjAzKGRpbWVuc2lvbik7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc2V0RXZlbnRQcm9jZXNzSW50ZXJ2YWwoaW50ZXJ2YWxJblNlY29uZHM6bnVtYmVyKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5zZXRFdmVudFByb2Nlc3NJbnRlcnZhbChpbnRlcnZhbEluU2Vjb25kcyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgc3RhcnRTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgLy9pZihHQVN0YXRlLmdldFVzZU1hbnVhbFNlc3Npb25IYW5kbGluZygpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICB2YXIgdGltZWRCbG9jazpUaW1lZEJsb2NrID0gR0FUaHJlYWRpbmcuY3JlYXRlVGltZWRCbG9jaygpO1xuICAgICAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MuaW5pdFRpbWVkQmxvY2tJZCA9IHRpbWVkQmxvY2suaWQ7XG4gICAgICAgICAgICAgICAgdGltZWRCbG9jay5ibG9jayA9ICgpID0+XG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZihHQVN0YXRlLmlzRW5hYmxlZCgpICYmIEdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbmRTZXNzaW9uQW5kU3RvcFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLnJlc3VtZVNlc3Npb25BbmRTdGFydFF1ZXVlKCk7XG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZW5kU2Vzc2lvbigpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIC8vaWYoR0FTdGF0ZS5nZXRVc2VNYW51YWxTZXNzaW9uSGFuZGxpbmcoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHYW1lQW5hbHl0aWNzLm9uU3RvcCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBvblN0b3AoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVRocmVhZGluZy5wZXJmb3JtVGFza09uR0FUaHJlYWQoKCkgPT5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0cnlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBVGhyZWFkaW5nLmVuZFNlc3Npb25BbmRTdG9wUXVldWUoKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKEV4Y2VwdGlvbilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIG9uUmVzdW1lKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmNyZWF0ZVRpbWVkQmxvY2soKTtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYXN5bmMgPSB0cnVlO1xuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gdGltZWRCbG9jay5pZDtcbiAgICAgICAgICAgIHRpbWVkQmxvY2suYmxvY2sgPSAoKSA9PlxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdhbWVBbmFseXRpY3MucmVzdW1lU2Vzc2lvbkFuZFN0YXJ0UXVldWUoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIEdBVGhyZWFkaW5nLnBlcmZvcm1UaW1lZEJsb2NrT25HQVRocmVhZCh0aW1lZEJsb2NrKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgZ2V0UmVtb3RlQ29uZmlnc1ZhbHVlQXNTdHJpbmcoa2V5OnN0cmluZywgZGVmYXVsdFZhbHVlOnN0cmluZyA9IG51bGwpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRDb25maWd1cmF0aW9uU3RyaW5nVmFsdWUoa2V5LCBkZWZhdWx0VmFsdWUpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBpc1JlbW90ZUNvbmZpZ3NSZWFkeSgpOmJvb2xlYW5cbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuaXNSZW1vdGVDb25maWdzUmVhZHkoKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHB1YmxpYyBzdGF0aWMgYWRkUmVtb3RlQ29uZmlnc0xpc3RlbmVyKGxpc3RlbmVyOnsgb25SZW1vdGVDb25maWdzVXBkYXRlZDooKSA9PiB2b2lkIH0pOnZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FTdGF0ZS5hZGRSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXIpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyByZW1vdmVSZW1vdGVDb25maWdzTGlzdGVuZXIobGlzdGVuZXI6eyBvblJlbW90ZUNvbmZpZ3NVcGRhdGVkOigpID0+IHZvaWQgfSk6dm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLnJlbW92ZVJlbW90ZUNvbmZpZ3NMaXN0ZW5lcihsaXN0ZW5lcik7XG4gICAgICAgIH1cblxuICAgICAgICBwdWJsaWMgc3RhdGljIGdldFJlbW90ZUNvbmZpZ3NDb250ZW50QXNTdHJpbmcoKTpzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0UmVtb3RlQ29uZmlnc0NvbnRlbnRBc1N0cmluZygpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdJZCgpOnN0cmluZ1xuICAgICAgICB7XG4gICAgICAgICAgICByZXR1cm4gR0FTdGF0ZS5nZXRBQlRlc3RpbmdJZCgpO1xuICAgICAgICB9XG5cbiAgICAgICAgcHVibGljIHN0YXRpYyBnZXRBQlRlc3RpbmdWYXJpYW50SWQoKTpzdHJpbmdcbiAgICAgICAge1xuICAgICAgICAgICAgcmV0dXJuIEdBU3RhdGUuZ2V0QUJUZXN0aW5nVmFyaWFudElkKCk7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpbnRlcm5hbEluaXRpYWxpemUoKTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICBHQVN0YXRlLmVuc3VyZVBlcnNpc3RlZFN0YXRlcygpO1xuICAgICAgICAgICAgR0FTdG9yZS5zZXRJdGVtKEdBU3RhdGUuRGVmYXVsdFVzZXJJZEtleSwgR0FTdGF0ZS5nZXREZWZhdWx0SWQoKSk7XG5cbiAgICAgICAgICAgIEdBU3RhdGUuc2V0SW5pdGlhbGl6ZWQodHJ1ZSk7XG5cbiAgICAgICAgICAgIEdhbWVBbmFseXRpY3MubmV3U2Vzc2lvbigpO1xuXG4gICAgICAgICAgICBpZiAoR0FTdGF0ZS5pc0VuYWJsZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBHQVRocmVhZGluZy5lbnN1cmVFdmVudFF1ZXVlSXNSdW5uaW5nKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBuZXdTZXNzaW9uKCk6IHZvaWRcbiAgICAgICAge1xuICAgICAgICAgICAgR0FMb2dnZXIuaShcIlN0YXJ0aW5nIGEgbmV3IHNlc3Npb24uXCIpO1xuXG4gICAgICAgICAgICAvLyBtYWtlIHN1cmUgdGhlIGN1cnJlbnQgY3VzdG9tIGRpbWVuc2lvbnMgYXJlIHZhbGlkXG4gICAgICAgICAgICBHQVN0YXRlLnZhbGlkYXRlQW5kRml4Q3VycmVudERpbWVuc2lvbnMoKTtcblxuICAgICAgICAgICAgR0FIVFRQQXBpLmluc3RhbmNlLnJlcXVlc3RJbml0KEdBU3RhdGUuaW5zdGFuY2UuY29uZmlnc0hhc2gsIEdhbWVBbmFseXRpY3Muc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2spO1xuICAgICAgICB9XG5cbiAgICAgICAgcHJpdmF0ZSBzdGF0aWMgc3RhcnROZXdTZXNzaW9uQ2FsbGJhY2soaW5pdFJlc3BvbnNlOkVHQUhUVFBBcGlSZXNwb25zZSwgaW5pdFJlc3BvbnNlRGljdDp7W2tleTpzdHJpbmddOiBhbnl9KTogdm9pZFxuICAgICAgICB7XG4gICAgICAgICAgICAvLyBpbml0IGlzIG9rXG4gICAgICAgICAgICBpZigoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuT2sgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZCkgJiYgaW5pdFJlc3BvbnNlRGljdClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAvLyBzZXQgdGhlIHRpbWUgb2Zmc2V0IC0gaG93IG1hbnkgc2Vjb25kcyB0aGUgbG9jYWwgdGltZSBpcyBkaWZmZXJlbnQgZnJvbSBzZXJ2ZXJ0aW1lXG4gICAgICAgICAgICAgICAgdmFyIHRpbWVPZmZzZXRTZWNvbmRzOm51bWJlciA9IDA7XG4gICAgICAgICAgICAgICAgaWYoaW5pdFJlc3BvbnNlRGljdFtcInNlcnZlcl90c1wiXSlcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXJUczpudW1iZXIgPSBpbml0UmVzcG9uc2VEaWN0W1wic2VydmVyX3RzXCJdIGFzIG51bWJlcjtcbiAgICAgICAgICAgICAgICAgICAgdGltZU9mZnNldFNlY29uZHMgPSBHQVN0YXRlLmNhbGN1bGF0ZVNlcnZlclRpbWVPZmZzZXQoc2VydmVyVHMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1widGltZV9vZmZzZXRcIl0gPSB0aW1lT2Zmc2V0U2Vjb25kcztcblxuICAgICAgICAgICAgICAgIGlmKGluaXRSZXNwb25zZSAhPSBFR0FIVFRQQXBpUmVzcG9uc2UuQ3JlYXRlZClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjdXJyZW50U2RrQ29uZmlnOntba2V5OnN0cmluZ106IGFueX0gPSBHQVN0YXRlLmdldFNka0NvbmZpZygpO1xuICAgICAgICAgICAgICAgICAgICAvLyB1c2UgY2FjaGVkIGlmIG5vdCBDcmVhdGVkXG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc1wiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJjb25maWdzX2hhc2hcIl0pXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzX2hhc2hcIl0gPSBjdXJyZW50U2RrQ29uZmlnW1wiY29uZmlnc19oYXNoXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl9pZFwiXSlcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5pdFJlc3BvbnNlRGljdFtcImFiX2lkXCJdID0gY3VycmVudFNka0NvbmZpZ1tcImFiX2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGlmKGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdKVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA9IGN1cnJlbnRTZGtDb25maWdbXCJhYl92YXJpYW50X2lkXCJdO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jb25maWdzSGFzaCA9IGluaXRSZXNwb25zZURpY3RbXCJjb25maWdzX2hhc2hcIl0gPyBpbml0UmVzcG9uc2VEaWN0W1wiY29uZmlnc19oYXNoXCJdIDogXCJcIjtcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmFiSWQgPSBpbml0UmVzcG9uc2VEaWN0W1wiYWJfaWRcIl0gPyBpbml0UmVzcG9uc2VEaWN0W1wiYWJfaWRcIl0gOiBcIlwiO1xuICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2UuYWJWYXJpYW50SWQgPSBpbml0UmVzcG9uc2VEaWN0W1wiYWJfdmFyaWFudF9pZFwiXSA/IGluaXRSZXNwb25zZURpY3RbXCJhYl92YXJpYW50X2lkXCJdIDogXCJcIjtcblxuICAgICAgICAgICAgICAgIC8vIGluc2VydCBuZXcgY29uZmlnIGluIHNxbCBsaXRlIGNyb3NzIHNlc3Npb24gc3RvcmFnZVxuICAgICAgICAgICAgICAgIEdBU3RvcmUuc2V0SXRlbShHQVN0YXRlLlNka0NvbmZpZ0NhY2hlZEtleSwgR0FVdGlsaXRpZXMuZW5jb2RlNjQoSlNPTi5zdHJpbmdpZnkoaW5pdFJlc3BvbnNlRGljdCkpKTtcblxuICAgICAgICAgICAgICAgIC8vIHNldCBuZXcgY29uZmlnIGFuZCBjYWNoZSBpbiBtZW1vcnlcbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZ0NhY2hlZCA9IGluaXRSZXNwb25zZURpY3Q7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPSBpbml0UmVzcG9uc2VEaWN0O1xuXG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmKGluaXRSZXNwb25zZSA9PSBFR0FIVFRQQXBpUmVzcG9uc2UuVW5hdXRob3JpemVkKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJJbml0aWFsaXplIFNESyBmYWlsZWQgLSBVbmF1dGhvcml6ZWRcIik7XG4gICAgICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5pbml0QXV0aG9yaXplZCA9IGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIC8vIGxvZyB0aGUgc3RhdHVzIGlmIG5vIGNvbm5lY3Rpb25cbiAgICAgICAgICAgICAgICBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Ob1Jlc3BvbnNlIHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLlJlcXVlc3RUaW1lb3V0KVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gbm8gcmVzcG9uc2UuIENvdWxkIGJlIG9mZmxpbmUgb3IgdGltZW91dC5cIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYoaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuQmFkUmVzcG9uc2UgfHwgaW5pdFJlc3BvbnNlID09PSBFR0FIVFRQQXBpUmVzcG9uc2UuSnNvbkVuY29kZUZhaWxlZCB8fCBpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5Kc29uRGVjb2RlRmFpbGVkKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIuaShcIkluaXQgY2FsbCAoc2Vzc2lvbiBzdGFydCkgZmFpbGVkIC0gYmFkIHJlc3BvbnNlLiBDb3VsZCBiZSBiYWQgcmVzcG9uc2UgZnJvbSBwcm94eSBvciBHQSBzZXJ2ZXJzLlwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZihpbml0UmVzcG9uc2UgPT09IEVHQUhUVFBBcGlSZXNwb25zZS5CYWRSZXF1ZXN0IHx8IGluaXRSZXNwb25zZSA9PT0gRUdBSFRUUEFwaVJlc3BvbnNlLlVua25vd25SZXNwb25zZUNvZGUpXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSBiYWQgcmVxdWVzdCBvciB1bmtub3duIHJlc3BvbnNlLlwiKTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyBpbml0IGNhbGwgZmFpbGVkIChwZXJoYXBzIG9mZmxpbmUpXG4gICAgICAgICAgICAgICAgaWYoR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWcgPT0gbnVsbClcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIGlmKEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnQ2FjaGVkICE9IG51bGwpXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLmkoXCJJbml0IGNhbGwgKHNlc3Npb24gc3RhcnQpIGZhaWxlZCAtIHVzaW5nIGNhY2hlZCBpbml0IHZhbHVlcy5cIik7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBzZXQgbGFzdCBjcm9zcyBzZXNzaW9uIHN0b3JlZCBjb25maWcgaW5pdCB2YWx1ZXNcbiAgICAgICAgICAgICAgICAgICAgICAgIEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnID0gR0FTdGF0ZS5pbnN0YW5jZS5zZGtDb25maWdDYWNoZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZVxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBkZWZhdWx0IGluaXQgdmFsdWVzLlwiKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IGluaXQgdmFsdWVzXG4gICAgICAgICAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNka0NvbmZpZyA9IEdBU3RhdGUuaW5zdGFuY2Uuc2RrQ29uZmlnRGVmYXVsdDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBHQUxvZ2dlci5pKFwiSW5pdCBjYWxsIChzZXNzaW9uIHN0YXJ0KSBmYWlsZWQgLSB1c2luZyBjYWNoZWQgaW5pdCB2YWx1ZXMuXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLmluaXRBdXRob3JpemVkID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gc2V0IG9mZnNldCBpbiBzdGF0ZSAobWVtb3J5KSBmcm9tIGN1cnJlbnQgY29uZmlnIChjb25maWcgY291bGQgYmUgZnJvbSBjYWNoZSBldGMuKVxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5jbGllbnRTZXJ2ZXJUaW1lT2Zmc2V0ID0gR0FTdGF0ZS5nZXRTZGtDb25maWcoKVtcInRpbWVfb2Zmc2V0XCJdID8gR0FTdGF0ZS5nZXRTZGtDb25maWcoKVtcInRpbWVfb2Zmc2V0XCJdIGFzIG51bWJlciA6IDA7XG5cbiAgICAgICAgICAgIC8vIHBvcHVsYXRlIGNvbmZpZ3VyYXRpb25zXG4gICAgICAgICAgICBHQVN0YXRlLnBvcHVsYXRlQ29uZmlndXJhdGlvbnMoR0FTdGF0ZS5nZXRTZGtDb25maWcoKSk7XG5cbiAgICAgICAgICAgIC8vIGlmIFNESyBpcyBkaXNhYmxlZCBpbiBjb25maWdcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncoXCJDb3VsZCBub3Qgc3RhcnQgc2Vzc2lvbjogU0RLIGlzIGRpc2FibGVkLlwiKTtcbiAgICAgICAgICAgICAgICAvLyBzdG9wIGV2ZW50IHF1ZXVlXG4gICAgICAgICAgICAgICAgLy8gKyBtYWtlIHN1cmUgaXQncyBhYmxlIHRvIHJlc3RhcnQgaWYgYW5vdGhlciBzZXNzaW9uIGRldGVjdHMgaXQncyBlbmFibGVkIGFnYWluXG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuc3RvcEV2ZW50UXVldWUoKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR0FUaHJlYWRpbmcuZW5zdXJlRXZlbnRRdWV1ZUlzUnVubmluZygpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBnZW5lcmF0ZSB0aGUgbmV3IHNlc3Npb25cbiAgICAgICAgICAgIHZhciBuZXdTZXNzaW9uSWQ6c3RyaW5nID0gR0FVdGlsaXRpZXMuY3JlYXRlR3VpZCgpO1xuXG4gICAgICAgICAgICAvLyBTZXQgc2Vzc2lvbiBpZFxuICAgICAgICAgICAgR0FTdGF0ZS5pbnN0YW5jZS5zZXNzaW9uSWQgPSBuZXdTZXNzaW9uSWQ7XG5cbiAgICAgICAgICAgIC8vIFNldCBzZXNzaW9uIHN0YXJ0XG4gICAgICAgICAgICBHQVN0YXRlLmluc3RhbmNlLnNlc3Npb25TdGFydCA9IEdBU3RhdGUuZ2V0Q2xpZW50VHNBZGp1c3RlZCgpO1xuXG4gICAgICAgICAgICAvLyBBZGQgc2Vzc2lvbiBzdGFydCBldmVudFxuICAgICAgICAgICAgR0FFdmVudHMuYWRkU2Vzc2lvblN0YXJ0RXZlbnQoKTtcblxuICAgICAgICAgICAgdmFyIHRpbWVkQmxvY2s6VGltZWRCbG9jayA9IEdBVGhyZWFkaW5nLmdldFRpbWVkQmxvY2tCeUlkKEdhbWVBbmFseXRpY3MuaW5pdFRpbWVkQmxvY2tJZCk7XG5cbiAgICAgICAgICAgIGlmKHRpbWVkQmxvY2sgIT0gbnVsbClcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB0aW1lZEJsb2NrLnJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5pbml0VGltZWRCbG9ja0lkID0gLTE7XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyByZXN1bWVTZXNzaW9uQW5kU3RhcnRRdWV1ZSgpOiB2b2lkXG4gICAgICAgIHtcbiAgICAgICAgICAgIGlmKCFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBHQUxvZ2dlci5pKFwiUmVzdW1pbmcgc2Vzc2lvbi5cIik7XG4gICAgICAgICAgICBpZighR0FTdGF0ZS5zZXNzaW9uSXNTdGFydGVkKCkpXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgR2FtZUFuYWx5dGljcy5uZXdTZXNzaW9uKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBwcml2YXRlIHN0YXRpYyBpc1Nka1JlYWR5KG5lZWRzSW5pdGlhbGl6ZWQ6Ym9vbGVhbiwgd2Fybjpib29sZWFuID0gdHJ1ZSwgbWVzc2FnZTpzdHJpbmcgPSBcIlwiKTogYm9vbGVhblxuICAgICAgICB7XG4gICAgICAgICAgICBpZihtZXNzYWdlKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlICsgXCI6IFwiO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBJcyBTREsgaW5pdGlhbGl6ZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzSW5pdGlhbGl6ZWQoKSlcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBpZiAod2FybilcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIEdBTG9nZ2VyLncobWVzc2FnZSArIFwiU0RLIGlzIG5vdCBpbml0aWFsaXplZFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gSXMgU0RLIGVuYWJsZWRcbiAgICAgICAgICAgIGlmIChuZWVkc0luaXRpYWxpemVkICYmICFHQVN0YXRlLmlzRW5hYmxlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTREsgaXMgZGlzYWJsZWRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIElzIHNlc3Npb24gc3RhcnRlZFxuICAgICAgICAgICAgaWYgKG5lZWRzSW5pdGlhbGl6ZWQgJiYgIUdBU3RhdGUuc2Vzc2lvbklzU3RhcnRlZCgpKVxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGlmICh3YXJuKVxuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgR0FMb2dnZXIudyhtZXNzYWdlICsgXCJTZXNzaW9uIGhhcyBub3Qgc3RhcnRlZCB5ZXRcIik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgfVxufVxuZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmluaXQoKTtcbnZhciBHYW1lQW5hbHl0aWNzID0gZ2FtZWFuYWx5dGljcy5HYW1lQW5hbHl0aWNzLmdhQ29tbWFuZDtcbiJdfQ==
