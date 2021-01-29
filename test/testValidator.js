describe("Validator", function () {
    describe("Currency", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid currency", function() {
            expect(GAValidator.validateCurrency("USD")).toEqual(true);
            expect(GAValidator.validateCurrency("XXX")).toEqual(true);
        });

        it("should be invalid currency", function() {
            expect(GAValidator.validateCurrency("usd")).toEqual(false);
            expect(GAValidator.validateCurrency("US")).toEqual(false);
            expect(GAValidator.validateCurrency("KR")).toEqual(false);
            expect(GAValidator.validateCurrency("USDOLLARS")).toEqual(false);
            expect(GAValidator.validateCurrency("$")).toEqual(false);
            expect(GAValidator.validateCurrency("")).toEqual(false);
            expect(GAValidator.validateCurrency(null)).toEqual(false);
            expect(GAValidator.validateCurrency(undefined)).toEqual(false);
        });
    });

    describe("ResourceCurrencies", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid resource currency", function() {
            expect(GAValidator.validateResourceCurrencies(["gems", "gold"])).toEqual(true);
        });

        it("should be invalid resource currency", function() {
            expect(GAValidator.validateResourceCurrencies(["", "gold"])).toEqual(false);
            expect(GAValidator.validateResourceCurrencies([])).toEqual(false);
            expect(GAValidator.validateResourceCurrencies([null])).toEqual(false);
            expect(GAValidator.validateResourceCurrencies([undefined, "gold"])).toEqual(false);
        });
    });

    describe("ResourceItemTypes", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid resource item types", function() {
            expect(GAValidator.validateResourceItemTypes(["gems", "gold"])).toEqual(true);
        });

        it("should be invalid resource item types", function() {
            expect(GAValidator.validateResourceItemTypes(["", "gold"])).toEqual(false);
            expect(GAValidator.validateResourceItemTypes([])).toEqual(false);
            expect(GAValidator.validateResourceItemTypes([null])).toEqual(false);
            expect(GAValidator.validateResourceItemTypes([undefined, "gold"])).toEqual(false);
        });
    });

    describe("ProgressionEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGAProgressionStatus = gameanalytics.EGAProgressionStatus;

        it("should be valid progression event", function() {
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", "phase_001") == null).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", "") == null).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", null) == null).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "", "") == null).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", undefined, undefined) == null).toEqual(true);
        });

        it("should be invalid progression event", function() {
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "", "") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, null, null) == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, undefined, undefined) == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "", "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", null, "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", undefined, "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "level_001", "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, "level_001", "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, "level_001", "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "level_001", "") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, "level_001", null) == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, "level_001", undefined) == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "", "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, null, "phase_001") == null).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, undefined, "phase_001") == null).toEqual(false);
        });
    });

    describe("BusinessEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid business event", function() {
            expect(GAValidator.validateBusinessEvent("USD", 99, "cartType", "itemType", "itemId") == null).toEqual(true);
            expect(GAValidator.validateBusinessEvent("USD", 99, "", "itemType", "itemId") == null).toEqual(true);
            expect(GAValidator.validateBusinessEvent("USD", 99, null, "itemType", "itemId") == null).toEqual(true);
            expect(GAValidator.validateBusinessEvent("USD", 99, undefined, "itemType", "itemId") == null).toEqual(true);
            expect(GAValidator.validateBusinessEvent("USD", 0, "cartType", "itemType", "itemId") == null).toEqual(true);
        });

        it("should be invalid business event", function() {
            expect(GAValidator.validateBusinessEvent("USD", -99, "cartType", "itemType", "itemId") == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "", "", "itemId") == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "", null, "itemId") == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "", undefined, "itemId") == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "cartType", "itemType", "") == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "cartType", "itemType", null) == null).toEqual(false);
            expect(GAValidator.validateBusinessEvent("USD", 99, "cartType", "itemType", undefined) == null).toEqual(false);
        });
    });

    describe("ResourceEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGAResourceFlowType = gameanalytics.EGAResourceFlowType;
        var GAState = gameanalytics.state.GAState;

        GAState.setAvailableResourceCurrencies(["gems", "gold"]);
        GAState.setAvailableResourceItemTypes(["guns", "powerups"]);

        it("should be valid resource event", function() {
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 100, "guns", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(true);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gold", 100, "powerups", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(true);
        });

        it("should be invalid resource event", function() {
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "iron", 100, "guns", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 100, "cows", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 0, "guns", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", -10, "guns", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, "guns", "", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, "guns", null, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, "guns", undefined, GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, "", "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, null, "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
            expect(GAValidator.validateResourceEvent(EGAResourceFlowType.Sink, "gems", 10, undefined, "item", GAState.getAvailableResourceCurrencies(), GAState.getAvailableResourceItemTypes()) == null).toEqual(false);
        });
    });

    describe("DesignEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid design event", function() {
            expect(GAValidator.validateDesignEvent("name:name") == null).toEqual(true);
            expect(GAValidator.validateDesignEvent("name:name:name") == null).toEqual(true);
            expect(GAValidator.validateDesignEvent("name:name:name:name") == null).toEqual(true);
            expect(GAValidator.validateDesignEvent("name:name:name:name:name") == null).toEqual(true);
            expect(GAValidator.validateDesignEvent("name:name") == null).toEqual(true);
        });

        it("should be invalid design event", function() {
            expect(GAValidator.validateDesignEvent("") == null).toEqual(false);
            expect(GAValidator.validateDesignEvent(null) == null).toEqual(false);
            expect(GAValidator.validateDesignEvent(undefined) == null).toEqual(false);
            expect(GAValidator.validateDesignEvent("name:name:name:name:name:name") == null).toEqual(false);
        });
    });

    describe("ErrorEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGAErrorSeverity = gameanalytics.EGAErrorSeverity;

        it("should be valid error event", function() {
            expect(GAValidator.validateErrorEvent(EGAErrorSeverity.Error, "This is a message") == null).toEqual(true);
            expect(GAValidator.validateErrorEvent(EGAErrorSeverity.Error, "") == null).toEqual(true);
            expect(GAValidator.validateErrorEvent(EGAErrorSeverity.Error, undefined) == null).toEqual(true);
        });

        it("should be invalid error event", function() {
            expect(GAValidator.validateErrorEvent(EGAErrorSeverity.Error, getRandomString(8193)) == null).toEqual(false);
        });
    });

    describe("SdkErrorEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGASdkErrorCategory = gameanalytics.events.EGASdkErrorCategory;
        var EGASdkErrorArea = gameanalytics.events.EGASdkErrorArea;
        var EGASdkErrorAction = gameanalytics.events.EGASdkErrorAction;

        it("should be valid sdk error event", function() {
            expect(GAValidator.validateSdkErrorEvent("c6cfc80ff69d1e7316bf1e0c8194eda6", "e0ae4809f70e2fa96916c7060f417ae53895f18d", EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidFlowType)).toEqual(true);
        });

        it("should be invalid sdk error event", function() {
            expect(GAValidator.validateSdkErrorEvent("", "e0ae4809f70e2fa96916c7060f417ae53895f18d", EGASdkErrorCategory.EventValidation, EGASdkErrorArea.ResourceEvent, EGASdkErrorAction.InvalidFlowType)).toEqual(false);
        });
    });

    describe("CustomDimensions", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid custom dimensions", function() {
            expect(GAValidator.validateCustomDimensions(["abc", "def", "ghi"])).toEqual(true);
        });

        it("should be invalid custom dimensions", function() {
            expect(GAValidator.validateCustomDimensions(["abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def", "abc", "def"])).toEqual(false);
            expect(GAValidator.validateCustomDimensions(["abc", ""])).toEqual(false);
            expect(GAValidator.validateCustomDimensions(["abc", null])).toEqual(false);
            expect(GAValidator.validateCustomDimensions(["abc", undefined])).toEqual(false);
        });
    });

    describe("SdkWrapperVersion", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid sdk wrapper version", function() {
            expect(GAValidator.validateSdkWrapperVersion("unity 1.2.3")).toEqual(true);
            expect(GAValidator.validateSdkWrapperVersion("unity 1233.101.0")).toEqual(true);
            expect(GAValidator.validateSdkWrapperVersion("unreal 1.2.3")).toEqual(true);
        });

        it("should be invalid sdk wrapper version", function() {
            expect(GAValidator.validateSdkWrapperVersion("123")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("test 1.2.x")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unkfalsewn 1.5.6")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unity 1.2.3.4")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("corona1.2.3")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unity x.2.3")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unity 1.x.3")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unity 1.2.x")).toEqual(false);
            expect(GAValidator.validateSdkWrapperVersion("unity 1.2.123456")).toEqual(false);
        });
    });

    describe("Build", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid build", function() {
            expect(GAValidator.validateBuild("alpha 1.2.3")).toEqual(true);
            expect(GAValidator.validateBuild("ALPHA 1.2.3")).toEqual(true);
            expect(GAValidator.validateBuild("TES# sdf.fd3")).toEqual(true);
        });

        it("should be invalid build", function() {
            expect(GAValidator.validateBuild("")).toEqual(false);
            expect(GAValidator.validateBuild(null)).toEqual(false);
            expect(GAValidator.validateBuild(undefined)).toEqual(false);
            expect(GAValidator.validateBuild(getRandomString(40))).toEqual(false);
        });
    });

    describe("EngineVersion", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid engine version", function() {
            expect(GAValidator.validateEngineVersion("unity 1.2.3")).toEqual(true);
            expect(GAValidator.validateEngineVersion("unity 1.2")).toEqual(true);
            expect(GAValidator.validateEngineVersion("unity 1")).toEqual(true);
            expect(GAValidator.validateEngineVersion("unreal 1.2.3")).toEqual(true);
            expect(GAValidator.validateEngineVersion("cocos2d 1.2.3")).toEqual(true);
        });

        it("should be invalid engine version", function() {
            expect(GAValidator.validateEngineVersion("")).toEqual(false);
            expect(GAValidator.validateEngineVersion(null)).toEqual(false);
            expect(GAValidator.validateEngineVersion(undefined)).toEqual(false);
            expect(GAValidator.validateEngineVersion(getRandomString(40))).toEqual(false);
            expect(GAValidator.validateEngineVersion("uni 1.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("unity 123456.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("unity1.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("unity 1.2.3.4")).toEqual(false);
            expect(GAValidator.validateEngineVersion("Unity 1.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("UNITY 1.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("marmalade 1.2.3")).toEqual(false);
            expect(GAValidator.validateEngineVersion("xamarin 1.2.3")).toEqual(false);
        });
    });

    describe("Keys", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var validGameKey = "123456789012345678901234567890ab";
        var validSecretKey = "123456789012345678901234567890123456789a";
        var tooLongKey = "123456789012345678901234567890123456789abcdefg";

        it("should be valid keys", function() {
            expect(GAValidator.validateKeys(validGameKey, validSecretKey)).toEqual(true);
        });

        it("should be invalid keys", function() {
            expect(GAValidator.validateKeys(validGameKey, "")).toEqual(false);
            expect(GAValidator.validateKeys(validGameKey, null)).toEqual(false);
            expect(GAValidator.validateKeys(validGameKey, undefined)).toEqual(false);
            expect(GAValidator.validateKeys(validGameKey, "123")).toEqual(false);
            expect(GAValidator.validateKeys(validGameKey, tooLongKey)).toEqual(false);
            expect(GAValidator.validateKeys("", validSecretKey)).toEqual(false);
            expect(GAValidator.validateKeys(null, validSecretKey)).toEqual(false);
            expect(GAValidator.validateKeys(undefined, validSecretKey)).toEqual(false);
            expect(GAValidator.validateKeys("123", validSecretKey)).toEqual(false);
            expect(GAValidator.validateKeys(tooLongKey, validSecretKey)).toEqual(false);
        });
    });

    describe("EventPartLength", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid event part length", function() {
            expect(GAValidator.validateEventPartLength("sdfdf", false)).toEqual(true);
            expect(GAValidator.validateEventPartLength("", true)).toEqual(true);
            expect(GAValidator.validateEventPartLength(null, true)).toEqual(true);
            expect(GAValidator.validateEventPartLength(undefined, true)).toEqual(true);
            expect(GAValidator.validateEventPartLength(getRandomString(32), true)).toEqual(true);
            expect(GAValidator.validateEventPartLength(getRandomString(40), true)).toEqual(true);
            expect(GAValidator.validateEventPartLength(getRandomString(40), false)).toEqual(true);
        });

        it("should be invalid event part length", function() {
            expect(GAValidator.validateEventPartLength(getRandomString(80), false)).toEqual(false);
            expect(GAValidator.validateEventPartLength(getRandomString(80), true)).toEqual(false);
            expect(GAValidator.validateEventPartLength("", false)).toEqual(false);
            expect(GAValidator.validateEventPartLength(null, false)).toEqual(false);
            expect(GAValidator.validateEventPartLength(undefined, false)).toEqual(false);
        });
    });

    describe("EventPartCharacters", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid event part characters", function() {
            expect(GAValidator.validateEventPartCharacters("sdfdffdgdfg")).toEqual(true);
        });

        it("should be invalid event part characters", function() {
            expect(GAValidator.validateEventPartCharacters("øææ")).toEqual(false);
            expect(GAValidator.validateEventPartCharacters("")).toEqual(false);
            expect(GAValidator.validateEventPartCharacters(null)).toEqual(false);
            expect(GAValidator.validateEventPartCharacters(undefined)).toEqual(false);
            expect(GAValidator.validateEventPartCharacters("*")).toEqual(false);
            expect(GAValidator.validateEventPartCharacters("))&%")).toEqual(false);
        });
    });

    describe("EventIdLength", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid event id length", function() {
            expect(GAValidator.validateEventIdLength(getRandomString(40))).toEqual(true);
            expect(GAValidator.validateEventIdLength(getRandomString(32))).toEqual(true);
            expect(GAValidator.validateEventIdLength("sdfdf")).toEqual(true);
        });

        it("should be invalid event id length", function() {
            expect(GAValidator.validateEventIdLength(getRandomString(80))).toEqual(false);
            expect(GAValidator.validateEventIdLength("")).toEqual(false);
            expect(GAValidator.validateEventIdLength(null)).toEqual(false);
            expect(GAValidator.validateEventIdLength(undefined)).toEqual(false);
        });
    });

    describe("EventIdCharacters", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid event id characters", function() {
            expect(GAValidator.validateEventIdCharacters("GHj:df(g?h d_fk7-58.9)3!47")).toEqual(true);
        });

        it("should be invalid event id characters", function() {
            expect(GAValidator.validateEventIdCharacters("GHj:df(g?h d_fk,7-58.9)3!47")).toEqual(false);
            expect(GAValidator.validateEventIdCharacters("")).toEqual(false);
            expect(GAValidator.validateEventIdCharacters(null)).toEqual(false);
            expect(GAValidator.validateEventIdCharacters(undefined)).toEqual(false);
        });
    });

    describe("ShortString", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid short string", function() {
            expect(GAValidator.validateShortString(getRandomString(32), false)).toEqual(true);
            expect(GAValidator.validateShortString(getRandomString(32), true)).toEqual(true);
            expect(GAValidator.validateShortString(getRandomString(10), false)).toEqual(true);
            expect(GAValidator.validateShortString(getRandomString(10), true)).toEqual(true);
            expect(GAValidator.validateShortString("", true)).toEqual(true);
            expect(GAValidator.validateShortString(null, true)).toEqual(true);
            expect(GAValidator.validateShortString(undefined, true)).toEqual(true);
        });

        it("should be invalid short string", function() {
            expect(GAValidator.validateShortString(getRandomString(40), false)).toEqual(false);
            expect(GAValidator.validateShortString(getRandomString(40), true)).toEqual(false);
            expect(GAValidator.validateShortString("", false)).toEqual(false);
            expect(GAValidator.validateShortString(null, false)).toEqual(false);
            expect(GAValidator.validateShortString(undefined, false)).toEqual(false);
        });
    });

    describe("String", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid string", function() {
            expect(GAValidator.validateString(getRandomString(64), false)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(64), true)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(10), false)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(10), true)).toEqual(true);
            expect(GAValidator.validateString("", true)).toEqual(true);
            expect(GAValidator.validateString(null, true)).toEqual(true);
            expect(GAValidator.validateString(undefined, true)).toEqual(true);
        });

        it("should be invalid string", function() {
            expect(GAValidator.validateString(getRandomString(80), false)).toEqual(false);
            expect(GAValidator.validateString(getRandomString(80), true)).toEqual(false);
            expect(GAValidator.validateString("", false)).toEqual(false);
            expect(GAValidator.validateString(null, false)).toEqual(false);
            expect(GAValidator.validateString(undefined, false)).toEqual(false);
        });
    });

    describe("String", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid string", function() {
            expect(GAValidator.validateString(getRandomString(64), false)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(64), true)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(10), false)).toEqual(true);
            expect(GAValidator.validateString(getRandomString(10), true)).toEqual(true);
            expect(GAValidator.validateString("", true)).toEqual(true);
            expect(GAValidator.validateString(null, true)).toEqual(true);
            expect(GAValidator.validateString(undefined, true)).toEqual(true);
        });

        it("should be invalid string", function() {
            expect(GAValidator.validateString(getRandomString(80), false)).toEqual(false);
            expect(GAValidator.validateString(getRandomString(80), true)).toEqual(false);
            expect(GAValidator.validateString("", false)).toEqual(false);
            expect(GAValidator.validateString(null, false)).toEqual(false);
            expect(GAValidator.validateString(undefined, false)).toEqual(false);
        });
    });

    describe("LongString", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid long string", function() {
            expect(GAValidator.validateLongString(getRandomString(8192), false)).toEqual(true);
            expect(GAValidator.validateLongString(getRandomString(8192), true)).toEqual(true);
            expect(GAValidator.validateLongString(getRandomString(10), false)).toEqual(true);
            expect(GAValidator.validateLongString(getRandomString(10), true)).toEqual(true);
            expect(GAValidator.validateLongString("", true)).toEqual(true);
            expect(GAValidator.validateLongString(null, true)).toEqual(true);
            expect(GAValidator.validateLongString(undefined, true)).toEqual(true);
        });

        it("should be invalid long string", function() {
            expect(GAValidator.validateLongString(getRandomString(8193), false)).toEqual(false);
            expect(GAValidator.validateLongString(getRandomString(8193), true)).toEqual(false);
            expect(GAValidator.validateLongString("", false)).toEqual(false);
            expect(GAValidator.validateLongString(null, false)).toEqual(false);
            expect(GAValidator.validateLongString(undefined, false)).toEqual(false);
        });
    });

    describe("ArrayOfStrings", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid array of strings", function() {
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [getRandomString(3), getRandomString(10), getRandomString(7)])).toEqual(true);
            expect(GAValidator.validateArrayOfStrings(3, 10, true, "test", [])).toEqual(true);
        });

        it("should be invalid array of strings", function() {
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [getRandomString(3), getRandomString(12), getRandomString(7)])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [getRandomString(3), "", getRandomString(7)])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [getRandomString(3), null, getRandomString(7)])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [getRandomString(3), undefined, getRandomString(7)])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(2, 10, false, "test", [getRandomString(3), getRandomString(10), getRandomString(7)])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", [])).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", null)).toEqual(false);
            expect(GAValidator.validateArrayOfStrings(3, 10, false, "test", undefined)).toEqual(false);
        });
    });

    describe("ClientTs", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var GAUtilities = gameanalytics.utilities.GAUtilities;

        it("should be valid client ts", function() {
            expect(GAValidator.validateClientTs(GAUtilities.timeIntervalSince1970())).toEqual(true);
            expect(GAValidator.validateClientTs(4294967295)).toEqual(true);
        });

        it("should be invalid client ts", function() {
            expect(GAValidator.validateClientTs(-4294967295)).toEqual(false);
        });
    });

    describe("UserId", function () {
        var GAValidator = gameanalytics.validators.GAValidator;

        it("should be valid user id", function() {
            expect(GAValidator.validateUserId("fhjkdfghdfjkgh")).toEqual(true);
        });

        it("should be invalid user id", function() {
            expect(GAValidator.validateUserId("")).toEqual(false);
            expect(GAValidator.validateUserId(null)).toEqual(false);
            expect(GAValidator.validateUserId(undefined)).toEqual(false);
        });
    });
});
