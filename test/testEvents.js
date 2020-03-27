describe("Events", function () {
    describe("configureAvailableCustomDimensions01", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureAvailableCustomDimensions01(["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions01")).toEqual(1);
            GameAnalytics("configureAvailableCustomDimensions01", ["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions01")).toEqual(2);
        });
    });

    describe("configureAvailableCustomDimensions02", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureAvailableCustomDimensions02(["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions02")).toEqual(1);
            GameAnalytics("configureAvailableCustomDimensions02", ["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions02")).toEqual(2);
        });
    });

    describe("configureAvailableCustomDimensions03", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureAvailableCustomDimensions03(["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions03")).toEqual(1);
            GameAnalytics("configureAvailableCustomDimensions03", ["ninja", "samurai"]);
            expect(countPatternFoundInBlocks("setAvailableCustomDimensions03")).toEqual(2);
        });
    });

    describe("configureAvailableResourceCurrencies", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureAvailableResourceCurrencies(["gems", "gold"]);
            expect(countPatternFoundInBlocks("setAvailableResourceCurrencies")).toEqual(1);
            GameAnalytics("configureAvailableResourceCurrencies", ["gems", "gold"]);
            expect(countPatternFoundInBlocks("setAvailableResourceCurrencies")).toEqual(2);
        });
    });

    describe("configureAvailableResourceItemTypes", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureAvailableResourceItemTypes(["guns", "powerups"]);
            expect(countPatternFoundInBlocks("setAvailableResourceItemTypes")).toEqual(1);
            GameAnalytics("configureAvailableResourceItemTypes", ["guns", "powerups"]);
            expect(countPatternFoundInBlocks("setAvailableResourceItemTypes")).toEqual(2);
        });
    });

    describe("configureBuild", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureBuild("1.0.0");
            expect(countPatternFoundInBlocks("setBuild")).toEqual(1);
            GameAnalytics("configureBuild", "1.0.0");
            expect(countPatternFoundInBlocks("setBuild")).toEqual(2);
        });
    });

    describe("configureSdkGameEngineVersion", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureSdkGameEngineVersion("unity 1.0.0");
            expect(countPatternFoundInBlocks("GADevice.sdkGameEngineVersion")).toEqual(1);
            GameAnalytics("configureSdkGameEngineVersion", "unity 1.0.0");
            expect(countPatternFoundInBlocks("GADevice.sdkGameEngineVersion")).toEqual(2);
        });
    });

    describe("configureGameEngineVersion", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureGameEngineVersion("unity 1.0.0");
            expect(countPatternFoundInBlocks("GADevice.gameEngineVersion")).toEqual(1);
            GameAnalytics("configureGameEngineVersion", "unity 1.0.0");
            expect(countPatternFoundInBlocks("GADevice.gameEngineVersion")).toEqual(2);
        });
    });

    describe("configureUserId", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.configureUserId("custom_id");
            expect(countPatternFoundInBlocks("setUserId")).toEqual(1);
            GameAnalytics("configureUserId", "custom_id");
            expect(countPatternFoundInBlocks("setUserId")).toEqual(2);
        });
    });

    describe("initialize", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.initialize("gameKey", "secretKey");
            expect(countPatternFoundInBlocks("internalInitialize")).toEqual(1);
            GameAnalytics("initialize", "gameKey", "secretKey");
            expect(countPatternFoundInBlocks("internalInitialize")).toEqual(2);
        });
    });

    describe("addBusinessEvent", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.addBusinessEvent("USD", 100, "itemType", "itemId", "shop");
            expect(countPatternFoundInBlocks("addBusinessEvent")).toEqual(1);
            GameAnalytics("addBusinessEvent", "USD", 100, "itemType", "itemId", "shop");
            expect(countPatternFoundInBlocks("addBusinessEvent")).toEqual(2);
        });
    });

    describe("addResourceEvent", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.addResourceEvent(gameanalytics.EGAResourceFlowType.Sink, "gems", 100, "guns", "bigGun");
            expect(countPatternFoundInBlocks("addResourceEvent")).toEqual(1);
            GameAnalytics("addResourceEvent", "Sink", "gems", 100, "guns", "bigGun");
            expect(countPatternFoundInBlocks("addResourceEvent")).toEqual(2);
        });
    });

    describe("addProgressionEvent", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.addProgressionEvent(gameanalytics.EGAProgressionStatus.Start, "world1", "level1", "phase1", 1000);
            expect(countPatternFoundInBlocks("addProgressionEvent")).toEqual(1);
            GameAnalytics("addProgressionEvent", "Start", "world1", "level1", "phase1", 1000);
            expect(countPatternFoundInBlocks("addProgressionEvent")).toEqual(2);
        });
    });

    describe("addDesignEvent", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.addDesignEvent("eventId:string");
            expect(countPatternFoundInBlocks("addDesignEvent")).toEqual(1);
            GameAnalytics("addDesignEvent", "eventId:string");
            expect(countPatternFoundInBlocks("addDesignEvent")).toEqual(2);
        });
    });

    describe("addErrorEvent", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.addErrorEvent(gameanalytics.EGAErrorSeverity.Info, "test");
            expect(countPatternFoundInBlocks("addErrorEvent")).toEqual(1);
            GameAnalytics("addErrorEvent", "Info", "test");
            expect(countPatternFoundInBlocks("addErrorEvent")).toEqual(2);
        });
    });

    describe("setEnabledInfoLog", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setEnabledInfoLog(true);
            expect(countPatternFoundInBlocks("setInfoLog")).toEqual(1);
            GameAnalytics("setEnabledInfoLog", false);
            expect(countPatternFoundInBlocks("setInfoLog")).toEqual(2);
        });
    });

    describe("setEnabledVerboseLog", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setEnabledVerboseLog(true);
            expect(countPatternFoundInBlocks("setVerboseLog")).toEqual(1);
            GameAnalytics("setEnabledVerboseLog", false);
            expect(countPatternFoundInBlocks("setVerboseLog")).toEqual(2);
        });
    });

    describe("setEnabledManualSessionHandling", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setEnabledManualSessionHandling(true);
            expect(countPatternFoundInBlocks("setManualSessionHandling")).toEqual(1);
            GameAnalytics("setEnabledManualSessionHandling", false);
            expect(countPatternFoundInBlocks("setManualSessionHandling")).toEqual(2);
        });
    });

    describe("setCustomDimension01", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setCustomDimension01("ninja");
            expect(countPatternFoundInBlocks("setCustomDimension01")).toEqual(1);
            GameAnalytics("setCustomDimension01", "ninja");
            expect(countPatternFoundInBlocks("setCustomDimension01")).toEqual(2);
        });
    });

    describe("setCustomDimension02", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setCustomDimension02("ninja");
            expect(countPatternFoundInBlocks("setCustomDimension02")).toEqual(1);
            GameAnalytics("setCustomDimension02", "ninja");
            expect(countPatternFoundInBlocks("setCustomDimension02")).toEqual(2);
        });
    });

    describe("setCustomDimension03", function () {
        it("should be added to queue", function() {
            gameanalytics.GameAnalytics.setCustomDimension03("ninja");
            expect(countPatternFoundInBlocks("setCustomDimension03")).toEqual(1);
            GameAnalytics("setCustomDimension03", "ninja");
            expect(countPatternFoundInBlocks("setCustomDimension03")).toEqual(2);
        });
    });
});
