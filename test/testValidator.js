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
        var GALogger = gameanalytics.logging.GALogger;

        it("should be valid progression event", function() {
            GALogger.setInfoLog(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", "phase_001")).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", "")).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "level_001", null)).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "", "")).toEqual(true);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", undefined, undefined)).toEqual(true);
        });

        it("should be invalid progression event", function() {
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "", "")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, null, null)).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, undefined, undefined)).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", "", "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", null, "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "world_001", undefined, "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "level_001", "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, "level_001", "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, "level_001", "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "level_001", "")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, "level_001", null)).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, "level_001", undefined)).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, "", "", "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, null, null, "phase_001")).toEqual(false);
            expect(GAValidator.validateProgressionEvent(EGAProgressionStatus.Start, undefined, undefined, "phase_001")).toEqual(false);
        });
    });

    describe("BusinessEvent", function () {
        var GAValidator = gameanalytics.validators.GAValidator;
        var EGAProgressionStatus = gameanalytics.EGAProgressionStatus;
        var GALogger = gameanalytics.logging.GALogger;

        it("should be valid business event", function() {
            expect(GAValidator.validateBusinessEvent("USD", 99, "cartType", "itemType", "itemId")).toEqual(true);
        });

        it("should be invalid business event", function() {
            expect(GAValidator.validateBusinessEvent("USD", 99, "", "", "itemId")).toEqual(false);
        });
    });
});
