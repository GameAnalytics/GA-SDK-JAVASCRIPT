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
});
