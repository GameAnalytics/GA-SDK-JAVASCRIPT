describe("GAState", function () {
    describe("ValidateAndCleanCustomFields", function () {
        var GAState = gameanalytics.state.GAState;

        var map = {};

        it("should be valid custom fields", function() {
            map = {};
            for(var i = 0; i < 100; ++i)
            {
                map[getRandomString(4)] = getRandomString(4);
            }
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(50);

            map = {};
            for(var i = 0; i < 50; ++i)
            {
                map[getRandomString(4)] = getRandomString(4);
            }
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(50);

            map = {};
            map[getRandomString(4)] = "";
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);

            map = {};
            map[getRandomString(4)] = getRandomString(257);
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);

            map = {};
            map[""] = getRandomString(4);
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);

            map = {};
            map["___"] = getRandomString(4);
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(1);

            map = {};
            map["_&_"] = getRandomString(4);
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);

            map = {};
            map[getRandomString(65)] = getRandomString(4);
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);

            map = {};
            map[getRandomString(4)] = 100;
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(1);

            map = {};
            map[getRandomString(4)] = [100];
            map[getRandomString(4)] = true;
            expect(Object.keys(GAState.validateAndCleanCustomFields(map)).length).toEqual(0);
        });
    });
});
