module gameanalytics
{
    import GAThreading = gameanalytics.threading.GAThreading;
    import GALogger = gameanalytics.logging.GALogger;

    export class GameAnalytics
    {
        public static init(): void
        {
        }

        public static configureAvailableCustomDimensions01(customDimensions: Array<string>): void
        {
            GAThreading.performTaskOnGAThread("configureAvailableCustomDimensions01", () =>
            {
                GALogger.i("Hello");
                if(GameAnalytics.isSdkReady(true, false))
                {
                    GALogger.w("Available custom dimensions must be set before SDK is initialized");
                    return;
                }

            });
        }

        private static isSdkReady(needsInitialized:boolean, warn:boolean = true, message:string = ""): boolean
        {
            return false;
        }
    }

    GameAnalytics.init();
}
