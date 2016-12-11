module gameanalytics
{
    export class GameAnalytics
    {
        public static test(): void
        {
            logging.GALogger.i("hello from logger");
        }

        public static configureAvailableCustomDimensions01(customDimensions: Array<string>): void
        {
        }
    }
}
