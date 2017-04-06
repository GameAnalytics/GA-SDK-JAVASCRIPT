//GALOGGER_START
module gameanalytics
{
    export module logging
    {
        enum EGALoggerMessageType
        {
            Error = 0,
            Warning = 1,
            Info = 2,
            Debug = 3
        }

        export class GALogger
        {
            // Fields and properties: START

            private static readonly instance:GALogger = new GALogger();
            private infoLogEnabled:boolean;
            private infoLogVerboseEnabled:boolean;
            private static debugEnabled:boolean;
            private static readonly Tag:string = "GameAnalytics";

            // Fields and properties: END

            private constructor()
            {
                GALogger.debugEnabled = true;
            }

            // Methods: START

            public static setInfoLog(value:boolean): void
            {
                GALogger.instance.infoLogEnabled = value;
            }

            public static setVerboseLog(value:boolean): void
            {
                GALogger.instance.infoLogVerboseEnabled = value;
            }

            public static i(format:string): void
            {
                if(!GALogger.instance.infoLogEnabled)
                {
                    return;
                }

                var message:string = "Info/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            }

            public static w(format:string): void
            {
                var message:string = "Warning/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Warning);
            }

            public static e(format:string): void
            {
                var message:string = "Error/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Error);
            }

            public static ii(format:string): void
            {
                if(!GALogger.instance.infoLogVerboseEnabled)
                {
                    return;
                }

                var message:string = "Verbose/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Info);
            }

            public static d(format:string): void
            {
                if(!GALogger.debugEnabled)
                {
                    return;
                }

                var message:string = "Debug/" + GALogger.Tag + ": " + format;
                GALogger.instance.sendNotificationMessage(message, EGALoggerMessageType.Debug);
            }

            private sendNotificationMessage(message:string, type:EGALoggerMessageType): void
            {
                switch(type)
                {
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
                        if(typeof console.debug === "function")
                        {
                            console.debug(message);
                        }
                        else
                        {
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
            }

            // Methods: END
        }
    }
}
//GALOGGER_END
