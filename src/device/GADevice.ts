module ga
{
    export module device
    {
        import GALogger = ga.logging.GALogger;

        export class GADevice
        {
            private static readonly sdkWrapperVersion:string = "javascript 1.0.4";
            public static readonly buildPlatform:string = GADevice.runtimePlatformToString();
            public static readonly deviceModel:string = "unknown";
            public static readonly deviceManufacturer:string = "unknown";
            public static readonly osVersion:string = GADevice.getOSVersionString();

            public static sdkGameEngineVersion:string;
            public static gameEngineVersion:string;
            private static connectionType:string;

            public static touch(): void
            {
            }

            public static getRelevantSdkVersion(): string
            {
                if(GADevice.sdkGameEngineVersion)
                {
                    return GADevice.sdkGameEngineVersion;
                }
                return GADevice.sdkWrapperVersion;
            }

            public static getConnectionType(): string
            {
                return GADevice.connectionType;
            }

            public static updateConnectionType(): void
            {
                if(navigator.onLine)
                {
                    if(GADevice.buildPlatform === "ios" || GADevice.buildPlatform === "android")
                    {
                        GADevice.connectionType = "wwan";
                    }
                    else
                    {
                        GADevice.connectionType = "lan";
                    }
                    // TODO: Detect wifi usage
                }
                else
                {
                    GADevice.connectionType = "offline";
                }
            }

            private static getOSVersionString(): string
            {
                return GADevice.buildPlatform + " 0.0.0";
            }

            private static runtimePlatformToString(): string
            {
                try
                {
                    var platform:string = navigator.platform;
                    platform = platform.toLowerCase();

                    GALogger.d("Finding platform for: " + platform);

                    if(platform.indexOf("mac") != -1)
                    {
                        return "mac_osx";
                    }
                    else if(platform.indexOf("linux") != -1)
                    {
                        return "linux";
                    }
                    else if(platform.indexOf("win") != -1)
                    {
                        return "windows";
                    }
                    else if(platform.indexOf("android") != -1)
                    {
                        return "android";
                    }
                    else if(platform.indexOf("iphone") != -1 || platform.indexOf("ipad") != -1 || platform.indexOf("ipod") != -1)
                    {
                        return "ios";
                    }

                    GALogger.d("Platform was not found: " + platform);
                }
                catch(e)
                {
                }

                return "unknown";
            }
        }
    }
}
