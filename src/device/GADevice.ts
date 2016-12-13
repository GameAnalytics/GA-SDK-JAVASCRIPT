module gameanalytics
{
    export module device
    {
        export class GADevice
        {
            private static readonly sdkWrapperVersion:string = "javascript 0.1.0";
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
                throw new Error("updateConnectionType not implemented");
            }

            private static getOSVersionString(): string
            {
                throw new Error("getOSVersionString not implemented");
            }

            private static runtimePlatformToString(): string
            {
                throw new Error("runtimePlatformToString not implemented");
            }
        }
    }
}
