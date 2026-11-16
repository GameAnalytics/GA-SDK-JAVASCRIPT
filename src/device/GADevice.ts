module gameanalytics
{
    export module device
    {
        export class NameValueVersion
        {
            public name:string;
            public value:string;
            public version:string;

            public constructor(name:string, value:string, version:string)
            {
                this.name = name;
                this.value = value;
                this.version = version;
            }
        }

        export class NameVersion
        {
            public name:string;
            public version:string;

            public constructor(name:string, version:string)
            {
                this.name = name;
                this.version = version;
            }
        }

        export class GADevice
        {
            private static readonly sdkWrapperVersion:string = "javascript 5.0.0";

            // Owned here, mirroring GADevice::_platform in the C++ SDK. Set by
            // GameAnalytics.init() before anything reads device information, so
            // nothing below touches a browser global at class-definition time.
            private static platform:gameanalytics.platform.GAPlatform = null;

            public static sdkGameEngineVersion:string;
            public static gameEngineVersion:string;
            private static connectionType:string;

            public static setPlatform(p:gameanalytics.platform.GAPlatform): void
            {
                GADevice.platform = p;
            }

            public static getPlatform(): gameanalytics.platform.GAPlatform
            {
                return GADevice.platform;
            }

            // Wraps getPersistentPath(), as GADevice::getWritablePath() does in C++.
            public static getWritablePath(): string
            {
                return GADevice.platform ? GADevice.platform.getPersistentPath() : "";
            }

            public static get buildPlatform(): string { return GADevice.platform ? GADevice.platform.getBuildPlatform() : "unknown"; }
            public static get deviceModel(): string { return GADevice.platform ? GADevice.platform.getDeviceModel() : "unknown"; }
            public static get deviceManufacturer(): string { return GADevice.platform ? GADevice.platform.getDeviceManufacturer() : "unknown"; }
            public static get osVersion(): string { return GADevice.platform ? GADevice.platform.getOSVersion() : "unknown 0.0.0"; }
            public static get browserVersion(): string { return GADevice.platform ? GADevice.platform.getBrowserVersion() : ""; }

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
                GADevice.connectionType = GADevice.platform ? GADevice.platform.getConnectionType() : "offline";
            }
        }
    }
}
