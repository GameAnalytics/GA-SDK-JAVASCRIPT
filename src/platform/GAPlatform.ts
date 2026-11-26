module gameanalytics
{
    export module platform
    {
        // Port of the C++ SDK's Platform/GAPlatform.h. Abstract members are the
        // C++ pure virtuals; the rest default to the same sentinels GAPlatform.cpp
        // returns: "" for strings, -1 for numbers. -1 means "not measurable on
        // this platform", which downstream can tell apart from a real 0.
        export abstract class GAPlatform
        {
            public abstract getOSVersion(): string;
            public abstract getDeviceManufacturer(): string;
            public abstract getBuildPlatform(): string;
            public abstract getPersistentPath(): string;
            public abstract getDeviceModel(): string;
            public abstract getConnectionType(): string;

            public getAdvertisingId(): string { return ""; }
            public getDeviceId(): string { return ""; }

            public getCpuModel(): string { return ""; }
            public getGpuModel(): string { return ""; }
            public getNumCpuCores(): number { return -1; }
            public getTotalDeviceMemory(): number { return -1; }
            public getAppMemoryUsage(): number { return -1; }
            public getSysMemoryUsage(): number { return -1; }
            public getBootTime(): number { return -1; }

            // JS-only, like the items store: browser_version is on the wire and
            // C++ has no browser. Defaulted so Node inherits the sentinel.
            public getBrowserVersion(): string { return ""; }

            // C++ installs its terminate handler here, gated on useErrorReporting().
            public onInit(): void {}
            public setupUncaughtExceptionHandler(): void {}
        }
    }
}
