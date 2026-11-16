module gameanalytics
{
    export module platform
    {
        import GALogger = gameanalytics.logging.GALogger;
        import NameValueVersion = gameanalytics.device.NameValueVersion;
        import NameVersion = gameanalytics.device.NameVersion;

        export class GAPlatformBrowser extends GAPlatform
        {
            private osVersionPair:NameVersion = null;

            private getOsVersionPair(): NameVersion
            {
                if (this.osVersionPair === null)
                {
                    var agent:string = (typeof navigator !== 'undefined')
                        ? [navigator.platform, navigator.userAgent, navigator.appVersion, navigator.vendor].join(' ')
                        : '';
                    this.osVersionPair = GAPlatformBrowser.matchItem(agent, [
                        new NameValueVersion("windows_phone", "Windows Phone", "OS"),
                        new NameValueVersion("windows", "Win", "NT"),
                        new NameValueVersion("ios", "iPhone", "OS"),
                        new NameValueVersion("ios", "iPad", "OS"),
                        new NameValueVersion("ios", "iPod", "OS"),
                        new NameValueVersion("android", "Android", "Android"),
                        new NameValueVersion("blackBerry", "BlackBerry", "/"),
                        new NameValueVersion("mac_osx", "Mac", "OS X"),
                        new NameValueVersion("tizen", "Tizen", "Tizen"),
                        new NameValueVersion("linux", "Linux", "rv"),
                        new NameValueVersion("kai_os", "KAIOS", "KAIOS")
                    ]);
                }
                return this.osVersionPair;
            }

            public getOSVersion(): string { return this.getBuildPlatform() + " " + this.getOsVersionPair().version; }
            public getBuildPlatform(): string { return this.getOsVersionPair().name; }
            public getDeviceManufacturer(): string { return "unknown"; }
            public getDeviceModel(): string { return "unknown"; }
            public getPersistentPath(): string { return ""; }

            public getConnectionType(): string
            {
                if (typeof navigator === 'undefined' || navigator.onLine)
                {
                    var p:string = this.getBuildPlatform();
                    return (p === "ios" || p === "android") ? "wwan" : "lan";
                }
                return "offline";
            }

            public getNumCpuCores(): number
            {
                return (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) ? navigator.hardwareConcurrency : -1;
            }

            public getTotalDeviceMemory(): number
            {
                return (typeof navigator !== 'undefined' && (navigator as any).deviceMemory) ? (navigator as any).deviceMemory * 1073741824 : -1;
            }

            public getAppMemoryUsage(): number
            {
                return (typeof performance !== 'undefined' && (performance as any).memory) ? (performance as any).memory.usedJSHeapSize : -1;
            }

            public getBootTime(): number
            {
                return (typeof performance !== 'undefined') ? Math.round(performance.now()) : -1;
            }

            public getGpuModel(): string
            {
                try
                {
                    if (typeof document !== 'undefined')
                    {
                        var canvas = document.createElement('canvas');
                        var gl: any = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                        if (gl)
                        {
                            var ext = gl.getExtension('WEBGL_debug_renderer_info');
                            if (ext) { return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || ''; }
                        }
                    }
                }
                catch (e) {}
                return "";
            }

            public getBrowserVersion(): string
            {
                if (typeof navigator === 'undefined') { return ""; }
                var ua:string = navigator.userAgent;
                var tem:string[] | null;
                var M:string[] = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident|fbav(?=\/))\/?\s*(\d+)/i) || [];

                if(M.length == 0)
                {
                    if(this.getBuildPlatform() === "ios")
                    {
                        return "webkit_" + this.getOSVersion();
                    }
                }

                if(/trident/i.test(M[1]))
                {
                    tem = /\brv[ :]+(\d+)/g.exec(ua) || [];
                    return 'IE ' + (tem[1] || '');
                }

                if(M[1] === 'Chrome')
                {
                    tem = ua.match(/\b(OPR|Edge|UBrowser)\/(\d+)/);
                    if(tem!= null)
                    {
                        return tem.slice(1).join(' ').replace('OPR', 'Opera').replace('UBrowser', 'UC').toLowerCase();
                    }
                }

                if(M[1] && M[1].toLowerCase() === 'fbav')
                {
                    M[1] = "facebook";
                    if(M[2])
                    {
                        return "facebook " + M[2];
                    }
                }

                var MString:string[] = M[2]? [M[1], M[2]]: [navigator.appName, navigator.appVersion, '-?'];

                if((tem = ua.match(/version\/(\d+)/i)) != null)
                {
                    MString.splice(1, 1, tem[1]);
                }

                return MString.join(' ').toLowerCase();
            }

            // beforeunload is a browser detail, registered here rather than in
            // GameAnalytics.init() where it used to throw on import in Node.
            public onInit(): void
            {
                if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') { return; }
                window.addEventListener("beforeunload", () => {
                    GALogger.d('addEventListener unload');
                    gameanalytics.state.GAState.instance.isUnloading = true;
                    gameanalytics.state.GAState.notifyBeforeUnloadListeners();
                    gameanalytics.threading.GAThreading.endSessionAndStopQueue();
                    gameanalytics.state.GAState.instance.isUnloading = false;
                });
            }

            private static matchItem(agent:string, data:Array<NameValueVersion>):NameVersion
            {
                var result:NameVersion = new NameVersion("unknown", "0.0.0");
                var mathcesResult:string;
                for (var i = 0; i < data.length; i += 1)
                {
                    if (new RegExp(data[i].value, 'i').test(agent))
                    {
                        var matches:RegExpMatchArray = agent.match(new RegExp(data[i].version + '[- /:;]([\\d._]+)', 'i'));
                        var version:string = '';
                        if (matches && matches[1]) { mathcesResult = matches[1]; }
                        if (mathcesResult)
                        {
                            var parts:string[] = mathcesResult.split(/[._]+/);
                            for (var j = 0; j < Math.min(parts.length, 3); j += 1)
                            {
                                version += parts[j] + (j < Math.min(parts.length, 3) - 1 ? '.' : '');
                            }
                        }
                        else
                        {
                            version = '0.0.0';
                        }
                        result.name = data[i].name;
                        result.version = version;
                        return result;
                    }
                }
                return result;
            }
        }
    }
}
