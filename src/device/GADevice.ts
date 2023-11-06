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
            private static readonly sdkWrapperVersion:string = "javascript 4.4.6";
            private static readonly osVersionPair:NameVersion = GADevice.matchItem([
                navigator.platform,
                navigator.userAgent,
                navigator.appVersion,
                navigator.vendor
            ].join(' '), [
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

            public static readonly buildPlatform:string = GADevice.runtimePlatformToString();
            public static readonly deviceModel:string = GADevice.getDeviceModel();
            public static readonly deviceManufacturer:string = GADevice.getDeviceManufacturer();
            public static readonly osVersion:string = GADevice.getOSVersionString();
            public static readonly browserVersion:string = GADevice.getBrowserVersionString();

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
                return GADevice.buildPlatform + " " + GADevice.osVersionPair.version;
            }

            private static runtimePlatformToString(): string
            {
                return GADevice.osVersionPair.name;
            }

            private static getBrowserVersionString(): string
            {
                var ua:string = navigator.userAgent;
                var tem:RegExpMatchArray;
                var M:RegExpMatchArray = ua.match(/(opera|chrome|safari|firefox|ubrowser|msie|trident|fbav(?=\/))\/?\s*(\d+)/i) || [];

                if(M.length == 0)
                {
                    if(GADevice.buildPlatform === "ios")
                    {
                        return "webkit_" + GADevice.osVersion;
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

            private static getDeviceModel():string
            {
                var result:string = "unknown";

                return result;
            }

            private static getDeviceManufacturer():string
            {
                var result:string = "unknown";

                return result;
            }

            private static matchItem(agent:string, data:Array<NameValueVersion>):NameVersion
            {
                var result:NameVersion = new NameVersion("unknown", "0.0.0");

                var i:number = 0;
                var j:number = 0;
                var regex:RegExp;
                var regexv:RegExp;
                var match:boolean;
                var matches:RegExpMatchArray;
                var mathcesResult:string;
                var version:string;

                for (i = 0; i < data.length; i += 1)
                {
                    regex = new RegExp(data[i].value, 'i');
                    match = regex.test(agent);
                    if (match)
                    {
                        regexv = new RegExp(data[i].version + '[- /:;]([\\d._]+)', 'i');
                        matches = agent.match(regexv);
                        version = '';
                        if (matches)
                        {
                            if (matches[1])
                            {
                                mathcesResult = matches[1];
                            }
                        }
                        if (mathcesResult)
                        {
                            var matchesArray:string[] = mathcesResult.split(/[._]+/);
                            for (j = 0; j < Math.min(matchesArray.length, 3); j += 1)
                            {
                                version += matchesArray[j] + (j < Math.min(matchesArray.length, 3) - 1 ? '.' : '');
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
