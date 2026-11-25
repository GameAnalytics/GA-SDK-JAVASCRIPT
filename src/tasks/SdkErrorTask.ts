module gameanalytics
{
    export module tasks
    {
        import GAUtilities = gameanalytics.utilities.GAUtilities;
        import GALogger = gameanalytics.logging.GALogger;

        export class SdkErrorTask
        {
            private static readonly MaxCount:number = 10;
            private static readonly countMap:{[key:string]: number} = {};
            private static readonly timestampMap:{[key:string]: Date} = {};

            public static execute(url:string, type:string, payloadData:string, secretKey:string): void
            {
                var now:Date = new Date();

                if(!SdkErrorTask.timestampMap[type])
                {
                    SdkErrorTask.timestampMap[type] = now;
                }
                if(!SdkErrorTask.countMap[type])
                {
                    SdkErrorTask.countMap[type] = 0;
                }
                var diff:number = now.getTime() - SdkErrorTask.timestampMap[type].getTime();
                var diffSeconds:number = diff / 1000;
                if(diffSeconds >= 3600)
                {
                    SdkErrorTask.timestampMap[type] = now;
                    SdkErrorTask.countMap[type] = 0;
                }

                if(SdkErrorTask.countMap[type] >= SdkErrorTask.MaxCount)
                {
                    return;
                }

                var hashHmac:string = GAUtilities.getHmac(secretKey, payloadData);

                var client = gameanalytics.http.GAHTTPApi.getClient();
                if (!client) { return; }
                client.sendRequest(url, hashHmac, new TextEncoder().encode(payloadData), false).then((response) => {
                    var text:string = response.packet && response.packet.length ? new TextDecoder().decode(response.packet) : "";
                    if(!text)
                    {
                        GALogger.d("sdk error failed. Might be no connection. Description: " + (response.statusText || "") + ", Status code: " + response.code);
                        return;
                    }
                    if(response.code != 200)
                    {
                        GALogger.w("sdk error failed. response code not 200. status code: " + response.code + ", description: " + (response.statusText || "") + ", body: " + text);
                        return;
                    }
                    SdkErrorTask.countMap[type] = SdkErrorTask.countMap[type] + 1;
                }).catch((e:any) => { GALogger.e("sdk error request failed: " + e); });
            }
        }
    }
}
