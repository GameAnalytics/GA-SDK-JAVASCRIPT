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

                var request:XMLHttpRequest = new XMLHttpRequest();

                request.onreadystatechange = () => {
                    if(request.readyState === 4)
                    {
                        if(!request.responseText)
                        {
                            GALogger.d("sdk error failed. Might be no connection. Description: " + request.statusText + ", Status code: " + request.status);
                            return;
                        }

                        if(request.status != 200)
                        {
                            GALogger.w("sdk error failed. response code not 200. status code: " + request.status + ", description: " + request.statusText + ", body: " + request.responseText);
                            return;
                        }
                        else
                        {
                            SdkErrorTask.countMap[type] = SdkErrorTask.countMap[type] + 1;
                        }
                    }
                };

                request.open("POST", url, true);
                request.setRequestHeader("Content-Type", "application/json");
                request.setRequestHeader("Authorization", hashHmac);

                try
                {
                    request.send(payloadData);
                }
                catch(e)
                {
                    console.error(e);
                }
            }
        }
    }
}
