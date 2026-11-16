module gameanalytics
{
    export module http
    {
        import GALogger = gameanalytics.logging.GALogger;

        export class GAHttpClientBrowser implements IGAHttpClient
        {
            public initialize(): void {}
            public cleanup(): void {}

            public sendRequest(url:string, auth:string, payload:Uint8Array, useGzip:boolean): Promise<GAHttpResponse>
            {
                return new Promise<GAHttpResponse>((resolve) => {
                    if (useGzip)
                    {
                        GALogger.w("gzip is not supported by the browser HTTP client");
                        resolve({code: -1, packet: new Uint8Array(0), statusText: "gzip unsupported"});
                        return;
                    }
                    var request:XMLHttpRequest = new XMLHttpRequest();
                    request.onreadystatechange = () => {
                        if (request.readyState === 4)
                        {
                            var text:string = request.responseText || "";
                            resolve({code: request.status || -1, packet: new TextEncoder().encode(text), statusText: request.statusText || ""});
                        }
                    };
                    request.open("POST", url, true);
                    request.setRequestHeader("Content-Type", "application/json");
                    request.setRequestHeader("Authorization", auth);
                    try { request.send(payload); }
                    catch (e) { GALogger.e(e && e.stack ? e.stack : String(e)); resolve({code: -1, packet: new Uint8Array(0), statusText: "send failed"}); }
                });
            }
        }
    }
}
