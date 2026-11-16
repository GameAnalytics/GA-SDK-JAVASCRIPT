module gameanalytics
{
    export module http
    {
        import GALogger = gameanalytics.logging.GALogger;

        // Node >= 18: global fetch, no dependency. gzip via built-in zlib, which C++
        // also implements (miniz); the browser client reports it unsupported.
        export class GAHttpClientNode implements IGAHttpClient
        {
            // fetch has no default timeout in Node; without one an unreachable
            // collector stalls onQuit() for the TCP timeout. -1 on abort maps to
            // NoResponse, so events are kept for the next run, same as offline.
            private static readonly TimeoutMs:number = 10000;

            public initialize(): void {}
            public cleanup(): void {}

            public sendRequest(url:string, auth:string, payload:Uint8Array, useGzip:boolean): Promise<GAHttpResponse>
            {
                var body:any = payload;
                var headers:{[k:string]: string} = {"Content-Type": "application/json", "Authorization": auth};
                if (useGzip)
                {
                    body = require("zlib").gzipSync(payload);
                    headers["Content-Encoding"] = "gzip";
                }
                var ctl:any = (typeof AbortController !== 'undefined') ? new AbortController() : null;
                var timer:any = ctl ? setTimeout(() => ctl.abort(), GAHttpClientNode.TimeoutMs) : null;
                if (timer && typeof timer.unref === 'function') { timer.unref(); }
                return fetch(url, {method: "POST", headers: headers, body: body, signal: ctl ? ctl.signal : undefined})
                    .then((res:any) => res.arrayBuffer().then((buf:ArrayBuffer) => { if (timer) { clearTimeout(timer); } return {code: res.status, packet: new Uint8Array(buf), statusText: res.statusText || ""}; }))
                    .catch((e:any) => {
                        if (timer) { clearTimeout(timer); }
                        GALogger.d("HTTP request failed: " + (e && e.message ? e.message : String(e)));
                        return {code: -1, packet: new Uint8Array(0), statusText: String(e && e.message || e)};
                    });
            }
        }

        // Mirrors Http/GAHttpStub: a no-op client for tests.
        export class GAHttpClientStub implements IGAHttpClient
        {
            public initialize(): void {}
            public cleanup(): void {}
            public sendRequest(): Promise<GAHttpResponse> { return Promise.resolve({code: -1, packet: new Uint8Array(0), statusText: "stub"}); }
        }
    }
}
