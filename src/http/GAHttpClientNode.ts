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

            private pending:Array<any> = [];
            private closed:boolean = false;

            public initialize(): void {}

            public cleanup(): void
            {
                this.closed = true;
                this.pending.forEach((controller:any) => controller.abort());
            }

            public sendRequest(url:string, auth:string, payload:Uint8Array, useGzip:boolean): Promise<GAHttpResponse>
            {
                if (this.closed) { return Promise.resolve({code: -1, packet: new Uint8Array(0), statusText: "closed"}); }
                var body:any = payload;
                var headers:{[k:string]: string} = {"Content-Type": "application/json", "Authorization": auth};
                if (useGzip)
                {
                    body = require("zlib").gzipSync(payload);
                    headers["Content-Encoding"] = "gzip";
                }
                var controller:any = new AbortController();
                var timer:any = setTimeout(() => controller.abort(), GAHttpClientNode.TimeoutMs);
                timer.unref();
                this.pending.push(controller);
                var done = () => { clearTimeout(timer); this.pending = this.pending.filter((other:any) => other !== controller); };
                return fetch(url, {method: "POST", headers: headers, body: body, signal: controller.signal})
                    .then((res:any) => res.arrayBuffer().then((buf:ArrayBuffer) => { done(); return {code: res.status, packet: new Uint8Array(buf), statusText: res.statusText || ""}; }))
                    .catch((e:any) => {
                        done();
                        GALogger.d("HTTP request failed: " + (e && e.message ? e.message : String(e)));
                        return {code: -1, packet: new Uint8Array(0), statusText: String(e && e.message || e)};
                    });
            }
        }
    }
}
