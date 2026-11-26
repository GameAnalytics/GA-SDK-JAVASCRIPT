module gameanalytics
{
    export module http
    {
        // Port of include/GameAnalytics/GAHttpClient.h. Divergence 2: C++ returns the
        // Response synchronously; JS returns a promise. code = -1 is the failure
        // sentinel. statusText is a JS addition used only for log lines.
        export interface GAHttpResponse
        {
            code:number;
            packet:Uint8Array;
            statusText?:string;
        }

        export interface IGAHttpClient
        {
            initialize(): void;
            cleanup(): void;
            sendRequest(url:string, auth:string, payload:Uint8Array, useGzip:boolean): Promise<GAHttpResponse>;
        }

        // What the existing response callbacks read. XMLHttpRequest satisfies it.
        export interface GAHttpResponseLike
        {
            status:number;
            statusText:string;
            responseText:string;
        }
    }
}
