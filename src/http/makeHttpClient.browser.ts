module gameanalytics
{
    export module http
    {
        export function makeHttpClient(): IGAHttpClient
        {
            return new GAHttpClientBrowser();
        }
    }
}
