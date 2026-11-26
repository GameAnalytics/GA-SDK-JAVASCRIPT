module gameanalytics
{
    export module platform
    {
        export function makePlatform(): GAPlatform
        {
            return new GAPlatformNode();
        }
    }
}
