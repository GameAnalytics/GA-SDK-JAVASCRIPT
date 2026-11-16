module gameanalytics
{
    export module platform
    {
        // Browser build target. The Node bundle compiles makePlatform.node.ts
        // instead; this is the JS analogue of C++'s GADevicePlatform.h selection.
        export function makePlatform(): GAPlatform
        {
            return new GAPlatformBrowser();
        }
    }
}
