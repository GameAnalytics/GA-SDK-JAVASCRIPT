module gameanalytics
{
    export module storage
    {
        export function makeStorage(): IGAStorage
        {
            return new GAStorageBrowser();
        }
    }
}
