module gameanalytics
{
    export module storage
    {
        // Key/value storage, the shape of localStorage. Divergence 1 in the spec:
        // C++ models persistence as a path because every platform has a
        // filesystem; the browser does not, so the abstraction is this interface.
        //
        // Two JS-port extensions beyond the spec's four methods:
        //  - getSizeBytes(): the spec decides Node measures the store in bytes and
        //    the browser in entries; GAStore has to be able to ask. -1 = cannot
        //    measure (browser), and GAStore falls back to the entry count.
        //  - deleteSessionCache(): the spec puts the per-session tmp cache inside
        //    IGAStorage and has onQuit() delete it after a successful drain.
        export interface IGAStorage
        {
            getItem(key:string): string | null;
            setItem(key:string, value:string): void;
            removeItem(key:string): void;
            isAvailable(): boolean;
            getSizeBytes(): number;
            deleteSessionCache(): void;
        }
    }
}
