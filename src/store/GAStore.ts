module gameanalytics
{
    export module store
    {
        export enum EGAStoreArgsOperator
        {
            Equal,
            LessOrEqual,
            NotEqual
        }

        export enum EGAStore
        {
            Events,
            Sessions
        }

        export class GAStore
        {
            private static readonly instance:GAStore = new GAStore();
            private static storageAvailable:boolean = false;
            private static readonly MaxDbSizeBytes:number = 1048576;
            private static readonly MaxDbSizeBytesBeforeTrim = 819200;

            private constructor()
            {
                GAStore.storageAvailable = typeof(Storage) !== "undefined";
            }

            public static isStorageAvailable():boolean
            {
                return GAStore.storageAvailable;
            }

            public static setState(key:string, value:string): void
            {
                throw new Error("isTableReady is not implemented yet");
            }

            public static select(store:EGAStore, args:Array<[string, EGAStoreArgsOperator, string]>, sort:boolean = false, maxCount:number = 0): Array<{[key:string]: any}>
            {
                return null;
            }

            public static update(store:EGAStore, setArgs:Array<[string, string]>, whereArgs:Array<[string, EGAStoreArgsOperator, string]> = null): boolean
            {
                return false;
            }
        }
    }
}
