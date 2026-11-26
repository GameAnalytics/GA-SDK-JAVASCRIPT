module gameanalytics
{
    export module storage
    {
        export class GAStorageBrowser implements IGAStorage
        {
            private available:boolean = false;

            public constructor()
            {
                try
                {
                    if (typeof localStorage === 'object')
                    {
                        localStorage.setItem('testingLocalStorage', 'yes');
                        localStorage.removeItem('testingLocalStorage');
                        this.available = true;
                    }
                }
                catch (e) {}
            }

            public getItem(key:string): string | null { return localStorage.getItem(key); }
            public setItem(key:string, value:string): void { localStorage.setItem(key, value); }
            public removeItem(key:string): void { localStorage.removeItem(key); }
            public isAvailable(): boolean { return this.available; }
            public getSizeBytes(): number { return -1; }
            public deleteSessionCache(): void {}
        }
    }
}
