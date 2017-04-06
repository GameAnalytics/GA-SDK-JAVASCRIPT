module gameanalytics
{
    export module threading
    {
        export class TimedBlock
        {
            public readonly deadline:Date;
            public block:() => void;
            public readonly id:number;
            public ignore:boolean;
            public async:boolean;
            public running:boolean;
            private static idCounter:number = 0;

            public constructor(deadline:Date)
            {
                this.deadline = deadline;
                this.ignore = false;
                this.async = false;
                this.running = false;
                this.id = ++TimedBlock.idCounter;
            }
        }
    }
}
