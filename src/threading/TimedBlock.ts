module gameanalytics
{
    export module threading
    {
        export class TimedBlock
        {
            public readonly deadline:Date;
            public readonly block:() => void;
            public readonly id:number;
            public ignore:boolean;
            public readonly blockName:string;
            private static idCounter:number = 0;

            public constructor(deadline:Date, block:() => void, blockName:string)
            {
                this.deadline = deadline;
                this.block = block;
                this.blockName = blockName;
                this.ignore = false;
                this.id = ++TimedBlock.idCounter;
            }
        }
    }
}
