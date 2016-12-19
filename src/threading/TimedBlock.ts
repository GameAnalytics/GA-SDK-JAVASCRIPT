module ga
{
    export module threading
    {
        export class TimedBlock
        {
            public readonly deadline:Date;
            public readonly block:() => void;
            public readonly id:number;
            public ignore:boolean;
            private static idCounter:number = 0;

            public constructor(deadline:Date, block:() => void)
            {
                this.deadline = deadline;
                this.block = block;
                this.ignore = false;
                this.id = ++TimedBlock.idCounter;
            }
        }
    }
}
