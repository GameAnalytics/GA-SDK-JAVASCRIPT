module gameanalytics
{
    export module threading
    {
        export interface IComparer<T>
        {
            compare(x:T, y:T): number;
        }

        export class PriorityQueue<TItem>
        {
            public _subQueues:{[key:number]: Array<TItem>};
            public _sortedKeys:Array<number>;
            private comparer:IComparer<number>;

            public constructor(priorityComparer:IComparer<number>)
            {
                this.comparer = priorityComparer;
                this._subQueues = {};
                this._sortedKeys = [];
            }

            public enqueue(priority:number, item:TItem): void
            {
                if(this._sortedKeys.indexOf(priority) === -1)
                {
                    this.addQueueOfPriority(priority);
                }

                this._subQueues[priority].push(item);
            }

            private addQueueOfPriority(priority:number): void
            {
                this._sortedKeys.push(priority);
                this._sortedKeys.sort((x:number, y:number) => this.comparer.compare(x, y));
                this._subQueues[priority] = [];
            }

            public peek(): TItem
            {
                if(this.hasItems())
                {
                    return this._subQueues[this._sortedKeys[0]][0];
                }
                else
                {
                    throw new Error("The queue is empty");
                }
            }

            public hasItems(): boolean
            {
                return this._sortedKeys.length > 0;
            }

            public dequeue(): TItem
            {
                if(this.hasItems())
                {
                    return this.dequeueFromHighPriorityQueue();
                }
                else
                {
                    throw new Error("The queue is empty");
                }
            }

            private dequeueFromHighPriorityQueue(): TItem
            {
                var firstKey:number = this._sortedKeys[0];
                var nextItem:TItem = this._subQueues[firstKey].shift();
                if(this._subQueues[firstKey].length === 0)
                {
                    this._sortedKeys.shift();
                    delete this._subQueues[firstKey];
                }

                return nextItem;
            }
        }
    }
}
