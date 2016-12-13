module gameanalytics
{
    export module events
    {
        export class GAEvents
        {
            public static addSessionStartEvent(): void
            {
                throw new Error("addSessionEndEvent not implemented");
            }

            public static addSessionEndEvent(): void
            {
                throw new Error("addSessionEndEvent not implemented");
            }
        }
    }
}
