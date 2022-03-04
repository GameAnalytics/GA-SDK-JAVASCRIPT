module gameanalytics
{
    export enum EGAErrorSeverity {
        Undefined = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4,
        Critical = 5
    }

    export enum EGAProgressionStatus {
        Undefined = 0,
        Start = 1,
        Complete = 2,
        Fail = 3
    }

    export enum EGAResourceFlowType {
        Undefined = 0,
        Source = 1,
        Sink = 2
    }

    export enum EGAAdAction {
        Undefined = 0,
        Clicked = 1,
        Show = 2,
        FailedShow = 3,
        RewardReceived = 4
    }

    export enum EGAAdError {
        Undefined = 0,
        Unknown = 1,
        Offline = 2,
        NoFill = 3,
        InternalError = 4,
        InvalidRequest = 5,
        UnableToPrecache = 6
    }

    export enum EGAAdType {
        Undefined = 0,
        Video = 1,
        RewardedVideo = 2,
        Playable = 3,
        Interstitial = 4,
        OfferWall = 5,
        Banner = 6
    }

    export module http
    {
        export enum EGAHTTPApiResponse
        {
            // client
            NoResponse,
            BadResponse,
            RequestTimeout, // 408
            JsonEncodeFailed,
            JsonDecodeFailed,
            // server
            InternalServerError,
            BadRequest, // 400
            Unauthorized, // 401
            UnknownResponseCode,
            Ok,
            Created
        }
    }

    export module events
    {
        export enum EGASdkErrorCategory
        {
            Undefined = 0,
            EventValidation = 1,
            Database = 2,
            Init = 3,
            Http = 4,
            Json = 5
        }

        export enum EGASdkErrorArea
        {
            Undefined = 0,
            BusinessEvent = 1,
            ResourceEvent = 2,
            ProgressionEvent = 3,
            DesignEvent = 4,
            ErrorEvent = 5,
            InitHttp = 9,
            EventsHttp = 10,
            ProcessEvents = 11,
            AddEventsToStore = 12,
            AdEvent = 20
        }

        export enum EGASdkErrorAction
        {
            Undefined = 0,
            InvalidCurrency = 1,
            InvalidShortString = 2,
            InvalidEventPartLength = 3,
            InvalidEventPartCharacters = 4,
            InvalidStore = 5,
            InvalidFlowType = 6,
            StringEmptyOrNull = 7,
            NotFoundInAvailableCurrencies = 8,
            InvalidAmount = 9,
            NotFoundInAvailableItemTypes = 10,
            WrongProgressionOrder = 11,
            InvalidEventIdLength = 12,
            InvalidEventIdCharacters = 13,
            InvalidProgressionStatus = 15,
            InvalidSeverity = 16,
            InvalidLongString = 17,
            DatabaseTooLarge = 18,
            DatabaseOpenOrCreate = 19,
            JsonError = 25,
            FailHttpJsonDecode = 29,
            FailHttpJsonEncode = 30,
            InvalidAdAction = 31,
            InvalidAdType = 32,
            InvalidString = 33
        }

        export enum EGASdkErrorParameter
        {
            Undefined = 0,
            Currency = 1,
            CartType = 2,
            ItemType = 3,
            ItemId = 4,
            Store = 5,
            FlowType = 6,
            Amount = 7,
            Progression01 = 8,
            Progression02 = 9,
            Progression03 = 10,
            EventId = 11,
            ProgressionStatus = 12,
            Severity = 13,
            Message = 14,
            AdAction = 15,
            AdType = 16,
            AdSdkName = 17,
            AdPlacement = 18
        }
    }
}
