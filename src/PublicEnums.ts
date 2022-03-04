module public_enums
{
    export enum EGAErrorSeverity
    {
        Undefined = 0,
        Debug = 1,
        Info = 2,
        Warning = 3,
        Error = 4,
        Critical = 5
    }

    export enum EGAProgressionStatus
    {
        Undefined = 0,
        Start = 1,
        Complete = 2,
        Fail = 3
    }

    export enum EGAResourceFlowType
    {
        Undefined = 0,
        Source = 1,
        Sink = 2
    }

    export enum EGAAdAction
    {
        Undefined = 0,
        Clicked = 1,
        Show = 2,
        FailedShow = 3,
        RewardReceived = 4
    }

    export enum EGAAdError
    {
        Undefined = 0,
        Unknown = 1,
        Offline = 2,
        NoFill = 3,
        InternalError = 4,
        InvalidRequest = 5,
        UnableToPrecache = 6
    }

    export enum EGAAdType
    {
        Undefined = 0,
        Video = 1,
        RewardedVideo = 2,
        Playable = 3,
        Interstitial = 4,
        OfferWall = 5,
        Banner = 6
    }
}
