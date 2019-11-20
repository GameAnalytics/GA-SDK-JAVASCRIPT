module gameanalytics
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

    export enum EGAGender
    {
        Undefined = 0,
        Male = 1,
        Female = 2
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

    export module http
    {
        export enum EGASdkErrorType
        {
            Undefined = 0,
            Rejected = 1
        }

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
}
var EGAErrorSeverity = gameanalytics.EGAErrorSeverity;
var EGAGender = gameanalytics.EGAGender;
var EGAProgressionStatus = gameanalytics.EGAProgressionStatus;
var EGAResourceFlowType = gameanalytics.EGAResourceFlowType;
