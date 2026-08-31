//! Semantically reachable error contracts for public discv5 Runtime operations.

pub const InitError = error{
    BindFailed,
    Canceled,
    InvalidBindAddressFamily,
    InvalidCapacity,
    InvalidEnr,
    InvalidLocalIdentity,
    InvalidLookupNumResults,
    InvalidLookupParallelism,
    InvalidLookupRequestLimit,
    InvalidMaintenanceInterval,
    InvalidRateLimiterCapacity,
    InvalidRateLimiterQuota,
    InvalidRequestRetries,
    InvalidSessionCapacity,
    InvalidVoteThreshold,
    NoBindAddresses,
    OutOfMemory,
};

pub const RunError = error{
    AlreadyRunning,
    Canceled,
    ConcurrencyUnavailable,
    RuntimeStopped,
};

pub const EventError = error{
    Canceled,
    Closed,
};

pub const LookupResultError = error{
    Canceled,
    Closed,
};

pub const RequestResultError = error{
    Canceled,
    Closed,
};

pub const CommandError = error{
    Canceled,
    Closed,
    CommandQueueFull,
    RuntimeNotRunning,
    RuntimeStopped,
};

pub const EnrAdmissionError = CommandError || error{
    InvalidEnr,
    InvalidPublicKey,
    OutOfMemory,
    WrongNodeId,
};

pub const SetLocalEnrError = CommandError || error{
    InvalidEnr,
    InvalidPublicKey,
    InvalidSignature,
    OutOfMemory,
    StaleEnrSeq,
    UnsupportedScheme,
    WrongNodeId,
};

pub const RequestError = CommandError || error{
    DuplicateChallenge,
    DuplicateRequest,
    GenerationExhausted,
    NoSocketForAddressFamily,
    OutOfMemory,
    PermitGenerationExhausted,
    RequestResultCapacityExceeded,
    TooManyActiveRequests,
    TooManyQueuedRequests,
    TooManyQueuedRequestsForEndpoint,
    TransportSendFailed,
    UnknownPeer,
};

pub const FindNodeError = RequestError || error{ InvalidDistance, TooManyDistances };
pub const TalkRequestError = RequestError || error{MessageTooLarge};

pub const TalkResponseError = CommandError || error{
    EndpointMismatch,
    GenerationExhausted,
    InvalidRequestId,
    MessageTooLarge,
    NoSession,
    NoSocketForAddressFamily,
    NonceGenerationExhausted,
    OutOfMemory,
    PermitGenerationExhausted,
    TooManyActiveRequests,
    TransportSendFailed,
    UnknownPeer,
};

pub const LookupError = CommandError || error{
    LookupResultCapacityExceeded,
    OutOfMemory,
    TooManyLookups,
};

/// Compatibility umbrella for callers that want one Runtime-wide error type.
pub const Error = InitError || RunError || EventError || LookupResultError || RequestResultError || EnrAdmissionError ||
    SetLocalEnrError || RequestError || FindNodeError || TalkRequestError ||
    TalkResponseError || LookupError;
