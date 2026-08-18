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

pub const CommandError = error{
    Canceled,
    Closed,
    CommandQueueFull,
    RuntimeNotRunning,
    RuntimeStopped,
};

pub const EnrAdmissionError = CommandError || error{
    InvalidEnr,
    OutOfMemory,
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
    NoSocketForAddressFamily,
    OutOfMemory,
    PermitGenerationExhausted,
    TooManyActiveRequests,
    TooManyQueuedRequests,
    TooManyQueuedRequestsForEndpoint,
    TransportSendFailed,
};

pub const FindNodeError = RequestError || error{TooManyDistances};
pub const TalkRequestError = RequestError || error{MessageTooLarge};

pub const TalkResponseError = CommandError || error{
    EndpointMismatch,
    MessageTooLarge,
    NoSession,
    NoSocketForAddressFamily,
    NonceGenerationExhausted,
    OutOfMemory,
    PermitGenerationExhausted,
    TransportSendFailed,
    UnknownPeer,
};

pub const LookupError = CommandError || error{
    OutOfMemory,
    TooManyLookups,
};

/// Compatibility umbrella for callers that want one Runtime-wide error type.
pub const Error = InitError || RunError || EventError || EnrAdmissionError ||
    SetLocalEnrError || RequestError || FindNodeError || TalkRequestError ||
    TalkResponseError || LookupError;
