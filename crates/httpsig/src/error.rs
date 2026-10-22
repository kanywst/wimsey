//! Error type for HTTP Message Signature creation and verification.

/// The RFC 9457 problem type for a signed request that failed authentication —
/// the WIT or the HTTP message signature — sent with status `400`.
///
/// One type for every [`HttpSigError`]: the draft forbids telling the peer which
/// check failed.
pub const PROBLEM_SIGNATURE_INVALID: &str =
    "https://iana.org/assignments/http-problem-types#wimse-signature-invalid";

/// The RFC 9457 problem type for a server that does not support response
/// signing but was asked for it by `wimse-sign-response`, sent with status `501`.
pub const PROBLEM_SIGNED_RESPONSE_UNSUPPORTED: &str =
    "https://iana.org/assignments/http-problem-types#wimse-signed-response-unsupported";

/// The RFC 9457 problem type for a server that signs responses but cannot sign
/// this one (a streamed or exceptionally large body), sent with status `400`.
pub const PROBLEM_SIGNED_RESPONSE_UNAVAILABLE: &str =
    "https://iana.org/assignments/http-problem-types#wimse-signed-response-unavailable";

/// An error returned while signing or verifying an HTTP message signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpSigError {
    /// A covered component referenced a header field not present in the message.
    #[error("covered component `{0}` is not present in the message")]
    MissingComponent(String),
    /// A component identifier is not supported by this crate.
    #[error("unsupported component identifier `{0}`")]
    UnsupportedComponent(String),
    /// A component value contained a bare CR or LF, which would corrupt the
    /// signature base.
    #[error("component `{0}` has a value containing CR or LF")]
    InvalidComponentValue(String),
    /// A component required by the verifier was not covered by the signature.
    #[error("required component `{0}` is not covered by the signature")]
    MissingRequiredComponent(String),
    /// The signature's `alg` parameter did not name the verifying key's
    /// algorithm, or that algorithm is not one the verifier accepts.
    #[error("unexpected or unaccepted algorithm `{found}`")]
    UnsupportedAlg {
        /// The algorithm that was found.
        found: String,
    },
    /// The signature's `expires` is before its `created`.
    #[error("signature `expires` precedes `created`")]
    InvalidTimeWindow,
    /// The signature is older than the verifier's `max_age`.
    #[error("signature is older than the allowed maximum age")]
    TooOld,
    /// The `Signature-Input` or `Signature` field value could not be parsed.
    #[error("could not parse structured field: {0}")]
    Parse(String),
    /// The `Signature` field has no member for the chosen `Signature-Input`
    /// label, the requested label was absent, or several signatures were
    /// present with no label to choose between them.
    #[error("signature label mismatch")]
    LabelMismatch,
    /// The signature byte sequence was not valid Base64 or not 64 bytes.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature did not verify against the supplied key.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The signature's `expires` parameter is in the past.
    #[error("signature has expired")]
    Expired,
    /// The signature's `created` parameter is in the future.
    #[error("signature created in the future")]
    CreatedInFuture,
    /// The WIMSE profile requires a signature parameter that is absent.
    #[error("the WIMSE profile requires the `{0}` signature parameter")]
    MissingParameter(&'static str),
    /// The WIMSE profile forbids a signature parameter that is present.
    #[error("the WIMSE profile forbids the `{0}` signature parameter")]
    ForbiddenParameter(&'static str),
    /// The WIMSE profile forbids a covered component that is present — `@path`
    /// or `@query` (or their `;req` forms) on a signature over a `CONNECT`.
    #[error("the WIMSE profile forbids covering `{0}` here")]
    ForbiddenComponent(String),
    /// The signature's `tag` is not the WIMSE workload-to-workload tag.
    #[error("unexpected signature tag `{found}`, expected `wimse-workload-to-workload`")]
    WrongTag {
        /// The `tag` value that was found.
        found: String,
    },
    /// The signature's `wimse-aud` did not match the audience the verifier
    /// expected — the signature was minted for a different service.
    #[error("audience mismatch")]
    AudienceMismatch,
    /// A signed response carried back a `wimse-req-nonce` that is not the nonce
    /// the client sent, so the response answers some other request.
    #[error("the response's `wimse-req-nonce` does not match the request's nonce")]
    RequestNonceMismatch,
    /// Several signatures were present and none carried the
    /// `wimse-workload-to-workload` tag, so the message carries no WIMSE
    /// signature.
    #[error("no signature carries the `wimse-workload-to-workload` tag")]
    NoWimseSignature,
    /// More than one signature carried the `wimse-workload-to-workload` tag,
    /// which the draft requires a recipient to reject.
    #[error("more than one signature carries the `wimse-workload-to-workload` tag")]
    AmbiguousWimseSignature,
}
