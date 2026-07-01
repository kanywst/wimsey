//! Error type for HTTP Message Signature creation and verification.

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
    /// The signature's `alg` parameter was present but not `ed25519`.
    #[error("unexpected algorithm `{found}`, expected `ed25519`")]
    UnsupportedAlg {
        /// The `alg` value that was found.
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
    /// The `Signature-Input` and `Signature` used different labels, or the
    /// requested label was absent.
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
}
