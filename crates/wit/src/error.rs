//! Error type for WIT issuance and verification.

/// An error returned while issuing or verifying a Workload Identity Token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitError {
    /// The compact serialization did not have exactly three parts, or a part
    /// was not the expected size.
    #[error("malformed token")]
    MalformedToken,
    /// The token is larger than the accepted maximum.
    #[error("token exceeds the maximum accepted size")]
    TokenTooLong,
    /// The JOSE header marked an extension critical that this crate does not
    /// understand (RFC 7515 section 4.1.11).
    #[error("unsupported critical header parameter(s)")]
    UnsupportedCritical,
    /// A Base64url component could not be decoded.
    #[error("invalid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A JSON component could not be parsed or serialized.
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    /// The JOSE header `typ` was not `wit+jwt`.
    #[error("unexpected token type `{found}`, expected `wit+jwt`")]
    WrongType {
        /// The `typ` value that was found.
        found: String,
    },
    /// The JOSE header `alg` was not a supported algorithm.
    #[error("unsupported algorithm `{found}`, expected `EdDSA`")]
    UnsupportedAlg {
        /// The `alg` value that was found.
        found: String,
    },
    /// The signature did not verify against the supplied key.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The token has expired (`exp` is in the past).
    #[error("token has expired")]
    Expired,
    /// The token was issued in the future (`iat` is ahead of now).
    #[error("token issued in the future")]
    IssuedInFuture,
    /// The token issuer did not match the expected issuer.
    #[error("issuer mismatch")]
    IssuerMismatch,
    /// A key could not be decoded into an Ed25519 key.
    #[error("invalid key")]
    InvalidKey,
}
