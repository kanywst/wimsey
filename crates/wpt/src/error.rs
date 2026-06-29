//! Error type for WPT issuance and verification.

/// An error returned while issuing or verifying a Workload Proof Token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WptError {
    /// The compact serialization did not have exactly three parts, or a part
    /// was not the expected size.
    #[error("malformed token")]
    MalformedToken,
    /// The token is larger than the accepted maximum.
    #[error("token exceeds the maximum accepted size")]
    TokenTooLong,
    /// A Base64url component could not be decoded.
    #[error("invalid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A JSON component could not be parsed or serialized.
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    /// The JOSE header `typ` was not `wpt+jwt`.
    #[error("unexpected token type `{found}`, expected `wpt+jwt`")]
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
    /// The JOSE header marked an extension critical that this crate does not
    /// understand (RFC 7515 section 4.1.11).
    #[error("unsupported critical header parameter(s)")]
    UnsupportedCritical,
    /// The signature did not verify against the confirmation key.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The proof has expired (`exp` is in the past).
    #[error("proof has expired")]
    Expired,
    /// The `aud` claim did not match the expected audience.
    #[error("audience mismatch")]
    AudienceMismatch,
    /// The `wth` claim did not match the hash of the presented WIT.
    #[error("WIT binding mismatch")]
    WitBindingMismatch,
    /// The `ath` claim and the presented access token did not agree (one was
    /// present without the other, or the hashes differed).
    #[error("access token binding mismatch")]
    AccessTokenBindingMismatch,
    /// The proof's lifetime (`exp - now`) exceeds the configured maximum.
    #[error("proof lifetime exceeds the configured maximum")]
    LifetimeTooLong,
}
