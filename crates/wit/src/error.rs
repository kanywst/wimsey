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
    /// A key could not be decoded.
    #[error("invalid key")]
    InvalidKey,
    /// The JOSE header named an algorithm the verifying key does not use, so
    /// the token was signed with a different algorithm than the one presented.
    #[error("the token's `alg` does not match the verifying key's algorithm")]
    AlgorithmMismatch,
    /// The `cnf` JWK omitted the `alg` member, which the draft requires.
    #[error("the confirmation key is missing the required `alg` member")]
    MissingConfirmationAlg,
    /// The `cnf` JWK named an algorithm the draft forbids: `none`, a symmetric
    /// algorithm, or an encryption algorithm.
    #[error("the confirmation key algorithm `{found}` is forbidden for a proof of possession")]
    ForbiddenConfirmationAlg {
        /// The `alg` value that was found.
        found: String,
    },
    /// The `cnf` JWK named a legal algorithm this crate cannot verify a proof
    /// with. This crate supports `EdDSA` only.
    #[error("unsupported confirmation key algorithm `{found}`, expected `EdDSA`")]
    UnsupportedConfirmationAlg {
        /// The `alg` value that was found.
        found: String,
    },
}

impl From<wimsey_jose::JoseError> for WitError {
    fn from(error: wimsey_jose::JoseError) -> Self {
        use wimsey_jose::JoseError;
        match error {
            JoseError::MissingAlg => Self::MissingConfirmationAlg,
            JoseError::ForbiddenAlg { found } => Self::ForbiddenConfirmationAlg { found },
            JoseError::UnsupportedAlg { found } => Self::UnsupportedConfirmationAlg { found },
            JoseError::InvalidSignature => Self::InvalidSignature,
            // `InvalidKey`, `InvalidEncoding`, and any variant added later:
            // every remaining way a JOSE key can be rejected reaches this crate
            // as an unusable key.
            _ => Self::InvalidKey,
        }
    }
}
