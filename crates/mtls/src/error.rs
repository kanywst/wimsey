//! Error type for WIC issuance and verification.

/// An error returned while issuing or verifying a Workload Identity Certificate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MtlsError {
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),
    /// The certificate could not be parsed as DER X.509.
    #[error("could not parse the certificate")]
    Parse,
    /// The certificate is not signed with Ed25519.
    #[error("unexpected signature algorithm, expected Ed25519")]
    UnsupportedAlgorithm,
    /// A key could not be decoded into an Ed25519 key.
    #[error("invalid key")]
    InvalidKey,
    /// The certificate signature did not verify against the CA.
    #[error("certificate signature verification failed")]
    InvalidSignature,
    /// The certificate is not valid at the given time.
    #[error("certificate is not valid at the given time")]
    NotValid,
    /// The certificate carries no URI SAN workload identifier.
    #[error("certificate has no URI SAN workload identifier")]
    MissingIdentifier,
    /// The URI SAN was not a valid workload identifier.
    #[error("invalid workload identifier: {0}")]
    Identifier(#[from] wimsey_identifier::ParseError),
    /// A Unix timestamp could not be represented.
    #[error("invalid time")]
    Time,
}
