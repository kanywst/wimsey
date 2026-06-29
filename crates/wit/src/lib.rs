//! `wimsey-wit` — WIMSE Workload Identity Token (WIT) issuance and verification.
//!
//! Target spec: `draft-ietf-wimse-workload-creds-01`. A WIT is a JWT with JOSE
//! header `typ: wit+jwt`, signed by an issuer, carrying the workload's
//! identifier in `sub` and a proof-of-possession key in `cnf`.
//!
//! This crate signs with `EdDSA` (Ed25519, RFC 8037). Ed25519 signatures are
//! deterministic, so a token is byte-for-byte reproducible for a given key and
//! input — see the conformance vectors under `conformance/wit/`.
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use wimsey_identifier::WorkloadIdentifier;
//! use wimsey_wit::{issue, verify, Confirmation, Jwk, Validation, WitClaims};
//!
//! let issuer_key = SigningKey::from_bytes(&[1u8; 32]);
//! let pop_key = SigningKey::from_bytes(&[7u8; 32]);
//!
//! let claims = WitClaims {
//!     iss: "https://issuer.example".to_owned(),
//!     sub: WorkloadIdentifier::parse("spiffe://example.org/api").unwrap(),
//!     iat: 1_700_000_000,
//!     exp: 1_700_003_600,
//!     jti: "a1b2c3".to_owned(),
//!     cnf: Confirmation { jwk: Jwk::from_ed25519(&pop_key.verifying_key()) },
//! };
//!
//! let token = issue(&claims, Some("issuer-key-1"), &issuer_key).unwrap();
//! let verified = verify(&token, &issuer_key.verifying_key(), &Validation::at(1_700_000_000)).unwrap();
//! assert_eq!(verified.claims.sub.trust_domain(), "example.org");
//! ```

mod claims;
mod error;
mod jwk;
mod token;

pub use claims::{Confirmation, WitClaims};
pub use error::WitError;
pub use jwk::Jwk;
pub use token::{issue, verify, Validation, VerifiedWit, ALG, TYP};

// Re-exported so callers can name the key types without a direct dependency.
pub use ed25519_dalek::{SigningKey, VerifyingKey};

/// Returns the current time in seconds since the Unix epoch.
///
/// Provided as a convenience for callers building a [`Validation`]; the
/// verification path itself takes the time explicitly so it stays
/// deterministic.
#[must_use]
pub fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
